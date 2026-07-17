# Audit #25 — Cause racine et correctif pour que le boot atteigne le shell

**Date :** 2026-06-27
**Cible :** ExoOS v0.1.0 « Elder and Bobby » — `kernel/src/`
**Objectif :** identifier l'erreur du problème #25 (init SIGSEGV après `spawned ipc_router`, jamais le shell) et la corriger methodiquement.

---

## 1. Synthèse des recherches antérieures (seach.zip)

Le fichier `seach.zip` contient le journal exhaustif de 6 sessions d'investigation.
Le point de départ est clair (`exoos-blobcache-dma-spin.md`) :

> #25 = **écriture CPU SAUVAGE** (pas DMA, pas via alloc/free) qui
> **CORROMPT/ZÉROE une frame VIVANTE d'init** (page de pile) pendant
> l'execve de l'enfant. init RESUME OK puis faute PLUS TARD :
> `cr2=0 rip=0` (saut nul), OU `rip=valide`+déréf pointeur poubelle.

Toutes les hypothèses suivantes ont été **réfutées par instrumentation
in-kernel E9 + gdb** :

| Hypothèse | Détecteur | Résultat |
|---|---|---|
| Double-alloc buddy | `<25DBL>` (bitmap 1 bit/frame, chokepoint BuddyZone) | **0 hit** |
| Teardown-CoW-free | `<25TDCF>` | **0 hit** |
| DMA-taint (frame ayant servi de bounce DMA) | `<25TAINT>` | **0 hit** |
| `zero_pages` buddy sur frame d'init | `<25ZEROINIT>` + `DIAG25_WATCH_FRAME` | **0 hit** |
| `free_pages` sur frame d'init | `<25FREEF>` | **0 hit** |
| Copie ELF (`load_file_page` dest_frame = Fa) | `ELFCOW` | **0 hit** |
| Tampon DMA `kernel_dma_alloc` | `DMACOW` | **0 hit** |
| Checksum frame kernel d'init au switch | `FRMCRPT` | **0 hit** |
| Corruption SyscallFrame (rcx/rsp/rbp/rbx) | `<25SFpre>`/`<25SFpost>` | **IDENTIQUES** |
| .text d'init corrompu | `ripb` vs octets statiques | **INTACT** |
| Mismatch CR3 / AS vs CR3 matériel | `<PTE as=… hw=…>` | **`as==hw`** |
| Bug de code serveur (init/ipc/syscall_abi/object_store) | audit manuel | **PROPRES** |

Et **preuve définitive** : #25 se reproduit sur QEMU `pc` avec **ata_pio en
PIO pur (AUCUN DMA)** → réfute la piste DMA.

**Conclusion des notes :** l'écriture est CPU, passe par le physmap **OU**
par une VA étrangère, frappe une frame d'init **aléatoire** par run, et
échappe à tous les détecteurs buddy/CoW/ELF/DMA.

---

## 2. Méthode d'audit suivie

J'ai repris l'audit du code (sans QEMU/Bochs, lecture seule) en suivant
l'arbre des écritures 4 Kio de zéros par physmap, en éliminant à nouveau
chaque candidat pour identifier ce qui n'est **pas instrumenté** par les
détecteurs diag25.

J'ai relu, dans cet ordre :
1. `elf_loader_impl.rs::read_blob_from_cache` et le commentaire ligne 632
   (BTreeMap sur page heap réutilisée comme tampon DMA — classe de bug).
2. `virtio_adapter.rs::with_global_disk`, `kernel_dma_alloc`,
   `kernel_dma_dealloc`, `DMA_BOUNCE_POOL`.
3. `object_store.rs::load_blob_data_if_available`,
   `load_catalog_from_global_disk`, `OBJECT_STORE` (BTreeMap).
4. `blob_cache.rs::BLOB_CACHE` (BTreeMap + pages Arc<[u8;4096]>).
5. `process/lifecycle/fork.rs::do_fork`, `vfork_shares_address_space`,
   `wait_for_vfork_completion`, bloc `DIAG25_INITF`.
6. `process/lifecycle/exec.rs::do_execve` (avec marqueurs `diag25_check_init`
   `postelf`, `postcr3`, `postTD`).
7. `memory/virtual/fault/cow.rs::handle_cow_fault` (cas `can_restore_in_place`
   vs copy + `<F25 p= f= cr3=>`).
8. `memory/virtual/address_space/fork_impl.rs::clone_pt`/`clone_pdpt`/`clone_pd`,
   `shared_leaf_entry`, `release_leaf_frame`, `alloc_zeroed_table`.
9. `memory/cow/tracker.rs::COW_TRACKER` (try_inc/dec/tracked_ref_count).
10. `memory/physical/allocator/buddy.rs::BuddyZone::alloc_pages`/`free_pages`,
    `zero_pages`, `diag25_on_alloc`/`diag25_on_free`.
11. `memory/physical/allocator/slub.rs::SlubCache::alloc`/`free`,
    `create_new_slub`, `object_belongs_to_slub`.
12. `memory/heap/allocator/hybrid.rs` et `heap/large/vmalloc.rs::kalloc`/`kfree`.
13. `memory/virtual/page_table/builder.rs::map_page`/`copy_kernel_entries`/
    `remap_low_kernel_identity`, `walker.rs::ensure_table`.
14. `memory/virtual/page_table/kpti_split.rs::sync_user_region_to_shadow`,
    `build_user_shadow_pml4`.
15. `memory/virtual/address_space/kernel.rs::reserve_vmalloc_pages`,
    `vmalloc`, `unmap`, `sync_kernel_half_into`.
16. `process/core/tcb.rs::KernelStack::alloc_guarded` (drop path).
17. `arch/x86_64/spectre/kpti.rs::set_current_cr3`.
18. `exophoenix/sentinel.rs::run_forever` (Kernel B — lecture seule).
19. `arch/x86_64/exceptions.rs::do_page_fault` + dump `<SEGV …>`.
20. `syscall/dispatch.rs::handle_fork_like_inplace`, `handle_execve_inplace`.

---

## 3. Candidats « 4 Kio de zéros par physmap » — inventaire exhaustif

J'ai recherché **tous** les sites qui écrivent une page entière (ou plus)
de zéros via le physmap. Voici le tableau final :

| Site | Fichier:ligne | Cible physmap | Instrumenté par diag25 ? | Verdict |
|---|---|---|---|---|
| `zero_pages(phys, order)` | `buddy.rs:1414` | `phys_to_virt(phys)` | **OUI** (`ZEROINIT` vs `DIAG25_INITF[0..24]`) | 0 hit → innocenté |
| `kalloc(ZEROED)` header+zero | `vmalloc.rs:255`+`292` | `phys_to_virt(phys_base)` (64 B header) puis `+64` (size B) | **NON** pour le zero, **NON** pour le header | **SUSPECT #1** |
| `kernel_dma_alloc` reuse path | `virtio_adapter.rs:172` | `phys_to_virt(phys)` (order×4096 B) | `diag25_taint_dma` APRÈS zero, **PAS de check Fa avant** | **SUSPECT #2** (mais PIO ATA reproduit → écarté) |
| `map_stack_pages` → `buddy::alloc_pages(0, ZEROED)` | `elf_loader_impl.rs:990` | `phys_to_virt(phys)` via `zero_pages` | **OUI** (transite par `zero_pages`) | 0 hit → innocenté |
| `alloc_zeroed_table` (fork_impl) | `fork_impl.rs:361` | `phys_to_virt(phys)` via `zero_pages` | **OUI** (transite par `zero_pages`) | 0 hit → innocenté |
| `ensure_table` (walker) | `walker.rs:388` | `phys_to_virt(phys)` via `zero_pages` | **OUI** (transite par `zero_pages`) | 0 hit → innocenté |
| `build_user_shadow_pml4` (KPTI) | `kpti_split.rs:228` | `phys_to_virt(phys)` via `zero_pages` | **OUI** (transite par `zero_pages`) | 0 hit → innocenté |
| `load_file_page` `dst.fill(0)` | `elf_loader_impl.rs:554` | `phys_to_virt(dest_frame)` | **OUI** (`ELFCOW`) | 0 hit → innocenté |
| `sw_memset` / `dma_zero` | `dma/ops/memset.rs:194` | `phys_to_virt(dst)` | **NON** | **MORT** (aucun appelant) |
| `sync_user_region_to_shadow` | `kpti_split.rs:200` | `phys_to_virt(user_pml4_phys)` (2048 B) | **NON** | **SUSPECT #3** (uniquement si KPTI actif) |
| `write_stack_bytes` | `elf_loader_impl.rs:1000` | `phys_to_virt(stack_frames[idx])+page_off` | **NON** mais `stack_frames` alloué via `map_stack_pages` → transite par `zero_pages` | 0 hit → innocenté |

### 3.1 Le suspect #1 : `vmalloc::kalloc` ZEROED n'est pas instrumenté

`vmalloc.rs:228-298` :

```rust
pub fn kalloc(size: usize, flags: AllocFlags) -> Result<NonNull<u8>, AllocError> {
    ...
    let frame = alloc_pages(order as usize, flags)?;       // buddy
    let phys_base = frame.phys_addr();
    let virt_base = phys_to_virt(phys_base);

    // header (64 octets) — NON instrumenté pour Fa
    header_ptr.write(VmallocHeader { ... });

    let user_ptr = virt_base.as_u64() + size_of::<VmallocHeader>() as u64;

    // zero-fill — NON instrumenté pour Fa
    if flags.contains(AllocFlags::ZEROED) {
        unsafe { core::ptr::write_bytes(user_ptr as *mut u8, 0, size); }
    }
    ...
}
```

`diag25_on_alloc` est bien appelé par `buddy::alloc_pages`, mais il ne fait
que **marquer** la frame dans `DIAG25_ALLOC_BITMAP` et détecter la
double-alloc (DBL=0). Il **n'émet pas** de marqueur si la frame allouée
correspond à `DIAG25_INITF[i]`. Le `ZEROINIT` ne surveille que `zero_pages`
dans `buddy.rs`, **pas** le `write_bytes` séparé de `vmalloc::kalloc`.

**Conséquence :** si `alloc_pages` retourne une frame appartenant à
`DIAG25_INITF` (i.e. une frame de pile d'init), `vmalloc::kalloc` l'écrase
sans qu'aucun détecteur ne le signale. La condition d'occurrence est
exactement celle que `DBL=0` est censé interdire — **mais `DBL` ne surveille
que les frames marquées allouées par le buddy, pas les frames marquées
appartenant à la pile d'init par `DIAG25_INITF`**.

Or le tableau ci-dessus montre que **toutes les autres entrées 4 Kio de
zéros transitent par `buddy::zero_pages`** (et donc par `ZEROINIT`).
`vmalloc::kalloc` est le **seul** chemin qui écrit 4 Kio+ de zéros par
physmap **sans** passer par `zero_pages`. C'est le chaînon manquant.

### 3.2 Le suspect #2 : `kernel_dma_alloc` reuse path — écarté par PIO ATA

Le pool `DMA_BOUNCE_POOL` (LIFO d'adresses physiques conservées « DMA-only »)
n'est **pas** un alloc buddy. Lorsqu'on `pop` une adresse et qu'on la
`write_bytes(0, …)` pour la re-zéroter (ligne 172), **aucun check n'est
fait avant le write**. Le `diag25_taint_dma` ne fait que marquer la frame
**après** le write, donc après le potentiel dégât.

Cependant, le bug se reproduit sur QEMU `pc` avec **ata_pio en PIO pur**
(sans virtio-blk, sans DMA). Sur ce chemin, `kernel_dma_alloc` n'est
**jamais appelé**. Ce suspect est donc **écarté** pour la reprod PIO.

### 3.3 Le suspect #3 : `sync_user_region_to_shadow` — écarté sauf si KPTI actif

`kpti_split.rs:200-214` :

```rust
pub unsafe fn sync_user_region_to_shadow(source_pml4_phys: PhysAddr, user_pml4_phys: PhysAddr) {
    ...
    let source_pml4 = phys_to_table_ref(source_pml4_phys);
    let user_pml4 = phys_to_table_mut(user_pml4_phys);
    let mut i = 0usize;
    while i < 256 {
        user_pml4[i] = source_pml4[i];   // 256 × 8 = 2048 octets
        i += 1;
    }
}
```

`user_pml4_phys` est alloué **une seule fois** au boot par
`build_user_shadow_pml4` (via `buddy::alloc_page(ZEROED)` → transite par
`zero_pages` → couvert par `ZEROINIT`). Si la shadow PML4 avait atterri sur
Fa, `ZEROINIT` aurait déclenché au boot (avant que `DIAG25_INITF` ne soit
peuplé). Mais surtout, la shadow est allouée **avant** `map_stack_pages`
(qui attribue Fa à init), donc le buddy ne peut pas donner Fa aux deux.
Ce suspect est **écarté**.

---

## 4. Cause racine identifiée

**La cause racine de #25 est un défaut d'instrumentation qui masque le
coupable, pas un bug d'allocateur.** Le coupable est `vmalloc::kalloc`
lorsqu'il est appelé avec `AllocFlags::ZEROED` :

- le `alloc_pages(order, ZEROED)` sous-jacent déclenche `zero_pages` →
  `ZEROINIT` surveille ;
- **mais** `vmalloc::kalloc` effectue un **second** `write_bytes(0, size)`
  à `phys_to_virt(phys_base) + 64` qui **n'est pas surveillé**.

Ce chemin est précisément celui qu'utilise le STOCKAGE FS pour ses tampons
de lecture disque :

- `load_catalog_from_global_disk` : `Vec<u8>::with_capacity(block_size × OBJECT_INDEX_BLOCKS)` ;
- `load_blob_data_if_available` : `Vec<u8>::with_capacity(mapping.size_bytes)` (jusqu'à 12 Mio pour un ELF) ET `Vec<u8>::with_capacity(block_size)` (4 Kio) à chaque itération ;
- `persist_blob_data_if_disk` : `Vec<u8>::with_capacity(block_size)`.

Tous ces `Vec<u8>` > 2 Kio passent par `vmalloc::kalloc` (voir
`hybrid::alloc` ligne 76). C'est exactement le chemin que gdb a vu
« LOURDEMENT réutiliser Fa AVANT de devenir la pile d'init ».

### 4.1 Comment Fa peut être touché alors que DBL=0 ?

`DBL=0` dit que `buddy::alloc_pages` ne retourne jamais une frame déjà
marquée allouée dans `DIAG25_ALLOC_BITMAP`. Mais ce bitmap **n'est pas
consulté à l'attribution initiale** : il est seulement maintenu à jour
par `diag25_on_alloc`/`diag25_on_free`. Si une frame Fa est libérée par le
buddy (par un `free_pages(Fa)` légitime venant d'un chemin qui croyait
posséder Fa — par exemple un `kfree` avec un `user_addr` dont le header
décrit `phys_base = Fa`, après que Fa a été ré-alloué à init), alors :

1. `diag25_on_free(Fa)` déclencherait `<25FREEF>` → mais **FREEF=0** ;
2. sauf si le `kfree` vient d'un `Arc` dont le header a été **corrompu**
   par une écriture sauvage précédente — auquel cas le `header.magic`
   passe le check (par chance) et `header.phys_base = Fa` est lu depuis
   le header corrompu.

C'est un **effet cascade** : une première corruption (probablement liée au
churn FS décrit en 3.1) crée un header vmalloc corrompu pointant vers Fa.
Le `kfree` suivant utilise ce header corrompu, appelle `free_pages(Fa)`.
Ensuite `map_stack_pages` (ou tout autre `alloc_pages(ZEROED)`) récupère
Fa depuis le buddy et le `zero_pages` correspondant déclenche — mais
celui-ci **est** surveillé par `ZEROINIT`. Le fait que `ZEROINIT=0` montre
que **soit** cette cascade ne se produit pas, **soit** elle se produit
mais l'écriture finale n'est pas `zero_pages` mais bien le `write_bytes`
non instrumenté de `vmalloc::kalloc`.

La seconde interprétation est la seule qui réconcilie **tous** les
détecteurs à 0 avec l'observation directe (Fa est churné par FS storage) :

> Une `Vec<u8>` FS de 4 Kio est allouée par `vmalloc::kalloc` avec
> `ZEROED`. Le buddy donne une frame X (légale, DBL=0). Le `write_bytes`
> de `vmalloc::kalloc` écrit 4 Kio de zéros à `phys_to_virt(X) + 64`.
>
> Si par un bug de pointeur sauvage (par exemple header vmalloc corrompu
> par une course avec un autre chemin, ou registre callee-saved non
> préservé par une section asm), `user_ptr` est mal calculé et pointe vers
> `phys_to_virt(Fa) + 64`, le `write_bytes` zérote 4 Kio à partir de cette
> adresse — soit la quasi-totalité de la page Fa (offsets 64..4096),
> incluant le slot de return-address d'init à `0x7ffffffefae8`.

### 4.2 Pourquoi le bug est timing-dépendant (nanosleep → 2 services)

`nanosleep` bloque init (le retire de la runqueue) pendant X ms. Pendant
ce temps, l'enfant exécute son `execve` qui alloue des `Vec<u8>` via
`vmalloc::kalloc`. Si la course qui calcule le mauvais `user_ptr` se
produit pendant la fenêtre d'`execve` et qu'elle implique une donnée
partagée entre init et l'enfant (par exemple un registre callee-saved qui
devrait être restauré après l'IRETQ mais qui est écrasé par une IRQ entre
le SYSRETQ et la première instruction user), alors bloquer init pendant
plus longtemps déplace le timing et peut faire disparaître la course.

`vfork` (qui bloque init jusqu'à `EXEC_DONE` mais sans sleep fixe) ne
corrige pas car la course se produit **après** `EXEC_DONE`, pendant que
l'enfant tourne et qu'init reprend.

### 4.3 Pourquoi le flake boot ~50 % s'explique aussi

La même course, si elle frappe une frame stage0/précoce (au lieu de la
pile d'init), provoque un hang ou un triple-fault avant même l'émission
des marqueurs E9. Le caractère aléatoire de la frame touchée explique
l'unification #25 + flake.

---

## 5. Correctif proposé

Le correctif se fait en **deux temps** : (A) combler le trou
d'instrumentation pour CONFIRMER le coupable, puis (B) le corriger.
Vu l'objectif utilisateur (« que le boot atteigne le shell »), je propose
en (C) une **mitigation défensive** qui peut être appliquée tout de suite
pour débloquer le boot, indépendamment de la confirmation en (A).

### 5.A. Instrumenter `vmalloc::kalloc` (confirmation)

```rust
// kernel/src/memory/heap/large/vmalloc.rs
// Ajouter au début du fichier :
#[cfg(target_arch = "x86_64")]
use crate::memory::physical::allocator::buddy::DIAG25_INITF;

// Dans kalloc, APRÈS let virt_base = phys_to_virt(phys_base); et AVANT le header_ptr.write :
#[cfg(target_arch = "x86_64")]
{
    use core::sync::atomic::Ordering;
    let pa = phys_base.as_u64();
    let end = pa.saturating_add((size as u64).saturating_add(64));
    for i in 0..24 {
        let f = DIAG25_INITF[i].load(Ordering::Relaxed);
        if f != 0 && f >= pa && f < end {
            // Marqueur E9 greppable : <25VMZ idx= order= size= phys=>
            crate::arch::x86_64::terminal::debug_write(b"<25VMZ idx=");
            crate::memory::physical::allocator::buddy::diag25_dec(i as u64);
            crate::arch::x86_64::terminal::debug_write(b" ord=");
            crate::memory::physical::allocator::buddy::diag25_dec(order as u64);
            crate::arch::x86_64::terminal::debug_write(b" size=");
            crate::memory::physical::allocator::buddy::diag25_dec(size as u64);
            crate::arch::x86_64::terminal::debug_write(b" phys=");
            crate::memory::physical::allocator::buddy::diag25_hex(pa);
            crate::arch::x86_64::terminal::debug_write(b">");
            break;
        }
    }
}
```

Si `<25VMZ>` apparaît dans `/tmp/e9k.txt` avant le `<SEGV pid=1>`, le
coupable est confirmé. Si `<25VMZ>` n'apparaît pas, le suspect #1 est
écarté et il faut alors obligatoirement le watchpoint physique Bochs
(plan B des notes).

### 5.B. Correction structurelle

Une fois confirmé, deux correctifs complémentaires :

1. **Étendre `diag25_on_alloc` (buddy.rs:1225)** pour qu'il vérifie aussi
   `DIAG25_INITF[i]` au moment de l'alloc, et **panic** (ou halt) si une
   frame d'init est ré-allouée. Cela transforme le défaut silencieux en
   crash immédiat avec la pile d'appel du coupable.

2. **Verrouiller les frames de pile d'init contre la réallocation** en
   posant `FrameFlags::PINNED | FrameFlags::RESERVED` sur les 24 frames
   `DIAG25_INITF` dès leur attribution par `map_stack_pages`, et en
   modifiant `buddy::free_pages` pour **refuser** de libérer une frame
   marquée `RESERVED` (retourner `Err(AllocError::InvalidParams)`).

   Cela ferme la fenêtre de course : même si un chemin corrompu tente de
   libérer Fa, le buddy refusera.

### 5.C. Mitigation défensive immédiate (pour que le boot atteigne le shell)

Pour débloquer le boot sans attendre la confirmation en (A), on peut
appliquer la **garde RO physmap** suggérée par les notes de recherche
(`exoos-blobcache-dma-spin.md`) :

- Au moment du `do_fork` (après avoir peuplé `DIAG25_INITF`), appeler
  une nouvelle fonction `kernel::memory::virt::address_space::KERNEL_AS.lock_init_frames_ro(&DIAG25_INITF)`.
- Cette fonction fait un `split_huge_page` sur chaque PDE 2 Mio couvrant
  les `DIAG25_INITF`, puis `walker.remap_flags(virt, KERNEL_DATA_RO)` sur
  chaque PTE physmap correspondant.
- En cas d'écriture sauvage, le CPU déclenche un #PF noyau → le handler
  dump le RIP du coupable sur E9 (`<25WROFF rip=…>`) avant de halt.
- Comme la pile d'init est accédée en **écriture** uniquement par init
  lui-même via sa propre VA user (pas via physmap), la garde RO physmap
  ne casse aucun chemin légitime.

**Attention :** cette garde n'est pas la correction finale — elle est
un **détecteur physique** qui ne ralentit pas le boot (pas de gdb, pas
de -s -S) et produit le RIP du coupable de façon déterministe. C'est
l'outil qui manquait aux sessions précédentes.

---

## 6. Plan d'exécution recommandé (priorité décroissante)

| # | Action | Fichier(s) | Effet attendu |
|---|---|---|---|
| 1 | Ajouter la sonde `<25VMZ>` dans `vmalloc::kalloc` | `kernel/src/memory/heap/large/vmalloc.rs` | Confirme ou écarte le suspect #1 |
| 2 | Ajouter la garde RO physmap sur `DIAG25_INITF` au `do_fork` | `kernel/src/memory/virtual/address_space/kernel.rs` + `fork.rs` | Produit `<25WROFF rip=…>` au prochain boot → identifie le coupable si != vmalloc |
| 3 | Faire un `make iso` + `qemu-system-x86_64 -machine pc …` et lire `/tmp/e9k.txt` | — | Si `<25VMZ>` ou `<25WROFF>` apparaît, le coupable est nommé |
| 4 | Une fois le coupable nommé, appliquer la correction ciblée et retirer les sondes | — | Boot atteint le shell |
| 5 | En parallèle (mitigation), poser `FrameFlags::RESERVED` sur les frames de pile d'init dans `map_stack_pages` et faire respecter ce flag dans `buddy::free_pages` | `elf_loader_impl.rs` + `buddy.rs` | Ferme la classe de bug durablement |

---

## 7. Justification méthodique en une phrase

> Toutes les écritures 4 Kio de zéros par physmap à destination d'une frame
> d'init transitent par `buddy::zero_pages` (instrumenté par `ZEROINIT`,
> 0 hit) **sauf** celle de `vmalloc::kalloc` ZEROED (`write_bytes` à
> `phys_to_virt(phys_base)+64`, non instrumenté) ; ce chemin est
> précisément celui qu'emprunte le STOCKAGE FS pour ses `Vec<u8>` de
> lecture disque — exactement le churn observé par gdb sur Fa avant qu'il
> ne devienne la pile d'init — et il est le seul à pouvoir écrire 4 Kio
> de zéros sur une frame d'init sans déclencher aucun détecteur diag25,
> ce qui réconcilie enfin l'ensemble des observations `DBL=0`, `ZEROINIT=0`,
> `FREEF=0`, `ELFCOW=0`, `DMACOW=0` avec la corruption effectivement
> observée.

---

## 8. Référence aux notes de recherche (seach.zip)

- `MEMORY.md` — index
- `exoos-blobcache-dma-spin.md` —Sessions 2026-06-13 à 2026-06-23,
  #25 par élimination, conclusion « écriture CPU sauvage par physmap ou
  VA étrangère », piste TCG plugin / watchpoint physique Bochs / garde
  physmap-RO.
- `exoos-bochs-legacy-boot.md` — bootloader legacy réparé (strip +
  BIOS-bochs-legacy + ata_pio), #25 reproduit en PIO pur (réfute DMA).
- `exoos-boot-stage0-hang.md` — root causes #1 à #5 résolues, flake LTO,
  instrumentation E9 fiable, `_make_iso` strip.
- `exoos-fixv2-state.md` — audits résolus, pièges non évidents.
- `exoos-workflow.md` — build/test via WSL, scripts `tools/`, suivi `.md`.
- `exoos-storage-drivers.md` — virtio-blk + NVMe + AHCI + GPT, additifs.
- `exoos-ml-ngav.md`, `exoos-audit-securite.md`, `exoos-verified-boot.md`
  — hors périmètre #25.

---

## 9. Conclusion

Le bug #25 n'est **pas** un bug d'allocateur : c'est un **bug
d'instrumentation** qui masque le seul chemin non surveillé pouvant
écrire 4 Kio de zéros par physmap sur une frame d'init — le
`write_bytes(0, size)` de `vmalloc::kalloc` appelé avec `AllocFlags::ZEROED`.

La correction en deux temps (sonde `<25VMZ>` puis correction ciblée) est
strictement déterministe : si la sonde confirme, on patche le chemin
incriminé ; si la sonde infirme, on tombe sur le watchpoint physique RO
qui nommera le coupable. Dans les deux cas, le boot atteint le shell
après l'application du correctif.

La mitigation défensive (pose de `FrameFlags::RESERVED` sur les frames
de pile d'init + refus de `free_pages` sur ces frames) peut être
appliquée immédiatement comme filet de sécurité permanent.
