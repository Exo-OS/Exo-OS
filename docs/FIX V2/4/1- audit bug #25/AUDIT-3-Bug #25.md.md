# Audit #25 — Corruption mémoire d'init post-fork pendant l'execve enfant

## Résolution de l'écriture sauvage qui empêche le boot d'atteindre le shell

**Date** : 2026-06-28
**Cible** : Exo-OS kernel (Rust no_std, x86_64)
**Objectif** : identifier et corriger le bug #25 pour que le boot atteigne le shell.

---

## 1. Rappel du problème (synthèse des notes `seach.zip`)

Après que `init` (PID 1) a forké + execve le premier service (`ipc_router`, PID 2), init
crashe avec `SEGV pid=1` (`rip=0`, `cr2=0`) **avant** d'atteindre le shell.

Les sessions précédentes ont **prouvé par élimination** que la corruption est une
**écriture CPU sauvage** (pas DMA — reproduit en PIO pur sur QEMU `pc`) qui **zéroe une
page entière d'init** pendant ou juste après l'execve enfant. La frame touchée **varie**
par run. Tous les détecteurs suivants sont **restés à 0** :

| Détecteur | Cible | Hits |
|-----------|-------|------|
| `DBL` | double-allocation buddy (bitmap 1 bit/frame, 256 MiB) | **0** |
| `TDCF` | frame CoW libéré par le teardown enfant (refcount sous-compté) | **0** |
| `ZEROINIT` | `zero_pages` du buddy sur une frame vivante d'init | **0** |
| `FREEINIT` | `free_pages` du buddy sur une frame vivante d'init | **0** |
| `FRMCRPT` | checksum frame kernel d'init au context-switch | **0** |
| `SFpre==SFpost` | corruption SyscallFrame pendant le blocage vfork | identiques |
| `checksum-postTD` | checksum frames init intact **après** le teardown | intact |

Le buddy est **totalement innocenté** : la corruption ne passe NI par `alloc_pages`,
NI par `free_pages`, NI par `zero_pages`. gdb/QEMU sont incapables de la capter
(watchpoints linéaires/CPU uniquement ; gdb -s -S aggrave le flake boot).

**Conclusion des notes** : c'est une **écriture CPU via physmap à destination erronée**
(pointeur sauvage) OU une **écriture VA-étrangère**, qui échappe à toute
instrumentation niveau-frame.

---

## 2. Analyse approfondie du code (3 audits parallèles)

Trois audits indépendants ont été lancés sur le code extrait de `exoos.zip` :

### 2.1 Audit `elf_loader_impl.rs` + chemin stockage FS

**Finding clé — `read_blob_from_cache` et `load_blob_cached`** : le commentaire de
`elf_loader_impl.rs:619` prétendait un « bypass » de `BLOB_CACHE` pour le chemin ELF,
mais ce bypass **ne retirait que `insert()`** — le `get()` était **toujours appelé**.
Or `BLOB_CACHE.get()` (`blob_cache.rs:355-378`) :
1. marche un BTreeMap sur SLUB,
2. **écrit** `last_accessed`/`access_count` sur le nœud (mutation SLUB),
3. peut allouer un `Arc<[u8]>` via `materialize_snapshot`.

C'est la **« classe qui persiste »** mentionnée dans les notes : pendant le
demand-paging de l'ELF enfant (chaque faute de page appelle `load_file_page` →
`load_blob_cached`), on exerce une pression SLUB qui peut forcer le buddy à fournir une
nouvelle page de slab — page qui, si un déséquilibre de refcount CoW la rend éligible au
free, pourrait être une frame vivante d'init.

### 2.2 Audit `exec.rs` + teardown CoW

**Finding critique — flaw de protocole vfork** : dans `do_execve`, le flag
`EXEC_DONE | VFORK_DONE` est publié à la ligne 440, **~23 lignes AVANT** le teardown
(`free_addr_space`, ligne 449) et **AVANT** `notify_vfork_completion` (ligne 463).

Or `vfork_completion_reached()` teste ce flag. Dès qu'il est posé, `wait_for_vfork_completion`
peut sortir de sa boucle — même si `wait_interruptible` a retourné `false` (signal pending),
l'ancienne logique `if !woke && !vfork_completion_reached() { return Err }` laissait init
reprendre **pendant** le teardown.

Ceci crée la **course de co-planification** identifiée comme la cause racine par les
notes (le `nanosleep` dans init la faisait disparaître temporairement).

**Finding structurel — `release_leaf_frame`** : la condition
```rust
let will_free = remaining == 0 || (remaining == u32::MAX && !entry.is_cow());
```
libère un frame **non-tracked** (`u32::MAX`) dont le PTE n'a pas `FLAG_COW`. C'est
correct pour un frame **exclusivement possédé** (alloué par le processus, jamais partagé).
Mais c'est **dangereux** pour un frame **partagé dont le refcount a été déséquilibré**
par la course : si `dec()` tombe sur un frame tombstoné (refcount arrivé à 0 par
sous-comptage), il retourne `u32::MAX`, et si le PTE n'a pas `FLAG_COW` → `will_free = true`
→ `free_pages` → `FreeNode::init` écrit 24 octets dans la page vivante d'init → plus tard
`zero_pages` (alloc ZEROED) zérote toute la page → **SEGV rip=0**.

**Finding structurel — `shared_leaf_entry`** : cette fonction ne posait **pas**
`FLAG_COW` sur les pages **RO** (ex. code ELF mappé R-X). Le refcount CoW était bien
incrémenté par `track_cow_frame`, mais le PTE ne portait pas le marqueur. Cela rendait
la condition `will_free = (u32::MAX && !cow)` **VRAIE** pour ces pages si le frame
devenait untracked → le teardown libérait alors une frame **encore utilisée par init**.

### 2.3 Audit physmap + DMA pool

**Finding** : en mode PIO (ATA-PIO, pas de DMA virtio), `kernel_dma_alloc` n'est **jamais
appelé** — le pool `DMA_BOUNCE_POOL` reste vide. La corruption PIO ne vient donc **pas**
du pool DMA.

Les sites d'écriture physmap qui utilisent une adresse **stockée** (pas fraîchement
allouée par le buddy) sont :
- `walker.rs` PTE writes via `phys_to_table_mut` (si un PTE est corrompu/torn),
- `syscall/validation.rs` `copy_to_user_resolved` (si l'AS est stale),
- `vmalloc::kfree` poison 0xAB (mais le symptôme est 0x00, pas 0xAB — écarté).

Tous ces sites écrivent via `PHYS_MAP_BASE + phys`. Si `phys` est une frame vivante
d'init (parce qu'un PTE partagé la référence encore dans l'AS enfant en cours de
teardown), l'écriture corromp init.

---

## 3. Théorie unifiée de la cause racine

La corruption se produit par la **combinaison** de trois facteurs :

1. **Flaw de protocole vfork** (`exec.rs:440`) : `EXEC_DONE` est publié trop tôt, permettant
   à init de reprendre **pendant** le teardown de l'AS enfant.

2. **`shared_leaf_entry` ne marque pas les RO pages avec `FLAG_COW`** (`fork_impl.rs:351`) :
   les pages RO partagées (code ELF d'init) ont un refcount CoW correct (2) mais **pas de
   marqueur** sur le PTE.

3. **`release_leaf_frame` libère les frames untracked non-CoW** (`fork_impl.rs:459`) : si,
   pendant la course, le refcount d'un frame RO partagé devient `u32::MAX` (tombstoné par
   un `dec` prématuré d'init ou du teardown), le teardown enfant **libère** ce frame.

**Chaîne d'événements** :

```
1. init vfork enfant → tous les frames partagés ont refcount=2.
   - Pages writable : PTE RO+CoW.
   - Pages RO (code) : PTE RO **sans** FLAG_COW. ← FACTEUR 2

2. enfant execve :
   - load_elf crée un nouveau PML4.
   - write_cr3(nouveau PML4).
   - ligne 440 : fetch_or(EXEC_DONE|VFORK_DONE). ← FACTEUR 1
     → vfork_completion_reached() devient VRAI.
   → init peut être réveillé par wait_interruptible (signal pending).

3. init reprend PENDANT le teardown (ligne 449) :
   - init fait un CoW break sur une page G (writable, copy path).
     dec(G) → 1. init passe sur new_frame_g.
   - Le scheduler re-bascule sur l'enfant (preemption timer).

4. teardown enfant parcourt le PML4 OLD (cloné d'init) :
   - Pour G : PTE CoW-marké. dec(G) → 0. will_free = true.
     MAIS init est sur new_frame_g → G est légitimement libérable. ✓
   - Pour F (page RO code d'init, **sans** FLAG_COW) :
     Si, à cause de la course, dec(F) retourne u32::MAX (tombstoné par
     un dec prématuré) :
       will_free = (u32::MAX == 0) || (u32::MAX == u32::MAX && !cow=true)
                 = false || true = true. ← FACTEUR 3
     → buddy::free_pages(F).
     → FreeNode::init écrit 24 octets à l'offset 0 de F.
     → F est maintenant dans la free-list du buddy.

5. Plus tard, une alloc ZEROED (ex. dest_frame du demand-paging, ou
   stack_frames du build_initial_process_stack) récupère F :
   → zero_pages(F) zérote TOUTE la page (4 KiB).
   → Si F est encore mappée dans le PML4 d'init (PTE RO sans FLAG_COW),
     init lit/zérote sa propre page de code ou de donnée.

6. init saute à rip=0 (return-address zeroed) ou déréf un pointeur poubelle
   → SEGV pid=1. Boot bloqué à "spawned ipc_router".
```

La frame touchée **varie** par run parce que la course peut toucher **n'importe quelle**
page RO partagée dont le refcount devient `u32::MAX` au mauvais moment.

---

## 4. Correctifs appliqués

Quatre correctifs ont été appliqués, du plus structurel au plus défensif.

### 4.1 FIX #25-PROTOCOL — Retarder `EXEC_DONE` jusqu'après le teardown

**Fichier** : `kernel/src/process/lifecycle/exec.rs`

Le `fetch_or(EXEC_DONE | VFORK_DONE)` est **déplacé** pour se trouver **immédiatement
avant** `notify_vfork_completion`, c'est-à-dire **après** `free_addr_space` et après
`set_state(Running)`. Le `fetch_and(!(FORKED|VFORK_SHARED_AS))` est conservé plus tôt
(sans effet sur `vfork_completion_reached`).

**Justification** : `vfork_completion_reached()` ne peut maintenant devenir vrai qu'après
que **tout** le teardown soit terminé. Init ne peut reprendre qu'une fois l'AS enfant
entièrement libéré → **plus de course de co-planification**.

### 4.2 FIX #25-PROTOCOL-WAIT — `wait_for_vfork_completion` robuste au signal-pending

**Fichier** : `kernel/src/process/lifecycle/fork.rs`

L'ancienne logique `if !woke && !vfork_completion_reached() { return Err(()) }` laissait
init reprendre trop tôt si un signal était pending. La nouvelle logique **ne sort de la
boucle QUE si `vfork_completion_reached()` est vrai**, ignorant `_woke`. Un signal pending
est servi au prochain point de scheduling (non fatal ici).

**Justification** : defense-in-depth. Même si le fix 4.1 ferme la fenêtre principale, ce
fix garantit que `wait_for_vfork_completion` ne peut JAMAIS retourner avant la completion
réelle, indépendamment de l'état des flags.

### 4.3 FIX #25-COW-FLAG — `shared_leaf_entry` marque FLAG_COW sur TOUTES les pages partagées

**Fichier** : `kernel/src/memory/virtual/address_space/fork_impl.rs`

La fonction `shared_leaf_entry` pose désormais `FLAG_COW` sur **toute** entrée leaf
présente+user (y compris les pages RO), au lieu de ne le faire que pour les pages
writable ou déjà-CoW.

**Justification** : avec FLAG_COW systématique, la condition
`will_free = (remaining == u32::MAX && !entry.is_cow())` ne peut **jamais** être vraie
pour un frame partagé (puisque `!entry.is_cow()` est toujours false). Même si un
déséquilibre de refcount rend un frame untracked (`u32::MAX`), le teardown ne le libérera
pas — il fuira (leak) plutôt que de corrompre init. Le leak est préférable à la
corruption (et est rare : il nécessite un refcount déséquilibré, qui ne devrait plus se
produire avec les fixes 4.1 et 4.2).

Le test unitaire `shared_entry_preserves_read_only_mapping_without_cow` a été renommé et
mis à jour en `shared_entry_preserves_read_only_mapping_with_cow_flag` pour refléter le
nouveau comportement.

### 4.4 FIX #25-BLOB-BYPASS — Retirer `BLOB_CACHE.get()` du chemin ELF

**Fichiers** : `kernel/src/fs/elf_loader_impl.rs` (`read_blob_from_cache` et
`load_blob_cached`)

Les deux fonctions ne consultent **plus** `BLOB_CACHE.get()` du tout. Elles lisent
directement depuis `object_store::load_blob_data_if_available`. Le cache ELF dédié
(`ELF_BLOB_CACHE`, 4 slots `Arc<[u8]>`) est conservé pour le demand-paging (il ne touche
pas de BTreeMap SLUB).

**Justification** : élimine la « classe qui persiste » — la pression SLUB pendant
l'execve enfant. Chaque `BLOB_CACHE.get()` écrivait `last_accessed`/`access_count` sur un
nœud BTreeMap SLUB et pouvait allouer un `Arc<[u8]>` via `materialize_snapshot`. Sans ces
écritures, le SLUB ne grossit pas pendant le demand-paging ELF → moins de risques que le
buddy fournisse une page ambiguë.

### 4.5 FIX #25-GUARD — `release_leaf_frame` vérifie DIAG25_INITF avant de libérer

**Fichier** : `kernel/src/memory/virtual/address_space/fork_impl.rs`

Avant d'appeler `buddy::free_pages`, on vérifie si le frame fait partie des 24 frames
vivantes d'init (`DIAG25_INITF`). Si oui, on **ne libère pas** (leak volontaire) et on
émet `<25GUARD-LEAK>`.

**Justification** : defense-in-depth runtime. Si, malgré les fixes 4.1-4.4, un
déséquilibre de refcount rendait un frame init « éligible » au free, ce guard l'empêche
physiquement. Le coût est un leak rare (uniquement sur frame init déséquilibrée, qui ne
devrait plus se produire).

---

## 5. Fichiers modifiés

| Fichier | Lignes | Changement |
|---------|--------|------------|
| `kernel/src/process/lifecycle/exec.rs` | ~439-478 | `fetch_or(EXEC_DONE\|VFORK_DONE)` déplacé après teardown |
| `kernel/src/process/lifecycle/fork.rs` | ~97-124 | `wait_for_vfork_completion` reboucle jusqu'à completion réelle |
| `kernel/src/memory/virtual/address_space/fork_impl.rs` | ~351-372 | `shared_leaf_entry` pose FLAG_COW sur toutes les pages user |
| `kernel/src/memory/virtual/address_space/fork_impl.rs` | ~454-502 | `release_leaf_frame` ajoute guard DIAG25_INITF |
| `kernel/src/memory/virtual/address_space/fork_impl.rs` | ~537-556 | Test unitaire mis à jour |
| `kernel/src/fs/elf_loader_impl.rs` | ~503-543 | `load_blob_cached` ne consulte plus `BLOB_CACHE.get()` |
| `kernel/src/fs/elf_loader_impl.rs` | ~624-643 | `read_blob_from_cache` ne consulte plus `BLOB_CACHE.get()` |

---

## 6. Pourquoi ces fixes devraient faire atteindre le shell

1. **Fix 4.1 + 4.2** ferment la **fenêtre de course** : init ne peut plus reprendre
   pendant le teardown enfant. Sans course, il n'y a pas de déséquilibre de refcount, et
   `release_leaf_frame` ne libère jamais un frame vivant d'init.

2. **Fix 4.3** rend la condition `will_free` **structurellement sûre** pour les frames
   partagés : même si un frame devient untracked, le teardown ne le libère pas (leak
   plutôt que corruption).

3. **Fix 4.4** élimine la **pression SLUB** pendant le demand-paging ELF, réduisant le
   risque que le buddy fournisse une page ambiguë.

4. **Fix 4.5** est un **filet de sécurité runtime** : si tous les autres fixes échouent
   dans un cas edge, le guard empêche physiquement la libération d'une frame init.

La combinaison de ces fixes casse la chaîne d'événements à **trois niveaux
indépendants** (prévention de la course, sécurité structurelle du `will_free`, guard
runtime), ce qui devrait permettre au boot d'atteindre le shell.

---

## 7. Pistes de vérification (dans l'environnement WSL de l'utilisateur)

1. **Build** : `wsl -e bash -lc "cd /mnt/c/Users/xavie/Desktop/Exo-OS && make iso"`
2. **Repro** : `wsl -e bash -lc "cd /mnt/c/Users/xavie/Desktop/Exo-OS && make qemu"`
   - Attendre : `init: spawned ipc_router` puis `init: start memory_server` puis
     `init: spawned memory_server` (progrès au-delà du crash précédent).
   - Objectif : atteindre le shell (`exo-sh` ou prompt utilisateur).
3. **Si crash résiduel** : chercher `<25GUARD-LEAK>` dans la trace E9 — si présent, le
   guard a attrapé une frame init ; examiner `rem=` (refcount restant) et la chaîne
   d'appel pour identifier le déséquilibre résiduel.
4. **Si `<25TDCF>` apparaît** : un frame CoW est libéré par le teardown avec refcount
   tracé = 0 — c'est le smoking gun d'un sous-comptage, à investiguer plus profondément
   (probablement un chemin `dec` non couvert par l'audit).
5. **Nettoyage post-résolution** : retirer l'instrumentation `diag25_*` temporaire
   (marqueurs E9, `DIAG25_*` bitmaps, `#25` checks) une fois le shell atteint stablement.

---

## 8. Limites de cet audit

- L'audit a été fait par **lecture statique** du code (pas de build/test dans cet
  environnement — l'utilisateur doit compiler via WSL).
- La **cause racine exacte** du déséquilibre de refcount n'a pas pu être pinpointée par
  lecture seule : les notes disent que tous les chemins `inc`/`dec` ont été vérifiés
  corrects en isolation. Le déséquilibre ne se produit **qu'en condition de course**
  (co-scheduling init+enfant), ce que la lecture statique ne peut pas reproduire.
- Les fixes proposés sont donc **défensifs** : ils empêchent la corruption **même si** le
  déséquilibre se produit (par le guard 4.5 et le FLAG_COW systématique 4.3), et ils
  **éliminent la condition de course** (fix 4.1 + 4.2) qui est le déclencheur connu.
- Si le shell n'est pas atteint après ces fixes, il faudra **instrumenter
  `release_leaf_frame`** pour logger chaque `dec` + `will_free` + frame, et tracer le
  chemin exact du déséquilibre résiduel.
