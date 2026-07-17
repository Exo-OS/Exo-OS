# Audit Exo-OS — Issue #25 (corruption mémoire post-fork, boot bloqué avant le shell)

**Méthode** : audit statique complet du code fourni (`exoos.zip`), recoupé avec les notes de recherche fournies (`seach.zip`). Aucun environnement d'exécution n'était disponible (pas de toolchain Rust nightly accessible — dépôts whitelistés limités à crates.io/npm/pypi/apt Ubuntu —, pas de QEMU/Bochs installés, et surtout **le crate `libs/exo-phoenix-ssr` référencé par `kernel/Cargo.toml` est absent de l'archive**, donc un build complet est impossible en l'état). Ce rapport est donc une relecture de code méthodique, pas une vérification dynamique — exactement la limite déjà identifiée dans vos notes.

---

## 1. Confirmation indépendante des éliminations déjà faites

J'ai re-dérivé à la main, sans présupposer vos conclusions, les mécanismes suivants. Ils sont **corrects** :

- **`fork()`/`vfork()` (`kernel/src/process/lifecycle/fork.rs`)** : le FIX #25 (CoW séparé + parent bloqué via `wait_for_vfork_completion`) est bien en place. `WaitQueue::wait_interruptible` (`scheduler/sync/wait_queue.rs`) positionne l'état `Sleeping` et appelle `schedule_block` de façon atomique *avant* de rendre la main — pas de fenêtre où le parent reste runnable par erreur.
- **`COW_TRACKER` (`kernel/src/memory/cow/tracker.rs`) et `release_leaf_frame` (`fork_impl.rs`)** : j'ai rejoué à la main le scénario à 2 propriétaires (init + enfant) dans les deux ordres possibles (enfant casse le CoW en premier / init le restaure en place après l'exec) — dans les deux cas, le refcount retombe à 0 exactement une fois, sans double-free ni libération prématurée de la frame encore utilisée par l'autre partie. Ceci confirme indépendamment votre conclusion « allocateur buddy totalement innocenté ».
- **Bornes de boucle `clone_userspace_tables` / `free_userspace_tables`** : strictement symétriques (PML4 `0..256` = moitié user uniquement ; PDPT/PD/PT `0..512`). Aucun risque de toucher la moitié noyau partagée ni de désynchronisation clone/free.
- **`elf_loader_impl.rs::load_elf`** : le paramètre `cr3_in` (l'AS existant à « réinitialiser » selon la doc du trait) est en réalité **ignoré** (`_cr3_in`) — `load_elf` crée toujours un `UserAddressSpace` neuf via `Box::new(...)`. Il n'existe donc **pas** de chemin de « reset en place » qui contournerait le `free_userspace_tables` audité plus haut. `build_initial_process_stack` / `write_stack_bytes` / `map_stack_pages` n'écrivent que dans des frames fraîchement allouées, avec bornes vérifiées (`checked_sub`/`checked_add`).
- **`ata_pio.rs`** : `read_block`/`ata_read_sectors` vérifient la taille du buffer avant toute boucle `insw`. Pas de dépassement possible.
- **`virtio_adapter.rs`** : pool de bounce DMA correctement isolé (allocations `Vec<u8>` fraîches par I/O) — cohérent avec le fix « Spin BlobCache » déjà noté comme résolu.
- **`stage0_init_all_steps(kernel_a_boot)`**, le chemin *réellement exécuté* au boot (`kernel/src/lib.rs:284`) : aucune écriture physique brute (`write_volatile`/`copy_nonoverlapping`) hors des allocations `buddy::alloc_pages` ou des accesseurs bornés du module `ssr`.

Tout ceci confirme que la piste « bug bête dans le fork/CoW/loader » est bien morte, comme vous l'aviez déjà établi avec vos détecteurs in-kernel.

---

## 2. Deux bugs réels et nouveaux, confirmés par lecture de code

### 2.1 Fuite des PML4 shadow KPTI (confirmée, à corriger)

`kernel/src/memory/virtual/page_table/kpti_split.rs::build_user_shadow_pml4` appelle `buddy::alloc_page(AllocFlags::ZEROED)` pour créer une nouvelle table PML4 « shadow ». Cette fonction est appelée à **deux endroits distincts**, sans jamais libérer la valeur précédente :

- `scheduler/core/switch.rs:425-448` — construction *lazy*, une fois par thread, mise en cache dans `next.kpti_user_cr3()`.
- `process/lifecycle/exec.rs:300` (`build_exec_kpti_shadow`) — reconstruction **systématique à chaque `execve()`**, puis `thread.sched_tcb.set_kpti_user_cr3(exec_kpti_user_cr3)` qui **écrase** l'ancienne valeur sans la libérer.

J'ai vérifié par `grep` exhaustif qu'aucun `free_pages`/`free_addr_space` n'est jamais associé à `kpti_user_cr3` dans tout le noyau. Chaque `fork()`+`execve()` orpheline donc une page physique de 4 KiB.

**Impact sur #25** : ce n'est *a priori* pas la cause de la corruption observée (la shadow orpheline n'est plus jamais chargée dans CR3, donc elle est inerte une fois remplacée ; et le volume — quelques pages sur la poignée de services du boot — est trop faible pour expliquer un SEGV aussi précoce). C'est en revanche une vraie fuite à corriger, et elle a une odeur de famille avec #25 : c'est exactement le genre d'endroit qui devient dangereux le jour où KPTI est actif (cf. 2.2 et 3.1).

**Fix proposé** : libérer l'ancienne `kpti_user_cr3` (si non nulle et différente de la nouvelle) juste avant de la réécrire dans `exec.rs` et dans `switch.rs`, via `buddy::free_pages(Frame::from_start_address(PhysAddr::new(old)), 0)`.

### 2.2 `is_b_region()` a une fenêtre de 2 Go au lieu de la taille réelle du noyau (confirmée, à corriger — mais probablement inactive dans votre repro)

`kernel/src/exophoenix/sentinel.rs:31-32` :

```rust
const B_REGION_PHYS_BASE: u64 = KERNEL_LOAD_PHYS_ADDR;                    // 0x100000 (1 Mio)
const B_REGION_PHYS_END: u64 = KERNEL_LOAD_PHYS_ADDR + KERNEL_IMAGE_MAX_SIZE as u64; // +2 Gio
```

`KERNEL_IMAGE_MAX_SIZE` (`memory/core/layout.rs:155`) vaut **2 GiB** — c'est une borne haute de *budget de lien*, pas la taille réelle de l'image chargée. `is_b_region(pa)` retourne donc `true` pour **toute** adresse physique entre 1 Mio et ~2049 Mio, c'est-à-dire la quasi-totalité de la RAM normalement allouée par le buddy allocator à des processus ordinaires (la pile d'init y compris).

`walk_a_page_tables_iterative()` (appelée toutes les 10 ms par `sentinel::run_forever()`) utilise cette fonction pour scorer une « anomalie PA_REMAP » (+90 points, **par entrée de table rencontrée**) dès qu'un PDPT/PD/PT/page-feuille tombe dans cette plage — ce qui arrive pour à peu près n'importe quelle table de pages d'un processus normal. Le seuil `THREAT_THRESHOLD` est de 100 : un seul parcours des tables d'un processus réel le dépasserait très largement, déclenchant `handoff::begin_isolation_soft()`, qui :

- diffuse un IPI freeze, fait du *soft/hard revoke IOMMU* ;
- en cas d'échec d'ACK : appelle `begin_isolation_hard()`, qui exécute **`scan_and_release_spinlocks()`** — une libération forcée de *tous* les spinlocks du noyau, susceptible de produire exactement le genre d'accès concurrent non synchronisé (donc invisible à vos détecteurs buddy/CoW) qui correspond au profil de #25.

**Pourquoi je ne le mets pas en cause n°1 malgré la ressemblance frappante avec votre hypothèse ExoPhoenix** : j'ai tracé l'appelant. `sentinel::run_forever()` n'est invoqué que depuis `stage0_init()` (`exophoenix/stage0.rs:1163-1193`), qui est **le point d'entrée dédié au cœur Kernel B** (`kernel_a_boot=false`), lui-même responsable de faire un SIPI pour démarrer Kernel A sur un *autre* cœur. Le chemin de boot réellement utilisé par votre repro (`lib.rs:284`, `stage0_init_all_steps(true)`) ne passe jamais par `stage0_init()` et ne lance donc jamais la boucle sentinelle.

**Donc** : ce bug est réel et doit être corrigé (`is_b_region` doit comparer à la taille réelle de l'image chargée, pas à `KERNEL_IMAGE_MAX_SIZE`), mais il n'explique probablement **pas** la corruption observée *si et seulement si* votre Bochs/QEMU de repro tourne réellement en mono-cœur sans jamais SIPI un second cœur Kernel B. **À vérifier en une commande** : grep le log de boot pour un second cœur démarré / pour la chaîne `stage0_init` exécutée, ou comptez le nombre de cœurs réellement configurés dans votre `.bochsrc`/ligne de commande QEMU pour CE test précis. Si jamais un second cœur tourne, ce bug remonte immédiatement en priorité n°1.

---

## 3. Pourquoi je n'ai pas trouvé d'écriture sauvage « fumante » par lecture seule

J'ai creusé en détail plusieurs autres mécanismes qui correspondent au profil recherché (écriture CPU directe, hors alloc/free, asynchrone) :

- **`handle_pmc_snapshot_ipi`/`handle_freeze_ipi`** (`exophoenix/interrupts.rs`) écrivent bien par adresse physique brute via `ssr::SSR_BASE + offset`, mais restent confinées à la fenêtre SSR de 64 Kio à 16 Mio (`SSR_PHYS_BASE = 0x0100_0000`) — qui ne recoupe pas la zone ~87-91 Mio où vous situez Fa.
- **`forge::reconstruct_kernel_a()`** parse/valide/hash l'image propre de Kernel A mais — à la lecture du code fourni — **ne réécrit jamais réellement les sections `.text/.rodata/.data` en mémoire physique** ; le fichier porte d'ailleurs des marqueurs explicites `[ADAPT]` suggérant une implémentation passerelle/incomplète. Cette fonction n'est de toute façon, comme ci-dessus, jamais atteinte par le chemin de boot Kernel-A-seul.
- **`kpti_split::sync_user_region_to_shadow`** ne copie que des *pointeurs* de niveau PML4 (256 entrées × 8 octets), jamais le contenu des pages feuilles, et le fait dans une structure qui n'est pas activement chargée en CR3 pendant qu'on l'écrit (le cœur tourne en Ring 0 sur la PML4 « réelle » à ce moment). Je ne vois pas comment cela corromprait le contenu de Fa directement, malgré la ressemblance structurelle frappante avec le profil recherché.

Aucune de ces pistes ne m'a donné de preuve définitive par lecture seule — ce qui recoupe honnêtement votre propre expérience : c'est précisément pour cela que vos sessions précédentes ont dû basculer sur de l'instrumentation dynamique (checksums in-kernel) plutôt que sur le seul raisonnement statique.

---

## 4. Plan d'action prioritaire

1. **Lisez la sortie de la bissection déjà implémentée.** `do_execve()` (`exec.rs`) contient déjà trois points de contrôle `diag25_check_init(b"postelf"|b"postcr3"|b"postTD")` qui comparent un checksum en direct du contenu de la pile d'init (`buddy.rs::diag25_check_init`, lecture volatile + somme pondérée — donc sensible à *toute* écriture, pas seulement aux opérations qui passent par l'allocateur). Rien dans le code fourni n'indique que cette instrumentation a été *exécutée et son log lu* dans la session la plus récente. C'est la vérification la moins chère et la plus directe possible :
   - Corruption déjà visible à **`postelf`** → le suspect est dans `load_elf`/`install_elf_image` (je l'ai audité et il me semble propre, mais une exécution réelle est plus probante que ma relecture) ou plus tôt, dans le code utilisateur exécuté par l'enfant entre le retour de `vfork()` et l'appel `execve()`.
   - Apparaît entre **`postelf` et `postcr3`** → suspect : `build_exec_kpti_shadow`/KPTI (si KPTI est actif — vérifiez `feat.rdcl_no()` sur le CPU émulé : un Core2 Penryn Bochs ou un CPU QEMU par défaut ne expose généralement pas `IA32_ARCH_CAPABILITIES`, donc **KPTI est très probablement actif dans votre repro**, contrairement à l'hypothèse « KPTI off, fixes no-op » notée le 13/06 — à reconfirmer en loggant `kpti_enabled()` au boot).
   - Apparaît entre **`postcr3` et `postTD`** → suspect : `free_addr_space`/`free_userspace_tables` (que j'ai audité et que je crois correct, mais encore une fois, mieux vaut une preuve d'exécution).
   - Aucune corruption aux 3 points → la fenêtre se referme *après* `notify_vfork_completion()`, donc côté scheduler/interruption pendant que init tourne réellement, pas pendant l'exec de l'enfant lui-même : il faudrait étendre la bissection après le réveil d'init.

2. **Confirmez l'état réel de KPTI au boot du repro** (`log::info!("KPTI: {}", kpti_enabled())` juste après `apply_mitigations_bsp()`). C'est gratuit et lève une ambiguïté entre deux notes contradictoires (note du 13/06 : KPTI off ; ma lecture de `should_enable_kpti()`/`rdcl_no()` suggère qu'il devrait être *on* sur les CPU émulés Bochs/QEMU typiques).

3. **Confirmez le nombre de cœurs réellement démarrés** dans votre config de repro exacte. Si ≥ 2 et que `stage0_init()`/`sentinel::run_forever()` tourne effectivement, corrigez `is_b_region()` (§2.2) en priorité absolue et re-testez — c'est un correctif d'une ligne avec un mécanisme de déclenchement très plausible.

4. **Corrigez la fuite KPTI (§2.1)** dans la foulée — sans rapport certain avec #25, mais sans risque et nécessaire avant toute investigation plus poussée de KPTI, pour ne pas mélanger les symptômes.

5. Si après (1)-(4) la corruption persiste et se confirme entre `postcr3`/`postTD` avec KPTI actif, l'étape suivante est d'instrumenter spécifiquement `sync_user_region_to_shadow` et `build_user_shadow_pml4` (checksum avant/après comme pour `diag25_check_init`) plutôt que de continuer à élargir l'audit statique — c'est le seul mécanisme restant qui écrit directement des entrées de table de pages en dehors du chemin CoW déjà totalement innocenté.

---

## 5. Limites de cet audit

- Le crate `libs/exo-phoenix-ssr` est absent de l'archive : je n'ai pas pu vérifier les valeurs exactes de `A_LIVENESS_MIRROR_OFFSET`, `pmc_snapshot_offset()`, `SSR_MAX_CORES_LAYOUT`, etc. Si vous l'ajoutez, je peux recroiser ces constantes avec les adresses ~87-91 Mio observées.
- Aucune exécution réelle n'a été possible (toolchain Rust nightly et QEMU/Bochs absents du bac à sable, et build impossible de toute façon sans le crate manquant). Tout ce qui précède est donc une démonstration de cohérence/incohérence par lecture, pas une preuve empirique.
