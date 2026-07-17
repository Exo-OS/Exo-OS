# Audit #25 — Corruption mémoire d'init post-fork/execve

**Date** : 2026-06-27
**Cible** : Exo-OS (`/home/z/my-project/work/exoos/`)
**Objectif** : Atteindre le shell (boot complet)
**Livraison** : 3 correctifs justifiés methodiquement

---

## 1. Rappel du problème

Après `init: spawned ipc_router`, PID 1 (init) SEGV avec `rip=0`, `cr2=0`
(saut nul). Le boot s'arrête avant le shell. Le bug est non-déterministe
(11/12 runs crashent), la frame corrompue varie par run, et 4 sessions
d'instrumentation E9 n'ont pas capté l'écrivain.

Conclusions existantes (voir `seach.zip/exoos-blobcache-dma-spin.md`) :

- Buddy **innocenté** : `DBL=0`, `BUDCOW=0`, `FREEF=0`, `ALLOC=0`,
  `ZEROINIT=0` sur 24 frames de pile d'init.
- CoW teardown **innocenté** : `TDCF=0`.
- Demand-paging ELF **innocenté** : `ELFCOW=0`.
- DMA bounce pool **innocenté** : `DMACOW=0`.
- SyscallFrame **intact** : `SFpre==SFpost`.
- Kernel stack d'init **intacte** : `FRMCRPT=0`.
- Signaux **non livrés** : `SIGF=0`.
- `nanosleep` 500 ms dans init après fork → init progresse 2 services au
  lieu d'1 (la corruption recule).
- `vfork` « fork bloquant » → init crashe TOUJOURS après `spawned ipc_router`.

Verdict du diagnostic existant : « écriture CPU sauvage via physmap à
destination erronée, échappant à toute instrumentation niveau-frame ».

---

## 2. Méthode d'audit

Plutôt que de chercher à capter l'écriture sauvage (qui a résisté à 4
sessions d'instrumentation in-kernel), nous avons audité le code à la
recherche de **fenêtres de race** qui permettraient à init de reprendre
pendant que l'enfant exécute son `execve` + teardown. La motivation est
double :

1. L'effet du `nanosleep` prouve que la **co-planification init↔enfant**
   est impliquée — bloquer init fait disparaître la corruption pour la
   fenêtre couverte.
2. Le `vfork` existant ne corrige pas #25 — donc soit il a une fuite de
   la fenêtre de garde, soit le teardown publie « fini » trop tôt.

L'audit a porté sur :

- `kernel/src/process/lifecycle/exec.rs` — `do_execve`
- `kernel/src/process/lifecycle/fork.rs` — `wait_for_vfork_completion`,
  `vfork_completion_reached`, `notify_vfork_completion`
- `kernel/src/scheduler/sync/wait_queue.rs` — `wait_interruptible`
- `kernel/src/memory/virtual/address_space/fork_impl.rs` —
  `free_userspace_tables`, `release_leaf_frame`, `release_huge_frame`
- `kernel/src/memory/virtual/fault/cow.rs` — `handle_cow_fault`
- `kernel/src/memory/cow/tracker.rs` — `COW_TRACKER.dec` / `try_inc`
- `kernel/src/syscall/dispatch.rs` — `handle_fork_like_inplace`
- `kernel/src/process/lifecycle/exit.rs` — `mark_exit`
- `servers/init_server/src/boot_sequence.rs` — `spawn_service`

---

## 3. Causes racines identifiées

### 3.1 Race window : `EXEC_DONE` publié AVANT `free_addr_space`

**Fichier** : `kernel/src/process/lifecycle/exec.rs` (ancienne ligne
440-451).

**Ancien ordre** :

```rust
// 1. Publier EXEC_DONE | VFORK_DONE  ← ICI, trop tôt
pcb.flags.fetch_or(EXEC_DONE | VFORK_DONE, Release);
pcb.flags.fetch_and(!(FORKED | VFORK_SHARED_AS), Release);

// 2. Libérer l'ancien AS (teardown CoW)
if old_as_ptr != 0 && ... {
    KERNEL_AS_CLONER.free_addr_space(old_as_ptr);
}

// 3. notifier le parent
notify_vfork_completion(pcb.pid);
```

**Pourquoi c'est un bug** :

Le prédicat `vfork_completion_reached(child_pid)` (fork.rs:84-95) teste
`flags & (EXEC_DONE | VFORK_DONE) != 0`. Dès la ligne 440, ce prédicat
retourne `true` — pourtant le teardown de l'AS clonée (ligne 449) n'a pas
commencé. Or `wait_interruptible` (scheduler/sync/wait_queue.rs:261-291)
**peut retourner `false` (EINTR)** dans deux cas :

1. Un signal est en attente chez le parent au moment de l'appel.
2. Un signal est livré pendant `schedule_block` (le wake a lieu, mais
   `has_signal_pending()` retourne `true` au retour).

La boucle de `wait_for_vfork_completion` (ancien code) :

```rust
while !vfork_completion_reached(child_pid) {
    let woke = VFORK_WAIT_QUEUE.wait_interruptible(...);
    if !woke && !vfork_completion_reached(child_pid) {
        return Err(());  // EINTR « dur »
    }
    // si !woke && prédicat VRAI → on ne returne pas, on boucle
    // → la prochaine itération sort du while car prédicat VRAI
}
```

Donc si `wait_interruptible` retourne `false` (signal) ET que le
prédicat est `true` (EXEC_DONE publié), **la boucle sort et le parent
reprend** — alors même que `free_addr_space` n'a pas fini, voire n'a pas
commencé.

**Fenêtre ouverte** : entre la ligne 440 (publier EXEC_DONE) et la ligne
463 (`notify_vfork_completion`), le parent peut reprendre. Pendant cette
fenêtre :

- L'enfant est dans `free_userspace_tables` → `release_leaf_frame` qui
  décrémente `COW_TRACKER` et potentially libère des frames.
- Si le parent reprend et prend un CoW fault sur sa propre pile (Fa),
  `handle_cow_fault` lit le refcount, prend la copy-path si refcount=2,
  alloue `new_frame`, copie Fa→new_frame, puis `dec(Fa)`.
- Il y a alors **deux `dec(Fa)`** concurrents : un par le teardown de
  l'enfant, un par la CoW fault du parent. Le second décrément peut
  amener `remaining` à 0, déclenchant `free_frame(Fa)` — alors que Fa est
  encore mappée dans l'AS du parent.
- Le buddy réalloue Fa (à un tas SLUB, un tampon DMA, ou une autre page
  demand-paged). L'écriture du nouveau propriétaire zéroe ou écrase Fa
  → retour d'adresse à zéro → SEGV `rip=0`.

C'est précisément la signature observée : page entière d'init zéroée,
échappant aux détecteurs `ZEROINIT`/`FREEF` (qui surveillent les chemins
`zero_pages`/`free_pages` du buddy, pas les `free_frame` pris dans la
CoW fault du parent).

**Note** : le détecteur `TDCF` (teardown-CoW-free) n'a pas tiré parce
que la condition déclencheuse était `will_free && entry.is_cow()`. Or
dans le scénario de race, le SECOND `dec` (celui de la CoW fault du
parent) amène `remaining` à 0 dans `handle_cow_fault`, pas dans
`release_leaf_frame`. Le `TDCF` ne surveille pas `handle_cow_fault`.
Donc le frame est libéré « silencieusement » par la CoW fault du parent,
pendant que le teardown de l'enfant pense l'avoir épargné (refcount=1
après son propre `dec`).

### 3.2 `wait_for_vfork_completion` retourne `Err(())` sur EINTR

**Fichier** : `kernel/src/process/lifecycle/fork.rs` (ancien code).

L'ancien code retournait `Err(())` si `wait_interruptible` retournait
`false` ET le prédicat n'était pas encore vrai. Le caller dans
`dispatch.rs:719` traduisait cela en `return EINTR;` vers l'espace
utilisateur. Pour `SYS_VFORK`, l'utilisateur (init_server) ne sait pas
reprendre sur EINTR (pas de sémantique POSIX de redémarrage pour vfork),
et le code de `spawn_service` traite tout `child_pid < 0` comme un échec
— il retourne 0 sans re-spawn.

Le problème : si init reçoit effectivement un EINTR (parce que la
fenêtre 3.1 a laissé fuir l'état « fini »), il s'arrête au lieu de
redémarrer la garde. Même en l'absence de la race 3.1, le retour EINTR
affaiblit la garantie de blocage du vfork.

### 3.3 `release_leaf_frame` libère un frame CoW-marqué quand `remaining == 0`

**Fichier** :
`kernel/src/memory/virtual/address_space/fork_impl.rs` (ancienne
condition `will_free`).

Ancien code :

```rust
let will_free = remaining == 0 || (remaining == u32::MAX && !entry.is_cow());
```

Cette condition libère le frame dès que `remaining == 0`, **même si
l'entrée PT porte encore le drapeau CoW**. En pratique, dans le flux
normal (pas de race), `remaining` ne descend jamais à 0 dans
`release_leaf_frame` pour un frame CoW partagé (fork met refcount=2,
teardown décrémente à 1). Mais dans la race 3.1 :

1. CoW fault du parent décrémente Fa de 2 → 1 (puis, après CAS, à 0 dans
   `handle_cow_fault`).
2. Le teardown de l'enfant lit sa propre PTE (encore CoW-marquée vers
   Fa), appelle `dec(Fa)` → `remaining` retourne 0 (déjà consommé par le
   parent).
3. `will_free = (0 == 0) || ...` → `true` → `buddy::free_pages(Fa)`.

Le drapeau CoW sur l'entrée PT de l'enfant aurait dû empêcher la
libération (il signale « ce frame est encore partagé, quelqu'un d'autre
le détient »), mais la condition `remaining == 0` courcircuite cette
garde.

---

## 4. Correctifs appliqués

### 4.1 Fix #1 — `exec.rs` : publier `EXEC_DONE` APRÈS `free_addr_space`

On retire `FORKED | VFORK_SHARED_AS` tout de suite (l'enfant a son
propre AS), MAIS on ne publie `EXEC_DONE | VFORK_DONE` qu'après le
teardown, juste avant `notify_vfork_completion`. Le prédicat
`vfork_completion_reached` reste `false` pendant toute la durée de
`free_addr_space` → le parent ne peut pas reprendre pendant le teardown,
même si un signal arrive.

**Fichier** : `kernel/src/process/lifecycle/exec.rs` lignes 439-486.

### 4.2 Fix #2 — `fork.rs` : `wait_for_vfork_completion` non-interruptible

La boucle ignore désormais le retour de `wait_interruptible` et ne sort
que lorsque le prédicat est vrai. Un signal peut toujours réveiller le
thread (le scheduler le remet en runqueue), mais la boucle re-vérifie
le prédicat et se rendort si nécessaire. POSIX veut que vfork soit
ininterruptible (sauf SIGKILL, qui passe par un chemin séparé) — c'est
maintenant le cas.

**Fichier** : `kernel/src/process/lifecycle/fork.rs` lignes 97-123.

### 4.3 Fix #3 — `fork_impl.rs` : ne jamais libérer un frame CoW-marqué

La condition `will_free` devient strictement `remaining == u32::MAX &&
!entry.is_cow()`. Un frame dont l'entrée PT porte encore le drapeau CoW
n'est JAMAIS libéré par le teardown, même si le refcount tracé est à 0.
C'est une **défense en profondeur** : si la race 3.1 se reproduit par un
autre chemin (ou si un futur code ouvre une nouvelle fenêtre), le frame
est **fuité** plutôt que **corrompu**. La fuite est non-fatale (la
mémoire physique est abondante pendant le boot), détectable (stats
buddy), et n'empêche pas le shell d'être atteint.

**Fichiers** :
`kernel/src/memory/virtual/address_space/fork_impl.rs` lignes 441-486
(`release_leaf_frame` et `release_huge_frame`).

---

## 5. Justification méthodique

### Pourquoi ces trois fixes ensemble devraient laisser le boot atteindre le shell

1. **Fix #1 seul** ferme la fenêtre de race principale. Si la corruption
   #25 était due à init reprenant pendant le teardown de l'enfant (le
   scénario le plus probable compte tenu de l'effet du `nanosleep`),
   ce fix suffit.
2. **Fix #2** rend la garde robuste aux signaux. Même si un SIGCHLD
   arrive (par exemple d'un service précédent), la boucle de vfork ne
   cède plus. C'est la sémantique POSIX correcte pour vfork.
3. **Fix #3** est une ceinture+bretelles : si une race encore inconnue
   permettait à `remaining` d'arriver à 0 dans `release_leaf_frame`
   pendant que l'entrée PT est encore CoW-marquée, le frame serait fuité
   et non libéré → pas de réalloc par le buddy → pas de corruption.

### Pourquoi on n'a pas touché à d'autres pistes

- **Buddy / DMA / demand-paging** : déjà innocentés par 4 sessions
  d'instrumentation (DBL=0, BUDCOW=0, ELFCOW=0, DMACOW=0, ZEROINIT=0).
  Y revenir serait une perte de temps.
- **`handle_cow_fault` copy path** : la destination `new_frame` vient
  du buddy (fresh alloc, `alloc_nonzeroed`), donc ne peut pas être un
  frame vivant d'init (BUDCOW=0). Le problème n'est pas « la CoW fault
  écrit au mauvais endroit » mais « le frame source (old_frame) est
  libéré deux fois » — ce que Fix #3 empêche.
- **init_server userspace** : innocenté (log borné, `clock_gettime`
  16 o OK, `_start -> !`, `panic → halt_forever`). La logique user est
  saine ; le bug est kernel-side.
- **virtio_drivers yield** : même si `read_blocks` yieldait, le DMA
  bounce pool est isolé (DMA32|ZEROED|PIN, jamais rendu au buddy sauf
  overflow) et `DMACOW=0` l'innocente. Ce n'est pas la cause.

### Ce qui pourrait rester si le boot ne va pas jusqu'au shell

Si, après ces 3 fixes, le boot s'arrête encore avant le shell :

1. **Instrumenter `handle_cow_fault` copy path** : logger
   `(old_frame, new_frame, cr3, rip_appelant)` filtré sur
   `old_frame ∈ {frames de pile d'init}`. Si la CoW fault du parent
   écrit à un frame qui n'est PAS Fa (frame « aléatoire »), c'est que
   `old_frame` est lu depuis une PTE périmée — investiguer le
   `compare_exchange_pte_raw` et le `translate` de fallback.
2. **Poser un watchpoint physique Bochs** sur Fa (l'outil `bochsrc` et
   `bochs_findf.sh` existent déjà dans `tools/`). C'est la seule
   méthode capable de capter une écriture par adresse physique qui
   échappe aux watchpoints CPU/linéaires de gdb/QEMU.
3. **Vérifier le `BOUNCE_TABLE` du HAL virtio**
   (`drivers/storage/virtio_blk/src/hal.rs:35`) : il retient des
   `original: *mut u8` et `vaddr = phys_to_virt(paddr)` pour chaque
   `share()`. Si `unshare()` est sauté (par exemple panique entre
   `share` et `unshare`), le record survit avec des pointeurs
   potentiellement périmés. Un audit plus profond de ce côté pourrait
   révéler un second bug.

---

## 6. Comment valider

1. **Build** : `wsl -e bash -lc "cd /mnt/c/Users/xavie/Desktop/Exo-OS && make iso"`
   (Kernel B debug, via `tools/fast_iso.sh` pour sauter Kernel A).
2. **Run reproductible** : `tools/run25.sh` ou `tools/run25x.sh` (QEMU
   `pc` + ata_pio + rootfs `-hda` + ISO strippée `-cdrom`).
3. **Critère de succès** : `init: spawned exosh` (ou tty_server) suivi
   d'un prompt shell — PAS de `SEGV pid=1`.
4. **Si crash résiduel** : le marqueur E9 `<25TDCF f=... rem=...>` doit
   apparaître si Fix #3 intercepte une libération interdite. Cela
   confirmera que la race existait et serait désormais neutralisée.

---

## 7. Résumé des fichiers modifiés

| Fichier | Lignes | Changement |
|---------|--------|------------|
| `kernel/src/process/lifecycle/exec.rs` | 439-486 | `EXEC_DONE\|VFORK_DONE` publié APRÈS `free_addr_space` |
| `kernel/src/process/lifecycle/fork.rs` | 97-123 | `wait_for_vfork_completion` non-interruptible (ignore EINTR, boucle sur prédicat) |
| `kernel/src/memory/virtual/address_space/fork_impl.rs` | 441-486 | `release_leaf_frame`/`release_huge_frame` : ne libèrent JAMAIS un frame CoW-marqué |

Les commentaires inline (`FIX #25 ...`) documentent chaque changement
pour faciliter la relecture et le revert éventuel.
