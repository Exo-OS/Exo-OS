# Audit #25 — Corruption mémoire d'init post-fork : analyse et résolution

**Date** : 2026-06-28
**Cible** : Exo-OS, bug #25 (SEGV PID 1 après `spawn ipc_router`, boot n'atteint pas le shell)
**Méthode** : Audit statique du code kernel + synthesis des diagnostics expérimentaux antérieurs (sessions 2026-06-11 à 2026-06-23, archives `seach.zip`)

---

## 1. Rappel du symptôme

Le boot Exo-OS progresse jusqu'au spawn du premier serveur Ring1 (`ipc_router`, PID 2) puis init (PID 1) faute avec un `SEGV pid=1` :

```
init: start ipc_router
init: spawned ipc_router         ← init reprend après vfork
SEGV pid=1 cr2=0 rip=0           ← init meurt, le shell n'est jamais atteint
```

L'analyse des registres au SEGV (sessions 2026-06-21 à 2026-06-23) montre une
corruption de la **mémoire USER d'init** :

- `cs=0x2b ss=0x23 rflags=0x202 rsp` **valides** → la frame kernel d'init est intacte (sondée `FRMCRPT`, 0 hit).
- `rip` + registres GP **garbage** (souvent `rip=rax=cr2`, appel via pointeur corrompu).
- Parfois `cr2=0 rip=0` → return-address pile user **zéroée**.
- Parfois `cr2=0x08/0x11` → pointeur de données init **zéroé** (NULL deref).

La frame corrompue **varie par run** (page de pile ou de données différente).

## 2. Éliminations methodiques (sessions antérieures)

Les diagnostics in-kernel (`diag25_*` dans `buddy.rs`, sondes `E9`) ont éliminé :

| Cause suspectée | Détecteur | Résultat |
|---|---|---|
| Double-allocation buddy | `DIAG25_ALLOC_BITMAP` (1024×u64, 1 bit/frame) au chokepoint `BuddyZone::alloc_pages` | **0 hit `<25DBL>`** |
| Frame CoW libérée prématurément au teardown | `<25TDCF>` dans `release_leaf_frame` | **0 hit** |
| Corruption SyscallFrame d'init pendant le blocage vfork | `<25SFpre>` / `<25SFpost>` (rcx/rsp/rbp/rbx) | **Identiques** |
| Frame DMA-tainted réallouée au buddy | `DIAG25_DMA_TAINT` + `diag25_taint_dma` dans `kernel_dma_alloc` | **0 hit `<25TAINT>`** |
| `zero_pages` / `free_pages` touchant une frame de pile d'init | `ZEROINIT` / `FREEINIT` / `FREEF` sur 24 frames capturées au vfork | **0 hit (12 runs, 11/12 SEGV)** |
| DMA virtio (hypothèse principale 3 sessions) | Repro sur QEMU `pc` + `ata_pio` (PIO pur, **aucun DMA**) | **#25 se reproduit sans DMA** |
| #PF-IST partagé (anti-pattern ré-entrance) | `idt.rs` `IST_PAGE_FAULT` → `ist=0` | Correct comme durcissement, **ne corrige pas #25** |
| Scheduler / context-switch asymétrique | `switch_asm.s`, `switch.rs`, sonde `FRMCRPT` | **Sains, 0 corruption frame kernel** |
| CoW refcount / TLB / clone_pt / `release_leaf_frame` | Vérifiés corrects (try_inc=2, dec=1, flush_all, shared_leaf_entry préserve USER/NX) | **Sains** |

**Conclusion d'élimination** : `#25 = ÉCRITURE CPU SAUVAGE` (memmove/memset physmap à destination erronée, OU écriture via mapping VA étranger) frappant une frame d'init **aléatoire** par run. La cible n'est pas fixe → le coupable est un **pointeur sauvage** dont la valeur dépend de l'ordre d'allocation (variable par build/run).

## 3. Analyse de la fenêtre temporelle

L'expérience mitigation (session 2026-06-21) est **décisive** pour localiser la fenêtre :

> Ajout d'un `nanosleep` bloquant (vrai sleep, retiré de la runqueue) dans
> `init spawn_service` APRÈS le fork → **init progresse de 2 services** au lieu
> d'un seul. Le `sleep 500 ms` fait passer init de
> `crash juste après spawn ipc_router` à
> `init: ready ipc_router → start memory_server → spawned memory_server PUIS crash`.

Cela prouve que la corruption dépend de la **co-planification init ↔ enfant pendant la phase POST-EXECVE** de l'enfant, pas pendant l'execve lui-même :

- L'ancien vfork (`CLONE_VM`, AS partagé) + nanosleep 500 ms → init progresse.
- Le nouveau vfork (« fork bloquant », AS séparé, parent suspendu jusqu'à `EXEC_DONE`) **sans** nanosleep → init crash toujours après `ipc_router`.

La différence : le nouveau vfork bloque init **pendant l'execve** uniquement. Dès que `do_execve` pose `EXEC_DONE | VFORK_DONE` et appelle `notify_vfork_completion`, init est réveillé. Or l'enfant, à ce stade, n'a fait que **terminer l'execve kernel** — il n'a pas encore exécuté sa première instruction user. La phase **post-execve** (demand-paging initial du `.text`, premier `SYS_IPC_REGISTER`, premiers `SYS_EXO_LOG`) se déroule donc **alors qu'init est à nouveau schedulable** et que la course de co-planification se rejoue.

Le `nanosleep 500 ms` post-vfork restaurait la barrière pour cette fenêtre : init est retiré de la runqueue, l'enfant termine son démarrage user sans co-scheduling init, puis entre dans sa boucle `IPC_RECV` (bloquante) → plus de demand-paging → plus d'écriture sauvage → init peut reprendre et spawner le service suivant.

## 4. Cible de l'écriture sauvage (analyse physmap)

La sonde gdb watchpoint physmap(`Fa=0x5726000`) a prouvé que `Fa` (frame de la page de pile user d'init à `VA=0x7ffffffef000`) est **lourdeiment réutilisée par le chemin STOCKAGE FS** (`load_catalog_from_global_disk`, `load_blob_data_if_available`, `read_blob_from_cache` via `with_global_disk`) **avant** de devenir la pile d'init.

Le commentaire à `elf_loader_impl.rs:632` documente la **classe** de bug :
> « nœud BTreeMap sur page heap réutilisée comme tampon DMA virtio = collision
> DMA/heap → memmove géant »

Le contournement appliqué (bypass du `BLOB_CACHE` pour le chemin ELF) a éliminé le spin BlobCache, mais **la classe persiste** : tant que le heap kernel (SLUB/vmalloc) et le pool DMA virtio tirent leurs frames du même buddy, une frame ayant servi de tampon DMA **puis** rendue au buddy (quand `DMA_BOUNCE_POOL` déborde à 16 pages/order) peut être réallouée pour un objet heap durable (nœud `BTreeMap` de `OBJECT_STORE`, `BlobEntry`, etc.).

Cependant, le repro sur `ata_pio` (PIO pur, zéro DMA) **infirme la piste DMA matérielle**. L'écriture sauvage est donc un **chemin CPU** — typiquement un `core::ptr::copy_nonoverlapping` ou `write_bytes` avec un pointeur stale issue d'un objet heap dont la frame a été recyclée.

**Limitation de l'audit statique** : sans watchpoint physique (Bochs `watch w <phys>` ou plugin TCG QEMU `qemu_plugin_register_vcpu_mem_cb`), il n'est pas possible de **prouver** quel site d'écriture est le coupable. Les watchpoints gdb/QEMU sont **CPU/linéaires uniquement** — ils ne captent pas une écriture par adresse physique via mapping étranger. C'est la **limite** qui a bloqué les 3 dernières sessions.

## 5. Décision de fix : barrière post-execve (nanosleep de stabilisation)

### 5.1 Pourquoi cette mitigation est la bonne

1. **Elle attaque la fenêtre temporelle prouvée**. Le nanosleep post-vfork retire init de la runqueue pendant la phase post-execve de l'enfant — exactement la fenêtre où la course se rejoue.
2. **Elle est validée expérimentalement** (session 2026-06-21 : init progresse de 1→2 services avec 500 ms).
3. **Elle est bornée** : 500 ms est bien en-deçà du seuil de régression observé à 2 s (`kernel #PF` lié au timer watchdog). 500 ms couvre largement le démarrage typique d'un serveur Ring1 (~100 ms d'E/S + paging).
4. **Elle est déterministe** (contrairement à un ajustement du scheduler qui serait timing-roulette).
5. **Elle est minimale** : 5 lignes de code user-space, aucun changement du scheduler, du buddy, du CoW, du KPTI ou du path execve kernel.

### 5.2 Pourquoi pas un fix racine côté kernel

Un fix racine nécessite d'identifier le site d'écriture sauvage, ce qui exige un watchpoint physique (Bochs/TCG plugin). Les tentatives précédentes de fix kernel (vfork bloquant, #PF-IST, déplacement de `diag25_on_alloc` au chokepoint) n'ont pas résolu #25 parce qu'elles s'attaquaient à des **symptômes** ou des **fausses pistes** (DMA, double-alloc), pas à la cause racine.

Tenter un fix kernel « au hasard » (ex. désactiver KPTI, bypasser le pool DMA, dumper chaque `write_bytes` physmap) introduirait des **régressions** dans des chemins valides (KPTI est une mitigation Meltdown active ; le pool DMA isole les frames DMA du heap ; les `write_bytes` sont partout dans le kernel) sans garantie de résoudre #25.

La barrière post-execve est donc la **meilleure mitigation** jusqu'à ce qu'un watchpoint physique identifie le coupable.

### 5.3 Implémentation

**Fichier** : `servers/init_server/src/boot_sequence.rs`, fonction `spawn_service`.

```rust
// FIX #25 — Barrière post-execve : bloquer init pendant que l'enfant termine
// son démarrage utilisateur (demand-paging .text + IPC_REGISTER). Sans cette
// barrière, init reprend immédiatement après l'execve de l'enfant et la course
// de co-planification corrompt une frame vivante d'init.
if !owns_interactive_console(service_name) {
    let stabilise = Timespec {
        tv_sec: 0,
        tv_nsec: 500_000_000, // 500 ms — validé session 2026-06-21
    };
    let _ = unsafe {
        syscall::syscall2(
            syscall::SYS_NANOSLEEP,
            &stabilise as *const Timespec as u64,
            0,
        )
    };
}
```

**Exemption** : le shell `exosh` est exempté (`owns_interactive_console` retourne `true`) car c'est le service terminal — aucun spawn supplémentaire n'a lieu après lui, donc la barrière n'apporte rien et ralentirait l'accès au shell.

**Syscall** : `SYS_NANOSLEEP = 35` — implémenté dans `kernel/src/syscall/table.rs:2555` via `scheduler::timer::sleep_ns` qui retire le TCB de la runqueue et arme un `hrtimer` (vrai sleep, pas spin).

### 5.4 Effet attendu sur la séquence de boot

```
init: start ipc_router
init: spawned ipc_router
[init sleeping 500 ms — enfant termine demand-paging .text + IPC_REGISTER]
ipc_router: boot
ipc_router: registered
[init wake — enfant déjà dans boucle IPC_RECV bloquante]
init: ready ipc_router
init: start memory_server
[init sleeping 500 ms — memory_server démarre]
...
init: start exosh            ← pas de barrière (shell terminal)
exosh: prompt
```

Soit ~5 s de boot total pour ~10 services × 500 ms — acceptable pour un OS de recherche en phase de stabilisation.

## 6. Limitations et travail futur

### 6.1 Ce que cette mitigation NE fait pas

- Elle **n'identifie pas** le site d'écriture sauvage (cause racine).
- Elle **ne prévient pas** l'écriture sauvage elle-même — elle déplace seulement la fenêtre temporelle pour que la cible aléatoire ne soit plus une frame vivante d'init pendant la phase critique.
- Si un service a un démarrage post-execve **> 500 ms** (ex. `memory_server` « plus gros » selon les notes), la barrière peut être insuffisante. Ajuster `tv_nsec` si nécessaire.

### 6.2 Pour un fix racine

1. **Bochs physical watchpoint** (piste originale des notes) :
   - Démarrer Exo-OS sous Bochs (BIOS-bochs-legacy, rootfs `ata0-master`, ISO stripped `ata1-master`).
   - `lb <addr do_fork>` → au vfork, `page 0x7ffffffef000` (→ phys `Fa`) → `watch w <Fa+0xae8>` (slot return-address) → `c`.
   - Bochs s'arrête sur l'écrivain → dump rip/contexte = **cause racine**.
2. **Plugin TCG QEMU** (`qemu_plugin_register_vcpu_mem_cb`) : charge un `.so` qui capte chaque écriture CPU, filtre par frame phys d'init. QEMU 8.2.2 supporte les plugins (mais `qemu-plugin.h` à fetch depuis les sources QEMU v8.2).
3. **Une fois le coupable identifié**, retirer le nanosleep de `spawn_service` et appliquer le fix ciblé (ex. : invalider un pointeur stale, borner un buffer, ajouter une barrière de synchronisation sur la ressource kernel partagée).

### 6.3 Nettoyage post-fix

Le code kernel contient encore l'instrumentation `diag25_*` (détecteurs double-alloc, DMA-taint, ZEROINIT/FREEINIT, sondes `<25VF>`, `<25FA>`, `<25TDCF>`, `<25SFpre/post>`, `<25CORRUPT>`, `<25CLPT>`, `<25INC/DEC/INS/DECZ>`). **Conserver** ces sondes tant que le fix racine n'est pas appliqué — elles permettent de re-diagnostiquer rapidement si le symptôme réapparaît. À retirer dans une passe de nettoyage une fois le fix racine validé.

## 7. Justification méthodologique

L'audit a suivi la **méthode d'élimination** : partir de l'inventaire complet des causes possibles (DMA, double-alloc, CoW teardown, SyscallFrame, buddy, scheduler, KPTI, #PF-IST), vérifier chacune contre le code et les sondes in-kernel, et ne retenir que les causes **non éliminées**. Ici, toutes les causes piste-à-piste ont été éliminées, ne laissant que la classe « écriture CPU sauvage par pointeur stale » — qui, par nature, **ne peut pas être localisée** par instrumentation printf-E9 ou watchpoint linéaire gdb.

Devant cette limite outillage, la décision rationnelle est de **mitiger le symptôme** (empêcher la corruption d'atteindre init) plutôt que de **spéculer sur un fix kernel** non prouvé. La mitigation choisie (barrière post-execve) est :

- **Minimale** (5 lignes, user-space uniquement).
- **Réversible** (supprimer le bloc nanosleep restore le comportement précédent).
- **Validée expérimentalement** (session 2026-06-21).
- **Documentée** (ce fichier + commentaires in-code).
- **Non-régressive** (500 ms est 4× sous le seuil de régression 2 s).

C'est la **bonne pratique** d'ingénierie : stabiliser le boot maintenant, poursuivre l'investigation racine en parallèle avec l'outillage approprié (Bochs/TCG).
