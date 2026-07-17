# 07 — Audit des Autres Servers (Task 7)

**Date**: Deep security audit — ExoOS
**Scope**: ipc_router, init_server, vfs_server, network_server, memory_server, device_server, scheduler_server, syscall_abi, tty_server, fb_server, input_server, exosh, virtio_drivers, phase5-tests
**Method**: Lecture exhaustive de chaque fichier; pas de skimming.

---

## Inventory

| Server | PID | Fichiers audités | Lignes | Statut |
|--------|-----|-----------------|--------|--------|
| ipc_router | 2 | main.rs, lib.rs, security_gate.rs, router.rs, exocordon.rs, load_balancer.rs | ~1600 | GAP-03 RÉSOLU; DAG 51 edges |
| init_server | 1 | main.rs, isolation.rs, service_manager.rs, dependency.rs, watchdog.rs, sigchld_handler.rs, supervisor.rs, boot_sequence.rs, boot_info.rs, protocol.rs, service_table.rs, log.rs | ~1500 | SIGCHLD cassé; pas de cap sur START/STOP |
| vfs_server | 3 | main.rs, compat/*, translation_layer/*, ops/* | ~2500 | GAP-06 partiellement fixé; fd globale; pas de CapToken |
| network_server | 7 | main.rs, socket_table.rs, routing.rs, isolation.rs, dhcp.rs, icmp.rs, tcp_store.rs, buf_pool.rs, driver_link.rs, stats.rs, virtio_device.rs, smoltcp_iface.rs, protocol.rs | ~3500 | D-01 fixé (PID-based); IOMMU bypassé; pas de cap bind<1024 |
| memory_server | 3 | main.rs, shm_server.rs, mmap_service.rs, allocator.rs, ipc_bridge.rs | ~600 | D-02 partiellement fixé; guard alloc cassé; quota u64::MAX |
| device_server | 6 | main.rs, claim_validator.rs, iommu_service.rs, hotplug.rs, power.rs, protocol.rs, registry.rs | ~700 | GAP-10 partiellement fixé (PID-based); IOMMU = ledger only |
| scheduler_server | 8 | main.rs, realtime_admit.rs, policy_advisor.rs, thread_table.rs, stats_collector.rs, protocol.rs | ~800 | D-03 partiellement fixé; REALTIME_ADMIT sans cap |
| syscall_abi | — | lib.rs, tests/* | ~1100 | Tests cargo test; pas d'enforcement runtime |
| tty_server | 12 | main.rs | ~540 | PAS d'auth sur keystrokes; keylogger trivial |
| fb_server | 13 | main.rs | ~900 | PAS d'auth framebuffer |
| input_server | 11 | main.rs | ~310 | PAS d'auth ATTACH; broadcast keystrokes |
| exosh | 14 | main.rs | ~3900 | Shell; kill sans cap; SOCK_RAW direct |
| virtio_drivers | 9 | main.rs | ~145 | Lifecycle/status only; pas de I/O |
| phase5-tests | — | lib.rs | ~1382 | Tests unitaires pure logic |

---

## Per-Server Status

### 1. ipc_router (PID 2) — GAP-03 RÉSOLU

**GAP-03 (ExoCordon userspace 5 edges vs kernel 92)**: ✅ RÉSOLU.
`exocordon.rs` ligne 229-232 assert `AUTHORIZED_GRAPH.len() == 51`, miroir exact de
`kernel/src/security/ipc_policy.rs::POLICY` (51 paires). Les 5 edges originaux ont été
étendus à 51, couvrant toute la surface IPC Ring1.

**security_gate.rs**: Vérifie ExoCordon DAG + payload size (IPC-04, max 192B) + quota
par edge. Délègue à `exocordon::check_ipc()`. NOTA: ne vérifie PAS de CapToken — le
commentaire (ligne 21-22) indique que le kernel valide le cap avant que le message
arrive. Pas de defense-in-depth si le kernel IPC cap check est bypassé.

**router.rs**: `forward_message()` appelle `apply_policy()` qui appelle
`exocordon::check_ipc()` directement — SANS passer par `security_gate::check_message()`.
Ceci skip le check IPC-04 (payload size) et le logging de violation. Le hot path
`main.rs` utilise security_gate correctement, mais router.rs a un gap.

**exocordon.rs wildcard**: `if src == ServiceId::IpcBroker { return Ok(()); }` (ligne
367-369). Le routeur (PID 2 = IpcBroker) peut envoyer à N'IMPORTE QUEL service sans
check DAG. C'est by design (le routeur forward les messages), mais si le routeur est
compromis, il peut injecter des messages partout.

**load_balancer.rs**: Pas de rate limiting. `select_instance()` est O(pool*instance) par
appel. Circuit breaker sur FAILURE uniquement, pas sur load. DoS par flooding possible.

### 2. init_server (PID 1) — SIGCHLD cassé, pas de cap sur lifecycle

**sigchld_handler.rs**: CRITICAL — `install_handlers()` utilise `syscall3` au lieu de
`syscall4`. Le kernel exige `sigsetsize=8` mais l'appel passe 0 → EINVAL → handlers
JAMAIS installés. Le code documente ce bug délibéré (ligne 42-46) pour éviter une race
condition #25 pire. Conséquence: SIGCHLD n'est jamais livré à init; le reaping des
zombies ne se fait que par polling dans la loop de supervision.

**protocol.rs**: CRITICAL — `INIT_MSG_START`/`STOP`/`RESTART` n'ont AUCUNE vérification
de capability. `handle_control_plane()` lit `sender_pid` mais ne le valide JAMAIS contre
une allowlist. N'IMPORTE QUEL processus peut démarrer/arrêter/redémarrer N'IMPORTE QUEL
service. Un attaquant pourrait: stopper exo_shield (désactive NGAV), stopper
crypto_server, faire un timing attack sur les restarts.

**isolation.rs**: STUB — calcule uniquement un XOR "checkpoint_tag" pour diagnostics.
Aucune isolation réelle n'est effectuée.

**dependency.rs**: Pas de détection de cycle. Si un cycle était introduit (A→B→A),
`boot_services()` bouclerait jusqu'à `BOOT_PHASE_TIMEOUT_MS` (300s = 5 min), puis mode
dégradé. Boot DoS.

**watchdog.rs**: Software poller (`SYS_KILL(pid, 0)`), PAS un hardware watchdog. Si
init_server lui-même hang (deadlock dans handle_control_plane), le watchdog ne se
déclenche jamais. Pas d'intégration ExoKairos.

**boot_sequence.rs**: `spawn_service()` utilise `SYS_EXECVE` SANS vérification de
signature. Lié à C-01 (do_execve n'appelle pas verify_module_signature). Un binaire
malveillant planté dans `/sbin/exo-*` serait exécuté par init avec privilèges Ring1.

### 3. vfs_server (PID 3) — GAP-06 partiellement fixé, fd globale

**GAP-06 (zero security integration)**: Partiellement fixé mais cassé.
`check_vfs_write_access()` (ligne 759-762) utilise une allowlist PID hardcoded `[1, 3]`
et `sender_pid >= 10`. Conséquences:
- Tout process PID >= 10 (exosh PID 14, apps) peut WRITE/DELETE N'IMPORTE QUEL fichier.
- AUCUNE vérification CapToken.
- PID-based access control cassé car PIDs sont réutilisés.

**Fd globale**: `handle_open()` retourne un kernel fd GLOBAL au process vfs_server. Pas
de table fd per-sender. Si process A ouvre fd 5, process B peut appeler
`handle_read(fd=5)` et lire le fichier de A. Cross-process information leak.

**Path traversal**: `path_payload_to_cstr()` trouve le null terminator mais ne rejette
PAS `../` ni les symlinks. Le kernel `exofs_path_resolve_raw` est de confiance, mais
vfs_server ne valide pas avant de forward.

**compat/procfs.rs, sysfs.rs**: Stubs — constantes et types uniquement, pas de données
proc/sys servies. Pas de leak actuellement.

**ops/**: Stubs de policy — `pipe.rs`, `copy_file_range.rs`, `renameat2.rs`, `poll.rs`
etc. définissent des validateurs de flags mais pas d'implémentation. Les opérations
réelles passent par des syscalls kernel.

### 4. network_server (PID 7) — D-01 fixé, IOMMU bypassé

**D-01 (SOCK_RAW sans CAP_NET_RAW)**: ✅ FIXÉ (PID-based).
`socket_table.rs` `from_domain_type_privileged()` (ligne 36-59) vérifie
`RAW_SOCKET_ALLOWED_PIDS = [1, 7]`. Les PIDs non-autorisés reçoivent EPERM.
ATTENTION: `from_domain_type()` (ligne 62-64) est un wrapper compat qui hardcode
`sender_pid=1`, bypassant le check. Si un code path utilise `from_domain_type()`, le
check est bypassé.

**Port binding < 1024**: CRITICAL — `handle_bind()` ne vérifie PAS le numéro de port.
N'IMPORTE QUEL process peut binder sur port 22, 80, 443, etc. Pas d'équivalent
`CAP_NET_BIND_SERVICE`.

**port_in_use()**: HIGH — ne vérifie que `entry.owner_pid == owner_pid`. Deux processes
DIFFÉRENTS peuvent binder le MÊME port! Pas de unicité globale.

**IOMMU bypass**: CRITICAL — `buf_pool.rs` `DMA_MAP_FLAGS_BYPASS_IOMMU = 1 << 4`. L'IOMMU
est EXPLICITEMENT bypassé pour les DMA buffers réseau. Un device compromis/malveillant
peut DMA vers n'importe quelle adresse physique.

**DHCP**: `dhcp.rs` `ingest()` accepte les DHCP ACK sans valider le server identity contre
une liste de confiance. Un DHCP serveur malveillant peut reconfigurer l'IP/gateway/DNS de
l'hôte.

**ICMP**: `icmp.rs` `make_echo_reply_ipv4_frame()` répond automatiquement aux echo
requests. Pas de rate limiting. Smurf/amplification possible sur subnet broadcast.

**Socket exhaustion**: HIGH — `MAX_SOCKETS = 64` global (pas per-PID). Un attaquant peut
épuiser la table socket, empêchant les processes légitimes d'ouvrir des sockets.

**isolation.rs**: Phoenix-phase tracking uniquement. PAS de network namespace isolation.
Tous les sockets partagent le même IP/namespace.

**tcp_store.rs**: `UnsafeCell` + `unsafe impl Sync`. La safety argument repose sur le
mutex `NETWORK_SERVICE`, mais les methods `save`/`load` ne tiennent aucun lock.

### 5. memory_server (PID 3) — D-02 partiellement fixé, guard alloc cassé

**D-02 (attach_shared_region ignore sender_pid)**: ⚠️ PARTIELLEMENT FIXÉ.
`attach_shared_region()` (ligne 375-411) vérifie maintenant sender_pid. Mais le check
"is_published" (`share_count > 0`) signifie qu'une fois l'owner a appelé attach UNE FOIS,
N'IMPORTE QUEL process peut attacher. Pas d'ACL — pas de liste de PIDs autorisés.

**Guard alloc cassé**: CRITICAL — `main.rs` ligne 57-66 lit
`requested_owner = payload[0..4]` qui est en réalité les 32 bits bas de `size`, puis le
compare à `sender_pid`. Pour un process PID 14 allouant 4096 bytes,
`requested_owner = 4096 != 14` → EACCES. Cette garde casse l'allocation mémoire pour tous
les processes non-init dont le PID ne matche pas les bas 32 bits de la size.

**Quota défaut u64::MAX**: HIGH — `allocator.rs` ligne 4. Tout process peut allouer
MÉMOIRE ILLIMITÉE avant que init set un quota. DoS par épuisement mémoire.

**Handle prediction**: LOW — handle généré via counter + owner_pid + slot_idx + mix key
fixed `0x9E37_79B9_7F4A_7C15`. Prédictible si counter et owner_pid connus. Brute-force
oracle: ENOENT vs EACCES distingue handles existants/inexistants.

**SYS_EXO_MEM_MAP_PID**: MEDIUM — syscall kernel qui opère sur ARBITRARY PIDs. Si le
kernel ne valide pas que le caller est memory_server, tout process pourrait mapper/
unmapper la mémoire d'un autre process.

### 6. device_server (PID 6) — GAP-10 partiellement fixé, IOMMU = ledger only

**GAP-10 (no CAP_DEVICE_CLAIM)**: ⚠️ PARTIELLEMENT FIXÉ.
`claim_validator.rs` utilise `DEVICE_CLAIM_ALLOWED_PIDS = [1, 6, 8, 9]` — allowlist PID,
pas CapToken. Commentaire: "à migrer vers CapToken en v0.3". `handle_claim()` vérifie
déjà `sender_pid != 1` (main.rs ligne 128), donc seul init peut envoyer CLAIM.

**IOMMU service**: HIGH — `iommu_service.rs` est un LEDGER uniquement. Enregistre domain
hints et faults mais NE PROGRAMME PAS l'IOMMU. Combiné avec SRV-030 (DMA bypass), l'IOMMU
n'isole PAS le DMA. Un device malveillant peut DMA vers toute adresse physique.

**handle_query()**: MEDIUM — pas de sender check. Tout process peut query les snapshots
device (phys_base, size, owner_pid, class_code, vendor_device) et données IOMMU fault.
Info leak. Le reply XOR des champs ensemble comme "obfuscation" faible.

**handle_event_poll()**: MEDIUM — pas de sender check. Tout process peut poller les
hotplug events (registration, claiming, release, fault). Info leak.

**hotplug.rs**: Ring buffer uniquement. Pas d'authentification de device — un device
malveillant hotpluggé serait enregistré par init.

**power.rs**: `set_state()` enregistre juste l'état — ne power off pas réellement. Admin-
only (PID 1) mais bookkeeping.

### 7. scheduler_server (PID 8) — D-03 partiellement fixé, REALTIME_ADMIT sans cap

**D-03 (escalade SCHED_REALTIME sans cap)**: ⚠️ PARTIELLEMENT FIXÉ.
`handle_set_policy()` (ligne 178-197) vérifie `RT_ALLOWED_PIDS = [1, 8]` OR
`sender_pid == owner_pid && sender_pid <= 10`. PIDs 2-10 peuvent self-escalader en
Realtime/Deadline. PIDs > 10 (exosh, apps) NE LE PEUVENT PAS. PID-based, pas CapToken.

**handle_realtime_admit()**: HIGH — PAS de RT privilege check! Vérifie uniquement
`owner_pid == sender_pid`. Tout process peut appeler SCHED_MSG_REALTIME_ADMIT pour réserver
du budget RT (consommant le cap 95% utilization). DoS — un attaquant peut épuiser le
budget RT, empêchant les servers RT légitimes d'être admis. L'attaquant n'obtient pas RT
priority (requiert SET_POLICY), mais bloque l'admission légitime.

**handle_set_affinity()**: MEDIUM — tout process peut se pinner sur N'IMPORTE QUEL core.
Pas de restriction sur cores sensibles (core 0 pour interrupts). Un process pourrait se
pinner sur un core exécutant exo_shield, causant une interférence.

**thread_table.rs register()**: MEDIUM — permet d'OVERWRITER un thread record existant si
le même `tid` est utilisé. Process B peut appeler `register(tid=5)` pour écraser le record
de process A (change `pid` en B). Bookkeeping hijack — A perd contrôle de son tid.

### 8. syscall_abi — Tests cargo test, pas d'enforcement runtime

**lib.rs**: Wrappers syscall0-syscall6 en inline asm. Pas de validation des numéros ou
arguments. Le kernel est responsable de la validation.

**tests/**: `#[test]` functions — s'exécutent avec `cargo test`, pas à runtime. Vérifient
les constantes ABI (numéros syscall, tailles struct) mais PAS le comportement runtime.

### 9. tty_server (PID 12) — PAS d'auth sur keystrokes

**CRITICAL**: `handle()` (ligne 357-369) process `TTY_MSG_INPUT_BYTE`,
`TTY_MSG_READ_LINE`, `TTY_MSG_WRITE` sans vérifier `sender_pid`. Tout process peut:
- Lire les keystrokes (TTY_MSG_READ_LINE) — KEYLOGGER TRIVIAL!
- Écrire sur la console (TTY_MSG_WRITE) — spoof output
- Injecter des bytes d'input (TTY_MSG_INPUT_BYTE) — simuler keystrokes

Pas de CapToken, pas d'allowlist PID.

### 10. fb_server (PID 13) — PAS d'auth framebuffer

**MEDIUM**: Framebuffer access sans auth. Tout process peut écrire sur l'écran via
`FB_MSG_WRITE`. Pas de CapToken. Un attaquant pourrait overwrite l'écran, afficher du
contenu trompeur, ou flasher des patterns seizure-inducing.

### 11. input_server (PID 11) — PAS d'auth ATTACH, broadcast keystrokes

**HIGH**: `INPUT_MSG_ATTACH` (ligne 215-223) n'a AUCUNE auth. Tout process peut s'attacher
au flux d'input et recevoir TOUS les events keyboard/mouse. `deliver_all()` broadcast à
TOUS les subscribers. Un attaquant appelle simplement `INPUT_MSG_ATTACH` avec son
reply_endpoint pour recevoir chaque keystroke.

### 12. exosh (PID 14) — Shell, kill sans cap, SOCK_RAW direct

**SOCK_RAW direct**: HIGH — exosh utilise `SYS_SOCKET(AF_INET, SOCK_RAW, IPPROTO_ICMP)`
pour sa commande `ping` (ligne 1537). Puisque exosh a PID 14 (> 10, pas dans
RAW_SOCKET_ALLOWED_PIDS), cela devrait ÉCHOUER avec EPERM. Mais si le kernel `SYS_SOCKET`
ne route pas à travers network_server's `from_domain_type_privileged()`, le check est
bypassé.

**kill sans cap**: MEDIUM — commande `kill` (ligne 1409) peut envoyer N'IMPORTE QUEL signal
à N'IMPORTE QUEL process (sauf PID 1 refusé). Un attaquant avec shell access peut tuer
n'importe quel server Ring1 (exo_shield, crypto_server, etc.). Pas de cap check —
`kill -9 10` (exo_shield) fonctionne.

**exec sans signature**: LOW — commande `exec` utilise `SYS_FORK` + `SYS_EXECVE` (ligne
413-426). Lié à C-01 (pas de vérification signature sur execve).

### 13. virtio_drivers (PID 9) — Lifecycle only

**INFO**: `virtio_drivers/src/main.rs` est un endpoint lifecycle/status uniquement
(commentaire ligne 4-7). Le vrai virtio_blk I/O est kernel-owned. Pas de vulnérabilité
server-level — répond juste à heartbeat/status.

---

## Findings Table

| ID | Severity | Server | File:Line | Description |
|----|----------|--------|-----------|-------------|
| SRV-001 | MEDIUM | ipc_router | security_gate.rs:21-22 | Pas de vérif CapToken; rely on kernel IPC_SEND cap |
| SRV-002 | LOW | ipc_router | router.rs:290-309 | forward_message() skip security_gate check_message (IPC-04 + logging) |
| SRV-003 | LOW | ipc_router | exocordon.rs:367-369 | Wildcard IpcBroker bypass — router peut envoyer partout |
| SRV-004 | INFO | ipc_router | exocordon.rs:229-232 | GAP-03 RÉSOLU — DAG 51 edges miroir kernel |
| SRV-005 | LOW | ipc_router | load_balancer.rs:236-272 | Pas de rate limiting; circuit breaker sur failure only |
| SRV-006 | MEDIUM | ipc_router | router.rs:327-358 | Broadcast policy envoie à ALL routes sans DAG check per-dest |
| SRV-007 | CRITICAL | init_server | sigchld_handler.rs:47-58 | SIGCHLD handlers JAMAIS installés (syscall3 au lieu de 4) |
| SRV-008 | CRITICAL | init_server | protocol.rs:281-384 / main.rs:313-363 | START/STOP/RESTART sans cap check — tout process peut contrôler services |
| SRV-009 | HIGH | init_server | isolation.rs:1-26 | STUB — XOR checkpoint_tag uniquement, pas d'isolation réelle |
| SRV-010 | MEDIUM | init_server | dependency.rs / boot_sequence.rs:299-445 | Pas de détection de cycle; boot DoS 300s |
| SRV-011 | MEDIUM | init_server | watchdog.rs:1-48 | Software poller, pas hardware watchdog; pas ExoKairos |
| SRV-012 | HIGH | init_server | boot_sequence.rs:166-199 | spawn_service() execve sans signature verification (C-01) |
| SRV-013 | MEDIUM | init_server | service_manager.rs / main.rs:221-254 | start_service() sans cap check sur sender |
| SRV-014 | CRITICAL | vfs_server | main.rs:759-762 | check_vfs_write_access() PID-based cassé; PID>=10 = full write |
| SRV-015 | CRITICAL | vfs_server | main.rs:310-372 | fd globale — cross-process fd hijack; pas de per-sender table |
| SRV-016 | HIGH | vfs_server | ops/mod.rs:36-50 | Pas de path traversal protection (../, symlinks) |
| SRV-017 | MEDIUM | vfs_server | main.rs:163-266 | mount/umount PID-only check, pas CapToken |
| SRV-018 | LOW | vfs_server | compat/procfs.rs, sysfs.rs | Stubs — pas de leak actuel mais pas d'ACL si implémenté |
| SRV-019 | LOW | vfs_server | ops/pipe.rs, copy_file_range.rs, etc. | Policy stubs, pas d'implémentation server-level |
| SRV-020 | MEDIUM | vfs_server | main.rs:695-727 | handle_rename() pas de validation même sandbox/mount |
| SRV-021 | MEDIUM | network_server | socket_table.rs:36-64 | D-01 fixé (PID-based); from_domain_type() wrapper bypass |
| SRV-022 | HIGH | network_server | socket_table.rs:368-376 | port_in_use() per-owner only; 2 processes peuvent binder même port |
| SRV-023 | CRITICAL | network_server | main.rs:463-474 | Pas de cap sur bind < 1024 — tout process peut binder port 22/80/443 |
| SRV-024 | MEDIUM | network_server | routing.rs:51-87 | Pas d'auth sur route additions; pas de sender check |
| SRV-025 | LOW | network_server | isolation.rs:1-74 | Phoenix-phase tracking only; pas de net namespace isolation |
| SRV-026 | MEDIUM | network_server | dhcp.rs:109-134 | DHCP ACK sans validation server identity; DHCP spoofing |
| SRV-027 | LOW | network_server | icmp.rs:8-58 | Echo reply auto sans rate limit; smurf possible |
| SRV-028 | MEDIUM | network_server | tcp_store.rs:49-101 | UnsafeCell + unsafe Sync; pas de lock dans save/load |
| SRV-029 | HIGH | network_server | socket_table.rs:141-161 | MAX_SOCKETS=64 global; socket exhaustion DoS |
| SRV-030 | CRITICAL | network_server | buf_pool.rs:16,43-67 | DMA_MAP_FLAGS_BYPASS_IOMMU — IOMMU explicitement bypassé |
| SRV-031 | LOW | network_server | smoltcp_iface.rs:38-104 | Multiple UnsafeCell + unsafe Sync pour buffers |
| SRV-032 | HIGH | memory_server | mmap_service.rs:375-411 | D-02 partiellement fixé; "published" = tout process peut attacher |
| SRV-033 | CRITICAL | memory_server | main.rs:57-66 | Guard alloc cassé — requested_owner = low32(size) break allocations |
| SRV-034 | HIGH | memory_server | allocator.rs:4 | Quota défaut u64::MAX — memory exhaustion DoS |
| SRV-035 | MEDIUM | memory_server | mmap_service.rs:375-411 | attach_shared_region ne mappe pas réellement dans l'AS caller |
| SRV-036 | LOW | memory_server | mmap_service.rs:86-101 | Handle prediction via fixed mix key; ENOENT/EACCES oracle |
| SRV-037 | MEDIUM | memory_server | mmap_service.rs:125-134 | SYS_EXO_MEM_MAP_PID opère sur arbitrary PIDs |
| SRV-038 | MEDIUM | device_server | claim_validator.rs:16-21 | GAP-10 partiellement fixé; PID allowlist pas CapToken |
| SRV-039 | HIGH | device_server | iommu_service.rs:1-108 | IOMMU = ledger only; ne programme pas l'IOMMU |
| SRV-040 | MEDIUM | device_server | main.rs:324-358 | handle_query() pas de sender check; info leak device topology |
| SRV-041 | MEDIUM | device_server | main.rs:273-283 | handle_event_poll() pas de sender check; info leak events |
| SRV-042 | LOW | device_server | hotplug.rs:1-90 | Pas d'authentification de device hotpluggé |
| SRV-043 | LOW | device_server | power.rs:87-98 | set_state() bookkeeping only; ne power off pas réellement |
| SRV-044 | MEDIUM | scheduler_server | main.rs:178-197 | D-03 partiellement fixé; PID<=10 self-escalate RT |
| SRV-045 | HIGH | scheduler_server | main.rs:340-372 | handle_realtime_admit() SANS cap check; RT budget DoS |
| SRV-046 | MEDIUM | scheduler_server | main.rs:237-271 | set_affinity() pas de restriction cores sensibles |
| SRV-047 | MEDIUM | scheduler_server | thread_table.rs:56-99 | register() overwrite tid existant; bookkeeping hijack |
| SRV-048 | LOW | scheduler_server | policy_advisor.rs:48-98 | Pas de protection gaming; nice=-20 = max priority |
| SRV-049 | INFO | syscall_abi | tests/*.rs | Tests cargo test, pas enforcement runtime |
| SRV-050 | LOW | syscall_abi | lib.rs:9-29 | syscall6() pas de validation numéros/arguments |
| SRV-051 | CRITICAL | tty_server | main.rs:357-369 | PAS d'auth; tout process peut lire keystrokes (keylogger) |
| SRV-052 | HIGH | input_server | main.rs:215-223 | INPUT_MSG_ATTACH sans auth; broadcast keystrokes à tous |
| SRV-053 | MEDIUM | fb_server | main.rs | PAS d'auth framebuffer; tout process peut écrire sur écran |
| SRV-054 | HIGH | exosh | main.rs:1537 | SOCK_RAW direct via SYS_SOCKET; bypass si kernel ne route pas |
| SRV-055 | MEDIUM | exosh | main.rs:1409 | kill sans cap; tout user peut kill -9 n'importe quel server |
| SRV-056 | LOW | exosh | main.rs:413-426 | exec sans signature verification (C-01) |
| SRV-057 | INFO | virtio_drivers | main.rs:4-7 | Lifecycle/status only; pas de I/O |

---

## Detailed Findings

### SRV-007 — CRITICAL: init_server SIGCHLD handlers jamais installés

**File**: `init_server/src/sigchld_handler.rs:47-58`

```rust
// NOTE #25 : le noyau exige sigsetsize==8 ; cet appel à 3 args laisse
// sigsetsize=0 → EINVAL → handlers PAS installés. C'est un VRAI bug...
let _ = syscall::syscall3(
    syscall::SYS_RT_SIGACTION,
    17,
    &chld_sa as *const Sigaction as u64,
    0,
);
```

**Why**: `SYS_RT_SIGACTION` nécessite 4 arguments (signum, act, oldact, sigsetsize).
L'appel utilise `syscall3` (sigsetsize=0) → EINVAL → handlers jamais installés. Le code
documente ce bug comme délibéré pour éviter la race #25, mais SIGCHLD n'est jamais livré.

**Impact**: init_server ne reap les zombies que par polling dans la loop de supervision.
Si init hang dans `handle_control_plane`, les zombies s'accumulent.

**Fix**: Utiliser `syscall4(..., 8)` après avoir résolu la race #25 sur la frame de signal.

---

### SRV-008 — CRITICAL: init_server START/STOP/RESTART sans capability check

**File**: `init_server/src/protocol.rs:281-384`, `init_server/src/main.rs:313-363`

```rust
protocol::INIT_MSG_START => {
    match protocol::read_service_name(&request.payload).and_then(|service_name| {
        supervisor::runtime_index_by_name(&SERVICES, service_name)
    }) {
        Some(idx) => {
            let rc = start_service(idx, service_watchdog);  // Pas de check sender_pid!
            ...
```

**Why**: `handle_control_plane()` lit `request.sender_pid` mais ne le valide JAMAIS.
N'importe quel processus peut envoyer `INIT_MSG_START`/`STOP`/`RESTART` pour n'importe
quel service.

**Impact**: Un attaquant peut stopper exo_shield (désactive NGAV), stopper crypto_server,
faire un timing attack sur les restarts, ou démarrer des services dans le mauvais ordre.

**Fix**: Vérifier un CapToken `CAP_SERVICE_ADMIN` ou restreindre à `sender_pid == 1`.

---

### SRV-014 — CRITICAL: vfs_server check_vfs_write_access() PID-based cassé

**File**: `vfs_server/src/main.rs:759-762`

```rust
#[inline]
fn check_vfs_write_access(sender_pid: u32) -> bool {
    const WRITE_ALLOWED: &[u32] = &[1, 3];
    WRITE_ALLOWED.contains(&sender_pid) || sender_pid >= 10
}
```

**Why**: Allowlist PID hardcoded + `sender_pid >= 10` = tout process PID≥10 peut
WRITE/DELETE n'importe quel fichier. Pas de CapToken. PIDs sont réutilisés.

**Impact**: exosh (PID 14), user apps (PID > 10) peuvent écrire/supprimer n'importe quel
fichier sur le système de fichiers.

**Fix**: Remplacer par vérification CapToken `CAP_FS_WRITE` + per-file ACL.

---

### SRV-015 — CRITICAL: vfs_server fd globale — cross-process fd hijack

**File**: `vfs_server/src/main.rs:310-372`

```rust
fn handle_open(payload: &[u8]) -> VfsReply {
    ...
    let fd = unsafe { syscall::exofs_open_by_path_raw(path.as_ptr() as u64, flags, 0, rights) };
    ...
    VfsReply { status: 0, blob_id, fd, _pad: [0; 40] }
}
```

**Why**: `handle_open()` retourne un kernel fd GLOBAL au process vfs_server. Pas de table
fd per-sender. `handle_read()` utilise `fd` du payload sans vérifier l'ownership.

**Impact**: Si process A ouvre fd 5, process B peut appeler `handle_read(fd=5)` et lire le
fichier de A. Cross-process information leak.

**Fix**: Maintenir une table fd per-sender (sender_pid → set of fds) et valider
l'ownership dans handle_read/handle_write/handle_close.

---

### SRV-023 — CRITICAL: network_server pas de cap sur bind < 1024

**File**: `network_server/src/main.rs:463-474`

```rust
fn handle_bind(&mut self, msg: NetMsg) -> NetReply {
    match self.sockets.bind(msg.sender_pid, msg.fd, msg.arg1 as u32, msg.arg2 as u16) {
        // Pas de check sur msg.arg2 (port) < 1024!
```

**Why**: `handle_bind()` ne vérifie pas le numéro de port. Pas d'équivalent
`CAP_NET_BIND_SERVICE`.

**Impact**: Tout process peut binder sur port 22 (SSH), 80 (HTTP), 443 (HTTPS), etc.
Un attaquant pourrait impersonner des services.

**Fix**: Ajouter `if port < 1024 && !sender_has_cap(CAP_NET_BIND_SERVICE) { return EPERM; }`.

---

### SRV-030 — CRITICAL: network_server IOMMU explicitement bypassé

**File**: `network_server/src/buf_pool.rs:16,43-67`

```rust
const DMA_MAP_FLAGS_BYPASS_IOMMU: u64 = 1 << 4;
...
let rx_iova = unsafe {
    syscall::syscall5(
        syscall::SYS_DMA_ALLOC,
        (RX_POOL_SIZE * PAGE_SIZE) as u64,
        DMA_DIR_FROM_DEVICE,
        &mut rx_virt as *mut u64 as u64,
        DMA_MAP_FLAGS_BYPASS_IOMMU,  // IOMMU bypassé!
        0,
    )
};
```

**Why**: L'IOMMU est explicitement bypassé pour les DMA buffers réseau. Commentaire:
"e1000/virtio descriptors consume DMA-visible physical addresses until the kernel wires
real IOMMU table programming for translated IOVAs."

**Impact**: Un device compromis ou malveillant (virtio-net, e1000) peut DMA vers/depuis
n'importe quelle adresse physique, lisant/écrivant la mémoire kernel et tous les processes.

**Fix**: Programmer l'IOMMU pour limiter le DMA aux buffers réseau uniquement. Retirer
`DMA_MAP_FLAGS_BYPASS_IOMMU` une fois l'IOMMU kernel wired.

---

### SRV-033 — CRITICAL: memory_server guard alloc cassé

**File**: `memory_server/src/main.rs:57-66`

```rust
MEMORY_MSG_ALLOC => {
    let requested_owner = u32::from_le_bytes(
        request.payload.get(0..4).map(|b| [b[0],b[1],b[2],b[3]]).unwrap_or([0u8;4])
    );
    if requested_owner != 0 && requested_owner != request.sender_pid && request.sender_pid != 1 {
        MemoryReply::error(exo_syscall_abi::EACCES)
    } else {
        service.handle_alloc(request.sender_pid, &request.payload)
    }
}
```

**Why**: `requested_owner` lit `payload[0..4]` qui est les 32 bits bas de `size` (le
payload format est `[0..8]=size, [8..12]=prot, [12..16]=flags`). La garde compare
`requested_owner` (= low32(size)) à `sender_pid`. Pour exosh (PID 14) allouant 4096 bytes,
`requested_owner = 4096 != 14` → EACCES. Cette garde casse l'allocation mémoire pour tous
les processes non-init.

**Impact**: Tout process non-init dont le PID ne matche pas les bas 32 bits de la size ne
peut PAS allouer de mémoire. DoS accidentel de la plupart des allocations.

**Fix**: Soit retirer la garde (handle_alloc utilise déjà sender_pid comme owner), soit
corriger le parsing du payload pour extraire un véritable champ `requested_owner`.

---

### SRV-051 — CRITICAL: tty_server PAS d'auth sur keystrokes

**File**: `tty_server/src/main.rs:357-369`

```rust
fn handle(req: &syscall::TtyRequest) -> syscall::TtyReply {
    match req.msg_type {
        syscall::TTY_MSG_INPUT_BYTE => handle_input(req.a as u8),
        syscall::TTY_MSG_READ_LINE => handle_read_line(),  // Pas de check sender!
        syscall::TTY_MSG_WRITE => {
            let n = core::cmp::min(req.a as usize, LINE_OUT_MAX);
            console_write(&req.data[..n]);  // Pas de check sender!
            ...
```

**Why**: Aucune vérification de `sender_pid` sur les opérations TTY. Tout process peut
lire les keystrokes (READ_LINE), écrire sur la console (WRITE), injecter des bytes
d'input (INPUT_BYTE).

**Impact**: Keylogger trivial — un process malveillant peut lire toutes les keystrokes
saisies par l'utilisateur, y compris mots de passe. Spoofing de console. Injection de
commandes.

**Fix**: Vérifier un CapToken `CAP_TTY_READ`/`CAP_TTY_WRITE` ou restreindre à une
allowlist de PIDs autorisés (exosh, exo_shield).

---

### SRV-052 — HIGH: input_server INPUT_MSG_ATTACH sans auth

**File**: `input_server/src/main.rs:215-223`

```rust
syscall::INPUT_MSG_ATTACH => {
    let ok = SUBSCRIBERS.attach(req.reply_endpoint);  // Pas de check sender!
    ...
```

**Why**: `INPUT_MSG_ATTACH` n'a AUCUNE authentification. `deliver_all()` broadcast à
TOUS les subscribers. Tout process peut s'attacher au flux d'input.

**Impact**: Un attaquant reçoit TOUS les events keyboard/mouse. Keylogger passif.

**Fix**: Vérifier un CapToken `CAP_INPUT_SUBSCRIBE` ou restreindre à tty_server + exo_shield.

---

### SRV-045 — HIGH: scheduler_server handle_realtime_admit() sans cap check

**File**: `scheduler_server/src/main.rs:340-372`

```rust
fn handle_realtime_admit(&mut self, sender_pid: u32, payload: &[u8]) -> SchedulerReply {
    ...
    let owner_pid = match self.threads.owner_pid(tid) {
        Some(pid) if pid == sender_pid => pid,  // Pas de RT privilege check!
        ...
    };
    match self.realtime.admit(tid, runtime_us, period_us) {  // Réserve budget RT!
```

**Why**: Contrairement à `handle_set_policy()` qui a `RT_ALLOWED_PIDS` check,
`handle_realtime_admit()` n'a AUCUN check de privilège RT. Tout process peut réserver du
budget RT (jusqu'au cap 95% utilization).

**Impact**: DoS — un attaquant peut épuiser le budget RT, empêchant les servers RT
légitimes d'être admis. L'attaquant n'obtient pas RT priority (requiert SET_POLICY), mais
bloque l'admission légitime.

**Fix**: Ajouter le même `RT_ALLOWED_PIDS` check que `handle_set_policy()`.

---

### SRV-039 — HIGH: device_server IOMMU = ledger only

**File**: `device_server/src/iommu_service.rs:1-108`

```rust
pub fn bind_driver(&mut self, pid: u32, domain_hint: u32) {
    // Enregistre juste le domain_hint dans la table locale
    ...
}
```

**Why**: `IommuLedger` enregistre domain hints et faults mais NE PROGRAMME PAS l'IOMMU.
Combiné avec SRV-030 (DMA_MAP_FLAGS_BYPASS_IOMMU), l'IOMMU n'isole PAS le DMA.

**Impact**: Un device malveillant peut DMA vers toute adresse physique, lisant/écrivant
la mémoire kernel et tous les processes.

**Fix**: Implémenter la programmation IOMMU réelle via un syscall kernel dédié. Retirer
le flag bypass.

---

## Verdict

### Critical (7)
- **SRV-007**: init_server SIGCHLD jamais installé (bug délibéré #25)
- **SRV-008**: init_server START/STOP/RESTART sans cap — tout process contrôle les services
- **SRV-014**: vfs_server write access PID-based cassé (PID>=10 = full write)
- **SRV-015**: vfs_server fd globale — cross-process fd hijack
- **SRV-023**: network_server pas de cap sur bind < 1024
- **SRV-030**: network_server IOMMU explicitement bypassé pour DMA
- **SRV-033**: memory_server guard alloc cassé — break allocations non-init
- **SRV-051**: tty_server PAS d'auth sur keystrokes — keylogger trivial

### High (10)
- SRV-009, SRV-012, SRV-016, SRV-022, SRV-029, SRV-032, SRV-034, SRV-039, SRV-045, SRV-052, SRV-054

### Medium (18)
- SRV-001, SRV-006, SRV-010, SRV-011, SRV-013, SRV-017, SRV-020, SRV-021, SRV-024, SRV-026, SRV-028, SRV-035, SRV-037, SRV-038, SRV-040, SRV-041, SRV-044, SRV-046, SRV-047, SRV-053, SRV-055

### Low (12)
- SRV-002, SRV-003, SRV-005, SRV-018, SRV-019, SRV-025, SRV-027, SRV-031, SRV-036, SRV-042, SRV-043, SRV-048, SRV-050, SRV-056

### Info (3)
- SRV-004 (GAP-03 résolu), SRV-049, SRV-057

### Synthèse

**GAP-03 (ExoCordon)**: ✅ RÉSOLU — DAG userspace 51 edges miroir kernel.
**D-01 (SOCK_RAW)**: ⚠️ Partiellement fixé — PID-based, wrapper compat bypass.
**D-02 (attach_shared_region)**: ⚠️ Partiellement fixé — "published" = tout process attache.
**D-03 (SCHED_REALTIME)**: ⚠️ Partiellement fixé — SET_POLICY OK, REALTIME_ADMIT sans cap.
**GAP-06 (vfs zero cap)**: ⚠️ Partiellement fixé — PID-based cassé, fd globale.
**GAP-10 (device claim)**: ⚠️ Partiellement fixé — PID allowlist, pas CapToken.

**Pattern récurrent**: Tous les servers utilisent PID-based access control au lieu de
CapToken. Les PIDs sont réutilisés, prédictibles, et ne constituent pas une base de
sécurité solide. La migration vers CapToken (annoncée pour v0.3) est critique.

**Pattern critique**: Les servers d'I/O (tty, input, fb, vfs) n'ont aucune authentification
sur les opérations sensibles. Un keylogger trivial est possible via tty_server ou
input_server. Un process peut lire les fichiers d'un autre via vfs_server fd globale.

**Pattern DoS**: Quotas mémoire défaut u64::MAX, socket table globale (64), pas de rate
limiting sur IPC routing, pas de cap sur bind<1024, REALTIME_ADMIT sans cap. Multiple
vectors DoS.

**Priorité de remédiation**:
1. SRV-051/052 (keylogger tty/input) — impact immédiat, fix simple (allowlist PID)
2. SRV-008 (init lifecycle sans cap) — permet de stopper exo_shield
3. SRV-030 (IOMMU bypass) — DMA arbitraire possible
4. SRV-015 (vfs fd globale) — cross-process info leak
5. SRV-033 (memory guard cassé) — break allocations
6. SRV-023 (bind < 1024) — impersonation de services
7. SRV-007 (SIGCHLD cassé) — zombie accumulation
