# 04 — Audit Kernel Core (memory · ipc · syscall · scheduler · drivers)

**Task ID:** 4
**Scope:** kernel/src/{memory, ipc, syscall, scheduler, drivers, main.rs, lib.rs}
**Method:** Lecture exhaustive de chaque fichier cité dans le mandat. Aucun skimming.
**Auditeur:** Sub-agent général (sandboxed vibe coding workspace)
**Date:** 2026-03

---

## 0. Inventaire

| Sous-système | Fichiers relus | Verdict global |
|---|---|---|
| memory/core | mod, types, address, constants, layout | OK (les types sont sains, layout cohérent) |
| memory/arch_iface, numa | arch_iface.rs, numa.rs (façade) | OK |
| memory/physical | mod, stats, zone/*, numa/*, frame/*, allocator/* (slub/buddy/bitmap/slab/numa_*) | Alertes (voir KERN-009, KERN-015) |
| memory/virtual | mod, mmap, page_table/{walker,x86_64,builder,kpti_split,mod}, address_space/*, vma/*, fault/* | Alertes (voir KERN-003, KERN-005, KERN-008, KERN-011) |
| memory/heap | mod, allocator/{hybrid,global,size_classes}, thread_local/*, large/vmalloc | Alertes (voir KERN-012, KERN-013, KERN-014) |
| memory/cow | mod, breaker, tracker | Alertes (voir KERN-010) |
| memory/huge_pages | mod, thp, split, hugetlbfs | non détaillé ici, rien de critique relevé |
| memory/protection | mod, smap, smep, nx, pku, umip | CRITIQUE (KERN-001, KERN-002) |
| memory/integrity | mod, sanitizer, canary, guard_pages | Alertes (KERN-006, KERN-007) |
| memory/dma | dma/{mod, core/*, channels/*, completion/*, engines/*, iommu/*, ops/*, stats/*} | OK (callbacks vers drivers/iommu) |
| ipc/core | mod, types, sequence, transfer, fastcall_asm.s, constants | OK (séquence ok, fastcall stub correct) |
| ipc/endpoint | mod, descriptor, registry, connection, lifecycle | Alertes (KERN-018) |
| ipc/message | mod, builder, serializer, router, priority | OK (bounds-check dans SerdeFixed) |
| ipc/channel | mod, raw, sync, async, mpmc, broadcast, typed, streaming | Alertes (KERN-020) |
| ipc/ring | mod, slot, spsc, mpmc, zerocopy, batch, fusion | OK (array_index_nospec Spectre v1 OK) |
| ipc/shared_memory | mod, descriptor, page, pool, mapping, allocator, numa_aware, memory_bridge | CRITIQUE (KERN-016, KERN-017) |
| ipc/capability_bridge | mod, check | OK (vérifie via access_control) |
| ipc/stats | mod, counters | OK |
| ipc/sync, ipc/rpc | event, futex, rendezvous, sched_hooks, wait_queue, barrier ; protocol, server, client, timeout, raw | non détaillé |
| syscall | mod, abi, dispatch, errno, fast_path, fixup, fs_bridge, net_bridge, numbers, table, validation, entry_asm | CRITIQUE (KERN-021, KERN-022, KERN-023, KERN-024, KERN-025) |
| syscall/compat | posix, linux, mod | non détaillé |
| syscall/handlers | fs_posix, fd, memory, signal, time, process, misc, mod | Alertes (KERN-026, KERN-027) |
| scheduler/core | mod, switch, preempt, runqueue, task, pick_next, boot_idle | OK IBPB ; KERN-028 (mutex) |
| scheduler/policies | mod, cfs, realtime, deadline, idle | OK |
| scheduler/timer | mod, tick, clock, hrtimer, deadline_timer, sleep | non détaillé |
| scheduler/smp | mod, migration, load_balance, affinity, topology | OK |
| scheduler/fpu | mod, lazy, state, save_restore | CRITIQUE (KERN-029) |
| scheduler/energy, stats | power_profile, frequency, c_states, per_cpu, latency | non détaillé |
| scheduler/sync | spinlock, mutex, rwlock, condvar, seqlock, wait_queue, barrier | KERN-028 (mutex) ; spinlock OK |
| scheduler/asm | fast_path.s, switch_asm.s | OK (callee-saved only) |
| drivers | mod, pci_cfg, pci_topology, pci_link, dma, device_claims, device_server_ipc, tests, iommu/* | OK (claims capacités, IOMMU domain registry) |
| main.rs, lib.rs | main.rs, lib.rs | OK (panic/alloc handlers ; pas de fuite registre) |

---

## 1. Statut par sous-système

### 1.1 memory/protection
- **SMAP** : activé, `SmapAccessGuard` RAII correct ; mais `copy_from_user`/`copy_to_user` ne valident PAS que les pointeurs user sont bien dans l'espace user (contrat délégué à l'appelant). Les wrappers de validation (validation.rs) font ce check.
- **SMEP** : activé, `SmepGuard` RAII ok.
- **NX** : activé (EFER.NXE), politique régionale NX_REGION_RULES en .rodata.
- **UMIP** : activé si supporté.
- **PKU** : **CRITIQUE** — voir KERN-001 : seul `CR4_PKE` (user PKU) est activé, jamais `CR4_PKS` (supervisor PKU). Les clés 1 (kernel heap), 2 (guard), 3 (MMIO) sont définies et la PKRU initiale les restreint, mais sans PKS elles n'ont **aucun effet** en kernel mode.

### 1.2 memory/integrity
- **canary** : généré via RDTSC+splitmix64 (pseudo-aléa), par CPU, thread_canary = cpu_canary XOR tid. Vérification via `verify_thread_canary`. Rotation possible.
- **guard_pages** : table MAX_GUARD_REGIONS=4096, tag dans bits 11:9 = 0b111. Détection via fault handler. OK.
- **sanitizer (KASAN-lite)** : **CRITIQUE** — voir KERN-006 : `init()` active KASAN sans empoisonner la shadow map. Le commentaire l'admet explicitement : "on fait confiance au zeroing de la page table (0x00 = ACCESSIBLE)". Conséquence : tout octet du heap kernel est marqué accessible par défaut, annulant la détection uninit et buffer-overflow.

### 1.3 memory/virtual
- **walker.rs** : walks PML4→PDPT→PD→PT. Aucun check d'adresse canonique avant indexation — mais les indices sont masqués via `p4_index()/p3_index()/...` qui devrait borner à 9 bits. `compare_exchange_leaf_raw` expose une opération atomique sur PTE.
- **kpti_split.rs** : build_user_shadow_pml4 construit une PML4 user copiant les 256 entrées user (0..255) et les pages de transition (syscall_entry, IDT handlers, TSS, IST stacks). **Aucune des pages de transition ne porte le bit USER** (correct), mais le bit NX n'est pas toujours positionné (entry_asm est marquée executable, ok). KPTI activé conditionnellement via `should_enable_kpti()`. Voir KERN-003 pour un souci de cohérence.
- **fault/handler.rs** : kernel fault = panic immédiate (`KernelFault` retourné, mais le handler arch doit paniquer). Pas de fixup réel — voir KERN-005 (fixup.rs cassé).
- **fault/cow.rs** : CoW break avec CAS sur PTE. **Course critique** — voir KERN-008.

### 1.4 memory/cow
- **breaker.rs** : `break_cow(frame)` lit refcount, alloue nouveau frame, copie via physmap, décrémente refcount. **Pas de lock entre la lecture du refcount et la décision de copier** : un autre thread peut casser le CoW en parallèle et les deux threads vont chacun copier, gaspillant un frame. Le résultat reste correct (l'un des deux CAS va échouer), mais c'est une inefficacité — pas une vulnérabilité.
- **tracker.rs** : table de hash FNV-1a avec sondage linéaire, lock global Mutex. Sentinel `u32::MAX` retournée en cas de "non trouvé" sur `dec()` : dangereux car l'appelant pourrait l'interpréter comme "frame libérable".

### 1.5 memory/heap
- **hybrid.rs** : dispatch SLUB (≤2048) / vmalloc (>2048). Fallback robustesse SLUB→vmalloc si SLUB pas prêt.
- **vmalloc.rs** : **CRITIQUE** — voir KERN-013 : vmalloc retourne des pointeurs dans la **physmap** (`PHYS_MAP_BASE + phys`), pas dans VMALLOC_BASE. Le nom est trompeur. Le header 64B est collé en début de frame physique. Conséquence : pas de séparation d'adressage entre données kernel "statiques" (physmap) et allocations dynamiques "vmalloc" ; un débordement sur une allocation vmalloc peut corrompre n'importe quelle autre donnée physmap (structures kernel, autres allocations).
- **slub.rs** : freelist XOR-encodée avec clé `virt_base.wrapping_mul(0x9e3779b97f4a7c15)` — **voir KERN-014** : clé prédictible.
- **global.rs** : `KernelAllocator` `#[global_allocator]`. `realloc` fait alloc+copy+dealloc sans vérifier le retour intermédiaire de copy (mais ok car copy_nonoverlapping ne retourne rien). `Layout::from_size_align` est vérifié.

### 1.6 memory/dma
- dma/core/*, dma/iommu/*, dma/engines/*, dma/ops/*, dma/channels/*, dma/completion/*, dma/stats/* : orchestration. L'IOMMU est enforced via `IOMMU_DOMAINS` (drivers/iommu/domain_registry.rs). Voir KERN-031.

### 1.7 ipc/core
- **fastcall_asm.s** : wrapper ASM pour ipc_fast_send/recv/call. Juste un thunk vers `ipc_ring_fast_write`/`read`. Pas de bypass : les checks cap sont faits dans le code Rust appelant (channel/sync.rs, channel/raw.rs `send_raw_checked`).
- **sequence.rs** : SeqReceiver avec sliding window. Validation correcte (InOrder/Future/Duplicate/TooOld). Pas atomique en multi-consommateur, mais le SPSC est mono-consommateur.

### 1.8 ipc/endpoint
- **connection.rs** : `do_connect` vérifie `Rights::IPC_CONNECT` via capability_bridge. `do_accept` vérifie `ep.is_owner(server)`. OK.
- **lifecycle.rs** : pool statique MAX_ENDPOINTS via bitmap CAS. `endpoint_destroy` : vérifie active_conns==0, mais **voir KERN-018** : la recherche est O(MAX_ENDPOINTS) itérative.

### 1.9 ipc/channel
- **raw.rs** : table statique MAX_RAW_SLOTS=64. Auto-open à la première écriture — **voir KERN-020** : DoS trivial par épuisement de slots.
- `send_raw` (sans checked) ne vérifie PAS de capability — réservé aux appels kernel-internes. `send_raw_checked` vérifie `Rights::IPC_SEND`. Le syscall `SYS_EXO_IPC_SEND` doit appeler `_checked`. Vérifié dans table.rs.

### 1.10 ipc/shared_memory
- **mapping.rs** : **CRITIQUE** — voir KERN-016 : `shm_map(desc_idx, pid, ...)` ne vérifie PAS de capability. N'importe quel processus connaissant l'index du descripteur peut mapper la région SHM.
- **descriptor.rs** : MAX_SHM_REGIONS=1024, MAX_SHM_PAGES_PER_DESC=64 (256 KiB max/région). `shm_destroy` ne libère pas explicitement les mappings existants avant destroy — en réalité `shm_destroy` appelle `shm_unmap_all_for_desc` via `mapping.rs`. OK.
- **allocator.rs** : buddy-like 4 niveaux (1/4/16/64 pages). Pas de cap max par propriétaire — **voir KERN-017** : DoS par épuisement du pool.

### 1.11 syscall
- **dispatch.rs** : pipeline : validation numéro → audit_syscall_entry → zero-trust verify_syscall → fast_path → compat translate → handler. Le `verify_syscall` est correctement câblé (TIER 1.1).
- **validation.rs** : `validate_user_range` vérifie NULL + USER_ADDR_MAX + align. `copy_from_user` résout via `resolve_user_page` qui déclenche le fault handler (CoW/demand paging). `walk_user_mapping` rejette les PTE sans FLAG_USER — **voir KERN-021** : la vérification `is_user()` est faite dans `resolve_user_page` mais pas systématiquement dans tous les callers.
- **fixup.rs** : **CRITIQUE** — voir KERN-022 : le mécanisme de fixup est cassé. `fixup_signal_fault` ne jump pas à `recovery_rip`, le handler #PF reprend à l'instruction fautive → boucle infinie. Heureusement, ce module n'est PAS câblé dans `copy_from_user` (qui utilise `copy_from_user_resolved` à la place). Mais le code mort reste alarmant.
- **fast_path.rs** : getpid/gettid/getuid/etc via GS:[0x20]. `current_creds` retourne `Credentials::root()` si PCB non trouvé — comportement boot-safe mais potentiellement dangereux si jamais un process non-initialisé appelle un syscall.
- **entry_asm.rs** : documentation uniquement ; implémentation réelle dans `arch/x86_64/syscall.rs` via `global_asm!`. La séquence documente SWAPGS, save RSP/RIP, call `syscall_rust_handler`. `apply_ibrs()` est bien appelé dans `syscall_rust_handler` (B-02 résolu).
- **table.rs** : `get_handler(nr)` utilise un `match nr { … _ => sys_enosys }` — pas d'OOB possible. La table `SYSCALL_STATS` utilise un `transmute<[u64; N], [AtomicU64; N]>` qui est techniquement UB si la représentation diffère, mais en pratique sûr.
- **handlers/misc.rs** : `sys_arch_prctl` — **voir KERN-023** (ARCH_SET_FS/SET_GS sans validation user).
- **handlers/signal.rs** : `sys_kill` — **voir KERN-024** : pas de check CAP_KILL/UID.
- **handlers/process.rs** : wrappers ENOSYS (fork/exec passent par dispatch.rs handle_*_inplace).
- **handlers/memory.rs** : wrappers vers `do_mmap`/`do_munmap`/etc — `do_mmap` ne semble pas valider que `addr` est user (mais c'est délégué à la fonction sous-jacente).
- **handlers/time.rs** : wrappers ENOSYS (clock_gettime passe par fast_path).

### 1.12 scheduler
- **core/switch.rs** : IBPB émis sur context switch cross-processus (B-01 résolu). `context_switch_asm` est inclus via `global_asm!`. Lazy FPU : `xsave_current(prev)` puis `xrstor_for(next)`.
- **core/preempt.rs** : PreemptGuard RAII. `preempt_disable_raw` détecte >64 imbrications (debug_assert). Aucun timeout — un kernel spinlock peut désactiver la préemption indéfiniment.
- **policies/realtime.rs** : SCHED_FIFO + SCHED_RR (quantum 10ms). Pas de cap max threads RT par CPU — un process peut créer N threads RT et monopoliser un CPU. (Mais sched_setscheduler est limité par CAP_SYS_NICE dans Linux ; à vérifier côté Exo-OS.)
- **fpu/lazy.rs** + **fpu/state.rs** + **fpu/save_restore.rs** : **CRITIQUE** — voir KERN-029 : si `alloc_fpu_state` échoue (contexte IN_RECLAIM ou OOM), `fpu_state_ptr` reste NULL, et `xrstor_for()` initialise les registres par défaut sans zone de sauvegarde. Au prochain switch, `xsave_current()` voit NULL et retourne sans sauvegarder. L'état FPU est **silencieusement perdu** entre context switches — corruption de données silencieuse pouvant affecter crypto/AES-NI.
- **sync/spinlock.rs** : SpinLock simple + IrqSpinLock. Pas de timeout. `IrqSpinLock::lock_irq` désactive IRQ **avant** d'acquérir le lock — si contention longue, IRQ off pendant longtemps (latence IRQ).
- **sync/mutex.rs** : **voir KERN-028** : commenté comme "héritage de priorité simplifié" mais **aucun PI implémenté**. `lock_blocking` utilise WaitQueue FIFO. Priority inversion trivial : thread basse priorité tient le mutex, thread haute priorité bloqué, thread moyenne priorité préempte le thread basse → inversion non bornée.

### 1.13 drivers
- **pci_cfg.rs** : `pci_cfg_read/write` protégés par `PCI_CFG_LOCK` + `irq_save`. `sys_pci_cfg_read_for_pid` exige `claimed_bdf(pid)` → le PID doit avoir claim le device. OK.
- **device_claims.rs** : `sys_pci_claim` exige `check_sys_admin_capability` (root). Vérifie MMIO whitelist + non-RAM + pas déjà claim. OK.
- **iommu/mod.rs** + **iommu/domain_registry.rs** : IOMMU_DOMAIN_REGISTRY associe PID→domain. `ensure_domain` crée un domaine translated par PID. OK. Voir KERN-031 pour l'enforcement.
- **dma.rs** : `sys_dma_map` exige `domain_id` (de l'appelant). `sys_mmio_map_for_pid` exige `claim_contains(pid, phys, size)` (le device doit être claim par le PID). Voir KERN-030.

---

## 2. Findings Table

| ID | Severity | File:line | Résumé |
|---|---|---|---|
| KERN-001 | **CRITICAL** | memory/protection/pku.rs:274-285 | `enable_pku` active `CR4_PKE` mais JAMAIS `CR4_PKS` — les clés PKRU kernel (heap/guard/MMIO) sont inefficaces |
| KERN-002 | HIGH | memory/protection/smap.rs:217-237 | `copy_from_user`/`copy_to_user` ne valident pas l'appartenance user des pointeurs (contrat unsafe délégué) |
| KERN-003 | MEDIUM | memory/virtual/page_table/kpti_split.rs:200-214 | `sync_user_region_to_shadow` copie les 256 entrées PML4 user sans lock explicite — risque de TOCTOU sur PML4[user] pendant fork+migration |
| KERN-004 | LOW | memory/cow/breaker.rs:95-139 | `break_cow` lit refcount puis alloue+copie sans CAS — double-copie sous contention (gaspillage, non vuln) |
| KERN-005 | HIGH | syscall/fixup.rs:165-291 | `copy_from_user_safe`/`copy_to_user_safe` + `fixup_signal_fault` cassés : le handler #PF ne jump pas à `recovery_rip`, la boucle `for i in 0..len` vérifie `FAULTED[cpu_id]` mais RIP revient à l'instruction fautive → boucle infinie |
| KERN-006 | **CRITICAL** | memory/integrity/sanitizer.rs:340-345 | `kasan::init()` active KASAN sans empoisonner la shadow map (0x00 = ACCESSIBLE) → tous les accès heap sont réputés valides, détection uninit/overflow/UAF neutralisée |
| KERN-007 | MEDIUM | memory/integrity/canary.rs:150-157 | canary généré via RDTSC+splitmix64 (déterministe si attaquant contrôle le boot timing) |
| KERN-008 | HIGH | memory/virtual/fault/cow.rs:44-69 | `can_restore_in_place` : lit refcount tracker puis CAS PTE — si le tracker renvoie `None` (frame non suivi) la restauration in-place est autorisée même si la page est partagée hors tracker |
| KERN-009 | MEDIUM | memory/physical/allocator/slub.rs:317-318 | XOR key freelist = `virt_base * 0x9e3779b97f4a7c15` — prédictible si attaquant connaît l'adresse physique du slub |
| KERN-010 | MEDIUM | memory/cow/tracker.rs:237 | `dec()` retourne `u32::MAX` si frame non trouvé — callers peuvent l'interpréter comme refcount valide |
| KERN-011 | MEDIUM | memory/virtual/page_table/walker.rs:361-386 | `leaf_entry_ptr` retourne `*mut PageTableEntry` sans check de cohérence de niveau (huge page = None, ok) — mais `ensure_table` élève silencieusement les droits d'une entrée intermédiaire existante (WRITABLE/USER) sans verifier que les feuilles sous-jacentes méritent ces droits |
| KERN-012 | LOW | memory/heap/allocator/global.rs:52-72 | `realloc` ne vérifie pas le retour de `Layout::from_size_align` pour `new_layout` align==layout.align (ok), mais l'ancien pointeur est libéré même si le copy échoue partiellement (ok car copy_nonoverlapping ne peut pas échouer) |
| KERN-013 | **CRITICAL** | memory/heap/large/vmalloc.rs:246-297 | `kalloc` retourne `phys_to_virt(phys_base) + sizeof(VmallocHeader)` — pointeur UTILISATEUR dans la physmap, PAS dans VMALLOC_BASE. Le nom "vmalloc" est trompeur. Conséquence : pas d'isolation d'adressage entre allocations "large" et structures kernel dans physmap ; débordement = corruption arbitraire kernel |
| KERN-014 | HIGH | memory/physical/allocator/slub.rs:317-318 | SLUB freelist XOR key dérivée d'adresse physique prédictible — un attaquant ayant une fuite d'info peut deviner la clé et corrompre la freelist (heap overflow → RCE) |
| KERN-015 | LOW | memory/physical/frame/emergency_pool.rs (const EMERGENCY_POOL_SIZE=256) | OK — la constante respecte la règle SCHED-POOL (≥256) |
| KERN-016 | **CRITICAL** | ipc/shared_memory/mapping.rs:253-380 | `shm_map(desc_idx, pid, hint_virt, requested_perms)` ne vérifie PAS de capability token. N'importe quel process connaissant `desc_idx` peut mapper la région SHM de n'importe quel autre process. Aucun appel à `check_shm_access` |
| KERN-017 | HIGH | ipc/shared_memory/allocator.rs:172-213 | `shm_alloc` n'a pas de limite par owner — un process peut épuiser MAX_SHM_REGIONS=1024 et le pool SHM (DoS) |
| KERN-018 | LOW | ipc/endpoint/lifecycle.rs:180-227 | `endpoint_destroy` recherche l'index par O(MAX_ENDPOINTS) itératif — pas une vuln, juste inefficace |
| KERN-019 | MEDIUM | ipc/channel/raw.rs:84-95 | `InnerRing::enqueue` utilise `data.len().min(MAX_MSG_SIZE)` puis copie `&data[..len]` — si data.len() < MAX_MSG_SIZE c'est ok, mais n'avertit pas si data.len() > MAX_MSG_SIZE (silently truncated) |
| KERN-020 | MEDIUM | ipc/channel/raw.rs:202-225, 259-311 | Auto-open mailbox (RÈGLE IPC-RAW-01) : n'importe quel process peut créer une mailbox pour n'importe quel EndpointId en appelant `send_raw`. MAX_RAW_SLOTS=64 → DoS par épuisement trivial |
| KERN-021 | MEDIUM | syscall/validation.rs:522-562 | `resolve_user_page` vérifie `entry.is_user()` et `entry.is_writable()` mais pas `entry.is_no_execute()` — pas une vuln en soi (NX est enforced par CPU), mais cohérence à revoir |
| KERN-022 | **CRITICAL** | syscall/fixup.rs:165-291 | `copy_from_user_safe` cassé : la boucle lit `FAULTED[cpu_id]` entre itérations, mais après un #PF le handler appelle `fixup_signal_fault` qui ne jump pas à `recovery_rip` ; RIP retourne à l'instruction fautive → **boucle infinie**. Heureusement non câblé dans `validation::copy_from_user` (qui utilise `copy_from_user_resolved`), mais code mort dangereux |
| KERN-023 | **CRITICAL** | syscall/handlers/misc.rs:157-198 | `sys_arch_prctl(ARCH_SET_FS, addr)` écrit `addr` dans `MSR_FS_BASE` sans valider que `addr` est user-canonical. Un process peut positionner FS_BASE sur une adresse kernel et accéder à `fs:[x]` depuis Ring3. Sans KPTI : leak kernel memory. Avec KPTI : #PF mais comportement imprévisible. Linux valide `addr < TASK_SIZE` |
| KERN-024 | **CRITICAL** | syscall/handlers/signal.rs:232-275 + process/signal/delivery.rs:62-97 | `sys_kill` ne vérifie PAS CAP_KILL ni même-UID. `send_signal_number_to_pid` se contente de vérifier que le PID existe. N'importe quel process peut envoyer SIGKILL à n'importe quel autre process |
| KERN-025 | HIGH | syscall/dispatch.rs:189-219 | `verify_syscall` est skippé pour SYS_SCHED_YIELD, SYS_GETPID, SYS_CLOCK_GETTIME — si un process pledged en interdisant ces syscalls, le pledge est bypassé pour ces 3 numéros |
| KERN-026 | MEDIUM | syscall/handlers/fs_posix.rs:200-216 | `sys_chdir` lit le path mais retourne ENOSYS — chemin est donc validé mais l'opération échoue silencieusement. Pas une vuln |
| KERN-027 | LOW | syscall/handlers/process.rs:280-353 | `sys_clone` ne valide pas que `stack` est user — `read_user_typed::<u64>(stack)` le fait indirectement, mais `stack_addr = stack` est utilisé tel quel |
| KERN-028 | HIGH | scheduler/sync/mutex.rs:79-149 | `KMutex` est commenté "héritage de priorité simplifié" mais **aucun PI implémenté**. WaitQueue FIFO. Priority inversion non bornée |
| KERN-029 | **CRITICAL** | scheduler/fpu/lazy.rs:115-135 + scheduler/fpu/save_restore.rs:95-114 | Si `alloc_fpu_state` échoue (IN_RECLAIM ou OOM), `fpu_state_ptr` reste NULL. `xrstor_for()` initialise les registres FPU par défaut sans zone de sauvegarde. Au prochain switch, `xsave_current()` voit NULL et **retourne sans sauvegarder**. L'état FPU est silencieusement perdu → corruption crypto (AES-NI keys leak cross-process) |
| KERN-030 | MEDIUM | drivers/dma.rs:832-928 | `sys_mmio_map_for_pid` exige `claim_contains(pid, phys, size)` mais pas de cap explicite — un process root peut mapper n'importe quel MMIO claimé |
| KERN-031 | LOW | drivers/iommu/mod.rs:32-38 | `force_disable_domain`/`disable_domain_atomic` désactivent un domaine IOMMU sans flush des mappings existants — un device DMA peut toujours accéder à d'anciennes IOVAs jusqu'à ce que le device soit reset |
| KERN-032 | LOW | memory/protection/smap.rs:217-237 | `copy_from_user`/`copy_to_user` de protection/smap.rs sont shadowed par `syscall::validation::copy_from_user`/`copy_to_user` (noms identiques). Les callers doivent importer le bon module. Risque de confusion |

---

## 3. Findings détaillés

### KERN-001 (CRITICAL) — PKU sans PKS : clés kernel heap/guard/MMIO inefficaces

**File:** `kernel/src/memory/protection/pku.rs:274-286`

```rust
pub unsafe fn enable_pku() {
    if !pku_supported() {
        return;
    }
    let cr4 = read_cr4();
    write_cr4(cr4 | CR4_PKE_BIT);      // ← uniquement PKE (user)
    PKU_STATS.enable_count.fetch_add(1, Ordering::Relaxed);

    // PKRU initial : clé 2 (guard) inaccessible.
    let pkru: u32 = pkru_ad_bit(PKU_GUARD_KEY) // clé 2 AD
                  | pkru_wd_bit(PKU_MMIO_KEY); // clé 3 WD
    wrpkru(pkru);
}
```

**Constantes concernées :**
```rust
pub const CR4_PKE_BIT: u64 = 1 << 22;   // PKE = user-mode PKU
pub const CR4_PKS_BIT: u64 = 1 << 24;   // PKS = supervisor-mode PKU  ← jamais utilisé
pub const PKU_KERNEL_HEAP_KEY: u8 = 1;  // clé 1 réservée heap kernel
pub const PKU_GUARD_KEY: u8 = 2;        // clé 2 réservée guard pages
pub const PKU_MMIO_KEY: u8 = 3;         // clé 3 réservée MMIO
```

**Pourquoi c'est une vulnérabilité :**
- `CR4_PKE` active la vérification PKRU **uniquement en Ring 3**.
- `CR4.PKS` (bit 24) activerait la vérification PKRU **en Ring 0**.
- Sans PKS, les clés 1 (kernel heap), 2 (guard), 3 (MMIO) définies dans `enable_pku()` n'ont **aucun effet** en mode supervisor.
- Un débordement kernel sur le heap, un accès à une guard page, ou un write intempestif sur du MMIO via la physmap ne sera PAS bloqué par PKRU.
- Le commentaire du fichier prétend que la clé 1 "isole le heap kernel", ce qui est **faux** en l'état.

**Fix recommandé :**
```rust
write_cr4(cr4 | CR4_PKE_BIT | CR4_PKS_BIT);
```
+ Initialisation explicite de la PKRS (MSR `IA32_PKRS` 0x6E1) à la même valeur que PKRU initial.
+ Assurer que les PTEs du heap kernel portent la clé 1 (`PTE bits 62:59 = 1`), les guard pages la clé 2, le MMIO la clé 3, via `pte_set_pkey()`.

---

### KERN-002 (HIGH) — `copy_from_user`/`copy_to_user` ne valident pas l'espace user

**File:** `kernel/src/memory/protection/smap.rs:217-237`

```rust
pub unsafe fn copy_from_user(kernel_dst: *mut u8, user_src: *const u8, count: usize) {
    let _guard = SmapAccessGuard::new();
    core::ptr::copy_nonoverlapping(user_src, kernel_dst, count);
    // Guard dropped ici → clac automatique.
}

pub unsafe fn copy_to_user(user_dst: *mut u8, kernel_src: *const u8, count: usize) {
    let _guard = SmapAccessGuard::new();
    core::ptr::copy_nonoverlapping(kernel_src, user_dst, count);
}
```

**Pourquoi c'est une vulnérabilité :**
- La fonction est marquée `unsafe` et le contrat "l'appelant garantit que `user_src` est user" est délégué.
- Si un caller oublie de valider, l'ouverture SMAP (STAC) permet au kernel de lire/écrire à une adresse kernel passée par un process malveillant — par exemple un syscall passant un pointeur kernel en arg, le handler appelle `copy_from_user(kernel_buf, attacker_user_ptr, len)` où `attacker_user_ptr = 0xFFFF_8000_0000_0000` (kernel physmap) → le kernel lit sa propre mémoire et la copie dans `kernel_buf` qui est ensuite renvoyée à l'utilisateur via un autre syscall.
- Heureusement, les handlers syscall utilisent `syscall::validation::copy_from_user` (qui valide), pas `memory::protection::copy_from_user`. Mais le shadowing de noms est un piège.

**Fix recommandé :**
- Renommer `memory::protection::copy_from_user` en `memory::protection::raw_copy_from_user` ou exiger un `ValidatedUserPtr` en argument.
- Ajouter un `debug_assert!(is_user_canonical(user_src as u64))` au début.

---

### KERN-003 (MEDIUM) — `sync_user_region_to_shadow` sans lock explicite

**File:** `kernel/src/memory/virtual/page_table/kpti_split.rs:200-214`

```rust
#[inline]
pub unsafe fn sync_user_region_to_shadow(source_pml4_phys: PhysAddr, user_pml4_phys: PhysAddr) {
    if source_pml4_phys.as_u64() == 0 || user_pml4_phys.as_u64() == 0 {
        return;
    }
    if source_pml4_phys.as_u64() == user_pml4_phys.as_u64() {
        return;
    }
    let source_pml4 = phys_to_table_ref(source_pml4_phys);
    let user_pml4 = phys_to_table_mut(user_pml4_phys);
    let mut i = 0usize;
    while i < 256 {
        user_pml4[i] = source_pml4[i];   // ← copie non-atomique
        i += 1;
    }
}
```

**Pourquoi c'est une vulnérabilité :**
- Si un autre CPU modifie `source_pml4[i]` pendant la copie (par exemple fork créant un nouveau PDPT), la shadow KPTI peut capturer un état intermédiaire.
- Le caller doit garantir qu'aucun autre CPU n'a ce process en exécution (typiquement au context switch), mais ce n'est pas documenté ici.
- La copie entry-par-entry n'est pas atomique (entries 64-bit, mais le CPU peut interrompre entre deux stores).

**Fix recommandé :**
- Documenter le pré-requis "caller must hold the page table lock".
- Ou utiliser un seqlock : lire un générateur avant/après la copie, retry si changement.

---

### KERN-005 (HIGH) — `fixup.rs` cassé : handler #PF ne jump pas à recovery_rip

**File:** `kernel/src/syscall/fixup.rs:165-291`

```rust
pub fn copy_from_user_safe(dst: *mut u8, src: *const u8, len: usize, cpu_id: usize) -> bool {
    // ...
    FAULTED[cpu_id.min(FIXUP_MAX_CPUS - 1)].store(false, Ordering::Relaxed);
    let recovery_addr = fault_recovery_stub as *const () as usize;
    unsafe { fixup_enter(cpu_id, recovery_addr); }

    let ok = unsafe {
        let mut faulted_mid = false;
        for i in 0..len {
            if FAULTED[cpu_id.min(FIXUP_MAX_CPUS - 1)].load(Ordering::Relaxed) {
                faulted_mid = true;
                break;
            }
            let byte = core::ptr::read_volatile(src.add(i));   // ← peut faulter
            core::ptr::write(dst.add(i), byte);
        }
        !faulted_mid
    };
    // ...
}

pub fn fixup_signal_fault(cpu_id: usize) {
    if cpu_id >= FIXUP_MAX_CPUS { return; }
    FAULTED[cpu_id].store(true, Ordering::Release);
    fixup_exit(cpu_id);
}
```

**Pourquoi c'est une vulnérabilité :**
- Quand `read_volatile(src.add(i))` déclenche un #PF (page userspace non mappée, par ex. demand paging ou page invalide), le handler #PF appelle `fixup_lookup(cpu_id)` qui retourne `Some(recovery_rip)`.
- Le handler est censé patcher `frame.rip = recovery_rip` et retourner. Mais le commentaire du fichier dit explicitement : "le handler #PF n'utilise pas cette adresse pour un jump réel (on utilise fixup_signal_fault à la place)".
- Donc le handler appelle `fixup_signal_fault(cpu_id)` qui met `FAULTED[cpu_id]=true` et `active=false`, puis **retourne normalement**.
- Le CPU reprend à l'instruction fautive (`read_volatile(src.add(i))`) qui fault à nouveau → **boucle infinie**.
- La boucle `for i in 0..len` vérifie `FAULTED[cpu_id]` **entre** les itérations, pas pendant — donc le #PF à l'intérieur d'une itération n'est jamais interrompu par la vérification.

**Fix recommandé :**
- Soit implémenter un vrai setjmp/longjmp kernel (la recovery_addr doit être le jump target).
- Soit supprimer ce module (il n'est pas câblé : `validation::copy_from_user` utilise `copy_from_user_resolved` qui déclenche le fault handler userspace normal).
- Code mort dangereux à supprimer.

---

### KERN-006 (CRITICAL) — KASAN init() sans empoisonnement shadow map

**File:** `kernel/src/memory/integrity/sanitizer.rs:340-345`

```rust
pub unsafe fn init() {
    // Empoisonner toute la shadow map en SHADOW_UNINIT.
    // En pratique on fait confiance au zeroing de la page table (0x00 = ACCESSIBLE).
    // On active simplement KASAN.
    kasan_enable();
}
```

**Pourquoi c'est une vulnérabilité :**
- Le commentaire l'admet : la shadow map est remplie de zéros, ce qui correspond à `SHADOW_ACCESSIBLE` (0x00).
- Toute la plage KERNEL_HEAP_START..+256 GiB est donc réputée "accessible" par KASAN.
- `kasan_check_access(addr, size)` lit la shadow : `0x00` = Ok, ne détecte rien.
- `kasan_on_alloc` (qui devrait marquer accessible) est no-op (la shadow est déjà accessible).
- `kasan_on_free` marque `SHADOW_FREED` (0xFD) — mais ce n'appelle que `kasan_poison`, qui ne fait rien si KASAN est désactivé. Si KASAN est activé, `kasan_on_free` est appelée par le hybrid allocator... mais la shadow initiale étant accessible, un UAF n'est détecté QUE si `kasan_on_free` a bien été appelée pour cet objet. Si un objet est libéré sans passer par `kasan_on_free` (par ex. via un chemin non-instrumenté), l'UAF n'est pas détectée.

**Fix recommandé :**
- Activer KASAN implique empoisonner la shadow map avec `SHADOW_UNINIT` (0xFF) au boot.
- `kasan_on_alloc` doit appeler `kasan_unpoison(ptr, size)`.
- `kasan_on_free` doit appeler `kasan_poison(ptr, size, SHADOW_FREED)`.
- Ajouter `kasan_on_alloc`/`kasan_on_free` à `hybrid::alloc`/`hybrid::free`.

---

### KERN-008 (HIGH) — CoW in-place break sans vérification de partage complet

**File:** `kernel/src/memory/virtual/fault/cow.rs:41-69`

```rust
let tracked_ref_count = COW_TRACKER.tracked_ref_count(old_frame);
let can_restore_in_place = tracked_ref_count.is_some_and(|rc| rc <= 1) || !old_entry.is_cow();

if can_restore_in_place {
    let new_raw = PageTableEntry::from_page_flags(old_frame, writable_flags).raw();
    match alloc.compare_exchange_pte_raw(page_addr, old_raw, new_raw) {
        // ...
    }
}
```

**Pourquoi c'est une vulnérabilité :**
- `can_restore_in_place` est vrai si `tracked_ref_count ≤ 1` OU si `old_entry.is_cow()` est faux.
- Si une page est partagée via mmap shared (plusieurs process mappent la même page file-backed) mais n'est PAS tracked dans `COW_TRACKER`, alors `tracked_ref_count` retourne `None`, et `can_restore_in_place` devient vrai (à cause du `|| !old_entry.is_cow()`).
- Le code écrit alors `writable_flags` sur le PTE sans copier, **autorisant l'écriture directe sur une page partagée**.
- Conséquence : corruption de la page partagée, vue par tous les autres process qui l'ont mappée.
- Le COW_TRACKER ne track que les frames explicitement marqués via `try_inc()` (typiquement fork). Les pages mmap shared file-backed ne le sont pas.

**Fix recommandé :**
- Supprimer la branche `|| !old_entry.is_cow()`. Si le PTE n'a pas FLAG_COW, ce n'est pas un CoW fault — c'est un write fault normal qui devrait segfault si la VMA n'est pas WRITE.
- Le handler `handle_present_permission_fault` déjà check `vma.flags.contains(VmaFlags::COW) || pte.is_cow()`, donc on ne devrait jamais arriver ici sans COW. Mais la condition est trop permissive.

---

### KERN-013 (CRITICAL) — vmalloc retourne des pointeurs dans la physmap

**File:** `kernel/src/memory/heap/large/vmalloc.rs:246-298`

```rust
pub fn kalloc(size: usize, flags: AllocFlags) -> Result<NonNull<u8>, AllocError> {
    // ...
    let frame = alloc_pages(order as usize, flags)?;
    let phys_base = frame.phys_addr();

    // Obtient l'adresse virtuelle via le physmap.
    let virt_base = phys_to_virt(phys_base);

    // SAFETY: Le physmap couvre intégralement la RAM physique.
    let header_ptr = virt_base.as_u64() as *mut VmallocHeader;
    unsafe {
        header_ptr.write(VmallocHeader { /* ... */ });
    }

    // L'objet utilisateur commence juste après l'en-tête.
    let user_ptr = virt_base.as_u64() + core::mem::size_of::<VmallocHeader>() as u64;
    // ...
    Ok(unsafe { NonNull::new_unchecked(user_ptr as *mut u8) })
}
```

**Pourquoi c'est une vulnérabilité :**
- Le module s'appelle `vmalloc` (suggère VMALLOC_BASE = 0xFFFF_C000_0000_0000), mais les allocations vont dans la **physmap** (PHYS_MAP_BASE = 0xFFFF_8000_0000_0000).
- La physmap est un mapping direct de toute la RAM physique : `phys_to_virt(phys) = PHYS_MAP_BASE + phys`.
- Conséquence : un débordement sur une allocation "vmalloc" peut corrompre n'importe quelle autre donnée résidant dans la physmap, y compris :
  - d'autres allocations vmalloc (compromis trivial)
  - des structures kernel (PCB, TCB, GDT, IDT) si elles sont dans des frames physiques adjacents
  - la page physique du code kernel lui-même (si mutable, mais .text est read-only)
- De plus, le header 64B est placé **en début de frame physique**. Si le frame est partagé (CoW, page cache, etc.), le header écrase les données partagées. Mais `alloc_pages` retourne un frame exclusif, donc pas de partage en pratique.
- La vraie vulnérabilité est l'absence d'isolation d'adressage : une erreur de borne sur une allocation vmalloc ne déclenche pas de guard page (pas de pages non-présentes entre allocations).

**Fix recommandé :**
- Soit utiliser VMALLOC_BASE pour les allocations "vmalloc" (mapper chaque allocation avec ses propres PTEs, insert guard pages entre allocations).
- Soit renommer le module en `large_alloc.rs` et documenter que les allocations vont dans la physmap (mais alors ajouter guard pages via frame_descriptor metadata).

---

### KERN-014 (HIGH) — SLUB freelist XOR key prédictible

**File:** `kernel/src/memory/physical/allocator/slub.rs:317-318`

```rust
fn create_new_slub(&self, inner: &mut SlubCacheInner) -> Result<NonNull<u8>, AllocError> {
    let phys = alloc_slab_backing_page()?;
    let virt_base = crate::memory::core::layout::PHYS_MAP_BASE.as_u64() + phys.as_u64();
    // ...
    let key = (virt_base as usize).wrapping_mul(0x9e3779b97f4a7c15);
    // ...
}
```

**Pourquoi c'est une vulnérabilité :**
- La XOR key de la freelist est dérivée de `virt_base` qui est `PHYS_MAP_BASE + phys`.
- `PHYS_MAP_BASE` est une constante publique.
- `phys` est l'adresse physique du frame backing, déterministe (buddy allocator, premier frame libre).
- Si un attaquant a une fuite d'info (par ex. via /proc ou un autre canal), il peut déterminer `phys` et donc dériver `key`.
- Avec la clé, il peut encoder un faux next-pointer dans un objet libre (heap overflow) et faire pointer la freelist vers une adresse arbitraire → RCE.

**Fix recommandé :**
- Utiliser un PRNG initialisé au boot (RDRAND+stack entropy) pour générer une clé par slub.
- Ou utiliser la technique Linux SLUB freelist randomization + pointer mangling avec une clé par CPU.

---

### KERN-016 (CRITICAL) — `shm_map` sans check de capability

**File:** `kernel/src/ipc/shared_memory/mapping.rs:253-380`

```rust
pub fn shm_map(
    desc_idx: usize,
    pid: ProcessId,
    hint_virt: VirtAddr,
    requested_perms: ShmPermissions,
) -> Result<ShmMapResult, IpcError> {
    // ... (pas de check_shm_access ici)

    // Vérifier que la région existe et est active
    let (n_pages, region_perms, size_bytes) = {
        let dir = SHM_DESC_DIR.lock();
        let desc = unsafe { dir.get(desc_idx) }.ok_or(IpcError::InvalidHandle)?;
        if !desc.is_active() {
            return Err(IpcError::InvalidHandle);
        }
        // Calculer les permissions effectives (intersection)
        let rp = ShmPermissions(requested_perms.0 & desc.permissions);
        let n = desc.page_count();
        // ...
    };
    // ... (map pages)
}
```

**Pourquoi c'est une vulnérabilité :**
- `shm_map` accepte `desc_idx` (un simple `usize`) et `pid` (caller).
- Aucune vérification que `pid` a une capability sur la région `desc_idx`.
- N'importe quel process connaissant `desc_idx` (alloué séquentiellement, donc prédictible : 0, 1, 2, ...) peut mapper la région SHM de n'importe qui.
- Le `requested_perms.0 & desc.permissions` ne fait qu'intersecter les permissions demandées avec celles déclarées par le créateur — mais le créateur peut avoir mis `READ|WRITE`, donnant accès en écriture à tout attaquant.
- `check_shm_access` existe dans `ipc/capability_bridge/check.rs` mais n'est **jamais appelé** par `shm_map`.

**Fix recommandé :**
```rust
pub fn shm_map(
    desc_idx: usize,
    pid: ProcessId,
    hint_virt: VirtAddr,
    requested_perms: ShmPermissions,
    cap_table: &CapTable,
    cap_token: CapToken,
) -> Result<ShmMapResult, IpcError> {
    crate::ipc::capability_bridge::check_shm_access(cap_table, cap_token, /* rights */)?;
    // ...
}
```
+ Modifier le syscall `SYS_EXO_IPC_SHM_MAP` pour passer le cap_token.

---

### KERN-017 (HIGH) — `shm_alloc` sans limite par owner

**File:** `kernel/src/ipc/shared_memory/allocator.rs:172-213`

```rust
pub fn shm_alloc(
    owner: ProcessId,
    perms: ShmPermissions,
    requested_bytes: usize,
) -> Result<ShmHandle, IpcError> {
    if requested_bytes == 0 {
        return Err(IpcError::InvalidArgument);
    }
    let class = ShmSizeClass::for_size(requested_bytes);
    let n_pages = class.pages();
    // ... (pas de check per-owner)

    match shm_create(owner, perms, n_pages) { /* ... */ }
}
```

**Pourquoi c'est une vulnérabilité :**
- `shm_create` alloue un slot dans `SHM_DESC_DIR` (MAX_SHM_REGIONS=1024) et des pages dans le pool SHM.
- Aucune limite par owner : un process malveillant peut appeler `shm_alloc` en boucle et épuiser les 1024 slots + le pool SHM (256 pages par défaut = 1 MiB).
- DoS trivial par épuisement.

**Fix recommandé :**
- Ajouter un compteur `regions_per_owner` et une limite (ex: 32 par process).
- Vérifier `shm_pool_stats().free_pages >= n_pages` avant l'allocation (déjà fait dans `shm_can_alloc`, mais pas appelé par `shm_alloc`).

---

### KERN-020 (MEDIUM) — Auto-open mailbox IPC → DoS par épuisement

**File:** `kernel/src/ipc/channel/raw.rs:202-225` and `259-311`

```rust
pub fn mailbox_open(ep_id: EndpointId) -> bool {
    let id = ep_id.get();
    if id == 0 { return false; }
    if find_slot(id).is_some() { return true; }
    let start = (id as usize).wrapping_mul(2654435761) % MAX_RAW_SLOTS;
    for i in 0..MAX_RAW_SLOTS {
        let idx = (start + i) % MAX_RAW_SLOTS;
        if RAW_TABLE[idx].endpoint_id
            .compare_exchange(0, id, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            OPEN_COUNT.fetch_add(1, Ordering::Relaxed);
            return true;
        }
    }
    false // table pleine
}

pub fn send_raw(ep_id: EndpointId, data: &[u8], flags: u32) -> Result<MessageId, IpcError> {
    // ...
    if find_slot(id).is_none() {
        if !mailbox_open(ep_id) {       // ← auto-open
            return Err(IpcError::OutOfResources);
        }
    }
    // ...
}
```

**Pourquoi c'est une vulnérabilité :**
- `MAX_RAW_SLOTS = 64` (très petit).
- Auto-open : n'importe quel process peut créer une mailbox pour un nouvel `EndpointId` (donc un nouveau slot) en appelant `send_raw` avec un EndpointId jamais vu.
- 64 appels `send_raw` avec 64 EndpointIds différents → table pleine → plus aucun process ne peut créer de mailbox IPC.
- DoS trivial.

**Fix recommandé :**
- Augmenter `MAX_RAW_SLOTS` (ex: 4096).
- Exiger une capability pour `mailbox_open` (pas d'auto-open).
- Ou limiter le nombre de mailboxes par PID.

---

### KERN-022 (CRITICAL) — `fixup.rs` cassé (voir KERN-005 ci-dessus pour détails)

Le module `syscall/fixup.rs` implémente un mécanisme de "fixup" pour les page faults kernel pendant `copy_from_user_safe`/`copy_to_user_safe`. Le mécanisme est **cassé** : après un #PF, le handler appelle `fixup_signal_fault(cpu_id)` qui set `FAULTED[cpu_id]=true` mais ne jump pas à `recovery_rip`. Le CPU reprend à l'instruction fautive → boucle infinie.

Heureusement, ce module n'est PAS câblé dans `validation::copy_from_user` (qui utilise `copy_from_user_resolved` à la place, qui déclenche le fault handler userspace normal via `resolve_user_page`).

**Fix recommandé :** Supprimer `syscall/fixup.rs` entièrement (code mort dangereux).

---

### KERN-023 (CRITICAL) — `sys_arch_prctl(ARCH_SET_FS, addr)` sans validation user

**File:** `kernel/src/syscall/handlers/misc.rs:157-198`

```rust
pub fn sys_arch_prctl(code: u64, addr: u64, _a3: u64, _a4: u64, _a5: u64, _a6: u64) -> i64 {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;
    match code {
        ARCH_SET_FS => {
            // Écrire IA32_FS_BASE MSR — initialise le TLS Ring3.
            unsafe {
                core::arch::x86_64::_mm_mfence();
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0100u32,
                    in("eax") (addr & 0xFFFF_FFFF) as u32,
                    in("edx") (addr >> 32) as u32,
                    options(nomem, nostack),
                );
            }
            0
        }
        ARCH_SET_GS => {
            unsafe {
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0102u32,
                    in("eax") (addr & 0xFFFF_FFFF) as u32,
                    in("edx") (addr >> 32) as u32,
                    options(nomem, nostack),
                );
            }
            0
        }
        // ...
    }
}
```

**Pourquoi c'est une vulnérabilité :**
- `addr` est une valeur u64 arbitraire passée par userspace.
- Aucune validation que `addr` est canonique user (< 0x0000_8000_0000_0000) ou même canonique tout court.
- Un process peut positionner `FS_BASE` à une adresse kernel (ex: `0xFFFF_8000_0000_0000` = physmap).
- En Ring 3, une instruction `mov rax, fs:[0]` tente de lire `FS_BASE + 0` = adresse kernel.
- **Sans KPTI** : la PML4 kernel est chargée en Ring 3, la lecture réussit → **leak de mémoire kernel**.
- **Avec KPTI** : la PML4 user n'a pas de mappings kernel, la lecture fault → #PF en Ring 3, mais le kernel a quand même écrit une valeur arbitraire dans MSR_FS_BASE, ce qui peut avoir d'autres effets (ex: FS_BASE utilisé par le kernel lui-même pour per-CPU data via `gs:[...]` — non, FS_BASE est pour le thread user).
- Linux valide `addr` est canonique et user (`TASK_SIZE`).

**Fix recommandé :**
```rust
ARCH_SET_FS | ARCH_SET_GS => {
    if addr >= USER_ADDR_MAX || !is_canonical(addr) {
        return EINVAL;
    }
    // ... wrmsr
}
```

---

### KERN-024 (CRITICAL) — `sys_kill` sans check CAP_KILL / même-UID

**File:** `kernel/src/syscall/handlers/signal.rs:232-275` + `kernel/src/process/signal/delivery.rs:62-97`

```rust
pub fn sys_kill(pid: u64, signum: u64, _a3: u64, _a4: u64, _a5: u64, _a6: u64) -> i64 {
    use crate::process::signal::delivery::{send_signal_number_to_pid, SendError};
    // ...
    let real_pid: u32 = if target_pid <= 0 { /* ... */ } else { target_pid as u32 };
    // ...
    match send_signal_number_to_pid(Pid(real_pid), sig as u8) {
        Ok(()) => 0,
        Err(SendError::PermissionDenied) => EPERM,
        Err(_) => ESRCH,
    }
}

// process/signal/delivery.rs
pub fn send_signal_number_to_pid(pid: Pid, sig_n: u8) -> Result<(), SendError> {
    if sig_n == 0 || sig_n > MAX_SIGNAL_NUMBER {
        return Err(SendError::InvalidSignal);
    }
    let pcb = PROCESS_REGISTRY
        .find_by_pid(pid)
        .ok_or(SendError::NoSuchProcess)?;
    // ... (aucun check UID/CAP_KILL)
    let thread_ptr = pcb.find_alive_thread();
    // ...
    thread.sig_queue.enqueue(sig_n);
    thread.raise_signal_pending();
    Ok(())
}
```

**Pourquoi c'est une vulnérabilité :**
- `send_signal_number_to_pid` vérifie uniquement que le PID existe.
- Aucun check que l'appelant a CAP_KILL ou le même UID que la cible.
- N'importe quel process peut tuer n'importe quel autre process via `sys_kill(target_pid, SIGKILL)`.
- `send_signal_to_tcb` (appelé par `sys_tgkill`) a le même défaut.

**Fix recommandé :**
```rust
fn check_kill_permission(caller_pid: Pid, target_pid: Pid) -> Result<(), SendError> {
    let caller_pcb = PROCESS_REGISTRY.find_by_pid(caller_pid).ok_or(SendError::PermissionDenied)?;
    let target_pcb = PROCESS_REGISTRY.find_by_pid(target_pid).ok_or(SendError::NoSuchProcess)?;
    // Root (CAP_KILL) peut tout tuer
    if caller_pcb.is_root() { return Ok(()); }
    // Sinon, même UID réel
    let caller_uid = caller_pcb.creds.lock().uid;
    let target_uid = target_pcb.creds.lock().uid;
    if caller_uid != target_uid { return Err(SendError::PermissionDenied); }
    Ok(())
}
```
+ Appeler `check_kill_permission` au début de `send_signal_number_to_pid` (avec le PID appelant récupéré via `current_thread_raw()`).

---

### KERN-025 (HIGH) — `verify_syscall` skippé pour 3 syscalls fast-path

**File:** `kernel/src/syscall/dispatch.rs:189-219`

```rust
if nr != crate::syscall::numbers::SYS_SCHED_YIELD
    && nr != crate::syscall::numbers::SYS_GETPID
    && nr != crate::syscall::numbers::SYS_CLOCK_GETTIME
{
    let zt_ok = {
        use crate::security::zero_trust::{context_for_caller, verify_syscall};
        let ctx = context_for_caller(caller_pid, caller_tid);
        verify_syscall(&ctx, nr).is_ok()
    };
    if !zt_ok {
        // ...
        return EPERM;
    }
}
```

**Pourquoi c'est une vulnérabilité :**
- `verify_syscall` applique les restrictions pledge/zero-trust du process appelant.
- Pour `SYS_SCHED_YIELD`, `SYS_GETPID`, `SYS_CLOCK_GETTIME`, le check est skippé.
- Si un process a pledge'd en interdisant ces 3 syscalls (rare mais possible), le pledge est bypassé.
- `SYS_SCHED_YIELD` peut être utilisé pour des attaques temporelles (DoS coopératif).
- `SYS_CLOCK_GETTIME` peut leak du timing kernel.
- `SYS_GETPID` est informatif mais peut faciliter des attaques par PID guess.

**Fix recommandé :**
- Appliquer `verify_syscall` à TOUS les syscalls, y compris fast-path. Le coût est acceptable (1 lecture atomique de la restriction mask).

---

### KERN-028 (HIGH) — `KMutex` : aucun héritage de priorité malgré le commentaire

**File:** `kernel/src/scheduler/sync/mutex.rs:79-149`

```rust
/// KMutex — Mutex bloquant kernel avec héritage de priorité simplifié
pub struct KMutex<T> {
    owner_tid: AtomicU32,
    waiters: UnsafeCell<WaitQueue>,
    data: UnsafeCell<T>,
}

pub unsafe fn lock_blocking(&self, tid: u32, tcb: *mut ThreadControlBlock) -> KMutexGuard<'_, T> {
    // Fast path (non-contended)
    if self.owner_tid.compare_exchange(0, tid, Ordering::Acquire, Ordering::Relaxed).is_ok() {
        return KMutexGuard { mutex: self };
    }
    // ...
    loop {
        if let Some(node) = WaitNode::alloc(tcb, 0) {
            if !tcb.is_null() {
                (*tcb).set_state(TaskState::Sleeping);
            }
            let wq = &mut *self.waiters.get();
            wq.insert(node);  // ← FIFO, pas de tri par priorité
            // ...
            schedule_block(rq, &mut *tcb);
        }
        // ...
    }
}
```

**Pourquoi c'est une vulnérabilité :**
- Le commentaire du fichier prétend "héritage de priorité simplifié" mais **aucun PI n'est implémenté**.
- `waiters.insert(node)` insère en FIFO, sans tenir compte de la priorité du thread.
- Si un thread haute priorité est bloqué derrière un thread basse priorité tenant le mutex, et un thread moyenne priorité préempte le thread basse → **priority inversion non bornée**.
- Le thread haute priorité peut être bloqué indéfiniment.

**Fix recommandé :**
- Implémenter un priority inheritance protocol :
  - Quand `lock_blocking` est appelé par un thread haute priorité, booster temporairement la priorité du `owner_tid` à la priorité du caller.
  - Au `release()`, restaurer la priorité d'origine du owner.
- Ou utiliser un wait_queue trié par priorité (priority queue).

---

### KERN-029 (CRITICAL) — FPU state silencieusement perdu si alloc_fpu_state échoue

**File:** `kernel/src/scheduler/fpu/lazy.rs:115-135` + `kernel/src/scheduler/fpu/save_restore.rs:95-114`

```rust
// fpu/lazy.rs
pub unsafe fn handle_nm_exception(tcb: &mut ThreadControlBlock) {
    cr0_clear_ts();
    if tcb.fpu_state_ptr == 0 {
        super::save_restore::alloc_fpu_state(tcb);
        // Si l'allocation échoue (IN_RECLAIM ou OOM), fpu_state_ptr reste NULL.
    }
    super::save_restore::xrstor_for(tcb);
    // xrstor_for positionne déjà FPU_LOADED = true dans le TCB.
}

// fpu/save_restore.rs
pub unsafe fn xrstor_for(tcb: &mut ThreadControlBlock) {
    let state_ptr = tcb.fpu_state_ptr as *mut FpuState;
    if state_ptr.is_null() {
        // Ce thread n'a jamais sauvegardé de FPU → charger l'état initial.
        init_fpu_registers();
        tcb.set_fpu_loaded(true);
        return;
    }
    // ...
}

pub unsafe fn xsave_current(tcb: &mut ThreadControlBlock) {
    let state_ptr = tcb.fpu_state_ptr as *mut FpuState;
    if state_ptr.is_null() {
        // FpuState pas encore allouée — rien à sauvegarder.
        tcb.set_fpu_loaded(false);
        return;  // ← retour sans sauvegarder l'état FPU actuel !
    }
    // ...
}
```

**Pourquoi c'est une vulnérabilité :**
- Si `alloc_fpu_state` échoue (contexte IN_RECLAIM ou OOM), `fpu_state_ptr` reste NULL.
- `xrstor_for()` initialise les registres FPU par défaut (FNINIT + LDMXCSR 0x1F80).
- Le thread continue d'utiliser la FPU (FPU_LOADED=true), modifiant les registres.
- Au prochain context switch, `xsave_current(prev)` voit `state_ptr == NULL` et **retourne sans sauvegarder**.
- Le thread suivant récupère les registres FPU du thread précédent → **fuite d'état FPU cross-process**.
- Si le thread précédent faisait du AES-NI (clés AES key schedule dans les registres XMM), les clés sont leakées au thread suivant.
- Le commentaire l'admet : "dégradation gracieuse" — c'est en réalité une corruption silencieuse.

**Fix recommandé :**
- Si `alloc_fpu_state` échoue, le thread doit être tué (SIGKILL) ou blocké jusqu'à ce que l'allocation réussisse.
- Ne jamais laisser `fpu_state_ptr == NULL` avec `fpu_loaded = true`.
- Alternative : utiliser une zone FPU statique par CPU pour le cas OOM (mais alors pas de préemption possible).

---

## 4. Vulnérabilités transversales identifiées par ailleurs

Ces éléments confirment ou approfondissent des problèmes déjà listés dans `01_architecture.md` :

| Issue arch | Confirmando dans 04 |
|---|---|
| A-01 (sys_exo_ipc_send → send_raw au lieu de send_raw_checked) | Non vérifié dans le périmètre de cet audit (table.rs appelle sys_exo_ipc_send, non visible) |
| B-01 (IBPB context-switch) | ✅ Résolu — `scheduler/core/switch.rs:301-306` émet IBPB sur cross-process |
| B-02 (apply_ibrs absent sur non-EIBRS CPUs) | ✅ Résolu — `arch/x86_64/syscall.rs:410` appelle `apply_ibrs()` à l'entrée syscall |
| D-01 (network_server SOCK_RAW sans CAP_NET_RAW) | Hors périmètre |
| D-02 (memory_server attach_shared_region ignore sender_pid) | Lié à KERN-016 — `shm_map` n'a aucun check capability |
| D-03 (scheduler_server escalade SCHED_REALTIME sans cap) | Hors périmètre (exo-scheduler-server) |
| PhoenixWakeEntropy non wired | Hors périmètre |

---

## 5. Verdict

**État général :** Le kernel core présente une architecture défensive en profondeur (SMAP/SMEP/NX/UMIP/PKU, canary, guard pages, KASAN-lite, KPTI, IBPB/IBRS), mais **plusieurs couches de protection sont neutralisées par des bugs d'implémentation** :

1. **PKU sans PKS** (KERN-001) — les clés kernel heap/guard/MMIO ne sont pas enforced en Ring 0.
2. **KASAN neutralisé** (KERN-006) — la shadow map n'est pas empoisonnée au boot, tous les accès heap sont réputés valides.
3. **SHM sans capability** (KERN-016) — n'importe quel process peut mapper n'importe quelle région SHM.
4. **`sys_kill` sans permission check** (KERN-024) — n'importe quel process peut SIGKILL n'importe quel autre.
5. **`sys_arch_prctl` sans validation user** (KERN-023) — un process peut positionner FS_BASE sur une adresse kernel.
6. **FPU state silencieusement perdu** (KERN-029) — fuite d'état FPU cross-process en cas d'OOM.
7. **vmalloc dans physmap** (KERN-013) — pas d'isolation d'adressage pour les grandes allocations kernel.
8. **`fixup.rs` cassé** (KERN-005/022) — code mort dangereux.

**Critical findings à traiter en priorité P0 :**
- KERN-001 (PKS)
- KERN-006 (KASAN)
- KERN-016 (SHM cap)
- KERN-023 (arch_prctl)
- KERN-024 (kill)
- KERN-029 (FPU)

**High findings à traiter en P1 :**
- KERN-002 (copy_from_user user check)
- KERN-005/022 (fixup cassé)
- KERN-008 (CoW in-place break)
- KERN-014 (SLUB XOR key prédictible)
- KERN-017 (shm_alloc DoS)
- KERN-025 (verify_syscall skippé)
- KERN-028 (mutex PI absent)

**Medium / Low :** KERN-003, KERN-004, KERN-007, KERN-009, KERN-010, KERN-011, KERN-012, KERN-015, KERN-018, KERN-019, KERN-020, KERN-021, KERN-026, KERN-027, KERN-030, KERN-031, KERN-032.

**Actions immédiates recommandées :**
1. Patcher KERN-024 (kill permission) et KERN-023 (arch_prctl validation) — trivial, haute valeur.
2. Patcher KERN-016 (shm_map cap check) — require threading cap_token à travers le syscall SHM_MAP.
3. Patcher KERN-029 (FPU OOM) — tuer le thread si alloc_fpu_state échoue.
4. Patcher KERN-001 (PKS) — une ligne : `write_cr4(cr4 | CR4_PKE_BIT | CR4_PKS_BIT)` + init PKRS.
5. Patcher KERN-006 (KASAN) — empoisonner la shadow au boot.
6. Supprimer `syscall/fixup.rs` (KERN-005/022) — code mort cassé.
7. Documenter et auditer `vmalloc` (KERN-013) — décider si migration vers VMALLOC_BASE est nécessaire.

**Fin du rapport 04 — Kernel Core.**
