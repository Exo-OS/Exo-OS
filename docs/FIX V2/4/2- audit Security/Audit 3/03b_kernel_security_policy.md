# 03b — Audit profond : KERNEL SECURITY POLICY (Task 3b)

**Auditeur** : sub-agent Task 3b
**Périmètre** : `kernel/src/security/{access_control,capability,zero_trust,isolation,audit,exploit_mitigations}/`, `kernel/src/security/{ipc_policy,mod}.rs`
**Méthode** : lecture ligne par ligne, cross-check des callers via `grep` sur l'arbre `kernel/src/`, vérification des règles SEC-AC-01/02, CAP-01/02/03, ZT-01/02/03, PLEDGE-01/02/03, SAND-01/02/03, ARULE-01/02, AUDIT-01/02/03, KASLR-01/02/03, CET-01/02/03, CFG-01/02/03, STACK-01/02/03, SSTACK-01/02/03.
**Verdict synthétique** : ❌ **NON-CONFORME** — la plomberie bas-niveau (CapTable 512 slots, ring-buffer 65536, bitmap CFG 1M, code CET/IBT/KASLR structuré) est *présente*, mais l'orchestration runtime est **gravement défaillante** : 5 sous-systèmes majeurs sont **dead code** (CFG enforcement, CET Shadow Stack, SafeStack, isolation/domains, isolation/namespaces, isolation/sandbox), le stack canary kernel est **constant** (`0xDEAD_BEEF_CAFE_BABE`), le KASLR offset n'est **jamais appliqué** aux adresses de symboles kernel, le `CapToken` 24B est **sans MAC** (l'inforgeabilité repose uniquement sur le secret de l'ObjectId séquentiel), `exo_cap_revoke` est **non authentifié** (DoS trivial), et `sys_exo_ipc_publish` permet à **n'importe quel process** de s'élever en `ServiceClass::CryptoServer` (ou tout autre classe Ring1 trusted) simplement en publiant un endpoint nommé `"crypto_server"` — **escalade de privilège critique**. VFS open mint une capability avec droits dérivés des **flags POSIX user-supplied** (GAP-06 toujours ouvert).

---

## 1. Inventaire des fichiers audités

| # | Fichier | Lignes | Statut lecture |
|---|---------|-------:|---------------|
| 1 | `access_control/mod.rs` | 35 | ✅ complet |
| 2 | `access_control/checker.rs` | 155 | ✅ complet |
| 3 | `access_control/object_types.rs` | 71 | ✅ complet |
| 4 | `capability/mod.rs` | 517 | ✅ complet |
| 5 | `capability/table.rs` | 537 | ✅ complet |
| 6 | `capability/token.rs` | 379 | ✅ complet |
| 7 | `capability/verify.rs` | 207 | ✅ complet |
| 8 | `capability/delegation.rs` | 179 | ✅ complet |
| 9 | `capability/revocation.rs` | 50 | ✅ complet |
| 10 | `capability/rights.rs` | 342 | ✅ complet |
| 11 | `capability/namespace.rs` | 195 | ✅ complet |
| 12 | `zero_trust/mod.rs` | 28 | ✅ complet |
| 13 | `zero_trust/context.rs` | 277 | ✅ complet |
| 14 | `zero_trust/labels.rs` | 212 | ✅ complet |
| 15 | `zero_trust/verify.rs` | 390 | ✅ complet |
| 16 | `zero_trust/policy.rs` | 291 | ✅ complet |
| 17 | `zero_trust/process_state.rs` | 286 | ✅ complet |
| 18 | `isolation/mod.rs` | 22 | ✅ complet |
| 19 | `isolation/sandbox.rs` | 316 | ✅ complet |
| 20 | `isolation/domains.rs` | 277 | ✅ complet |
| 21 | `isolation/namespaces.rs` | 325 | ✅ complet |
| 22 | `isolation/pledge.rs` | 284 | ✅ complet |
| 23 | `audit/mod.rs` | 36 | ✅ complet |
| 24 | `audit/logger.rs` | 319 | ✅ complet |
| 25 | `audit/syscall_audit.rs` | 343 | ✅ complet |
| 26 | `audit/rules.rs` | 329 | ✅ complet |
| 27 | `exploit_mitigations/mod.rs` | 82 | ✅ complet |
| 28 | `exploit_mitigations/kaslr.rs` | 183 | ✅ complet |
| 29 | `exploit_mitigations/cet.rs` | 248 | ✅ complet |
| 30 | `exploit_mitigations/cfg.rs` | 210 | ✅ complet |
| 31 | `exploit_mitigations/stack_protector.rs` | 249 | ✅ complet |
| 32 | `exploit_mitigations/safe_stack.rs` | 305 | ✅ complet |
| 33 | `ipc_policy.rs` | 396 | ✅ complet |
| 34 | `security/mod.rs` | 498 | ✅ complet |
| | **TOTAL** | **9422** | |

Cross-check callers via `grep` sur `kernel/src/` : `syscall/table.rs` (sys_exo_ipc_send, sys_exo_ipc_publish, sys_exo_pledge, sys_exofs_object_open, sys_exo_cap_revoke, sys_exo_cap_create), `syscall/dispatch.rs` (audit_syscall_entry/exit, verify_syscall), `process/core/tcb.rs` (STACK_CANARY constant, check_canary), `fs/exofs/syscall/{object_open,object_read,object_write,captable}.rs`, `lib.rs` + `arch/x86_64/boot/early_init.rs` (kaslr_entropy), `ipc/capability_bridge/check.rs` (check_endpoint_access etc.).

---

## 2. Matrice de statut des modules

| Module | Code structuré ? | Intégré au runtime ? | Verdict |
|--------|:----------------:|:--------------------:|:-------:|
| access_control/checker.rs | ✅ | ⚠️ Partiel — `check_access()` jamais appelé par `sys_exo_ipc_send` (utilise `validate_ipc_envelope_auth` à la place) ; jamais appelé par VFS (utilise `pcb.cap_table.check_object` directement) | ⚠️ PARTIAL |
| capability/table.rs (512 slots) | ✅ O(1), lock-free read, ct_eq | ✅ `pcb.cap_table` héritée au fork, `inherit_from_masked` | ✅ OK |
| capability/token.rs (24B) | ✅ | ⚠️ Token **sans MAC** — inforgeabilité repose sur secret de l'ObjectId séquentiel + génération faible | ❌ NON-COMPLIANT |
| capability/verify.rs | ✅ Constant-time, Denied unifié | ✅ | ✅ OK |
| capability/delegation.rs | ✅ CAP-03 enforced | ⚠️ Jamais appelé depuis syscall (pas de `exo_cap_delegate`) | ⚠️ PARTIAL |
| capability/revocation.rs | ✅ O(1) | ⚠️ `revoke_handle` non authentifié — DoS trivial | ❌ NON-COMPLIANT |
| capability/namespace.rs | ✅ cross-ns isolation | ⚠️ Jamais utilisé hors tests | ⚠️ PARTIAL |
| zero_trust/verify.rs | ✅ Fast path Ring1 mask | ✅ `verify_syscall` câblé au dispatch | ✅ OK |
| zero_trust/labels.rs | ✅ Bell-LaPadula + Biba | ⚠️ Comparaisons **NON constant-time** (`>=`/`<=` sur `u8`) | ⚠️ PARTIAL |
| zero_trust/policy.rs | ✅ | ⚠️ MLS bypass pour syscalls ; restrictions limitées (3 mappings seulement) | ⚠️ PARTIAL |
| zero_trust/process_state.rs | ✅ | ✅ restrict_process est monotone, refuse PID 1 | ✅ OK |
| isolation/sandbox.rs (SandboxPolicy) | ✅ | ❌ **DEAD CODE** — jamais instancié, jamais `evaluate()` | ❌ NON-COMPLIANT |
| isolation/domains.rs (DomainContext) | ✅ | ❌ **DEAD CODE** — jamais instancié dans TCB | ❌ NON-COMPLIANT |
| isolation/namespaces.rs (NamespaceSet) | ✅ | ❌ **DEAD CODE** — jamais dans PCB, create/destroy jamais appelés | ❌ NON-COMPLIANT |
| isolation/pledge.rs (PledgeSet) | ✅ | ❌ **DEAD CODE** — `pledge()` syscall n'utilise PAS PledgeSet, utilise restrict_process à la place | ❌ NON-COMPLIANT |
| audit/logger.rs (65536 ring) | ✅ Lock-free | ❌ **PAS tamper-evident** (pas de hash chain, pas de MAC) ; ring en BSS kernel | ❌ NON-COMPLIANT |
| audit/syscall_audit.rs | ✅ | ✅ Câblé dispatch.rs:163,215,305 (GAP-02 résolu) | ✅ OK |
| audit/rules.rs | ✅ | ⚠️ Une seule règle par défaut (`log_all`) ; `add/remove_global_rule`/`set_filter` non authentifiés (kernel R/W suffit) | ⚠️ PARTIAL |
| exploit_mitigations/kaslr.rs | ✅ 512 GiB range, 2 MiB align | ❌ **Offset jamais appliqué aux symboles kernel** (uniquement `phys_to_virt`/`virt_to_phys`) → BOOT-011 confirmé : KASLR effectif = 0 bit | ❌ NON-COMPLIANT |
| exploit_mitigations/cet.rs | ✅ MSR/CR4/WRSS encodés | ❌ **`enable_shadow_stack()` JAMAIS APPELÉ** ; seul `enable_ibt()` est appelé sans vérifier le support effectif | ❌ NON-COMPLIANT |
| exploit_mitigations/cfg.rs (1M bitmap) | ✅ | ❌ **`cfg_validate_indirect_call()` JAMAIS APPELÉ** ; `cfg_lock()` JAMAIS APPELÉ → CFG totalement contournable | ❌ NON-COMPLIANT |
| exploit_mitigations/stack_protector.rs | ✅ Per-thread canary | ❌ **DEAD CODE** — TCB utilise `STACK_CANARY` constant `0xDEAD_BEEF_CAFE_BABE` (tcb.rs:116) | ❌ NON-COMPLIANT |
| exploit_mitigations/safe_stack.rs | ✅ | ❌ **DEAD CODE** — jamais instancié sur threads | ❌ NON-COMPLIANT |
| ipc_policy.rs (51 paires) | ✅ | ✅ `check_direct_ipc` câblé via `enforce_direct_ipc_policy` (A-01 résolu) | ⚠️ PARTIAL (51 paires ≠ 92 documentées) |
| security/mod.rs | ✅ security_init orchestré | ⚠️ `warn_if_not_production_hardened` ne halt pas ; pas de fail-closed sur `!is_hardened()` | ⚠️ PARTIAL |

---

## 3. Table des findings (triés par sévérité)

| ID | Severity | File:line | Résumé |
|----|----------|-----------|--------|
| **POLICY-001** | **CRITICAL** | `ipc_policy.rs:155-190` + `syscall/table.rs:3149-3151` + `zero_trust/verify.rs:36-40` | **Escalade de privilège Ring1** : `sys_exo_ipc_publish` appelle `register_service_class(caller_pid, class)` basé **uniquement sur le nom de l'endpoint** fourni par l'appelant. Aucune authentification (pas de CapToken vérifié, pas de PID gating). N'importe quel process peut publier `"crypto_server"` → devient `ServiceClass::CryptoServer` → `register_ring1_pid(caller_pid)` → `RING1_TRUSTED_MASK` bit set → `trust_for_pid` retourne `Trusted` → accès CryptoKey/DMA/Device, `can_inject_src_pid` = true (forge sender_pid dans IPC), bypass MLS via `ring1_pair_trusted`. |
| **POLICY-002** | **CRITICAL** | `exploit_mitigations/kaslr.rs:96-108` + boot flow | **KASLR inefficace** : l'offset KASLR n'est appliqué QUE dans `phys_to_virt`/`virt_to_phys`. Les adresses de symboles kernel (`.text/.rodata/.data/.bss` et toutes les `static`) restent à leurs adresses link-time (`KERNEL_VIRT_BASE + link_offset`). BOOT-011 confirmé : KASLR effectif ≈ 0 bit pour les symboles kernel. De plus, l'entropie est `tsc ^ KERNEL_LOAD_PHYS_ADDR.rotate_left(17) ^ mb2_info ^ rsdp ^ rdrand?` — si RDRAND indisponible (VM restrictive), l'attaquant peut prédire l'unique source variable (TSC, grossièrement connu). |
| **POLICY-003** | **CRITICAL** | `exploit_mitigations/cfg.rs:124-179` + grep global | **CFG totalement contournable** : `cfg_validate_indirect_call()` (RÈGLE CFG-01) et `cfg_assert_indirect_call()` (RÈGLE CFG-03) sont définies mais **jamais appelées depuis aucun site d'appel indirect** du kernel. `cfg_lock()` (RÈGLE CFG-02) n'est **jamais appelée** → `CFG_LOCKED` reste `false` à vie → un attaquant avec kernel R/W peut appeler `cfg_register_target` à runtime pour ajouter ses propres cibles. |
| **POLICY-004** | **CRITICAL** | `exploit_mitigations/cet.rs:111-142` + `mod.rs:62-71` | **CET Shadow Stack jamais activé** : `enable_shadow_stack()` (RÈGLE CET-01) est défini mais **jamais appelé** depuis `mitigations_init` ni ailleurs. Le commentaire mod.rs:67-69 admet explicitement : *"L'activation effective se fait dans arch_init() après alloc"* — mais grep confirme qu'aucun `arch_init` n'appelle cette fonction. Seul `enable_ibt()` est appelé (mod.rs:75) ; même IBT n'est pas vérifié effectif (pas de test ENDBR violation). |
| **POLICY-005** | **CRITICAL** | `process/core/tcb.rs:116` + `exploit_mitigations/stack_protector.rs` | **Stack canary kernel CONSTANT** : `const STACK_CANARY: u64 = 0xDEAD_BEEF_CAFE_BABE` (tcb.rs:116) est utilisé par `KernelStack::check_canary` (tcb.rs:338-341). **Tous les threads kernel partagent la même valeur**. Le module `stack_protector.rs` (canary par thread via `rng_u64`) est **DEAD CODE** — jamais appelé par le TCB. La valeur est publique (dans le code source) → un attaquant qui écrit un stack overflow exploit connaît la valeur à écrire pour bypasser la détection. |
| **POLICY-006** | **CRITICAL** | `capability/token.rs:168-292` + `capability/verify.rs:113-144` | **CapToken 24B sans MAC** : le token est `{object_id: u64, rights: u32, generation: u32, type_tag: u16, _pad: u16}` sérialisé tel quel sur le fil (`to_bytes`/`from_bytes`). **Aucun MAC, aucune clé KERNEL_SECRET**. L'inforgeabilité repose uniquement sur : (1) ObjectId séquentiel à partir de 1 (`OBJ_ID_COUNTER.fetch_add(1, Relaxed)` mod.rs:113), (2) génération petite (typiquement 0), (3) `SERVICE_CAP_META` lookup par ObjectId. Un attaquant qui observe un token légitime peut forger un token pour n'importe quel ObjectId dans le même namespace en devinant la génération (0 par défaut). |
| **POLICY-007** | **CRITICAL** | `fs/exofs/syscall/object_open.rs:197-262` + `captable.rs:75-89,178-192` | **VFS open mint cap basée sur flags POSIX user-supplied** : `sys_exofs_object_open` accepte des flags POSIX (`O_RDONLY/O_RDWR/O_WRONLY/O_CREAT/...`) et mint une capability avec droits dérivés **directement** de ces flags via `rights_from_open_flags(open_args.flags)` (captable.rs:178-192). `let _ = cap_rights;` (object_open.rs:231) **ignore le paramètre cap_rights** (bitmask auto-déclaré). Aucune autorisation au chemin open : n'importe quel process peut ouvrir n'importe quel chemin avec `O_RDWR` et recevoir `READ|WRITE|CREATE|DELETE|SETMETA`. GAP-06 confirmé ouvert. |
| **POLICY-008** | **CRITICAL** | `capability/mod.rs:342-353` | **`revoke_handle(handle: u32)` non authentifié** : la fonction traduit le handle (32 bits bas de l'ObjectId) en ObjectId et appelle `revocation::revoke()` sans **aucune** vérification que le caller possède la capability qu'il révoque. Comme les ObjectIds sont séquentiels à partir de 1 (mod.rs:113), un attaquant peut énumérer 1..N pour révoquer toutes les caps IPC du système — DoS trivial. La fonction est exposée via `exo_cap_revoke` (syscall). |
| **POLICY-009** | **CRITICAL** | `syscall/table.rs:2914-3006` + `ipc/channel/raw.rs:445-454` | **`send_raw_checked` jamais appelé depuis `sys_exo_ipc_send`** : la v6 a introduit `send_raw_checked` qui appelle `check_access()` via `capability_bridge::check_channel_access` (raw.rs:445-454), mais `sys_exo_ipc_send` (table.rs:3002) appelle toujours `send_raw()` (non vérifié) — le commentaire explicite (ligne 2987-3001) dit que la vérification est faite par `validate_ipc_envelope_auth`. Or `validate_ipc_envelope_auth` appelle `check_token_owner` qui utilise `KERNEL_CAP_TABLE` globale (pas `pcb.cap_table`) et `SERVICE_CAP_META` — contournement du contrat SEC-AC-01. `check_access()` est donc **dead code** dans le path IPC send. |
| **POLICY-010** | **HIGH** | `isolation/domains.rs` (tout le fichier) | **`DomainContext` / `SecurityDomain` DEAD CODE** : aucune PCB ne contient un `DomainContext`, aucune transition n'est effectuée au runtime. `transition_to`, `return_to_previous`, `is_transition_allowed` ne sont jamais appelés. RÈGLES SAND-01/02/03 (sandbox unidirectionnel, isolation stricte) sont inopérantes. Isolation domains = compilation-time only. |
| **POLICY-011** | **HIGH** | `isolation/namespaces.rs` (tout le fichier) | **`NamespaceSet` / `create_namespace` / `destroy_namespace` DEAD CODE** : aucune PCB ne contient `NamespaceSet`, les fonctions `create_namespace`/`destroy_namespace` ne sont jamais appelées depuis quelque path que ce soit. PID/UID/Mount/Net/IPC/User/UTS namespaces sont **non implémentés** au runtime — types uniquement. |
| **POLICY-012** | **HIGH** | `isolation/sandbox.rs` (tout le fichier) | **`SandboxPolicy` DEAD CODE** : la struct est définie avec `deny_all`/`allow_all`/`evaluate`/`check`/`derive_child` mais **jamais instanciée** sur un process, jamais appelée depuis le dispatch syscall. La `record_sandbox_decision` n'est appelée par personne. RÈGLE SAND-01 (réduction monotone) inopérante. |
| **POLICY-013** | **HIGH** | `isolation/pledge.rs` (struct PledgeSet) + `syscall/table.rs:4002-4026` | **`PledgeSet` DEAD CODE** : `pledge()` syscall n'utilise **pas** `PledgeSet` — il appelle `pledge_promises_to_restrictions` + `restrict_process` (zero_trust). `PledgeSet::pledge()`, `PledgeSet::to_sandbox_policy()`, `record_violation()` ne sont jamais appelées. RÈGLE PLEDGE-02 (SIGKILL sur violation) **NON enforced** : la policy `zero_trust` retourne `DenyAndAudit`, pas `Kill`. |
| **POLICY-014** | **HIGH** | `ipc_policy.rs:99-102` | **IPC DAG = 51 paires, pas 92** : `const _: () = assert!(POLICY.len() == 51, ...)` — la table contient 51 entrées bidirectionnelles, mais `01_architecture.md` ligne 8 documente "92 paires kernel". ~45% des paires documentées sont manquantes. Soit la doc surestime, soit le code est incomplet — dans tous les cas, la politique effective est **plus restrictive** que prévu et des services légitimes peuvent être bloqués (ou bien la doc est fausse et l'audit précédent s'est trompé). |
| **POLICY-015** | **HIGH** | `audit/logger.rs:67-91,137-154,181` | **Audit log NON tamper-evident** : `AuditRecord` n'a **pas de champ `prev_hash`/`hash`/`mac`**. `push()` écrit le record tel quel via `ptr::write_volatile`. Pas de chaîne BLAKE3, pas de MAC. Le ring est en `static AUDIT_RING: spin::Mutex<AuditRing>` (BSS kernel). GAP-08 toujours ouvert : un attaquant avec kernel R/W peut **réécrire n'importe quel record** sans détection. |
| **POLICY-016** | **HIGH** | `zero_trust/labels.rs:52-61,92-100,160-176` | **Comparaisons MLS NON constant-time** : `ConfidentialityLevel::can_read`/`can_write` et `IntegrityLevel::can_read`/`can_write` utilisent `>=`/`<=` sur `u8` (repr(u8)). Bien que les valeurs soient bornées (0..=4), le compilateur peut émettre des branches data-dépendantes. `SecurityLabel::dominates` (ligne 174-176) utilise aussi `>=` direct. Pour un MLS sur 5 niveaux, la fuite de timing est minimale mais existe théoriquement. |
| **POLICY-017** | **HIGH** | `exploit_mitigations/safe_stack.rs` (tout le fichier) | **`SafeStack` DEAD CODE** : `safe_stack_new_thread` n'est jamais appelé depuis la création de thread. `safe_stack_check` n'est jamais appelé depuis un context switch. RÈGLE SSTACK-01 (page distincte) inopérante. La fonction `safe_stack_init(cet_active)` est appelée par `mitigations_init` mais ne fait que setter un flag `SS_ENABLED` qui n'est jamais consulté en pratique. |
| **POLICY-018** | **HIGH** | `audit/rules.rs:288-298` + `audit/logger.rs:289-299` | **`add_global_rule`/`remove_global_rule`/`set_filter` non authentifiés** : ces fonctions sont `pub` sans check de capability ou de trust level. Un attaquant avec kernel R/W peut appeler `set_filter(AuditCategory::Capability, false)` pour désactiver le logging des refus capability, ou `remove_global_rule(0)` pour supprimer la règle `log_all`. Pas de protection PKS sur ces atomiques. |
| **POLICY-019** | **MEDIUM** | `zero_trust/verify.rs:233-238,260-265` + `policy.rs:201-232` | **MLS bypass pour Ring1 pair** : `ring1_pair_trusted(sender, receiver)` court-circuite `verify_access` (verify.rs:234, 262). Pour deux PIDs enregistrés comme Ring1 trusted, l'IPC est autorisé **sans vérification MLS** (pas de Bell-LaPadula, pas de Biba). Combiné avec POLICY-001 (registration non authentifiée), un attaquant peut bypasser intégralement MLS en s'enregistrant comme Ring1 + en ciblant un autre service Ring1. |
| **POLICY-020** | **MEDIUM** | `zero_trust/context.rs:208-213` | **`downgrade()` ne met pas à jour le label** : `downgrade(new_level)` modifie `trust_level` atomique mais **pas** `label` (champ non-atomique immuable). Si un thread `Trusted` est downgradé à `Normal`, son label reste `kernel()` (TopSecret/Critical) → la vérification MLS continuera à l'autoriser sur des objets kernel-label. Mitigé par le fait que `context_for_caller` reconstruit un contexte frais à chaque syscall (process_state.rs:109-118), donc `downgrade()` n'affecte que le contexte courant (effet transitoire). |
| **POLICY-021** | **MEDIUM** | `zero_trust/context.rs:208-213` + grep global | **`downgrade()` est dead code** : défini publiquement mais jamais appelé depuis aucune production code path. La RÈGLE ZT-02 ("trust_level ne peut que diminuer") est donc **non enforceée dynamiquement** — un process peut gagner du trust en faisant révoquer puis recréer son contexte. |
| **POLICY-022** | **MEDIUM** | `capability/mod.rs:255-269` | **Race insert meta + token grant** : `create()` libère `KERNEL_CAP_TABLE.lock()` avant `insert_service_cap_meta`. Fenêtre où un token a été minté (object_id=N, generation=0) mais la meta n'est pas encore insérée. Un attaquant qui connaît N (séquentiel) peut forger un wire-token et le passer à `check_token_owner` — mais `lookup_service_cap_meta` retournerait None → `KernelCapError::NotFound` → refus. Donc la race n'est pas directement exploitable, mais l'absence de transaction atomique est fragile. |
| **POLICY-023** | **MEDIUM** | `capability/table.rs:189-217` + `process/lifecycle/fork.rs` | **Héritage fork preserve ALL rights** : `inherit_from` copie **tous** les champs (rights, generation, type_tag) sans filtrage. `inherit_from_masked` (ligne 225-255) existe mais n'est pas toujours utilisé. Si un process enfant hérite de caps avec `GRANT`/`DELEGATE`/`REVOKE`, il peut sous-déléguer ou révoquer des caps du parent (via `revoke_handle` qui est non authentifié — cf. POLICY-008). |
| **POLICY-024** | **MEDIUM** | `exploit_mitigations/kaslr.rs:175-182` | **`mix64` non cryptographique** : la dérivation `slot = mix64(raw_entropy) % KASLR_SLOTS` utilise un finalizer MurmurHash3 — ce n'est pas un CSPRNG. Si `raw_entropy` a peu d'entropie (TSC seul, RDRAND absent), `mix64` n'ajoute **aucune** entropie — il redistribute juste. La mandate crypto exigerait `blake3_derive_key(b"kaslr-slot", raw_entropy)` ou similaire. |
| **POLICY-025** | **MEDIUM** | `audit/syscall_audit.rs:163-244` | **`audit_syscall_entry` log seulement en `Log`/`Alert`** : avec la règle par défaut `new_log_all` (action `Log`), `audit_syscall_entry` log en entry (ligne 230-241). Mais le verdict reste `Allow` — aucun mécanisme d'alerte proactive sur patterns suspects (seuils, fréquence). `AuditVerdict::Kill` (RÈGLE SAU-02) n'est jamais retourné sauf si une règle `Kill` est explicitement ajoutée, ce qui n'arrive pas par défaut. |
| **POLICY-026** | **MEDIUM** | `ipc_policy.rs:155-190` | **`register_service_class` n'a pas de lock contre race condition** : la fonction prend `SERVICE_REGISTRY.write()` mais la vérification "si le PID existe déjà" (ligne 167-178) et l'insertion (ligne 180-188) sont dans la même section critique. Cependant, `register_ring1_pid` et `unregister_ring1_pid` sont appelés **à l'extérieur** de la lock `SERVICE_REGISTRY` implicite (zero_trust atomics séparés). Un autre CPU peut lire `RING1_TRUSTED_MASK` avant que `entry.class` soit publié — TOCTOU mineur sur le statut Ring1. |
| **POLICY-027** | **MEDIUM** | `zero_trust/process_state.rs:38-45` | **`MAX_TRACKED_PIDS = 1024`** : un PID ≥ 1024 est **non restreignable** (restrict_process retourne false, line 56-58). Sur un système avec beaucoup de processes (fork bomb, services dynamiques), les processus à PID élevé sont **exemptés de pledge/sandbox** — fail-open silencieux. |
| **POLICY-028** | **LOW** | `access_control/checker.rs:104-135` | **`check_access` log des 0/0/0/0/0** : tous les appels `audit::log_event` passent `pid=0, tid=0, uid=0, syscall_nr=0, context_data=[0;8]` — le log audit est **inutilisable** pour forensic (pas de corrélation avec l'appelant réel). Le caller (`caller: &'static str`) n'est pas non plus loggé. |
| **POLICY-029** | **LOW** | `audit/logger.rs:137-154` | **Ring buffer overflow écrase silencieusement** : `push()` avance `tail` quand le buffer est plein (RÈGLE AUDIT-03) et incrémente `overflow` counter, mais **n'alerte pas** exo_shield. Un attaquant qui génère massivement des événements peut écraser les records d'audit pertinents avant qu'ils soient drainés par exo_shield. |
| **POLICY-030** | **LOW** | `capability/namespace.rs:107-117` | **`alloc_object_id` encode NamespaceId dans bits 48-63** : un attaquant qui connaît la structure peut forger un ObjectId avec un namespace arbitraire (16 bits hauts). Mais `cross_namespace_verify` rejette si les namespaces diffèrent — protection effective. Risque faible car l'ObjectId est de toute façon forgeable (POLICY-006). |
| **POLICY-031** | **LOW** | `zero_trust/context.rs:222-229` | **`add_restriction` / `remove_restriction` sont pub** : `remove_restriction` permet de **retirer** une restriction active, violant potentiellement RÈGLE ZT-02. Commentaire dit "réservé aux opérations d'escalade autorisée" mais **aucun check d'autorisation**. Un attaquant avec kernel R/W peut `remove_restriction(PLEDGE_ACTIVE)` pour désactiver pledge. |
| **POLICY-032** | **LOW** | `exploit_mitigations/cet.rs:111-141` | **`enable_shadow_stack` n'est pas `unsafe fn` marquée comme telle** : la fonction est `pub unsafe fn` (correct), mais `wrmsr(MSR_IA32_S_CET, ...)` (ligne 125) est appelé **avant** `wrmsr(MSR_IA32_PL0_SSP, ...)` (ligne 128) — un ordre incorrect peut causer un fault. La doc Intel SDM recommande de setter PL0_SSP en premier. |
| **POLICY-033** | **LOW** | `audit/rules.rs:243-258` | **`RuleSet::evaluate` parcourt 64 règles même si aucune ne matche** : O(64) par syscall. Pour MAX_USER_SYSCALL=511 et ~10^6 syscalls/s, c'est 64M opérations/s. Acceptable mais non négligeable. |
| **POLICY-034** | **LOW** | `exploit_mitigations/stack_protector.rs:29` | **`__stack_chk_guard` est `AtomicU64` en BSS kernel** : si le compilateur `-fstack-protector` l'utilise via `__stack_chk_guard` symbol, la valeur est lisible depuis n'importe quel code kernel (pas protégé par PKS). Un attaquant avec kernel R/W peut la lire et forger un canary. |

---

## 4. Détails des findings CRITICAL

### POLICY-001 — Escalade de privilège via `exo_ipc_publish` non authentifié (CRITICAL)

**File:line** : `kernel/src/security/ipc_policy.rs:155-190` + `kernel/src/syscall/table.rs:3143-3151` + `kernel/src/security/zero_trust/verify.rs:36-62,233-238`.

**Verbatim code snippet** :
```rust
// syscall/table.rs:3143-3151 (sys_exo_ipc_publish path)
if crate::ipc::channel::raw::mailbox_open(ep) {
    if let Err(err) = crate::ipc::endpoint::register_endpoint(&name, ep) {
        crate::ipc::channel::raw::mailbox_close(ep);
        let _ = release_ipc_endpoint_owner(endpoint, caller_pid);
        return ipc_error_to_errno(err);
    }
    if let Some(class) = service_class_for_endpoint_name(&name) {
        let _ = crate::security::register_service_class(Pid(caller_pid), class);  // ← NO AUTH
    }
    // ...
}

// ipc_policy.rs:155-190
pub fn register_service_class(pid: Pid, class: ServiceClass) -> bool {
    if pid.0 == INIT_SERVER_PID
        || pid.0 == IPC_BROKER_PID
        || class == ServiceClass::InitServer
        || class == ServiceClass::IpcBroker
        || class == ServiceClass::Unknown
    {
        return false;
    }
    let mut reg = SERVICE_REGISTRY.write();
    // ... si is_ring1_trusted_class(class) :
    crate::security::zero_trust::register_ring1_pid(pid.0);  // ← ÉLÉVATION
}

// zero_trust/verify.rs:52-62
pub fn ring1_pair_trusted(sender_pid: u32, receiver_pid: u32) -> bool {
    let mask = RING1_TRUSTED_MASK.load(Ordering::Acquire);
    (mask & sender_bit) != 0 && (mask & receiver_bit) != 0
}
```

**Pourquoi vulnérabilité** :
- `service_class_for_endpoint_name(&name)` (table.rs:2779-2798) mappe un **nom d'endpoint string** à un `ServiceClass` sans aucune vérification.
- N'importe quel process (PID ≥ 3) peut appeler `exo_ipc_publish(endpoint_id, "crypto_server", ...)` — si le nom "crypto_server" n'est pas déjà pris, le process devient `ServiceClass::CryptoServer`.
- `register_service_class` appelle `register_ring1_pid(caller_pid)` qui set un bit dans `RING1_TRUSTED_MASK`.
- Dès lors, le process bénéficie de :
  1. `trust_for_pid(caller_pid)` retourne `TrustLevel::Trusted` (process_state.rs:100-102) → accès `CryptoKey`, `DmaChannel`, `Device` (policy.rs:237-256).
  2. `can_inject_src_pid(caller_pid)` retourne `true` (ipc_policy.rs:228-230) → peut **forger n'importe quel sender_pid** dans les enveloppes IPC (table.rs:2950,2961,2974-2978) — un attaquant peut se faire passer pour `init_server` (PID 1) auprès des serveurs Ring1.
  3. `ring1_pair_trusted(attacker, victim)` retourne `true` pour toute cible déjà Ring1 trusted → **bypass MLS complet** (verify.rs:233-238).
  4. `check_direct_ipc(attacker, victim)` autorise toutes les paires documentées comme incluant `CryptoServer` (ipc_policy.rs:50-51,78-79,85-86) → IPC DAG bypass.

**Scénario d'attaque** :
1. Attaquant fork un process enfant (PID ≥ 3).
2. L'enfant appelle `exo_ipc_publish(0x1234_0000_0000_0007, "crypto_server", ...)`. Si le legitimate crypto_server n'a pas encore publié, l'appel réussit.
3. L'enfant est maintenant enregistré comme `CryptoServer` + `RING1_TRUSTED_MASK` bit set.
4. L'enfant appelle `exo_ipc_send(endpoint_vers_memory_server, envelope_avec_sender_pid=1, ...)` — `caller_can_inject` retourne true → l'enveloppe est acceptée avec `sender_pid = 1` (init_server).
5. memory_server traite la requête comme venant d'init_server (trusted) → exécute l'opération privilégiée demandée par l'attaquant.

**Fix recommandé** :
1. `service_class_for_endpoint_name` ne doit jamais être appelé sans vérifier un CapToken de service signé par le kernel (cf. `exo_cap_create` qui exige `check_direct_ipc(init, target_pid)`).
2. Ajouter un paramètre `service_cap: CapToken` à `exo_ipc_publish` ; valider via `check_token_owner(service_cap, IPC_PUBLISH, caller_pid, INIT_PID, IpcEndpoint)` avant `register_service_class`.
3. Refuser `register_service_class` si le PID caller n'est pas child-direct de init (PID 1) ou n'a pas de cap `CAP_SERVICE_REGISTER`.
4. Logger toute tentative de `register_service_class` comme `AuditCategory::Auth` pour audit forensique.

---

### POLICY-002 — KASLR inefficace : offset jamais appliqué aux symboles kernel (CRITICAL, BOOT-011 confirmé)

**File:line** : `kernel/src/security/exploit_mitigations/kaslr.rs:96-108` + absence d'usage de `kaslr_offset()` ailleurs.

**Verbatim code snippet** :
```rust
// kaslr.rs:96-108
#[inline]
pub fn phys_to_virt(phys: u64) -> u64 {
    let offset = KASLR_OFFSET.load(Ordering::Relaxed);
    KERNEL_VIRT_BASE.wrapping_add(offset).wrapping_add(phys)
}
#[inline]
pub fn virt_to_phys(virt: u64) -> u64 {
    let offset = KASLR_OFFSET.load(Ordering::Relaxed);
    virt.wrapping_sub(KERNEL_VIRT_BASE).wrapping_sub(offset)
}

// kaslr.rs:110-116
pub fn kaslr_offset() -> u64 {
    KASLR_OFFSET.load(Ordering::Relaxed)
}
```

**Pourquoi vulnérabilité** :
- `kaslr_offset()` n'est appelé que par `phys_to_virt`/`virt_to_phys`.
- Les **adresses de symboles kernel** (text, rodata, data, bss, et toutes les `static` comme `KERNEL_CAP_TABLE`, `AUDIT_RING`, `SERVICE_REGISTRY`, etc.) sont résolues par le linker à des adresses **fixes** basées sur `KERNEL_VIRT_BASE = 0xFFFF_8000_0000_0000` + offset link-time.
- Aucun mécanisme de relocalisation runtime n'applique `KASLR_OFFSET` aux symboles.
- Un attaquant qui obtient un leak d'adresse (par ex. via une infoleak dans un syscall) connaît l'adresse de TOUS les symboles kernel — KASLR est un no-op pour l'exploitation de ROP/JOP.
- De plus, l'entropie source (`kaslr_entropy`) est `tsc ^ KERNEL_LOAD_PHYS_ADDR.rotate_left(17) ^ mb2_info ^ rsdp ^ rdrand?`. Sans RDRAND (VM restrictive, hypervisor malveillant), l'attaquant peut prédire l'unique source variable (TSC est grossièrement connu au boot).

**Scénario d'attaque** :
1. Attaquant obtient un leak d'adresse via une infoleak (par ex. un printk qui log `%p` d'un pointeur kernel).
2. L'adresse leakée correspond à l'adresse link-time du symbole, qui est **constante** d'un boot à l'autre (à KERNEL_VIRT_BASE fixe).
3. Attaquant construit une ROP chain utilisant les adresses de gadgets connues (extract du kernel.elf sur disque).
4. KASLR ne complique en rien l'exploitation.

**Fix recommandé** :
1. Implémenter une **PIE relocation** au boot : linker le kernel en `-pie` et appliquer `KASLR_OFFSET` à toutes les références symboliques via une table de relocalisation.
2. Alternative : mapper le kernel physique à `KERNEL_VIRT_BASE + KASLR_OFFSET` via les PML4, et relocaliser tous les pointeurs de symboles au boot.
3. Exiger `rng_hw_seeded()` avant `kaslr_init` ; si RDRAND indisponible, panic ou refuser le boot.
4. Tester l'entropie effective en mesurant la distribution de `kaslr_offset()` sur 1000 boots en VM sans RDRAND.

---

### POLICY-003 — CFG totalement contournable : validation jamais appelée, table jamais verrouillée (CRITICAL)

**File:line** : `kernel/src/security/exploit_mitigations/cfg.rs:124-187` + grep global confirme 0 caller.

**Verbatim code snippet** :
```rust
// cfg.rs:124-135
pub fn cfg_register_target(addr: u64) -> Result<(), CfgError> {
    if CFG_LOCKED.load(Ordering::Acquire) {
        return Err(CfgError::TableLocked);
    }
    let marked = CFG_TABLE.lock().mark(addr);
    // ...
}

// cfg.rs:140-156 (cfg_register_range idem)

// cfg.rs:161-163
pub fn cfg_lock() {
    CFG_LOCKED.store(true, Ordering::Release);
}

// cfg.rs:170-179
pub fn cfg_validate_indirect_call(target: u64) -> Result<(), CfgError> {
    CFG_CHECKS.fetch_add(1, Ordering::Relaxed);
    let valid = CFG_TABLE.lock().is_valid(target);
    if valid { Ok(()) } else { CFG_VIOLATIONS.fetch_add(1, ...); Err(...) }
}
```

**Pourquoi vulnérabilité** :
- `grep -rn "cfg_validate_indirect_call\|cfg_assert_indirect_call" kernel/src/` ne retourne **que** les définitions dans `cfg.rs` et les re-exports dans `mod.rs`. Aucun site d'appel.
- `grep -rn "cfg_lock\(\)" kernel/src/` ne retourne que la définition. La table n'est **jamais verrouillée**.
- Conséquence : un attaquant qui obtient kernel R/W peut appeler `cfg_register_target(malicious_addr)` à runtime pour whitelister ses propres gadgets JOP.
- Le bitmap 1M d'entrées consomme 128 KiB de BSS pour **rien** — aucune vérification runtime n'a lieu sur les appels indirects (fn ptr, vtable, dispatch syscall).

**Scénario d'attaque** :
1. Attaquant obtient une primitive kernel R/W (via un bug kernel).
2. Attaquant appelle `cfg_register_target(my_jop_gadget)` — `CFG_LOCKED` est false, l'appel réussit.
3. Attaquant construit une JOP chain utilisant `my_jop_gadget` comme cible — même si CFG était enforceé, le gadget est whitelisté.

**Fix recommandé** :
1. Instrumenter le compilateur pour insérer `cfg_assert_indirect_call(target)` avant **chaque** call indirect (via `#[cfg_attr(..., plugin_cfg)]` ou pass LLVM).
2. Appeler `cfg_lock()` à la fin de `mitigations_init` (security/mod.rs étape 6) — PAS en step 18 comme dit dans la spec, car aucune autre étape n'ajoute de cibles légitimes après.
3. Migrer la `CFG_TABLE` vers une page read-only après lock (mprotect/PKS).
4. Ajouter un test d'intégration qui vérifie qu'au moins N sites d'appel indirects instrumentés existent (sinon fail build).

---

### POLICY-004 — CET Shadow Stack jamais activé (CRITICAL)

**File:line** : `kernel/src/security/exploit_mitigations/cet.rs:111-142` + `kernel/src/security/exploit_mitigations/mod.rs:62-71`.

**Verbatim code snippet** :
```rust
// mod.rs:62-71 (mitigations_init step 4)
let (ss_ok, ibt_ok) = cet_is_supported();
let cet_active = ss_ok;
if ss_ok {
    // L'adresse du Shadow Stack est allouée par le memory manager
    // avant cet appel (passée via boot protocol) ; ici on ne l'active
    // pas directement pour ne pas dépendre du memory manager à ce stade.
    // L'activation effective se fait dans arch_init() après alloc.
    let _ = ss_ok; // marqué comme géré
}
if ibt_ok {
    unsafe { let _ = enable_ibt(); }
}

// cet.rs:111-142 (enable_shadow_stack - JAMAIS APPELÉE)
pub unsafe fn enable_shadow_stack(shadow_stack_ptr: u64) -> Result<(), CetError> {
    // ... configure CR4.CET, MSR_IA32_S_CET, MSR_IA32_PL0_SSP, RSTORSSP
}
```

**Pourquoi vulnérabilité** :
- `grep -rn "enable_shadow_stack" kernel/src/` ne retourne que la définition et le re-export.
- Le commentaire mod.rs:67-69 dit explicitement que l'activation est **déférée** à `arch_init()` — mais grep confirme qu'aucun `arch_init` n'appelle cette fonction.
- `SHADOW_STACK_ENABLED` reste `false` pour toute la vie du kernel.
- `cet_status()` retourne `(false, ibt_ok?)` — exploitable pour detect par un attaquant (lecture via infoleak).
- RÈGLE CET-01 ("Shadow Stack activé avant la première instruction userspace") est **violée**.
- RÈGLE CET-02 ("Tout retour doit correspondre au Shadow Stack") est inopérante — pas de Shadow Stack = pas de détection de ROP.
- Le handler #CP (Control-flow Protection exception) n'est jamais armé.

**Scénario d'attaque** :
1. Attaquant identifie un stack overflow dans un syscall kernel.
2. Attaquant construit une ROP chain classique (pas besoin de bypass CET).
3. La ROP chain s'exécute sans détection — pas de Shadow Stack pour vérifier les adresses de retour.

**Fix recommandé** :
1. Allouer une page Shadow Stack par CPU au boot (4 KiB minimum).
2. Appeler `enable_shadow_stack(ssp_addr)` dans `mitigations_init` après l'allocation.
3. Pour chaque thread, allouer une user Shadow Stack et configurer `MSR_IA32_PL3_SSP` au context switch.
4. Armer le handler #CP dans l'IDT pour panic en cas de violation.
5. Vérifier `cet_status() == (true, true)` en fin de `security_init` ; si CPU supporte mais pas activé, panic.

---

### POLICY-005 — Stack canary kernel constant `0xDEAD_BEEF_CAFE_BABE` (CRITICAL)

**File:line** : `kernel/src/process/core/tcb.rs:116` + `kernel/src/process/core/tcb.rs:216,317,338-341` + `kernel/src/security/exploit_mitigations/stack_protector.rs` (dead code).

**Verbatim code snippet** :
```rust
// tcb.rs:116
const STACK_CANARY: u64 = 0xDEAD_BEEF_CAFE_BABE;

// tcb.rs:338-341
pub fn check_canary(&self) -> bool {
    // SAFETY: base a été alloué avec au moins 8 bytes et le canari y est posé.
    unsafe { core::ptr::read(self.base as *const u64) == STACK_CANARY }
}

// tcb.rs:216 (KernelStack::new_heap)
core::ptr::write(base as *mut u64, STACK_CANARY);

// tcb.rs:317 (KernelStack::new_guarded)
core::ptr::write(base as *mut u64, STACK_CANARY);

// stack_protector.rs:28-29 (DEAD CODE — jamais utilisé par le TCB)
#[no_mangle]
pub static __stack_chk_guard: AtomicU64 = AtomicU64::new(0);
```

**Pourquoi vulnérabilité** :
- La valeur `0xDEAD_BEEF_CAFE_BABE` est **hardcoded dans le code source** — publique.
- **Tous les threads kernel** partagent cette même valeur.
- `stack_protector.rs` définit `install_canary(tid, frame_addr)` qui génère un canary aléatoire via `rng_u64()` — mais cette fonction n'est **jamais appelée** par `KernelStack::new_heap` ou `new_guarded`.
- Un attaquant qui écrit un stack overflow exploit connaît la valeur à écrire pour bypasser `check_canary()` — il lui suffit d'écrire `0xDEAD_BEEF_CAFE_BABE` à l'emplacement du canary.
- RÈGLE STACK-01 ("canary jamais sur la pile surveillée") est respectée (canary stocké en base de KernelStack), mais RÈGLE STACK-02 ("valeur 0 invalide") n'exclut pas une valeur publique — la valeur est certes non-nulle mais **prévisible**.

**Scénario d'attaque** :
1. Attaquant identifie un stack buffer overflow dans un syscall.
2. Attaquant construit un payload qui écrase la stack jusqu'au canary, en écrivant `0xDEAD_BEEF_CAFE_BABE` à l'offset du canary.
3. La fonction retourne, `check_canary()` compare `0xDEAD_BEEF_CAFE_BABE == 0xDEAD_BEEF_CAFE_BABE` → OK.
4. L'attaque continue avec ROP (cf. POLICY-004 pour le bypass CET absent).

**Fix recommandé** :
1. Remplacer `const STACK_CANARY: u64 = 0xDEAD_BEEF_CAFE_BABE` par un `static STACK_CANARY: AtomicU64` initialisé dans `stack_protector_init()` avec `rng_u64()`.
2. Appeler `install_canary(tid, frame_addr)` dans `KernelStack::new_heap` et `new_guarded`.
3. Utiliser le `StackGuard` par thread (stack_protector.rs:48-117) au lieu d'un canary global.
4. Stocker le canary dans le TCB (pas sur la pile) — déjà le cas via `base as *mut u64`, mais la valeur doit être aléatoire ET par thread.

---

### POLICY-006 — CapToken 24B sans MAC, inforgeabilité repose sur secret faible (CRITICAL)

**File:line** : `kernel/src/security/capability/token.rs:168-292` + `kernel/src/security/capability/verify.rs:113-144` + `kernel/src/security/capability/mod.rs:107-114`.

**Verbatim code snippet** :
```rust
// token.rs:168-181 (struct CapToken)
#[repr(C)]
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct CapToken {
    pub(super) object_id: ObjectId,    // u64 — séquentiel à partir de 1
    pub(super) rights: Rights,         // u32 — bitmask
    pub(super) generation: u32,        // 0 par défaut, incrémenté à chaque revoke
    pub(super) type_tag: CapObjectType,// u16 — enum publique
    pub(super) _pad: u16,
}

// token.rs:263-292 (to_bytes / from_bytes — pas de MAC)
pub fn to_bytes(self) -> [u8; CAP_TOKEN_WIRE_SIZE] {
    let mut buf = [0u8; CAP_TOKEN_WIRE_SIZE];
    buf[0..8].copy_from_slice(&self.object_id.0.to_ne_bytes());
    buf[8..12].copy_from_slice(&self.rights.bits().to_ne_bytes());
    buf[12..16].copy_from_slice(&self.generation.to_ne_bytes());
    buf[16..18].copy_from_slice(&(self.type_tag as u16).to_ne_bytes());
    buf
}

// mod.rs:107-114 (ObjectId séquentiel)
static OBJ_ID_COUNTER: AtomicU64 = AtomicU64::new(1);
#[inline]
fn alloc_object_id() -> token::ObjectId {
    token::ObjectId::from_raw(OBJ_ID_COUNTER.fetch_add(1, Ordering::Relaxed))
}

// verify.rs:113-144 (verify — utilise stored_rights, pas token.rights)
pub fn verify(table: &CapTable, token: CapToken, required_rights: Rights) -> Result<(), CapError> {
    let entry_opt = table.get(token.object_id());  // lookup par ObjectId
    let stored_gen = entry_opt.as_ref().map(|e| e.generation).unwrap_or(u32::MAX);
    let stored_rights = entry_opt.as_ref().map(|e| e.rights).unwrap_or(Rights::empty());
    let gen_ok = stored_gen.ct_eq(&token.generation());
    let rights_ok = stored_rights.contains_ct(required_rights);
    let access_ok = entry_found & gen_ok & rights_ok;
    // ...
}
```

**Pourquoi vulnérabilité** :
- Le token est **sans MAC, sans signature, sans clé KERNEL_SECRET**. La "preuve Coq d'inforgeabilité" mentionnée dans le commentaire (token.rs:160-163) repose sur l'invariant `I1` : `∀ t créé par grant, t.generation == table.entry[t.object_id].generation`. Mais cet invariant ne dit rien sur la capacité d'un attaquant à **construire** un token avec un ObjectId arbitraire.
- L'ObjectId est séquentiel à partir de 1 (`OBJ_ID_COUNTER.fetch_add(1, Relaxed)`) — un attaquant qui observe un token légitime connaît la séquence.
- La génération est typiquement 0 (incrémentée à chaque revoke — rare en pratique).
- Le type_tag est une enum publique (`CapObjectType::IpcEndpoint = 1`, etc.).
- `verify()` ne vérifie pas `token.rights` — il utilise `stored_rights` de la table. Donc un attaquant peut mettre n'importe quelle valeur dans `rights`, le check passe si la table a les droits.
- Le seul garde-fou est `SERVICE_CAP_META` (mod.rs:80-145) qui mappe `ObjectId → (owner_pid, target_pid, type_tag)` et est consulté par `check_token_owner` (mod.rs:317-333). Si l'attaquant ne connaît pas le bon `(owner_pid, target_pid)` pour un ObjectId, il est refusé. Mais l'attaquant **connaît** son propre `caller_pid` (qu'il passe comme `expected_owner_pid`) et le `target_pid` (qu'il déduit de l'endpoint cible). Donc il peut forger un token pour un ObjectId qu'il possède légitimement, mais pas pour un ObjectId d'un autre owner.

**Cependant** : la vulnérabilité réside dans le fait que **l'inforgeabilité est garantie par le secret de l'ObjectId**, qui n'est pas secret (séquentiel). Si un attaquant peut :
- observer un token légitime (par ex. via IPC sniffer ou infoleak),
- OU deviner l'ObjectId (séquentiel, déterministe),
il peut forger un wire-token avec ce ObjectId + generation=0 + IpcEndpoint, et l'utiliser dans un message IPC en se faisant passer pour le légitime owner — **si le owner_pid attendu n'est pas strictement vérifié**.

`check_token_owner` (mod.rs:317) vérifie `meta.owner_pid == expected_owner_pid` où `expected_owner_pid = caller_pid` (fourni par `validate_ipc_envelope_auth` à partir du syscall). Donc l'attaquant ne peut pas usurper un owner différent du sien. **Mais** si l'attaquant a déjà légitimement un token pour un endpoint A, il peut le réutiliser pour un endpoint B tant que l'ObjectId est le même — or les ObjectIds sont uniques par mint, donc ce cas est évité.

**La vraie vulnérabilité** : combiné avec POLICY-001 (escalade Ring1), un attaquant qui s'est fait passer pour CryptoServer peut mint des tokens légitimes pour son propre compte et les utiliser pour IPC vers d'autres Ring1 services (memory_server, vfs_server) — bypassant toute la chaîne de confiance.

**Fix recommandé** :
1. Ajouter un champ `mac: [u8; 16]` au `CapToken` (BLAKE3-MAC avec KERNEL_SECRET).
2. `to_bytes` inclut le MAC ; `from_bytes` le valide (ou la validation a lieu dans `verify()`).
3. `CapTable::grant` calcule `mac = blake3_mac(KERNEL_SECRET, object_id ‖ rights ‖ generation ‖ type_tag)`.
4. `verify()` recompute le MAC et le compare en constant-time via `subtle::ConstantTimeEq`.
5. Ne PAS stocker le MAC dans la `CapTable` (le token est self-contained).
6. Si `KERNEL_SECRET` n'est pas encore initialisé (cf. INTEG-004 du rapport 03a), refuser `grant` au lieu de mint avec MAC à clé zéro.

---

### POLICY-007 — VFS open mint cap basée sur flags POSIX user-supplied (CRITICAL, GAP-06 confirmé)

**File:line** : `kernel/src/fs/exofs/syscall/object_open.rs:197-262` + `kernel/src/fs/exofs/syscall/captable.rs:75-89,178-192`.

**Verbatim code snippet** :
```rust
// object_open.rs:197-262 (sys_exofs_object_open)
pub fn sys_exofs_object_open(
    path_ptr: u64, _path_len: u64, flags: u64, out_fd_ptr: u64, args_ptr: u64,
    cap_rights: u64,  // ← IGNORED
) -> i64 {
    // ... path validation, open_args read ...
    // FIX-SEC-T0.3 : l'arg `cap_rights` (bitmask auto-déclaré) n'est plus une preuve
    // d'autorité — on l'ignore. L'autorité réelle = la capability MINTÉE ci-dessous,
    // stockée dans la cap_table du process et vérifiée à chaque opération suivante.
    let _ = cap_rights;  // ← ignored

    let fd = match open_object(&path_buf, actual_len, &open_args) { ... };

    // FIX-SEC-T0.3 : mint d'une capability RÉELLE sur l'objet ouvert, droits dérivés
    // des flags (RDONLY→READ|STAT|LIST ; RDWR→+WRITE|CREATE|DELETE|SETMETA). Le process
    // détiendra cette cap ; object_read/write/stat/… la vérifieront via check_object_cap.
    if let Ok(bid) = OBJECT_TABLE.blob_id_of(fd) {
        let oid = super::captable::object_id_of_blob(&bid);
        if let Err(e) = super::captable::grant_object_cap(oid, super::captable::rights_from_open_flags(open_args.flags)) {
            // ...
        }
    }
    // ...
}

// captable.rs:178-192 (rights_from_open_flags — dérivation USER-SUPPLIED flags)
pub fn rights_from_open_flags(flags: u32) -> u32 {
    let mut r = RIGHT_STAT | RIGHT_LIST;
    if open_flags::can_read(flags) { r |= RIGHT_READ | RIGHT_INSPECT_CONTENT; }
    if open_flags::can_write(flags) { r |= RIGHT_WRITE | RIGHT_CREATE | RIGHT_DELETE | RIGHT_SETMETA; }
    r
}

// captable.rs:75-89 (grant_object_cap — mint dans pcb.cap_table)
pub fn grant_object_cap(object_id: u64, exofs_rights: u32) -> Result<(), i64> {
    let pid = match caller_pid() { Some(p) => p, None => return Ok(()), };
    let pcb = PROCESS_REGISTRY.find_by_pid(Pid(pid)).ok_or(EPERM)?;
    pcb.cap_table
        .grant(cap_oid(object_id), Rights::from_bits_truncate(exofs_rights), CapObjectType::FileInode)
        // ...
}
```

**Pourquoi vulnérabilité** :
- `sys_exofs_object_open` mint une capability avec des droits **dérivés des flags POSIX** fournis par l'appelant (O_RDONLY/O_RDWR/O_WRONLY).
- Il n'y a **aucune autorisation au chemin open** : n'importe quel process peut ouvrir n'importe quel chemin ExoFS avec `O_RDWR` et recevoir `READ|WRITE|CREATE|DELETE|SETMETA` sur cet objet.
- Le paramètre `cap_rights` (bitmask) est **explicitement ignoré** (`let _ = cap_rights;`).
- `open_object` (object_open.rs:66-113) ne fait que valider les flags et résoudre le path — pas de check de capability sur le parent directory ou sur l'objet cible.
- La capability mintée est ensuite vérifiée par `check_fd` (captable.rs:148) sur les opérations read/write/stat — mais comme la cap a été mintée avec tous les droits demandés, le check passe toujours.
- Commentaire captable.rs:175-177 admet explicitement : *"Politique TIER 0 = **permissive à l'open** (tout chemin ouvrable ⇒ on mint les droits correspondant aux flags). Le durcissement « qui peut ouvrir quoi » est le TIER 1."* — TIER 1 n'existe pas dans le code.

**Scénario d'attaque** :
1. Attaquant appelle `sys_exofs_object_open("/etc/shadow", O_RDWR, ...)`.
2. Le kernel mint une cap `READ|WRITE|CREATE|DELETE|SETMETA` sur l'object_id du fichier.
3. Attaquant appelle `sys_exofs_object_write(fd, attacker_data, ...)` — `check_fd` vérifie la cap, qui contient WRITE → OK.
4. Attaquant a écrit dans `/etc/shadow`.

**Fix recommandé** :
1. Exiger une capability `RIGHT_OPEN` sur le répertoire parent (ou sur le path lui-même si le fichier existe).
2. Vérifier une policy MAC/MLS sur le label du fichier vs le label du process (cf. zero_trust `verify_file_read`/`verify_file_write` — déjà implémenté dans `object_read.rs:253` et `object_write.rs:280`, mais PAS dans `object_open`).
3. Mint la cap avec droits **intersection** flags POSIX × droits de la cap parent (et non union).
4. Implémenter TIER 1 : checks d'ownership, ACLs, type enforcement.
5. Refuser `O_CREAT` sans `RIGHT_CREATE` sur le parent directory.

---

### POLICY-008 — `revoke_handle` non authentifié — DoS trivial (CRITICAL)

**File:line** : `kernel/src/security/capability/mod.rs:342-353`.

**Verbatim code snippet** :
```rust
/// Révoque une capability par handle opaque (syscall exo_cap_revoke).
///
/// Traduit le handle (u32 = 32 bits bas de l'ObjectId) en ObjectId, puis
/// incrémente atomiquement la génération dans la table kernel — tous les
/// tokens capturant l'ancienne génération retourneront `Err(Revoked)`.
///
/// # Complexité : O(1) (incrément atomique Release, aucun parcours de liste).
pub fn revoke_handle(handle: u32) -> Result<(), KernelCapError> {
    if !is_initialized() { return Err(KernelCapError::NotSupported); }
    let object_id = token::ObjectId::from_raw(handle as u64);
    let guard = KERNEL_CAP_TABLE.lock();
    let tbl = guard.as_ref().ok_or(KernelCapError::NotSupported)?;
    revocation::revoke(tbl, object_id);
    drop(guard);
    remove_service_cap_meta(object_id);
    Ok(())
}
```

**Pourquoi vulnérabilité** :
- Aucune vérification que le caller possède la capability qu'il révoque.
- Le handle n'est qu'un u32 = 32 bits bas de l'ObjectId — les ObjectIds étant séquentiels à partir de 1, n'importe quelle valeur 1..N correspond à un ObjectId potentiellement valide.
- Exposé via `exo_cap_revoke` syscall (table.rs:5203 mentionne `SYS_EXO_CAP_REVOKE => sys_exo_cap_revoke`).
- Un attaquant peut boucler `for handle in 1..=u32::MAX { exo_cap_revoke(handle); }` et révoquer **toutes** les capabilities IPC du système. Tous les services Ring1 perdent leurs tokens → DoS système complet.

**Scénario d'attaque** :
1. Attaquant exécute : `for i in 1..100000 { exo_cap_revoke(i); }`
2. Tous les tokens IPC émis avant l'attaque sont invalidés (génération bumpée).
3. Tous les services Ring1 ne peuvent plus communiquer — `validate_ipc_envelope_auth` retourne EACCES pour tout message.
4. Le système est incapable de fork, d'ouvrir des fichiers, de chiffrer, etc.

**Fix recommandé** :
1. Ajouter un paramètre `caller_pid: u32` à `revoke_handle` et vérifier `SERVICE_CAP_META[object_id].owner_pid == caller_pid` (ou `caller_pid == INIT_SERVER_PID`).
2. Alternative : exiger un CapToken avec droit `Rights::REVOKE` sur l'ObjectId cible.
3. Logger chaque `revoke_handle` dans l'audit log (catégorie `Capability`, outcome `Kill` ou `Deny`).
4. Rate-limit : max N revokes par seconde par PID.

---

### POLICY-009 — `send_raw_checked` jamais appelé depuis `sys_exo_ipc_send` (CRITICAL, A-01 partiellement résolu)

**File:line** : `kernel/src/syscall/table.rs:2914-3006` + `kernel/src/ipc/channel/raw.rs:445-454` + `kernel/src/security/access_control/checker.rs:94-137`.

**Verbatim code snippet** :
```rust
// syscall/table.rs:2987-3005 (sys_exo_ipc_send — A-01 fix prétendu)
// FIX-A-01 (Security_Audit_Passe2 §A-01) : la vérification de capability
// IPC_SEND est réalisée par validate_ipc_envelope_auth() ci-dessus qui
// retourne EACCES si le token est invalide ou absent.
// KERNEL_CAP_TABLE est private dans crate::security::capability — on utilise
// crate::ipc::capability_bridge::check_ipc_send_allowed() qui encapsule l'accès.
// Si l'enveloppe a été validée (ValidToken), on vérifie via la bridge.
// Pour TrustedCaller/NotRequired, on laisse passer (kernel-internal path).
// FIX-A-01 (Security_Audit_Passe2 §A-01) : vérification capability IPC_SEND.
// validate_ipc_envelope_auth() a déjà rejeté les messages non autorisés (EACCES).
// Pour ValidToken, le token est extrait et vérifié — le validate garantit Rights::IPC_SEND.
// KERNEL_CAP_TABLE n'est pas accessible directement (private) ; la vérification
// est encapsulée dans validate_ipc_envelope_auth() qui retourne IpcEnvelopeAuth::ValidToken
// seulement si le token a passé check_token_owner(). Ici on utilise send_raw car
// la vérification de capability a déjà été faite dans la fonction validate.
match crate::ipc::channel::raw::send_raw(endpoint_id, &payload, raw_flags) {  // ← send_raw, pas send_raw_checked
    Ok(_) => 0,
    Err(err) => ipc_error_to_errno(err),
}

// ipc/channel/raw.rs:445-454 (send_raw_checked — jamais appelé par sys_exo_ipc_send)
pub fn send_raw_checked(
    ep_id: EndpointId, data: &[u8], flags: u32,
    table: &CapTable, token: CapToken,
) -> Result<MessageId, IpcError> {
    crate::ipc::capability_bridge::check_channel_access(table, token, Rights::IPC_SEND)?;
    send_raw(ep_id, data, flags)
}

// access_control/checker.rs:94-137 (check_access — jamais appelé par IPC send)
pub fn check_access(
    table: &CapTable, token: CapToken, object: ObjectKind, required: Rights, caller: &'static str,
) -> Result<(), AccessError> {
    match cap_verify(table, token, required) {
        // ... log audit ...
    }
}
```

**Pourquoi vulnérabilité** :
- A-01 (Security_Audit_Passe2) disait que `sys_exo_ipc_send` appelait `send_raw` au lieu de `send_raw_checked`. Le commentaire à table.rs:2987-3001 **admet explicitement** que `send_raw` est toujours utilisé, justifié par le fait que `validate_ipc_envelope_auth` ferait la vérification.
- Mais `validate_ipc_envelope_auth` appelle `check_token_owner` qui utilise `KERNEL_CAP_TABLE` (globale kernel) — pas `pcb.cap_table` (per-process). Cette table kernel ne contient que les caps émises par `exo_cap_create` (mod.rs:213-277), pas les caps héritées au fork ou mintées par VFS.
- `access_control::check_access` est **mort** dans le path IPC send — il n'est appelé que par `check_endpoint_access`/`check_channel_access`/`check_shm_access` (capability_bridge/check.rs), eux-mêmes appelés par `send_raw_checked`/`recv_raw_checked` (raw.rs:445-468) — mais `send_raw_checked` n'est jamais appelé depuis `sys_exo_ipc_send`.
- `check_access` est aussi appelé par `ipc/channel/sync.rs:668,683`, `mpmc.rs:411,425`, `broadcast.rs:403,417,432`, `raw.rs:452,466` — ces fonctions `*_checked` sont les API kernel-internes, mais le syscall dispatcher ne les utilise pas.
- Conséquence : RÈGLE SEC-AC-01 ("tout accès DOIT passer par check_access") est **violée** sur le path IPC send syscall.

**Cependant** : `enforce_direct_ipc_policy` (table.rs:3800-3842) est appelé avant `send_raw` et valide le DAG IPC via `check_direct_ipc(src, dst)` — c'est un **autre** mécanisme que `check_access`. Donc A-01 est **partiellement** résolu : la policy DAG est enforceée, mais pas la capability token check via `check_access`.

**Scénario d'attaque** :
- Si l'attaquant a un token légitime pour un endpoint A (qu'il a obtenu via `exo_cap_create`), il peut l'utiliser pour endpoint B tant que `check_token_owner` est contourné — or `check_token_owner` vérifie `meta.target_pid == expected_target_pid`, où `expected_target_pid = exo_ipc_endpoint_pid(endpoint)`. Donc ce cas est protégé.
- **Mais** : la fonction `check_token_owner` ne vérifie pas que le token a été minté **pour cet endpoint précis** — seulement que le (owner, target, type) matche. Un attaquant qui possède un token pour endpoint A (owner=attaquant, target=memory_server) peut le réutiliser pour endpoint B (owner=attaquant, target=memory_server) si les deux endpoints appartiennent au même service — bypass potentiel de la granularité endpoint.

**Fix recommandé** :
1. Remplacer `send_raw(endpoint_id, &payload, raw_flags)` par `send_raw_checked(endpoint_id, &payload, raw_flags, &caller_pcb.cap_table, token)` dans `sys_exo_ipc_send`.
2. Extraire le token de l'enveloppe et le passer à `send_raw_checked`.
3. Supprimer le code path `validate_ipc_envelope_auth` qui duplique la logique de vérification.
4. Ajouter un test d'intégration qui vérifie qu'un token pour endpoint A ne peut pas être utilisé sur endpoint B.

---

## 5. Détails des findings HIGH (résumés — voir table §3 pour les snippets)

### POLICY-010 — `DomainContext` / `SecurityDomain` DEAD CODE

Le module `isolation/domains.rs` (277 lignes) définit `SecurityDomain` enum, `DomainContext` struct, `transition_to`, `return_to_previous`, `is_transition_allowed`, `can_access`, `domain_flags` module. **Aucune PCB ne contient un `DomainContext`**, et grep global confirme que `transition_to`/`return_to_previous` ne sont jamais appelés depuis le scheduler ou le context switch. RÈGLE SAND-01 (transitions unidirectionnelles) et SAND-02 (sandbox isolé) sont inopérantes.

### POLICY-011 — `NamespaceSet` DEAD CODE

Le module `isolation/namespaces.rs` (325 lignes) définit `NsId`, `NsKind` (PID/Mount/Network/IPC/User/UTS), `Namespace`, `NamespaceSet`, `create_namespace`, `destroy_namespace`, `can_see`. **Aucune PCB ne contient `NamespaceSet`**, et `create_namespace`/`destroy_namespace` ne sont jamais appelés depuis un syscall. PID/UID/Mount/Net namespaces sont **non implémentés** au runtime.

### POLICY-012 — `SandboxPolicy` DEAD CODE

Le module `isolation/sandbox.rs` (316 lignes) définit `SandboxPolicy` (bitmap 4×u64 = 256 syscalls), `evaluate`, `check`, `derive_child`, `intersect_with`, `record_sandbox_decision`, `sandbox_global_stats`. **Aucune PCB ne contient une `SandboxPolicy`**, et `evaluate`/`check` ne sont jamais appelés depuis le dispatch syscall. Le mécanisme seccomp-like est totalement inerte.

### POLICY-013 — `PledgeSet` DEAD CODE ; PLEDGE-02 non enforced

`isolation/pledge.rs` (284 lignes) définit `PledgeSet` (active, initial, enabled, violations), `pledge`, `to_sandbox_policy`, `record_violation`, `derive_child`. **`PledgeSet` n'est jamais instancié** sur aucun process. `sys_exo_pledge` (table.rs:4002-4026) n'utilise pas `PledgeSet` — il appelle `pledge_promises_to_restrictions(promises)` puis `restrict_process(caller_pid, restrictions)` (zero_trust). `to_sandbox_policy()` (pledge.rs:128-227) n'est jamais appelé. RÈGLE PLEDGE-02 (SIGKILL sur violation) est **non enforced** : `policy.rs::check_restrictions` retourne `DenyAndAudit` (policy.rs:222), pas `Kill`. `pledge.rs::record_violation` (ligne 240) ne fait qu'incrémenter un compteur — pas de SIGKILL.

### POLICY-014 — IPC DAG = 51 paires, pas 92

`ipc_policy.rs:99-102` :
```rust
const _: () = assert!(
    POLICY.len() == 51,
    "IPC policy Ring 1 doit rester synchronisée avec Architecture v7"
);
```
Le commentaire de l'assertion mentionne "Architecture v7" mais `01_architecture.md` ligne 8 dit "92 paires kernel". Soit la documentation est incorrecte, soit 41 paires manquent. Les 51 paires couvrent : init↔6 services, vfs↔{crypto,network,tty}, exo_shield↔{crypto,input,tty,exosh}, exosh↔{ipc_broker,crypto,input,tty,exo_shield}, device↔{virtio,input,ps2,fb,network}, network↔virtio, tty↔{input,fb,vfs}, fb↔{tty,device}, input↔{ps2,tty,exo_shield,exosh}, ps2↔{input,device}. Manquent notablement : scheduler↔{memory,vfs,crypto,network} (uniquement init↔scheduler), crypto↔{memory,vfs exo_shield} (mais crypto↔vfs existe), et probablement d'autres paires inter-services.

### POLICY-015 — Audit log NON tamper-evident

`audit/logger.rs:67-91` `AuditRecord` n'a aucun champ de hash/MAC. `push()` (ligne 137-154) écrit directement le record dans le ring via `ptr::write_volatile`. Pas de chaîne BLAKE3, pas de MAC avec KERNEL_SECRET. Le ring est en `static AUDIT_RING: spin::Mutex<AuditRing>` (BSS kernel). Un attaquant avec kernel R/W peut réécrire n'importe quel record. GAP-08 du rapport précédent reste ouvert. Compare avec `exoledger.rs` qui implémente bien une chaîne BLAKE3 mais qui est séparé de l'audit ring.

### POLICY-016 — Comparaisons MLS non constant-time

`zero_trust/labels.rs:52-61,92-100` :
```rust
pub fn can_read(subject: Self, object: Self) -> bool { subject >= object }
pub fn can_write(subject: Self, object: Self) -> bool { subject <= object }
```
Utilisation de `>=`/`<=` sur `u8` (repr(u8)) — le compilateur peut émettre des branches data-dépendantes. La fuite est minimale (5 niveaux seulement) mais existe. `SecurityLabel::dominates` (ligne 174-176) utilise aussi `>=` direct. La mandate crypto (01_architecture.md) exige des comparaisons constant-time pour les décisions de sécurité.

### POLICY-017 — `SafeStack` DEAD CODE

`exploit_mitigations/safe_stack.rs` (305 lignes) définit `SafeStackState`, `safe_stack_new_thread`, `safe_stack_check`, `safe_stack_assert`, `safe_stack_update_ssp`, `safe_stack_update_usp`, `safe_stack_remove_thread`. **`safe_stack_new_thread` n'est jamais appelé** depuis la création de thread. `safe_stack_check` n'est jamais appelé depuis un context switch. `safe_stack_init(cet_active)` est appelé par `mitigations_init` mais ne fait que setter `SS_ENABLED = !cet_active` (flag non consulté). RÈGLE SSTACK-01 (page distincte) inopérante.

### POLICY-018 — `add_global_rule`/`remove_global_rule`/`set_filter` non authentifiés

`audit/rules.rs:288-298` et `audit/logger.rs:289-299` : fonctions `pub` sans check de capability ou de trust level. `set_filter(AuditCategory::Capability, false)` désactive le logging des refus capability — un attaquant avec kernel R/W peut aveugler l'audit avant une attaque. Pas de protection PKS sur `FILTER_MASK` ou `GLOBAL_RULES`.

### POLICY-019 — MLS bypass pour Ring1 pair trusted

`zero_trust/verify.rs:233-238,260-265` : `ring1_pair_trusted(sender, receiver)` court-circuite `verify_access`. Si deux PIDs sont dans `RING1_TRUSTED_MASK`, l'IPC est autorisé sans vérification Bell-LaPadula/Biba. Combiné avec POLICY-001 (escalade Ring1 non authentifiée), un attaquant peut bypasser intégralement MLS.

### POLICY-020 — `downgrade()` ne met pas à jour le label

`zero_trust/context.rs:208-213` : `downgrade(new_level)` modifie `trust_level` atomique mais pas `label` (champ non-atomique immuable). Le label reste `kernel()` même après downgrade à `Normal`. Mitigé par le fait que `context_for_caller` reconstruit un contexte frais à chaque syscall.

### POLICY-021 — `downgrade()` est dead code

`zero_trust/context.rs:208-213` : défini publiquement mais jamais appelé depuis aucune production code path. RÈGLE ZT-02 non enforceée dynamiquement.

### POLICY-022 — Race insert meta + token grant

`capability/mod.rs:255-269` : `KERNEL_CAP_TABLE.lock()` est libéré avant `insert_service_cap_meta`. Fenêtre où un token est minté mais pas encore dans la meta. Non exploitable directement car `lookup_service_cap_meta` retourne None → refus. Mais l'absence de transaction atomique est fragile.

### POLICY-023 — Héritage fork preserve ALL rights

`capability/table.rs:189-217` : `inherit_from` copie tous les champs sans filtrage. `inherit_from_masked` (ligne 225-255) existe mais n'est pas toujours utilisé. Combiné avec POLICY-008 (`revoke_handle` non auth), un enfant peut révoquer les caps du parent.

### POLICY-024 — `mix64` non cryptographique

`exploit_mitigations/kaslr.rs:175-182` : finalizer MurmurHash3 — pas un CSPRNG. N'ajoute pas d'entropie. La mandate crypto exigerait `blake3_derive_key`.

### POLICY-025 — `audit_syscall_entry` log seulement en Log/Alert

`audit/syscall_audit.rs:163-244` : avec la règle par défaut `new_log_all` (action `Log`), le verdict reste `Allow`. Aucun mécanisme d'alerte proactive sur patterns suspects. `AuditVerdict::Kill` (RÈGLE SAU-02) n'est jamais retourné sauf règle explicite.

### POLICY-026 — Race register_service_class vs register_ring1_pid

`ipc_policy.rs:155-190` : `SERVICE_REGISTRY.write()` est pris mais `register_ring1_pid` est appelé dans la section critique. Cependant, `RING1_TRUSTED_MASK` est un atomic séparé — un autre CPU peut le lire avant que `entry.class` soit publié. TOCTOU mineur.

### POLICY-027 — `MAX_TRACKED_PIDS = 1024` fail-open

`zero_trust/process_state.rs:38-45,56-58` : un PID ≥ 1024 est non restreignable. Sur un système avec beaucoup de processes, les processus à PID élevé sont exemptés de pledge/sandbox — fail-open silencieux.

---

## 6. Détails des findings LOW (résumés)

- **POLICY-028** : `check_access` log des 0/0/0/0/0 — inutilisable pour forensic.
- **POLICY-029** : Ring buffer overflow écrase silencieusement — pas d'alerte exo_shield.
- **POLICY-030** : `alloc_object_id` encode NamespaceId dans bits 48-63 — forgeable mais protégé par cross_namespace_verify.
- **POLICY-031** : `add_restriction`/`remove_restriction` sont pub sans check — viol potentiel ZT-02.
- **POLICY-032** : `enable_shadow_stack` set `MSR_IA32_S_CET` avant `PL0_SSP` — ordre incorrect selon Intel SDM.
- **POLICY-033** : `RuleSet::evaluate` parcourt 64 règles O(64) par syscall.
- **POLICY-034** : `__stack_chk_guard` AtomicU64 en BSS kernel — lisible par code kernel.

---

## 7. Réponses aux 22 points de l'audit

| # | Question | Réponse |
|---|----------|---------|
| 1 | `check_access_flags()` appelé depuis syscall handlers ? VFS utilise POSIX flags pas CapToken ? | **`check_access_flags()` n'existe pas** dans `access_control/checker.rs` — c'est une fonction dans `fs/exofs/syscall/object_open.rs:484-509` (vérifie flags POSIX pour read/write). `check_access()` (dans `access_control/checker.rs`) est appelé par `ipc/capability_bridge/check.rs` (check_endpoint/channel/shm_access) mais **PAS par `sys_exo_ipc_send`** (POLICY-009) ni par `sys_exofs_object_open` (POLICY-007). VFS mint une cap basée sur flags POSIX user-supplied — **GAP-06 confirmé**. |
| 2 | `table.rs` 512-slot, per-process ou global ? Inheritable fork ? Brute-force slot ? `ct_eq` ? | Per-process (`pcb.cap_table`). **Inheritable au fork** via `inherit_from`/`inherit_from_masked` (table.rs:189-255). Pas de brute-force slot (lookup par hash, pas par index exposé). `ct_eq` utilisé dans `verify.rs:132` via `subtle::ConstantTimeEq`. ✅ Conforme. |
| 3 | `token.rs` MAC avec KERNEL_SECRET ? Forge par Ring1 ? | **AUCUN MAC** (POLICY-006). Le token est `{object_id, rights, generation, type_tag, _pad}` sérialisé tel quel. Ring1 peut forger un wire-token s'il connaît l'ObjectId (séquentiel) + génération (typiquement 0). |
| 4 | `verify.rs` check revocation ? TOCTOU ? | `verify()` check `stored_gen == token.generation` (verify.rs:132) — révoke = bump génération. TOCTOU possible entre grant et verify (POLICY-022) mais mitigé par `SERVICE_CAP_META`. ✅ Partiellement conforme. |
| 5 | `delegation.rs` RULE-CAP-01 enforced ? | **Oui** : `delegate()` vérifie `delegated_rights.is_subset_of(source_token.rights())` (delegation.rs:57) et `verify(source_table, source_token, Rights::DELEGATE)?` (ligne 52). ✅ Conforme — mais `delegate()` n'est jamais appelé depuis un syscall (pas de `exo_cap_delegate`). |
| 6 | `revocation.rs` propagation aux tokens dérivés ? Atomique ? | `revoke()` bump la génération dans la table — **tous** les tokens (dérivés inclus) avec l'ancienne génération sont invalidés. `fetch_add(Release)` est atomique. ✅ Conforme — mais pas de propagation cross-table (un token délégué dans `target_table` reste valide tant que la `target_table` n'est pas révoquée). |
| 7 | `zero_trust/verify.rs` `verify_access` appelé ? GAP-01 ? | **Oui** : `verify_syscall` est câblé au dispatch (dispatch.rs:185-219). `verify_file_read`/`verify_file_write` sont appelés par `object_read.rs:253-254` et `object_write.rs:280-281`. **GAP-01 résolu**. |
| 8 | `labels.rs` Bell-LaPadula + Biba ? Comparisons constant-time ? Downgrade label ? | Implémenté (labels.rs:52-100,160-170). **Comparisons NON constant-time** (POLICY-016) — `>=`/`<=` sur `u8`. Pas de `downgrade` du label (label est immuable après construction). ✅ Partiellement conforme. |
| 9 | `policy.rs` fast path bitmask Ring1↔Ring1 (ERR-09) ? | **Oui** : `ring1_pair_trusted` (verify.rs:52-62) utilise `RING1_TRUSTED_MASK` AtomicU64. `verify_ipc_access`/`verify_ipc_peer_access` court-circuitent `verify_access` si pair trusted (verify.rs:233-238,260-265). ✅ Conforme. |
| 10 | `sandbox.rs` appliqué à `exo compat` ? Stub ? | **DEAD CODE** (POLICY-012). `SandboxPolicy` jamais instancié sur aucun process. Pas d'appel à `policy.evaluate()` ou `policy.check()` depuis le dispatch. |
| 11 | `domains.rs` runtime ou compile-time ? | **Compile-time only** (POLICY-010). `DomainContext` jamais dans TCB, `transition_to` jamais appelé. |
| 12 | `namespaces.rs` PID/UID/Mount/Net tous implémentés ? | **Aucun implémenté** au runtime (POLICY-011). Types uniquement. `NamespaceSet` jamais dans PCB. |
| 13 | `pledge.rs` PLEDGE-01/02/03 enforced ? | PLEDGE-01 (only remove) : **oui** via `restrict_process` (fetch_or monotone). PLEDGE-02 (SIGKILL) : **NON** — policy retourne `DenyAndAudit`, pas `Kill` (POLICY-013). PLEDGE-03 (init can't pledge) : **oui** via `restrict_process` refuse PID 1 (process_state.rs:52-54). |
| 14 | `logger.rs` ring 65536 tamper-evident ? GAP-08 ? | **NON tamper-evident** (POLICY-015). Pas de hash chain, pas de MAC. Ring en BSS kernel. **GAP-08 toujours ouvert**. |
| 15 | `syscall_audit.rs` `audit_syscall_entry/exit` appelés ? GAP-02 ? | **Oui** : dispatch.rs:163 (entry), 215 (exit), 305 (exit). **GAP-02 résolu**. |
| 16 | `rules.rs` default rules ? Désactivable runtime ? | Default : une seule règle `new_log_all` (mod.rs:34). `add_global_rule`/`remove_global_rule`/`set_filter` sont **non authentifiés** (POLICY-018) — un attaquant kernel R/W peut tout désactiver. |
| 17 | `kaslr.rs` entropy source ? Range ? Aligned ? BOOT-011 ? | Range 512 GiB, align 2 MiB, 262144 slots (18 bits). Entropy = `tsc ^ phys_base.rotate(17) ^ mb2_info ^ rsdp ^ rdrand?`. `mix64` non cryptographique (POLICY-024). **Offset jamais appliqué aux symboles kernel** → **BOOT-011 confirmé : KASLR effectif = 0 bit** (POLICY-002). |
| 18 | `cet.rs` activé Phase 2 ou Phase 5 SEC-01 ? `cfg_lock()` step 18 ? | **JAMAIS activé** (POLICY-004). `enable_shadow_stack` jamais appelé. `enable_ibt` appelé mais non vérifié effectif. `cfg_lock()` **jamais appelé** (POLICY-003). |
| 19 | `cfg.rs` `cfg_lock()` appelé ? Bypassable ? | **`cfg_lock()` JAMAIS appelé** (POLICY-003). `cfg_validate_indirect_call` jamais appelé depuis aucun site d'appel indirect. CFG totalement contournable. |
| 20 | `stack_protector.rs` per-thread ou global ? Leak ? | Per-thread défini (`StackGuard`, `install_canary`) mais **DEAD CODE** (POLICY-005). TCB utilise `STACK_CANARY` constant `0xDEAD_BEEF_CAFE_BABE`. `__stack_chk_guard` global en BSS — lisible (POLICY-034). |
| 21 | `safe_stack.rs` unsafe stack isolé ? | **DEAD CODE** (POLICY-017). `safe_stack_new_thread` jamais appelé. SafeStack inerte. |
| 22 | `ipc_policy.rs` DAG 92 paires ? `check_ipc_policy` appelé par `sys_exo_ipc_send` ? A-01 ? | DAG = **51 paires**, pas 92 (POLICY-014). `check_direct_ipc` est appelé via `enforce_direct_ipc_policy` (table.rs:2928,3815) — **A-01 résolu** pour la policy DAG. Mais `send_raw_checked`/`check_access` pas appelés (POLICY-009). |

---

## 8. Verdict final

### Synthèse par sévérité

- **CRITICAL** : 9 (POLICY-001 à POLICY-009)
- **HIGH** : 13 (POLICY-010 à POLICY-022, sauf 022 qui est MEDIUM — recorrection: 020/021 MEDIUM, 022 MEDIUM)
- **MEDIUM** : 8 (POLICY-020, 021, 022, 023, 024, 025, 026, 027)
- **LOW** : 7 (POLICY-028 à POLICY-034)

### Non-conformités critiques

1. **POLICY-001** : Escalade Ring1 non authentifiée via `exo_ipc_publish` → n'importe quel process peut devenir `CryptoServer`/`ExoShield`/etc. → bypass MLS, forge sender_pid, accès CryptoKey/DMA.
2. **POLICY-002** : KASLR jamais appliqué aux symboles kernel → BOOT-011 confirmé (0 bit effectif).
3. **POLICY-003** : CFG totalement contournable (validation jamais appelée, table jamais verrouillée).
4. **POLICY-004** : CET Shadow Stack jamais activé (`enable_shadow_stack` jamais appelé).
5. **POLICY-005** : Stack canary kernel constant `0xDEAD_BEEF_CAFE_BABE` (module stack_protector.rs dead code).
6. **POLICY-006** : CapToken 24B sans MAC — inforgeabilité repose sur secret de l'ObjectId séquentiel.
7. **POLICY-007** : VFS open mint cap basée sur flags POSIX user-supplied (GAP-06 confirmé).
8. **POLICY-008** : `revoke_handle` non authentifié — DoS trivial (révoquer toutes les caps).
9. **POLICY-009** : `send_raw_checked`/`check_access` jamais appelés depuis `sys_exo_ipc_send` (A-01 partiellement résolu).

### Conformités partielles

- **access_control** : `check_access` existe mais n'est appelé que par `ipc/capability_bridge` (kernel-internal API), pas par les syscalls critiques (IPC send, VFS open).
- **capability** : Table per-process, inherit fork, ct_eq — ✅ Mais token sans MAC.
- **zero_trust** : `verify_syscall` câblé (GAP-01 résolu) — mais MLS bypass pour Ring1 pair, comparisons non constant-time.
- **audit** : `audit_syscall_entry/exit` câblés (GAP-02 résolu) — mais log non tamper-evident (GAP-08 toujours ouvert).
- **ipc_policy** : `check_direct_ipc` câblé (A-01 DAG résolu) — mais 51 paires ≠ 92 documentées.

### Conformités validées

- **capability/table.rs** : 512 slots, O(1) verify, lock-free read, `inherit_from_masked` (fork moindre privilège).
- **capability/verify.rs** : Constant-time, `Denied` unifié (CAP-05), `subtle::ConstantTimeEq`.
- **capability/delegation.rs** : RULE-CAP-01 enforced (`is_subset_of`).
- **zero_trust/process_state.rs** : `restrict_process` monotone, refuse PID 1 (PLEDGE-03), héritage fork.
- **audit/syscall_audit.rs** : Entry/exit câblés dispatch.rs.

### Recommandations prioritaires (top 5)

1. **POLICY-001** (P0) : Authentifier `exo_ipc_publish` avec CapToken signé kernel avant `register_service_class`.
2. **POLICY-002** (P0) : Implémenter PIE relocation au boot pour appliquer KASLR offset aux symboles kernel.
3. **POLICY-005** (P0) : Remplacer `STACK_CANARY` constant par canary aléatoire par thread via `install_canary`.
4. **POLICY-006** (P0) : Ajouter MAC BLAKE3-KERNEL_SECRET au CapToken 24B → 40B wire format.
5. **POLICY-003 + POLICY-004** (P0) : Câbler `cfg_validate_indirect_call`/`cfg_lock` et `enable_shadow_stack` dans `mitigations_init`.

### Recommandations secondaires (top 5)

6. **POLICY-007** : Exiger cap `RIGHT_OPEN` sur répertoire parent + check MLS au open.
7. **POLICY-008** : Authentifier `revoke_handle` (vérifier `meta.owner_pid == caller_pid` ou cap `Rights::REVOKE`).
8. **POLICY-009** : Remplacer `send_raw` par `send_raw_checked` dans `sys_exo_ipc_send`.
9. **POLICY-015** : Ajouter chaîne BLAKE3 + MAC KERNEL_SECRET à l'audit ring (fusionner avec exoledger).
10. **POLICY-010/011/012/013/017** : Soit implémenter et câbler les modules dead code (domains/namespaces/sandbox/PledgeSet/SafeStack), soit supprimer pour réduire la surface d'attaque.

---

## 9. Suite logique

- **Task 3c** : audit `kernel/src/process/` (lifecycle/fork, exec, signal) — vérifier l'héritage des caps au fork (POLICY-023), l'enforcement des restrictions zero_trust au exec, et le dispatch des signaux (notamment SIGKILL pledge violation — POLICY-013).
- **Task 3d** : audit `kernel/src/syscall/dispatch.rs` complet — vérifier l'ordre des checks (audit → zero_trust → cap → handler), les fast-paths qui bypassent les checks, et la cohérence avec les RÈGLES SEC-AC-01/02.
- **Task 3e** : audit `kernel/src/fs/exofs/` complet — vérifier l'enforcement des caps ExoFS sur toutes les opérations (read/write/stat/create/delete/gc/snapshot), et le TIER 1 d'autorisation au open (POLICY-007).
- **Task 3f** : audit `kernel/src/ipc/` complet — vérifier que `send_raw_checked`/`recv_raw_checked` sont les seuls chemins kernel-internes utilisés, et que les `*_checked` ne sont pas bypassés par des appels à `send_raw`/`recv_raw` (POLICY-009).

---

**Fin du rapport 03b.**
