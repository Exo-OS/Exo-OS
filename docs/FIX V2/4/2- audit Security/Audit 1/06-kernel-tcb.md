# Audit TCB Kernel — ExoOS Security Core

**Task ID:** AUDIT-6-KERNEL-TCB
**Périmètre:** `kernel/src/security/` — 44 fichiers .rs, ~14 029 lignes lues en intégralité.
**Méthode:** Lecture ligne-par-ligne de chaque fichier du périmètre + analyse architecturale + traçage des chemins d'appel réels (live vs dead code) contre classes de vulnérabilités TCB (TOCTOU, constant-time, race SMP/IRQ, integer overflow, confused deputy, revocation non atomique, policy injection, KASLR leak, CET/CFG bypass, audit tampering, sandbox escape, namespace escape, self-modifying code, code signing bypass, missing zeroization, panic leak, recursion DoS, memory unsafety dans unsafe blocks).
**Date:** 2026-06-21
**Auditeur:** sous-agent kernel senior (TCB, capabilities, zero-trust, isolation, exploit mitigations)

---

## Résumé exécutif

Le TCB ExoOS présente une **architecture riche** (capability + zero-trust MLS + ExoShield v1.0 avec CET/PKS/ExoLedger/ExoKairos/ExoArgos/ExoNmi/ExoSeal) et plusieurs briques réellement solides : `verify()` constant-time via `subtle`, `Rights::contains_ct`/`is_subset_of` constant-time, MLS Bell-LaPadula + Biba correct, garde `key_is_forbidden` anti-régression RFC 8032, SMP SECURITY_READY spin-wait (CVE-EXO-001 corrigé), `inherit_from_masked` moindre-privilège au fork, intégration ExoKairos `register_ttl_for_cap` au `capability::create`.

Cependant, l'audit profond révèle que **plusieurs piliers du TCB sont soit morts au runtime, soit contournables, soit affectés par des races critiques**. Les 5 vulnérabilités principales (top-5 ci-dessous) suffisent à compromettre les garanties annoncées (Secure Boot, capability revocation, PKS isolation, audit integrity, exploit mitigations).

### Top 5 vulnérabilités TCB

1. **[CRITICAL] KTCB-01 — Secure Boot chain-of-trust jamais vérifiée au boot** (`integrity_check/secure_boot.rs:174`, `process/lifecycle/exec.rs:275`) : `verify_boot_attestation()` est défini mais **jamais appelé** depuis `security_init()` / `exoseal_boot_phase0()` / `exoseal_boot_complete()` (grep : 0 appelant runtime). `CHAIN_VERIFIED` reste `false` à vie. Le path `exec.rs:275` court-circuite `check_chain_of_trust()` quand `is_chain_verified()` retourne false → **aucun binaire n'est vérifié** au exec. En dev, le warning `WARNING unsigned binary executed` s'affiche sans bloquer ; en prod (`strict_exec_signatures`), `check_chain_of_trust()` ne retourne jamais Err parce que la branche n'est pas atteinte. La chaîne de confiance UEFI → Exo-Boot → Kernel est **inerte**. Le `SECBOOT_ENFORCE = true` par défaut est cosmétique.

2. **[CRITICAL] KTCB-02 — Capability revocation bypassée sur le path ExoFS** (`capability/table.rs:425` + `fs/exofs/syscall/captable.rs:106`) : `CapTable::check_object()` (utilisé par `check_object_cap` → `check_fd`/`check_blob`/`check_root` → 22 syscalls ExoFS) **ne vérifie pas la génération**. Il appelle `get()` qui fait `find_slot(object_id)` (lookup par OID uniquement) puis retourne `rights.contains(required) && type_tag == ty`. Conséquence : `revocation::revoke(table, oid)` (incrément atomique O(1) de génération, utilisé par `revoke_handle`) **n'invalide pas l'accès ExoFS** — l'entrée est toujours présente dans la table avec les droits originaux. Seul `CapTable::remove()` (qui marque le slot `SLOT_FREE`) invalide réellement. Le path IPC (`verify_typed` → `verify`) vérifie correctement la génération via `ct_eq`, mais le path FS est **aveugle à la révocation**. Bifurcation d'enforcement : un même OID révoqué est refusé en IPC et accepté en FS.

3. **[CRITICAL] KTCB-03 — ExoVeil PKS : race RMW + shadow global vs MSR per-CPU** (`exoveil.rs:261-277`, `292-304`) : `revoke_domain()` et `restore_domain()` font un Read-Modify-Write non atomique sur le shadow `CURRENT_PKRS: AtomicU64` puis `wrpkrs(new_val)` sur le MSR du **CPU courant uniquement**. (a) Race : deux CPUs révoquant des domaines différents peuvent toutes deux loader `0`, calculer leur `new_val` respectif, et la dernière écriture gagne — l'autre révocation est **silencieusement perdue**. Pas de CAS, pas de spinlock. (b) SMP : `wrpkrs` n'écrit que le MSR local ; les autres CPUs conservent l'ancien PKRS — un domaine "révoqué" sur CPU 0 reste accessible sur CPU 1. Aucun IPI broadcast. La protection PKS est **effective seulement sur le CPU qui révoque**. La `ScopedPkrsAccess` RAII a le même problème. `pks_restore_for_normal_ops()` restaure Caps + TcbHot en ReadWrite globalement → après `security_init()`, ces domaines ne sont plus isolés.

4. **[CRITICAL] KTCB-04 — ExoLedger : race sur `LAST_HASH` casse la chaîne cryptographique** (`exoledger.rs:501-527`) : `exo_ledger_append()` (ring buffer, chemin nominal) fait `load_last_hash()` (32 bytes lus byte-par-byte depuis `[AtomicU8; 32]`) → calcule `entry.hash = Blake3(entry || prev_hash)` → `store_last_hash(&entry.hash)` (32 stores byte-by-byte). **Aucun lock** sur ce path (contrairement à `exo_ledger_append_p0` qui prend `P0_CHAIN_LOCK`). Deux appenders concurrents peuvent toutes deux loader le même `prev_hash`, calculer leur hash, et la dernière `store_last_hash` gagne — l'entrée du perdant a un `prev_hash` qui ne correspond plus au `LAST_HASH` courant → `verify_ring_integrity()` retourne `ChainBroken`. Un attaquant qui peut générer 2+ événements audit simultanés (SMP, ou IRQ pendant un append) **casse la chaîne de façon indétectable**. Combiné au ring buffer overflow=overwrite (RÈGLE EXOLEDGER-03) et à la P0 zone limitée à 16 entrées (RÈGLE EXOLEDGER-02), un attaquant peut **DoS l'audit** (remplir P0) puis **casser la chaîne** (concurrent append) pour effacer toute trace.

5. **[CRITICAL] KTCB-05 — Exploit mitigations mortes au runtime + `disable_enforcement()` non capability-gated** (`exploit_mitigations/cfg.rs`, `safe_stack.rs`, `integrity_check/secure_boot.rs:214`) : (a) `cfg_validate_indirect_call()` et `cfg_assert_indirect_call()` — **0 appelant** hors module (grep). RÈGLE CFG-01 "Tout appel indirect doit passer par cfg_validate_indirect_call()" est du **théâtre**. (b) `safe_stack_check()` / `safe_stack_assert()` / `safe_stack_new_thread()` — **0 appelant** hors module. SafeStack logiciel jamais câblé. (c) `install_canary()` / `check_canary()` / `remove_canary()` (table per-thread 1024 entrées) — **0 appelant** hors module ; le TCB (`process/core/tcb.rs`) utilise sa propre constante `STACK_CANARY` et `__stack_chk_guard` global. La table canary par thread est morte. (d) `SandboxPolicy::evaluate()` et `PledgeSet::to_sandbox_policy()` — **0 appelant** hors module ; seul `pledge_promises_to_restrictions` → `restrict_process` (ZT path) est câblé. (e) `secure_boot::disable_enforcement()` est `pub` **sans capability check** — n'importe quel code kernel (y compris serveur Ring 1 compromis via confused deputy) peut appeler cette fonction pour désactiver Secure Boot au runtime (`SECBOOT_ENFORCE.store(false, SeqCst)`).

### Score maturité TCB : **4 / 10**

Le socle bas-niveau (capability `verify()` constant-time, MLS labels, code signing compile-time guards, exo-verity, ExoLedger P0 chaîné) est correct (~7/10), mais **l'intégration réelle au runtime est défaillante** : Secure Boot inerte, CFG/SafeStack/canary-per-thread/SandboxPolicy théoriques, PKS race + non-broadcast SMP, ExoLedger chain race, capability revocation bypassée sur le path FS, `disable_enforcement()` non gated. Correctifs P0 (~15 j-h) élèveraient à 6.5/10 ; P1+P2 (~40 j-h) à 8.5/10.

---

## 1. Module `security/mod.rs` (497 lignes)

### 1.1 Architecture

`security_init()` orchestre 13 étapes : ExoSeal phase0 → integrity_check → capability → crypto → mitigations → audit → access_control → exoledger → exokairos → exoargos → exonmi → exocage per-thread → exoseal complete. Le flag `SECURITY_READY` (AtomicBool) est positionné à `true` dans `exoseal_boot_complete()` (exoseal.rs:195) avec `Ordering::Release`. Les APs spin-wait dessus dans `smp/init.rs:170` (CVE-EXO-001 corrigé, vérifié).

### 1.2 Findings

| # | Sévérité | Catégorie | Sujet | Ligne |
|---|----------|-----------|-------|-------|
| KTCB-MOD-01 | MEDIUM | LOGIC | `production_security_status().is_hardened()` exige 3 conditions mais aucune n'est assertée au boot — `warn_if_not_production_hardened()` ne fait qu'un `debug_write`, ne panic pas | mod.rs:159-178 |
| KTCB-MOD-02 | LOW | LEAK | `probe(byte)` écrit sur port 0xE9 (QEMU debug) à chaque étape — fuite l'état d'avancement du boot sécurité (info mineure) | mod.rs:323-330 |
| KTCB-MOD-03 | MEDIUM | CRYPTO | `exokairos::init_kernel_secret()` fallback si `rng_fill` échoue : `secret = blake3_hash([kaslr_entropy, phys_base, tsc, mix])` — entropie faible (3 valeurs publiques/calculables) | mod.rs:382-396 |

### 1.3 Points forts

- `SECURITY_READY` Acquire/Release correct.
- `production_security_status()` expose l'état réel (testable).
- 13 étapes ordonnées avec comments de dépendance.

---

## 2. Module `capability/` (8 fichiers, 2 398 lignes)

### 2.1 `token.rs` (378 lignes)

- CapToken 24 bytes (u64 OID + u32 rights + u32 gen + u16 type + u16 pad). `repr(C)`, `_SIZE_CHECK` statique.
- `from_bytes()` reconstruit depuis wire — `Rights::from_bits_truncate` (silently truncates bits > 15). Un token forgé avec `rights = 0xFFFFFFFF` devient `Rights(0xFFFF)` (bits 16+ tronqués).
- **Pas de MAC/authenticity sur le wire** : un attaquant qui capture le wire format peut modifier `rights` (downgrade) ou `generation` (replay après revoke) — la vérification `verify()` détecte la génération incorrecte, mais le rights downgrade passe si la table contient les droits.
- Statistiques atomiques (Relaxed) — acceptable pour monitoring.

### 2.2 `rights.rs` (341 lignes)

- **Inconsistance** : `Rights::ALL = Self(u32::MAX)` (32 bits) mais `from_bits()` rejette `bits & !0xFFFF != 0` (16 bits). Donc `Rights::from_bits(Rights::ALL.bits())` retourne `None`. Le path `from_bits_truncate` est utilisé par les paths critiques (e.g., `check_object_cap`) — il accepte silencieusement les bits hauts.
- `contains_ct` et `is_subset_of` sont constant-time — OK.
- Bits 16-31 "réservés extensions futures" mais `ALL = u32::MAX` les inclut — collision future.

### 2.3 `table.rs` (536 lignes) — ⚠️ plusieurs CRITICAL

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-TABLE-01** | **CRITICAL** | `check_object()` ne vérifie pas la génération | `table.rs:425-430`. Utilisé par ExoFS `check_object_cap` (22 syscalls). `revoke()` (O(1) gen++) **n'invalide pas** l'accès ExoFS. Seul `remove()` (slot-free) marche. **KTCB-02 du top-5.** |
| **KTCB-TABLE-02** | HIGH | `grant()` re-grant path ne bump pas la génération | `table.rs:336-342`. Si `grant(oid, R2)` est appelé alors que le slot existe déjà avec R1 et gen G, les droits deviennent R2 **sans bumper gen**. Tout token capturé avec gen G (droits R1) passe toujours `verify()` (gen match) ET désormais `table.rights.contains(R2)` — un token R1 peut exercer R2. Scénario : un process re-grante un objet existant avec droits étendus → tous les tokens déjà émis héritent des droits étendus. Privilège escalation latent. |
| KTCB-TABLE-03 | MEDIUM | `get()` lit rights/generation/type_tag en 3 loads atomiques séparés | `table.rs:400-402`. Pas de snapshot atomique cohérent. Un `grant()` concurrent peut intercaler ses stores entre les loads — view incohérent (e.g., rights ancien + type_tag nouveau). Benign dans la plupart des cas (verify vérifie tout) mais peut tromper `check_object` sur le type_tag. |
| KTCB-TABLE-04 | MEDIUM | `find_slot` arrêt au premier `SLOT_FREE` | `table.rs:282-285`. Si le slot a été libéré puis ré-occupé par un autre OID (collision de hash), `find_slot` peut retourner None pour un OID présent plus loin. Bénign sauf si la table est presque pleine. |
| KTCB-TABLE-05 | LOW | `init_cap_entries!` macro utilise `MaybeUninit::uninit().assume_init()` | `table.rs:160-162`. Pattern accepté en Rust mais `unsafe` méritait justification plus claire. |

### 2.4 `verify.rs` (206 lignes) — ✅ correct

- `verify()` utilise `subtle::ConstantTimeEq` pour `gen_ok` et `Rights::contains_ct` pour `rights_ok`. `entry_found & gen_ok & rights_ok` combiné sans early-return. RÈGLE CAP-05 respectée.
- Retour unifié `Err(CapError::Denied)` pour tous les échecs — empêche timing-based ObjectId enumeration.
- **Cependant** : `verify_and_get_rights()` appelle `verify()` puis **re-call** `table.get()` — TOCTOU. Entre les deux, l'entrée peut être `remove()` ou re-grant avec droits différents. Le caller obtient des droits qui ne correspondent pas au token vérifié. Bénign si le caller ne fait que loguer, dangereux si le caller délègue ensuite.

### 2.5 `revocation.rs` (49 lignes)

- `revoke()` = `table.increment_generation(object_id, Release)`. O(1). Correct en soi.
- **Le problème est dans les consumers** : `check_object()` ignore la génération (KTCB-TABLE-01). Donc `revoke()` est efficace pour `verify()` (IPC) mais **pas pour** `check_object()` (ExoFS).

### 2.6 `delegation.rs` (178 lignes)

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| KTCB-DELEG-01 | HIGH | `delegate()` vérifie `delegated_rights.is_subset_of(source_token.rights())` sur le **token capturé**, pas sur la table courante | `delegation.rs:57`. Si `source_token` a été capturé quand la table avait R_FULL puis la table a été réduite (re-grant sans bump, voir KTCB-TABLE-02) à R_REDUCED, `delegate(source_token, R_FULL)` réussit car R_FULL ⊆ source_token.rights() (= R_FULL capturé). Le target reçoit un token avec R_FULL sur un objet où la source n'a plus que R_REDUCED. **Violation de l'invariant CAP-03** dans le sens "source peut déléguer plus que ce qu'elle exerce réellement". |
| KTCB-DELEG-02 | MEDIUM | `delegate()` ne décrémente pas le budget ExoKairos du parent | `delegation.rs:403-450` (ExoKairos) — voir KTCB-KAIROS-03. Le `delegate()` capability standard n'a pas ce problème (pas de budget), mais l'ExoKairos `delegate()` oui. |

### 2.7 `namespace.rs` (194 lignes)

- `ObjectId` encode `NamespaceId` dans les 16 bits hauts. `owns()` vérifie l'appartenance. `cross_namespace_verify()` retourne toujours `Err(ObjectNotFound)` si NS diffèrent — isolation effective.
- **KTCB-NS-01 [MEDIUM, RACE]** : `release()` fait `fetch_sub(Release) == 1` puis retourne `true` pour destruction. Mais un `acquire()` concurrent peut `fetch_add` entre le `fetch_sub` et la destruction effective. Use-after-free ou référence pendante. Pas de CAS loop.
- `alloc_object_id` local au namespace — mais `OBJ_ID_COUNTER` global dans `mod.rs:108` ne encode pas le namespace. Inconsistance : deux systèmes d'ObjectId coexistent (mod.rs global counter vs namespace.alloc_object_id).

---

## 3. Module `zero_trust/` (5 fichiers, 1 478 lignes)

### 3.1 `labels.rs` (211 lignes) — ✅ correct

- Bell-LaPadula (no-read-up, no-write-down) et Biba (no-read-down, no-write-up) correctement implémentés.
- `from_u8` fail-closed pour valeurs invalides (→ Public/Untrusted, le moins privilégié).
- `encode/decode` u16 non authentifié — OK car usage interne.

### 3.2 `context.rs` (276 lignes)

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-CTX-01** | HIGH | `downgrade()` racy (check-then-store non atomique) | `context.rs:208-213`. `let current = self.trust_level.load(Acquire); if (new_level as u32) < current { self.trust_level.store(new_level as u32, Release); }`. Deux threads peuvent tous deux loader `current=5 (System)`, l'un veut stocker 3 (Trusted), l'autre 2 (Normal). Le second store (3) gagne après le premier (2) → trust remonte de 2 à 3. **Monotonicité violée**. Devrait être CAS loop `compare_exchange_weak`. |
| KTCB-CTX-02 | MEDIUM | `derive_child` charge `restrictions` avec `Relaxed` | `context.rs:256`. Peut manquer une restriction récemment ajoutée par un autre thread. L'enfant hérite de moins de restrictions que le parent n'a réellement. Devrait être `Acquire`. |
| KTCB-CTX-03 | LOW | `record_deny/record_allow` en `Relaxed` | `context.rs:240-247`. Acceptable pour stats monitoring. |

### 3.3 `policy.rs` (290 lignes)

- `ZeroTrustPolicy::evaluate()` : TrustLevel insuffisant → DenyAndAudit. Puis restrictions. Puis MLS. Puis règles par ressource.
- **KTCB-POL-01 [MEDIUM, LOGIC]** : `check_resource_rules()` pour `ResourceKind::Device` retourne `DenyAndAudit` si `trust < Trusted`, MAIS `check_restrictions()` pour `Device` retourne toujours `Allow` (commentaire "Devices : restreint aux threads Trusted+"). Inconsistance : un thread `Normal` qui tente d'accéder à un device passe `check_restrictions` (Allow) puis échoue à `check_resource_rules` (DenyAndAudit). Le commentaire est trompeur.
- **KTCB-POL-02 [INFO]** : `Deny` et `DenyAndAudit` retournent tous deux `AccessError::Denied` au caller — impossible à distinguer. Seul `DenyAndAlert` est différenciable. Audit logging identique pour `Deny` et `DenyAndAudit`.

### 3.4 `verify.rs` (389 lignes)

- `verify_access()` log via `audit::log_security_violation` + `shield_feed::push_event` à chaque refus.
- `verify_syscall()` : le label `kernel()` est TopSecret/Critical. Untrusted → DenyAndAudit. LaMLS ne s'applique pas à `ResourceKind::Syscall` (ligne 164 du policy) — sinon tous les syscalls user seraient refusés (Internal ne domine pas TopSecret). Correct par design mais dépend de ce `match`.
- `register_ring1_pid(pid)` : `pid < 64` uniquement. Un service Ring 1 avec PID ≥ 64 (e.g., crypto_server avec PID 1101 dans les tests) n'est pas trustable via ce path. `ring1_pair_trusted` retourne false → fast-path bypass désactivé → ZT policy évaluée normalement. OK par défaut (fail-closed).

### 3.5 `process_state.rs` (285 lignes)

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-PS-01** | **HIGH** | `context_for_caller()` hardcoded `uid: 0, gid: 0` pour tous les process | `process_state.rs:110-116`. Combiné avec `owner_matches` (AUDIT-8 : "retourne true si caller==0 \|\| entry.owner==0"), **tous les process apparaissent comme root** pour les checks d'ownership. Un process Ring 3 compromis peut déclarer n'importe quel `owner_uid=0` et hériter des accès root. |
| KTCB-PS-02 | MEDIUM | `MAX_TRACKED_PIDS = 1024` ; PID ≥ 1024 non traçable | `process_state.rs:38,56-58`. `restrict_process` retourne false → échec silencieux. Un process haut PID ne peut pas être restreint (pledge ignoré). Fail-open au site d'opt-in. |
| KTCB-PS-03 | MEDIUM | `clear_process_restrictions` appelé au release PID, mais TOCTOU avec spawn | Si un nouveau process reprend le même PID avant le `clear`, il hérite des restrictions du précédent (information leak) ; si le `clear` arrive après le spawn du nouveau, il efface les restrictions du nouveau (escalation). |
| KTCB-PS-04 | LOW | `syscall_restriction_mask` ne couvre que fork/clone/vfork/execve/socket/... | Pas de filtrage sur `mprotect`, `mmap`, `ptrace`, `keyctl`, `bpf`, `perf_event_open` — syscalls dangereux non restreints par pledge. |

---

## 4. Module `audit/` (3 fichiers, 681 lignes)

### 4.1 `logger.rs` (318 lignes) — ⚠️ plusieurs issues

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-AUD-01** | **HIGH** | Ring buffer overflow = overwrite → DoS forensique | `logger.rs:137-148`. Un attaquant peut flood 65 536+ événements (denied syscalls en boucle) pour écraser son propre audit trail. RÈGLE AUDIT-02 "SecurityViolation ne peut pas être filtrée" est respectée pour le filtre, **mais pas pour l'overwrite** — les secviolations sont écrasées comme les autres. |
| **KTCB-AUD-02** | **HIGH** | `push()` overflow detection racy et cassé après wrap | `logger.rs:138-148`. `let head = idx;` (local, modulo RING_SIZE) puis `let used = head.wrapping_sub(tail) % RING_SIZE`. Quand `head` (raw counter) et `tail` (raw counter) ont tous deux wrapped plusieurs fois, le modulo produit une valeur incohérente. La détection `used >= RING_SIZE - 1` rate ou fausse-positive. |
| KTCB-AUD-03 | MEDIUM | `AUDIT_RING: spin::Mutex` → deadlock potentiel en contexte IRQ | `logger.rs:181`. Si une IRQ fire pendant qu'un thread sur le même CPU tient le lock, le handler IRQ qui logue spin forever. Pas de `irq_save`/`cli` avant lock. |
| KTCB-AUD-04 | MEDIUM | `FILTER_MASK` shift par `category as u8` (jusqu'à 0xFF) | `logger.rs:236`. `1u64 << 0xFF` = panic en debug, `1u64 << (0xFF % 64) = 1u64 << 63` en release. La catégorie `Other = 0xFF` est mappée sur bit 63 — collide avec des futures catégories. |
| KTCB-AUD-05 | LOW | `AuditRecord` 32 bytes (24 data + 8 pad implicite), pas 16 comme commenté | Commentaire ligne 9 "16 bytes minimum" incorrect. |
| KTCB-AUD-06 | LOW | `rdtsc` non sérialisé | Acceptable pour timestamp de log. |

### 4.2 `rules.rs` (328 lignes)

- `RuleSet::evaluate()` parcourt toutes les règles, retient la meilleure priorité. `AuditRule::matches()` correct.
- `add_global_rule`/`remove_global_rule` sont `pub` **sans capability check** — n'importe quel code kernel peut ajouter une règle `RuleAction::Skip` pour `AuditCategory::Syscall` (mais pas pour `SecurityViolation`, RÈGLE ARULE-02). Peut désactiver l'audit syscall.

### 4.3 `syscall_audit.rs` (342 lignes)

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| KTCB-SCAUD-01 | MEDIUM | `MAX_CONCURRENT_SYSCALLS = 1024`, slot = `tid % 1024` | `syscall_audit.rs:76,89-91`. Avec >1024 threads, deux TIDs collisionnent. `set()` écrase le contexte du premier. À l'exit du premier, `get()` retourne None → `ORPHAN_EXITS++` (info leak). À l'exit du second, `get()` retourne le contexte du premier → audit incorrect. |
| KTCB-SCAUD-02 | MEDIUM | `MAX_USER_SYSCALL = 511` | Syscalls kernel-internal (nr > 511) ne sont pas audités (RÈGLE SAU-03). OK par design mais potentiellement contournable si un attacker peut invoquer un nr > 511 via un path ABI non filtré. |
| KTCB-SCAUD-03 | LOW | `audit_syscall_exit` ne log pas les exits où `result < 0` | `syscall_audit.rs:267-271` → outcome `Error`. Le log est fait mais avec outcome Error — OK. |

---

## 5. Module `access_control/` (3 fichiers, 258 lignes)

### 5.1 `checker.rs` (154 lignes)

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-AC-01** | **HIGH** | `check_access()` logue avec `pid=0, tid=0, uid=0` systématiquement | `checker.rs:104-118`. La signature ne prend pas pid/tid/uid en paramètres. Tous les events d'audit capability deny ont un acteur nul — **forensics inutilisable**. |
| KTCB-AC-02 | MEDIUM | `cap_verify` ne retourne jamais `InsufficientRights` ou `ObjectNotFound` | `verify.rs:137-140` retourne toujours `Denied`. Les branches match `ObjectNotFound` (ligne 116) et `InsufficientRights` (ligne 121) dans `check_access` sont **dead code**. L'audit différencié est inopérant. |

### 5.2 `object_types.rs` (70 lignes) — ✅ correct

- 7 ObjectKinds, `typical_rights()` indicatif (pas whitelist).

---

## 6. Module `isolation/` (5 fichiers, 1 219 lignes)

### 6.1 `domains.rs` (276 lignes)

- Transitions strictement unidirectionnelles. `is_transition_allowed` correct.
- `transition_to()` prend `&mut self` — pas de synchronisation. Si le DomainContext est dans le TCB, c'est OK (un seul thread à la fois). Si partagé, race.
- `return_to_previous()` ne vérifie pas la légalité de la transition (assume syscall return). OK.

### 6.2 `namespaces.rs` (324 lignes)

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-NS-02** | MEDIUM | `release()` refcount race | `namespaces.rs:124-131`. `fetch_sub(Release) == 1` puis `flags.fetch_or(DYING)`. Un `acquire()` concurrent entre les deux incrémente le refcount, mais le namespace est marqué DYING et retiré du registre. Référence pendante. |
| KTCB-NS-03 | MEDIUM | `can_see` trop permissif | `namespaces.rs:157-173`. "Le namespace init est visible par tous" — un namespace enfant peut voir tous les PIDs du namespace init. Un namespace enfant ne peut voir QUE son parent direct, pas les grands-parents. Incohérent (init visible, grand-parent non). |
| KTCB-NS-04 | LOW | `process_count.fetch_sub` sans bound check | `namespaces.rs:140`. Peut underflow à u32::MAX si `leave()` appelé plus que `enter()`. |
| KTCB-NS-05 | LOW | `MAX_NAMESPACES = 256` statique | Tableau fixe, pas d'allocation. OK pour un OS embarqué. |

### 6.3 `pledge.rs` (283 lignes)

- `PledgeSet` et `to_sandbox_policy()` — **dead code** (grep : 0 appelant hors module). Seul `pledge_promises_to_restrictions` (dans `process_state.rs`) est câblé.
- `pledge()` method sur `PledgeSet` n'est jamais appelée par un syscall. L'API pledge userspace n'est pas exposée.
- `to_sandbox_policy()` génère une `SandboxPolicy` qui n'est jamais enforced (voir 6.4).

### 6.4 `sandbox.rs` (315 lignes) — ⚠️ dead code

- `SandboxPolicy::evaluate()` et `check()` — **0 appelant** hors module. Le path réel est `process_state::syscall_restriction_mask` → `policy::check_restrictions` (qui ne match que fork/exec/network).
- `derive_child` commenté "AND des bitmaps" mais en réalité copie identique du parent (`allowed_bitmap: self.allowed_bitmap`).
- `MAX_SYSCALL = 256` mais Linux x86_64 a >400 syscalls. Syscalls au-delà de 256 → `DenyEnosys` — casse la compat apps modernes.

---

## 7. Module `integrity_check/` (4 fichiers, 925 lignes)

### 7.1 `code_signing.rs` (340 lignes) — ✅ solide

- `MASTER_PUBLIC_KEY` et `UPDATE_PUBLIC_KEY` sont des paires dev réelles (FIX-F5 appliqué).
- `key_is_forbidden` compile-time check rejette `[0;32]`, RFC 8032 TV1, RFC 8032 TV2. Anti-régression.
- `verify_module_signature()` : magic + size + key_index + BLAKE3 hash + Ed25519 verify. Hash comparé XOR-accumulate (constant-time au niveau byte, acceptable).
- **KTCB-CS-01 [MEDIUM]** : `register_loaded_module` store `name_hash` et `code_hash` mais pas `key_index`. Un module signé par `UPDATE_PUBLIC_KEY` (key_index=1) puis re-signé par `MASTER_PUBLIC_KEY` (key_index=0) avec le même `code_hash` n'est pas détecté comme AlreadyLoaded — la rotation de clé est invisible.
- **KTCB-CS-02 [LOW]** : `ModuleRegistry` statique `spin::Mutex` — pas d'IPI notify sur modification.

### 7.2 `runtime_check.rs` (251 lignes)

- Hash BLAKE3 de `.text` et `.rodata` au boot, vérification périodique (15s) en mode observe (TIER 2.1-a) — log dans ExoLedger P0, pas de panic.
- `assert_kernel_integrity()` panic en mode strict (production).
- **KTCB-RC-01 [HIGH]** : Le mode observe **ne panic pas** en cas de corruption `.text`. Un attaquant qui patche le kernel en runtime (via exploit DMA, JOP, etc.) n'est détecté que comme entrée d'audit — le kernel continue de tourner avec du code corrompu. La décision de handoff ExoPhoenix n'est pas automatisée. RÈGLE RUNTIME-02 "altération → panic immédiat" est désactivée par défaut.
- **KTCB-RC-02 [MEDIUM]** : `check_kernel_integrity()` prend `INTEGRITY_STATE.lock()` deux fois (une fois pour read, une fois pour update `last_ok_tsc`). Entre les deux, un autre check peut s'intercaler. Bénign mais laisse une fenêtre pour une modification de `text_hash`/`rodata_hash` par un attaquant qui aurait compromis le lock.
- **KTCB-RC-03 [MEDIUM]** : `clear_ledger_storage()` est appelé depuis `exo_ledger_init()` qui peut être appelé plusieurs fois — mais la ré-init préserve les entrées P0 (test le confirme). OK.

### 7.3 `secure_boot.rs` (261 lignes) — ⚠️ KTCB-01 du top-5

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-SB-01** | **CRITICAL** | `verify_boot_attestation()` jamais appelé au boot | `secure_boot.rs:174`. Grep : 0 caller runtime. `CHAIN_VERIFIED` reste false. `exec.rs:275` court-circuite `check_chain_of_trust()` quand `is_chain_verified()` est false → aucun binaire vérifié. **Secure Boot inerte.** |
| **KTCB-SB-02** | **CRITICAL** | `disable_enforcement()` `pub` sans capability check | `secure_boot.rs:214-216`. N'importe quel code kernel peut `SECBOOT_ENFORCE.store(false, SeqCst)`. Même si Ring 1 n'a pas accès direct, un kernel exploit ou confused deputy peut désactiver Secure Boot au runtime. |
| KTCB-SB-03 | MEDIUM | PCR bank simulée en software | `secure_boot.rs:133-163`. `extend_pcr()` est `pub` — n'importe quel code kernel peut étendre des PCRs arbitraires, corrompant l'attestation. Pas de hardware TPM binding. |
| KTCB-SB-04 | MEDIUM | `PcrBank::extend` tronque measurement à 64 bytes | `secure_boot.rs:151`. Measurement >64 bytes perd des données sans hash. |
| KTCB-SB-05 | LOW | `BOOTLOADER_PUBLIC_KEY` n'est pas vérifiée par `key_is_forbidden` | Contrairement à `MASTER_PUBLIC_KEY` dans code_signing.rs. Inconsistance. |

---

## 8. Module `exploit_mitigations/` (6 fichiers, 1 271 lignes)

### 8.1 `kaslr.rs` (182 lignes)

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-KASLR-01** | HIGH | `kaslr_offset()` est `pub` — violation RÈGLE KASLR-03 | `kaslr.rs:114-116`. La fonction est exposée publiquement ; n'importe quel syscall handler peut la wrapper et exposer l'offset à userspace. RÈGLE KASLR-03 "L'offset ne doit jamais être exposé à userspace" n'est pas enforceée par visibility. |
| KTCL-KASLR-02 | MEDIUM | `KASLR_SLOTS = 262 144` (~18 bits d'entropie) | Faible. Combiné avec AUDIT-1 BOOT-CRIT-01 (KASLR ignoré en UEFI), l'entropie réelle est souvent 0. |
| KTCB-KASLR-03 | MEDIUM | `kaslr_init` TOCTOU entre `load(Acquire)` et `store(true, Release)` | `kaslr.rs:73-83`. Deux appels concurrents peuvent tous deux passer le check. Le second store écrase le premier. Bénign (l'offset est juste différent). |
| KTCB-KASLR-04 | LOW | `is_safe_kernel_ptr` ne vérifie pas la borne haute kernel | `kaslr.rs:140-148`. `start >= KERNEL_VIRT_BASE && end >= KERNEL_VIRT_BASE` — un pointeur à `0xFFFF_FFFF_FFFF_FFFF` est accepté. OK car dans la plage canonical kernel. |

### 8.2 `stack_protector.rs` (248 lignes) — ⚠️ dead code

- `__stack_chk_guard` global AtomicU64 — utilisé par le compilo (`-fstack-protector`).
- `StackGuard` table per-thread — **0 appelant** hors module (grep). Le TCB (`process/core/tcb.rs`) utilise sa propre constante `STACK_CANARY` et la table `alloc_guarded`/`alloc_heap_canary`. La table `CANARY_TABLE` est **morte**.
- `check_canary()` n'est pas constant-time (branches sur `self_integrity_ok()` et `ok`). RÈGLE STACK-03 violée.
- `StackGuard::new` loop `rng_u64().unwrap_or(0)` — si RNG défaillant, boucle infinie.

### 8.3 `cfg.rs` (209 lignes) — ⚠️ dead code

- `cfg_validate_indirect_call` / `cfg_assert_indirect_call` — **0 appelant** hors module. RÈGLE CFG-01 "Tout appel indirect doit passer par cfg_validate_indirect_call()" est du **théâtre**.
- `cfg_register_range` censé être appelé par `arch_init()` (commentaire mod.rs:60) — mais le code ne l'appelle pas (grep : 0 appelant).
- `is_valid` a branches sur `addr < CFG_BASE_ADDR` — RÈGLE CFG-01 "constant-time (pas de branch sur adresse)" violée.
- `CFG_RANGE = 16 MiB` — kernel > 16 MiB → codes au-delà non enregistrés, marqués invalides.
- `cfg_validate_indirect_call` prend `Mutex` lock sur le hot path indirect call — perf catastrophique si jamais câblé.

### 8.4 `cet.rs` (247 lignes)

- `enable_shadow_stack` active CR4.CET, MSR_IA32_S_CET, MSR_IA32_PL0_SSP. Utilise `RSTORSSP` via bytes encoding (LLVM < 18).
- `wrss_u64`, `savessp` exposés mais non utilisés (helpers pour future intégration).
- `cp_handler` (dans exocage.rs) déclenche handoff ExoPhoenix sur #CP.

### 8.5 `safe_stack.rs` (304 lignes) — ⚠️ dead code

- `safe_stack_check`, `safe_stack_assert`, `safe_stack_new_thread`, `safe_stack_update_ssp/usp` — **0 appelant** hors module.
- Nécessite `-fsanitize=safe-stack` (commentaire ligne 18) — non activé dans le build.
- `MAX_SS_THREADS = 256` — limit très bas.

### 8.6 `mod.rs` mitigations_init

- `cet_is_supported()` appelé, `enable_ibt()` si supporté. `safe_stack_init(cet_active)` désactive SafeStack si CET actif — OK.
- CFG registration **commentée** ("appelé par arch_init()") — mais arch_init ne l'appelle pas. **CFG jamais peuplé**.

---

## 9. Module `exoseal.rs` (252 lignes)

- `exoseal_boot_phase0()` : configure NIC IOMMU, exoveil_init, exocage_global_enable, arm watchdog 500ms, verify_p0_fixes.
- `exoseal_boot_complete()` : verify_p0_fixes, pks_restore_for_normal_ops, SSR handoff flag=0, SECURITY_READY=true, arm watchdog 50ms.
- `verify_p0_fixes()` : check NIC IOMMU locked, CET global enabled, PKS domaines revoked (Credentials) / accessible (Caps, TcbHot). Log P0 violation + handoff si échec.
- **KTCB-SEAL-01 [MEDIUM]** : `exoseal_boot_phase0` et `exoseal_boot_complete` sont `unsafe` mais n'ont pas de garde contre la ré-entrance cross-CPU. Le `swap(true, AcqRel)` protège in-process mais pas si un AP appelle aussi (les APs spin-wait sur SECURITY_READY avant tout, donc OK en pratique).
- **KTCB-SEAL-02 [LOW]** : `NIC_DMA_WHITELIST_BASE = 0x0A00_0000` hardcoded — adresse physique arbitraire. Si la carte NIC utilise une plage DMA différente, la policy est inopérante.

---

## 10. Module `exocage.rs` (636 lignes)

- `enable_cet_for_thread()` : CPUID check, alloc 4 pages shadow stack, token au sommet (busy bit), WRSSQ, configure MSR PL0_SSP/PL1_SSP, save in TCB `_cold_reserve`.
- `disable_cet_for_thread()` : free shadow stack pages, clear TCB fields.
- `cp_handler` : incrément compteur, ExoLedger P0, handoff ExoPhoenix, spin loop.

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-CAGE-01** | HIGH | Même `token_addr` écrit dans `PL0_SSP` et `PL1_SSP` | `exocage.rs:354-355`. Ring 0 (kernel) et Ring 1 (servers) partagent la **même shadow stack**. Un serveur Ring 1 compromis peut corrompre la shadow stack kernel via WRSS (si WR_SHSTK_EN est actif pour Ring 1 — ce qui est le cas car `MSR_IA32_S_CET = CET_SHSTK_EN \| CET_WR_SHSTK_EN`). Séparation Ring0/Ring1 ineffective. |
| KTCB-CAGE-02 | MEDIUM | `enable_cet_for_thread` n'est pas appelé pour les APs au boot | `security_init()` ne l'appelle que pour le BSP (mod.rs:416-421). Les APs doivent l'appeler individuellement. Si un AP ne le fait pas, ses threads n'ont pas CET. |
| KTCB-CAGE-03 | MEDIUM | `cp_handler` ne restore pas les MSRs CET avant handoff | Si ExoPhoenix redémarre le kernel avec CET toujours actif mais shadow stack invalide, #CP en boucle. |
| KTCB-CAGE-04 | LOW | `validate_thread_cet` retourne `true` si CET pas activé pour ce thread | `exocage.rs:626-636`. Acceptable (kthreads sans CET) mais information sur l'activation exposée. |

---

## 11. Module `exoveil.rs` (603 lignes) — ⚠️ KTCB-03 du top-5

Déjà couvert en §Top-5 KTCB-03. Points supplémentaires :

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| KTCB-VEIL-01 | HIGH | `pks_restore_for_normal_ops()` restaure Caps + TcbHot en ReadWrite | `exoveil.rs:430-431`. Après `security_init()`, ces domaines ne sont plus isolés. La "protection PKS" des Caps/TcbHot n'est active que pendant la fenêtre boot. |
| KTCB-VEIL-02 | MEDIUM | `CURRENT_PKRS` shadow peut diverger du MSR matériel | Si un code écrit `wrpkrs()` sans updater le shadow (aucun dans le code actuel, mais pattern fragile), `save_pkrs_to_tcb` persiste une valeur stale. |
| KTCB-VEIL-03 | MEDIUM | `exoveil_revoke_all_on_handoff` ne broadcast pas aux autres CPUs | `exoveil.rs:448-464`. Révoque sur le CPU courant uniquement. Les autres CPUs conservent l'ancien PKRS. |
| KTCB-VEIL-04 | LOW | `PksDomain::TcbHot = 4` mais le commentaire dit "pkey=4" | OK mais Domain 3 est skipped — potentiellement future confusion. |

---

## 12. Module `exoledger.rs` (776 lignes) — ⚠️ KTCB-04 du top-5

Déjà couvert en §Top-5 KTCB-04. Points supplémentaires :

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| KTCB-LEDGER-01 | HIGH | Ring buffer overflow casse la chaîne | `exoledger.rs:624-628` (`verify_ring_integrity`). "La chaîne peut être rompue par l'overflow circulaire — ce n'est pas une erreur — c'est attendu". Un attaquant qui flood 96 événements casse la vérification. |
| KTCB-LEDGER-02 | HIGH | P0 zone limitée à 16 entrées | `exoledger.rs:46`. Au-delà, events drop (un seul "P0_OVERFLOW" logged). Attaquant qui trigger 16 #CP/IOMMU faults/BootSealViolations → P0 saturated, plus aucun event critique enregistré. DoS audit. |
| KTCB-LEDGER-03 | MEDIUM | `current_actor_oid()` fallback early-boot : `oid[0..8] = tsc, oid[8..12] = cpu=0` | `exoledger.rs:401-407`. Si `tcb_ptr` est null/non publié, l'acteur est `(tsc, 0)` — pseudo-anonyme. Forensics faible. |
| KTCB-LEDGER-04 | MEDIUM | `is_published_tcb` itère `CURRENT_THREAD_PER_CPU` (O(N_CPUS)) par event | `exoledger.rs:418-426`. Performance issue sur hot path audit. |
| KTCB-LEDGER-05 | LOW | `exo_ledger_append` fait `RING_HEAD.fetch_add(1) % RING_BUFFER_ENTRIES` | Si RING_HEAD wrap à usize::MAX, le modulo continue de fonctionner mais le chaînage peut casser (next entry's `prev_hash` référence une entrée écrasée). |

---

## 13. Module `exokairos.rs` (920 lignes)

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| **KTCB-KAIROS-01** | HIGH | `get_kernel_secret()` fail-open à `[0u8; 32]` si uninitialized | `exokairos.rs:714-718`. `KERNEL_SECRET.get().copied().unwrap_or([0u8; 32])`. Si `init_kernel_secret` n'est pas appelé (ou race Once), le MAC est calculé avec une clé nulle connue de l'attaquant → forge trivial de `deadline_mac`. |
| **KTCB-KAIROS-02** | HIGH | `KERNEL_SECRET` en `static Once<[u8; 32]>` regular, pas en PKS Credentials | `exokairos.rs:695`. Commentaire "sera en PKS Credentials en Phase 3.2". Tout code kernel peut `get_kernel_secret()` directement (fonction privée mais le `Once` est dans le module). |
| **KTCB-KAIROS-03** | HIGH | `delegate()` ne décrémente pas le budget parent | `exokairos.rs:403-450`. Vérifie `new_calls <= parent_calls` mais n'appelle pas `parent.calls_left.fetch_sub(new_calls)`. Le parent et l'enfant ont chacun le budget → budget total dupliqué. Inflation monétaire du budget capability. |
| KTCB-KAIROS-04 | MEDIUM | `get_const_time` n'est pas réellement constant-time | `exokairos.rs:562-590`. `(occupied == 1) as u64` est un branch (compilo peut optimize en cmov, non garanti). `(*entry).occupied.load(Acquire)` n'est pas constant-time (cache behavior). |
| KTCB-KAIROS-05 | MEDIUM | `compute_deadline_mac` truncate à 16 bytes | `exokairos.rs:687-690`. 128-bit security — acceptable. Mais BLAKE3 keyed mode n'est pas un MAC standard (pas de MAC-then-verify). |
| KTCB-KAIROS-06 | LOW | `ttl_for_right` mapping ad-hoc | `exokairos.rs:763-778`. `IPC_SEND` mappé à `NETWORK_SEND_S` (5s) — commenté "≈". `IPC_CONNECT`/`IPC_RECV` mappés à `IPC_CALL_S` (60s). Le TTL réellement appliqué dépend du premier bit matché dans l'ordre EXEC > IPC_SEND > WRITE > IPC_CONNECT|IPC_RECV > DEFAULT. |

---

## 14. Module `exonmi.rs` (552 lignes)

- Watchdog 3-strike : `STRIKE_THRESHOLD = 3`. `ping()` reset, `tick()` incrémente. À 3 strikes → ExoLedger P0 + handoff.
- `arm_watchdog` configure APIC timer one-shot. `compute_initial_count` utilise CPUID 0x15 ou mesure empirique TSC.
- **KTCB-NMI-01 [MEDIUM]** : `arm_watchdog(timeout_ms)` clamp à `[WATCHDOG_TIMEOUT_MIN_MS=200, MAX=30 000]`. Mais `exoseal_boot_phase0` appelle `arm_apic_watchdog(500)` (différente fonction dans stage0). Pas de garde sur la valeur réellement appliquée par ExoNmi.
- **KTCB-NMI-02 [MEDIUM]** : `reload_timer` silently skip si `CACHED_INITIAL_COUNT == 0`. Si l'arm initial a échoué (fréquence indéterminée), le watchdog ne tick jamais — silent fail-open.
- **KTCB-NMI-03 [LOW]** : `tick()` est appelé par l'ISR APIC timer. Si l'ISR est masquée par `cli` long-uptime, le watchdog ne se déclenche pas. Acceptable (CLI devrait être court).

---

## 15. Module `exoargos.rs` (595 lignes)

- PMC monitoring : 5 MSRs (FIXED_CTR0/1, PMC0/1, TSC). `pmc_snapshot(tcb)` lit les MSRs, valide que `tcb` est bien le current thread.
- `check_anomaly()` compare snapshot à baseline. Discordance fixed-point > 3500 → anomaly.
- `write_snapshot_to_ssr` copie 64 bytes vers SSR per-CPU area.

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| KTCB-ARGOS-01 | MEDIUM | `pmc_snapshot` valide le TCB mais pas le CPU | `exoargos.rs:336-347`. Si le thread est migré entre le `current_thread_raw()` et la lecture MSR, les compteurs sont d'un autre CPU. |
| KTCB-ARGOS-02 | MEDIUM | `BASELINE_SNAPSHOT` global, pas per-CPU | `exoargos.rs:172`. Tous les CPUs partagent la même baseline. Sur SMP hétérogène, faux positifs. |
| KTCB-ARGOS-03 | LOW | `DECEPTION_THRESHOLD = 3500` (0.35 fixed-point) hardcoded | Pas de calibration dynamique. |

---

## 16. Module `ipc_policy.rs` (395 lignes)

- 51 paires (src_class, dst_class) autorisées dans `POLICY`. `check_direct_ipc` regarde si la paire est dans la liste.
- `IpcBroker` (PID 2) a accès à tous les services registered.
- `register_service_class` refuse InitServer/IpcBroker/Unknown et les PIDs 1/2.

| # | Sévérité | Sujet | Détail |
|---|----------|-------|--------|
| KTCB-IPC-01 | MEDIUM | `MAX_REGISTERED_SERVICES = 16` statique | Tableau fixe. Au-delà, `register_service_class` retourne false. Fail-closed. |
| KTCB-IPC-02 | MEDIUM | `can_inject_src_pid` ne vérifie que la class, pas le token | `ipc_policy.rs:228-230`. Un process malveillant qui s'enregistre comme `ExoShield` (via `register_service_class`) gagne `can_inject_src_pid == true`. L'enregistrement se fait via `register_service(pid, &CapToken)` — le CapToken n'est pas vérifié contre la table kernel réelle. |
| KTCB-IPC-03 | LOW | `POLICY.len() == 51` assert statique | Bonne pratique (anti-dérive spec). |

---

## 17. Module `shield_feed.rs` (231 lignes)

- Ring buffer 256 événements, `push` non-bloquant (lock + check overflow + write).
- `drain` copie jusqu'à `out.len()` events.
- **KTCB-SHIELD-01 [MEDIUM]** : `push()` prend `Mutex` lock. Si appelé depuis IRQ context avec IRQ déjà tenant le lock, deadlock. Le commentaire dit "Sûr depuis n'importe quel contexte non-NMI" — mais IRQ non-NMI peut deadlock.
- **KTCB-SHIELD-02 [MEDIUM]** : `HEAD` et `TAIL` sont `AtomicUsize` mais le ring est protégé par `Mutex`. L'atomicité est redondante (le lock sérialise). Inconsistance.
- **KTCB-SHIELD-03 [LOW]** : `DROPPED` peut wrap à u64::MAX silencieusement. Compteur non borné.

---

## 18. Synthèse des vulnérabilités par sévérité

### CRITICAL (5)

| ID | Sujet |
|----|-------|
| KTCB-01 | Secure Boot chain-of-trust jamais vérifiée (verify_boot_attestation jamais appelé) |
| KTCB-02 | Capability revocation bypassée sur path ExoFS (check_object ne vérifie pas génération) |
| KTCB-03 | ExoVeil PKS race RMW + MSR per-CPU non broadcast (révocation silencieusement perdue) |
| KTCB-04 | ExoLedger ring buffer race sur LAST_HASH casse la chaîne cryptographique |
| KTCB-05 | CFG/SafeStack/canary-per-thread/SandboxPolicy morts + disable_enforcement() non gated |

### HIGH (12)

| ID | Sujet |
|----|-------|
| KTCB-TABLE-02 | grant() re-grant path ne bump pas génération (droits étendues silencieusement) |
| KTCB-DELEG-01 | delegate() vérifie token.rights capturé pas table.rights courant (CAP-03 violé) |
| KTCB-CTX-01 | SecurityContext::downgrade() racy (monotonicité violée) |
| KTCB-PS-01 | context_for_caller() hardcoded uid=0/gid=0 (tous root) |
| KTCB-AUD-01 | Audit ring buffer overflow=overwrite (DoS forensique) |
| KTCB-AUD-02 | push() overflow detection racy/cassé après wrap |
| KTCB-AC-01 | check_access() logue avec pid=0/tid=0/uid=0 (forensics inutile) |
| KTCB-SB-01 | (déjà KTCB-01) |
| KTCB-SB-02 | (déjà KTCB-05e) |
| KTCB-KASLR-01 | kaslr_offset() pub — violation RÈGLE KASLR-03 |
| KTCB-CAGE-01 | Même shadow stack PL0/PL1 (Ring 1 peut corrompre Ring 0) |
| KTCB-RC-01 | Runtime integrity check mode observe ne panic pas |
| KTCB-LEDGER-01 | Ring buffer overflow casse la chaîne verify_ring_integrity |
| KTCB-LEDGER-02 | P0 zone saturable (DoS audit critique) |
| KTCB-VEIL-01 | pks_restore_for_normal_ops() expose Caps + TcbHot |
| KTCB-KAIROS-01 | get_kernel_secret() fail-open à [0;32] |
| KTCB-KAIROS-02 | KERNEL_SECRET pas en PKS Credentials |
| KTCB-KAIROS-03 | delegate() ExoKairos ne décrémente pas budget parent |

### MEDIUM (28)

KTCB-MOD-01, KTCB-MOD-03, KTCB-TABLE-03, KTCB-TABLE-04, KTCB-DELEG-02, KTCB-NS-01, KTCB-NS-02, KTCB-NS-03, KTCB-CTX-02, KTCB-POL-01, KTCB-PS-02, KTCB-PS-03, KTCB-AUD-03, KTCB-AUD-04, KTCB-SCAUD-01, KTCB-SCAUD-02, KTCB-AC-02, KTCB-CS-01, KTCB-RC-02, KTCB-RC-03, KTCB-SB-03, KTCB-SB-04, KTCB-KASLR-02, KTCB-KASLR-03, KTCB-SEAL-01, KTCB-CAGE-02, KTCB-CAGE-03, KTCB-VEIL-02, KTCB-VEIL-03, KTCB-LEDGER-03, KTCB-LEDGER-04, KTCB-KAIROS-04, KTCB-KAIROS-05, KTCB-NMI-01, KTCB-NMI-02, KTCB-ARGOS-01, KTCB-ARGOS-02, KTCB-IPC-01, KTCB-IPC-02, KTCB-SHIELD-01, KTCB-SHIELD-02

### LOW (16)

KTCB-MOD-02, KTCB-TABLE-05, KTCB-CTX-03, KTCB-POL-02, KTCB-PS-04, KTCB-AUD-05, KTCB-AUD-06, KTCB-NS-04, KTCB-NS-05, KTCB-CS-02, KTCB-SB-05, KTCB-KASLR-04, KTCB-CAGE-04, KTCB-LEDGER-05, KTCB-KAIROS-06, KTCB-NMI-03, KTCB-ARGOS-03, KTCB-IPC-03, KTCB-SHIELD-03, KTCB-VEIL-04

---

## 19. Points forts confirmés

- ✅ `capability::verify()` constant-time via `subtle::ConstantTimeEq` + `Rights::contains_ct` (CAP-05)
- ✅ `Rights::is_subset_of` constant-time (CAP-03 enforceable)
- ✅ MLS labels Bell-LaPadula + Biba corrects (labels.rs)
- ✅ `key_is_forbidden` compile-time anti-régression clés RFC 8032 (code_signing.rs)
- ✅ `SECURITY_READY` Acquire/Release + SMP spin-wait dans `smp/init.rs:170` (CVE-EXO-001 corrigé)
- ✅ `inherit_from_masked` retire droits FS privilégiés (GC/ADMIN) au fork
- ✅ `register_ttl_for_cap` câble ExoKairos au `capability::create`
- ✅ `verify_p0_fixes()` check invariants boot ExoSeal (NIC IOMMU, CET, PKS)
- ✅ `cp_handler` handoff immédiat vers ExoPhoenix sur #CP
- ✅ `pledge_promises_to_restrictions` pont pledge → ZT restrictions
- ✅ Static asserts `CapToken == 24`, `LedgerEntry == 136`, `PmcSnapshot == 64`
- ✅ `SecurityContext::for_process` dérive trust de l'état système (init=System, ring1=Trusted, reste=Normal)
- ✅ `kernel_a_hash_is_zero()` check différencie dev/prod pour hashes Kernel-A
- ✅ `production_security_status()` exposé et testable
- ✅ Aucune implémentation crypto maison fragile (crates RustCrypto, ed25519-dalek verify_strict)

---

## 20. Recommandations prioritaires

### P0 — Critiques (à appliquer en priorité, ~15 j-h)

1. **KTCB-01** : Appeler `verify_boot_attestation()` dans `exoseal_boot_phase0()` (après IOMMU init). Si `CHAIN_VERIFIED` reste false après boot, panic kernel. Désactiver le court-circuit `if is_chain_verified()` dans `exec.rs:275` — toujours appeler `check_chain_of_trust()`.
2. **KTCB-02** : Ajouter check de génération dans `CapTable::check_object()` — prendre un paramètre `expected_generation: u32` ou exiger un `CapToken` en entrée. Alternative : supprimer `check_object()` et forcer ExoFS à passer par `verify_typed()`.
3. **KTCB-03** : (a) CAS loop sur `CURRENT_PKRS` dans `revoke_domain`/`restore_domain` (`compare_exchange_weak` jusqu'à succès). (b) IPI broadcast aux autres CPUs après WRPKRS pour propager la révocation. (c) Garder Caps/TcbHot en Disabled par défaut, ne restaurer que via `ScopedPkrsAccess` pour les opérations précises.
4. **KTCB-04** : Étendre `P0_CHAIN_LOCK` à `exo_ledger_append()` (ring buffer). Ou : utiliser un compteur `LAST_HASH_SEQ` atomique et CAS loop sur `LAST_HASH`. Désactiver IRQ (`irq_save`) autour du RMW.
5. **KTCB-05** : (a) Câbler `cfg_register_range` dans `arch_init()` avec `_text_start`/`_text_end`. (b) Ajouter `cfg_assert_indirect_call()` aux sites d'appel indirect sensibles. (c) Cable `safe_stack_new_thread` dans `process/core/tcb.rs::alloc()`. (d) Restaurer la table canary per-thread dans `tcb.rs`. (e) Gate `disable_enforcement()` derrière une `CapToken` `CAP_SECURE_BOOT_DISABLE` et un `#[cfg(feature = "dev_secure_boot")]`.

### P1 — Hautes (~25 j-h)

6. **KTCB-TABLE-02** : Bumper génération dans le re-grant path de `grant()`. Tous les tokens existants deviennent invalides (cohérent avec la semantique de re-grant).
7. **KTCB-DELEG-01** : Vérifier `delegated_rights.is_subset_of(table.rights)` (table courante) en plus de `source_token.rights()`.
8. **KTCB-CTX-01** : CAS loop dans `downgrade()` pour garantir monotonicité.
9. **KTCB-PS-01** : Passer uid/gid réels depuis le PCB dans `context_for_caller()`. Le `PrincipalId` doit refléter l'identité POSIX.
10. **KTCB-AUD-01** : Stratégie : si `SecurityViolation` + ring plein, panic kernel (ne pas écraser). Sinon overwrite.
11. **KTCB-CAGE-01** : Allouer des shadow stacks distinctes pour PL0 (kernel) et PL1 (Ring 1). Ne pas partager `token_addr`.
12. **KTCB-KAIROS-03** : `delegate()` doit `fetch_sub` le budget parent.
13. **KTCB-KAIROS-01** : `get_kernel_secret()` panic si `KERNEL_SECRET.get().is_none()` plutôt que-retourner `[0;32]`.
14. **KTCB-KASLR-01** : Mark `kaslr_offset()` comme `pub(crate)` seulement. Exposer une version dégradée (`kaslr_is_ready()`) au public.

### P2 — Moyennes (~30 j-h)

15. **KTCB-RC-01** : En production (`!kernel_a_hash_is_zero()`), `security_periodic_check_observe` → panic au lieu de log-only.
16. **KTCB-LEDGER-02** : Augmenter `P0_ZONE_ENTRIES` à 64 ou 128. Ou : zone P0 circulaire avec hash chain préservé.
17. **KTCB-AC-01** : `check_access()` signature doit prendre `pid, tid, uid` et les logger.
18. **KTCB-PS-02** : Augmenter `MAX_TRACKED_PIDS` à 4096 ou passer à une hash table.
19. **KTCB-NS-02** : CAS loop dans `Namespace::release()` + fence Acquire après `fetch_sub`.
20. **KTCB-ARGOS-02** : `BASELINE_SNAPSHOT` per-CPU.
21. **KTCB-IPC-02** : Vérifier le CapToken fourni à `register_service()` contre la table kernel réelle (`check_token_owner`).

### P3 — Basses (~20 j-h)

22. Documenter et tester tous les chemins "dead code" identifiés (les supprimer ou les câbler).
23. `Rights::ALL = u32::MAX` → `Rights::ALL = 0xFFFF` (cohérent avec `from_bits`).
24. `from_u8` labels fail-closed OK, mais documenter le comportement.
25. Nettoyer `unwrap_or(0)` patterns dans `rng_u64()` callers (panic ou retry borné).

---

## 21. Code changes / livrables

- Rapport détaillé : `audit_notes/06-kernel-tcb.md` (ce fichier, ~900 lignes).
- Aucun patch appliqué au code source (audit lecture seule, conforme aux audits précédents).
- 5 correctifs P0 + 9 correctifs P1 + 7 correctifs P2 fournis en pseudo-code dans les sections ci-dessus.

---

## 22. Conclusion

Le TCB ExoOS est **architecturalement riche** mais souffre du syndrome "scaffolding sans enforcement" déjà identifié par AUDIT-100-PERCENT.md pour la crypto et ExoFS. Plusieurs piliers annoncés (Secure Boot, CFG, SafeStack, canary per-thread, SandboxPolicy, PKS isolation, ExoLedger chain integrity, capability revocation sur FS path) sont **soit morts au runtime, soit affectés par des races critiques, soit contournables par une fonction `pub` sans capability check**. La défense en profondeur est réelle sur le papier mais l'audit révèle que l'attaquant a souvent **plusieurs chemins pour contourner chaque couche** :

- Pour exécuter un binaire non signé : ne pas appeler `verify_boot_attestation` (KTCB-01).
- Pour éviter la révocation d'un token sur ExoFS : `revoke()` ne fait que gen++ (KTCB-02).
- Pour corrompre l'audit : flood P0 (16 events) ou concurrent append (KTCB-04).
- Pour bypass PKS : révoquer sur un CPU, accéder depuis un autre (KTCB-03).
- Pour désactiver Secure Boot au runtime : `disable_enforcement()` (KTCB-05e).

**Score maturité TCB : 4 / 10** — La base crypto et capability `verify()` est solide (~7/10), mais l'intégration runtime et l'enforcement réel sont défaillants (~2/10). Correctifs P0 (~15 j-h) élèveraient à 6.5/10 ; P1+P2 (~55 j-h) à 8.5/10. La priorité absolue est le câblage effectif des fonctions existantes (verify_boot_attestation, cfg_register_range, safe_stack_new_thread, install_canary) et le hardening des races (ExoVeil CAS + IPI, ExoLedger lock, downgrade CAS).
