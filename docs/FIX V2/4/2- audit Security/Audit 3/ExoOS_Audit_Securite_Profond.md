# ExoOS v0.2.0 « Strata » — Audit de Sécurité Profond et Exhaustif

**Date**: 2 juillet 2026
**Périmètre**: kernel complet + tous les modules (loader, bootloader, drivers, fs, servers), ExoShield (NGAV), crypto_server, cryptographie kernel
**Méthodologie**: lecture ligne-par-ligne à froid de ~364 000 LOC Rust + 21 000 LOC scripts/tools
**Volumétrie**: 9 rapports de sous-audits + 1 passe de vérification = ~9 400 lignes de notes

---

## 1. Résumé Exécutif

ExoOS v0.2.0 « Strata » présente une **architecture de sécurité extraordinairement ambitieuse** — 8 couches, 15+ sous-systèmes kernel (ExoSeal, ExoCage, ExoKairos, ExoLedger, ExoVeil/PKS, ExoArgos, ExoNMI, Zero-Trust MLS, CapToken, Pledge, Sandbox), un EDR Ring1 ExoShield, une résurrection double-noyau ExoPhoenix, un crypto_server centralisé, et une chaîne de boot Ed25519+SHA-512.

**Cependant, l'audit révèle un décalage systémique entre code implémenté et enforcement opérationnel.**

### Verdict global

| Domaine | Verdict |
|---|---|
| Boot chain (UEFI → kernel.elf) | ✅ **Solide** : Ed25519 `verify_strict` + SHA-512 + fail-closed + compile-time guards |
| Boot chain (kernel → userspace) | ❌ **Brisée** : `do_execve()` n'invoque jamais `verify_module_signature()` ; `CHAIN_VERIFIED` reste `false` à vie |
| ExoPhoenix (résurrection A↔B) | ❌ **Mirage** : `stage0_init_all_steps(true)` est appelé mais `isolate_kernel_a_memory()` ne l'est pas ; pas de hash BLAKE3 SSR |
| Crypto kernel (primitives) | ⚠️ **Partiellement conforme** : BLAKE3, Ed25519 OK ; X25519 manque RFC 7748 §6 ; AES software a branches data-dépendantes |
| ExoShield (NGAV) | ❌ **Pas un NGAV** : ~47 % de code mort ; `PhoenixSafe` absent ; détection post-factum seulement |
| Crypto server | ❌ **Autorité non fiable** : bypass Phoenix ; TLS = DH anonyme (MITM trivial) ; PKI morte |
| Capability / IPC policy | ⚠️ **Plomberie OK, orchestration défaillante** : tokens 24B sans MAC forgeables ; `sys_exo_ipc_create` permet d'usurper `CryptoServer` |
| Memory / IOMMU | ❌ **IOMMU contournable depuis userspace** via `DMA_MAP_FLAGS_BYPASS_IOMMU` sans cap check |
| Mitigations (CFG, CET, KASLR, canary) | ❌ **Toutes mortes ou inefficaces** : `cfg_lock()` jamais appelé ; `enable_shadow_stack()` jamais appelé ; KASLR ~0 bit ; canary TCB = `0xDEAD_BEEF_CAFE_BABE` |
| Audit log (ExoLedger) | ❌ **Non tamper-evident** : pas de hash chain, pas de MAC, en BSS |
| Filesystems (ext4, fat32) | ⚠️ **Vulnérables à un disque malveillant** : pas de CRC32c JBD2, extent tree depth>0 non récursif |
| fscrypt | ❌ **Incomplet** : XChaCha20+BLAKE3-MAC au lieu de XChaCha20-Poly1305 ; pas de filename encryption ; pas de rollback protection |
| Dépendances cargo | ✅ **Propres** : aucune CVE connue (curve25519-dalek 4.1.3, ed25519-dalek 2.2.0, blake3 1.8.3, chacha20poly1305 0.10.1, argon2 0.5.3, hkdf 0.12.4, subtle 2.6.1) |

### Toutes les CVE/dependency vulnerabilities

Aucune CVE connue dans les crates externes (Cargo.lock vérifié). Toutes les vulnérabilités ci-dessous sont des **failles natives** introduites par le code d'ExoOS lui-même.

### Comptage consolidé des findings

| Sévérité | Count |
|---|---|
| 🔴 CRITICAL | ~50 |
| 🟠 HIGH | ~70 |
| 🟡 MEDIUM | ~75 |
| 🟢 LOW | ~40 |
| **Total** | **~235 findings** |

### Top 10 vulnérabilités critiques (à corriger en priorité absolue)

| # | ID | Résumé | Impact |
|---|---|---|---|
| 1 | INTEG-001 / USER-004 | `verify_boot_attestation()` jamais appelée → `CHAIN_VERIFIED` false à vie | Toute la chaîne de confiance secure-boot est morte |
| 2 | INTEG-002 / C-01 / USER-003 | `do_execve()` ne vérifie jamais la signature binaire | N'importe quel ELF s'exécute, avec ou sans signature |
| 3 | USER-001 | `stage0_init()` (Kernel B entry) jamais appelé | ExoPhoenix dual-kernel recovery = 3 926 LOC de code mort |
| 4 | USER-002 / BOOT-001 | `isolate_kernel_a_memory()` jamais appelée | Kernel A garde accès complet pendant "l'isolation" Phoenix |
| 5 | DRV-001/002/003 / KERN-030 | Drivers réseau passent `DMA_MAP_FLAGS_BYPASS_IOMMU` ; kernel honore le flag sans cap check | Périphérique malveillant peut DMA vers toute la RAM |
| 6 | SHIELD-001 | `PhoenixSafe` non implémenté dans exo_shield | Attaquant survit à un switch Phoenix indétecté |
| 7 | CRYPTOSRV-002 | TLS = DH anonyme, `tls_verify_certificate` jamais appelé | MITM trivial sur tout tunnel inter-serveurs |
| 8 | POLICY-001 | `sys_exo_ipc_create` laisse n'importe quel process devenir `CryptoServer` par nom | Escalade Ring1 non authentifiée + bypass MLS |
| 9 | KERN-016 | `shm_map()` ne vérifie aucune capability | N'importe quel process mappe n'importe quel SHM |
| 10 | KERN-024 | `sys_kill` sans CAP_KILL ni même-UID | N'importe quel process SIGKILL n'importe quel autre |

---

## 2. Méthodologie

L'audit a été conduit en **9 passes parallèles** par 9 agents indépendants, chacun dédié à un sous-système :

1. **Architecture & docs** — Lecture exhaustive de tous les documents d'architecture (`docs/Vision v0.2.0/`, `docs/FIX V2/`, `docs/SECURITE/`, specs TLA+).
2. **Chaîne de boot** — `bootloader/`, `exo-boot/`, `loader/`, `tools/kernel_signer/`, `kernel/src/userspace_boot.rs`, `kernel/src/main.rs`, `kernel/src/exophoenix/*`.
3a. **Kernel crypto & intégrité** — `kernel/src/security/{crypto, integrity_check, exoseal, exoveil, exoledger, exokairos, exoargos, exonmi, exocage, shield_feed}.*`
3b. **Kernel security policy** — `kernel/src/security/{access_control, capability, zero_trust, isolation, audit, exploit_mitigations, ipc_policy}.*`
4. **Kernel core** — `kernel/src/{memory, ipc, syscall, scheduler, drivers}/*`
5. **ExoShield NGAV** — `servers/exo_shield/src/**`
6. **Crypto server** — `servers/crypto_server/src/**`
7. **Autres servers** — `servers/{ipc_router, init_server, vfs_server, network_server, memory_server, device_server, scheduler_server, tty_server, fb_server, input_server, exosh, virtio_drivers, syscall_abi, phase5-tests}/**`
8. **Drivers & filesystems** — `drivers/{network, storage, security, fs, tty, input, display}/**`
9a. **Userspace + loader + tools + build** — `userspace/`, `loader/`, `exo-boot/` (re-vérifié), `tools/`, `Cargo.toml`, `Makefile`, `*.json`, `kernel/src/exophoenix/*` (re-vérifié)
9b. **Vérification des 25 findings critiques** — Re-lecture directe du code source pour confirmer/réfuter.

**Chaque agent a été instruit de** : lire chaque fichier complètement sans skimming, extraire les snippets verbatim, décrire des scénarios d'attaque concrets, recommander des fixes précis.

**Vérification 9b** : 25 findings critiques re-lus directement. Résultat : 15 confirmés, 5 partiellement fixés, 5 réfutés. Les chiffres ci-dessus intègrent ces corrections.

---

## 3. Architecture de Sécurité (Synthèse)

ExoOS est un microkernel Rust bare-metal x86_64 avec 8 couches de sécurité :

```
COUCHE 1 — Boot Integrity      : ExoSeal (hash chain kernel + ring1)
COUCHE 2 — Isolation Hardware  : ExoCage (CET SS + IBT + SMEP + SMAP + KPTI + NX)
COUCHE 3 — Vérification Continue: Zero Trust (IPC labelled + verified)
COUCHE 4a — CapToken System     : droits par ressource
COUCHE 4b — ExoKairos          : budgets temporels anti-DoS
COUCHE 5 — Audit Immuable       : ExoLedger (BLAKE3 chainé)
COUCHE 6 — Isolation Physique   : IOMMU ExoShield (DMA domains)
COUCHE 7 — Watchdog Permanent   : ExoNMI (200ms NMI, canary, IDT)
COUCHE 8 — Détection & Réponse  : ExoShield (Ring1 EDR)
```

**Modèle** : Zero-Trust MLS (Bell-LaPadula + Biba), Capability-based (24B tokens, 512 slots), Pledge (16 flags), Sandbox `exo compat`, IPC DAG.

**Crypto mandate** : Ed25519 `verify_strict`, X25519 RFC 7748 §6, AES-GCM (GHASH constant-time, ct_eq tag, verify-before-decrypt), XChaCha20-Poly1305 AEAD encrypt-then-MAC, BLAKE3 (`constant_time_eq`, `derive_key`), HKDF-Blake3, SHA-512, Argon2id (m=64MiB t=3 p=4), RNG (RDSEED×4 + RDRAND×6 + jitter + stack, BLAKE3-conditioned, reseed 4096, zeroization).

**Boot chain** : UEFI SecureBoot → exo-boot.efi (PE32+ sig) → kernel.elf (Ed25519+SHA-512 footer EXOSIG01 256B) → BootInfo integrity → ExoSeal phase0 (BLAKE3 kernel + Ring1).

**ExoPhoenix** : Dual-kernel A↔B, recovery <500ms, SSR 4KiB @ `0x0100_0000` (magic `0xEXO_PHXF`, BLAKE3 hash), sentinel NMI heartbeat >2s, PhoenixSafe trait pour 9 services.

**ExoShield** : Ring1 EDR — 8 modules (engine, behavioral, hooks, network, sandbox, signatures, ml, forensics), 7 IPC ops, YARA + ML 32→16 Q16.16, Ed25519-signed signature DB updates.

---

## 4. Findings par Domaine

### 4.1 Chaîne de Boot (5 CRITICAL, 6 HIGH)

| ID | Sév | Fichier | Résumé |
|---|---|---|---|
| BOOT-001 | 🔴 | `kernel/src/exophoenix/isolate.rs` | `isolate_kernel_a_memory()` définie mais **jamais appelée**. Kernel A garde un accès complet pendant le handoff. |
| BOOT-002 | 🟠 (réfuté) | `kernel/src/exophoenix/stage0.rs` | `stage0_init_all_steps(true)` IS appelée depuis `lib.rs:284` (vérification 9b a réfuté le finding original). |
| BOOT-003 | 🔴 | `exo-boot/src/config/defaults.rs:49` + `kernel/src/main.rs` | `SECURE_BOOT_ACTIVE` basé sur config (`secure_boot_required=false` défaut), pas sur vérification réelle ; le kernel ne lit jamais `boot_flags`. |
| BOOT-004 | 🔴 | `loader/src/...` | Note `EXOSIG\0\0` détectée par string match mais jamais vérifiée crypto. |
| BOOT-005 | 🔴 | `kernel/src/exophoenix/handoff.rs` | `begin_isolation_hard()` relâche les cœurs Kernel A sans reconstruction ni isolation PTE. |
| BOOT-006 | 🟠 | `kernel/src/main.rs` | `BootInfo.version` non validé par le kernel (seul magic). |
| BOOT-007 | 🟠 | `kernel/src/main.rs` | Champ `entropy[64]` du BootInfo **jamais lu** par le kernel (EFI_RNG gaspillé). |
| BOOT-008 | 🟠 | `kernel/src/exophoenix/ssr.rs` | `SSR_OFFSET_CHECKSUM` défini mais jamais vérifié (pas de hash BLAKE3 SSR). |
| BOOT-009 | 🟠 | `kernel/src/exophoenix/ssr.rs` | Échec `initialize_layout_v7()` non-fatal → SSR corrompue désactive silencieusement Phoenix. |
| BOOT-010 | 🟠 | `exo-boot/src/config/defaults.rs:49` | `secure_boot_required = false` par défaut → kernel non-signé démarre avec warning. |
| BOOT-011 | 🟠 | `exo-boot/src/...` | KASLR plage [4 MiB, 2 GiB] = ~9 bits (spec annonce 1 GiB..256 GiB) ; court-circuité par `AllocateType::AnyPages` → KASLR effectif ≈ 0 bit. |

### 4.2 Kernel Crypto & Intégrité (4 CRITICAL, 7 HIGH)

| ID | Sév | Fichier | Résumé |
|---|---|---|---|
| INTEG-001 | 🔴 | `kernel/src/security/integrity_check/secure_boot.rs` | `verify_boot_attestation()` JAMAIS appelée → `CHAIN_VERIFIED` reste `false` à vie. |
| INTEG-002 | 🔴 | `kernel/src/syscall/handlers/process.rs:275` | `verify_module_signature()` PAS appelée par `do_execve()`. Check circulaire `is_chain_verified() → check_chain_of_trust()`. **C-01 toujours ouvert**. |
| INTEG-003 | 🔴 | `kernel/src/security/exoseal.rs` | `exoseal_boot_phase0/complete` ne halt pas le boot si `verify_p0_fixes()` échoue — `return` early sans panic. Aucun hash BLAKE3 kernel+Ring1. |
| INTEG-004 | 🔴 | `kernel/src/security/exokairos.rs` | `get_kernel_secret()` retourne `[0u8;32]` si `init_kernel_secret` pas encore appelée → caps créées avant step 10 ont un MAC à clé zéro forgeable par Ring1. |
| CRYPTO-001 | 🟠 | `kernel/src/security/crypto/x25519.rs` | Ne rejette que le point identité — RFC 7748 §6 weak-order subgroup checks ABSENTS → small-subgroup attack. |
| CRYPTO-002 | 🟠 | `kernel/src/security/crypto/aes_gcm.rs` | `aes_xtime()` a branche data-dépendante → timing side-channel sur AES software (MixColumns). |
| CRYPTO-003 | 🟠 | `kernel/src/security/crypto/aes_gcm.rs` | AES-NI asm déclare `preserves_flags` incorrectement (`add rax,16` clobber flags) → risque miscompilation. |
| INTEG-005 | 🟠 | `kernel/src/security/integrity_check/secure_boot.rs` | `disable_enforcement()` pub non-unsafe — désactive secure-boot à runtime. |
| INTEG-006 | 🟠 | `kernel/src/security/integrity_check/runtime_check.rs` | Runtime integrity check en mode OBSERVE (log-only, jamais panic). |
| INTEG-007 | 🟠 | `kernel/src/security/integrity_check/runtime_check.rs` | Hash référence .text/.rodata en clair en BSS — attaquant kernel R/W peut le réécrire. |
| INTEG-008 | 🟠 | `kernel/src/security/exoledger.rs` | ExoLedger en BSS (pas SSR.LOG_AUDIT), chaîne BLAKE3 sans clé secrète → forgeable. |
| INTEG-009 | 🟠 | `kernel/src/security/exonmi.rs` | `arm_watchdog(0)` pub non-unsafe — désarme le NMI watchdog. |
| INTEG-010 | 🟠 | `kernel/src/security/exoveil.rs` | `restore_domain()` pub unsafe sans cap — restaure PKS Credentials à volonté. |

### 4.3 Kernel Security Policy (9 CRITICAL, 9 HIGH)

| ID | Sév | Fichier | Résumé |
|---|---|---|---|
| POLICY-001 | 🔴 | `kernel/src/syscall/handlers/ipc.rs` | `sys_exo_ipc_create` laisse n'importe quel process réclamer `ServiceClass::CryptoServer` par nom → forge sender_pid, bypass MLS. |
| POLICY-002 | 🔴 | `kernel/src/security/exploit_mitigations/kaslr.rs` | KASLR jamais appliqué aux symboles kernel (offset calculé mais pas appliqué) — 0 bit effectif. |
| POLICY-003 | 🔴 | `kernel/src/security/exploit_mitigations/cfg.rs` | CFG totalement contournable : `cfg_validate_indirect_call` jamais appelé, `cfg_lock()` jamais appelé. |
| POLICY-004 | 🔴 | `kernel/src/security/exploit_mitigations/cet.rs` | CET Shadow Stack jamais activé — `enable_shadow_stack()` jamais appelé (seul IBT est wired). |
| POLICY-005 | 🔴 | `kernel/src/security/exploit_mitigations/stack_protector.rs` + `kernel/src/.../tcb.rs` | Stack canary kernel TCB = constant `0xDEAD_BEEF_CAFE_BABE` (stack_protector.rs est dead code). |
| POLICY-006 | 🔴 | `kernel/src/security/isolation/sandbox.rs` | `SandboxPolicy` jamais instancié — DEAD CODE. |
| POLICY-007 | 🔴 | `kernel/src/security/isolation/namespaces.rs` | `NamespaceSet` jamais dans PCB — types uniquement. |
| POLICY-008 | 🔴 | `kernel/src/security/audit/logger.rs` | Ring 65536 NON tamper-evident — pas de hash chain, pas de MAC. `add/remove_global_rule`/`set_filter` non authentifiés. |
| POLICY-009 | 🔴 | `kernel/src/security/capability/token.rs` | Token 24B = `{object_id, rights, generation, type_tag}` sans MAC — Ring1 peut forger des wire-tokens. |
| POLICY-010 | 🟠 | `kernel/src/security/zero_trust/labels.rs` | Comparaisons Bell-LaPadula/Biba non constant-time. |
| POLICY-011 | 🟠 | `kernel/src/security/isolation/pledge.rs` | PLEDGE-02 non respecté : violation → `DenyAndAudit`, pas `SIGKILL` immédiat. |
| POLICY-012 | 🟠 | `kernel/src/security/isolation/domains.rs` | `DomainContext` jamais dans TCB — compile-time only. |
| POLICY-013 | 🟠 | `kernel/src/security/exploit_mitigations/safe_stack.rs` | `safe_stack_new_thread` jamais appelé — DEAD CODE. |
| POLICY-014 | 🟠 | `kernel/src/security/capability/delegation.rs` | `delegate()` n'est jamais appelé depuis syscall. |
| POLICY-015 | 🟠 | `kernel/src/security/audit/rules.rs` | Règles désactivables runtime sans auth. |
| POLICY-016 | 🟠 | `kernel/src/security/zero_trust/labels.rs` | Downgrade label non bloqué explicitement. |
| POLICY-017 | 🟠 | `kernel/src/security/exploit_mitigations/cet.rs` | `cfg_lock()` non appelé à l'étape 18 du boot. |
| POLICY-018 | 🟠 | `kernel/src/security/capability/revocation.rs` | Revocation propagation atomique intra-table OK, mais pas cross-table. |

### 4.4 Kernel Core (6 CRITICAL, 7 HIGH)

| ID | Sév | Fichier | Résumé |
|---|---|---|---|
| KERN-001 | 🔴 | `kernel/src/memory/protection/pku.rs:274` | `enable_pku` active `CR4_PKE` mais jamais `CR4_PKS` — clés kernel heap/guard/MMIO inefficaces en Ring 0. |
| KERN-006 | 🔴 | `kernel/src/memory/integrity/sanitizer.rs:340` | `kasan::init()` active KASAN sans empoisonner la shadow map (0x00 = ACCESSIBLE) → détection UAF/overflow neutralisée. |
| KERN-013 | 🔴 | `kernel/src/memory/heap/large/vmalloc.rs:246` | `vmalloc` retourne des pointeurs dans la physmap (pas VMALLOC_BASE) → pas d'isolation d'adressage pour grandes allocations kernel. |
| KERN-016 | 🔴 | `kernel/src/ipc/shared_memory/mapping.rs:253` | `shm_map(desc_idx, pid, ...)` ne vérifie PAS de capability → n'importe quel process peut mapper n'importe quelle région SHM. |
| KERN-023 | 🔴 | `kernel/src/syscall/handlers/misc.rs:157` | `sys_arch_prctl(ARCH_SET_FS, addr)` ne valide pas que `addr` est user → FS_BASE sur adresse kernel (leak sans KPTI). |
| KERN-024 | 🔴 | `kernel/src/syscall/handlers/signal.rs:232` | `sys_kill` ne vérifie PAS CAP_KILL ni même-UID → n'importe quel process peut SIGKILL n'importe quel autre. |
| KERN-029 | 🔴 | `kernel/src/scheduler/fpu/lazy.rs:115` | Si `alloc_fpu_state` échoue (OOM), `xsave_current` retourne sans sauvegarder → **état FPU (clés AES-NI) silencieusement leaké cross-process**. |
| KERN-002 | 🟠 | `kernel/src/memory/protection/smap.rs` | `copy_from_user`/`copy_to_user` ne valident pas l'espace user (contrat unsafe délégué). |
| KERN-005 | 🟠 | `kernel/src/syscall/fixup.rs` | Handler #PF ne jump pas à recovery_rip → boucle infinie (code mort, non câblé). |
| KERN-008 | 🟠 | `kernel/src/memory/virtual/fault/cow.rs` | CoW in-place break condition trop permissive (`|| !old_entry.is_cow()`). |
| KERN-014 | 🟠 | `kernel/src/memory/physical/allocator/slub.rs` | SLUB freelist XOR key dérivée d'adresse physique prédictible. |
| KERN-017 | 🟠 | `kernel/src/ipc/shared_memory/allocator.rs` | `shm_alloc` sans limite par owner → DoS par épuisement. |
| KERN-025 | 🟠 | `kernel/src/syscall/dispatch.rs` | `verify_syscall` skippé pour 3 syscalls fast-path (pledge bypass). |
| KERN-028 | 🟠 | `kernel/src/scheduler/sync/mutex.rs` | `KMutex` commenté "héritage de priorité" mais aucun PI implémenté. |
| KERN-030 | 🔴 | `kernel/src/memory/dma/...` | Kernel honore `DMA_MAP_FLAGS_BYPASS_IOMMU` de n'importe quel caller userspace, sans cap check. |

### 4.5 ExoShield NGAV (5 CRITICAL, 12 HIGH)

| ID | Sév | Fichier | Résumé |
|---|---|---|---|
| SHIELD-001 | 🔴 | `servers/exo_shield/src/lib.rs` | `PhoenixSafe` NON IMPLÉMENTÉ — 0 match dans tout le codebase. Pre/post-switch resilience absente. |
| SHIELD-002 | 🔴 | `servers/exo_shield/src/behavioral/*` | `anomaly`, `heuristic`, `profiler`, `sequence` (3 180 LOC) — `observe()`, `evaluate()`, `record_syscall()`, `submit_event()` jamais appelés en production. |
| SHIELD-003 | 🔴 | `servers/exo_shield/src/network/*` | `IntrusionDetectionSystem`, `DnsGuard`, `TrafficAnalyzer`, `Firewall` struct (2 656 LOC) jamais instanciés. Seul le PID blocklist est utilisé. |
| SHIELD-004 | 🔴 | `servers/exo_shield/src/signatures/{database,matcher,yara,update}.rs` | 3 010 LOC jamais appelées en production. `trusted_keys` toujours vide → signature updates ne peuvent jamais réussir. |
| SHIELD-005 | 🔴 | `servers/exo_shield/src/engine/realtime.rs` | Buffer overflow canary jamais mis à jour par le kernel (rapporte toujours "intact"). |
| SHIELD-006 | 🔴 | `servers/exo_shield/src/behavioral/sequence.rs` | `record_free` jamais appelé → détection UAF inerte. |
| SHIELD-007 | 🔴 | `servers/exo_shield/src/network/dns_guard.rs` | `record_dns_query` jamais appelé → détection exfiltration DNS inerte. |
| SHIELD-008 | 🔴 | `servers/exo_shield/src/engine/core.rs` | `compute_threat_score` bug division entière → la plupart des scores = 0. Quarantine en mémoire seulement, kernel n'enforce pas. |
| SHIELD-009 | 🟠 | `servers/exo_shield/src/engine/realtime.rs` | Buffer d'alertes silently drop quand plein d'unacknowledged. |
| SHIELD-010 | 🟠 | `servers/exo_shield/src/engine/scanner.rs` | Scanner utilise FNV-1a non cryptographique (viole mandate HKDF-BLAKE3). |
| SHIELD-011 | 🟠 | `servers/exo_shield/src/hooks/*` | Shield ne peut pas bloquer syscalls/execs/network — tous hooks post-factum. |
| SHIELD-012 | 🟠 | `servers/exo_shield/src/forensics/memory_dump.rs` | CRC32 utilisé pour intégrité forensique (forgeable). |
| SHIELD-013 | 🟠 | `servers/exo_shield/src/forensics/timeline.rs` | Timeline sans aucune protection d'intégrité. |
| SHIELD-017 | 🟠 | `servers/exo_shield/src/ipc_gate/policy.rs` | Kernel PID 0 + ipc_router(2) + init_server(1) bypassent toute IPC policy. |

### 4.6 Crypto Server (4 CRITICAL, 7 HIGH)

| ID | Sév | Fichier | Résumé |
|---|---|---|---|
| CRYPTOSRV-002 | 🔴 | `servers/crypto_server/src/tls.rs` | TLS = Diffie-Hellman **anonyme**, aucun certificat vérifié → MITM trivial sur tout tunnel inter-serveurs. |
| CRYPTOSRV-003 | 🔴 | `servers/crypto_server/src/pki.rs` | PKI (996 lignes) est du **dead code** — `pki_init` jamais appelée au boot, `tls_verify_certificate` jamais invoquée. |
| CRYPTOSRV-004 | 🔴 | `servers/crypto_server/src/pki.rs` | Root CA private key en RAM du service (pas offline) — contradiction avec la doc d'en-tête ; compromission process = forge de toute la chaîne. |
| CRYPTOSRV-005 | 🔴 | `servers/crypto_server/src/xchacha20.rs` | Reseed XChaCha20 par XOR (pas HKDF). |
| CRYPTOSRV-006 | 🟠 | `servers/crypto_server/src/tls.rs` | `handshake_hash` jamais alimenté. |
| CRYPTOSRV-007 | 🟠 | `servers/crypto_server/src/tls.rs` | Compteurs TLS jamais utilisés (pas d'anti-rejeu). |
| CRYPTOSRV-008 | 🟠 | `servers/crypto_server/src/tls.rs` | `cleanup_expired_sessions` jamais appelée → DoS pool 16. |
| CRYPTOSRV-009 | 🟠 | `servers/crypto_server/src/keystore.rs` | `crypto_shred` LCG + commentaire menteur « RDRAND ». |
| CRYPTOSRV-010 | 🟠 | `servers/crypto_server/src/tls.rs` | Clés TLS locales non zeroized. |
| CRYPTOSRV-011 | 🟠 | `servers/crypto_server/src/xchacha20.rs` | Cipher `XChaCha20Poly1305` non zeroized sur stack. |
| CRYPTOSRV-012 | 🟠 | `servers/crypto_server/src/main.rs` | `CRYPTO_RANDOM` ne valide pas `r==n` (rejection sampling incomplet). |

### 4.7 Autres Servers (7 CRITICAL, 10 HIGH)

| ID | Sév | Fichier | Résumé |
|---|---|---|---|
| SRV-007 | 🔴 | `servers/init_server/src/service_manager.rs` | START/STOP/RESTART services sans capability check → n'importe quel process peut stopper exo_shield. |
| SRV-008 | 🔴 | `servers/init_server/src/main.rs` | SIGCHLD handlers jamais installés — zombie reaping par polling seulement. |
| SRV-014 | 🔴 | `servers/scheduler_server/src/realtime_admit.rs` | Path B (escalade SCHED_REALTIME) n'a pas de capability check (Path A oui). |
| SRV-015 | 🔴 | `servers/vfs_server/src/main.rs` | fd table est globale. Process B peut lire les fichiers du Process A via fd reuse. **GAP-06 confirmé** : zero CapToken check. |
| SRV-023 | 🔴 | `servers/network_server/src/main.rs` | SOCK_RAW maintenant PID-allowlisté {1,7} (D-01 partiellement fixé) — mais pas de cap réelle. |
| SRV-030 | 🔴 | `servers/network_server/src/virtio_device.rs` | network_server explicitement bypass IOMMU (`DMA_MAP_FLAGS_BYPASS_IOMMU`). |
| SRV-033 | 🔴 | `servers/memory_server/src/allocator.rs` | Allocation guard cassé — lit `size` low-32-bits comme `requested_owner`, bloquant la plupart des allocations non-init. |
| SRV-051 | 🔴 | `servers/tty_server/src/main.rs` | tty_server n'a AUCUNE auth sur la lecture des keystrokes → n'importe quel process peut keylogger. |
| SRV-002 | 🟠 | `servers/memory_server/src/shm_server.rs` | `attach_shared_region` vérifie sender_pid MAIS `share_count > 0` permet à n'importe qui avec le handle d'attacher (D-02 partiellement fixé). |
| SRV-019 | 🟠 | `servers/ipc_router/src/security_gate.rs` | Pas de signature d'auth sur sender PID — usurpation possible. |
| SRV-021 | 🟠 | `servers/network_server/src/main.rs` | Pas de cap sur le binding à des ports < 1024 → n'importe quel process bind port 22/80/443. |
| SRV-027 | 🟠 | `servers/device_server/src/claim_validator.rs` | PID allowlist au lieu de cap réelle (GAP-10 partiellement fixé). |

### 4.8 Drivers & Filesystems (7 CRITICAL, 18 HIGH)

| ID | Sév | Fichier | Résumé |
|---|---|---|---|
| DRV-001 | 🔴 | `drivers/network/virtio_net/src/virtqueue.rs:11,86-95` | Passe `DMA_MAP_FLAGS_BYPASS_IOMMU = 1 << 4` à `SYS_DMA_ALLOC`. |
| DRV-002 | 🔴 | `drivers/network/e1000/src/main.rs:25,550-561` | Idem — bypass IOMMU explicite. |
| DRV-003 | 🔴 | `kernel/src/memory/dma/...` + `syscall/table.rs:4624` | Kernel honore le flag user-supplied sans cap check → device malveillant peut DMA vers toute la RAM. |
| DRV-006 | 🔴 | `drivers/storage/fscrypt/src/lib.rs` | AEAD = XChaCha20 + BLAKE3-MAC (tag 16o), **PAS Poly1305** comme mandaté par l'architecture. Pas de filename encryption. Pas de rollback protection. Pas de zeroization keys. |
| DRV-007 | 🔴 | `drivers/storage/fscrypt/src/lib.rs:305` | `xor_block()` = XChaCha20 **SANS MAC** pour blobs at-rest → bit-flipping attack. |
| DRV-012 | 🔴 | `drivers/security/verity/src/lib.rs` | N'est PAS dm-verity — c'est Ed25519 boot image signature. Pas de Merkle tree, pas de per-block hash, pas de runtime integrity. Module **mal nommé**. |
| DRV-013 | 🔴 | `drivers/fs/src/fat32/dir_entry.rs` | FAT32 LFN parsing ne sanitize pas `..`, `/`, NUL → path traversal. |
| DRV-004 | 🟠 | `drivers/network/virtio_net/src/virtqueue.rs` | Bounds checks manquants sur `head`, `len`, `pool_idx`, `next` contrôlés par device → OOB/double-use. |
| DRV-005 | 🟠 | `drivers/network/e1000/src/rx.rs` | Idem sur descriptors RX. |
| DRV-017 | 🟠 | `drivers/fs/src/ext4/extent.rs` | Extent tree ne recurse pas dans nœuds internes (depth > 0) → fichiers >4 GiB silencieusement tronqués. |
| DRV-020 | 🟠 | `drivers/fs/src/ext4/journal.rs` | État journal lu sans validation CRC32c JBD2. |
| DRV-022 | 🟠 | `drivers/tty/src/main.rs` | Driver TTY est un stub (spinloop). |
| DRV-023 | 🟠 | `drivers/tty/src/pty.rs` | Juste un ring buffer sans auth. |
| DRV-024 | 🟠 | `drivers/tty/src/vt100.rs` | Seulement génération d'escape sequences (pas de parser) — pas de validation entrée. |
| DRV-039 | 🟠 | `drivers/network/virtio_net/src/main.rs` | Pas d'auth IPC sender → n'importe quel process peut injecter TX packets. |

### 4.9 Userspace + Loader (4 CRITICAL, 10 HIGH)

| ID | Sév | Fichier | Résumé |
|---|---|---|---|
| USER-001 | 🔴 | `kernel/src/exophoenix/stage0.rs` | `stage0_init()` (Kernel B entry) jamais appelé dans tout le codebase. Le kernel appelle `stage0_init_all_steps(true)` (Kernel A inline). ExoPhoenix dual-kernel = 3 926 LOC de code mort. |
| USER-002 | 🔴 | `kernel/src/exophoenix/isolate.rs` | `isolate_kernel_a_memory()` jamais appelée. Le handoff fait freeze IPI + IOMMU revoke + forge reconstruct, mais ne marque JAMAIS les pages de Kernel A `!PRESENT`. |
| USER-003 | 🔴 | `kernel/src/syscall/handlers/process.rs:275` | Bloc `if is_chain_verified()` est code mort car `is_chain_verified()` retourne toujours `false` (USER-004). N'importe quel ELF peut être exec'd sans vérification. |
| USER-004 | 🔴 | `kernel/src/security/integrity_check/secure_boot.rs` | `verify_boot_attestation()` (seul setter de `CHAIN_VERIFIED=true`) a 0 appelant. Conséquence directe de USER-003. |
| USER-005 | 🟠 | `loader/src/...` | GAP-09 "fix" cosmétique — `check_exec_permission()` défini mais jamais appelé par `runtime_entry()`. |
| USER-006 | 🟠 | `loader/src/...` | `detect_signature_note()` = string match `"EXOSIG\0\0"` — bypass trivial en ajoutant 8 bytes à un ELF malveillant. |
| USER-007 | 🟠 | `loader/src/dynamic_linker/mod.rs:153-175` | `run_initializers()` `transmute u64 → extern "C" fn()` puis appel direct, sans vérification (signature, plage PT_LOAD exécutable, capability). |
| USER-008 | 🟠 | `exo-boot/src/config/defaults.rs:49` | `secure_boot_required: false` par défaut — kernel non signé accepté avec warning seulement. |
| USER-009 | 🟠 | `exo-boot/src/...` | `exo-boot.cfg` sur l'ESP **non signé** — attaquant avec accès ESP peut désactiver SB + KASLR + rediriger `kernel_path`. |
| USER-010 | 🟠 | `drivers/storage/fscrypt/src/lib.rs:305` | `xor_block()` = XChaCha20 SANS MAC pour blobs at-rest — bit-flipping attack possible. |
| USER-011 | 🟠 | `kernel/src/exophoenix/handoff.rs:198` | `PhoenixWakeRequest.cap_token = [0u8; CAP_TOKEN_WIRE_SIZE]` — token zéro. Si crypto_server n'invalide pas les tokens zéro, bypass possible. |
| USER-012 | 🟠 | `Makefile:_sign_kernel` | Si `.secrets/kernel_signing.seed` absent (défaut après `git clone`), le build produit un kernel non signé avec warning jaune seulement. Pas d'exit 1. |
| USER-013 | 🟠 | `kernel ↔ crypto_server` | `PhoenixWakeEntropy` IPC non wired côté crypto_server → risque de **nonce reuse** post-Phoenix dans XChaCha20/AES-GCM. |
| USER-014 | 🟠 | `kernel/src/exophoenix/ssr.rs` | SSR validée par magic+version seulement — **pas de hash cryptographique du contenu**. |

---

## 5. Dépendances Cargo — Analyse CVE

Le `Cargo.lock` a été analysé. Toutes les crates crypto externes sont à des versions récentes sans CVE connue :

| Crate | Version | Statut |
|---|---|---|
| `curve25519-dalek` | 4.1.3 | ✅ Latest — fixe le timing leak de 4.1.0 |
| `ed25519-dalek` | 2.2.0 | ✅ Intègre le fix batch verification (CVE-2024-?) |
| `x25519-dalek` | 2.0.1 | ✅ Latest |
| `chacha20` | 0.9.1 | ✅ Latest 0.9.x |
| `chacha20poly1305` | 0.10.1 | ✅ Latest |
| `poly1305` | 0.8.0 | ✅ Latest |
| `aes-gcm` | (utilise AES-NI maison) | ⚠️ Voir CRYPTO-002/003 |
| `blake3` | 1.8.3 | ✅ Latest |
| `blake2` | 0.10.6 | ✅ Latest |
| `argon2` | 0.5.3 | ✅ Latest |
| `hkdf` | 0.12.4 | ✅ Latest |
| `sha2` | 0.10.9 | ✅ Latest |
| `subtle` | 2.6.1 | ✅ Latest |
| `constant_time_eq` | 0.4.2 | ✅ Latest |
| `zeroize` | 1.8.2 | ✅ Latest |
| `getrandom` | 0.2.17 | ✅ Latest 0.2.x (0.3.x existe mais 0.2.x est OK) |
| `rand_core` | 0.6.4 + 0.9.5 | ⚠️ Deux versions (legacy 0.6 tirée par vieilles deps) |
| `pkcs8` | 0.10.2 | ✅ Latest |
| `spki` | 0.7.3 | ✅ Latest |
| `der` | 0.7.10 | ✅ Latest |
| `fiat-crypto` | 0.2.9 | ✅ Latest |

**Conclusion dépendances** : ❌ Aucune CVE connue dans les crates externes. ✅ Toutes les vulnérabilités de cet audit sont des **failles natives** introduites par le code d'ExoOS lui-même (code dead, wiring manquant, checks absents, primitives crypto custom incomplètes).

---

## 6. Feuille de Route de Remédiation

### P0 — À corriger avant toute release (blockers)

1. **Câbler `verify_boot_attestation()`** dans `kernel_main` ou `security_init` (INTEG-001, USER-004). Panic sur Err.
2. **Câbler `verify_module_signature()`** dans `do_execve` avant remplacement de l'address space (INTEG-002, C-01, USER-003).
3. **`exoseal_boot_phase0/complete` doivent `panic!`** sur `verify_p0_fixes().is_err()` ; ajouter hash BLAKE3 kernel+Ring1 (INTEG-003).
4. **`get_kernel_secret()` doit `panic!`** si non-init ; déplacer en step 0 ; vérifier `rng_hw_seeded()` (INTEG-004).
5. **Implémenter RFC 7748 §6 complet** (5 points faibles) dans `x25519_diffie_hellman` (CRYPTO-001).
6. **`sys_exo_ipc_create` doit exiger une capability** pour réclamer `ServiceClass::CryptoServer` ou tout service système (POLICY-001).
7. **`shm_map()` doit exiger une capability** avant mapping (KERN-016).
8. **`sys_kill` doit vérifier CAP_KILL ou même-UID** (KERN-024).
9. **`sys_arch_prctl(ARCH_SET_FS, ...)` doit valider que `addr` est user** (KERN-023).
10. **IOMMU bypass flag** : le kernel doit refuser `DMA_MAP_FLAGS_BYPASS_IOMMU` depuis userspace, ou exiger `CAP_SYS_RAWIO` (DRV-001/002/003, KERN-030, SRV-030).
11. **`isolate_kernel_a_memory()` doit être appelée** dans le handoff Phoenix (BOOT-001, USER-002).
12. **Implémenter `PhoenixSafe`** dans exo_shield (SHIELD-001).
13. **TLS doit vérifier les certificats** : câbler `tls_verify_certificate` et `pki_init` au boot (CRYPTOSRV-002, CRYPTOSRV-003).
14. **`init_server` START/STOP/RESTART** doit exiger `CAP_SERVICE_ADMIN` (SRV-007).
15. **`tty_server` doit authentifier** les lecteurs de keystrokes (SRV-051).
16. **`vfs_server` doit vérifier CapToken** sur open/read/write (SRV-015, GAP-06).
17. **`memory_server::attach_shared_region()`** doit rejeter si `share_count > 0` et sender_pid != owner (SRV-002, D-02).
18. **`scheduler_server::realtime_admit` Path B** doit exiger cap (SRV-014, D-03).
19. **`fscrypt` doit utiliser XChaCha20-Poly1305** AEAD pour les blobs, pas XChaCha20+BLAKE3-MAC ni xor_block (DRV-006/007, USER-010).
20. **`CapToken` 24B doit avoir un MAC** (BLAKE3 keyed) avec KERNEL_SECRET (POLICY-009).
21. **`enable_shadow_stack()` doit être appelée** au boot (POLICY-004).
22. **`cfg_lock()` doit être appelée** à l'étape 18 du boot (POLICY-003, POLICY-017).
23. **KASLR offset doit être appliqué** aux symboles kernel (POLICY-002, BOOT-011).
24. **Stack canary TCB doit être aléatoire** (POLICY-005).
25. **ExoLedger doit être chaîné BLAKE3 + MAC clé** (POLICY-008, INTEG-008).
26. **`secure_boot_required` doit être `true` par défaut** en release (BOOT-010, USER-008).
27. **`Makefile:_sign_kernel` doit `exit 1`** si clé absente en release (USER-012).
28. **`PhoenixWakeEntropy` doit être wired** kernel → crypto_server (USER-013).
29. **SSR doit avoir un hash BLAKE3 du contenu** vérifié par Kernel B (USER-014, BOOT-008).
30. **`audit_syscall_entry/exit` sont OK** mais `add/remove_global_rule` doit être cap-gated (POLICY-015).

### P1 — À corriger dans la foulée

- **DRV-012** : Renommer `drivers/security/verity` en `boot_signature` et implémenter un vrai module dm-verity (Merkle tree BLAKE3, root hash anchored in kernel BSS + TPM PCR).
- **SHIELD-002/003/004** : Câbler behavioral modules, network IDS/DNS/traffic, signature database/YARA/matcher/update au moteur de production. ~47 % du code exo_shield est mort.
- **SHIELD-005/006/007/008** : Câbler buffer overflow canary, `record_free`, `record_dns_query`, fixer le bug division entière dans `compute_threat_score`.
- **KERN-006** : Empoisonner la KASAN shadow map au boot.
- **KERN-001** : Activer `CR4_PKS` en plus de `CR4_PKE`, initialiser PKRS.
- **KERN-013** : Migrer `vmalloc` vers VMALLOC_BASE.
- **KERN-029** : Tuer le thread si `alloc_fpu_state` échoue.
- **CRYPTOSRV-005** : Reseed XChaCha20 par HKDF-Blake3.
- **CRYPTOSRV-009** : `crypto_shred` doit utiliser un vrai CSPRNG (RDRAND), pas LCG.
- **DRV-017** : Extent tree récursif pour depth > 0.
- **DRV-020** : CRC32c JBD2 sur le journal ext4.
- **DRV-013** : Sanitizer `..`, `/`, NUL dans FAT32 LFN.
- **USER-009** : Signer `exo-boot.cfg` (Ed25519 detached signature).
- **USER-007** : `run_initializers()` doit valider la plage PT_LOAD exécutable et la signature.

### P2 — Durcissement

- Constant-time comparisons dans zero_trust/labels (POLICY-010).
- PLEDGE-02 → SIGKILL immédiat (POLICY-011).
- PI dans KMutex (KERN-028).
- Supprimer `syscall/fixup.rs` mort (KERN-005).
- Ajouter filename encryption à fscrypt.
- Renforcer RNG kernel : utiliser boot_info entropy[64] (BOOT-007).
- Migration des PID-based checks vers CapToken-based (SRV-019/027, et général).

---

## 7. Conclusion

### Verdict final

**ExoOS v0.2.0 « Strata » n'offre PAS la sécurité annoncée par son architecture.**

L'architecture de sécurité spécifiée dans les documents est **remarquablement bien conçue** : 8 couches, MLS Bell-LaPadula+Biba, CapToken, Pledge, Sandbox, ExoPhoenix, ExoShield EDR, chaîne de boot Ed25519. Les **primitives cryptographiques bas-niveau sont correctement choisies** (Ed25519 `verify_strict`, BLAKE3, XChaCha20-Poly1305, AES-GCM avec GHASH branchless, HKDF-Blake3, Argon2id).

**Cependant, l'enforcement opérationnel est gravement défaillant** :

1. **La chaîne de confiance secure-boot est brisée** : `verify_boot_attestation()` n'est jamais appelée → `CHAIN_VERIFIED` reste `false` à vie → `do_execve()` skip son propre check → n'importe quel ELF s'exécute. (INTEG-001 + INTEG-002 + USER-004 = collapse total)

2. **ExoPhoenix est un mirage** : `stage0_init()` du Kernel B n'est jamais appelé ; `isolate_kernel_a_memory()` n'est jamais appelée ; SSR n'a pas de hash BLAKE3 ; `PhoenixSafe` n'est pas implémenté dans exo_shield ; `PhoenixWakeEntropy` n'est pas wired. 3 926 LOC de code mort.

3. **ExoShield n'est pas un NGAV** : ~47 % du code est mort. Pas de hook bloquant. `PhoenixSafe` absent. Forensics en CRC32. Detection post-factum seulement. Un attaquant peut exécuter n'importe quel syscall/exec/network op avant qu'ExoShield ne voie l'événement.

4. **Le crypto_server n'est pas une autorité fiable** : TLS = DH anonyme (MITM trivial). PKI morte. Root CA en RAM. Bypass Phoenix par token zéro potentiel.

5. **L'IOMMU est contournable depuis userspace** : `DMA_MAP_FLAGS_BYPASS_IOMMU` honoré sans cap check → périphérique malveillant peut DMA vers toute la RAM.

6. **Les mitigations d'exploit sont mortes** : CFG jamais verrouillé, CET Shadow Stack jamais activé, KASLR ~0 bit, stack canary TCB constant `0xDEAD_BEEF_CAFE_BABE`, SafeStack dead code, KASAN shadow map non empoisonnée.

7. **Capability tokens sont forgeables** : 24B `{object_id, rights, generation, type_tag}` sans MAC — Ring1 peut forger des wire-tokens.

8. **`sys_exo_ipc_create` permet l'escalade Ring1** : n'importe quel process peut devenir `CryptoServer` par nom.

9. **IPC shared memory sans cap** : `shm_map()` ne vérifie aucune capability.

10. **`sys_kill` sans cap** : n'importe quel process peut SIGKILL n'importe quel autre.

### Points forts (à préserver)

- ✅ Chaîne de boot UEFI → exo-boot → kernel.elf (Ed25519 `verify_strict` + SHA-512 + fail-closed + compile-time guards)
- ✅ Aucune CVE connue dans les dépendances cargo
- ✅ BLAKE3, Ed25519, Argon2id avec paramètres conformes au mandat
- ✅ AEAD kernel (XChaCha20-Poly1305) avec encrypt-then-MAC, AAD length-prefixed
- ✅ RNG kernel multi-source (RDSEED×4 + RDRAND×6 + jitter + stack, BLAKE3-conditioned)
- ✅ `subtle::ct_eq` pour les comparaisons de tags crypto
- ✅ Capability table per-process, O(1) verify, `inherit_from_masked` pour fork moindre privilège
- ✅ Zero-trust `verify_syscall` est câblé au dispatch
- ✅ `audit_syscall_entry/exit` sont câblés (GAP-02 résolu)
- ✅ IBPB context-switch (B-01 résolu), IBRS syscall entry (B-02 résolu)
- ✅ `audit_syscall_entry/exit` sont câblés (GAP-02 résolu)
- ✅ DAG IPC policy (51 paires, A-01 DAG résolu via `check_direct_ipc`)
- ✅ Compile-time guard rejetant clés Ed25519 de test
- ✅ PKS revoke-all sur Phoenix handoff
- ✅ ExoNMI watchdog câblé dans IRQ timer
- ✅ ExoArgos PMC snapshot hooké sur context_switch_out

### Recommandation finale

**Ne pas déployer ExoOS v0.2.0 en production sans avoir résolu les 30 actions P0 listées en section 6.** L'audit identifie ~50 vulnérabilités critiques qui permettent à un attaquant Ring3 (POSIX app) ou Ring1 (server compromis) d'escalader en Ring0, d'exécuter du code non signé, de DMA vers la RAM, de keylogger, de SIGKILL arbitrairement, de forger des capabilities, et de survivre à un switch ExoPhoenix indétecté.

La **fondation cryptographique est solide** — il faut maintenant **câbler l'enforcement**. La majorité des findings sont des problèmes de wiring (code exists but is not called) plutôt que des bugs cryptographiques. Une passe de remédiation disciplinée peut transformer ExoOS en un OS réellement sécurisé.

---

## 8. Annexe — Inventaire des rapports de sous-audit

Tous les rapports détaillés (avec snippets verbatim, scénarios d'attaque, et fixes recommandés pour chaque finding) sont disponibles dans `/home/z/my-project/audit_memory/` :

| Fichier | Sujet | Lignes |
|---|---|---|
| `01_architecture.md` | Synthèse architecture | 62 |
| `02_boot_chain.md` | Chaîne de boot | 778 |
| `03a_kernel_crypto.md` | Kernel crypto & intégrité | 566 |
| `03b_kernel_security_policy.md` | Kernel security policy | 834 |
| `04_kernel_core.md` | Kernel core (memory/ipc/syscall/scheduler) | 907 |
| `05_exoshield.md` | ExoShield NGAV | 1025 |
| `06_crypto_server.md` | Crypto server | 576 |
| `07_other_servers.md` | Autres servers | 662 |
| `08_drivers_fs.md` | Drivers & filesystems | 1207 |
| `09_userspace.md` | Userspace + loader + tools + build | 1590 |
| `09b_verification.md` | Vérification des 25 findings critiques | 1197 |
| **Total** | | **9 404 lignes** |
