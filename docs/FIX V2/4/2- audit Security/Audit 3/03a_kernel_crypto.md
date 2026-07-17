# 03a — Audit profond : KERNEL CRYPTO + INTEGRITY (Task 3a)

**Auditeur** : sub-agent Task 3a  
**Périmètre** : `kernel/src/security/crypto/*`, `kernel/src/security/integrity_check/*`, `kernel/src/security/{exoseal,exoveil,exoledger,exokairos,exoargos,exonmi,exocage,shield_feed}.rs`  
**Méthode** : lecture ligne par ligne, cross-check des callers via grep, vérification des contrats de la mandate crypto (01_architecture.md §"Crypto mandate").  
**Verdict synthétique** : ❌ **NON-CONFORME** — la plupart des primitives bas-niveau sont correctes (BLAKE3, Ed25519, AES-GCM, XChaCha20), MAIS l'orchestration de l'intégrité est **gravement défaillante** : `verify_boot_attestation()` n'est JAMAIS appelée, `verify_module_signature()` n'est JAMAIS appelée par `do_execve`, et la chaîne de confiance secure-boot est **totalement coupée** du boot path. Le runtime integrity check est en mode OBSERVE (log-only, pas de panic). Un attaquant qui obtient kernel R/W peut trifouiller .text/.rodata, exécuter du code non signé, et tronquer le ledger sans détection.

---

## 1. Inventaire des fichiers audités

| # | Fichier | Lignes | Statut lecture |
|---|---------|-------:|---------------|
| 1 | `crypto/mod.rs` | 90 | ✅ complet |
| 2 | `crypto/aes_gcm.rs` | 866 | ✅ complet |
| 3 | `crypto/xchacha20_poly1305.rs` | 294 | ✅ complet |
| 4 | `crypto/blake3.rs` | 257 | ✅ complet |
| 5 | `crypto/ed25519.rs` | 184 | ✅ complet |
| 6 | `crypto/x25519.rs` | 141 | ✅ complet |
| 7 | `crypto/kdf.rs` | 253 | ✅ complet |
| 8 | `crypto/rng.rs` | 530 | ✅ complet |
| 9 | `integrity_check/mod.rs` | 73 | ✅ complet |
| 10 | `integrity_check/code_signing.rs` | 340 | ✅ complet |
| 11 | `integrity_check/runtime_check.rs` | 251 | ✅ complet |
| 12 | `integrity_check/secure_boot.rs` | 261 | ✅ complet |
| 13 | `exoseal.rs` | 252 | ✅ complet |
| 14 | `exoveil.rs` | 603 | ✅ complet |
| 15 | `exoledger.rs` | 776 | ✅ complet |
| 16 | `exokairos.rs` | 920 | ✅ complet |
| 17 | `exoargos.rs` | 595 | ✅ complet |
| 18 | `exonmi.rs` | 552 | ✅ complet |
| 19 | `exocage.rs` | 636 | ✅ complet |
| 20 | `shield_feed.rs` | 231 | ✅ complet |
| | **TOTAL** | **8105** | |

Cross-check callers via `grep` : `do_execve` (`process/lifecycle/exec.rs:280-292`), `kernel_main` (`main.rs:323-434`), `security_init` (`security/mod.rs:322-430`), `arch/x86_64/exceptions.rs:615,1258`, `arch/x86_64/idt.rs:640`, `process/core/tcb.rs:478,508`, `syscall/table.rs:1565,3831,4033`.

---

## 2. Table de conformité des primitives crypto (vs mandate §"Crypto mandate")

| Primitive | Mandate | Implémentation | Verdict |
|-----------|---------|----------------|---------|
| **AES-256-GCM** | GHASH CT, `ct_eq` tag, verify-before-decrypt, nonce unique | GHASH masqué constant-time ✅ ; tag via `subtle::ConstantTimeEq` ✅ ; verify-then-decrypt ✅ ; nonce = paramètre caller, **AUCUNE API counter/HKDF** ⚠️ ; **chemin software AES `aes_xtime` a branche data-dépendante** ❌ ; asm AES-NI déclare `preserves_flags` alors que `add rax,16` clobber flags ❌ | ⚠️ PARTIAL |
| **XChaCha20-Poly1305** | EtM, MAC key séparée, AAD length-prefixed, nonce unique | EtM ✅ ; MAC key dérivée via `blake3_derive_key(MAC_CONTEXT, key‖nonce)` ✅ ; AAD length-prefixed ✅ ; **mais c'est BLAKE3-MAC pas Poly1305** (le nom du module est trompeur — commentaire l'admet ligne 6-8) ⚠️ ; nonce caller ⚠️ | ✅ COMPLIANT (avec reserve nominale) |
| **BLAKE3** | `constant_time_eq`, `derive_key` | `subtle::Choice`+`ct_eq` ✅ ; `blake3::derive_key` avec context ASCII ✅ ; fallback `"ExoOS-KDF-Blake3"` si non-UTF8 ⚠️ (perte de domain separation) | ✅ COMPLIANT |
| **Ed25519** | `verify_strict`, reject low-order, pk len validation | `vk.verify_strict` ✅ ; `VerifyingKey::from_bytes` valide pk ✅ ; cofactor handling via dalek v2 ✅ | ✅ COMPLIANT |
| **X25519** | RFC 7748 §6 (reject all-zero + weak-order) | All-zero check ✅ ; **weak-order subgroup check ABSENT** ❌ (seul le point identité est rejeté) | ❌ NON-COMPLIANT |
| **HKDF-Blake3** (toutes rotations) | Remplace XOR+FNV | **`kdf.rs` utilise HKDF-SHA256/SHA512, pas HKDF-BLAKE3** ❌ ; `blake3_kdf` existe pour usages kernel internes ✅ ; aucun XOR+FNV legacy ✅ | ⚠️ PARTIAL |
| **RNG** | RDSEED×4 + RDRAND×6 + jitter TSC + SP, BLAKE3-conditioned, reseed 4096, zeroization, `hw_seeded` | Toutes sources ✅ ; BLAKE3-conditioned ✅ ; reseed 4096 blocs ✅ ; `hw_seeded` flag ✅ ; zeroization pool+seed ✅ ; **`KernelRng`/`ChaCha20Csprng` n'implémente PAS `Drop`** (clés pas zerisées si move) ❌ ; **nonce dérivé du seed via XOR+wrapping ad-hoc** (pas HKDF) ❌ ; **`hw_seeded` jamais enforced pour clés long-terme** ⚠️ | ⚠️ PARTIAL |
| **ChaCha20 maison** (RFC 8439 KAT) | Conforme RFC 8439 | KAT RFC 8439 §2.3.2 testé ✅ ; hchacha20 correct ✅ | ✅ COMPLIANT |
| **SHA-512** (hash corps kernel signature) | Usage pour signatures | `sha2::Sha512` utilisé dans `ed25519.rs` et `kdf.rs` ✅ | ✅ COMPLIANT |

---

## 3. Table des findings (triés par sévérité)

| ID | Severity | File:line | Résumé |
|----|----------|-----------|--------|
| INTEG-001 | **CRITICAL** | `integrity_check/secure_boot.rs:174` + `main.rs:323` | `verify_boot_attestation()` n'est JAMAIS appelée depuis `kernel_main`/`security_init`. La chaîne de confiance secure-boot est **complètement morte**. |
| INTEG-002 | **CRITICAL** | `process/lifecycle/exec.rs:275-292` + `code_signing.rs:194` | `verify_module_signature()` n'est PAS appelée par `do_execve`. C-01 TOUJOURS OUVERT. Le check présent est circulaire (`is_chain_verified() → check_chain_of_trust()`) et **jamais bloquant** même avec `strict_exec_signatures`. |
| INTEG-003 | **CRITICAL** | `exoseal.rs:155-198` | `exoseal_boot_phase0()` / `exoseal_boot_complete()` **ne haltent PAS** le boot si `verify_p0_fixes()` échoue — elles `return` early après avoir écrit `SSR_HANDOFF_FLAG=1`. Aucun phase0 hash kernel+Ring1 (contrairement à la spec). Un attaquant peut skipper phase0. |
| INTEG-004 | **CRITICAL** | `exokairos.rs:714-719` + `security/mod.rs:382-396` | `get_kernel_secret()` retourne `[0u8;32]` si `init_kernel_secret` pas encore appelée → **toute cap créée avant step 10 a un MAC à clé zéro**, forgeable par Ring1. |
| CRYPTO-001 | **HIGH** | `crypto/x25519.rs:94-98` | RFC 7748 §6 : seul le point identité (all-zero) est rejeté. Les 4 autres weak-order points (small-subgroup) ne sont pas filtrés → **twist/small-subgroup attack** sur X25519. |
| CRYPTO-002 | **HIGH** | `crypto/aes_gcm.rs:202-208` | `aes_xtime()` a une branche data-dépendante `if x & 0x80 != 0` dans le chemin software AES → **timing side-channel** sur MixColumns. Le chemin AES-NI est constant-time, mais le fallback soft est vulnérable. |
| CRYPTO-003 | **HIGH** | `crypto/aes_gcm.rs:303-400` | Bloc asm AES-NI déclare `options(preserves_flags)` mais `add rax,16` clobber flags → **miscompilation risk** par LLVM (le compilateur peut supposer flags préservés). |
| INTEG-005 | **HIGH** | `integrity_check/secure_boot.rs:214-216` | `disable_enforcement()` est `pub` et **non unsafe**. N'importe quel code kernel (ou attaquant avec kernel R/W) peut appeler `disable_enforcement()` pour désactiver secure-boot sans barrière. |
| INTEG-006 | **HIGH** | `integrity_check/runtime_check.rs:212-231` + `integrity_check/mod.rs:44-58` | Le `integrity_monitor_loop` kthread appelle `security_periodic_check_observe()` en mode **OBSERVE (log-only, jamais panic)**. Altération .text/.rodata → log ExoLedger, **pas de halt**. |
| INTEG-007 | **HIGH** | `integrity_check/runtime_check.rs:56-67` | Le hash de référence `.text/.rodata` est stocké en clair dans `static Mutex<RuntimeIntegrityState>`. Un attaquant avec kernel R/W peut **réécrire le hash de référence** avant de modifier .text → détection bypassée. |
| INTEG-008 | **HIGH** | `exoledger.rs:292-301,540-565` | ExoLedger est en **BSS statique** (pas SSR.LOG_AUDIT comme la spec l'exige). Chaîne BLAKE3 sans clé secrète → un attaquant kernel R/W peut **réécrire entrées + recomputer hashes** (BLAKE3 public). `verify_p0_integrity` n'est appelée par personne automatiquement. |
| INTEG-009 | **HIGH** | `exonmi.rs:376-389` | `arm_watchdog(0)` est `pub fn` (pas unsafe) — **un attaquant kernel peut désarmer le watchdog** avec un simple appel. Aucune protection PKS ou capabilities sur cette fonction. |
| INTEG-010 | **HIGH** | `exoveil.rs:261-277,292-304` | `revoke_domain`/`restore_domain` sont `pub unsafe` — tout code kernel Ring 0 (ou attaquant kernel R/W) peut **restaurer Credentials/Caps/TcbHot** à volonté. PKS n'isole que vs Ring1/3, pas vs kernel attacker. |
| CRYPTO-004 | **MEDIUM** | `crypto/kdf.rs:82-108` | Mandate dit "HKDF-Blake3 pour TOUTES les rotations". L'implémentation utilise **HKDF-SHA256** pour `derive_subkey`, `derive_enc_mac_keys`, `derive_ipc_channel_key`, etc. `blake3_kdf` existe mais n'est pas utilisé pour les clés IPC/FS. |
| CRYPTO-005 | **MEDIUM** | `crypto/rng.rs:288-299` | Nonce ChaCha20 dérivé du seed via `wrapping_add` ad-hoc (`entropy[i] + entropy[i+20] + entropy[(i+7)%32]`). Key et nonce **corrélés** (dérivés du même 32-byte seed sans KDF). Doit être `blake3_derive_key(b"rng-key", seed)` + `blake3_derive_key(b"rng-nonce", seed)`. |
| CRYPTO-006 | **MEDIUM** | `crypto/rng.rs:260-350` (pas de `Drop`) | `ChaCha20Csprng`/`KernelRng` n'implémentent pas `Drop` → **clé 32B pas zerisée** si la struct est déplacée/libérée. La mandate dit "Zeroization on drop". |
| CRYPTO-007 | **MEDIUM** | `crypto/blake3.rs:193-202` | `constant_time_eq` short-circuite sur `if a.len() != b.len()`. Pas un problème pour des hashes 32B/tags 16B (longueurs fixes), mais la fonction est générique — fuite de timing sur la longueur. |
| INTEG-011 | **MEDIUM** | `exokairos.rs:693-719` | `KERNEL_SECRET` est en `static Once<[u8;32]>` en BSS, **pas en PKS Credentials** (commentaire l'admet : "sera en PKS Credentials en Phase 3.2"). Attaquant kernel R/W peut lire le secret et forger des deadlines. |
| INTEG-012 | **MEDIUM** | `exokairos.rs:737-758` | `register_ttl_for_cap` est best-effort : si `monotonic_ns()==0` (early boot), **aucune deadline n'est enregistrée** → le cap n'a pas d'expiration temporelle. Les caps créées avant calibration TSC sont non-temporelles. |
| INTEG-013 | **MEDIUM** | `exoseal.rs:38-102` | `verify_p0_fixes()` ne vérifie que IOMMU/PKS/CET **configurés**, **PAS le hash kernel+Ring1**. La spec dit "ExoSeal phase0 (BLAKE3 hash kernel + Ring1)" — cette mesure n'existe pas dans le code. |
| INTEG-014 | **MEDIUM** | `exoledger.rs:606-640` | `verify_ring_integrity` **tolère** les chaînes cassées (`break` au lieu de `Err`) sous prétexte d'"overflow circulaire attendu". Un attaquant peut exploiter ce comportement pour **tronquer** le ring buffer sans déclencher d'alerte. |
| INTEG-015 | **MEDIUM** | `exoargos.rs:476-517` | `check_anomaly()` détecte l'anomalie mais **ne pousse PAS l'alerte vers `shield_feed`** (TIER 3.1 partiellement ouvert pour PMC). Seul un compteur `ANOMALY_COUNT` est incrémenté. |
| CRYPTO-008 | **LOW** | `crypto/aes_gcm.rs:597-677` | `aes_gcm_seal`/`aes_gcm_open` zerisent `h_block` sur failure open, mais **pas les `round_keys`** (240B dans `Aes256GcmCipher` sur la stack). Hygiène key material incomplète. |
| CRYPTO-009 | **LOW** | `crypto/blake3.rs:57-60,175` | `new_derive_key` et `blake3_derive_key` fallback sur `"ExoOS-KDF-Blake3"` si contexte non-UTF8. Perte silencieuse de domain separation si caller passe contexte binaire. |
| CRYPTO-010 | **LOW** | `crypto/aes_gcm.rs:435-444` | `encrypt_block` dispatch `if self.has_aesni` est constant-time (set une fois au `new`), mais l'info `has_aesni` est dans la struct sur la stack — pas un timing leak mais info leak. |
| INTEG-016 | **LOW** | `integrity_check/secure_boot.rs:126` + `exoseal.rs:24` | `SECBOOT_ENFORCE`/`NIC_POLICY_REQUIRED` etc. sont `AtomicBool` non protégés par PKS. Attaquant kernel R/W peut flip ces flags. |
| INTEG-017 | **LOW** | `exonmi.rs:462-484` | `tick()` spin-loop infinie après `HANDOFF_FREEZE_REQ`. Si ExoPhoenix n'est pas présent (test, config dégradée), le core est bloqué à jamais sans diagnostic. |
| INTEG-018 | **LOW** | `exocage.rs:340-343` | WRSSQ encodé en `.byte 0xF3, 0x48, 0x0F, 0x01, 0x3E` — correct, mais l'absence de `options(nomem)` indique au compilateur que l'asm peut accéder mémoire (correct), mais `preserves_flags` n'est pas spécifié — OK car WRSSQ ne modifie pas flags. |
| INTEG-019 | **LOW** | `exoveil.rs:514-535` | `save_pkrs_to_tcb`/`restore_pkrs_from_tcb` sont `pub unsafe` sans vérifier que le TCB est valide/non-préempté. Si appelée sur un TCB distant en cours d'exécution sur un autre CPU → race sur `IA32_PKRS`. |

---

## 4. Détails des findings (CRITICAL et HIGH)

### INTEG-001 — `verify_boot_attestation()` JAMAIS appelée (CRITICAL)
**File:line** : `kernel/src/security/integrity_check/secure_boot.rs:174` ; absence de caller confirmée par `grep verify_boot_attestation` (uniquement def + re-export).
```rust
pub fn verify_boot_attestation(attestation: &BootAttestation) -> Result<(), SecureBootError> {
    if !attestation.check_magic() {
        return Err(SecureBootError::InvalidAttestation);
    }
    let signed_data = attestation.signed_data();
    ed25519_verify(&BOOTLOADER_PUBLIC_KEY, &signed_data, &attestation.signature)
        .map_err(|_| SecureBootError::InvalidBootloaderSignature)?;
    // ...
    CHAIN_VERIFIED.store(true, Ordering::Release);
    Ok(())
}
```
**Pourquoi vulnérabilité** : `CHAIN_VERIFIED` reste `false` pour toute la vie du kernel. `check_chain_of_trust()` retourne donc `Err(ChainNotVerified)` indéfiniment. `kernel_main` (`main.rs:323-434`) appelle `arch_boot_init` puis `kernel_init` puis `userspace_boot` — aucun de ces chemins ne parse la `BootAttestation` passée par exo-boot, ni n'appelle `verify_boot_attestation`. **L'attestation bootloader peut être absente, mal signée, ou altérée — le kernel n'en sait rien.**
**Scénario d'attaque** : un attaquant remplace le kernel sur disque, supprime l'attestation, ou fournit une attestation avec signature invalide. Le kernel boot normalement. Toute la chaîne de confiance UEFI→exo-boot→kernel est **cosmétique**.
**Fix recommandé** :
1. Dans `kernel_main` (ou `security_init` step 0), parser `boot_info.attestation` et appeler `verify_boot_attestation`.
2. En cas d'`Err`, `panic!("Secure boot attestation failed: {:?}", e)` — fail-closed.
3. Ajouter test d'intégration qui vérifie qu'un kernel sans appel à `verify_boot_attestation` ne compile pas (const assert sur un symbole utilisé).

---

### INTEG-002 — `verify_module_signature()` pas appelée par `do_execve` (CRITICAL, C-01 TOUJOURS OUVERT)
**File:line** : `kernel/src/process/lifecycle/exec.rs:267-293` + `kernel/src/security/integrity_check/code_signing.rs:194`.
```rust
// exec.rs:267-293
// FIX-EXEC-SIG (Security_Audit_Passe2 §C-01) : vérification de la signature
// du module avant remplacement de l'espace d'adressage.
// ElfLoadResult ne fournit pas le ModuleHeader directement — la vérification
// se fait via is_chain_verified() qui confirme que la chaîne de confiance
// ExoSeal a bien validé ce binaire lors du chargement initial depuis ExoFS.
if crate::security::is_chain_verified() {                       // ← (1)
    if let Err(_e) = crate::security::check_chain_of_trust() {  // ← (2)
        #[cfg(not(feature = "strict_exec_signatures"))]
        { crate::arch::x86_64::terminal::debug_write(b"exec: WARNING unsigned binary executed\n"); }
        #[cfg(feature = "strict_exec_signatures")]
        { return Err(ExecError::SignatureVerificationFailed); }
    }
}
```
**Pourquoi vulnérabilité** :
- **(1)** `is_chain_verified()` retourne `CHAIN_VERIVED.load(Acquire)` qui est **false** tant que `verify_boot_attestation` n'a pas été appelée (cf. INTEG-001). Donc le bloc entier est **skip** dans tous les cas.
- **(2)** Même si `is_chain_verified()` était `true`, `check_chain_of_trust()` retourne `Ok(())` quand `CHAIN_VERIFIED` est true — le test est **circulaire** (`if A { if not A { … } }`).
- Le commentaire à la ligne 270 admet explicitement : *"ElfLoadResult ne fournit pas le ModuleHeader directement — la vérification se fait via is_chain_verified()"*. Ce n'est PAS une vérification de signature de binaire — c'est une vérification de flag global.
- `verify_module_signature()` (qui fait la vraie vérif Ed25519 + BLAKE3 par binaire) **n'est jamais appelée** par qui que ce soit (grep confirme : uniquement def + re-export + tests).
**Scénario d'attaque** : un attaquant dépose un binaire non signé sur le filesystem (via exploit FS, DMA, ou partition montée rw). `do_execve` l'exécute sans aucune vérification. Même avec `--features strict_exec_signatures`, le check est un no-op.
**Fix recommandé** :
1. `ElfLoader::load_elf` doit retourner le `ModuleHeader` (ou au moins le slice `&[u8]` du header).
2. `do_execve` doit appeler `verify_module_signature(&header, &code)` AVANT `load_elf` (ou après, mais avant le `replace_address_space`).
3. En cas d'`Err`, `return Err(ExecError::SignatureVerificationFailed)` — même sans feature flag (le feature flag ne devrait contrôler que les binaires kernel pré-signés obligatoires, pas la logique de vérification).
4. Le check `is_chain_verified() → check_chain_of_trust()` doit être supprimé (circulaire).

---

### INTEG-003 — `exoseal_boot_phase0()` ne halt pas le boot si Phase 0 fail (CRITICAL)
**File:line** : `kernel/src/security/exoseal.rs:155-198`.
```rust
pub unsafe fn exoseal_boot_phase0() {
    if EXOSEAL_PHASE0_DONE.swap(true, Ordering::AcqRel) { return; }
    configure_nic_iommu_policy();
    unsafe { exoveil::exoveil_init(); }
    let _ = unsafe { exocage::exocage_global_enable() };
    let _ = stage0::arm_apic_watchdog(BOOT_PHASE0_WATCHDOG_MS);
    if verify_p0_fixes().is_err() {
        return;   // ← return early, le boot continue !
    }
    exoledger::exo_ledger_append(exoledger::ActionTag::BootEvent { step: 0 });
}
```
Et dans `verify_p0_fixes()` (ligne 84-99) :
```rust
if let Err(error) = result {
    // ...
    unsafe { ssr::ssr_atomic(ssr::SSR_HANDOFF_FLAG).store(1, Ordering::Release); }
    return Err(error);
}
```
**Pourquoi vulnérabilité** :
- Sur échec Phase 0 (IOMMU NIC non verrouillé, CET désactivé, PKS domaines exposés), la fonction :
  1. Écrit `SSR_HANDOFF_FLAG = 1` (demande de handoff ExoPhoenix),
  2. **Retourne normalement** sans panic, sans halt, sans boucle infinie.
- `security_init` appelle simplement `exoseal_boot_phase0()` puis passe à l'étape suivante (`integrity_init`). Si ExoPhoenix n'est pas présent ou ne freeze pas le core à temps, **le kernel continue de booter dans un état non-durci** (PKS désactivé, CET off, IOMMU NIC non verrouillé).
- **AUCUN hash BLAKE3 kernel+Ring1 n'est calculé** dans Phase 0 (contrairement à la spec `01_architecture.md` ligne 24 : "ExoSeal phase0 (BLAKE3 hash kernel + Ring1)"). Le `verify_p0_fixes` ne vérifie que des flags de configuration, pas l'intégrité du code.
- `BOOT_SEAL_STATE::Verified` (mentionné dans le task description) n'existe pas dans le code — le seul signal est `SSR_HANDOFF_FLAG`.
**Scénario d'attaque** : un attaquant compromet l'IOMMU NIC ou désactive CET avant le boot (via hypervisor ou DMA attack). Phase 0 détecte le problème, écrit HANDOFF_FLAG=1, mais `security_init` continue. Si ExoPhoenix est absent ou delayed, le kernel finit de booter avec IOMMU NIC compromis.
**Fix recommandé** :
1. `verify_p0_fixes()` doit `panic!("Phase 0 verification failed: {:?}`, error)` au lieu de `return Err`.
2. Ajouter une vérification de hash BLAKE3(kernel.text + kernel.rodata + Ring1 servers) au démarrage, avec le hash de référence embarqué dans le kernel.
3. `exoseal_boot_complete` doit pareillement panic sur `verify_p0_fixes().is_err()`.
4. Ajouter un watchdog qui halt le boot si `SSR_HANDOFF_FLAG` est à 1 et qu'ExoPhoenix n'a pas répondu dans 500ms.

---

### INTEG-004 — `get_kernel_secret()` retourne `[0u8;32]` avant init → MAC forgeable (CRITICAL)
**File:line** : `kernel/src/security/exokairos.rs:714-719` + `kernel/src/security/mod.rs:382-396`.
```rust
// exokairos.rs:714
fn get_kernel_secret() -> [u8; 32] {
    let _guard = unsafe { exoveil::scoped_domain_access(PksDomain::Credentials, PksPermission::ReadOnly) };
    KERNEL_SECRET.get().copied().unwrap_or([0u8; 32])   // ← ZÉRO si pas init !
}
```
```rust
// security/mod.rs:382-396 (step 10 de security_init)
{
    let mut secret = [0u8; 32];
    if rng_fill(&mut secret).is_err() {
        // fallback TSC+kaslr_entropy+phys_base → BLAKE3
        // ...
        secret = blake3_hash(&fallback_material);
    }
    exokairos::init_kernel_secret(&secret);
}
```
**Pourquoi vulnérabilité** :
- `KERNEL_SECRET` est initialisé à l'étape 10 de `security_init`. Mais `capability::init_capability_subsystem()` (étape 2) peut créer des capabilities **avant** l'étape 10. Si ces caps sont des `TemporalCap`, leur `deadline_mac` est calculé avec `get_kernel_secret()` retournant `[0u8;32]`.
- **Conséquence** : tout Ring1 qui connaît l'algorithme (oid ‖ deadline_tsc → blake3_mac([0u8;32], …)) peut forger un `deadline_mac` valide pour n'importe quel (oid, deadline) — c'est-à-dire **créer une capability avec une deadline arbitraire** (par exemple `u64::MAX` = jamais expirante).
- De plus, le fallback si `rng_fill` échoue (ligne 386-393) utilise `blake3_hash(kaslr_entropy ‖ phys_base ‖ tsc ‖ …)` — si RDRAND/RDSEED ne sont pas disponibles (VM sans RDRAND, hypervisor restrictif), le secret est déterministe et prédictible par un attaquant qui connaît kaslr_entropy et phys_base (qui viennent du bootloader).
**Scénario d'attaque** :
1. Attaquant crée une cap IPC_SEND pendant la fenêtre steps 2-9.
2. La cap a un `deadline_mac` à clé zéro.
3. Après step 10, `verify()` recompute le MAC avec la vraie clé → `MacMismatch`.
4. **OU** pire : si l'attaquant contrôle le boot (pas de RDRAND), le `KERNEL_SECRET` est prédictible → il peut forger des caps avec deadline arbitraire.
**Fix recommandé** :
1. `init_kernel_secret` doit être appelée à l'**étape 0** de `security_init` (avant capability::init).
2. `get_kernel_secret` doit `panic!("KERNEL_SECRET not initialized")` au lieu de retourner `[0u8;32]`.
3. Vérifier `rng_hw_seeded()` avant d'accepter le secret ; si faux, soit retry, soit panic.
4. Migrer `KERNEL_SECRET` vers PKS Credentials dès maintenant (la "Phase 3.2" évoquée n'existe pas).

---

### CRYPTO-001 — X25519 : RFC 7748 §6 weak-order subgroup check absent (HIGH)
**File:line** : `kernel/src/security/crypto/x25519.rs:94-98`.
```rust
// Vérification contre low-order points (all-zeros = point neutre)
let is_zero = shared.iter().fold(0u8, |acc, &b| acc | b);
if is_zero == 0 {
    return Err(X25519Error::InvalidDhResult);
}
Ok(shared)
```
**Pourquoi vulnérabilité** : RFC 7748 §6 liste **5** points faibles à rejeter sur X25519 :
- `0x0000…0000` (identité) — ✅ couvert
- `0x0000…0001`, `0x0000…0058`, `0x0000…00DF`, `0x00FF…FFFF` (points d'ordre 2, 4, 8 sur le twist) — ❌ **pas couverts**

Avec un de ces points, un attaquant (serveur X25519 malicieux) peut forcer le shared secret à être un point de petit ordre. Le résultat n'est PAS all-zéros, mais révèle `scalar mod 8` — soit 3 bits de la clé privée par échange. En répétant avec 4 points différents, **l'attaquant récupère la clé privée** (small-subgroup attack, [CVE-2017-8932-style](https://eprint.iacr.org/2017/255.pdf)).
**Scénario d'attaque** : un client ExoOS établit un canal IPC chiffré avec un "server" malicieux qui envoie un point d'ordre 8. Le client calcule `shared = X25519(my_priv, their_pub)` qui est non-zero → accepté. L'attaquant déduit 3 bits de `my_priv`. Répète avec d'autres points faibles → récupère toute la clé.
**Fix recommandé** : implémenter la liste de 5 points faibles comme dans [RFC 7748 §6](https://datatracker.ietf.org/doc/html/rfc7748#section-6) :
```rust
const FORBIDDEN: [[u8; 32]; 5] = [
    [0; 32],                                    // 0
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1], // 1
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x58], // ordre 4
    [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0xdf], // ordre 8 (twist)
    [0xff; 32], // u-coord max
];
// Constant-time check against all 5
```

---

### CRYPTO-002 — AES-GCM software `aes_xtime()` : branche data-dépendante (HIGH)
**File:line** : `kernel/src/security/crypto/aes_gcm.rs:201-208`.
```rust
#[inline]
fn aes_xtime(x: u8) -> u8 {
    if x & 0x80 != 0 {       // ← branche sur bit de l'état AES (data-dependent)
        (x << 1) ^ 0x1B
    } else {
        x << 1
    }
}
```
**Pourquoi vulnérabilité** : `aes_xtime` est appelé par `aes_mul2`/`aes_mul3` → `aes_mix_single_column` → `aes_mix_columns` → `aes256_encrypt_block_sw`. Dans AES-GCM, le bloc d'entrée du AES est :
- `J0 = IV ‖ 0x00000001` (pour calculer `AES_K(J0)` → tag),
- Compteurs successifs `inc32(J0)` (pour le keystream CTR).
Si l'attaquant contrôle l'IV (protocole avec nonce user-supplied), il contrôle partiellement l'entrée AES. Le timing de `aes_xtime` dépend du bit 7 de l'état interne après `SubBytes`+`ShiftRows`, qui dépend lui-même de l'entrée AES + la clé. **Cache-timing + FLUSH+RELOAD** permettrait de reconstruire la clé AES en observant le timing de MixColumns sur plusieurs milliers d'invocations. (Voir [Osvik-Shamir-Tromer 2006](https://eprint.iacr.org/2005/271.pdf).)
**Mitigation actuelle** : sur CPU avec AES-NI, le chemin hardware est utilisé (`aes256_encrypt_block_ni`) qui est constant-time. Le problème n'existe que sur CPUs sans AES-NI (vieilles VMs, QEMU sans `-cpu host`).
**Fix recommandé** :
```rust
#[inline]
fn aes_xtime(x: u8) -> u8 {
    let mask = ((x >> 7) as u8).wrapping_sub(1); // 0xFF si bit7=0, 0x00 si bit7=1
    (x << 1) ^ (0x1B & !mask)   // wait — inverse: 0x1B & mask si bit7=1
    // Correct: 0x1B & (0u8.wrapping_sub(x >> 7)) — masque = 0xFF si bit7=1
}
// i.e. let m = 0u8.wrapping_sub(x >> 7); (x << 1) ^ (0x1B & m)
```

---

### CRYPTO-003 — AES-NI asm : `preserves_flags` incorrect (HIGH)
**File:line** : `kernel/src/security/crypto/aes_gcm.rs:303-400`.
```rust
core::arch::asm!(
    "sub rsp, 32",
    // ...
    "lea rax, [rsi + 16]",
    // 13 AESENC rounds, each followed by:
    "add rax, 16",   // ← clobber flags !
    // ...
    "add rsp, 32",
    in("rdi") block,
    in("rsi") round_keys,
    out("rax") _,
    options(preserves_flags),  // ← INCORRECT, `add` clobber flags
);
```
**Pourquoi vulnérabilité** : `preserves_flags` dit à LLVM que le bloc asm ne modifie pas les flags (CF/ZF/SF/OF/PF/AF). Or `add rax, 16` modifie tous ces flags. LLVM peut alors hoister/scheduler du code qui dépend des flags **autour** du bloc asm en supposant qu'ils sont préservés — menant à **miscompilation** (e.g., un `cmp` suivi d'un `jne` pourrait être déplacé à travers l'asm en supposant les flags intacts).
**Fix recommandé** : retirer `preserves_flags` (l'option par défaut "clobbers flags" est correcte).

---

### INTEG-005 — `disable_enforcement()` pub non-unsafe (HIGH)
**File:line** : `kernel/src/security/integrity_check/secure_boot.rs:213-216`.
```rust
/// Désactive l'enforcement du Secure Boot (mode debug uniquement).
/// **NE PAS utiliser en production.**
pub fn disable_enforcement() {
    SECBOOT_ENFORCE.store(false, Ordering::SeqCst);
}
```
**Pourquoi vulnérabilité** : `pub fn` (pas `unsafe`) — n'importe quel module kernel peut l'appeler sans SAFETY contract. Attaquant avec un seul bug kernel UAF/RW peut écrire `disable_enforcement();` pour désactiver secure-boot enforcement à runtime. Pas de gate par capability, pas de gate par PKS. Grep confirme qu'aucun caller légitime n'existe — la fonction est un **pied-de-biche** intentionnel.
**Fix recommandé** : soit supprimer la fonction (enforcement toujours ON en production), soit la déplacer derrière `#[cfg(feature = "debug_secure_boot_disable")]` + `unsafe` + un check que `SECURITY_READY` n'est pas encore true.

---

### INTEG-006 — Runtime integrity check en mode OBSERVE (HIGH)
**File:line** : `kernel/src/security/integrity_check/runtime_check.rs:212-231` + `kernel/src/security/integrity_check/mod.rs:44-58`.
```rust
// runtime_check.rs:212
pub fn security_periodic_check_observe() {
    if !INITIALIZED.load(Ordering::Acquire) { return; }
    if let Err(e) = check_kernel_integrity() {
        let code = match e { /* ... */ };
        // 0x494E_5445_4752_5459 = b"INTEGRTY" — tag custom d'audit intégrité.
        crate::security::exoledger::exo_ledger_append_p0(
            crate::security::exoledger::ActionTag::Custom {
                tag: 0x494E_5445_4752_5459,
                data: code,
            },
        );
    }
}
```
```rust
// mod.rs:44 — kthread moniteur
fn integrity_monitor_loop(_arg: usize) -> ! {
    loop {
        // ...
        if crate::security::is_security_ready() {
            security_periodic_check_observe();   // ← observe-only, jamais panic
        }
    }
}
```
**Pourquoi vulnérabilité** : la spec `01_architecture.md` ligne 14 dit "AES-GCM GHASH constant-time, ct_eq tag, verify-before-decrypt" — et la `RÈGLE RUNTIME-02` (commentaire runtime_check.rs:14) dit "**Une altération détectée → kernel_panic() IMMÉDIAT, pas de retry**". Mais le kthread moniteur appelle la version OBSERVE qui ne fait que logger. La version FATALE (`assert_kernel_integrity`) n'est appelée **nulle part** automatiquement — seulement `security_periodic_check()` (wrapper de `assert_kernel_integrity`) qui n'a aucun caller automatique.
Un attaquant qui patch .text (via DMA, JOP, ou exploit mémoire) reste indétecté en pratique : le log ExoLedger est lui-même dans une zone BSS falsifiable (cf. INTEG-008).
**Fix recommandé** :
1. Le kthread moniteur doit appeler `assert_kernel_integrity()` (qui panic) en production, pas `security_periodic_check_observe()`.
2. Derrière un feature flag `runtime_integrity_observe_only` pour les environnements de dev/debug.
3. En production (`--release` sans feature debug), le mode OBSERVE ne doit pas exister.

---

### INTEG-007 — Hash de référence .text/.rodata en clair (HIGH)
**File:line** : `kernel/src/security/integrity_check/runtime_check.rs:56-67,144-148`.
```rust
struct RuntimeIntegrityState {
    text_hash: [u8; 32],
    rodata_hash: [u8; 32],
    initialized: bool,
    // ...
}
static INTEGRITY_STATE: spin::Mutex<RuntimeIntegrityState> =
    spin::Mutex::new(RuntimeIntegrityState::new());
```
**Pourquoi vulnérabilité** : `text_hash`/`rodata_hash` sont stockés en clair dans une `static Mutex` en BSS kernel. Un attaquant avec kernel R/W peut :
1. Lire le hash actuel de .text,
2. Modifier .text (injecter son code),
3. Recalculer BLAKE3 du nouveau .text,
4. Écrire le nouveau hash dans `INTEGRITY_STATE.text_hash`,
5. `check_kernel_integrity()` retourne `Ok(())`.

La détection est **bypassée par construction**. PKS ne protège pas cette zone.
**Fix recommandé** :
1. Stocker les hashes de référence dans le domaine PKS Credentials (pkey=2) — `exoveil::scoped_domain_access(PksDomain::Credentials, ReadOnly)` pour les lire.
2. Idéalement, les hasher avec une clé kernel secrète (`blake3_mac(KERNEL_SECRET, hash)` — voir INTEG-004) pour empêcher la forge même avec kernel R/W.
3. Mieux : les signer avec une clé Ed25519 privée en ROM (jamais accessible au runtime).

---

### INTEG-008 — ExoLedger en BSS, chaîne BLAKE3 sans clé secrète (HIGH)
**File:line** : `kernel/src/security/exoledger.rs:292-301,540-565`.
```rust
// exoledger.rs:292 — PAS en SSR comme la spec l'exige
static mut P0_ZONE: [LedgerEntry; P0_ZONE_ENTRIES] = { /* ... */ };
static mut RING_BUFFER: [LedgerEntry; RING_BUFFER_ENTRIES] = { /* ... */ };

// exoledger.rs:540 — commentaire admet le gap
/// En Phase 3.1, les zones P0 et ring buffer sont en mémoire statique BSS.
/// En Phase 3.2+, elles seront mappées dans SSR.LOG_AUDIT (+0x8000) en
/// collaboration avec l'infrastructure ExoPhoenix SSR.
```
Et la fonction de hash (`exoledger.rs:244-254`) :
```rust
fn compute_hash(&self) -> [u8; 32] {
    let mut buf = [0u8; 104];
    // ... seq, tsc, actor_oid, action, prev_hash ...
    crate::security::crypto::blake3::blake3_hash(&buf)  // ← BLAKE3 public, pas keyed
}
```
**Pourquoi vulnérabilité** :
- Le hash est `BLAKE3(entry || prev_hash)` **sans clé secrète**. N'importe qui connaissant l'algorithme (public) peut recalculer un hash valide.
- La zone est en BSS, pas en SSR.LOG_AUDIT — aucune protection hardware (PKS, IOMMU, hypervisor).
- `verify_p0_integrity()` et `verify_ring_integrity()` existent mais ne sont **jamais appelées automatiquement** sur read. Seul Kernel B (ExoPhoenix) les appellerait — et encore, seulement s'il est présent.
- `LAST_HASH` est un `AtomicU8; 32]` en BSS — un attaquant peut le modifier pour forger une chaîne avec un nouveau hash de départ.
**Scénario d'attaque** : attaquant kernel R/W efface une entrée P0 compromettante (e.g., `BootSealViolation`), recale `P0_USED`, recalcule `prev_hash` chain — tout passe inaperçu.
**Fix recommandé** :
1. Migrer P0_ZONE et RING_BUFFER vers SSR.LOG_AUDIT (+0x8000) mappé RO pour kernel A (la spec l'exige).
2. Utiliser `blake3_mac(KERNEL_SECRET, entry || prev_hash)` au lieu de `blake3_hash` — la chaîne devient inforgeable sans le secret.
3. Appeler `verify_p0_integrity()` automatiquement avant chaque `read_p0_entry` et à chaque `security_periodic_check`.

---

### INTEG-009 — `arm_watchdog(0)` désarme le NMI watchdog (HIGH)
**File:line** : `kernel/src/security/exonmi.rs:376-389`.
```rust
pub fn arm_watchdog(timeout_ms: u64) {       // ← pub fn, pas unsafe !
    if timeout_ms == 0 {
        // Disarm the watchdog
        WATCHDOG_ARMED.store(false, Ordering::Release);
        CONFIGURED_TIMEOUT_MS.store(0, Ordering::Release);
        CACHED_INITIAL_COUNT.store(0, Ordering::Release);
        if local_apic::lapic_timer_owner() == LapicTimerOwner::ExoNmiWatchdog {
            unsafe {
                lapic_write32(LAPIC_LVT_TIMER, LVT_TIMER_MASKED | LVT_TIMER_ONESHOT);
            }
        }
        return;
    }
    // ...
}
```
**Pourquoi vulnérabilité** : `pub fn` sans unsafe, sans capability check, sans PKS gate. Un attaquant avec un seul bug kernel peut appeler `arm_watchdog(0)` pour **désarmer silencieusement le watchdog NMI**. Ensuite, il peut geler le scheduler (spinlock, deadlock) sans déclencher le HANDOFF ExoPhoenix — DoS persistant indétecté.
La fonction est également accessible via `security::arm_watchdog` (re-export mod.rs:287).
**Fix recommandé** :
1. Rendre `arm_watchdog` `unsafe` + exiger une `CapToken` avec `Rights::WATCHDOG_ADMIN` (à créer).
2. Refuser `timeout_ms == 0` après `SECURITY_READY.store(true)` (le watchdog ne peut être désarmé qu'avant la fin du boot).
3. Logger toute tentative de disarm dans ExoLedger P0.

---

### INTEG-010 — `restore_domain`/`revoke_domain` pub unsafe sans capability (HIGH)
**File:line** : `kernel/src/security/exoveil.rs:261-277,292-304`.
```rust
// SAFETY: opération bas-niveau validée — voir documentation du bloc.
pub unsafe fn revoke_domain(domain: PksDomain) {
    if !PKS_AVAILABLE.load(Ordering::Acquire) { return; }
    // ...
}

// SAFETY: opération bas-niveau validée — voir documentation du bloc.
pub unsafe fn restore_domain(domain: PksDomain) {
    if !PKS_AVAILABLE.load(Ordering::Acquire) { return; }
    // ...
}
```
**Pourquoi vulnérabilité** : `pub unsafe` — n'importe quel code kernel en Ring 0 peut appeler `restore_domain(PksDomain::Credentials)` pour ré-activer l'accès aux clés crypto sans passer par `crypto_server`. PKS est conçu pour isoler les domaines entre Ring 0 (kernel) et Ring 1/3, **PAS entre différents modules kernel**. Le commentaire `RÈGLE EXOVEIL-01` dit "révocation dynamique réactive DÉSACTIVÉE en v1.0" — mais la fonction reste callable.
**Scénario d'attaque** : attaquant compromet un driver kernel via bug UAF. Il appelle `restore_domain(PksDomain::Credentials)` → accède aux clés crypto → extrait `KERNEL_SECRET` → forge des capabilities à volonté.
**Fix recommandé** :
1. Renommer en `restore_domain_unchecked` et fournir un wrapper `restore_domain_checked(domain, cap: CapToken)` qui exige une cap `Rights::PKS_ADMIN`.
2. Vérifier `domain != PksDomain::Default` (Default ne doit jamais être révoqué/restauré manuellement).
3. Logger toute opération dans ExoLedger P0 avec `actor_oid`.

---

## 5. Détails des findings MEDIUM/LOW (résumés)

### CRYPTO-004 (MEDIUM) — KDF utilise HKDF-SHA256, pas HKDF-BLAKE3
`kdf.rs:82-108` — `Hkdf::<Sha256>::extract` et `Hkdf::<Sha512>::extract`. Mandate `01_architecture.md:17` dit "HKDF-Blake3 (toutes rotations, remplace XOR+FNV)". `blake3_kdf` existe mais n'est pas utilisé pour `derive_ipc_channel_key`, `derive_fs_block_key`, etc. **Fix** : remplacer `Hkdf::<Sha256>` par construction HKDF-BLAKE3 (extract = `blake3_keyed_hash(salt, ikm)`, expand = `blake3_derive_key("hkdf-expand", prk ‖ info ‖ counter)`).

### CRYPTO-005 (MEDIUM) — RNG : nonce ChaCha20 dérivé ad-hoc du seed
`rng.rs:288-299` — `self.nonce[i] = entropy[i].wrapping_add(entropy[i + 20]).wrapping_add(entropy[(i + 7) % 32])`. Key et nonce **corrélés** (dérivés du même 32-byte seed sans KDF). **Fix** : `blake3_derive_key(b"ExoOS-RNG-key", entropy, &mut self.key)` + `blake3_derive_key(b"ExoOS-RNG-nonce", entropy, &mut self.nonce)`.

### CRYPTO-006 (MEDIUM) — `KernelRng`/`ChaCha20Csprng` pas de `Drop`
`rng.rs:260-350` — la `struct ChaCha20Csprng { key: [u8;32], … }` n'implémente pas `Drop`. La mandate dit "Zeroization on drop". Bien que `KernelRng` soit `static`, le pattern `Drop` est important pour les futures instances (per-CPU RNG, RNG éphémères). **Fix** : `impl Drop for ChaCha20Csprng { fn drop(&mut self) { for b in self.key.iter_mut() { unsafe { core::ptr::write_volatile(b, 0) } } /* idem nonce */ } }`.

### CRYPTO-007 (MEDIUM) — `constant_time_eq` short-circuite sur longueur
`blake3.rs:193-202` — `if a.len() != b.len() { return false; }`. Pour des hashes/tags à longueur fixe, sans impact. Mais la fonction est générique `&[u8]`. **Fix** : retourner `false` sans early-return, ou borner l'itération au max des deux longueurs avec un mask.

### INTEG-011 (MEDIUM) — `KERNEL_SECRET` en BSS, pas en PKS
`exokairos.rs:695` — `static KERNEL_SECRET: Once<[u8; 32]> = Once::new();`. Commentaire ligne 693 : "sera en PKS Credentials en Phase 3.2". La Phase 3.2 n'existe pas. **Fix** : allouer `KERNEL_SECRET` dans une page marquée pkey=2 (Credentials), accéder uniquement via `scoped_domain_access`.

### INTEG-012 (MEDIUM) — `register_ttl_for_cap` best-effort
`exokairos.rs:737-758` — si `monotonic_ns() == 0` (early boot), `return` sans enregistrer la deadline. La cap est créée **sans expiration temporelle**. **Fix** : soit refuser la création de cap avant calibration TSC, soit utiliser une deadline relative (`deadline = now_ns + ttl` calculée lors du premier `verify`).

### INTEG-013 (MEDIUM) — Phase 0 ne hash pas kernel+Ring1
`exoseal.rs:38-102` — `validate_phase0_state` vérifie uniquement flags IOMMU/PKS/CET. Aucun hash BLAKE3 du code kernel ou des serveurs Ring1 n'est calculé/vérifié. Spéc `01_architecture.md:24` : "ExoSeal phase0 (BLAKE3 hash kernel + Ring1)". **Fix** : ajouter `let kernel_hash = blake3_hash(text_section()); blake3_hash(rodata_section()); if kernel_hash != EMBEDDED_KERNEL_HASH { panic!("kernel tampered at phase0"); }`.

### INTEG-014 (MEDIUM) — `verify_ring_integrity` tolère les chaînes cassées
`exoledger.rs:606-640` — `break` au lieu de `Err` quand `entry.prev_hash != prev_hash && valid > 0`. Commentaire : "La chaîne peut être rompue par l'overflow circulaire — Ce n'est pas une erreur — c'est attendu". Un attaquant peut exploiter cette tolérance pour **tronquer** le ring en écrivant une fausse entrée de continuation. **Fix** : maintenir un compteur séparé `WRAP_COUNT` et vérifier la chaîne modulo les wraps ; tout break non-explicite doit être `Err`.

### INTEG-015 (MEDIUM) — ExoArgos ne pousse pas les alertes vers shield_feed
`exoargos.rs:476-517` — `check_anomaly()` incrémente `ANOMALY_COUNT` et `return true/false`. **Aucun `shield_feed::push_event`**. TIER 3.1 (kernel→shield feed) est partiellement ouvert : capability/IPC/syscall/exec events sont poussés (6 sites), mais **PMC anomalies ne le sont pas**. **Fix** : dans `check_anomaly()`, si `discordance > DECEPTION_THRESHOLD`, appeler `shield_feed::push_event(0, event_type::MEMORY, severity::HIGH, PMC_ANOMALY_OPCODE, discordance as u64, snapshot.tsc)`.

### CRYPTO-008/009/010 (LOW) — Hygiène key material et dispatch info
- `aes_gcm_seal`/`aes_gcm_open` ne zerisent pas `Aes256GcmCipher.round_keys` (240B sur stack).
- `blake3_derive_key` fallback silencieux si contexte non-UTF8.
- `Aes256GcmCipher.has_aesni` est sur la stack (info-leak minime).
**Fix** : wrapper `Zeroizing<Aes256RoundKeys>`, exiger contextes `&'static str`, `'static`-ify le dispatch.

### INTEG-016/017/018/019 (LOW) — Divers
- `SECBOOT_ENFORCE`/`NIC_POLICY_REQUIRED` en `AtomicBool` non PKS — attaquant kernel peut flip.
- `exonmi::tick()` spin infinie si ExoPhoenix absent — ajouter timeout + diagnostic.
- WRSSQ asm correct mais pourrait être `core::arch::x86_64::_wrssq` si stabilisé.
- `save_pkrs_to_tcb`/`restore_pkrs_from_tcb` doivent vérifier TCB non-préempté (CPU affinity).

---

## 6. Verdict — Le kernel crypto est-il conforme au mandate ?

### ❌ NON — Conformité partielle seulement.

**Primitives bas-niveau correctes** (✅) : BLAKE3 (avec `subtle`), Ed25519 `verify_strict`, AES-GCM (GHASH CT + verify-then-decrypt + `ct_eq`), XChaCha20-EtM, ChaCha20 RFC 8439 KAT.

**Primitives bas-niveau non-conformes** (❌) :
- **X25519** : only all-zero check, **RFC 7748 §6 weak-order subgroup checks ABSENT** → small-subgroup attack possible.
- **HKDF** : mandate dit HKDF-BLAKE3, code utilise HKDF-SHA256/SHA512.
- **AES-GCM software** : `aes_xtime` a branche data-dépendante (side-channel timing sur MixColumns).
- **AES-NI asm** : `preserves_flags` incorrect (`add rax,16` clobber flags) → risque de miscompilation.

**Intégrité / orchestration gravement défaillante** (❌❌❌) :
- **Secure boot** : `verify_boot_attestation()` **jamais appelée** → chaîne de confiance morte.
- **Code signing exec** : `verify_module_signature()` **jamais appelée par `do_execve`** → C-01 toujours ouvert, le check dans exec.rs est circulaire (`is_chain_verified() → check_chain_of_trust()`) et jamais bloquant.
- **Phase 0 ExoSeal** : ne halt pas le boot sur échec ; **pas de hash kernel+Ring1** comme la spec l'exige.
- **Runtime integrity** : mode OBSERVE (log-only, jamais panic) en production.
- **ExoLedger** : en BSS (pas SSR.LOG_AUDIT), chaîne BLAKE3 sans clé secrète → **forgeable par attaquant kernel R/W**.
- **KERNEL_SECRET** : en BSS (pas PKS), fallback prédictible si RNG hw indispo, retourne `[0u8;32]` si pas init → **MAC forgeable**.
- **`disable_enforcement()`** : pub non-unsafe, désactive secure-boot à runtime.
- **`arm_watchdog(0)`** : pub non-unsafe, désarme le NMI watchdog.
- **`restore_domain()`** : pub unsafe sans cap, restaure Credentials à volonté.

**Points positifs** (✅) :
- Compile-time guard rejetant les clés Ed25519 de test (FIX-F5) — solide.
- IDT integrity check appelé depuis le handler NMI ✓.
- `exonmi::tick()` appelé depuis l'IRQ timer quand `LapicTimerOwner::ExoNmiWatchdog` ✓.
- `exoargos::pmc_snapshot()` hooké sur `context_switch_out` ✓.
- `shield_feed` wire-up effectif (6 sites de push + syscall drain) ✓ — TIER 3.1 fermé pour capability/IPC/syscall/exec.
- KAIROS_WINDOW_NS=1s, THROTTLE=100%, KILL=200% asserted à la compilation ✓.
- CET per-thread activé pour tout nouveau thread (`tcb.rs:478,508`) ✓.

### Actions prioritaires (top 5)
1. **[P0 INTEG-001]** Appeler `verify_boot_attestation()` dans `kernel_main`/`security_init`, panic sur Err.
2. **[P0 INTEG-002]** Câbler `verify_module_signature()` dans `do_execve` avant le replace d'address space ; supprimer le check circulaire `is_chain_verified → check_chain_of_trust`.
3. **[P0 INTEG-003]** `exoseal_boot_phase0/complete` doivent `panic!` sur `verify_p0_fixes().is_err()` ; ajouter hash BLAKE3 kernel+Ring1.
4. **[P0 INTEG-004]** `get_kernel_secret()` doit `panic!` si non-init ; déplacer `init_kernel_secret` en step 0 ; vérifier `rng_hw_seeded()`.
5. **[P0 CRYPTO-001]** Implémenter RFC 7748 §6 complet (5 points faibles) dans `x25519_diffie_hellman`.

---

## 7. Note sur les tests et la documentation

- Les tests unitaires sont présents pour la plupart des primitives (BLAKE3, AES-GCM roundtrip, XChaCha20 KAT RFC 8439, Ed25519, X25519 symétrie, KDF domain separation, RNG non-zero, exokairos window budget, exoveil PKRS, exoledger init/overflow).
- **Aucun test d'intégration boot** ne vérifie que `verify_boot_attestation` est appelée — un test `#[test] fn boot_calls_verify_attestation()` avec un mock `BootAttestation` invalide aurait détecté INTEG-001.
- **Aucun test exec** ne vérifie qu'un binaire non signé est rejeté — un test `#[test] fn exec_rejects_unsigned_binary()` aurait détecté INTEG-002.
- La documentation des modules (commentaires en français) est abondante et honnête : plusieurs `FIX-F5`, `FIX-F6`, `FIX-KAIROS-01`, `FIX-P1-KAIROS`, `FIX-EXEC-SIG`, `FIX-DEEP-CRYPTO` indiquent que les auteurs ont conscience des gaps. **Mais le code n'applique pas les fixes annoncés dans les commentaires** (e.g., `FIX-EXEC-SIG` commenté à exec.rs:267 ne fait que logger en mode dev — le "vrai fix" n'existe pas).

---

*Rapport généré par Task 3a — sub-agent deep audit kernel crypto + integrity.*
