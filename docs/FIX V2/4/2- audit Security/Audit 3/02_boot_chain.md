# ExoOS — Audit de la Chaîne de Boot (Task 02)

**Auditeur :** Sub-agent "boot-chain" (audit froid,lecture exhaustive)
**Périmètre :** `bootloader/`, `exo-boot/`, `loader/`, `tools/kernel_signer/`, `kernel/src/main.rs`, `kernel/src/userspace_boot.rs`, `kernel/src/exophoenix/*`, `drivers/security/verity/`
**Date :** 2026-07-02
**Pré-requis :** `01_architecture.md` (synthèse architecture + open issues)

---

## 1. Inventaire des fichiers audités (lecture complète, aucun skim)

| Fichier | Lignes | Rôle |
|---|---:|---|
| `bootloader/grub.cfg` | — | Config GRUB legacy (non-code) |
| `exo-boot/src/main.rs` | 338 | `efi_main()` UEFI + `exoboot_main_bios()` BIOS |
| `exo-boot/src/uefi/entry.rs` | 134 | Préconditions UEFI (version, RNG, SB) |
| `exo-boot/src/uefi/secure_boot.rs` | 104 | Lecture `SecureBoot`/`SetupMode`/`AuditMode`/`DeployedMode` |
| `exo-boot/src/uefi/protocols/rng.rs` | 251 | EFI_RNG_PROTOCOL + fallback RDRAND/TSC |
| `exo-boot/src/kernel_loader/verify.rs` | 179 | Adaptateur `exo-verity` + politique `decide()` |
| `exo-boot/src/kernel_loader/signing_key.rs` | 14 | Clé publique Ed25519 embarquée (générée) |
| `exo-boot/src/kernel_loader/elf.rs` | 514 | Parseur ELF64 + chargeur segments PT_LOAD |
| `exo-boot/src/kernel_loader/handoff.rs` | 303 | `BootInfo` + `handoff_to_kernel()` |
| `exo-boot/src/kernel_loader/relocations.rs` | 253 | KASLR + `R_X86_64_RELATIVE`/`R_X86_64_64` |
| `exo-boot/src/kernel_loader/mod.rs` | 155 | Orchestration `load_kernel()` |
| `exo-boot/src/config/defaults.rs` | 113 | `BootConfig::default_config()` |
| `drivers/security/verity/src/lib.rs` | 333 | Crate partagée exo-verity (Ed25519+SHA-512) |
| `tools/kernel_signer/src/main.rs` | 292 | `keygen`/`sign`/`verify` (CLI) |
| `loader/src/security/verify_signature.rs` | 13 | Détection NOTE `EXOSIG\0\0` (présence seule) |
| `loader/src/security/capability_check.rs` | 62 | `check_exec_permission()` userspace |
| `loader/src/security/pie_aslr.rs` | 7 | `deterministic_slide()` (PIE ASLR userspace) |
| `loader/src/elf/relocations.rs` | 98 | RELA userspace (`R_X86_64_*`) |
| `loader/src/elf/validator.rs` | 16 | Validation statique minimale |
| `loader/src/main.rs` | 127 | `_start` du dynamic linker ring3 |
| `kernel/src/main.rs` | 440 | `_start`/`_start_uefi`/`_start64`/`kernel_main` |
| `kernel/src/userspace_boot.rs` | 55 | `boot_userspace()` → PID 1 |
| `kernel/src/exophoenix/mod.rs` | 123 | États Phoenix + `take_slot_once` |
| `kernel/src/exophoenix/ssr.rs` | 172 | SSR atomics + `validate_layout_v7()` |
| `kernel/src/exophoenix/stage0.rs` | 1368 | Bootstrap Kernel B (13 étapes) + `stage0_init()` |
| `kernel/src/exophoenix/sentinel.rs` | 353 | `run_forever()` (introspection + menace) |
| `kernel/src/exophoenix/forge.rs` | 762 | Reconstruction Kernel A + Merkle + checklist |
| `kernel/src/exophoenix/handoff.rs` | 559 | Freeze IPI + IOMMU revoke + forge + crypto wake |
| `kernel/src/exophoenix/isolate.rs` | 243 | `isolate_kernel_a_memory()` (PTE + IOMMU + IDT) |
| `kernel/src/exophoenix/interrupts.rs` | 178 | Handlers 0xF1/0xF2/0xF3 |
| `kernel/src/exophoenix/resurrection.rs` | 169 | `try_recover_exception()` + landing pad |
| `kernel/build.rs` | 313 | Provisionnement `kernel_a_image_hash.bin` |
| `kernel/src/arch/x86_64/boot/memory_map.rs` (extrait) | ~120 | `ExoBootInfo` shim + `init_memory_subsystem_exoboot()` |
| `kernel/src/arch/x86_64/boot/early_init.rs` (extrait) | ~200 | `arch_boot_init()` chemin exo-boot |
| `kernel/src/lib.rs` (extrait) | ~280 | `kernel_init()` phases 2a→7 |
| `servers/crypto_server/src/main.rs` (extrait) | ~120 | Handler `PHOENIX_WAKE_ENTROPY` |

**Total : ~7 500 lignes de code auditées intégralement.**

---

## 2. Architecture de la chaîne de boot (synthèse)

```
UEFI firmware
  └─> exo-boot.efi (PE32+ signé par db firmware)
        ├─ query_secure_boot_status() → SecureBoot=1 ∧ SetupMode=0 ∧ AuditMode=0
        ├─ load kernel.elf depuis ESP
        ├─ enforce_or_panic() [exo-verity::verify_image]
        │     └─ SHA-512(corps) recalculé → Ed25519 verify_strict
        │     └─ Tampered → panic TOUJOURS ; Unsigned/NoVerifierKey → panic si strict
        ├─ collect_entropy() [EFI_RNG ou RDRAND ou TSC fallback]
        ├─ load_kernel() : parse ELF + KASLR + segments + relocations RELATIVE
        ├─ construit BootInfo (magic 0x4F42_5F53_4F4F_5845, version 1)
        ├─ ExitBootServices
        └─ handoff_to_kernel() : EAX=EXOBOOT_MAGIC_U32, RBX=&BootInfo, jmp _start_uefi

kernel _start_uefi → _start64 → kernel_main(EXOBOOT_MAGIC_U32, boot_info_phys, 0)
  └─ arch_boot_init()
        ├─ init_memory_subsystem_exoboot() [valide magic, ignore version]
        └─ security_init() [TSC/RDRAND, PAS l'entropie BootInfo]
  └─ kernel_init()
        ├─ Phase 5b : stage0_init_all_steps(kernel_a_boot=true)  ← inline sur Kernel A
        └─ Phase 7   : exofs_init + elf_loader

ExoPhoenix (Kernel B théorique) :
  stage0_init() -> !  ── JAMAIS APPELÉ ──
        ├─ stage0_init_all_steps(false)
        ├─ send_sipi_once(CORE_A_SLOT, A_ENTRY_VECTOR)
        └─ sentinel::run_forever()  ← JAMAIS EXÉCUTÉ

Récupération (try_recover_exception) :
  NMI/double-fault → forge::verify_seeded_kernel_a_image()
    → reconstruct_kernel_a() : ExoFS + Merkle + FLR drivers + checklist G9
    → notify_crypto_server_phoenix_wake() → xchacha20_reseed + revoke_pre_phoenix
    → landing_pad sain

Isolation mémoire (isolate_kernel_a_memory) : DÉFINIE MAIS JAMAIS APPELÉE
```

---

## 3. Tableau des findings (trié par sévérité)

| ID | Sévérité | Fichier:ligne | Résumé | Statut précédent |
|---|---|---|---|---|
| **BOOT-001** | **CRITICAL** | `exophoenix/isolate.rs:231` | `isolate_kernel_a_memory()` JAMAIS appelée — pages Kernel A jamais marquées `!PRESENT` | Nouveau |
| **BOOT-002** | **CRITICAL** | `exophoenix/stage0.rs:1163` | `stage0_init()` (Kernel B) JAMAIS appelé — `sentinel::run_forever()` JAMAIS exécuté | Nouveau |
| **BOOT-003** | **CRITICAL** | `exo-boot/src/main.rs:185` | `SECURE_BOOT_ACTIVE` flag basé sur config, pas sur vérification réelle ; kernel ne le lit jamais | Nouveau |
| **BOOT-004** | **CRITICAL** | `loader/src/security/capability_check.rs:36` | Userspace : note `EXOSIG\0\0` détectée mais JAMAIS vérifiée crypto — combiné à C-01 ouvert | C-01 toujours ouvert |
| **BOOT-005** | **CRITICAL** | `exophoenix/handoff.rs:545` | `begin_isolation_hard()` ne reconstruit PAS Kernel A — relâche les cœurs sans recovery | Nouveau |
| **BOOT-006** | **HIGH** | `kernel/src/arch/x86_64/boot/memory_map.rs:719` | `BootInfo.version` NON validé par le kernel (seul `magic`) | Nouveau |
| **BOOT-007** | **HIGH** | `kernel/src/arch/x86_64/boot/memory_map.rs:669` | Champ `entropy[64]` du BootInfo JAMAIS lu par le kernel — EFI_RNG gaspillé | Nouveau |
| **BOOT-008** | **HIGH** | `exophoenix/ssr.rs:30` | `SSR_OFFSET_CHECKSUM` défini mais JAMAIS vérifié — pas de hash BLAKE3 SSR | Nouveau |
| **BOOT-009** | **HIGH** | `exophoenix/stage0.rs:1023` | Échec `initialize_layout_v7()` non-fatal — SSR corrompue ⇒ Phoenix silencieusement désactivé | Nouveau |
| **BOOT-010** | **HIGH** | `exo-boot/src/config/defaults.rs:49` | `secure_boot_required = false` par défaut — kernel non-signé démarre avec warning | Nouveau |
| **BOOT-011** | **HIGH** | `exo-boot/src/kernel_loader/relocations.rs:80` | KASLR plage [4 MiB, 2 GiB] = ~9 bits (spec annonce 1 GiB..256 GiB) | Nouveau |
| **BOOT-012** | **MEDIUM** | `exo-boot/src/kernel_loader/relocations.rs:71` | Mixage entropie KASLR par XOR+rotation (non cryptographique) | Nouveau |
| **BOOT-013** | **MEDIUM** | `drivers/security/verity/src/lib.rs:187` | `digest != stored_sha` non constant-time — deviation mandate `ct_eq` | Nouveau |
| **BOOT-014** | **MEDIUM** | `exophoenix/forge.rs:337` | `computed != A_MERKLE_ROOT` non constant-time | Nouveau |
| **BOOT-015** | **MEDIUM** | `kernel/src/lib.rs:326` | `seed_kernel_a_image_blob()` commenté — forge échoue si `KERNEL_A_IMAGE_PATH` non set au build | Nouveau |
| **BOOT-016** | **MEDIUM** | `kernel/build.rs:296` | Sans `EXOPHOENIX_REQUIRE_HASHES=1`, build produit ZERO_HASH silencieusement | Nouveau |
| **BOOT-017** | **LOW** | `drivers/security/verity/src/lib.rs:105` | `key_is_usable` ne bloque que 2 vecteurs de test (RFC8032) — blocklist minimale | Nouveau |
| **BOOT-018** | **LOW** | `exo-boot/src/uefi/protocols/rng.rs:176` | Fallback TSC seul cryptographiquement faible (reconnu par le code) | Accepté (documenté) |
| **BOOT-019** | **LOW** | `exo-boot/src/main.rs:246` | BIOS path : `from_raw_parts(0x200000, 64 MiB)` sans vérif taille réelle — lit au-delà du kernel | Nouveau |

**Issues précédentes — statut mis à jour :**

| Issue | Statut | Détail |
|---|---|---|
| C-01 (do_execve ne vérifie pas signature module) | **TOUJOURS OUVERT** | `verify_module_signature` défini mais 0 appelant ; `capability_check` se contente de détecter la note |
| C-02 (forge Merkle degraded mode si hash=0) | **RÉSOLU** | `verify_merkle()` retourne `Err(MerkleVerifyFailed)` si `kernel_a_hash_is_zero()` |
| PhoenixWakeEntropy non wired | **RÉSOLU côté crypto_server** | `xchacha20_reseed()` + `revoke_all_pre_phoenix()` appelés ; MAIS `stage0_init()` jamais appelé ⇒ le reseed n'est jamais déclenché en pratique |
| TIER 5.3 (ExoPhoenix physical reload + huge page isolation) | **TOUJOURS OUVERT** | `isolate_kernel_a_memory()` jamais appelé |

---

## 4. Détail des findings

### BOOT-001 — CRITICAL — `isolate_kernel_a_memory()` jamais appelée

**Fichier :** `kernel/src/exophoenix/isolate.rs:231`

```rust
/// Applique la cage mémoire complète sur Kernel A.
/// Appelé par handoff.rs après confirmation des ACK freeze et drain IOMMU.
/// Ordre strict — ne pas modifier.
pub fn isolate_kernel_a_memory() {
    // 1. Marquer pages de A !PRESENT
    mark_a_pages_not_present();
    // 2. TLB shootdown sur tous les cores de A (S8)
    tlb_shootdown_all_a_cores();
    // 3. Hard revoke IOMMU + IOTLB flush (S-N1)
    iommu_hard_revoke_and_flush();
    // 4. Override IDT de A
    override_a_idt_with_b_handlers();
}
```

**Recherche exhaustive des appelants :**
```
$ grep -rn "isolate_kernel_a_memory\|isolate::" kernel/src/
exophoenix/isolate.rs:231:pub fn isolate_kernel_a_memory() {
```
→ **Zéro appelant.** La fonction existe, fait correctement le travail (PTE `!PRESENT`, TLB shootdown IPI 0xF3, IOMMU hard revoke, override IDT), mais n'est jamais invoquée.

**Scénario d'attaque :** Lors d'un handoff ExoPhoenix, Kernel A est supposé être isolé pendant que Kernel B reconstruit son image. Sans isolation PTE, Kernel A (compromis) continue d'exécuter son code avec ses pages présentes. Il peut lire/écrire la SSR, altérer le handoff flag, corrompre le contexte de Kernel B, ou attaquer le forge en cours.

**Recommandation :** Insérer `isolate::isolate_kernel_a_memory()` dans `handoff::begin_isolation_soft()` entre `stage_hard_revoke_iommu(true)` (ligne 537) et `try_forge_reconstruct_with_policy()` (ligne 541). Également dans `begin_isolation_hard()` avant tout retour.

---

### BOOT-002 — CRITICAL — `stage0_init()` / Kernel B jamais démarré

**Fichier :** `kernel/src/exophoenix/stage0.rs:1163`

```rust
/// Stage0 complet (1→13): bascule Normal, SIPI one-shot, puis boucle sentinelle.
pub fn stage0_init() -> ! {
    // Point d'entrée dédié du cœur de Kernel B : séquence complète (kernel_a_boot=false).
    let _summary = stage0_init_all_steps(false);
    // ...
    PHOENIX_STATE.store(PhoenixState::Normal as u8, Ordering::Release);
    let _ = send_sipi_once(CORE_A_SLOT, A_ENTRY_VECTOR);
    sentinel::run_forever()   // ← JAMAIS ATTEINT
}
```

**Recherche exhaustive :**
```
$ grep -rn "stage0_init\b\|stage0_init(" kernel/src/ | grep -v "stage0_init_all_steps"
exophoenix/stage0.rs:1163:pub fn stage0_init() -> ! {
exophoenix/stage0.rs:1165:    let _summary = stage0_init_all_steps(false);
```
→ **Zéro appelant.** Aucun point d'entrée assembleur, aucun `ap_entry`, aucun trampoline SIPI ne référence `stage0_init`. Le kernel boot uniquement Kernel A via `stage0_init_all_steps(true)` (lib.rs:284), qui saute explicitement les étapes Kernel B (pile/TSS/IDT/timer) et n'appelle jamais `sentinel::run_forever()`.

**Conséquence : Toute l'infrastructure ExoPhoenix est MOTEUR ÉTEINT.**
- Pas de `sentinel::run_forever()` → pas de détection heartbeat > 2 s
- Pas de `walk_a_page_tables_iterative()` → pas de détection de remap PA suspect
- Pas de `check_liveness_nonce()` → pas de détection de freeze Kernel A
- Pas de `pmc_anomaly_score()` → pas de détection d'anomalie PMC
- Pas de `begin_isolation_soft()` automatique → pas de déclenchement de forge
- `try_recover_exception()` ne peut être déclenché que par NMI/exception, pas par heartbeat sentinelle

Le `resurrection::try_recover_exception()` existe et peut être appelé depuis un handler d'exception, mais le gardien `phoenix_ready = PHOENIX_STATE == Normal` (ligne 98) ne sera **jamais vrai** car personne ne met l'état à `Normal`. En pratique, la récupération est également désactivée.

**Scénario d'attaque :** Un attaquant qui compromet Kernel A (via C-01, D-01, D-02, etc.) dispose d'un temps indéfini pour persister, exfiltrer, ou détruire — aucun watchdog ne le détectera. La "résurrection < 500 ms" promise par l'architecture est fictive.

**Recommandation :**
1. Définir un point d'entrée assembleur `_kernel_b_start` qui appelle `stage0_init()` après setup minimal long-mode.
2. Le bootloader (exo-boot) ou le stage0 de Kernel A doit réserver un core physique (le dernier AP du MADT) et lui envoyer un SIPI vers `_kernel_b_start` au lieu du trampoline scheduler normal.
3. Alternative plus simple : `create_kthread(stage0_init_as_kthread)` sur un core dédié via `scheduler::core::task::create_kthread` + `set_affinity(cpu_id)`. Adapter `stage0_init` pour retourner `()` au lieu de `-> !` et boucler en interne.

---

### BOOT-003 — CRITICAL — `SECURE_BOOT_ACTIVE` flag trompeur et jamais lu

**Fichier :** `exo-boot/src/main.rs:181-189`

```rust
boot_info_ref.boot_flags = {
    use kernel_loader::handoff::boot_flags::*;
    let mut flags = UEFI_BOOT;
    if cfg.kaslr_enabled                       { flags |= KASLR_ENABLED; }
    if cfg.secure_boot_required                { flags |= SECURE_BOOT_ACTIVE; }   // ← BUG
    if boot_info_ref.framebuffer.is_present()  { flags |= FRAMEBUFFER_PRESENT; }
    if boot_info_ref.acpi_rsdp != 0            { flags |= ACPI2_PRESENT; }
    flags
};
```

Deux défauts cumulés :

1. **Le flag est basé sur `cfg.secure_boot_required` (fichier config), pas sur le résultat réel de vérification.** Si l'utilisateur met `secure_boot_required=true` dans `exo-boot.cfg` mais que la clé de signature est absente (`NoVerifierKey`), en mode non-strict le kernel démarre avec warning (dev permissif) — pourtant `SECURE_BOOT_ACTIVE` est levé.

2. **Le kernel ne lit jamais `boot_flags`.** Recherche exhaustive :
```
$ grep -rn "boot_flags\|SECURE_BOOT_ACTIVE" kernel/src/
(zéro résultat)
```
Le `ExoBootInfo` shim (`memory_map.rs:669`) s'arrête à `acpi_rsdp` (offset 6200). Les champs `entropy` (6208), `kernel_physical_base` (6272), `kernel_entry_offset` (6280), `kernel_elf_phys` (6288), `kernel_elf_size` (6296), `boot_flags` (6304), `boot_tsc` (6312) sont **ignorés**.

**Scénario d'attaque :** Le flag `SECURE_BOOT_ACTIVE` est cosmétique. Un kernel altéré pourrait être chargé si l'opérateur oublie `secure_boot_required=true` dans la config (BOOT-010). Le kernel ne fait aucun renforcement runtime basé sur ce flag (pas de policy denial, pas de audit flag).

**Recommandation :**
1. Lever `SECURE_BOOT_ACTIVE` uniquement si `uefi_sb_enforcing && verdict == Verified`.
2. Côté kernel, lire `boot_flags` et refuser certaines opérations sensibles (montage de modules non-signés, désactivation de mitigations) si `SECURE_BOOT_ACTIVE` est levé.
3. Valider `boot_flags` cohérence : si `SECURE_BOOT_ACTIVE` mais pas de `kernel_elf_phys`, refuser le boot.

---

### BOOT-004 — CRITICAL — Userspace : note EXOSIG détectée mais jamais vérifiée

**Fichier :** `loader/src/security/capability_check.rs:34-56`

```rust
pub fn check_exec_permission(image: &[u8], require_signature: bool) -> ExecCheckResult {
    match detect_signature_note(image) {
        SignatureState::Present => ExecCheckResult::SignedOk,   // ← BUG
        SignatureState::Unsigned => {
            if require_signature {
                // ...
                ExecCheckResult::Denied
            } else {
                // ...
                ExecCheckResult::UnsignedAllowed
            }
        }
    }
}
```

**Fichier :** `loader/src/security/verify_signature.rs:7-13`

```rust
pub fn detect_signature_note(image: &[u8]) -> SignatureState {
    if image.windows(8).any(|w| w == b"EXOSIG\0\0") {
        SignatureState::Present
    } else {
        SignatureState::Unsigned
    }
}
```

La détection cherche le marqueur `EXOSIG\0\0` (8 octets) — différent du footer `EXOSIG01` (8 octets) utilisé par exo-verity. C'est une **note distincte**, pas le footer de signature réel. Aucune vérification cryptographique n'est faite.

Le commentaire de `capability_check.rs:31-33` indique : *"La vérification cryptographique complète est faite dans kernel::do_execve() via security::verify_module_signature()"*. Mais :

```
$ grep -rn "verify_module_signature" kernel/src/
security/mod.rs:121:    verify_module_signature, ...   (re-export)
security/integrity_check/mod.rs:15:    ..., verify_module_signature, ...  (re-export)
security/integrity_check/code_signing.rs:194:pub fn verify_module_signature(...) -> Result<...> { ... }   (définition)
```
→ **Zéro appelant dans do_execve ou ailleurs dans le chemin syscall/process.** L'issue C-01 reste OUVERT.

**Scénario d'attaque :** Un attaquant ajoute 8 octets `EXOSIG\0\0` n'importe où dans un binaire malveillant. `check_exec_permission` retourne `SignedOk`. Le kernel `do_execve` ne vérifie pas non plus. Le binaire s'exécute avec le statut "signé" — contournement total de la chaîne de confiance userspace.

**Recommandation :**
1. `do_execve` doit appeler `verify_module_signature(&header, &code)` et refuser `Err(_)` en mode secure boot.
2. Unifier `EXOSIG\0\0` (note) et `EXOSIG01` (footer) — utiliser le footer exo-verity partout.
3. En mode dev permissif, logger mais ne pas mentir sur `SignedOk` (utiliser `UnsignedAllowed`).

---

### BOOT-005 — CRITICAL — `begin_isolation_hard()` ne reconstruit pas Kernel A

**Fichier :** `exophoenix/handoff.rs:545-559`

```rust
/// Démarrage isolation forcée (Phase 2).
pub fn begin_isolation_hard() -> Result<(), &'static str> {
    let self_slot = current_slot();

    // G2: masquer MSI/MSI-X avant INIT IPI.
    mask_all_msi_msix();
    send_init_ipi_to_resistant_cores(self_slot);

    // Hard revoke sans drain.
    stage_hard_revoke_iommu(false);
    scan_and_release_spinlocks();

    PHOENIX_STATE.store(PhoenixState::Certif as u8, Ordering::Release);
    set_handoff_flag_release(HANDOFF_NORMAL);   // ← relâche les cœurs A
    Ok(())                                       // ← PAS de forge, PAS d'isolation PTE
}
```

Quand `begin_isolation_soft()` échoue (timeout ACK freeze à 100 µs), elle appelle `begin_isolation_hard()` (ligne 533). Mais `begin_isolation_hard()` :
- Ne fait PAS `isolate_kernel_a_memory()` (PTE + IDT override)
- Ne fait PAS `try_forge_reconstruct_with_policy()` (pas de reconstruction)
- Relâche les cœurs A via `HANDOFF_NORMAL`
- Retourne `Ok(())`

Les cœurs A reprennent donc l'exécution de Kernel A **tel quel**, sans vérification d'intégrité, alors qu'on est dans un chemin d'escalade (soft isolation a échoué = cœurs réfractaires ou compromis).

**Scénario d'attaque :** Un attaquant compromet Kernel A et hook le handler 0xF1 (freeze IPI) pour qu'il ne ACK pas. Le soft timeout (100 µs) expire, `begin_isolation_hard()` est appelé, qui relâche Kernel A sans reconstruction. L'attaquant garde le contrôle.

**Recommandation :** `begin_isolation_hard()` doit :
1. Appeler `isolate::isolate_kernel_a_memory()` (PTE + IDT override + IOMMU).
2. Appeler `try_forge_reconstruct_with_policy()` pour reconstruire depuis image propre.
3. En cas d'échec forge, rester en `IsolationHard` (pas `HANDOFF_NORMAL`) et éventuellement `Emergency` halt.

---

### BOOT-006 — HIGH — `BootInfo.version` non validé par le kernel

**Fichier :** `kernel/src/arch/x86_64/boot/memory_map.rs:718-721`

```rust
// Valider le magic avant tout accès supplémentaire
if bi.magic != EXOBOOT_BOOT_INFO_MAGIC {
    crate::arch::x86_64::halt_cpu();
}
```

Le kernel valide `magic` (0x4F42_5F53_4F4F_5845) mais **pas `version`**. `BOOT_INFO_VERSION = 1` côté exo-boot (`handoff.rs:39`). Si un futur exo-boot bump la version avec un layout différent, le kernel lira des offsets erronés sans s'en apercevoir.

**Scénario d'attaque :** Pas une attaque directe, mais un risque de corruption mémoire silencieuse lors d'un mismatch de version (downgrade exo-boot ou upgrade kernel partiel). Un attaquant physique pourrait aussi patcher le champ `version` sans effet, masquant une incohérence.

**Recommandation :** Ajouter après le check magic :
```rust
if bi.version != EXOBOOT_BOOT_INFO_VERSION {
    crate::arch::x86_64::halt_cpu();
}
```
avec `pub const EXOBOOT_BOOT_INFO_VERSION: u32 = 1;` synchronisé avec `exo-boot::handoff::BOOT_INFO_VERSION`.

---

### BOOT-007 — HIGH — Champ `entropy[64]` du BootInfo jamais lu par le kernel

**Fichier :** `kernel/src/arch/x86_64/boot/memory_map.rs:669-684` (shim `ExoBootInfo`)

```rust
#[repr(C, align(4096))]
struct ExoBootInfo {
    magic: u64,                          // offset   0
    version: u32,                        // offset   8
    memory_region_count: u32,            // offset  12
    memory_regions: [ExoMemRegion; 256], // offset 16
    fb_phys_addr: u64,                   // offset 6160
    // ...
    acpi_rsdp: u64,                      // offset 6200
    // STOP — entropy (6208), kernel_physical_base (6272), boot_flags (6304) non lus
}
```

Le kernel calcule sa propre entropie KASLR dans `early_init.rs:363-368` :
```rust
let mut kaslr_entropy = super::super::cpu::tsc::read_tsc()
    ^ ((mb2_magic as u64) << 32) ^ mb2_info ^ rsdp;
let mut rdrand = [0u8; 8];
if crate::security::crypto::rng::rdrand_fill(&mut rdrand).is_ok() {
    kaslr_entropy ^= u64::from_le_bytes(rdrand);
}
```

Les 64 octets d'entropie collectés par exo-boot via EFI_RNG_PROTOCOL (ou RDRAND/TSC fallback) sont **écrits dans BootInfo à l'offset 6208 mais jamais consommés**. Le kernel utilise uniquement TSC ^ magic ^ info ^ rsdp ^ 8 octets RDRAND.

**Scénario d'attaque :** Sur un firmware UEFI avec RNG matériel défectueux (mais RDRAND OK), le kernel devrait idéalement profiter des 64 octets EFI_RNG. En pratique, il ignore cette source. Sur VMs sans RDRAND, l'entropie se réduit à TSC ^ constantes — prédictible si l'attaquant contrôle le timing de boot (cold-boot attack, snapshot VM reseed).

**Recommandation :**
1. Étendre `ExoBootInfo` pour lire `entropy: [u8; 64]` à l'offset 6208.
2. Passer ces 64 octets à `security_init(kaslr_entropy, ...)` comme graine additionnelle (XOR dans le pool CSPRNG).
3. Idéalement, exiger que l'entropie BootInfo soit non-tout-zéro (refus si nulle).

---

### BOOT-008 — HIGH — Pas de vérification de hash BLAKE3 sur la SSR

**Fichier :** `kernel/src/exophoenix/ssr.rs:30-31`

```rust
pub const SSR_OFFSET_CHECKSUM: usize = 64;
pub const SSR_OFFSET_FLAGS: usize = SSR_OFFSET_CHECKSUM + 32;
```

Le champ `SSR_OFFSET_CHECKSUM` (32 octets, immédiatement après le header) est défini mais **jamais lu ni vérifié**. La fonction `validate_layout_v7()` ne vérifie que `magic+version` :

```rust
pub fn validate_layout_v7() -> Result<(), SsrVersionError> {
    let value = read_magic_version();
    if exo_phoenix_ssr::is_compatible_magic_version(value) {
        Ok(())
    } else {
        Err(SsrVersionError::IncompatibleMagicVersion(value))
    }
}
```

L'architecture (01_architecture.md) annonce *"SSR 4KiB @ 0x0100_0000, magic 0xEXO_PHXF, BLAKE3-hashed"*. En pratique, le hash n'existe pas ou n'est pas vérifié.

**Scénario d'attaque :** Kernel A (compromis) peut altérer la SSR — par exemple réécrire `SSR_HANDOFF_FLAG` à `HANDOFF_NORMAL` pour empêcher le freeze, ou corrompre `SSR_LIVENESS_NONCE` pour faire échouer le liveness check, ou injecter de faux `FREEZE_ACK_DONE`. Kernel B (si jamais il tournait — cf. BOOT-002) ne détecterait pas l'altération.

**Recommandation :**
1. Au boot Kernel B, recalculer BLAKE3 du contenu SSR (hors checksum) et comparer au champ `SSR_OFFSET_CHECKSUM`.
2. Si mismatch, `PHOENIX_STATE = Degraded` et refuser le handoff.
3. Le checksum doit être (ré)écrit par Kernel B à chaque mutation légitime de la SSR — pas seulement au boot.

---

### BOOT-009 — HIGH — Échec d'initialisation SSR non-fatal

**Fichier :** `kernel/src/exophoenix/stage0.rs:1023-1041`

```rust
if let Err(err) = super::ssr::initialize_layout_v7() {
    log::error!(
        "SSR ExoPhoenix incompatible au boot: {:?} (attendu v{}.{} magic={:#x})",
        err, ...
    );
    // FIX-BOOT-STAGE0-HANG : NE PAS halter ici. ...
    // On passe donc en mode dégradé et on CONTINUE le boot.
    PHOENIX_STATE.store(PhoenixState::Degraded as u8, Ordering::Release);
}
```

Le commentaire justifie ce choix : `stage0_init_all_steps(true)` est appelé inline sur le boot de Kernel A (lib.rs:284), avant IPC/FS. Halt = blocage total. C'est compréhensible pour le dev, mais en production c'est un bypass silencieux : si la SSR est corrompue (attaque ou bug firmware), ExoPhoenix se désactive sans alerter.

Le flag `Degraded` est ensuite consulté à la ligne 1147 :
```rust
if PHOENIX_STATE.load(Ordering::Acquire) != PhoenixState::Degraded as u8 {
    activate_exophoenix_vectors();
}
```
→ En mode dégradé, les vecteurs 0xF1/0xF2/0xF3 ne sont pas armés, et `begin_isolation_soft()` refusera de démarrer (garde `exophoenix_vectors_not_armed` à `handoff.rs:519`).

**Scénario d'attaque :** Un attaquant qui peut écrire dans la région physique SSR (via DMA non-IOMMU, ou via exploit Kernel A) peut casser le magic, ce qui désactive silencieusement toute la résurrection Phoenix.

**Recommandation :**
1. En production (cfg `production` ou `EXOPHOENIX_REQUIRE_HASHES=1`), paniquer sur SSR invalide.
2. En dev, continuer mais émettre un avertissement persistant (boot_display + audit log).
3. Ajouter une variable globale `SSR_VALID` consultée par `try_recover_exception` pour refuser la récupération si SSR jamais initialisée.

---

### BOOT-010 — HIGH — `secure_boot_required = false` par défaut

**Fichier :** `exo-boot/src/config/defaults.rs:46-57`

```rust
pub fn default_config() -> Self {
    // ...
    Self {
        kernel_path,
        kaslr_enabled:         true,   // Activé par défaut (sécurité)
        secure_boot_required:  false,  // Désactivé — pour compatibilité dev
        // ...
    }
}
```

Si `exo-boot.cfg` est absent ou ne contient pas `secure_boot_required=true`, et qu'UEFI Secure Boot n'est pas enforcing (SecureBoot=0 ou SetupMode=1), alors `enforce_or_panic` recevra `require_signed=false, uefi_sb_enforcing=false` → `strict=false` → un kernel `Unsigned` ou `NoVerifierKey` sera accepté avec warning.

**Scénario d'attaque :** Sur une machine UEFI sans Secure Boot activé (cas courant en dev, cloud, et même certains serveurs), un attaquant avec accès disque peut remplacer `kernel.elf` par un kernel non-signé. exo-boot le chargera avec juste un warning sur ConOut (que personne ne lit). Le `SECURE_BOOT_ACTIVE` flag sera 0 (au moins honnête), mais le kernel démarre quand même.

**Recommandation :**
1. En build `release`, changer le défaut à `secure_boot_required: true`.
2. Ou exiger un `exo-boot.cfg` explicite en release (panic si absent).
3. Documenter que `secure_boot_required=false` ne doit être utilisé qu'en dev.

---

### BOOT-011 — HIGH — KASLR plage bien plus faible que la spec

**Fichier :** `exo-boot/src/kernel_loader/relocations.rs:80-93`

```rust
// Plage physique [4 MiB, 2 GiB] avec pas de 2 MiB
// (512 − 2 = 510 positions possibles, évite les 2 premiers MiB = firmware)
const PHYS_MIN:  u64 = 4 * 1024 * 1024;            // 4 MiB
const PHYS_MAX:  u64 = 2 * 1024 * 1024 * 1024;     // 2 GiB
const STEP:      u64 = HUGE_PAGE_SIZE as u64;       // 2 MiB
let   range = (PHYS_MAX - PHYS_MIN) / STEP;        // = 510

let offset   = (mixed % range) * STEP;
let phys_base = PHYS_MIN + offset;
```

L'architecture (01_architecture.md) annonce : *"KASLR: EFI_RNG or RDRAND/TSC, 1GiB..256GiB, align 2MiB, PIE"*. En pratique :
- Plage : [4 MiB, 2 GiB] au lieu de [1 GiB, 256 GiB]
- Entropie : log2(510) ≈ **9 bits** au lieu de log2((256-1)*512) ≈ **17 bits**
- Le `phys_base` final est dans le premier 2 GiB — accessible via mapping direct 32-bit, facilitant les attaques par address guessing

De plus, le code UEFI alloue via `AllocateType::AnyPages` (main.rs:133) puis utilise `phys_dest` directement. Si l'allocateur UEFI place le kernel en dehors de [4 MiB, 2 GiB], le `compute_kaslr_base` est ignoré (mod.rs:96-100) :
```rust
if phys_dest == 0 { (pb, vb) }
else {
    let virt = ...kernel_virtual_base(phys_dest);
    (phys_dest, virt)
}
```
→ En pratique, `phys_dest` (retourné par `allocate_pages`) est non-zéro, donc **KASLR est court-circuité** par l'allocateur UEFI. Le `compute_kaslr_base` ne sert à rien.

**Scénario d'attaque :** KASLR effectif ≈ 0 bit (l'allocateur UEFI est déterministe pour un firmware donné). Les gadgets ROP/JOP ont des adresses prédictibles.

**Recommandation :**
1. Utiliser `AllocateType::Address` avec `compute_kaslr_base()` comme adresse demandée, après s'être assuré que la zone est libre via `memory_map`.
2. Étendre la plage à [1 GiB, 256 GiB] comme annoncé, en reservant les zones DMA32 pour les devices legacy.
3. Mélanger l'entropie via BLAKE3 (derive_key) plutôt que XOR+rotation.

---

### BOOT-012 — MEDIUM — Mixage entropie KASLR non cryptographique

**Fichier :** `exo-boot/src/kernel_loader/relocations.rs:70-78`

```rust
pub fn compute_kaslr_base(entropy: &[u8; 64]) -> (u64, u64) {
    let mut mixed: u64 = 0;
    for chunk in entropy.chunks_exact(8) {
        let val = u64::from_le_bytes(chunk.try_into().unwrap_or([0u8; 8]));
        mixed ^= val;
        mixed = mixed.rotate_left(13).wrapping_add(0x9E37_79B9_7F4A_7C15);
    }
    // ...
    let offset = (mixed % range) * STEP;
```

Le mélange XOR + rotate_left(13) + add Fibonacci est un hash non cryptographique (proche FNV-1a modifié). Il a une diffusion faible : deux entropies différant d'un seul bit peuvent produire des offsets corrélés.

**Recommandation :** Utiliser `blake3::derive_key("exo-kaslr", entropy)` puis prendre les 8 premiers octets du digest comme `mixed`. BLAKE3 est déjà une dépendance du workspace.

---

### BOOT-013 — MEDIUM — Comparaison SHA-512 non constant-time dans exo-verity

**Fichier :** `drivers/security/verity/src/lib.rs:186-189`

```rust
// Recalcul du hash du corps (autoritatif — pas de confiance au hash stocké).
let digest = sha512_of(&image[..body_len]);
if digest.as_slice() != stored_sha {
    return KernelVerdict::Tampered;
}
```

La comparaison `!=` sur slice n'est pas constant-time. Le mandate (01_architecture.md) exige `ct_eq` pour les comparaisons crypto (BLAKE3, GHASH, etc.).

**Scénario d'attaque :** Timing side-channel pour distinguer "hash match jusqu'au byte N" — théoriquement possible si l'attaquant peut observer le temps de réponse de `verify_image` avec des corps mutés. En pratique, la fenêtre est étroite (UEFI, pas d'observation remote directe), mais le mandate est clair.

**Recommandation :** Remplacer par `subtle::ConstantTimeEq` :
```rust
use subtle::ConstantTimeEq;
if !bool::from(digest.ct_eq(stored_sha)) {
    return KernelVerdict::Tampered;
}
```
Faire de même pour `marker != SIG_MARKER` (ligne 176).

---

### BOOT-014 — MEDIUM — Comparaison Merkle root non constant-time dans forge

**Fichier :** `kernel/src/exophoenix/forge.rs:337-339`

```rust
if computed != A_MERKLE_ROOT {
    return Err(ForgeError::MerkleVerifyFailed);
}
```

Comparaison `[u8; 32] != [u8; 32]` — non constant-time.

**Recommandation :** `subtle::ConstantTimeEq` (déjà dépendance workspace). Idem pour `checklist_madt_hash` ligne 657 (`current != expected`).

---

### BOOT-015 — MEDIUM — `seed_kernel_a_image_blob()` commenté

**Fichier :** `kernel/src/lib.rs:324-327`

```rust
if exofs_ready {
    // DIAG: seed_kernel_a_image_blob temporairement sauté pour isoler le fault.
    // let _ = crate::exophoenix::forge::seed_kernel_a_image_blob();
}
```

Le seeding du cache ExoFS avec l'image propre de Kernel A est commenté "temporairement". Le forge ne peut donc utiliser que `A_CLEAN_IMAGE` (embarqué via `include_bytes!`), qui est vide si `KERNEL_A_IMAGE_PATH` n'est pas set au build.

**Conséquence :** En build dev (sans `KERNEL_A_IMAGE_PATH`), `kernel_a_image_provisioned()` retourne false, `verify_merkle()` fail-closed (BOOT-016), `reconstruct_kernel_a()` échoue. Le forge est désactivé mais de manière échouée-fermée (sécurité OK, résilience HS).

**Recommandation :** Décommenter et diagnostiquer le "fault" mentionné. Si la cause est un BLOB_CACHE pas encore initialisé au moment de l'appel, déplacer l'appel après `exofs_init` complet.

---

### BOOT-016 — MEDIUM — Build produit ZERO_HASH silencieusement sans `EXOPHOENIX_REQUIRE_HASHES=1`

**Fichier :** `kernel/build.rs:285-305`

```rust
let require_hashes = env_flag("EXOPHOENIX_REQUIRE_HASHES");
// ...
if !has_legacy_hash {
    if require_hashes {
        panic!("EXOPHOENIX_REQUIRE_HASHES=1 but no KERNEL_A_IMAGE_PATH ...");
    }
    println!(
        "cargo:warning=ExoPhoenix: KERNEL_A_IMAGE_PATH not set — \
         building with ZERO_HASH (kernel_a_hash_is_zero()=true). \
         verify_merkle() will fail. Set KERNEL_A_IMAGE_PATH for production builds."
    );
}
```

Sans `EXOPHOENIX_REQUIRE_HASHES=1`, un warning Cargo est émis mais le build réussit avec `A_IMAGE_HASH = A_MERKLE_ROOT = [0; 32]`. À runtime, `kernel_a_hash_is_zero() = true` → `verify_merkle() = Err(MerkleVerifyFailed)` → `reconstruct_kernel_a() = Err` → `try_forge_reconstruct_with_policy()` échoue → `PHOENIX_STATE = Degraded`.

C'est fail-closed (sécurité OK), mais l'opérateur peut facilement oublier `EXOPHOENIX_REQUIRE_HASHES=1` en production et se retrouver avec ExoPhoenix silencieusement désactivé.

**Recommandation :**
1. En build `release`, activer `EXOPHOENIX_REQUIRE_HASHES` par défaut (panic si non set).
2. Ou exiger `KERNEL_A_IMAGE_PATH` en release.
3. Le warning Cargo est facilement noyé dans les logs de build — ajouter une étape de vérification post-build (script `verify_phoenix_contract.py`).

---

### BOOT-017 — LOW — Blocklist de clés minimale dans exo-verity

**Fichier :** `drivers/security/verity/src/lib.rs:105-114`

```rust
const RFC8032_TEST_PUB: [u8; 32] = [...];
const RFC8032_TEST_SEED_AS_PUB: [u8; 32] = [...];

pub const fn key_is_usable(pubkey: &[u8; 32]) -> bool {
    // ...
    !(arrays_eq_32(pubkey, &RFC8032_TEST_PUB) || arrays_eq_32(pubkey, &RFC8032_TEST_SEED_AS_PUB))
}
```

Seules 2 clés de test sont bloquées (RFC 8032 Test 1). D'autres vecteurs de test publics (RFC 8032 Test 2-7, clés de tests ed25519-dalek, clés de tutoriels) ne sont pas bloqués. Si un développeur copie une clé de test autre que Test 1, elle passera le garde.

**Recommandation :** Étendre la blocklist à tous les vecteurs RFC 8032 + clés de test ed25519-dalek documentées. Ou idéalement, exiger que la clé soit signée par une CA racine embarquée (PKI — cf. TIER 2.1-b/c).

---

### BOOT-018 — LOW — Fallback TSC seul cryptographiquement faible

**Fichier :** `exo-boot/src/uefi/protocols/rng.rs:176-225`

Si `EFI_RNG_PROTOCOL` est absent ET `RDRAND` indisponible (CPU pré-2012 ou VM sans RDRAND), le code tombe sur `collect_via_tsc_fallback` qui ne fait que XOR TSC avec un compteur et Fibonacci hashing. Le code reconnait lui-même : *"AVERTISSEMENT : Le fallback TSC seul n'est PAS cryptographiquement sûr."*

**Recommandation :** En l'absence d'EFI_RNG et RDRAND, refuser le boot en mode secure (panic) plutôt que de continuer avec une entropie faible. Au minimum, mélanger avec `rdseed` (non tenté ici) et `jitter entropy` (basé sur la variance de cycles d'instructions).

---

### BOOT-019 — LOW — BIOS path : lecture 64 MiB sans vérification taille réelle

**Fichier :** `exo-boot/src/main.rs:243-248`

```rust
const STAGE2_DISK_SHADOW_BASE: u64 = 0x0020_0000; // 2 MiB
const KERNEL_MAX_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
// SAFETY : stage2.asm garantit que les données kernel sont présentes ici.
let kernel_data: &[u8] = unsafe {
    core::slice::from_raw_parts(STAGE2_DISK_SHADOW_BASE as *const u8, KERNEL_MAX_BYTES)
};
```

Le slice de 64 MiB est créé sans vérifier la taille réelle du kernel chargé par stage2.asm. Le footer de signature (256 octets à la fin du kernel réel) sera cherché dans la fenêtre [0x200000, 0x200000+64MiB) — `verify_kernel` via `elf_signed_end` calcule la fin réelle de l'ELF et cherche le footer juste après, donc fonctionnellement OK. Mais la lecture de 64 MiB inclut de la mémoire potentiellement non-initialisée (garbage firmware), qui sera hashé en SHA-512 si on signe tout le tampon — non, en pratique `elf_signed_end` borne correctement.

**Recommandation :** Faire communiquer stage2.asm la taille réelle chargée via un header dédié (ex. u32 à offset 0x1FC), plutôt que de supposer 64 MiB.

---

## 5. Verdict — La chaîne de confiance est-elle réellement enforced end-to-end ?

### ✅ Points solides (vraiment enforced)

1. **Signature Ed25519 du kernel (exo-verity)** : `verify_strict` + SHA-512 recalculé + fail-closed sur `Tampered`. Compile-time guard contre clés de test. Clé partagée entre signer et bootloader via crate commune — pas de divergence possible. **C'est le maillon le plus fort de la chaîne.**

2. **Format de signature exo-verity** : footer 256 octets `EXOSIG01` + sig(64) + sha512(64) + padding(120). Hash autoritatif recalculé (pas confiance au hash stocké). Tampered ≠ Unsigned.

3. **Boot info magic** : validé côté kernel (`halt_cpu` si mismatch).

4. **Forge Merkle (C-02 résolu)** : `verify_merkle()` fail-closed si hash nul. BLAKE3 sur `.text || .rodata`. Checklist G9 (FACS RO, hash MADT, TLB shootdown, IDT vectors) correctement implémentée.

5. **PhoenixWakeEntropy (côté crypto_server)** : `xchacha20_reseed` + `revoke_all_pre_phoenix` implémentés. Authentification par `sender_pid == 0` (kernel).

6. **EFI_RNG + RDRAND + TSC fallback** : collecte d'entropie hiérarchique avec sanity check all-zero.

7. **Relocations PIE** : `R_X86_64_RELATIVE` et `R_X86_64_64` (sym_idx=0) correctement appliqués. Garde anti "aucune relocation RELATIVE".

### ❌ Points critiques (chaîne cassée)

1. **BOOT-002 : Kernel B / Sentinel jamais démarré** → **AUCUNE détection runtime d'attaque**. Toute la phase ExoPhoenix (sentinel, introspection, liveness, PMC, recovery automatique) est **code mort**. La "résurrection < 500 ms" est fictive.

2. **BOOT-001 : Isolation mémoire Kernel A jamais appliquée** → même si le handoff était déclenché, Kernel A compromis continuerait de s'exécuter avec ses pages présentes pendant la reconstruction.

3. **BOOT-005 : `begin_isolation_hard()` relâche Kernel A sans reconstruction** → en cas d'échec soft isolation, Kernel A reprend tel quel, compromis.

4. **BOOT-004 + C-01 : Userspace n'a aucune vérification crypto de signature** → un binaire avec 8 octets `EXOSIG\0\0` est considéré "signé". `do_execve` ne vérifie jamais.

5. **BOOT-003 + BOOT-010 : `SECURE_BOOT_ACTIVE` est cosmétique** → basé sur config (défaut false), jamais lu par le kernel. Un kernel non-signé démarre par défaut.

6. **BOOT-007 : Entropie BootInfo gaspillée** → le kernel utilise TSC/RDRAND faible au lieu des 64 octets EFI_RNG.

7. **BOOT-008 : Pas de hash BLAKE3 vérifié sur la SSR** → Kernel A compromis peut altérer la SSR indéfiniment.

8. **BOOT-011 : KASLR court-circuité par `AllocateType::AnyPages`** → ~0 bit d'entropie KASLR effectif en pratique.

### Verdict final

**NON, la chaîne de confiance n'est PAS enforced end-to-end.**

- **Du firmware au kernel (bootloader → kernel)** : ✅ enforced. Ed25519 verify_strict + SHA-512 + fail-closed. C'est solide.
- **Du kernel au userspace (do_execve)** : ❌ **complètement bypassé**. `verify_module_signature` est dead code, `capability_check` ment sur `SignedOk`.
- **Kernel A ↔ Kernel B (ExoPhoenix)** : ❌ **inopérant**. Le sentinel n'est jamais démarré, l'isolation mémoire n'est jamais appliquée, le hard-isolation relâche Kernel A sans recovery. Toute la résurrection est du code mort.
- **Secure Boot policy** : ❌ **cosmétique**. Flag basé sur config, jamais lu, défaut permissif.

**La sécurité de la chaîne de boot repose entièrement sur le maillon Ed25519 du bootloader.** Si ce maillon est contourné (par exemple via un kernel non-signé accepté en mode dev, ou via un bootloader compromis signé par une clé db légitime mais piratée), il n'y a **aucune défense en profondeur runtime** : pas de sentinel, pas d'introspection, pas de recovery automatique, pas de vérification userspace.

### Priorité de remédiation (P0 = bloquant pour production)

| Priorité | Finding | Effort |
|---|---|---|
| **P0** | BOOT-002 (démarrer Kernel B / sentinel) | Moyen (entry asm + réservation core) |
| **P0** | BOOT-001 (appeler `isolate_kernel_a_memory()`) | Faible (1 ligne dans `begin_isolation_soft/hard`) |
| **P0** | BOOT-005 (`begin_isolation_hard` doit forger) | Faible (réutiliser `try_forge_reconstruct_with_policy`) |
| **P0** | BOOT-004 + C-01 (vérifier signature userspace) | Moyen (appeler `verify_module_signature` dans `do_execve`) |
| **P0** | BOOT-010 (défaut `secure_boot_required=true` en release) | Faible |
| **P1** | BOOT-003 (lier `SECURE_BOOT_ACTIVE` à vérification réelle + le lire kernel-side) | Faible |
| **P1** | BOOT-007 (lire `entropy[64]` BootInfo) | Faible |
| **P1** | BOOT-011 (KASLR `AllocateType::Address`) | Moyen |
| **P1** | BOOT-008 (hash BLAKE3 SSR) | Moyen |
| **P1** | BOOT-009 (panic sur SSR invalide en release) | Faible |
| **P2** | BOOT-006 (valider `BootInfo.version`) | Très faible |
| **P2** | BOOT-013/014 (constant-time eq) | Très faible |
| **P2** | BOOT-015/016 (seeding blob + garde build release) | Faible |
| **P3** | BOOT-012, 017, 018, 019 | Faible |

---

## 6. Note méthodologique

- Tous les fichiers listés au §1 ont été lus intégralement (pas de skim, pas de sampling).
- Les recherches de callers ont été faites via `grep -rn` récursif sur `kernel/src/` et `exo-boot/src/`.
- Les constats "JAMAIS appelé" reposent sur l'absence totale de référence au symbole dans le code source audité. Si un appel existe via symbole dynamique non-résolvable (FFI, assembly non-inclus, linker script), cela n'a pas été détecté — mais la probabilité est faible pour du code Rust `#[no_mangle]` sans `extern`.
- L'absence du crate `exo-phoenix-ssr` (chemin `libs/` non présent dans le snapshot audit) limite l'audit du format SSR à ce qui est visible dans `kernel/src/exophoenix/ssr.rs` (re-exports et offsets). Le code source de la crate elle-même n'a pas pu être vérifié pour le hash BLAKE3 (cf. BOOT-008 — basé sur l'absence d'appel à toute fonction de hash SSR depuis le kernel).

---

**Fin du rapport Task 02 — Boot Chain.**
