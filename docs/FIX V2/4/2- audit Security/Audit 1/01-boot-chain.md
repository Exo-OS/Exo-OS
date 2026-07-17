# AUDIT-1-BOOT — Chaîne de boot sécurisée ExoOS

> **Task ID**: AUDIT-1-BOOT
> **Date**: 2026-06-28
> **Auditeur**: sous-agent sécurité boot chain
> **Périmètre**: `exo-boot/src/**/*.rs` (33 fichiers), `loader/src/**/*.rs` (20 fichiers),
> `tools/kernel_signer/src/main.rs`, `tools/exofs_mkroot/src/main.rs`,
> `drivers/security/verity/src/lib.rs` (crate partagée exo-verity)
> **Méthode**: lecture intégrale ligne à ligne de chaque fichier .rs, sans saut

---

## 1. Résumé exécutif

La chaîne de boot d'ExoOS présente une **architecture solide sur le papier** —
crypto Ed25519 `verify_strict`, verdict enum fail-closed, clé de test refusée à
la compilation, défense en profondeur (`refuse_if_tampered`), crate partagée
`exo-verity` — mais souffre de **bugs d'intégration critiques** qui réduisent
considérablement l'efficacité des garanties annoncées.

Les **trois problèmes les plus graves** sont des erreurs d'intégration, pas des
faiblesses cryptographiques :

1. **KASLR ignoré en UEFI** (`kernel_loader/mod.rs:96`) — le résultat de
   `compute_kaslr_base` est calculé puis jeté quand `phys_dest != 0` (toujours
   le cas en UEFI). Le flag `KASLR_ENABLED` est positionné **à tort** dans
   `boot_flags`. Fausse sécurité.

2. **Adresse VGA texte fausse** (`bios/vga.rs:23`) — `0xB800_0000` au lieu de
   `0xB8000` (deux zéros en trop). Le chemin BIOS écrit à ~3 GiB au lieu du
   buffer VGA texte → affichage cassé, panic handler BIOS cassé, corruption
   mémoire silencieuse possible.

3. **KASLR + shadow buffer BIOS se chevauchent** — le shadow buffer occupe
   `[2 MiB, 66 MiB)` ; la plage KASLR est `[4 MiB, 2 GiB)`. Avec KASLR activé
   par défaut, le kernel peut être chargé **sur sa propre image source** → UB
   `copy_nonoverlapping` sur zones chevauchantes → corruption aléatoire du
   kernel au boot.

Côté loader userspace, la fonction `verify_signature::detect_signature_note`
est un **théâtre de sécurité** : elle cherche l'octet `EXOSIG\0\0` n'importe où
dans le binaire sans aucune vérification cryptographique → contournable en
insérant 8 octets. Le commentaire documente que la vraie vérif est dans
`kernel::do_execve`, mais le loader est présenté comme une barrière de
défense-en-profondeur, ce qui est trompeur.

### Compte par sévérité

| Sévérité | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH     | 9 |
| MEDIUM   | 8 |
| LOW      | 5 |
| INFO     | 4 |
| **Total**| **30** |

---

## 2. Fichiers audités (confirmation de lecture intégrale)

### exo-boot/src/ (33 fichiers .rs)

| Fichier | Lignes | Lu |
|---------|--------|----|
| main.rs | 338 | ✅ |
| panic.rs | 107 | ✅ |
| config/mod.rs | 80 | ✅ |
| config/defaults.rs | 113 | ✅ |
| config/parser.rs | 169 | ✅ |
| bios/mod.rs | 204 | ✅ |
| bios/vga.rs | 265 | ✅ |
| bios/disk.rs | 314 | ✅ |
| display/mod.rs | 93 | ✅ |
| display/framebuffer.rs | 433 | ✅ |
| display/font.rs | 517 | ✅ |
| disk/mod.rs | 7 | ✅ |
| disk/gpt.rs | 160 | ✅ |
| memory/mod.rs | 47 | ✅ |
| memory/paging.rs | 344 | ✅ |
| memory/regions.rs | 252 | ✅ |
| memory/map.rs | 386 | ✅ |
| uefi/mod.rs | 20 | ✅ |
| uefi/entry.rs | 134 | ✅ |
| uefi/secure_boot.rs | 104 | ✅ |
| uefi/services.rs | 234 | ✅ |
| uefi/exit.rs | 104 | ✅ |
| uefi/protocols/mod.rs | 16 | ✅ |
| uefi/protocols/rng.rs | 251 | ✅ |
| uefi/protocols/graphics.rs | 177 | ✅ |
| uefi/protocols/file.rs | 268 | ✅ |
| uefi/protocols/loaded_image.rs | 104 | ✅ |
| kernel_loader/mod.rs | 156 | ✅ |
| kernel_loader/verify.rs | 180 | ✅ |
| kernel_loader/signing_key.rs | 15 | ✅ |
| kernel_loader/elf.rs | 515 | ✅ |
| kernel_loader/relocations.rs | 254 | ✅ |
| kernel_loader/handoff.rs | 304 | ✅ |

### loader/src/ (20 fichiers .rs)

| Fichier | Lignes | Lu |
|---------|--------|----|
| main.rs | 128 | ✅ |
| lib.rs | 13 | ✅ |
| entry.rs | 21 | ✅ |
| elf/mod.rs | 7 | ✅ |
| elf/parser.rs | 215 | ✅ |
| elf/validator.rs | 17 | ✅ |
| elf/segments.rs | 122 | ✅ |
| elf/dynamic.rs | 187 | ✅ |
| elf/relocations.rs | 99 | ✅ |
| elf/tls.rs | 9 | ✅ |
| security/mod.rs | 4 | ✅ |
| security/capability_check.rs | 63 | ✅ |
| security/pie_aslr.rs | 8 | ✅ |
| security/verify_signature.rs | 14 | ✅ |
| dynamic_linker/mod.rs | 176 | ✅ |
| dynamic_linker/resolver.rs | 6 | ✅ |
| dynamic_linker/symbol_table.rs | 7 | ✅ |
| dynamic_linker/library.rs | 5 | ✅ |
| dynamic_linker/search_path.rs | 2 | ✅ |
| dynamic_linker/version.rs | 2 | ✅ |

### tools/ et crate partagée

| Fichier | Lignes | Lu |
|---------|--------|----|
| tools/kernel_signer/src/main.rs | 293 | ✅ |
| tools/exofs_mkroot/src/main.rs | 699 | ✅ |
| drivers/security/verity/src/lib.rs | 334 | ✅ |

**Total**: 57 fichiers .rs lus en intégralité.

---

## 3. Schéma de la chaîne de confiance

```
┌─────────────────────────────────────────────────────────────────────┐
│                    FIRMWARE UEFI (Secure Boot DB)                    │
│  Vérifie signature PE32+ de exo-boot.efi via certificat dans db     │
└───────────────────────────────┬─────────────────────────────────────┘
                                 │ Niveau 1 (hardware/firmware)
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     exo-boot.efi (bootloader Rust)                    │
│                                                                      │
│  ┌─ config/parser.rs     ← exo-boot.cfg (FAT32/ESP)                 │
│  │  └ secure_boot_required = false (DÉFAUT!) ⚠                      │
│  │                                                                  │
│  ├─ uefi/secure_boot.rs ← lit SecureBoot/SetupMode/AuditMode/...    │
│  │                                                                  │
│  ├─ uefi/protocols/file.rs ← charge kernel.elf (64 MB max)          │
│  │                                                                  │
│  ├─ kernel_loader/verify.rs ← exo_verity::verify_image              │
│  │   ├─ Footer EXOSIG01 (256 octets, fin de l'ELF)                  │
│  │   ├─ SHA-512 du corps recalculé (pas de confiance au hash stocké)│
│  │   ├─ Ed25519 verify_strict (anti-malléabilité, cofacteur 8)      │
│  │   ├─ KernelVerdict: Verified / Unsigned / Tampered / NoVerifierKey│
│  │   └─ Garde de compilation: clé de test refusée                    │
│  │                                                                  │
│  ├─ kernel_loader/signing_key.rs ← KERNEL_SIGNING_PUBLIC_KEY (32 o)  │
│  │   └─ Générée par tools/kernel_signer keygen (getrandom)           │
│  │                                                                  │
│  ├─ uefi/protocols/rng.rs ← EFI_RNG → RDRAND → TSC (64 octets)      │
│  │                                                                  │
│  ├─ kernel_loader/elf.rs ← parse ELF64 + charge PT_LOAD              │
│  │                                                                  │
│  ├─ kernel_loader/relocations.rs ← R_X86_64_RELATIVE + R_X86_64_64   │
│  │   └─ compute_kaslr_base (XOR + rotate sur 64 octets entropie)     │
│  │                                                                  │
│  ├─ memory/paging.rs ← PML4 identité [0,4 GiB] + higher-half        │
│  │   └─ ⚠ enable_nxe() défini mais JAMAIS appelé                    │
│  │                                                                  │
│  ├─ kernel_loader/handoff.rs ← BootInfo (magic + version + régions)  │
│  │                                                                  │
│  └─ handoff_to_kernel: mov cr3; mov eax,EXOBOOT_MAGIC; jmp _start_uefi│
└───────────────────────────────┬─────────────────────────────────────┘
                                 │ Niveau 2 (bootloader → kernel)
                                 ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        kernel.elf (kernel Rust)                       │
│  Vérifie BootInfo.is_valid() (magic + version)                       │
│  Reprend page tables, installe GDT/IDT, active NX...                 │
└─────────────────────────────────────────────────────────────────────┘

Chemin BIOS (legacy):
  MBR (asm) → stage2 (asm, real→long mode) → exoboot_main_bios()
  kernel lu depuis shadow buffer @ 0x200000 (64 MiB)
  Pas de UEFI Secure Boot → enforcing = secure_boot_required (config)
```

### Points de rupture identifiés

| # | Point | Risque |
|---|-------|--------|
| R1 | `secure_boot_required = false` par défaut | Kernel non signé démarre en dev sans UEFI SB |
| R2 | KASLR ignoré en UEFI (`phys_dest != 0`) | Adresse kernel prévisible |
| R3 | `boot_flags.SECURE_BOOT_ACTIVE` = config, pas vérif réelle | Kernel trompé sur l'état |
| R4 | `enable_nxe()` jamais appelé | Toute la mémoire boot est exécutable |
| R5 | VGA `0xB800_0000` au lieu de `0xB8000` | BIOS path cassé |
| R6 | KASLR + shadow buffer overlap | Corruption kernel en BIOS |
| R7 | `loader/security/verify_signature.rs` trivial bypass | Défense-en-profondeur loader = théâtre |
| R8 | `pie_aslr::deterministic_slide` déterministe | ASLR userspace prévisible si seed devinable |
| R9 | Pas de rollback protection | Kernel ancien/vulnérable signé démarre |
| R10 | Relocations sans bounds check |_write_unaligned hors image (kernel signé atténue)|

---

## 4. Findings classés par sévérité

### 4.1 CRITICAL

---

#### BOOT-CRIT-01 — KASLR ignoré en chemin UEFI (fausse sécurité)

**Fichier**: `exo-boot/src/kernel_loader/mod.rs:92-104`
**Catégorie**: LOGIC / INTEGRITY
**CVSS**: 7.5 (AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Constat**

```rust
let (phys_base, virt_base) = if params.kaslr_enabled && elf.is_pie {
    let (pb, vb) = compute_kaslr_base(&params.entropy);
    // Si phys_dest == 0, utilise la base KASLR calculée
    if phys_dest == 0 { (pb, vb) }       // ← seulement si phys_dest == 0
    else {
        let virt = crate::kernel_loader::handoff::kernel_virtual_base(phys_dest);
        (phys_dest, virt)                  // ← KASLR ignoré !
    }
} else { ... };
```

En chemin UEFI, `phys_dest` est l'adresse retournée par
`boot_services.allocate_pages(AllocateType::AnyPages, ...)` — **jamais 0**.
Le résultat de `compute_kaslr_base` est calculé (consommant l'entropie) puis
**jeté**. Le kernel est chargé à l'adresse UEFI-allouée (déterministe selon le
firmware).

Pire, dans `main.rs:184` :
```rust
if cfg.kaslr_enabled { flags |= KASLR_ENABLED; }
```
Le flag `KASLR_ENABLED` est positionné dans `boot_flags` **même quand KASLR
n'a pas été appliqué**. Le kernel ne peut pas distinguer "KASLR actif" de
"KASLR configuré mais ignoré".

**Impact**: KASLR est cosmétique en UEFI. Un attaquant avec connaissance du
firmware peut prédire l'adresse du kernel. Contourne la protection
SEC-07/KASLR documentée dans `SECURITY.md`.

**Recommandation**:
1. En UEFI, utiliser `AllocateType::Address(kaslr_base)` pour allouer les
   pages à l'adresse KASLR calculée (après vérification de disponibilité).
2. Ne positionner `KASLR_ENABLED` que si `phys_base == kaslr_base` calculé.
3. Ajouter un test d'intégration vérifiant que deux boots consécutifs avec
   entropie différente produisent des `phys_base` différents.

---

#### BOOT-CRIT-02 — Adresse VGA texte fausse (BIOS path cassé)

**Fichier**: `exo-boot/src/bios/vga.rs:23`
**Catégorie**: LOGIC / MEMSAFE

**Constat**

```rust
/// Adresse physique du framebuffer VGA texte (0xB8000 — plan vidéo MMIO).
const VGA_BUFFER_BASE: usize = 0xB800_0000;  // ← 0xB8000000, pas 0xB8000 !
```

Le commentaire dit `0xB8000` (753 664, ~738 KiB — adresse standard VGA texte).
Le code utilise `0xB800_0000` (3 035 388 928, ~2.83 GiB). Deux zéros en trop.

Tous les `VgaWriter::write_byte`, `clear`, `scroll_up`, `move_cursor` écrivent
à cette adresse fausse. Conséquences selon le système :
- **RAM présente > 3 GiB**: corruption silencieuse de la mémoire à ~2.83 GiB.
- **MMIO/PCI hole à cette adresse**: comportement indéfini (possible fault).
- **Mémoire non mappée**: page fault → triple fault → reboot en boucle.

Le panic handler BIOS (`panic.rs:62-69`) utilise `VgaWriter` → les messages de
panic ne sont jamais affichés en BIOS. Le boot BIOS est donc **sans diagnostic
possible** en cas d'erreur.

**Impact**: Chemin BIOS entièrement cassé pour l'affichage. Tout panic
BIOS → reboot silencieux. Corruption mémoire possible selon topologie.

**Recommandation**: `const VGA_BUFFER_BASE: usize = 0xB8000;`

---

#### BOOT-CRIT-03 — KASLR BIOS charge le kernel sur sa propre image source

**Fichier**: `exo-boot/src/main.rs:243-248`, `kernel_loader/mod.rs:92-96`,
`relocations.rs:80-93`
**Catégorie**: MEMSAFE / LOGIC

**Constat**

En BIOS, stage2.asm charge le kernel à `STAGE2_DISK_SHADOW_BASE = 0x200000`
(2 MiB), dans un buffer de 64 MiB → plage `[2 MiB, 66 MiB)`.

KASLR (`relocations.rs:82-88`):
```rust
const PHYS_MIN: u64 = 4 * 1024 * 1024;       // 4 MiB
const PHYS_MAX: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const STEP:     u64 = HUGE_PAGE_SIZE as u64;   // 2 MiB
let range = (PHYS_MAX - PHYS_MIN) / STEP;     // 510 positions
let offset = (mixed % range) * STEP;
let phys_base = PHYS_MIN + offset;            // ∈ [4 MiB, 2 GiB)
```

En BIOS, `phys_dest = 0` → `phys_base = kaslr_base` calculé. Si KASLR tire
dans `[4 MiB, 66 MiB)` (≈ 3% de probabilité), `elf.load_segments(phys_base)`
copie depuis `self.data` (pointeur vers 0x200000) vers `phys_base` (ex: 0x400000).

Les plages source `[2 MiB, 2 MiB + kernel_size)` et destination
`[phys_base, phys_base + kernel_size)` se chevauchent si
`phys_base < 2 MiB + kernel_size`.

`load_segments` utilise `core::ptr::copy_nonoverlapping` (`elf.rs:306`) —
UB sur zones chevauchantes. Corruption non déterministe du kernel chargé.

**Impact**: ~3% des boots BIOS avec KASLR activé (défaut) corrompent le
kernel au chargement. Boot instable, panic aléatoire post-handoff, ou
exécution de code corrompu.

**Recommandation**:
1. En BIOS, soit désactiver KASLR par défaut, soit réserver le shadow buffer
   en dehors de la plage KASLR (ex: le déplacer à `64 MiB` minimum, et
   `PHYS_MIN = 68 MiB`).
2. Ajouter un `assert!` dans `load_kernel` vérifiant que
   `[phys_base, phys_base + load_size)` ne chevauche pas
   `[elf_phys_addr, elf_phys_addr + elf_data.len())`.
3. Utiliser `copy_overlapping` (ou vérifier + memmove) au lieu de
   `copy_nonoverlapping` comme défense en profondeur.

---

#### BOOT-CRIT-04 — `loader/security/verify_signature.rs` : bypass trivial

**Fichier**: `loader/src/security/verify_signature.rs:7-13`
**Catégorie**: INTEGRITY / CRYPTO

**Constat**

```rust
pub fn detect_signature_note(image: &[u8]) -> SignatureState {
    if image.windows(8).any(|w| w == b"EXOSIG\0\0") {
        SignatureState::Present
    } else {
        SignatureState::Unsigned
    }
}
```

La "détection de signature" cherche l'octet `EXOSIG\0\0` **n'importe où** dans
le binaire — sans aucune vérification cryptographique. N'importe quel
attaquant peut inclure ces 8 octets dans un commentaire, une chaîne de
caractères, ou le padding d'une section ELF pour passer la détection.

`capability_check.rs:34-56` utilise ce résultat pour décider
`SignedOk` vs `UnsignedAllowed`/`Denied`. Un binaire malveillant avec
`EXOSIG\0\0` embeddé est marqué `SignedOk` et potentiellement exécuté sans
avertissement même en mode `require_signature = true` (si la vraie vérif
kernel est absente ou contournable).

Le commentaire dans `capability_check.rs:30-33` documente:
> "La vérification cryptographique complète est faite dans kernel::do_execve()
>  via security::verify_module_signature()."

Cela fait du loader une **barrière illusoire** — présentée comme
défense-en-profondeur mais sans valeur cryptographique.

**Impact**: Contournement trivial de la gate "signature requise" du loader.
Si le kernel n'appelle pas `verify_module_signature()` correctement (ou pour
les binaires non couverts), exécution de code non authentifié.

**Recommandation**:
1. Le loader ne devrait **pas** déclarer `SignedOk` sans vérification
   cryptographique réelle. Renommer en `SignatureMarkerPresent` pour
   refléter ce que c'est réellement (une heuristique de détection).
2. Idéalement, appeler `exo_verity::verify_image` depuis le loader si le
   footer EXOSIG01 est présent (la crate est no_std-compatible).
3. Ne jamais utiliser `SignatureState::Present` comme condition d'exécution
   sans vérification crypto — c'est de la fausse sécurité.

---

### 4.2 HIGH

---

#### BOOT-HIGH-05 — `secure_boot_required = false` par défaut

**Fichier**: `exo-boot/src/config/defaults.rs:49`
**Catégorie**: INTEGRITY

**Constat**

```rust
secure_boot_required:  false,  // Désactivé — pour compatibilité dev
```

La politique fail-closed documentée dans `VERIFIED-BOOT.md` (tableau de la
fonction `decide`) ne s'active que si `secure_boot_required = true` (config)
OU `uefi_sb_enforcing` (firmware). En l'absence des deux, un kernel non signé
démarre avec un simple avertissement.

Sur une machine **sans UEFI Secure Boot** (VM QEMU, machine physique legacy,
ou firmware avec SB désactivé) et **sans fichier de config** (cas par défaut),
la chaîne de confiance est désactivée.

Le doc `VERIFIED-BOOT.md` identifie ceci comme un problème historique
("secure_boot_required = false par défaut") mais le code reste inchangé.

**Impact**: Sur systèmes non-UEFI-SB, kernel non signé démarre sans obstacle.

**Recommandation**:
1. En build "production" (feature flag `production-strict`), asserter à la
   compilation que `default_config()` retourne `secure_boot_required: true`.
2. Émettre un avertissement **bruyant** (rouge clignotant sur framebuffer)
   au boot si `!secure_boot_required && !uefi_sb_enforcing`.
3. Idéalement: `secure_boot_required = true` par défaut, override explicite
   via config pour le dev.

---

#### BOOT-HIGH-06 — `SECURE_BOOT_ACTIVE` basé sur la config, pas sur la vérif

**Fichier**: `exo-boot/src/main.rs:185`
**Catégorie**: INTEGRITY / LOGIC

**Constat**

```rust
if cfg.secure_boot_required                { flags |= SECURE_BOOT_ACTIVE; }
```

Le flag `SECURE_BOOT_ACTIVE` dans `boot_flags` est positionné selon la
**configuration** (`cfg.secure_boot_required`), pas selon le **résultat réel**
de la vérification.

Scénario problématique:
- UEFI Secure Boot **enforcing** au niveau firmware → `uefi_sb_enforcing = true`
- Config: `secure_boot_required = false`
- `enforce_or_panic` utilise `require_signed || uefi_sb_enforcing` = true →
  kernel vérifié et refusé si non signé. ✅
- Mais `boot_flags` ne positionne **pas** `SECURE_BOOT_ACTIVE` car
  `cfg.secure_boot_required = false`. ❌

Le kernel reçoit donc `boot_flags` sans `SECURE_BOOT_ACTIVE` alors que la
signature a été vérifiée. Si le kernel utilise ce flag pour décider d'activer
des protections runtime, il ne les activera pas.

**Recommandation**: Positionner `SECURE_BOOT_ACTIVE` si
`cfg.secure_boot_required || uefi_sb_enforcing` (et le kernel est `Verified`).

---

#### BOOT-HIGH-07 — `enable_nxe()` défini mais jamais appelé (W^X non respecté)

**Fichier**: `exo-boot/src/memory/paging.rs:288-318`, `main.rs:199-206`
**Catégorie**: MEMSAFE / LOGIC

**Constat**

`paging.rs` définit `flags::NO_EXECUTE` (bit 63) et la fonction
`enable_nxe()` (active EFER.NXE). Mais:
1. `enable_nxe()` n'est **jamais appelée** dans `main.rs` ni `handoff.rs`.
2. Aucune entrée de page n'utilise `flags::NO_EXECUTE`.

Les tables de pages initiales (`setup_kernel_page_tables`) mappent 4 GiB en
identité + 4 GiB en higher-half, toutes en `HUGE_RW | GLOBAL` — **lisible,
écrivable, ET exécutable**. La pile, les données, le BSS, les données UEFI,
le framebuffer — tout est exécutable.

Pendant la fenêtre de boot (entre `setup_kernel_page_tables` et le moment où
le kernel installe ses propres tables + active NXE), toute corruption mémoire
est exploitable en code execution.

**Impact**: Violation W^X pendant le boot. Surface d'attaque étendue si une
vulnérabilité mémoire est exploitable dans le bootloader ou pendant la fenêtre
pre-kernel-init.

**Recommandation**:
1. Appeler `enable_nxe()` avant `setup_kernel_page_tables` dans `main.rs`.
2. Marquer les pages de données (LOADER_DATA, BSS, framebuffer) avec
   `NO_EXECUTE` dans les tables initiales.
3. Les pages de code kernel (PT_LOAD avec PF_X uniquement) sans `WRITABLE`.

---

#### BOOT-HIGH-08 — Pas de rollback protection (anti-downgrade)

**Fichier**: `exo-boot/src/kernel_loader/verify.rs` (général)
**Catégorie**: INTEGRITY

**Constat**

La vérification de signature garantit l'**authenticité** du kernel mais pas sa
**fraîcheur**. Un kernel signé avec une ancienne version (potentiellement
vulnérable) peut être chargé sans objection. Le footer EXOSIG01 ne contient
pas de numéro de version monotonique ni de compteur anti-rollback.

`SECURITY.md` documente les invariants SEC-01 à SEC-05, mais aucun n'aborde
le rollback. Le doc `AUDIT-100-PERCENT.md` mentionne que `code_signing.rs`
(kernel) a une "version monotone + snapshot/rollback" pour les modules ML,
mais le boot chain n'a pas l'équivalent.

**Impact**: Un attaquant avec accès à un kernel signé ancien (volé ou
récupéré) peut rétrograder le système vers une version vulnérable.

**Recommandation**:
1. Ajouter un champ `version: u32` (ou `counter: u64`) dans le footer
   EXOSIG01, signé avec le reste.
2. Stocker le dernier numéro de version vu dans une variable UEFI
   authentifiée (Authenticated Variable) ou un registre TPM PCR étendu.
3. Refuser le boot si `footer.version < stored_version`.

---

#### BOOT-HIGH-09 — `pie_aslr::deterministic_slide` déterministe

**Fichier**: `loader/src/security/pie_aslr.rs:1-7`
**Catégorie**: CRYPTO / LOGIC

**Constat**

```rust
pub fn deterministic_slide(seed: u64, max_slide_pages: u64) -> u64 {
    if max_slide_pages == 0 { return 0; }
    let mixed = seed ^ seed.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
    (mixed % max_slide_pages) * 4096
}
```

L'ASLR userspace est calculé par une fonction **purement déterministe** avec
un seed 64-bit. Si le seed est prédictible (dérivé du PID, du TSC, ou pire,
d'une constante), le slide est calculable par l'attaquant.

Le mixing est faible (XOR + rotate, pas de hash cryptographique). Avec
`max_slide_pages` petit (ex: 256 = 1 MiB de slide), l'espace de recherche est
réduit.

Le nom `deterministic_slide` est au moins honnête, mais l'utilisation comme
ASLR est problématique si le seed n'est pas CSPRNG-derived.

**Impact**: ASLR userspace potentiellement prédictible → contournement d'ASLR
pour les exploit userspace.

**Recommandation**:
1. Le seed doit provenir d'un CSPRNG (le kernel passe l'entropie du bootloader
   au loader). Vérifier l'origine du seed côté kernel.
2. Utiliser un vrai PRNG (ChaCha8, PCG) plutôt que XOR+rotate.
3. Augmenter `max_slide_pages` (au moins 4096 = 16 MiB) pour un meilleur
   espace de randomisation.

---

#### BOOT-HIGH-10 — Relocations PIE sans bounds check (arbitrary write potentiel)

**Fichier**: `exo-boot/src/kernel_loader/relocations.rs:184-201`
**Catégorie**: MEMSAFE

**Constat**

```rust
R_X86_64_RELATIVE => {
    let target_voff = rela.r_offset - elf.virt_base();   // ← sous-flottement possible
    let target_phys = phys_load_base + target_voff;
    let value = phys_load_base.wrapping_add_signed(rela.r_addend);
    unsafe { core::ptr::write_unaligned(target_phys as *mut u64, value); }  // ← pas de bounds check
    applied_relative += 1;
}
```

Si `rela.r_offset < elf.virt_base()`, `target_voff` underflow (en u64) →
`target_phys` gigantesque → écriture à une adresse physique arbitraire.

De même pour `R_X86_64_64` (ligne 196-201).

La table RELA provient du kernel signé, donc un attaquant ne peut pas l'injecter
sans invalider la signature. Mais:
1. Un bug dans le toolchain (linker) pourrait produire des relocations invalides.
2. La défense en profondeur exigerait un bounds check.
3. Le `rela_phys` (ligne 170) est calculé de la même façon — lecture OOB possible
   si `rela_vaddr < elf.virt_base()`.

Le loader userspace (`loader/src/elf/relocations.rs:74-76`) a le même pattern:
```rust
let target = load_base
    .checked_add(rela.offset)
    .ok_or(RelocationError::OutOfRange)? as *mut u64;
```
Ici au moins `checked_add` protège contre l'overflow, mais pas contre
`rela.offset` pointant hors des segments mappés.

**Impact**: Faible probabilité (kernel signé), mais en cas de bug toolchain
ou de corruption mémoire, écriture arbitraire en mémoire physique.

**Recommandation**:
1. Valider `rela.r_offset` est dans `[virt_base, virt_end)`.
2. Valider `rela_vaddr` est dans `[virt_base, virt_end)`.
3. Idem pour le loader userspace: valider `rela.offset` dans les segments.

---

#### BOOT-HIGH-11 — Aucune zeroization mémoire après usage (clés résiduelles)

**Fichier**: `exo-boot/src/main.rs` (général), `uefi/services.rs:48`
**Catégorie**: LEAK

**Constat**

Pendant le boot, plusieurs buffers sensibles sont alloués en mémoire UEFI
(LOADER_DATA) et **jamais zeroïsés**:
- `kernel_data` (FileBuffer, `file.rs:127-130`) — contient le kernel signé
  (avec footer EXOSIG01 incluant la signature et le hash).
- `BOOT_INFO` (static, `main.rs:165`) — contient l'entropie 64 octets.
- Le pool de tables de pages (`paging.rs:242`) — zeroïsé à l'allocation,
  mais les tables finales ne le sont pas après handoff.
- L'entropie collectée est copiée dans `BootInfo.entropy` puis reste aussi
  dans les variables locales `entropy` (stack).

Après handoff, le kernel "réclame" la mémoire LOADER_DATA
(`MemoryKind::BootloaderReclaimable`). Si le kernel ne zeroïse pas ces
régions avant de les ajouter au buddy allocator, l'entropie boot et les
données du kernel signé sont lisibles dans la mémoire libre.

`services.rs:48` zeroïse les pages allouées par `allocate_pages`, mais le
wrapper n'est pas utilisé partout (`main.rs:133` appelle `allocate_pages`
directement sur le BootServices).

**Impact**: Fuite d'entropie boot et de données kernel dans la mémoire libre
post-boot. Un exploit userspace avec lecture de mémoire libre pourrait
récupérer l'entropie KASLR.

**Recommandation**:
1. Zeroïser `kernel_data` et `entropy` avant handoff (ou marquer les régions
   comme "à zeroïser" dans BootInfo pour que le kernel le fasse).
2. Documenter que le kernel DOIT zeroïser `BootloaderReclaimable` avant usage.
3. Considérer `zeroize` crate pour les variables stack contenant l'entropie.

---

#### BOOT-HIGH-12 — `kernel_signer` : écriture non-atomique (corruption possible)

**Fichier**: `tools/kernel_signer/src/main.rs:194-199`
**Catégorie**: INTEGRITY

**Constat**

```rust
match sign_image(body, &seed) {
    Ok(signed) => {
        if let Err(e) = fs::write(elf_path, &signed) {  // ← écriture directe
            ...
        }
        ...
    }
    ...
}
```

`fs::write` ouvre le fichier, tronque, écrit, ferme — sans atomicité. Si le
processus est interrompu (Ctrl-C, OOM, crash) pendant l'écriture, le kernel
ELF est laissé dans un état partiellement écrit → ELF corrompu.

Le Makefile appelle `sign-kernel` automatiquement pendant `make build`. Une
interruption → kernel corrompu → build suivant échoue silencieusement ou
produit un kernel non fonctionnel.

**Impact**: Corruption du kernel ELF en cas d'interruption pendant la
signature. DoS build, potentiellement kernel non bootable.

**Recommandation**: Écrire dans un fichier temporaire (`.elf.sigtmp`) puis
`fs::rename` (atomique sur même filesystem).

---

#### BOOT-HIGH-13 — RNG fallback TSC seul est cryptographiquement faible

**Fichier**: `exo-boot/src/uefi/protocols/rng.rs:176-225`
**Catégorie**: CRYPTO

**Constat**

Si `EFI_RNG_PROTOCOL` est absent ET RDRAND indisponible (CPU ancien ou
désactivé), le fallback `collect_via_tsc_fallback` utilise uniquement le
TSC (timestamp counter) mixé avec un XOR + Fibonacci hashing.

```rust
let mixed = tsc ^ (chunk as u64 * 0x9e3779b97f4a7c15);
```

Le TSC est prévisible pour un attaquant qui contrôle l'environnement
(machines virtuelles, boot timed, etc.). L'avertissement est documenté
(`AVERTISSEMENT : Le fallback TSC seul n'est PAS cryptographiquement sûr`)
mais aucune mesure de mitigation n'est prise.

`main.rs:123-124`:
```rust
let entropy = uefi::protocols::rng::collect_entropy(boot_services, 64)
    .expect("EFI_RNG_PROTOCOL indisponible");
```

Si `collect_entropy` retourne le fallback TSC, le boot continue avec une
entropie faible. KASLR (si appliqué en BIOS) et le CSPRNG kernel sont
affaiblis.

**Impact**: KASLR/CSPRNG prévisibles sur systèmes sans EFI_RNG ni RDRAND.

**Recommandation**:
1. Si seul le TSC est disponible, émettre un avertissement **bruyant** et
   considérer refuser le boot en mode strict.
2. Ajouter d'autres sources d'entropie: RTC, i8254 timer, NIC MAC (si dispo),
   MTRR/MSR values, UEFI memory map layout.
3. Mélanger avec un vrai hash (BLAKE3) plutôt que XOR.

---

### 4.3 MEDIUM

---

#### BOOT-MED-14 — Comparaison de hash SHA-512 non constant-time

**Fichier**: `drivers/security/verity/src/lib.rs:187`
**Catégorie**: CRYPTO / LEAK

**Constat**

```rust
if digest.as_slice() != stored_sha {
    return KernelVerdict::Tampered;
}
```

La comparaison `!=` sur slice utilise une comparaison byte-à-byte qui
**court-circuite** au premier octet différent → timing oracle potentiel.

En pratique, l'attaquant ne contrôle pas `stored_sha` indépendamment du corps
(les deux sont dans l'image signée). Mais en défense en profondeur, une
comparaison constant-time est attendue.

**Impact**: Faible (l'attaquant ne peut pas exploiter le timing pour forger
une signature), mais non-idéomatique pour du code crypto.

**Recommandation**: Utiliser `subtle::ConstantTimeEq` ou
`constant_time_eq::ct_eq`.

---

#### BOOT-MED-15 — Config parser : pas de limite de taille de fichier/ligne

**Fichier**: `exo-boot/src/config/parser.rs:29-67`
**Catégorie**: MEMSAFE / LOGIC

**Constat**

Le parser lit le buffer entier (jusqu'à 64 MB, limite de `load_file`) et
`split('\n')` crée un itérateur sur toutes les lignes. `MAX_LINES = 64`
limite le nombre de lignes traitées, mais une seule ligne de plusieurs
mégaoctets (sans `\n`) est traitée entièrement par `split_once('=')` et
`trim()`.

Le `kernel_path` est limité à 256 chars, mais les autres valeurs booléennes
et entières sont parsées sans consommation excessive.

Cependant, `text.split('\n')` alloue des sous-slices pour chaque ligne — en
`no_std` sans heap, c'est un itérateur, donc OK. Mais si le fichier de config
est énorme (64 MB de `#` comments), le parser itère sur 64 MB de données pour
rien.

**Impact**: Faible. Au pire, latence de boot accrue. Pas d'OOM (no heap).

**Recommandation**: Limiter la taille du buffer de config à 4 KiB dans
`load_config_uefi` (un fichier de config ne devrait pas dépasser quelques
centaines d'octets).

---

#### BOOT-MED-16 — `exofs_mkroot` : passphrase en argument ligne de commande

**Fichier**: `tools/exofs_mkroot/src/main.rs:163, 184-186`
**Catégorie**: LEAK

**Constat**

```rust
let passphrase = args.opt_value_from_str::<_, String>("--passphrase")?;
...
if encrypt && passphrase.is_none() {
    return Err("--encrypt requires --passphrase".into());
}
```

La passphrase de chiffrement du volume est passée en argument de la ligne de
commande → visible dans `/proc/<pid>/cmdline`, `ps aux`, l'historique shell,
les logs CI/CD.

**Impact**: Fuite de la passphrase de chiffrement du volume racine.

**Recommandation**:
1. Ajouter `--passphrase-file PATH` qui lit depuis un fichier (ou stdin).
2. Déprécier `--passphrase` direct avec un avertissement.
3. Documenter l'usage en CI: `--passphrase-file <(printf '%s' "$PW")`.

---

#### BOOT-MED-17 — `loaded_image.rs` : image_base/image_size toujours 0

**Fichier**: `exo-boot/src/uefi/protocols/loaded_image.rs:53-54`
**Catégorie**: LOGIC

**Constat**

```rust
let image_base = 0u64; // LoadedImage 0.26 n'expose pas image_base directement
let image_size = 0u64;
```

`image_base` et `image_size` sont hardcodés à 0. Si le kernel ou un
mécanisme de sécurité utilise ces valeurs pour vérifier l'intégrité du
bootloader en mémoire (comparer avec l'image sur disque), ils obtiendront 0 →
la vérification est meaningless.

Le commentaire reconnait le problème ("fallback 0 — rarement nécessaires").

**Impact**: Impossible de faire du runtime attestation du bootloader depuis le
kernel. Si le bootloader est altéré en mémoire (DMA attack, etc.), le kernel
ne peut pas le détecter.

**Recommandation**: Accéder à `LoadedImage::info()` ou utiliser l'API brute
`EFI_LOADED_IMAGE_PROTOCOL` pour récupérer `ImageBase` et `ImageSize`.

---

#### BOOT-MED-18 — `verify.rs::elf_file_end` : phnum capped à 256

**Fichier**: `exo-boot/src/kernel_loader/verify.rs:93`
**Catégorie**: LOGIC

**Constat**

```rust
let phnum_capped = phnum.min(256); // garde-fou anti-en-tête corrompu
```

Pour calculer `elf_file_end` (utilisé par le chemin BIOS pour localiser le
footer de signature), seuls les 256 premiers program headers sont considérés.
Si `phnum > 256`, les segments au-delà ne contribuent pas au calcul de
`end` → `elf_file_end` pourrait être sous-estimé.

Comme l'en-tête ELF (incluant `e_phnum`) fait partie du corps signé, un
attaquant ne peut pas modifier `phnum` sans invalider la signature. Donc
l'exploit nécessiterait un kernel légitime avec > 256 segments (très rare).

Le `ElfKernel::parse` (côté loader) ne cappe PAS phnum — il itère tous les
program headers. Une divergence entre le vérificateur (256 max) et le loader
(tous) pourrait théoriquement permettre à des segments non vérifiés d'être
chargés, mais seulement si le kernel signé a > 256 segments.

**Impact**: Faible (requiert kernel signé avec > 256 PT_LOAD), mais
divgence vérifieur/loader = dette technique.

**Recommandation**: Soit capper phnum des deux côtés (256 max légitime pour
un kernel), soit retirer le cap du vérificateur et utiliser `checked_mul`
pour la protection overflow.

---

#### BOOT-MED-19 — `bios/disk.rs` : scratch GPT lu sans validation d'adresse

**Fichier**: `exo-boot/src/bios/disk.rs:256-262`
**Catégorie**: MEMSAFE

**Constat**

```rust
let scratch: &[u8] = unsafe {
    core::slice::from_raw_parts(
        GPT_SCRATCH_BASE as *const u8,          // 0x0006_0000
        GPT_SCRATCH_SECTORS * SECTOR_SIZE,      // 34 * 512 = 17 408
    )
};
```

Le slice est créé à partir d'une adresse physique fixe (`0x60000`) sans
vérifier que:
1. Cette adresse est bien dans la RAM (pas dans un trou MMIO).
2. Stage2 a effectivement chargé les données là (contrat implicite).
3. La taille ne déborde pas dans une région réservée.

Si stage2.asm n'a pas chargé le scratch (bug, config différente), le slice
contient des données aléatoires. Le parser GPT (`exo_partition`) fait ses
propres validations (CRC, signature), donc des données aléatoires → échec
silencieux (`gpt_present = false`). Acceptable mais fragile.

**Impact**: Faible — le parsing GPT est non-fatal et validé par CRC.

**Recommandation**: Ajouter un magic number en tête du scratch (écrit par
stage2) pour confirmer que les données sont valides.

---

#### BOOT-MED-20 — Pas de vérification d'overlap des segments PT_LOAD

**Fichier**: `exo-boot/src/kernel_loader/elf.rs:274-322`
**Catégorie**: MEMSAFE

**Constat**

`load_segments` itère sur les PT_LOAD et copie chaque segment à
`phys_load_base + (p_vaddr - virt_base)`. Il n'y a pas de vérification que
deux segments ne se chevauchent pas.

Un ELF malformé avec deux segments PT_LOAD overlapping entraînerait une
corruption (le second écrase partiellement le premier). `copy_nonoverlapping`
est appelé pour chaque segment individuellement, donc l'UB est entre
segments, pas au sein d'un segment.

Comme l'ELF est signé, un attaquant ne peut pas injecter d'ELF malformé
sans invalider la signature. Mais un bug du linker pourrait produire un tel
ELF.

**Impact**: Faible (kernel signé), mais défense en profondeur manquante.

**Recommandation**: Valider que les segments PT_LOAD ne se chevauchent pas
dans `compute_virt_bounds` ou `parse`.

---

#### BOOT-MED-21 — Entropie KASLR réduite à 510 positions (9 bits)

**Fichier**: `exo-boot/src/kernel_loader/relocations.rs:80-93`
**Catégorie**: CRYPTO

**Constat**

```rust
const PHYS_MIN: u64 = 4 * 1024 * 1024;       // 4 MiB
const PHYS_MAX: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const STEP:     u64 = HUGE_PAGE_SIZE as u64;   // 2 MiB
let range = (PHYS_MAX - PHYS_MIN) / STEP;     // 510
let offset = (mixed % range) * STEP;
```

510 positions possibles = ~9 bits d'entropie KASLR. C'est faible comparé à
Linux KASLR (typiquement 512 positions × 2 MiB = ~9 bits also, mais avec
une plage plus large sur certains configs).

De plus, la plage `[4 MiB, 2 GiB)` exclut les adresses > 2 GiB, où un kernel
pourrait être moins attendu (et plus difficile à attaquer via DMA 32-bit).

**Impact**: KASLR faible (9 bits). Un attaquant par brute-force a 1/510 de
chance par essai.

**Recommandation**:
1. Étendre `PHYS_MAX` à au moins 64 GiB (range = 32 766 positions ≈ 15 bits)
   si le firmware le permet.
2. Mélanger avec l'entropie du kernel post-handoff pour re-randomiser les
   mappings.

---

### 4.4 LOW

---

#### BOOT-LOW-22 — `compute_kaslr_base` : mixing faible (XOR + rotate)

**Fichier**: `exo-boot/src/kernel_loader/relocations.rs:70-78`
**Catégorie**: CRYPTO

**Constat**

Le mixing des 64 octets d'entropie en un u64 utilise XOR + rotate_left(13) +
addition constante. Ce n'est pas un hash cryptographique — la diffusion est
limitée.

En pratique, avec 64 octets d'entropie bona fide (EFI_RNG), le biais du
mixing est négligeable. Mais si l'entropie est partielle (TSC fallback), le
biais pourrait réduire l'entropie effective en dessous de 9 bits.

**Recommandation**: Utiliser BLAKE3 ou SHA-256 pour hasher les 64 octets
d'entropie → 32 octets, puis prendre les 8 premiers comme u64.

---

#### BOOT-LOW-23 — `handoff.rs::ZEROED` : transmute de tableau de zéros

**Fichier**: `exo-boot/src/kernel_loader/handoff.rs:185`
**Catégorie**: MEMSAFE

**Constat**

```rust
pub const ZEROED: Self = unsafe { core::mem::transmute([0u8; core::mem::size_of::<Self>()]) };
```

`transmute` d'un tableau de zéros vers `BootInfo`. Si `BootInfo` a des champs
de type enum avec représentation non-zéro valide, le zéro pourrait être UB
(transmuting 0 to an enum variant that doesn't have 0 as valid discriminant).

En l'occurrence, `PixelFormat` a `None = 0xFFFF_FFFF` et `MemoryKind` a
`Empty = 0`, donc zéro est valide pour les deux. Le `const _: () = assert!`
sur la taille protège contre les changements structurels.

Mais c'est fragile — un futur ajout d'un champ enum sans variante 0 casserait.

**Recommandation**: Utiliser `core::mem::MaybeUninit::zeroed().assume_init()`
ou une fonction `const fn` qui initialise champ par champ.

---

#### BOOT-LOW-24 — `boot_print!` macro : ConOut noop (logging incomplet)

**Fichier**: `exo-boot/src/display/mod.rs:58-71`
**Catégorie**: LOGIC

**Constat**

```rust
#[cfg(feature = "uefi-boot")]
{
    // uefi_services redirige déjà via logger — noop ici
    let _ = format_args!($($arg)*);
}
```

Le commentaire dit "uefi_services redirige déjà via logger", mais le code ne
fait rien avec `format_args!` (résultat ignoré). Si `uefi_services` a un
logger global, il faut appeler `log::info!` ou similaire, pas juste
`format_args!`.

Les messages boot ne vont QUE sur le framebuffer GOP, pas sur ConOut UEFI.
Si le framebuffer est absent (headless server), les messages boot sont
invisibles.

**Impact**: Diagnostic boot difficile sur systèmes headless.

**Recommandation**: Appeler réellement le logger `uefi_services`
(`::uefi_services::println!` ou `log::info!`).

---

#### BOOT-LOW-25 — `BootInfo._reserved` non vérifié par le kernel (contrat implicite)

**Fichier**: `exo-boot/src/kernel_loader/handoff.rs:152`
**Catégorie**: INTEGRITY

**Constat**

`BootInfo._reserved: [u64; 16]` doit être à zéro (RÈGLE BOOT-03). Le
bootloader initialise via `zeroed()`, mais il n'y a pas de vérification côté
kernel que ces champs sont bien zéro. Un bootloader malveillant (ou buggy)
pourrait stocker des données dans `_reserved` qui seraient ignorées par le
kernel mais lisibles par un attaquant.

**Recommandation**: Le kernel devrait `assert!(boot_info._reserved == [0; 16])`
au démarrage.

---

#### BOOT-LOW-26 — `tls.rs` : structure TlsImage sans logique de validation

**Fichier**: `loader/src/elf/tls.rs:1-9`
**Catégorie**: LOGIC

**Constat**

`TlsImage` est une structure de données nue (5 champs u64) sans aucune
méthode, validation, ou logique. C'est un stub — le TLS n'est pas implémenté
dans le loader.

Si un binaire userspace utilise TLS (`PT_TLS`), le loader ne le gère pas →
comportement indéfini (TLS non initialisé).

**Impact**: Binaires userspace avec TLS ne fonctionnent pas correctement.

**Recommandation**: Soit implémenter le TLS (initialisation du TCB +
`fs_base`), soit documenter explicitement que TLS n'est pas supporté et
refuser les binaires avec `PT_TLS`.

---

### 4.5 INFO

---

#### BOOT-INFO-27 — Architecture exo-verity : source unique partagée (bon design)

**Fichier**: `drivers/security/verity/src/lib.rs`

La crate `exo-verity` est partagée entre le bootloader (no_std) et l'outil
de signature (std). Le format de signature et la logique de vérification
sont définis une seule fois → divergence signataire/vérificateur impossible.
C'est un excellent design pattern pour les chaînes de confiance.

La garde de compilation `const _: () = assert!(key_is_usable(...))` dans
`verify.rs:27-31` empêche de compiler un bootloader avec une clé de test —
la "fausse sécurité" ne peut pas revenir par erreur.

---

#### BOOT-INFO-28 — `enforce_or_panic` : politique fail-closed bien conçue

**Fichier**: `exo-boot/src/kernel_loader/verify.rs:126-167`

La fonction `decide` + `enforce_or_panic` implémente une politique claire:
- `Verified` → Proceed
- `Tampered` → Refuse (toujours, même en dev)
- `Unsigned` → Refuse si strict, warn si dev
- `NoVerifierKey` → Refuse si strict, warn si dev

La défense en profondeur (`refuse_if_tampered` re-vérifie juste avant le
chargement des segments) est une bonne pratique.

---

#### BOOT-INFO-29 — `boot_flags` : design extensible mais sous-utilisé

**Fichier**: `exo-boot/src/kernel_loader/handoff.rs:156-167`

Les flags `UEFI_BOOT`, `KASLR_ENABLED`, `SECURE_BOOT_ACTIVE`, `ACPI2_PRESENT`,
`FRAMEBUFFER_PRESENT` sont définis mais leur consommation côté kernel n'est
pas vérifiable depuis ce périmètre. Recommendation: tracer la consommation
de chaque flag dans le kernel pour identifier les flags non utilisés.

---

#### BOOT-INFO-30 — `EFI_RNG` sanity check all-zéros (bonne pratique)

**Fichier**: `exo-boot/src/uefi/protocols/rng.rs:87-89`

```rust
if buf[..count].iter().all(|&b| b == 0) {
    return Err(RngError::AllZeroOutput { count });
}
```

Détecte les firmwares défectueux qui retournent des zéros. Bonne défense.
Cependant, cette vérification ne détecte pas un RNG faible mais non-zéro
(ex: compteur monotone).

---

## 5. Recommandations priorisées

### P0 — Critique (corriger avant tout déploiement production)

| # | Finding | Action | Effort |
|---|---------|--------|--------|
| P0-1 | BOOT-CRIT-01 | Corriger KASLR UEFI: utiliser `AllocateType::Address(kaslr_base)` | 4h |
| P0-2 | BOOT-CRIT-02 | Corriger `VGA_BUFFER_BASE = 0xB8000` | 5 min |
| P0-3 | BOOT-CRIT-03 | Résoudre overlap shadow buffer/KASLR en BIOS | 1j |
| P0-4 | BOOT-CRIT-04 | Réimplémenter `verify_signature` du loader avec vraie crypto | 1j |

### P1 — Haute priorité

| # | Finding | Action | Effort |
|---|---------|--------|--------|
| P1-1 | BOOT-HIGH-05 | `secure_boot_required = true` en build production | 2h |
| P1-2 | BOOT-HIGH-06 | `SECURE_BOOT_ACTIVE` basé sur vérif réelle | 1h |
| P1-3 | BOOT-HIGH-07 | Appeler `enable_nxe()` + marquer pages NX | 4h |
| P1-4 | BOOT-HIGH-08 | Implémenter rollback protection (version footer + TPM) | 3j |
| P1-5 | BOOT-HIGH-09 | ASLR userspace: seed CSPRNG + vrai PRNG | 1j |
| P1-6 | BOOT-HIGH-10 | Bounds check relocations | 2h |
| P1-7 | BOOT-HIGH-11 | Zeroization mémoire post-handoff | 4h |
| P1-8 | BOOT-HIGH-12 | Écriture atomique dans kernel_signer | 1h |
| P1-9 | BOOT-HIGH-13 | RNG: refuser TSC-only en mode strict | 2h |

### P2 — Moyenne priorité

| # | Finding | Action | Effort |
|---|---------|--------|--------|
| P2-1 | BOOT-MED-14 | Comparaison constant-time hash | 30 min |
| P2-2 | BOOT-MED-15 | Limiter taille config à 4 KiB | 30 min |
| P2-3 | BOOT-MED-16 | `--passphrase-file` dans exofs_mkroot | 1h |
| P2-4 | BOOT-MED-17 | Récupérer image_base/image_size réels | 2h |
| P2-5 | BOOT-MED-18 | Cohérence phnum cap verify/loader | 1h |
| P2-6 | BOOT-MED-19 | Magic number scratch GPT BIOS | 30 min |
| P2-7 | BOOT-MED-20 | Validation overlap PT_LOAD | 2h |
| P2-8 | BOOT-MED-21 | Étendre plage KASLR à 64 GiB | 2h |

### P3 — Basse priorité / durcissement

| # | Finding | Action | Effort |
|---|---------|--------|--------|
| P3-1 | BOOT-LOW-22 | Hash BLAKE3 pour mixing KASLR | 1h |
| P3-2 | BOOT-LOW-23 | Remplacer transmute ZEROED | 30 min |
| P3-3 | BOOT-LOW-24 | Fix logging ConOut UEFI | 1h |
| P3-4 | BOOT-LOW-25 | Kernel vérifie _reserved == 0 | 15 min |
| P3-5 | BOOT-LOW-26 | Implémenter ou refuser TLS | 2j |

---

## 6. Conclusion

La chaîne de boot d'ExoOS a une **fondation cryptographique solide**
(`exo-verity`, Ed25519 `verify_strict`, garde de compilation anti-clé-test,
verdict enum fail-closed). C'est remarquable et rare.

Cependant, l'**intégration** de cette fondation dans le pipeline de boot
présente des **bugs critiques** qui annulent les garanties de sécurité
annoncées :

- **KASLR est cosmétique en UEFI** (BOOT-CRIT-01) — le calcul est fait puis
  ignoré, le flag est positionné à tort.
- **Le chemin BIOS est cassé** par l'adresse VGA fausse (BOOT-CRIT-02) et
  l'overlap KASLR/shadow (BOOT-CRIT-03).
- **Le loader userspace a une gate de signature contournable** (BOOT-CRIT-04).

Ces quatre problèmes sont des erreurs d'intégration, pas des faiblesses
cryptographiques — ils sont donc **corrigeables rapidement** (la plupart en
quelques heures). Mais ils doivent être corrigés **avant** toute prétention
de "secure boot" en production.

Le principe directeur de l'audit — « la promesse d'une fausse sécurité est
pire que l'absence de sécurité » — s'applique ici : le code **annonce** KASLR,
Secure Boot, et vérification de signature du loader, mais **ne livre pas**
ces garanties sur les chemins réels. La correction des P0/P1 restaurera la
confiance dans la chaîne de confiance.

---

*Rapport généré par AUDIT-1-BOOT. Pour chaque finding, le fichier et la ligne
exacte sont référencés pour faciliter la correction.*
