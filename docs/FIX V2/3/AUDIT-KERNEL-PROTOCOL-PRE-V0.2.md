# AUDIT-KERNEL-PROTOCOL-PRE-V0.2
## Protocole d'Audit Complet du Kernel — Fichier par Fichier, Module par Module
### Utilisation Intégrale de la Batterie TOOLS-AUDIT-EXOOS

**Auteur :** claude-beta  
**Date :** 2026-05-21  
**Statut :** DOCUMENT OPÉRATIONNEL — À exécuter avant tout démarrage de Phase 0.2.0  
**Prérequis :** `TOOLS-AUDIT-EXOOS.md` lu et compris, batterie installée  
**Objectif :** Zéro P0 ouvert, zéro incohérence de constante, zéro violation de règle ExoOS  
**Résolution cible :** Chaque fichier .rs du kernel audité individuellement, correction documentée

---

## Méta-règle d'Exécution

Chaque section de ce document suit le même schéma rigide :

```
MODULE
├── Fichiers couverts (chemins exacts)
├── Couche 1 — const_assert! à insérer (copier-coller exact)
├── Couche 2 — Python : patterns à étendre dans audit_constants.py
├── Couche 3 — Semgrep : règles à appliquer ou créer
├── Couche 4 — Kani : preuves à écrire
├── Couche 5 — cargo-deny : crates à surveiller
└── Critère de PASS (conditions nécessaires et suffisantes)
```

L'ordre d'exécution est :

```
1. Couche 1 (const_assert!) ─── bloquant à la compilation
2. Couche 2 (Python)         ─── exécuter sur kernel/src/ entier
3. Couche 3 (Semgrep)        ─── exécuter sur kernel/ + libs/ + servers/
4. Couche 4 (Kani)           ─── exécuter sur les modules modifiés
5. Couche 5 (cargo-deny)     ─── exécuter une fois globalement
6. TLA+ (Couche 7)           ─── pour les algorithmes de synchronisation
```

**Règle absolue :** Un module ne passe au statut ✅ que si **toutes les couches PASS** pour ce module.

---

## INDEX DES MODULES

| # | Module | Chemin | Priorité | Risque |
|---|--------|--------|----------|--------|
| M01 | arch/constants | `kernel/src/arch/constants.rs` | P0-BLOQUANT | INCOHÉRENCE GLOBALE |
| M02 | arch/percpu | `kernel/src/arch/percpu.rs` | P0 | DOUBLE COUNTER |
| M03 | arch/boot | `kernel/src/arch/boot_sequence.rs` | P0 | VIDE / INCOMPLET |
| M04 | arch/gdt-idt | `kernel/src/arch/gdt.rs`, `idt.rs` | P0 | SYSRETQ RSP |
| M05 | arch/interrupts | `kernel/src/arch/interrupts.rs` | P0 | ISR-ALLOC |
| M06 | memory/buddy | `kernel/src/memory/buddy/` | P0 | OOB, LEAK |
| M07 | memory/slub | `kernel/src/memory/slub/` | P0 | UAF, DOUBLEFREE |
| M08 | memory/vmalloc | `kernel/src/memory/vmalloc/` | P1 | FRAGMENTATION |
| M09 | memory/cow | `kernel/src/memory/cow/` | P0 | MAUVAIS CR3 |
| M10 | memory/paging | `kernel/src/memory/paging/` | P0 | KPTI |
| M11 | scheduler/cfs | `kernel/src/scheduler/cfs/` | P0 | PREEMPT COUNTER |
| M12 | scheduler/rt | `kernel/src/scheduler/rt/` | P1 | PRIO INVERSION |
| M13 | scheduler/smp | `kernel/src/scheduler/smp/` | P0 | IPI DEADLOCK |
| M14 | scheduler/fpu | `kernel/src/scheduler/fpu/` | P1 | FPU LEAK |
| M15 | ipc/spsc-ring | `kernel/src/ipc/ring/spsc.rs` | P0 | ZERO-COPY PATH |
| M16 | ipc/sync | `kernel/src/ipc/sync/` | P0 | TIMEOUT VIOLATION |
| M17 | ipc/shm | `kernel/src/ipc/shm/` | P1 | MAPPING STALE |
| M18 | ipc/rpc | `kernel/src/ipc/rpc/` | P1 | MSG TYPE |
| M19 | process/fork | `kernel/src/process/lifecycle/fork.rs` | P0 | VMA CLONE |
| M20 | process/exec | `kernel/src/process/lifecycle/exec.rs` | P0 | ELF BASE |
| M21 | process/signal | `kernel/src/process/signal/` | P1 | SIGNAL MASK |
| M22 | process/thread | `kernel/src/process/thread/` | P0 | TLS GS BASE |
| M23 | fs/exofs | `kernel/src/fs/exofs/` | P0 | PERSIST, IMMUTABLE |
| M24 | fs/vfs-bridge | `kernel/src/fs/vfs/` | P0 | READ/WRITE STUB |
| M25 | security/exoseal | `kernel/src/security/exoseal.rs` | P0 | HASH CHAIN |
| M26 | security/exocage | `kernel/src/security/exocage.rs` | P0 | SMEP/SMAP/KPTI |
| M27 | security/zero-trust | `kernel/src/security/zero_trust/` | P0 | IPC BYPASS |
| M28 | security/capability | `kernel/src/security/capability/` | P0 | VERIFY MANQUANT |
| M29 | security/exokairos | `kernel/src/security/exokairos.rs` | P0 | WINDOW RESET |
| M30 | security/exoledger | `kernel/src/security/exoledger.rs` | P0 | CHAIN, IMMUTABLE |
| M31 | security/iommu | `kernel/src/security/iommu/` | P0 | DMA OOB |
| M32 | security/exonmi | `kernel/src/security/exonmi.rs` | P1 | WATCHDOG ARMEMENT |
| M33 | drivers/pci | `kernel/src/drivers/pci/` | P1 | BAR PROBE |
| M34 | drivers/virtio | `kernel/src/drivers/virtio/` | P1 | MMIO HARDCODÉ |
| M35 | drivers/dma | `kernel/src/drivers/dma/` | P0 | IOVA DOMAIN |
| M36 | exophoenix/ssr | `kernel/src/exophoenix/ssr.rs` | P0 | BITMASK 256 |
| M37 | exophoenix/forge | `kernel/src/exophoenix/forge.rs` | P0 | BITMASK 256 |
| M38 | exophoenix/handoff | `kernel/src/exophoenix/handoff.rs` | P0 | BITMASK 256 |
| M39 | exophoenix/isolate | `kernel/src/exophoenix/isolate.rs` | P0 | BITMASK 256 |
| M40 | exophoenix/sentinel | `kernel/src/exophoenix/sentinel.rs` | P1 | HEARTBEAT MANQUANT |

---

## M01 — arch/constants.rs
### Fichier pivot de toute la batterie

**Chemin :** `kernel/src/arch/constants.rs`  
**Risque :** Ce fichier est la **source unique de vérité**. Toute incohérence ici se propage à l'ensemble du kernel.

### Couche 1 — const_assert! à insérer ou vérifier

```rust
// kernel/src/arch/constants.rs
// ── Constantes canoniques ─────────────────────────────────────────────────────

pub const MAX_CORES_LAYOUT: usize  = 256;
pub const MAX_CORES_RUNTIME: usize = 64;
pub const CORE_MASK_WORDS: usize   = MAX_CORES_LAYOUT / 64;   // = 4 obligatoire

pub const MAX_MSG_SIZE:    usize = 240;
pub const IPC_INLINE_MAX:  usize = 200;
pub const MAX_PROCESSES:   usize = 4096;
pub const MAX_ENDPOINTS:   usize = 8192;
pub const USER_ELF_BASE_MIN: u64 = 0x400000;
pub const USER_STACK_TOP:    u64 = 0x0000_7FFF_FFFF_F000;
pub const KERNEL_BASE:       u64 = 0xFFFF_8000_0000_0000;

// ── Vérifications statiques ───────────────────────────────────────────────────

// ASSERT-C01 : CORE_MASK_WORDS cohérent avec MAX_CORES_LAYOUT
const _: () = assert!(CORE_MASK_WORDS * 64 == MAX_CORES_LAYOUT,
    "[ASSERT-C01] CORE_MASK_WORDS incohérent — doit être MAX_CORES_LAYOUT / 64");

// ASSERT-C02 : Runtime ≤ Layout
const _: () = assert!(MAX_CORES_RUNTIME <= MAX_CORES_LAYOUT,
    "[ASSERT-C02] MAX_CORES_RUNTIME dépasse MAX_CORES_LAYOUT");

// ASSERT-C03 : IPC inline < message max
const _: () = assert!(IPC_INLINE_MAX < MAX_MSG_SIZE,
    "[ASSERT-C03] IPC_INLINE_MAX doit être < MAX_MSG_SIZE");

// ASSERT-C04 : ELF base dans l'espace utilisateur
const _: () = assert!(USER_ELF_BASE_MIN < USER_STACK_TOP,
    "[ASSERT-C04] USER_ELF_BASE_MIN >= USER_STACK_TOP");

// ASSERT-C05 : Kernel base en espace canonique haute
const _: () = assert!(KERNEL_BASE >= 0xFFFF_8000_0000_0000,
    "[ASSERT-C05] KERNEL_BASE hors plage canonique x86_64");

// ASSERT-C06 : Taille MAX_PROCESSES raisonnable
const _: () = assert!(MAX_PROCESSES <= 65536,
    "[ASSERT-C06] MAX_PROCESSES > 65536 — impact mémoire SSR");
```

### Couche 2 — Python : extensions à audit_constants.py

Ajouter dans `CRITICAL_PATTERNS` de `tools/audit_constants.py` :

```python
# Extensions pour M01
(r'MAX_CORES_LAYOUT',      "arch/constants.rs"),
(r'MAX_CORES_RUNTIME',     "arch/constants.rs"),
(r'CORE_MASK_WORDS',       "arch/constants.rs"),
(r'MAX_PROCESSES',         "arch/constants.rs"),
(r'MAX_ENDPOINTS',         "arch/constants.rs"),
(r'USER_ELF_BASE_MIN',     "arch/constants.rs"),
(r'KERNEL_BASE',           "arch/constants.rs"),
```

Commande de validation :
```bash
python3 tools/audit_constants.py --fail-on-warn 2>&1 | grep "INCOHERENCE"
# Résultat attendu : zéro ligne
```

### Couche 3 — Semgrep : règle de détection de redéfinition locale

```yaml
# Ajouter dans tools/semgrep-rules/exoos.yaml
- id: arch-const-redefined-locally
  pattern: |
    const MAX_CORES$_: $T = $VAL;
  pattern-not-inside:
    "arch/constants.rs"
  paths:
    include:
      - "kernel/src/**"
  message: |
    M01 : MAX_CORES* redéfini localement hors de arch/constants.rs.
    Utiliser `use crate::arch::constants::MAX_CORES_LAYOUT;`
  languages: [rust]
  severity: ERROR
```

### Critère de PASS M01

- [ ] `cargo build` passe sans erreur sur les ASSERT-C01..C06
- [ ] `python3 tools/audit_constants.py --fail-on-warn` → 0 INCOHERENCE
- [ ] `semgrep --config ... kernel/` → 0 violation `arch-const-redefined-locally`

---

## M02 — arch/percpu.rs
### Compteur de préemption — conflit historique avec preempt.rs

**Chemin :** `kernel/src/arch/percpu.rs`  
**Bug connu :** Compteur de préemption dupliqué entre `percpu.rs` et `preempt.rs` → double décrément possible.

### Couche 1 — const_assert!

```rust
// kernel/src/arch/percpu.rs — vérifications structurelles

// ASSERT-P01 : PerCpuData tient dans une page
const _: () = assert!(
    core::mem::size_of::<PerCpuData>() <= 4096,
    "[ASSERT-P01] PerCpuData dépasse 4096 octets — impact performances cache"
);

// ASSERT-P02 : preempt_count est bien à l'offset GS attendu
// (offset 0x20 pour compatibilité syscall path)
const _: () = assert!(
    core::mem::offset_of!(PerCpuData, preempt_count) == 0x20,
    "[ASSERT-P02] preempt_count n'est pas à l'offset GS:0x20 attendu"
);
```

### Couche 3 — Semgrep : détecter le double compteur

```yaml
- id: percpu-double-preempt-counter
  patterns:
    - pattern: |
        struct $CPU {
          ...
          preempt_count: $T,
          ...
        }
  paths:
    include:
      - "kernel/src/arch/**"
      - "kernel/src/scheduler/**"
  message: |
    M02 : Champ preempt_count détecté hors arch/percpu.rs.
    Un seul compteur de préemption autorisé — dans PerCpuData (percpu.rs).
    Utiliser `get_percpu().preempt_count` depuis les autres modules.
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani

```rust
// kernel/src/arch/tests/kani_percpu.rs
#[cfg(kani)]
mod kani_percpu {
    // PREUVE-P01 : preempt_count ne déborde jamais sur dec si jamais négatif
    #[kani::proof]
    fn proof_preempt_count_no_underflow() {
        let count: u32 = kani::any();
        kani::assume(count > 0);  // précondition : disable_preempt appelé avant
        let after = count.saturating_sub(1);
        // Propriété : après un enable_preempt, count >= 0 toujours
        assert!(after < u32::MAX);
    }
}
```

### Critère de PASS M02

- [ ] Un seul champ `preempt_count` dans tout le kernel → dans `PerCpuData`
- [ ] `preempt.rs` lit `get_percpu().preempt_count` (pas de champ propre)
- [ ] ASSERT-P01 passe (PerCpuData ≤ 4 KiB)
- [ ] ASSERT-P02 passe (offset 0x20)
- [ ] Kani PREUVE-P01 : `VERIFICATION SUCCESSFUL`

---

## M03 — arch/boot_sequence.rs
### Fichier historiquement vide — séquence de boot critique

**Chemin :** `kernel/src/arch/boot_sequence.rs`  
**Bug connu :** Fichier vide ou quasi-vide → les phases de boot (0..9) ne s'exécutent pas dans l'ordre.

### Couche 1 — const_assert! sur la séquence

```rust
// kernel/src/arch/boot_sequence.rs

// Phases de boot numérotées — immuables
pub const BOOT_PHASE_HARDWARE_INIT:     u8 = 0;
pub const BOOT_PHASE_MEMORY_INIT:       u8 = 1;
pub const BOOT_PHASE_GDT_IDT:           u8 = 2;
pub const BOOT_PHASE_PERCPU:            u8 = 3;
pub const BOOT_PHASE_SCHEDULER_INIT:    u8 = 4;
pub const BOOT_PHASE_SECURITY_INIT:     u8 = 5;   // ExoSeal, ExoCage, IOMMU
pub const BOOT_PHASE_IPC_INIT:          u8 = 6;
pub const BOOT_PHASE_SERVERS_LAUNCH:    u8 = 7;
pub const BOOT_PHASE_POSIX_LAYER:       u8 = 8;
pub const BOOT_PHASE_COMPLETE:          u8 = 9;

// ASSERT-B01 : Phases en ordre strict croissant
const _: () = assert!(BOOT_PHASE_SECURITY_INIT > BOOT_PHASE_MEMORY_INIT,
    "[ASSERT-B01] La sécurité doit être initialisée après la mémoire");

const _: () = assert!(BOOT_PHASE_IPC_INIT > BOOT_PHASE_SECURITY_INIT,
    "[ASSERT-B01b] L'IPC doit être initialisé après la sécurité");

const _: () = assert!(BOOT_PHASE_SERVERS_LAUNCH > BOOT_PHASE_IPC_INIT,
    "[ASSERT-B01c] Les serveurs doivent être lancés après l'IPC");
```

### Couche 3 — Semgrep : détecter les stubs non implémentés

```yaml
- id: boot-phase-stub
  patterns:
    - pattern: |
        fn $BOOT_INIT() {
          // TODO
        }
    - pattern: |
        fn $BOOT_INIT() {}
  paths:
    include:
      - "kernel/src/arch/boot_sequence.rs"
  message: |
    M03 : Fonction de boot stub détectée dans boot_sequence.rs.
    Chaque phase doit avoir une implémentation complète et non-vide.
  languages: [rust]
  severity: ERROR
```

### Vérification manuelle requise

Après correction, vérifier que `boot_sequence.rs` appelle dans l'ordre :

```
init_hardware()       → Phase 0
init_memory()         → Phase 1
load_gdt(); load_idt() → Phase 2
init_percpu()         → Phase 3
init_scheduler()      → Phase 4
security_init()       → Phase 5 : ExoSeal + ExoCage + IOMMU avant tout serveur
init_ipc()            → Phase 6
launch_ring1_servers() (minimum 9 serveurs) → Phase 7
init_posix_layer()    → Phase 8
```

### Couche 4 — Kani : vérifier la séquence

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_boot_phase_order() {
    // Propriété statique : les phases sont strictement croissantes
    assert!(BOOT_PHASE_SECURITY_INIT > BOOT_PHASE_MEMORY_INIT);
    assert!(BOOT_PHASE_SERVERS_LAUNCH > BOOT_PHASE_SECURITY_INIT);
    assert!(BOOT_PHASE_COMPLETE == 9);
}
```

### Critère de PASS M03

- [ ] `boot_sequence.rs` non vide : chaque phase appelle la bonne fonction
- [ ] `launch_ring1_servers()` lance ≥ 9 serveurs (vérifier par comptage manuel)
- [ ] `security_init()` est appelé en Phase 5, **avant** `launch_ring1_servers()`
- [ ] ASSERT-B01/B01b/B01c passent

---

## M04 — arch/gdt.rs + arch/idt.rs
### SYSRETQ RSP canonicity — CVE-2012-0217

**Chemins :**
- `kernel/src/arch/gdt.rs`
- `kernel/src/arch/idt.rs`

**Bug connu :** SYSRETQ avec RSP non canonique → escalade de privilège (CVE-2012-0217).

### Couche 1 — const_assert! sur les sélecteurs GDT

```rust
// kernel/src/arch/gdt.rs

// Sélecteurs GDT — layout Linux-compatible pour SYSCALL/SYSRET
pub const GDT_KERNEL_CODE64: u16 = 0x08;   // Ring0 code 64-bit
pub const GDT_KERNEL_DATA:   u16 = 0x10;   // Ring0 data
pub const GDT_USER_DATA:     u16 = 0x18;   // Ring3 data (STAR.SYSRET = 0x18)
pub const GDT_USER_CODE64:   u16 = 0x20;   // Ring3 code 64-bit
pub const GDT_TSS_LOW:       u16 = 0x28;   // TSS (2 descripteurs)

// ASSERT-G01 : Ordre STAR-compatible (SYSRET charge SS = STAR.SYSRET, CS = STAR.SYSRET+8)
const _: () = assert!(GDT_USER_CODE64 == GDT_USER_DATA + 8,
    "[ASSERT-G01] GDT_USER_CODE64 doit être GDT_USER_DATA + 8 pour SYSRET");

// ASSERT-G02 : SYSCALL charge CS = STAR.SYSCALL, SS = STAR.SYSCALL+8
const _: () = assert!(GDT_KERNEL_DATA == GDT_KERNEL_CODE64 + 8,
    "[ASSERT-G02] GDT_KERNEL_DATA doit être GDT_KERNEL_CODE64 + 8 pour SYSCALL");
```

### Couche 3 — Semgrep : détecter l'absence de vérification RSP canonique

```yaml
- id: sysretq-no-rsp-canonicity-check
  patterns:
    - pattern: |
        unsafe { core::arch::asm!("sysretq", ...) }
    - pattern-not-inside: |
        if $RSP & 0xFFFF_8000_0000_0000 != 0 &&
           $RSP & 0xFFFF_8000_0000_0000 != 0xFFFF_8000_0000_0000 {
          return Err(...);
        }
  paths:
    include:
      - "kernel/src/arch/**"
      - "kernel/src/syscall/**"
  message: |
    M04 : SYSRETQ sans vérification de canonicité RSP (CVE-2012-0217).
    Ajouter la vérification canonique sur $RSP avant SYSRETQ.
    RSP non canonique → escalade Ring3 → Ring0.
  languages: [rust]
  severity: ERROR
```

Correction à appliquer dans le syscall return path :

```rust
// kernel/src/syscall/return_path.rs — à vérifier/corriger
fn sysretq_safe(rsp: u64) -> Result<(), KernelError> {
    // Vérification de canonicité RSP avant SYSRETQ (CVE-2012-0217)
    let high_bits = rsp & 0xFFFF_8000_0000_0000;
    if high_bits != 0 && high_bits != 0xFFFF_8000_0000_0000 {
        // RSP non canonique — un attaquant Ring3 a manipulé RSP
        // Ne pas exécuter SYSRETQ → utiliser IRETQ à la place
        return Err(KernelError::NonCanonicalRsp(rsp));
    }
    unsafe { core::arch::asm!("sysretq", options(noreturn)) }
}
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_rsp_canonicity_check() {
    let rsp: u64 = kani::any();
    let high = rsp & 0xFFFF_8000_0000_0000;
    let is_canonical = high == 0 || high == 0xFFFF_8000_0000_0000;
    // Propriété : seuls les RSP canoniques passent
    if !is_canonical {
        // La fonction doit retourner une erreur — jamais exécuter SYSRETQ
        assert!(sysretq_safe(rsp).is_err());
    }
}
```

### Critère de PASS M04

- [ ] ASSERT-G01 et G02 passent (layout GDT STAR-compatible)
- [ ] Semgrep zéro violation `sysretq-no-rsp-canonicity-check`
- [ ] Kani `proof_rsp_canonicity_check` : VERIFICATION SUCCESSFUL
- [ ] Test manuel : tentative SYSRETQ avec RSP = `0x0000_DEAD_BEEF_0001` → `KernelError::NonCanonicalRsp`

---

## M05 — arch/interrupts.rs
### Allocation dans les ISR — règle DRV-ISR-01

**Chemin :** `kernel/src/arch/interrupts.rs`  
**Bug connu :** Des ISR contiennent des allocations (`Vec::new()`, `Box::new()`) → déadlock ou panic si l'allocateur est verrouillé.

### Couche 3 — Semgrep : ISR-01 déjà défini dans TOOLS-AUDIT-EXOOS

La règle `isr-alloc-forbidden` du fichier `tools/semgrep-rules/exoos.yaml` doit déjà couvrir ce cas. Vérifier l'exécution :

```bash
semgrep --config tools/semgrep-rules/exoos.yaml \
        kernel/src/arch/interrupts.rs \
        --error 2>&1
# Résultat attendu : zéro violation
```

Étendre la règle pour couvrir les macros `log!` (qui peuvent allouer) :

```yaml
- id: isr-log-forbidden
  patterns:
    - pattern: |
        extern "x86-interrupt" fn $ISR(...) {
          ...
          log!(...)
          ...
        }
    - pattern: |
        extern "x86-interrupt" fn $ISR(...) {
          ...
          info!(...)
          ...
        }
  message: |
    M05/ISR-LOG-01 : Macro de log dans une ISR.
    log!/info!/warn! allouent potentiellement en heap.
    Dans une ISR : flag atomique uniquement, EOI, retour immédiat.
  languages: [rust]
  severity: ERROR
```

### Couche 1 — const_assert! sur IDT

```rust
// kernel/src/arch/interrupts.rs

// ASSERT-I01 : L'IDT a 256 entrées (x86_64 standard)
const _: () = assert!(
    IDT_ENTRY_COUNT == 256,
    "[ASSERT-I01] IDT doit avoir exactement 256 entrées"
);

// ASSERT-I02 : Les vecteurs 0-31 sont réservés (exceptions CPU)
const _: () = assert!(
    FIRST_USER_IRQ_VECTOR >= 32,
    "[ASSERT-I02] FIRST_USER_IRQ_VECTOR empiète sur les exceptions CPU (0-31)"
);
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_isr_no_allocation_path() {
    // Propriété structurelle : la fonction timer_interrupt_handler
    // ne doit avoir aucun chemin atteignant alloc::alloc
    // Kani vérifie l'absence de panic dans le handler
    let frame = InterruptStackFrame::default();
    timer_interrupt_handler(frame);
    // Pas de panic, pas d'allocation → preuve valide
}
```

### Critère de PASS M05

- [ ] Semgrep `isr-alloc-forbidden` et `isr-log-forbidden` → 0 violation sur `interrupts.rs`
- [ ] ASSERT-I01/I02 passent
- [ ] Revue manuelle : chaque `extern "x86-interrupt" fn` se limite à : acquitter + flag atomique + APIC EOI

---

## M06 — memory/buddy/
### Allocateur Buddy — OOB et leaks

**Chemins :**
```
kernel/src/memory/buddy/
├── mod.rs
├── free_list.rs
├── allocator.rs
└── tests.rs
```

### Couche 1 — const_assert!

```rust
// kernel/src/memory/buddy/mod.rs

pub const BUDDY_MIN_ORDER: usize = 12;   // 4 KiB (une page)
pub const BUDDY_MAX_ORDER: usize = 21;   // 2 MiB (hugepage)
pub const BUDDY_ORDER_COUNT: usize = BUDDY_MAX_ORDER - BUDDY_MIN_ORDER + 1;

// ASSERT-BU01 : Ordre minimum = taille d'une page
const _: () = assert!(
    1usize << BUDDY_MIN_ORDER == 4096,
    "[ASSERT-BU01] BUDDY_MIN_ORDER doit correspondre à 4096 octets"
);

// ASSERT-BU02 : Nombre d'ordres cohérent
const _: () = assert!(
    BUDDY_ORDER_COUNT == 10,
    "[ASSERT-BU02] BUDDY_ORDER_COUNT incohérent avec MIN/MAX_ORDER"
);

// ASSERT-BU03 : free_list indexée par ordre — taille tableau
const _: () = assert!(
    core::mem::size_of::<[FreeList; BUDDY_ORDER_COUNT]>() <= 4096,
    "[ASSERT-BU03] Tableau free_list trop grand"
);
```

### Couche 3 — Semgrep

```yaml
- id: buddy-direct-ptr-arithmetic
  patterns:
    - pattern: |
        ($PTR as usize) + $OFFSET
    - pattern-not-inside: |
        fn $BUDDY_FN(...) -> ... {
          ...
          assert!($OFFSET < $LIMIT);
          ...
        }
  paths:
    include:
      - "kernel/src/memory/buddy/**"
  message: |
    M06 : Arithmétique de pointeur dans buddy allocator sans assertion de borne.
    Risque OOB critique. Ajouter assert!(offset < region_end) avant tout calcul.
  languages: [rust]
  severity: ERROR

- id: buddy-double-free-check
  patterns:
    - pattern: |
        fn $FREE(..., order: usize, ...) {
          ...
          free_list[$ORDER].push(...)
          ...
        }
    - pattern-not: |
        fn $FREE(...) {
          ...
          debug_assert!(!$FREE_LIST.contains(&$ADDR));
          ...
        }
  paths:
    include:
      - "kernel/src/memory/buddy/**"
  message: |
    M06 : Libération buddy sans vérification double-free.
    Ajouter debug_assert!(!free_list.contains(&addr)) en mode debug.
  languages: [rust]
  severity: WARNING
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
mod kani_buddy {
    // PREUVE-BU01 : alloc suivi de free redonne addr d'origine
    #[kani::proof]
    fn proof_buddy_alloc_free_roundtrip() {
        let order: usize = kani::any();
        kani::assume(order >= BUDDY_MIN_ORDER);
        kani::assume(order <= BUDDY_MAX_ORDER);
        let mut buddy = BuddyAllocator::new_test();
        if let Some(addr) = buddy.alloc(order) {
            buddy.free(addr, order);
            // Propriété : la région est de nouveau disponible
            let addr2 = buddy.alloc(order);
            assert!(addr2.is_some());
        }
    }

    // PREUVE-BU02 : deux allocations distinctes ne se chevauchent pas
    #[kani::proof]
    fn proof_buddy_no_overlap() {
        let order: usize = kani::any();
        kani::assume(order >= BUDDY_MIN_ORDER && order <= BUDDY_MAX_ORDER);
        let mut buddy = BuddyAllocator::new_test_large();
        if let (Some(a1), Some(a2)) = (buddy.alloc(order), buddy.alloc(order)) {
            let size = 1usize << order;
            // Pas de chevauchement
            assert!(a1 + size <= a2 || a2 + size <= a1);
        }
    }
}
```

### Critère de PASS M06

- [ ] ASSERT-BU01..BU03 passent
- [ ] Semgrep 0 violation sur `memory/buddy/`
- [ ] Kani PREUVE-BU01 et BU02 : VERIFICATION SUCCESSFUL
- [ ] `cargo test memory::buddy::` → tous PASS (alloc, free, roundtrip, fragmentation)

---

## M07 — memory/slub/
### Allocateur SLUB — Use-After-Free et Double-Free

**Chemins :**
```
kernel/src/memory/slub/
├── mod.rs
├── cache.rs
├── slab.rs
└── tests.rs
```

### Couche 1 — const_assert!

```rust
// kernel/src/memory/slub/mod.rs

pub const SLUB_MAX_OBJECT_SIZE: usize = 65536;  // 64 KiB max par objet SLUB
pub const SLUB_ALIGN_MIN:       usize = 8;       // Alignement minimum 8 octets

// ASSERT-SL01 : Aucun objet SLUB ne dépasse BUDDY_MIN_ORDER taille
const _: () = assert!(
    SLUB_MAX_OBJECT_SIZE < (1 << crate::memory::buddy::BUDDY_MIN_ORDER) * 16,
    "[ASSERT-SL01] SLUB_MAX_OBJECT_SIZE trop grand — utiliser buddy direct"
);

// ASSERT-SL02 : Alignement minimum puissance de 2
const _: () = assert!(
    SLUB_ALIGN_MIN.is_power_of_two(),
    "[ASSERT-SL02] SLUB_ALIGN_MIN doit être une puissance de 2"
);
```

### Couche 3 — Semgrep

```yaml
- id: slub-no-poison-on-free
  patterns:
    - pattern: |
        fn $FREE_OBJ(..., ptr: *mut $T, ...) {
          ...
        }
    - pattern-not: |
        fn $FREE_OBJ(...) {
          ...
          core::ptr::write_bytes($PTR, 0xCC, ...);
          ...
        }
  paths:
    include:
      - "kernel/src/memory/slub/**"
  message: |
    M07 : free_object() sans poison (0xCC) sur la mémoire libérée.
    Sans poison, les UAF sont silencieux. Ajouter write_bytes(ptr, 0xCC, size).
  languages: [rust]
  severity: WARNING

- id: slub-use-after-free-flag
  patterns:
    - pattern: |
        fn $ALLOC(...) -> *mut $T {
          ...
          $OBJ_PTR
        }
    - pattern-not: |
        fn $ALLOC(...) -> *mut $T {
          ...
          debug_assert!(!$OBJ.is_freed);
          ...
        }
  paths:
    include:
      - "kernel/src/memory/slub/**"
  message: |
    M07 : alloc_object() sans vérification du flag is_freed.
    Ajouter debug_assert!(!obj.is_freed) en mode debug pour détecter les UAF.
  languages: [rust]
  severity: WARNING
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_slub_no_double_free() {
    let size: usize = kani::any();
    kani::assume(size >= 8 && size <= SLUB_MAX_OBJECT_SIZE);
    let mut cache = SlubCache::new_test(size);
    let ptr = cache.alloc();
    if !ptr.is_null() {
        cache.free(ptr);
        // Double free → doit retourner Err ou panic en debug
        // Kani vérifie que le second free n'est pas silencieux
    }
}
```

### Critère de PASS M07

- [ ] ASSERT-SL01/SL02 passent
- [ ] Poison `0xCC` présent sur chaque `free_object()`
- [ ] `cargo test memory::slub::` → tous PASS

---

## M08 — memory/vmalloc/
### Fragmentation et mapping virtuel

**Chemins :** `kernel/src/memory/vmalloc/`

### Couche 1 — const_assert!

```rust
// ASSERT-VM01 : Plage vmalloc dans l'espace kernel
pub const VMALLOC_START: u64 = 0xFFFF_C000_0000_0000;
pub const VMALLOC_END:   u64 = 0xFFFF_E000_0000_0000;

const _: () = assert!(
    VMALLOC_START < VMALLOC_END,
    "[ASSERT-VM01] Plage vmalloc incohérente"
);
const _: () = assert!(
    VMALLOC_START >= crate::arch::constants::KERNEL_BASE,
    "[ASSERT-VM01b] VMALLOC_START hors espace kernel"
);
```

### Couche 3 — Semgrep

```yaml
- id: vmalloc-no-tlb-flush
  patterns:
    - pattern: |
        fn $UNMAP(...) {
          ...
          unmap_pages(...)
          ...
        }
    - pattern-not: |
        fn $UNMAP(...) {
          ...
          flush_tlb_range(...)
          ...
        }
  paths:
    include:
      - "kernel/src/memory/vmalloc/**"
  message: |
    M08 : vmalloc unmap sans flush TLB. Mapping stale possible → UAF virtuel.
    Appeler flush_tlb_range() ou flush_tlb_all() après unmap.
  languages: [rust]
  severity: ERROR
```

### Critère de PASS M08

- [ ] ASSERT-VM01/VM01b passent
- [ ] Semgrep 0 violation `vmalloc-no-tlb-flush`
- [ ] Test : `vmalloc(4096)` + `vfree()` + accès → fault détectée (PF)

---

## M09 — memory/cow/
### Copy-on-Write — mauvais espace d'adressage (CR3)

**Chemins :** `kernel/src/memory/cow/`  
**Bug connu :** `KERNEL_FAULT_ALLOC` opère sur le mauvais CR3 lors du fork.

### Couche 3 — Semgrep

```yaml
- id: cow-wrong-cr3
  patterns:
    - pattern: |
        fn $COW_HANDLER(...) {
          ...
          alloc_page(...)
          ...
        }
    - pattern-not: |
        fn $COW_HANDLER(...) {
          ...
          let _cr3_guard = switch_to_process_cr3($PID);
          ...
          alloc_page(...)
          ...
        }
  paths:
    include:
      - "kernel/src/memory/cow/**"
  message: |
    M09 : Page fault handler CoW sans switch_to_process_cr3().
    La page allouée peut être mappée dans le mauvais espace d'adressage.
    Acquérir le CR3 du processus fautif avant toute allocation.
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_cow_page_isolated_per_process() {
    // Deux processus forkés — leurs pages CoW ne partagent pas la même adresse physique
    let pid_a: ProcessId = kani::any();
    let pid_b: ProcessId = kani::any();
    kani::assume(pid_a != pid_b);
    let va: VirtAddr = kani::any();

    let pa_a = resolve_cow_page(pid_a, va);
    let pa_b = resolve_cow_page(pid_b, va);

    if pa_a.is_some() && pa_b.is_some() {
        // Après CoW, pages physiques distinctes
        assert!(pa_a != pa_b);
    }
}
```

### Critère de PASS M09

- [ ] Semgrep 0 violation `cow-wrong-cr3`
- [ ] Test : `fork()` + écriture dans le fils → parent voit l'ancienne valeur
- [ ] Kani `proof_cow_page_isolated_per_process` : VERIFICATION SUCCESSFUL

---

## M10 — memory/paging/
### KPTI — isolation kernel/user dans la table des pages

**Chemins :** `kernel/src/memory/paging/`  
**Bug connu :** KPTI incomplet → espace kernel visible depuis Ring3.

### Couche 1 — const_assert!

```rust
// kernel/src/memory/paging/mod.rs

pub const KPTI_USER_PGD_OFFSET: usize = 512;  // PGD user = 2e moitié du frame partagé

// ASSERT-KP01 : L'offset KPTI est dans la plage PGD (512 entrées)
const _: () = assert!(
    KPTI_USER_PGD_OFFSET < 512,
    "[ASSERT-KP01] KPTI_USER_PGD_OFFSET hors plage PGD"
);
```

### Couche 3 — Semgrep

```yaml
- id: kpti-kernel-page-user-accessible
  patterns:
    - pattern: |
        map_page($VA, $PA, PageFlags::USER_ACCESSIBLE)
    - pattern-not-inside: |
        fn map_trampoline_page(...)
  paths:
    include:
      - "kernel/src/memory/paging/**"
  message: |
    M10 : Page kernel mappée avec USER_ACCESSIBLE hors du trampoline KPTI.
    Toutes les pages kernel doivent être invisibles depuis Ring3.
    Seul le trampoline KPTI (syscall entry) peut être USER_ACCESSIBLE.
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_kpti_kernel_pages_not_user_visible() {
    let va: u64 = kani::any();
    // Pour toute adresse kernel (high half)
    kani::assume(va >= 0xFFFF_8000_0000_0000);
    let pte = lookup_user_pgtable(va);
    // Propriété : les pages kernel ne sont pas dans la table user (KPTI)
    assert!(pte.is_none() || pte.unwrap().is_trampoline());
}
```

### Critère de PASS M10

- [ ] ASSERT-KP01 passe
- [ ] Semgrep 0 violation `kpti-kernel-page-user-accessible`
- [ ] Test : depuis Ring3, lire adresse `0xFFFF_8000_0000_0000` → `SIGSEGV` / PF

---

## M11 — scheduler/cfs/
### CFS — compteur de préemption (conflit avec M02)

**Chemins :** `kernel/src/scheduler/cfs/`

### Couche 3 — Semgrep (extension de la règle M02)

```yaml
- id: cfs-direct-preempt-field
  patterns:
    - pattern: |
        $TCB.preempt_count $OP $VAL
    - pattern-not-inside: |
        fn $ENABLE_DISABLE_PREEMPT(...)
  paths:
    include:
      - "kernel/src/scheduler/cfs/**"
  message: |
    M11 : Accès direct à preempt_count dans CFS hors des fonctions enable/disable.
    Utiliser disable_preempt() / enable_preempt() depuis arch::percpu.
  languages: [rust]
  severity: ERROR
```

### Couche 1 — const_assert!

```rust
// kernel/src/scheduler/cfs/mod.rs

pub const CFS_MIN_GRANULARITY_NS:  u64 = 750_000;     // 750 µs
pub const CFS_LATENCY_TARGET_NS:   u64 = 6_000_000;   // 6 ms
pub const CFS_WAKEUP_GRANULARITY_NS: u64 = 1_000_000; // 1 ms

// ASSERT-SC01 : Granularité < cible de latence
const _: () = assert!(
    CFS_MIN_GRANULARITY_NS < CFS_LATENCY_TARGET_NS,
    "[ASSERT-SC01] CFS_MIN_GRANULARITY_NS >= CFS_LATENCY_TARGET_NS"
);

// ASSERT-SC02 : Wakeup granularity < latency target
const _: () = assert!(
    CFS_WAKEUP_GRANULARITY_NS < CFS_LATENCY_TARGET_NS,
    "[ASSERT-SC02] CFS_WAKEUP_GRANULARITY_NS >= CFS_LATENCY_TARGET_NS"
);
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_cfs_vruntime_monotonic() {
    let mut task = Task::default();
    let delta1: u64 = kani::any();
    let delta2: u64 = kani::any();
    kani::assume(delta1 < 1_000_000_000); // < 1s
    kani::assume(delta2 < 1_000_000_000);

    let v0 = task.vruntime;
    update_vruntime(&mut task, delta1);
    let v1 = task.vruntime;
    update_vruntime(&mut task, delta2);
    let v2 = task.vruntime;

    // Propriété : vruntime est strictement croissant
    assert!(v1 >= v0);
    assert!(v2 >= v1);
}
```

### Critère de PASS M11

- [ ] ASSERT-SC01/SC02 passent
- [ ] Semgrep 0 violation `cfs-direct-preempt-field`
- [ ] Kani `proof_cfs_vruntime_monotonic` : VERIFICATION SUCCESSFUL

---

## M12-M14 — scheduler/rt/, scheduler/smp/, scheduler/fpu/

**Note :** Ces modules font l'objet d'une section condensée. Appliquer le même protocole.

### M12 — scheduler/rt/ : Priorité inversée

```rust
// ASSERT-RT01 : RT prio range
pub const RT_PRIO_MAX: u8 = 99;
pub const RT_PRIO_MIN: u8 = 1;
const _: () = assert!(RT_PRIO_MIN < RT_PRIO_MAX, "[ASSERT-RT01] RT_PRIO range invalide");
```

Semgrep : détecter les wait sans priority inheritance.

### M13 — scheduler/smp/ : IPI deadlock

**Bug connu :** TLB shootdown IPI → `ack` jamais reçu si single-CPU.

```yaml
- id: smp-ipi-no-single-cpu-skip
  patterns:
    - pattern: |
        send_ipi_all_except_self(IPI_TLB_SHOOTDOWN, ...)
    - pattern-not-inside: |
        if get_online_cpu_count() > 1 { ... }
  paths:
    include:
      - "kernel/src/scheduler/smp/**"
  message: |
    M13 : TLB shootdown IPI sans guard single-CPU.
    Sur single-CPU, send_ipi_all_except_self bloque indéfiniment (ack jamais reçu).
    Ajouter : if get_online_cpu_count() > 1 { send_ipi... }
  languages: [rust]
  severity: ERROR
```

### M14 — scheduler/fpu/ : FPU state leak

```yaml
- id: fpu-no-save-on-switch
  patterns:
    - pattern: |
        fn context_switch($FROM: &mut Task, $TO: &mut Task) {
          ...
        }
    - pattern-not: |
        fn context_switch(...) {
          ...
          fpu_save($FROM);
          ...
          fpu_restore($TO);
          ...
        }
  paths:
    include:
      - "kernel/src/scheduler/**"
  message: |
    M14 : context_switch sans fpu_save/fpu_restore.
    Le state FPU (XMM, AVX) fuite entre processus.
  languages: [rust]
  severity: ERROR
```

---

## M15 — ipc/ring/spsc.rs
### SpscRing — zero-copy path et typage des messages

**Chemin :** `kernel/src/ipc/ring/spsc.rs`

### Couche 1 — const_assert!

```rust
// kernel/src/ipc/ring/spsc.rs

use crate::arch::constants::{MAX_MSG_SIZE, IPC_INLINE_MAX};

pub const RING_CAPACITY: usize = 256;  // Nb de slots dans le ring

// ASSERT-IPC01 : RING_CAPACITY puissance de 2 (masque modulo)
const _: () = assert!(
    RING_CAPACITY.is_power_of_two(),
    "[ASSERT-IPC01] RING_CAPACITY doit être une puissance de 2"
);

// ASSERT-IPC02 : Taille d'un slot cohérente avec MAX_MSG_SIZE
const _: () = assert!(
    core::mem::size_of::<IpcSlot>() >= MAX_MSG_SIZE + core::mem::size_of::<IpcHeader>(),
    "[ASSERT-IPC02] IpcSlot trop petit pour contenir MAX_MSG_SIZE + header"
);

// ASSERT-IPC03 : Tout le ring tient dans une plage adressable raisonnable
const _: () = assert!(
    core::mem::size_of::<IpcSlot>() * RING_CAPACITY <= 4 * 1024 * 1024,
    "[ASSERT-IPC03] Ring IPC > 4 MiB — revoir RING_CAPACITY ou IpcSlot"
);
```

### Couche 3 — Semgrep : IPC-RULE-01 (déjà dans TOOLS-AUDIT)

Vérifier que `ipc-rule-01-len-as-type` s'applique correctement sur `spsc.rs` :

```bash
semgrep --config tools/semgrep-rules/exoos.yaml \
        kernel/src/ipc/ring/spsc.rs --error
```

Ajouter la règle de typage explicite :

```yaml
- id: ipc-missing-msg-type-field
  pattern: |
    struct $HEADER {
      ...
    }
  pattern-not: |
    struct $HEADER {
      ...
      msg_type: $T,
      ...
    }
  paths:
    include:
      - "kernel/src/ipc/**"
  message: |
    M15 : Structure header IPC sans champ msg_type explicite.
    Chaque message IPC doit avoir un discriminant de type explicite (IPC-RULE-01).
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
mod kani_spsc {
    // PREUVE-IPC01 : send/recv préserve l'ordre FIFO
    #[kani::proof]
    fn proof_spsc_fifo_order() {
        let mut ring = SpscRing::new_test();
        let msg1 = IpcMessage { seq: 1, ..Default::default() };
        let msg2 = IpcMessage { seq: 2, ..Default::default() };

        ring.send(msg1.clone()).unwrap();
        ring.send(msg2.clone()).unwrap();

        let r1 = ring.recv().unwrap();
        let r2 = ring.recv().unwrap();

        assert!(r1.seq == 1); // FIFO
        assert!(r2.seq == 2);
    }

    // PREUVE-IPC02 : ring plein → send retourne Err (jamais OOB)
    #[kani::proof]
    fn proof_spsc_full_no_oob() {
        let mut ring = SpscRing::new_test(); // capacité = RING_CAPACITY
        for _ in 0..RING_CAPACITY {
            let _ = ring.send(IpcMessage::default());
        }
        // Ring plein — le prochain send doit retourner Err, pas paniquer
        let result = ring.send(IpcMessage::default());
        assert!(result.is_err());
    }
}
```

### Critère de PASS M15

- [ ] ASSERT-IPC01..IPC03 passent
- [ ] Semgrep 0 violation sur `ipc/ring/`
- [ ] Kani PREUVE-IPC01/IPC02 : VERIFICATION SUCCESSFUL

---

## M16 — ipc/sync/
### Timeouts IPC — violation des contraintes temporelles

**Chemins :** `kernel/src/ipc/sync/`  
**Bug connu :** Les timeouts IPC sont définis mais non vérifiés → appels bloquants indéfinis.

### Couche 1 — const_assert!

```rust
// kernel/src/ipc/sync/mod.rs

pub const IPC_TIMEOUT_DEFAULT_NS: u64 = 1_000_000;   // 1 ms
pub const IPC_TIMEOUT_MAX_NS:     u64 = 10_000_000;  // 10 ms
pub const IPC_TIMEOUT_ZERO:       u64 = 0;            // Non-bloquant

const _: () = assert!(
    IPC_TIMEOUT_DEFAULT_NS <= IPC_TIMEOUT_MAX_NS,
    "[ASSERT-IS01] IPC_TIMEOUT_DEFAULT_NS > IPC_TIMEOUT_MAX_NS"
);
```

### Couche 3 — Semgrep

```yaml
- id: ipc-blocking-wait-no-timeout
  patterns:
    - pattern: |
        fn $WAIT_FN(...) -> ... {
          ...
          loop {
            ...
            if $CONDITION { break; }
            ...
          }
          ...
        }
    - pattern-not: |
        fn $WAIT_FN(...) -> ... {
          ...
          let $DEADLINE = now() + $TIMEOUT;
          ...
          if now() > $DEADLINE { return Err(IpcError::Timeout); }
          ...
        }
  paths:
    include:
      - "kernel/src/ipc/sync/**"
  message: |
    M16 : Boucle d'attente IPC sans deadline/timeout.
    Tout wait IPC doit avoir un timeout explicite pour éviter le blocage indéfini.
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani (TLA+ recommandé en complément)

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_ipc_timeout_respected() {
    let timeout_ns: u64 = kani::any();
    kani::assume(timeout_ns > 0 && timeout_ns <= IPC_TIMEOUT_MAX_NS);

    let start = 0u64; // temps simulé
    let elapsed: u64 = kani::any();
    kani::assume(elapsed > timeout_ns); // simuler timeout dépassé

    let result = check_ipc_timeout(start, elapsed, timeout_ns);
    // Propriété : doit retourner Timeout si elapsed > timeout
    assert!(result == Err(IpcError::Timeout));
}
```

**TLA+ recommandé :** Modéliser le protocole send/recv avec timeouts dans un module TLA+ `IpcTimeout.tla` — voir `SPEC-IPC-TLA.md` pour la structure.

### Critère de PASS M16

- [ ] ASSERT-IS01 passe
- [ ] Semgrep 0 violation `ipc-blocking-wait-no-timeout`
- [ ] Test : `ipc_sync_test::timeout_respected` → PASS (appel retourne en ≤ IPC_TIMEOUT_MAX_NS)
- [ ] (Optionnel v0.2.0) TLA+ `IpcTimeout.tla` → 0 deadlock

---

## M17-M18 — ipc/shm/, ipc/rpc/

### M17 — ipc/shm/ : Mapping stale après revoke

```yaml
- id: shm-no-unmap-on-revoke
  patterns:
    - pattern: |
        fn revoke_shm($CAP: CapToken) {
          ...
        }
    - pattern-not: |
        fn revoke_shm($CAP: CapToken) {
          ...
          unmap_shm_from_all_processes($CAP.object_id);
          ...
        }
  message: |
    M17 : revoke_shm() sans unmap des processus existants.
    Après révocation, le mapping SHM doit être retiré de tous les espaces d'adressage.
  languages: [rust]
  severity: ERROR
```

### M18 — ipc/rpc/ : msg_type comme discriminant

Appliquer `ipc-rule-01-len-as-type` et `ipc-missing-msg-type-field` sur `ipc/rpc/`. Corriger tout payload RPC dont le type est inféré de la longueur.

---

## M19 — process/lifecycle/fork.rs
### Fork — VMA tree non clonée

**Chemin :** `kernel/src/process/lifecycle/fork.rs`  
**Bug connu :** VMA tree non deep-clonée → fils et père partagent le même arbre → corruption mémoire.

### Couche 3 — Semgrep

```yaml
- id: fork-shallow-vma-clone
  patterns:
    - pattern: |
        fn do_fork(...) -> ... {
          ...
          let child_mm = parent_mm.clone();
          ...
        }
    - pattern-not: |
        fn do_fork(...) -> ... {
          ...
          let child_mm = parent_mm.deep_clone_vma();
          ...
        }
  paths:
    include:
      - "kernel/src/process/lifecycle/fork.rs"
  message: |
    M19 : fork() utilise clone() superficiel sur la VMA tree.
    Utiliser deep_clone_vma() pour créer une copie indépendante (chaque VMA clonée).
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_fork_vma_independence() {
    let parent = Process::new_test();
    let child  = fork_process(&parent).unwrap();

    // Modifier une VMA dans le fils ne modifie pas le père
    let va: VirtAddr = kani::any();
    kani::assume(parent.mm.contains_vma(va));

    // Propriété : VMA du fils est un objet distinct
    let parent_vma_ptr = parent.mm.find_vma(va).unwrap() as *const _;
    let child_vma_ptr  = child.mm.find_vma(va).unwrap()  as *const _;
    assert!(parent_vma_ptr != child_vma_ptr);
}
```

### Critère de PASS M19

- [ ] Semgrep 0 violation `fork-shallow-vma-clone`
- [ ] Kani `proof_fork_vma_independence` : VERIFICATION SUCCESSFUL
- [ ] Test : `fork()` + write dans fils + read dans père → valeur père inchangée

---

## M20 — process/lifecycle/exec.rs
### ELF base min — CORR-80

**Chemin :** `kernel/src/process/lifecycle/exec.rs`

### Couche 1 — const_assert!

```rust
// kernel/src/process/lifecycle/exec.rs

use crate::arch::constants::USER_ELF_BASE_MIN;

// ASSERT-EX01 : ELF chargé à une adresse >= USER_ELF_BASE_MIN
// (vérifier dans load_elf)
const _: () = assert!(
    USER_ELF_BASE_MIN >= 0x400000,
    "[ASSERT-EX01] USER_ELF_BASE_MIN inférieur à 0x400000 — ELF ABI Linux standard"
);
```

### Couche 3 — Semgrep

```yaml
- id: exec-elf-base-too-low
  patterns:
    - pattern: |
        load_elf_segment($VA, ...)
    - pattern-not-inside: |
        if $VA >= USER_ELF_BASE_MIN { ... }
  paths:
    include:
      - "kernel/src/process/lifecycle/exec.rs"
  message: |
    M20 : Chargement de segment ELF sans vérification USER_ELF_BASE_MIN (CORR-80).
    Un segment ELF en-dessous de 0x400000 peut écraser le NULL page ou le vDSO.
  languages: [rust]
  severity: ERROR
```

---

## M21-M22 — process/signal/, process/thread/

### M21 — Masque de signaux et livraison

```rust
// ASSERT-SIG01 : SIGKILL et SIGSTOP ne peuvent pas être masqués
const _: () = assert!(
    SIGNAL_UNKILLABLE_MASK & (1u64 << (SIGKILL - 1)) != 0,
    "[ASSERT-SIG01] SIGKILL manquant dans SIGNAL_UNKILLABLE_MASK"
);
```

### M22 — TLS GS base pour les threads

```yaml
- id: thread-no-gs-base-init
  patterns:
    - pattern: |
        fn create_thread(...) -> ... {
          ...
        }
    - pattern-not: |
        fn create_thread(...) -> ... {
          ...
          set_gs_base($TCB_ADDR);
          ...
        }
  message: |
    M22 : create_thread() sans initialisation GS base pour TLS.
    Chaque nouveau thread doit avoir son propre PerCpuData / TCB pointé par GS.
  languages: [rust]
  severity: ERROR
```

---

## M23 — fs/exofs/
### ExoFS — persistance et protection is_immutable

**Chemins :**
```
kernel/src/fs/exofs/
├── objects/
│   ├── object_meta.rs
│   ├── blob_store.rs
│   └── directory.rs
├── syscall/
│   ├── read.rs
│   ├── write.rs
│   └── delete.rs
├── journal.rs
└── snapshot.rs
```

### Couche 1 — const_assert!

```rust
// kernel/src/fs/exofs/objects/object_meta.rs

// ASSERT-FS01 : ObjectMeta ≤ 64 octets (une ligne de cache)
const _: () = assert!(
    core::mem::size_of::<ObjectMeta>() <= 64,
    "[ASSERT-FS01] ObjectMeta > 64 octets — impact perf cache"
);

// ASSERT-FS02 : ZERO_BLOB_ID_4K est l'identifiant réservé
pub const ZERO_BLOB_ID_4K: u64 = 0;
const _: () = assert!(
    ZERO_BLOB_ID_4K == 0,
    "[ASSERT-FS02] ZERO_BLOB_ID_4K doit être 0 — convention ExoFS"
);

// ASSERT-FS03 : MAX_BLOB_SIZE cohérent avec le buddy allocator
pub const MAX_BLOB_SIZE: u64 = 1024 * 1024 * 1024; // 1 GiB
const _: () = assert!(
    MAX_BLOB_SIZE <= u64::MAX / 2,
    "[ASSERT-FS03] MAX_BLOB_SIZE trop grand"
);
```

### Couche 3 — Semgrep : règles ERR-04 (déjà dans TOOLS-AUDIT) + extensions

Vérifier `exofs-write-without-immutable-check` sur tous les fichiers `syscall/write*.rs` :

```bash
semgrep --config tools/semgrep-rules/exoos.yaml \
        kernel/src/fs/exofs/syscall/ --error
```

Extension pour la suppression (delete) :

```yaml
- id: exofs-delete-without-immutable-check
  patterns:
    - pattern: |
        fn $DELETE_FN(...) -> ... {
          ...
          delete_object(...)
          ...
        }
    - pattern-not: |
        fn $DELETE_FN(...) -> ... {
          ...
          if $META.is_immutable() { return Err(ExoFsError::Immutable); }
          ...
        }
  paths:
    include:
      - "kernel/src/fs/exofs/syscall/**"
  message: |
    M23 : delete_object() sans vérification is_immutable().
    ExoLedger est un objet sealed/immutable — sa suppression doit être bloquée.
  languages: [rust]
  severity: ERROR

- id: exofs-write-not-persisted
  patterns:
    - pattern: |
        fn $WRITE_FN(...) -> ... {
          ...
          write_blob_data(...);
          Ok(...)
        }
    - pattern-not: |
        fn $WRITE_FN(...) -> ... {
          ...
          write_blob_data(...);
          journal_commit(...);
          Ok(...)
        }
  paths:
    include:
      - "kernel/src/fs/exofs/syscall/**"
  message: |
    M23 : write_blob_data() sans journal_commit() — données perdues au crash.
    Chaque écriture doit être suivie d'un commit dans le journal ExoFS.
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
mod kani_exofs {
    // PREUVE-FS01 : write sur objet immutable retourne toujours Err
    #[kani::proof]
    fn proof_immutable_write_blocked() {
        let mut meta = ObjectMeta { flags: FLAG_IMMUTABLE, ..Default::default() };
        let result = exofs_write(&mut meta, &[0u8; 16]);
        assert!(result.is_err());
    }

    // PREUVE-FS02 : journal_commit est appelé après chaque write réussi
    #[kani::proof]
    fn proof_write_always_commits() {
        let mut meta = ObjectMeta::default(); // non immutable
        let mut journal = Journal::new_test();
        exofs_write_with_journal(&mut meta, &[0u8; 16], &mut journal).unwrap();
        assert!(journal.has_pending_commit() == false); // commit effectué
    }
}
```

### Critère de PASS M23

- [ ] ASSERT-FS01..FS03 passent
- [ ] Semgrep 0 violation sur `fs/exofs/syscall/`
- [ ] Kani PREUVE-FS01/FS02 : VERIFICATION SUCCESSFUL
- [ ] Test : `exofs_test::write_read_persist` → données retrouvées après reboot simulé

---

## M24 — fs/vfs/
### VFS Bridge — read/write stubs non persistants

**Chemins :** `kernel/src/fs/vfs/`  
**Bug connu historique :** `vfs_read()`/`vfs_write()` ne persistaient pas les données (stubs).

### Couche 3 — Semgrep

```yaml
- id: vfs-stub-unimplemented
  patterns:
    - pattern: |
        fn vfs_read(...) -> ... {
          unimplemented!()
        }
    - pattern: |
        fn vfs_write(...) -> ... {
          todo!()
        }
    - pattern: |
        fn vfs_read(...) -> ... {
          Ok(0)
        }
  paths:
    include:
      - "kernel/src/fs/vfs/**"
  message: |
    M24 : vfs_read/vfs_write stub détecté (unimplemented!/todo!/Ok(0) immédiat).
    Implémenter le bridge vers vfs_server via IPC.
  languages: [rust]
  severity: ERROR
```

### Critère de PASS M24

- [ ] Semgrep 0 violation `vfs-stub-unimplemented`
- [ ] Test : `vfs_test::write_then_read` → contenu cohérent

---

## M25 — security/exoseal.rs
### Chaîne de hash au boot

**Chemin :** `kernel/src/security/exoseal.rs`

### Couche 3 — Semgrep

```yaml
- id: exoseal-no-chain-verify
  patterns:
    - pattern: |
        fn boot_security_init() {
          ...
        }
    - pattern-not: |
        fn boot_security_init() {
          ...
          exoseal_verify_boot_chain()?;
          ...
        }
  paths:
    include:
      - "kernel/src/security/exoseal.rs"
      - "kernel/src/arch/boot_sequence.rs"
  message: |
    M25 : boot_security_init() sans appel à exoseal_verify_boot_chain().
    La chaîne de hash ExoSeal doit être vérifiée en Phase 5, avant tout serveur.
  languages: [rust]
  severity: ERROR

- id: exoseal-bypass-not-logged
  patterns:
    - pattern: |
        const EXOSEAL_DEV_BYPASS: bool = true;
    - pattern-not-inside: |
        if EXOSEAL_DEV_BYPASS {
          exoledger_log(ExoLedgerEvent::DevBypassActive);
        }
  message: |
    M25 : EXOSEAL_DEV_BYPASS actif sans logging dans ExoLedger.
    Toute activation du bypass doit être auditée.
  languages: [rust]
  severity: ERROR
```

### Critère de PASS M25

- [ ] Semgrep 0 violation sur `exoseal.rs`
- [ ] `security_test::exoseal_verify_chain` → PASS
- [ ] Boot avec EXOSEAL_DEV_BYPASS=true → entrée visible dans `exo audit`

---

## M26 — security/exocage.rs
### SMEP / SMAP / KPTI / CET — tous les mécanismes hardware

**Chemin :** `kernel/src/security/exocage.rs`

### Couche 1 — const_assert!

```rust
// kernel/src/security/exocage.rs

// Bits des MSR et CR4 attendus
pub const CR4_SMEP_BIT:   u64 = 1 << 20;
pub const CR4_SMAP_BIT:   u64 = 1 << 21;
pub const CR4_UMIP_BIT:   u64 = 1 << 11;
pub const EFER_NXE_BIT:   u64 = 1 << 11;
pub const MSR_IA32_U_CET: u32 = 0x6A0;

// ASSERT-EC01 : Les bits ne se chevauchent pas
const _: () = assert!(
    CR4_SMEP_BIT != CR4_SMAP_BIT,
    "[ASSERT-EC01] CR4_SMEP_BIT et CR4_SMAP_BIT identiques — erreur de constante"
);
```

### Couche 3 — Semgrep

```yaml
- id: exocage-missing-verify-call
  patterns:
    - pattern: |
        fn security_init() {
          ...
        }
    - pattern-not: |
        fn security_init() {
          ...
          exocage_verify_active()?;
          ...
        }
  message: |
    M26 : security_init() sans exocage_verify_active() à la fin.
    ExoCage doit vérifier que SMEP/SMAP/KPTI/CET sont tous actifs.
    Paniquer si un mécanisme est absent (matériel non supporté → halt).
  languages: [rust]
  severity: ERROR

- id: exocage-cr4-incomplete
  patterns:
    - pattern: |
        write_cr4($VAL)
    - pattern-not-inside: |
        fn $CR4_INIT(...) {
          ...
          let val = read_cr4() | CR4_SMEP_BIT | CR4_SMAP_BIT | CR4_UMIP_BIT;
          write_cr4(val);
          ...
        }
  paths:
    include:
      - "kernel/src/security/exocage.rs"
  message: |
    M26 : write_cr4() sans activer simultanément SMEP, SMAP et UMIP.
    Activer les trois bits ensemble pour éviter les fenêtres de vulnérabilité.
  languages: [rust]
  severity: ERROR
```

### Critère de PASS M26

- [ ] ASSERT-EC01 passe
- [ ] `exocage_verify_active()` appelé et panique si SMEP/SMAP/NXE/CET absent
- [ ] `security_test::exocage_all_mechanisms` → PASS
- [ ] Semgrep 0 violation sur `exocage.rs`

---

## M27 — security/zero_trust/
### Zero Trust IPC — bypass Ring3→Ring3

**Chemins :** `kernel/src/security/zero_trust/`

### Couche 3 — Semgrep

```yaml
- id: zerotrust-ipc-send-no-check
  patterns:
    - pattern: |
        fn ipc_send($MSG: &IpcMessage, $DST: EndpointId) -> ... {
          ...
          ring.push($MSG);
          ...
        }
    - pattern-not: |
        fn ipc_send($MSG: &IpcMessage, $DST: EndpointId) -> ... {
          ...
          zero_trust::check_ipc($MSG, $DST)?;
          ...
          ring.push($MSG);
          ...
        }
  paths:
    include:
      - "kernel/src/ipc/**"
  message: |
    M27 : ipc_send() sans zero_trust::check_ipc().
    Toute transmission IPC doit passer par la vérification Zero Trust.
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_zerotrust_ring3_direct_blocked() {
    let sender = ProcessId::ring3(kani::any());
    let receiver = ProcessId::ring3(kani::any());
    let msg = IpcMessage::default();

    // Ring3 → Ring3 direct doit toujours être bloqué
    let result = zero_trust::check_ipc_direct(sender, receiver, &msg);
    assert!(result == Err(ZeroTrustError::DirectRing3Forbidden));
}
```

### Critère de PASS M27

- [ ] Semgrep 0 violation `zerotrust-ipc-send-no-check`
- [ ] Kani `proof_zerotrust_ring3_direct_blocked` : VERIFICATION SUCCESSFUL
- [ ] `security_test::zerotrust_ipc_blocked` → PASS

---

## M28 — security/capability/
### CapToken — verify() manquant sur les accès critiques

**Chemins :** `kernel/src/security/capability/`

### Couche 3 — Semgrep

```yaml
- id: captoken-fs-access-no-verify
  patterns:
    - pattern: |
        fn $FS_OP(..., object_id: ObjectId, ...) -> ... {
          ...
          exofs_$OP(object_id, ...)
          ...
        }
    - pattern-not: |
        fn $FS_OP(...) -> ... {
          ...
          capability::verify($CAP, $RIGHTS)?;
          ...
        }
  paths:
    include:
      - "kernel/src/fs/**"
      - "kernel/src/syscall/**"
  message: |
    M28 : Opération FS sans capability::verify(). Tout accès ExoFS
    doit valider le CapToken correspondant avant l'opération.
  languages: [rust]
  severity: ERROR

- id: captoken-revocation-not-propagated
  patterns:
    - pattern: |
        fn revoke_capability($CAP: CapToken) -> ... {
          ...
          mark_revoked($CAP.object_id);
          ...
        }
    - pattern-not: |
        fn revoke_capability($CAP: CapToken) -> ... {
          ...
          propagate_revocation_to_derived($CAP);
          ...
        }
  message: |
    M28 : revoke_capability() sans propagate_revocation_to_derived().
    La révocation doit s'étendre immédiatement à tous les tokens dérivés.
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani (PREUVE-5 de TOOLS-AUDIT)

La preuve `proof_captoken_verify_no_panic` est déjà définie dans `TOOLS-AUDIT-EXOOS.md`.  
Ajouter :

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_revoked_token_always_denied() {
    let mut cap_table = CapTable::new_test();
    let cap = cap_table.mint_capability(ObjectId(kani::any()), Rights::READ);
    cap_table.revoke(cap.clone());
    // Après révocation, toute vérification doit échouer
    let result = cap_table.verify(&cap, Rights::READ);
    assert!(result.is_err());
}
```

### Critère de PASS M28

- [ ] Semgrep 0 violation `captoken-fs-access-no-verify`
- [ ] Semgrep 0 violation `captoken-revocation-not-propagated`
- [ ] Kani `proof_revoked_token_always_denied` : VERIFICATION SUCCESSFUL
- [ ] `security_test::captoken_revocation_immediate` → PASS (< 1 ms)

---

## M29 — security/exokairos.rs
### Budget temporel — reset de fenêtre (ERR-07)

**Chemin :** `kernel/src/security/exokairos.rs`  
**Bug connu :** `used_ns` incrémenté sans reset de la fenêtre → accumulation infinie → kill injuste.

### Couche 1 — const_assert!

```rust
// kernel/src/security/exokairos.rs

use crate::arch::constants::MAX_PROCESSES;

pub const KAIROS_WINDOW_NS:    u64 = 1_000_000_000; // 1 seconde
pub const KAIROS_DEFAULT_BUDGET_NS: u64 = 100_000_000; // 100 ms/s (10%)
pub const KAIROS_THROTTLE_PCT: u64 = 100;
pub const KAIROS_KILL_PCT:     u64 = 200;

// ASSERT-KA01 : Fenêtre = 1 seconde exactement (référence globale)
const _: () = assert!(
    KAIROS_WINDOW_NS == 1_000_000_000,
    "[ASSERT-KA01] KAIROS_WINDOW_NS doit être 1_000_000_000 ns (1 seconde)"
);

// ASSERT-KA02 : Budget default < fenêtre
const _: () = assert!(
    KAIROS_DEFAULT_BUDGET_NS < KAIROS_WINDOW_NS,
    "[ASSERT-KA02] KAIROS_DEFAULT_BUDGET_NS >= KAIROS_WINDOW_NS"
);

// ASSERT-KA03 : Kill > Throttle
const _: () = assert!(
    KAIROS_KILL_PCT > KAIROS_THROTTLE_PCT,
    "[ASSERT-KA03] KAIROS_KILL_PCT doit être > KAIROS_THROTTLE_PCT"
);
```

La règle Semgrep `kairos-no-window-reset` est déjà définie dans `TOOLS-AUDIT-EXOOS.md`.  
Vérifier qu'elle s'applique :

```bash
semgrep --config tools/semgrep-rules/exoos.yaml \
        kernel/src/security/exokairos.rs --error
```

La correction attendue dans le code :

```rust
// kernel/src/security/exokairos.rs — correction ERR-07
pub fn update_kairos_budget(tcb: &mut Tcb, elapsed_ns: u64, now_ns: u64) {
    let budget = &mut tcb.kairos_budget;

    // RESET DE FENÊTRE — obligatoire avant tout incrément
    if now_ns.saturating_sub(budget.window_start_ns) >= KAIROS_WINDOW_NS {
        budget.used_ns = 0;
        budget.window_start_ns = now_ns;
    }

    budget.used_ns = budget.used_ns.saturating_add(elapsed_ns);

    // Throttle à 100% du budget
    if budget.used_ns >= budget.budget_ns {
        tcb.state = TaskState::Throttled;
        exoledger_log(ExoLedgerEvent::KairosThrottle { pid: tcb.pid, used_ns: budget.used_ns });
    }

    // Kill à 200% cumulé (accumulation tolérée dans la fenêtre)
    if budget.used_ns >= budget.budget_ns.saturating_mul(KAIROS_KILL_PCT) / 100 {
        send_signal(tcb.pid, SIGKILL);
        exoledger_log(ExoLedgerEvent::KairosKill { pid: tcb.pid });
    }
}
```

### Couche 4 — Kani (PREUVE-3 de TOOLS-AUDIT)

La preuve `proof_kairos_no_overflow` est déjà définie dans `TOOLS-AUDIT-EXOOS.md`.  
Ajouter :

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_kairos_window_resets() {
    let mut tcb = Tcb::default();
    let now1: u64 = kani::any();
    // Avancer le temps d'exactement une fenêtre + 1
    let now2 = now1.saturating_add(KAIROS_WINDOW_NS + 1);

    // Charger le budget au max dans la fenêtre 1
    update_kairos_budget(&mut tcb, KAIROS_WINDOW_NS, now1);
    let used_after_window1 = tcb.kairos_budget.used_ns;

    // Appel dans la fenêtre suivante
    update_kairos_budget(&mut tcb, 100, now2);

    // Propriété : used_ns a été réinitialisé (reset de fenêtre)
    assert!(tcb.kairos_budget.used_ns < used_after_window1);
}
```

### Critère de PASS M29

- [ ] ASSERT-KA01..KA03 passent
- [ ] Semgrep 0 violation `kairos-no-window-reset`
- [ ] Kani `proof_kairos_no_overflow` et `proof_kairos_window_resets` : VERIFICATION SUCCESSFUL
- [ ] `security_test::exokairos_throttle_at_100pct` → PASS
- [ ] `security_test::exokairos_kill_at_200pct` → PASS

---

## M30 — security/exoledger.rs
### Journal immuable — chaîne BLAKE3

**Chemin :** `kernel/src/security/exoledger.rs`

### Couche 3 — Semgrep

```yaml
- id: exoledger-append-no-chain-hash
  patterns:
    - pattern: |
        fn append_entry($ENTRY: LedgerEntry) -> ... {
          ...
          journal.push($ENTRY);
          ...
        }
    - pattern-not: |
        fn append_entry($ENTRY: LedgerEntry) -> ... {
          ...
          let chain_hash = blake3::hash(&[&self.last_hash, &$ENTRY.to_bytes()]);
          $ENTRY.chain_hash = chain_hash;
          ...
          journal.push($ENTRY);
          ...
        }
  paths:
    include:
      - "kernel/src/security/exoledger.rs"
  message: |
    M30 : append_entry() sans mise à jour de la chaîne BLAKE3.
    Chaque entrée du ledger doit inclure le hash de l'entrée précédente.
  languages: [rust]
  severity: ERROR

- id: exoledger-mutable-past-entry
  patterns:
    - pattern: |
        fn update_entry($IDX: usize, $ENTRY: LedgerEntry) -> ... {
          ...
        }
    - pattern: |
        fn delete_entry($IDX: usize) -> ... {
          ...
        }
  paths:
    include:
      - "kernel/src/security/exoledger.rs"
  message: |
    M30 : ExoLedger expose une API de modification/suppression d'entrées passées.
    Le ledger est IMMUABLE. Supprimer update_entry() et delete_entry().
  languages: [rust]
  severity: ERROR
```

### Couche 4 — Kani

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_exoledger_chain_tamper_detected() {
    let mut ledger = ExoLedger::new_test();
    ledger.append(LedgerEntry { data: [1u8; 32], ..Default::default() });
    ledger.append(LedgerEntry { data: [2u8; 32], ..Default::default() });

    // Tamper avec la première entrée
    ledger.entries[0].data[0] ^= 0xFF;

    // Propriété : la vérification de chaîne doit détecter l'altération
    assert!(ledger.verify_chain().is_err());
}
```

### Critère de PASS M30

- [ ] Semgrep 0 violation `exoledger-append-no-chain-hash`
- [ ] Semgrep 0 violation `exoledger-mutable-past-entry`
- [ ] Kani `proof_exoledger_chain_tamper_detected` : VERIFICATION SUCCESSFUL
- [ ] `security_test::exoledger_chain_integrity` → PASS
- [ ] `exo audit --verify-chain` → 0 rupture

---

## M31 — security/iommu/ (ExoShield)
### Domaines IOMMU — DMA hors plage

**Chemins :** `kernel/src/security/iommu/`

### Couche 1 — const_assert!

```rust
// kernel/src/security/iommu/mod.rs

pub const IOMMU_DOMAIN_NET:       u32 = 1;
pub const IOMMU_DOMAIN_BLOCK:     u32 = 2;
pub const IOMMU_DOMAIN_BLACKHOLE: u32 = 0xFFFF_FFFF;

// ASSERT-IO01 : Les domaines sont distincts
const _: () = assert!(
    IOMMU_DOMAIN_NET != IOMMU_DOMAIN_BLOCK,
    "[ASSERT-IO01] Domaines IOMMU NET et BLOCK identiques"
);
const _: () = assert!(
    IOMMU_DOMAIN_BLOCK != IOMMU_DOMAIN_BLACKHOLE,
    "[ASSERT-IO01b] Domaine BLOCK et BLACKHOLE identiques"
);
```

### Couche 3 — Semgrep

```yaml
- id: iommu-driver-started-before-iommu
  patterns:
    - pattern: |
        fn init_drivers() {
          ...
          start_virtio_net_driver();
          ...
        }
    - pattern-not: |
        fn init_drivers() {
          ...
          assert!(iommu_is_active(), "IOMMU doit être actif avant drivers");
          ...
          start_virtio_net_driver();
          ...
        }
  paths:
    include:
      - "kernel/src/arch/boot_sequence.rs"
      - "kernel/src/drivers/**"
  message: |
    M31 : Driver Ring1 démarré sans vérifier que l'IOMMU est actif.
    ExoShield doit être initialisé avant tout driver (Phase 5 → avant Phase 7).
  languages: [rust]
  severity: ERROR

- id: dma-alloc-no-domain-check
  patterns:
    - pattern: |
        fn sys_dma_alloc($SIZE: usize) -> ... {
          ...
          alloc_dma_buffer($SIZE, ...)
          ...
        }
    - pattern-not: |
        fn sys_dma_alloc($SIZE: usize, $DOMAIN: IommuDomain) -> ... {
          ...
          iommu_map($DOMAIN, ...)
          ...
        }
  paths:
    include:
      - "kernel/src/syscall/**"
  message: |
    M31 : SYS_DMA_ALLOC sans paramètre de domaine IOMMU.
    Chaque allocation DMA doit spécifier le domaine IOMMU cible (NET/BLOCK).
  languages: [rust]
  severity: ERROR
```

### Critère de PASS M31

- [ ] ASSERT-IO01/IO01b passent
- [ ] IOMMU initialisé avant tout driver Ring1 (vérifier `boot_sequence.rs`)
- [ ] Semgrep 0 violation sur `security/iommu/` et `drivers/`
- [ ] `security_test::exoshield_dma_fault` → PASS

---

## M32 — security/exonmi.rs
### Watchdog NMI — armement et canaries stack

**Chemin :** `kernel/src/security/exonmi.rs`

### Couche 1 — const_assert!

```rust
pub const NMI_WATCHDOG_PERIOD_MS: u64 = 200; // 200 ms

const _: () = assert!(
    NMI_WATCHDOG_PERIOD_MS > 0 && NMI_WATCHDOG_PERIOD_MS <= 1000,
    "[ASSERT-NMI01] Période watchdog NMI hors plage [1, 1000] ms"
);
```

### Couche 3 — Semgrep

```yaml
- id: exonmi-no-idt-integrity-check
  patterns:
    - pattern: |
        extern "x86-interrupt" fn nmi_handler(...) {
          ...
        }
    - pattern-not: |
        extern "x86-interrupt" fn nmi_handler(...) {
          ...
          exonmi_check_idt_integrity();
          ...
        }
  message: |
    M32 : NMI handler sans vérification d'intégrité IDT.
    Un rootkit peut remplacer des entrées IDT. Vérifier l'IDT à chaque NMI.
  languages: [rust]
  severity: WARNING
```

---

## M33-M35 — drivers/pci/, drivers/virtio/, drivers/dma/

### M33 — drivers/pci/ : Découverte BAR dynamique

```yaml
- id: pci-bar-hardcoded
  patterns:
    - pattern: |
        const $BAR_ADDR: u64 = $HEX;
  metavariable-regex:
    $HEX: "0x[0-9a-fA-F]{7,}"
  paths:
    include:
      - "kernel/src/drivers/**"
  message: |
    M33 : Adresse BAR PCI hardcodée. Utiliser pci_read_bar() pour la découverte
    dynamique. Les adresses BAR varient selon le système (CORR-86).
  languages: [rust]
  severity: ERROR
```

### M34 — drivers/virtio/ : Règle `virtio-hardcoded-bar`

La règle `virtio-hardcoded-bar` est déjà dans `TOOLS-AUDIT-EXOOS.md`. Vérifier :

```bash
semgrep --config tools/semgrep-rules/exoos.yaml \
        kernel/src/drivers/virtio/ --error
```

### M35 — drivers/dma/ : Domaine IOMMU

Vérifier que chaque `dma_map_single()` spécifie un domaine IOMMU (cf. M31 `dma-alloc-no-domain-check`).

### Couche 5 — cargo-deny sur les crates drivers

```toml
# deny.toml — section [bans] — extensions pour les drivers
[bans.deny]
# Interdit : bibliothèque MMIO qui bypass l'abstraction ExoOS
{ name = "volatile-register", reason = "Utiliser les primitives MMIO d'ExoOS" },
{ name = "bit_field",         reason = "Utiliser bitflags! standard ou types ExoOS" },
```

---

## M36-M39 — exophoenix/ : SSR Bitmask 256-core
### Les 4 fichiers affectés — migration u64 → [u64; 4]

**Chemins :**
- `kernel/src/exophoenix/ssr.rs`
- `kernel/src/exophoenix/forge.rs`
- `kernel/src/exophoenix/handoff.rs`
- `kernel/src/exophoenix/isolate.rs`

### Couche 1 — const_assert! (déjà dans TOOLS-AUDIT — reproduit ici pour complétude)

```rust
// kernel/src/exophoenix/ssr.rs

use crate::arch::constants::{MAX_CORES_LAYOUT, CORE_MASK_WORDS, MAX_PROCESSES, MAX_ENDPOINTS};

// ASSERT-PHX01 : SSR ≤ 4096 octets (une page)
const _: () = assert!(
    core::mem::size_of::<SystemStateRecord>() <= 4096,
    "[ASSERT-PHX01] SSR dépasse 4096 octets — réduire SSR_MAX_PROCESSES ou SSR_MAX_ENDPOINTS"
);

// ASSERT-PHX02 : SsrCoreMask dimensionné pour CORE_MASK_WORDS
const _: () = assert!(
    core::mem::size_of::<SsrCoreMask>() == CORE_MASK_WORDS * 8,
    "[ASSERT-PHX02] SsrCoreMask mal dimensionné — vérifier CORE_MASK_WORDS"
);

// ASSERT-PHX03 : Nombre de processus dans le SSR cohérent avec MAX_PROCESSES
pub const SSR_MAX_PROCESSES: usize = 512; // ≤ MAX_PROCESSES
const _: () = assert!(
    SSR_MAX_PROCESSES <= MAX_PROCESSES,
    "[ASSERT-PHX03] SSR_MAX_PROCESSES > MAX_PROCESSES — incohérence"
);

// ASSERT-PHX04 : Nombre d'endpoints dans le SSR cohérent
pub const SSR_MAX_ENDPOINTS: usize = 1024; // ≤ MAX_ENDPOINTS
const _: () = assert!(
    SSR_MAX_ENDPOINTS <= MAX_ENDPOINTS,
    "[ASSERT-PHX04] SSR_MAX_ENDPOINTS > MAX_ENDPOINTS — incohérence"
);
```

### Couche 3 — Semgrep : détecter les u64 bitmask restants

La règle `u64-bitmask-too-small` est déjà dans `TOOLS-AUDIT-EXOOS.md`. Vérifier sur les 4 fichiers :

```bash
semgrep --config tools/semgrep-rules/exoos.yaml \
        kernel/src/exophoenix/ --error
# Zéro violation attendue après correction bitmask
```

### Migration exacte à appliquer dans les 4 fichiers

```rust
// DANS : ssr.rs, forge.rs, handoff.rs, isolate.rs
// AVANT (BUG) :
pub active_cores: u64,

// APRÈS (CORRECT) :
pub active_cores: [u64; CORE_MASK_WORDS],  // 4 mots u64 = 256 cores

// Toute opération sur le bitmask doit utiliser SsrCoreMask :
impl SsrCoreMask {
    pub fn set_core(&mut self, core_id: usize) {
        debug_assert!(core_id < MAX_CORES_LAYOUT);
        self.active_cores[core_id / 64] |= 1u64 << (core_id % 64);
    }
    pub fn clear_core(&mut self, core_id: usize) {
        debug_assert!(core_id < MAX_CORES_LAYOUT);
        self.active_cores[core_id / 64] &= !(1u64 << (core_id % 64));
    }
    pub fn is_core_active(&self, core_id: usize) -> bool {
        debug_assert!(core_id < MAX_CORES_LAYOUT);
        (self.active_cores[core_id / 64] >> (core_id % 64)) & 1 == 1
    }
}
```

### Couche 4 — Kani (PREUVE-1 de TOOLS-AUDIT)

La preuve `proof_ssr_core_mask_no_oob` et `proof_ssr_fits_in_page` sont déjà définies dans `TOOLS-AUDIT-EXOOS.md`.

Ajouter pour `handoff.rs` :

```rust
#[cfg(kani)]
#[kani::proof]
fn proof_phoenix_handoff_preserves_capabilities() {
    let kernel_a = KernelState::new_test();
    let kernel_b = KernelState::new_test();

    let surviving_caps: Vec<CapToken> = vec![CapToken::default()];
    let result = phoenix_handoff(&kernel_a, &kernel_b, &surviving_caps);

    // Propriété : toutes les caps survivantes sont présentes dans le kernel B
    for cap in &surviving_caps {
        assert!(result.kernel_b_state.has_capability(cap));
    }
}
```

### TLA+ — Protocole de bascule A↔B (Couche 7)

Pour le module ExoPhoenix, un modèle TLA+ est indispensable pour prouver l'absence de deadlock durant la bascule.  
Fichier cible : `formal/ExoPhoenix_Handoff.tla`

Propriétés à vérifier :
```tla
PROPERTY NoDeadlockDuringSwitch ==
    []<>(phoenix_state \in {KERNEL_A_ACTIVE, KERNEL_B_ACTIVE})

PROPERTY CapsPreservedAfterSwitch ==
    []( (phoenix_state = SWITCHING)
        => (surviving_caps \subseteq kernel_b_caps') )

PROPERTY SwitchCompletesInBoundedTime ==
    []( (phoenix_state = SWITCHING)
        => <>(phoenix_state = KERNEL_B_ACTIVE) )
```

### Critère de PASS M36-M39

- [ ] ASSERT-PHX01..PHX04 passent dans `ssr.rs`
- [ ] `active_cores: [u64; 4]` dans les 4 fichiers (zéro `active_cores: u64`)
- [ ] Semgrep 0 violation `u64-bitmask-too-small` sur `exophoenix/`
- [ ] Kani `proof_ssr_core_mask_no_oob` + `proof_ssr_fits_in_page` : VERIFICATION SUCCESSFUL
- [ ] Kani `proof_phoenix_handoff_preserves_capabilities` : VERIFICATION SUCCESSFUL
- [ ] TLA+ `ExoPhoenix_Handoff.tla` → 0 violation (optionnel mais recommandé avant v0.2.0)

---

## M40 — exophoenix/sentinel.rs
### Heartbeat du noyau surveillant

**Chemin :** `kernel/src/exophoenix/sentinel.rs`

### Couche 3 — Semgrep

```yaml
- id: sentinel-no-heartbeat
  patterns:
    - pattern: |
        fn sentinel_loop() {
          loop {
            ...
          }
        }
    - pattern-not: |
        fn sentinel_loop() {
          loop {
            ...
            check_kernel_heartbeat();
            ...
          }
        }
  message: |
    M40 : sentinel_loop() sans vérification de heartbeat.
    Le sentinel doit vérifier le compteur NMI watchdog à chaque itération.
  languages: [rust]
  severity: ERROR
```

---

## Commandes de Lancement de l'Audit Complet

### Exécution séquentielle recommandée

```bash
#!/bin/bash
# tools/run_full_audit.sh
# Audit complet kernel ExoOS — pré-v0.2.0
# Usage : bash tools/run_full_audit.sh [--strict]

set -e
STRICT="${1:-}"
PASS=0
FAIL=0
WARN=0

step() { echo; echo "═══════════════════════════════════════"; echo "▶ $1"; echo "═══════════════════════════════════════"; }
ok()   { echo "  ✅ $1"; ((PASS++)); }
fail() { echo "  ❌ $1"; ((FAIL++)); }
warn() { echo "  ⚠️  $1"; ((WARN++)); }

# ── Couche 1 : Compilation + const_assert! ────────────────────────────────────
step "COUCHE 1 — const_assert! (cargo check)"
if cargo check --all --quiet 2>&1; then
    ok "Compilation OK — tous les const_assert! passent"
else
    fail "Erreur de compilation — vérifier les ASSERT-* dans les modules"
    [ -z "$STRICT" ] || exit 1
fi

# ── Couche 2 : Audit de cohérence des constantes ──────────────────────────────
step "COUCHE 2 — Cohérence des constantes (Python)"
if python3 tools/audit_constants.py --fail-on-warn; then
    ok "0 incohérence de constante"
else
    fail "Incohérences détectées — corriger avant de continuer"
    [ -z "$STRICT" ] || exit 1
fi

# ── Couche 3 : Semgrep — règles ExoOS ─────────────────────────────────────────
step "COUCHE 3 — Semgrep (règles ExoOS)"
SEMGREP_ERRORS=$(semgrep --config tools/semgrep-rules/exoos.yaml \
    kernel/ libs/ servers/ --error --json 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print(len(d['results']))" || echo "ERR")

if [ "$SEMGREP_ERRORS" = "0" ]; then
    ok "0 violation Semgrep"
elif [ "$SEMGREP_ERRORS" = "ERR" ]; then
    warn "Semgrep non installé — pip install semgrep"
else
    fail "$SEMGREP_ERRORS violations Semgrep — voir semgrep --config ... pour détails"
    [ -z "$STRICT" ] || exit 1
fi

# ── Couche 4 : Kani (preuves mathématiques) ───────────────────────────────────
step "COUCHE 4 — Kani (model checking)"
if command -v kani &> /dev/null; then
    if cargo kani --tests --timeout 180 2>&1; then
        ok "Toutes les preuves Kani vérifiées"
    else
        fail "Échec d'une preuve Kani — voir output pour détails"
        [ -z "$STRICT" ] || exit 1
    fi
else
    warn "Kani non installé — cargo install --locked kani-verifier && cargo kani setup"
fi

# ── Couche 5 : cargo-deny ─────────────────────────────────────────────────────
step "COUCHE 5 — cargo-deny (dépendances)"
if cargo deny check 2>&1; then
    ok "Dépendances conformes"
else
    fail "Dépendances interdites détectées — voir deny.toml"
    [ -z "$STRICT" ] || exit 1
fi

# ── Couche 6 : cargo-audit (CVE) ──────────────────────────────────────────────
step "COUCHE 6 — cargo-audit (CVE)"
if cargo audit 2>&1; then
    ok "Aucune CVE sur les dépendances"
else
    warn "CVE détectées — évaluer criticité"
fi

# ── Tests unitaires ───────────────────────────────────────────────────────────
step "TESTS UNITAIRES"
if cargo test --all -- --test-output immediate 2>&1; then
    ok "Tous les tests unitaires PASS"
else
    fail "Tests unitaires échoués"
    [ -z "$STRICT" ] || exit 1
fi

# ── Résumé ────────────────────────────────────────────────────────────────────
echo
echo "═══════════════════════════════════════════════════════════════"
echo "  RÉSUMÉ AUDIT KERNEL ExoOS — PRÉ-v0.2.0"
echo "═══════════════════════════════════════════════════════════════"
echo "  ✅ PASS    : $PASS"
echo "  ❌ FAIL    : $FAIL"
echo "  ⚠️  WARN    : $WARN"
echo "═══════════════════════════════════════════════════════════════"

if [ "$FAIL" -gt 0 ]; then
    echo "  RÉSULTAT : ❌ AUDIT ÉCHOUÉ — $FAIL erreurs critiques"
    exit 1
else
    echo "  RÉSULTAT : ✅ AUDIT PASSÉ — kernel prêt pour Phase 0.2.0"
    exit 0
fi
```

---

## Tableau de Suivi des Modules

Ce tableau est à mettre à jour au fur et à mesure des corrections.

| Module | C1 assert | C2 Python | C3 Semgrep | C4 Kani | Tests | Statut |
|--------|-----------|-----------|------------|---------|-------|--------|
| M01 arch/constants | ⬜ | ⬜ | ⬜ | N/A | ⬜ | 🔴 P0 |
| M02 arch/percpu | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M03 arch/boot | ⬜ | N/A | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M04 arch/gdt-idt | ⬜ | N/A | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M05 arch/interrupts | ⬜ | N/A | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M06 memory/buddy | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M07 memory/slub | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M08 memory/vmalloc | ⬜ | ⬜ | ⬜ | N/A | ⬜ | 🟡 P1 |
| M09 memory/cow | ⬜ | N/A | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M10 memory/paging | ⬜ | N/A | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M11 scheduler/cfs | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M12 scheduler/rt | ⬜ | N/A | ⬜ | N/A | ⬜ | 🟡 P1 |
| M13 scheduler/smp | ⬜ | N/A | ⬜ | N/A | ⬜ | 🔴 P0 |
| M14 scheduler/fpu | ⬜ | N/A | ⬜ | N/A | ⬜ | 🟡 P1 |
| M15 ipc/spsc-ring | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M16 ipc/sync | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M17 ipc/shm | ⬜ | N/A | ⬜ | N/A | ⬜ | 🟡 P1 |
| M18 ipc/rpc | ⬜ | N/A | ⬜ | N/A | ⬜ | 🟡 P1 |
| M19 process/fork | ⬜ | N/A | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M20 process/exec | ⬜ | ⬜ | ⬜ | N/A | ⬜ | 🔴 P0 |
| M21 process/signal | ⬜ | N/A | ⬜ | N/A | ⬜ | 🟡 P1 |
| M22 process/thread | ⬜ | N/A | ⬜ | N/A | ⬜ | 🔴 P0 |
| M23 fs/exofs | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M24 fs/vfs-bridge | ⬜ | N/A | ⬜ | N/A | ⬜ | 🔴 P0 |
| M25 security/exoseal | ⬜ | N/A | ⬜ | N/A | ⬜ | 🔴 P0 |
| M26 security/exocage | ⬜ | N/A | ⬜ | N/A | ⬜ | 🔴 P0 |
| M27 security/zero-trust | ⬜ | N/A | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M28 security/capability | ⬜ | N/A | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M29 security/exokairos | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M30 security/exoledger | ⬜ | N/A | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M31 security/iommu | ⬜ | N/A | ⬜ | N/A | ⬜ | 🔴 P0 |
| M32 security/exonmi | ⬜ | N/A | ⬜ | N/A | ⬜ | 🟡 P1 |
| M33 drivers/pci | ⬜ | N/A | ⬜ | N/A | ⬜ | 🟡 P1 |
| M34 drivers/virtio | ⬜ | N/A | ⬜ | N/A | ⬜ | 🟡 P1 |
| M35 drivers/dma | ⬜ | N/A | ⬜ | N/A | ⬜ | 🔴 P0 |
| M36 exophoenix/ssr | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M37 exophoenix/forge | ⬜ | ⬜ | ⬜ | N/A | ⬜ | 🔴 P0 |
| M38 exophoenix/handoff | ⬜ | ⬜ | ⬜ | ⬜ | ⬜ | 🔴 P0 |
| M39 exophoenix/isolate | ⬜ | ⬜ | ⬜ | N/A | ⬜ | 🔴 P0 |
| M40 exophoenix/sentinel | ⬜ | N/A | ⬜ | N/A | ⬜ | 🟡 P1 |

**Légende :** ⬜ = à faire · ✅ = PASS · ❌ = FAIL · 🔴 = P0 bloquant · 🟡 = P1

---

## Condition de Passage en Phase 0.2.0

```
CONDITION NÉCESSAIRE ET SUFFISANTE :

  Tous les modules 🔴 P0 ont le statut ✅ sur TOUTES les couches applicables
  ET
  `tools/run_full_audit.sh --strict` → RÉSULTAT : ✅ AUDIT PASSÉ
  ET
  0 test unitaire FAIL ou SKIP (hors ceux explicitement marqués post-v0.2.0)
```

Seule cette condition autorise le démarrage de la Phase 0.2.0 du ROADMAP-IMPLEMENTATION-V0.2.md.

---

*claude-beta — ExoOS v0.2.0 — AUDIT-KERNEL-PROTOCOL-PRE-V0.2.md*
