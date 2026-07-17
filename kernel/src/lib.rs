//! # Exo-OS Kernel — Re-exports publics
//!
//! `lib.rs` expose l'API publique du noyau aux crates externes et aux tests.
//! Le point d'entrée réel (`_start` → `kernel_main`) est dans `main.rs`.
//!
//! ## Architecture des couches (docs/refonte)
//! ```
//! Couche 0   : memory/    — aucune dépendance kernel
//! Couche 1   : scheduler/ — dépend de memory/
//! Couche 1.5 : process/   — dépend de memory/ + scheduler/
//! Couche 2a  : security/  — dépend de memory/ + scheduler/process bootstrap
//! Couche 2b  : ipc/       — dépend de memory/ + scheduler/ + process/ + security/
//! Couche 3   : fs/        — dépend de tout sauf ipc/ direct
//! Transverse : arch/      — peut appeler n'importe quelle couche
//! ```
//!
//! ## Règles absolues
//! - `unsafe` → `// SAFETY:` obligatoire (regle_bonus.md)
//! - scheduler/core/ + ISR → NO-ALLOC (regle_bonus.md)
//! - Lock ordering : Memory → Scheduler → Security → IPC → FS (regle_bonus.md)
//! - signal/ ∈ process/ uniquement (DOC1 RÈGLE SIGNAL-01)
//! - capability/ ∈ security/ uniquement (DOC1 RÈGLE CAP-01)
//! - futex ∈ memory/utils/futex_table.rs (DOC3 RÈGLE SCHED-03)

#![cfg_attr(all(target_os = "none", not(kani)), no_std)]
#![allow(binary_asm_labels)]
#![allow(unexpected_cfgs)]

#[cfg(all(not(target_arch = "x86_64"), not(test)))]
compile_error!("ExoOS kernel v0.2.0 supporte uniquement x86_64 comme cible de boot.");

// Garde-fou anti-piège: les tests unitaires du crate kernel doivent être
// compilés sur une cible host (std), pas sur la cible bare-metal no_std.
// Sans ce garde-fou, `cargo test --target x86_64-unknown-none` produit une
// avalanche d'erreurs secondaires (`std`/prelude/macros introuvables).
#[cfg(all(test, target_os = "none"))]
compile_error!(
    "exo-os-kernel: `cargo test` sur cible bare-metal est non supporté. \
Utiliser une cible hôte pour les tests (ex: --target x86_64-unknown-linux-gnu), \
ou utiliser le check bare-metal via run_tests.sh/Makefile."
);

// ── Crates externes (no_std) ──────────────────────────────────────────────────

extern crate alloc;

#[cfg(all(test, not(target_os = "none")))]
extern crate std;

// ── Modules kernel ────────────────────────────────────────────────────────────

/// Couche transverse : code spécifique à l'architecture
pub mod arch;

/// Couche 0 : gestion mémoire physique, virtuelle, heap, DMA
pub mod memory;

/// Couche 1 : ordonnanceur, context switch, politiques d'ordo
pub mod scheduler;

/// Couche 1.5 : processus, threads, signaux, cycle de vie
pub mod process;

/// Couche 2a : IPC zero-copy, channels, shared memory
pub mod ipc;

/// Couche 2b : capabilities, isolation, intégrité
pub mod security;

/// Couche 3 : système de fichiers virtuel + exofs
pub mod fs;

/// GI-03 : wrappers canoniques IRQ/DMA/PCI/IOMMU
pub mod drivers;

/// ExoPhoenix (Kernel B) : état partagé SSR + orchestration sentinelle.
pub mod exophoenix;

/// Interface syscall → dispatch vers les couches supérieures
pub mod syscall;

/// Bootstrap des serveurs Ring1 et du PID 1.
pub mod userspace_boot;

// ── Re-exports publics ─────────────────────────────────────────────────────────
// Seuls les symboles nécessaires aux crates externes (tests, outils) sont exportés.
// Le binaire kernel_main utilise ces modules directement via `exo_os_kernel::`.

// FIX-LIB-CFG: ajout du guard #[cfg(target_arch = "x86_64")] manquant.
// Sans ce guard, la suppression accidentelle du compile_error! de la ligne 30
// produirait des erreurs de résolution de symboles cryptiques sur AArch64
// plutôt qu'un message clair.
#[cfg(target_arch = "x86_64")]
pub use arch::x86_64::{
    // Informations d'architecture
    arch_info,
    // Point d'entrée d'initialisation architecture
    boot::early_init::arch_boot_init,
    // Primitives bas niveau exposées
    halt_cpu,
    memory_barrier,
    KERNEL_BASE,
    // Constantes
    PAGE_SIZE,
};
#[cfg(target_arch = "x86_64")]
pub use arch::ArchInfo;

#[cfg(target_arch = "x86_64")]
pub use arch::x86_64::cpu::{
    features::{CpuFeatures, CPU_FEATURES},
    tsc::read_tsc,
};

/// Séquence d'initialisation des couches (appelée depuis `kernel_main` dans main.rs).
///
/// Suit l'ordre DOC2 + DOC3 :
/// 1. arch          (déjà fait avant cet appel)
/// 2. memory/       — EmergencyPool EN PREMIER (RÈGLE EMERGENCY-01)
/// 3. scheduler/    — après memory
/// 4. process/      — après scheduler
/// 5. security/     — après process bootstrap (RÈGLE SEC-BOOT-GAP : avant IPC)
/// 6. ipc/          — après process + security
/// 7. fs/           — en dernier
///
/// # Safety
/// Doit être appelé une seule fois, depuis le BSP, après `arch_boot_init`.
pub unsafe fn kernel_init(cpu_count: usize) {
    #[inline(always)]
    unsafe fn kdb(b: u8) {
        core::arch::asm!("out 0xE9, al", in("al") b, options(nomem, nostack));
    }

    struct IrqStateGuard(u64);

    impl Drop for IrqStateGuard {
        fn drop(&mut self) {
            crate::arch::x86_64::irq_restore(self.0);
        }
    }
    // ── Phase 2a : EmergencyPool — PREMIER ABSOLU (RÈGLE EMERGENCY-01) ─────────
    crate::memory::physical::frame::emergency_pool::init();
    kdb(b'2'); // Phase 2a done

    // ── Phase 2b : Allocateur heap (SLUB + large) ────────────────────────────
    crate::memory::heap::allocator::hybrid::init();
    crate::memory::cow::init();
    let _ = crate::arch::x86_64::apic::local_apic::init_lapic_fixmap_post_memory();
    kdb(b'3'); // Phase 2b done
    crate::arch::x86_64::boot_display::stage_ok("MEMORY");

    // ── Phase 2c : Time subsystem (HPET + calibration TSC + ktime seqlock) ────────
    // Remplace les 3 appels directs par time_init() qui orchestre :
    //   init_hpet_post_memory() → calibrate_tsc() → pll_init → init_ktime() → clock::init()
    // FIX TIME-02/03 : calibration par fenêtre temporelle réelle (loop = ticks HPET).
    // FIX TIME-01    : ktime protegé par seqlock ISR-safe.
    crate::arch::x86_64::time::time_init();
    kdb(b'4'); // Phase 2c done
    crate::arch::x86_64::boot_display::stage_ok("TIME");

    // ── Phase 2d : drivers GI-03 (IOMMU queues + notifications kernel) ────────
    crate::drivers::init();
    kdb(b'D'); // Phase 2d done
    crate::arch::x86_64::boot_display::stage_ok("DRIVERS");

    // ── Phase 2e : ExoSeal/ExoCage pré-scheduler (CORR-82 / S-03) ───────────
    // ExoSeal phase0 est idempotente et doit verrouiller CET/PKS/IOMMU avant
    // l'initialisation des runqueues et la création de threads.
    unsafe {
        crate::security::exoseal::exoseal_boot_phase0();
    }
    kdb(b'C');
    crate::arch::x86_64::boot_display::stage_ok("EXOSEAL0");

    // ── Phase 2f : cgroup root before runqueues (CORR-77) ─────────────
    crate::process::resource::cgroup::init();
    kdb(b'c'); // cgroup root ready before scheduler runqueues

    // ── Phase 3 : Scheduler ───────────────────────────────────────────
    let sched_cpus = if crate::arch::x86_64::smp::init::smp_boot_complete() {
        cpu_count.max(1)
    } else {
        1
    };
    crate::scheduler::init(&crate::scheduler::SchedInitParams {
        nr_cpus: sched_cpus,
        nr_nodes: 1,
    });
    kdb(b'5'); // Phase 3 done

    // ── Phase 3b : Thread idle de bootstrap (BSP + APs déjà en ligne) ─────────
    let _ = crate::scheduler::core::publish_current_boot_idle(
        0,
        crate::arch::x86_64::boot::early_init::boot_stack_top(),
    );
    crate::scheduler::core::bind_boot_idle_threads(sched_cpus);
    kdb(b'6'); // idle thread done

    // ── Phase 3c : Enregistrement du cloner d'espace d'adressage ───────────────
    // CORRECTION P0-01 : register le cloner pour fork() AVANT process::init()
    {
        use crate::memory::virt::address_space::fork_impl::KERNEL_AS_CLONER;
        use crate::process::lifecycle::fork::register_addr_space_cloner;
        register_addr_space_cloner(&KERNEL_AS_CLONER);
    }
    kdb(b'F'); // fork cloner registered
    crate::arch::x86_64::boot_display::stage_ok("SCHEDULER");

    // ── Phase 4 : Process ────────────────────────────────────────────────────
    // CORRECTIF : le crash GPF "f000ff53f000ff53" observé précédemment était causé
    // par le bug LAPIC LVT LINT0 (vecteur 0x8E non masqué, livré par le BIOS QEMU).
    // Corrigé par init_local_apic() qui masque tous les LVT entries (commit 40da75e).
    //
    // De plus, create_kthread() utilise désormais le bon frame stack pour
    // context_switch_asm (MXCSR+FCW + 6 regs + kthread_trampoline) au lieu
    // des 2 u64 incorrects qui corrompaient le stack au premier context switch.
    //
    // process::init() orchestre :
    //   1. pid::init()              — réserve PID 0 (idle) et PID 1 (init)
    //   2. registry::init()         — alloue la table PCB (32768 slots)
    //   3. lifecycle::reap::init_reaper() — enfile le kthread reaper
    //   4. state::wakeup::register_with_dma() — enregistre le handler DMA
    //   5. resource::cgroup::init() — initialise le cgroup racine
    //
    // NOTE: process::init() appelle cgroup::init() qui référence CGROUP_TABLE (~28KB .data).
    // Cette section est initialisée correctement mais augmente la taille du binaire.
    // Seuls les sous-systèmes critiques pour le démarrage sont activés ici :
    // GUARD: désactiver les interruptions pendant l'init du sous-système process
    // pour éviter qu'un timer interrupt ne déclenche un context switch avec des
    // structures de données partiellement initialisées.
    let process_irq_guard = IrqStateGuard(crate::arch::x86_64::irq_save());
    kdb(b'a'); // avant process::init
    crate::process::init(&crate::process::ProcessInitParams::default());
    drop(process_irq_guard);
    kdb(b'P'); // Phase 4 done (process init + cgroup root + OOM hooks)
    crate::arch::x86_64::boot_display::stage_ok("PROCESS");

    // ── Phase 5 : Security ──────────────────────────────────────────────────
    // Si la sécurité a déjà été initialisée en early boot (SECURITY_READY=true),
    // ne pas réinitialiser capability/crypto (double init -> panic).
    if !crate::security::is_security_ready() {
        let mut kaslr_entropy = crate::arch::x86_64::cpu::tsc::read_tsc()
            ^ crate::memory::core::layout::KERNEL_LOAD_PHYS_ADDR.rotate_left(17);
        let mut rdrand = [0u8; 8];
        if crate::security::crypto::rng::rdrand_fill(&mut rdrand).is_ok() {
            kaslr_entropy ^= u64::from_le_bytes(rdrand);
        }
        crate::security::security_init(
            kaslr_entropy,
            crate::memory::core::layout::KERNEL_LOAD_PHYS_ADDR,
        );
    }
    kdb(b'7'); // security done

    // ERR-05 fix: Init graine SipHash de la table futex (anti-DoS hash collision).
    {
        let mut seed = [0u8; 16];
        if crate::security::crypto::rng_fill(&mut seed).is_ok() {
            crate::memory::utils::futex_table::init_futex_seed(seed);
        }
    }
    kdb(b'8'); // futex seed done
    crate::arch::x86_64::boot_display::stage_ok("SECURITY");

    // TIER 2.1-a : kthread moniteur d'intégrité runtime (mode observe). Vérifie
    // périodiquement `.text/.rodata` une fois le boot sécurité terminé ; journalise
    // toute divergence dans ExoLedger sans paniquer (boot-safe). Best-effort.
    crate::security::start_integrity_monitor();

    // ── Phase 5b : ExoPhoenix Stage0 (domaine IOMMU de blocage) ─────────────
    // FIX-STAGE0 (rapport_analyse_kernel_exo_os.md §4.1) :
    // stage0_init_all_steps() n'était jamais appelé, laissant
    // IOMMU_BLOCKED_DOMAIN_ID = 0 (domaine identité VT-d par défaut).
    // Lors d'un handoff ExoPhoenix, stage_soft_revoke_iommu() flushait
    // le domaine 0 au lieu du domaine de blocage dédié → isolation silencieusement inopérante.
    //
    // Doit être après security_init() (PhasePhoenix nécessite le sous-système
    // de sécurité pour les capabilities IOMMU) et avant ipc_init() (Phase 6).
    //
    // SAFETY: appelé une seule fois depuis le BSP, après security_init().
    // FIX-BOOT-STAGE0-HANG : kernel_a_boot=true ⇒ saute les étapes Kernel-B qui
    // clobbent l'état CPU du BSP (TSS/IDT/timer APIC), cause du hang après SECURITY.
    let _stage0_summary = crate::exophoenix::stage0::stage0_init_all_steps(true);
    kdb(b'S'); // Stage0 ExoPhoenix done
    crate::arch::x86_64::boot_display::stage_ok("STAGE0");

    // ── Phase 6 : IPC ────────────────────────────────────────────────────────
    ipc::ring::spsc::init_spsc_rings();
    // BUG-C2B FIX: réserver un pool SHM physique dédié avant l'initialisation IPC.
    const SHM_POOL_ORDER: usize = 8; // 2^8 pages = 256 pages = 1 MiB
    let shm_pool =
        match crate::memory::alloc_pages(SHM_POOL_ORDER, crate::memory::AllocFlags::ZEROED) {
            Ok(pool) => pool,
            Err(err) => {
                panic!(
                    "ipc shm pool allocation failed: order={} err={:?}",
                    SHM_POOL_ORDER, err
                );
            }
        };
    crate::ipc::ipc_init(
        shm_pool.start_address().as_u64(),
        1, // nr_numa_nodes — à lire depuis ACPI NUMA si disponible
    );
    crate::ipc::ipc_install_scheduler_hooks(crate::scheduler::core::switch::block_current_thread);
    // P1-02 : installer les hooks VMM pour le mappage SHM dans les espaces
    // d'adressage des processus. Doit être fait après ipc_init() et avant
    // tout appel à shm_map() (i.e. avant le démarrage des serveurs Ring1).
    crate::ipc::ipc_install_vmm_hooks(
        crate::arch::x86_64::memory_iface::shm_vmm_map_page,
        crate::arch::x86_64::memory_iface::shm_vmm_unmap_page,
    );
    kdb(b'9'); // IPC done
    crate::arch::x86_64::boot_display::stage_ok("IPC");

    // ── Phase 7 : FS ─────────────────────────────────────────────────────────
    let exofs_ready = crate::fs::exofs::exofs_init(
        crate::fs::exofs::storage::virtio_adapter::default_global_disk_size_bytes(),
    )
    .is_ok();

    kdb(b'R'); // exofs_init retourné (post-#6)
    if exofs_ready {
        // DIAG: seed_kernel_a_image_blob temporairement sauté pour isoler le fault.
        // let _ = crate::exophoenix::forge::seed_kernel_a_image_blob();
    }
    kdb(b'T'); // seed_kernel_a_image_blob fait (ou sauté)

    // CORRECTION P0-02 : enregistrer le chargeur ELF après exofs_init
    {
        use crate::fs::elf_loader_impl::EXO_ELF_LOADER;
        use crate::memory::virt::fault::demand_paging::{
            register_file_fault_provider, FileFaultProvider,
        };
        use crate::process::lifecycle::exec::register_elf_loader;
        register_elf_loader(&EXO_ELF_LOADER);

        let provider: &dyn FileFaultProvider = &EXO_ELF_LOADER;
        let (data, vtable): (*const (), *const ()) = unsafe { core::mem::transmute(provider) };
        unsafe {
            register_file_fault_provider(data, vtable);
        }
    }
    kdb(b'E'); // ELF loader registered

    // BUG-02 FIX: activer le bridge syscall→fs après exofs_init
    // SAFETY: exofs_init() terminé, appelé une seule fois depuis BSP
    unsafe {
        crate::syscall::fs_bridge::fs_bridge_init();
        crate::syscall::net_bridge::net_bridge_preinit();
    }
    kdb(b'@'); // fs_bridge/net_bridge actifs
    crate::arch::x86_64::boot_display::stage_ok("FS");
}

#[cfg(all(target_os = "none", not(kani)))]
#[panic_handler]
fn kernel_panic(info: &core::panic::PanicInfo) -> ! {
    // BUG-5 FIX: l'ancien handler effectuait un halt silencieux sans aucun diagnostic.
    // Tout unwrap()/expect() stoppait le système sans message → débogage impossible.
    //
    // Port 0xE9 = QEMU ISA debug device : sortie directe sans initialisation requise.
    // Disponible dès le reset, même avant l'init des drivers série.
    #[inline(always)]
    unsafe fn debug_byte(b: u8) {
        core::arch::asm!("out 0xE9, al", in("al") b, options(nomem, nostack));
    }
    #[inline(always)]
    unsafe fn debug_str(s: &[u8]) {
        for &b in s {
            debug_byte(b);
        }
    }
    #[inline(always)]
    unsafe fn debug_u32(mut n: u32) {
        let mut buf = [0u8; 10];
        let mut len = 0usize;
        if n == 0 {
            debug_byte(b'0');
            return;
        }
        while n > 0 {
            buf[len] = b'0' + (n % 10) as u8;
            len += 1;
            n /= 10;
        }
        for i in (0..len).rev() {
            debug_byte(buf[i]);
        }
    }
    // SAFETY: CLI depuis Ring 0 — toujours sûr. debug_byte écrit sur le port 0xE9.
    unsafe {
        core::arch::asm!("cli", options(nostack, nomem));
        debug_str(b"\n\x1B[1;31m*** KERNEL PANIC ***\x1B[0m ");
        if let Some(loc) = info.location() {
            debug_str(loc.file().as_bytes());
            debug_byte(b':');
            debug_u32(loc.line());
            debug_byte(b':');
            debug_u32(loc.column());
        } else {
            debug_str(b"<location inconnue>");
        }
        debug_byte(b'\n');
    }
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nostack, nomem));
        }
    }
}

#[cfg(all(target_os = "none", not(kani)))]
#[alloc_error_handler]
fn alloc_error_handler(layout: core::alloc::Layout) -> ! {
    // BUG-5 FIX: même correction — affiche taille/alignement sur port 0xE9 QEMU.
    #[inline(always)]
    unsafe fn debug_byte(b: u8) {
        core::arch::asm!("out 0xE9, al", in("al") b, options(nomem, nostack));
    }
    #[inline(always)]
    unsafe fn debug_usize(mut n: usize) {
        let mut buf = [0u8; 20];
        let mut len = 0usize;
        if n == 0 {
            debug_byte(b'0');
            return;
        }
        while n > 0 {
            buf[len] = b'0' + (n % 10) as u8;
            len += 1;
            n /= 10;
        }
        for i in (0..len).rev() {
            debug_byte(buf[i]);
        }
    }
    unsafe {
        core::arch::asm!("cli", options(nostack, nomem));
        for &b in b"\n*** ALLOC ERROR size=" {
            debug_byte(b);
        }
        debug_usize(layout.size());
        for &b in b" align=" {
            debug_byte(b);
        }
        debug_usize(layout.align());
        debug_byte(b'\n');
    }
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nostack, nomem));
        }
    }
}

// ── Point d'entrée principal du kernel (BSP) ─────────────────────────────────
//
// Note : kernel_main est défini dans main.rs (le binaire).
// La lib expose uniquement kernel_init(), arch_boot_init() et halt_cpu().
