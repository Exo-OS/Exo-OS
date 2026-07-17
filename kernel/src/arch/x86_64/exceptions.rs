//! # arch/x86_64/exceptions.rs — Handlers d'exceptions CPU
//!
//! Implémente les handlers pour les 32 exceptions x86_64 (vecteurs 0–31),
//! les IRQ hardware, et les IPIs scheduler.
//!
//! ## Règle DOC1 — Point de retour userspace après préemption
//! `exception_return_to_user()` est le SECOND point d'orchestration des signaux
//! (avec `syscall_return_to_user()`). Après toute exception depuis Ring 3,
//! arch/ vérifie `signal_pending` et orchestre la livraison.
//!
//! ## Séquence handler d'exception
//! 1. Sauvegarder registres (PUSH dans ASM entry)
//! 2. SWAPGS si Ring 3 (vérifier CS saved sur la pile)
//! 3. Appeler handler Rust
//! 4. `exception_return_to_user()` si retour vers Ring 3
//! 5. SWAPGS si Ring 3
//! 6. IRETQ

use core::concat;
use core::sync::atomic::{AtomicU64, Ordering};

// ── Ponts C ABI vers le scheduler (RÈGLE FPU-02 + RÈGLE IPI-01 DOC3) ─────────
//
// arch/ ne peut pas importer scheduler/ directement (éviter cycle de dépendance
// Rust crate-level). Les deux fonctions ci-dessous sont exportées par le
// scheduler via `#[no_mangle] pub unsafe extern "C"` et résolues à l'édition
// des liens.
//
// sched_fpu_handle_nm   — scheduler/fpu/lazy.rs     — handler #NM (FPU lazy)
// sched_ipi_reschedule  — scheduler/timer/tick.rs   — IPI reschedule
extern "C" {
    /// Gère l'exception #NM (Device Not Available) pour le TCB courant.
    /// Efface CR0.TS et restaure le contexte FPU via xrstor.
    /// `tcb_ptr` = GS:[0x20] (current_tcb). Si null → simple clts.
    fn sched_fpu_handle_nm(tcb_ptr: *mut u8);
    /// Positionne NEED_RESCHED sur le thread courant suite à un IPI reschedule.
    /// `tcb_ptr` = GS:[0x20] (current_tcb). Si null → ignoré.
    fn sched_ipi_reschedule(tcb_ptr: *mut u8);
    /// Tick du scheduler timer : avance les quantum, décide préemption.
    /// `cpu_id` = GS:[0x10], `current` = GS:[0x20].
    fn scheduler_tick(cpu_id: u32, current: *mut u8);
    /// Pont arch/→process/ : livraison signaux au retour exception Ring 3.
    /// `tcb_ptr` = GS:[0x20], `excframe` = &mut ExceptionFrame courant.
    fn proc_signal_on_exception_return(tcb_ptr: *mut u8, excframe: *mut u8);
}

// ── Frame d'exception ─────────────────────────────────────────────────────────

/// Registres sauvegardés par le CPU + l'ASM de stub lors d'une exception
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct ExceptionFrame {
    // Registres sauvegardés par l'ASM stub (caller-saved)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,

    // Poussés par le stub ou le CPU selon l'exception
    pub error_code: u64,

    // Poussés automatiquement par le CPU
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64, // Présent uniquement si changement de niveau de privilège
    pub ss: u64,  // Idem
}

impl ExceptionFrame {
    /// Retourne `true` si l'exception vient de Ring 3 (userspace)
    #[inline(always)]
    pub fn from_userspace(&self) -> bool {
        (self.cs & 3) == 3
    }

    /// Retourne `true` si l'exception vient du kernel (Ring 0)
    #[inline(always)]
    pub fn from_kernel(&self) -> bool {
        (self.cs & 3) == 0
    }
}

// ── Macros ASM pour les stubs d'interruption ──────────────────────────────────

macro_rules! define_exception_handler_errcode {
    ($name:ident, $rust_handler:ident) => {
        core::arch::global_asm!(
            concat!(".global ", stringify!($name)),
            concat!(".type ", stringify!($name), ", @function"),
            concat!(stringify!($name), ":"),
            // À l'entrée du handler, le CPU a pousé (de bas à haut) :
            // [rsp+ 0] = error_code
            // [rsp+ 8] = RIP
            // [rsp+16] = CS  ← RPL bits [1:0] = ring level
            // [rsp+24] = RFLAGS
            // [rsp+32] = RSP  (si changement Ring 3→Ring 0)
            // [rsp+40] = SS   (si changement Ring 3→Ring 0)
            "test qword ptr [rsp + 16], 3", // CS & 3 != 0 ⇒ Ring 3
            "jz   1f",                      // ZF=1 ⇒ Ring 0 (kernel), sauter swapgs
            "swapgs",
            "mov  gs:[0x50], rax", // préserver rax pendant le switch CR3
            "mov  rax, gs:[0x40]", // kpti_kernel_cr3
            "test rax, rax",
            "jz   3f",
            "mov  cr3, rax",
            "3:",
            "mov  rax, gs:[0x50]",
            "1:",
            // Sauvegarder registres callee-saved + scratch
            "push rax",
            "push rbx",
            "push rcx",
            "push rdx",
            "push rsi",
            "push rdi",
            "push rbp",
            "push r8",
            "push r9",
            "push r10",
            "push r11",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            // ExceptionFrame* dans rdi. Le CPU peut entrer ici avec une pile
            // dont l'alignement n'est pas celui attendu par l'ABI SysV; aligner
            // la pile d'appel Rust sans déplacer la frame que le handler reçoit.
            "mov  rdi, rsp",
            "mov  r12, rsp",
            "and  rsp, -16",
            concat!("call ", stringify!($rust_handler)),
            "mov  rsp, r12",
            // Restaurer registres
            "pop  r15",
            "pop  r14",
            "pop  r13",
            "pop  r12",
            "pop  r11",
            "pop  r10",
            "pop  r9",
            "pop  r8",
            "pop  rbp",
            "pop  rdi",
            "pop  rsi",
            "pop  rdx",
            "pop  rcx",
            "pop  rbx",
            "pop  rax",
            // Dépiler error_code
            "add  rsp, 8",
            // Après add rsp,8 : [rsp+0]=RIP, [rsp+8]=CS, [rsp+16]=RFLAGS
            // Vérifier CS RPL pour le SWAPGS de sortie
            "test qword ptr [rsp + 8], 3", // CS & 3 != 0 ⇒ retour Ring 3
            "jz   2f",
            "mov  gs:[0x50], rax",
            "mov  rax, gs:[0x48]", // kpti_user_cr3
            "test rax, rax",
            "jz   4f",
            "mov  cr3, rax",
            "4:",
            "mov  rax, gs:[0x50]",
            "swapgs",
            "2:",
            "iretq",
        );
    };
}

/// Génère un stub d'entrée exception SANS error code (pousse 0 synthétique)
///
/// Après "push 0" (synthetic error_code), la pile est identique au cas errcode :
/// [rsp+ 0] = 0  (erreur synthétique)
/// [rsp+ 8] = RIP
/// [rsp+16] = CS  ← mêmes offsets que le cas errcode
macro_rules! define_exception_handler_no_errcode {
    ($name:ident, $rust_handler:ident) => {
        core::arch::global_asm!(
            concat!(".global ", stringify!($name)),
            concat!(".type ", stringify!($name), ", @function"),
            concat!(stringify!($name), ":"),
            // Pousser 0 comme error_code synthétique
            "push 0",
            // [rsp+ 0]=0, [rsp+ 8]=RIP, [rsp+16]=CS, [rsp+24]=RFLAGS ...
            "test qword ptr [rsp + 16], 3", // CS & 3 != 0 ⇒ Ring 3
            "jz   1f",
            "swapgs",
            "mov  gs:[0x50], rax", // préserver rax pendant le switch CR3
            "mov  rax, gs:[0x40]", // kpti_kernel_cr3
            "test rax, rax",
            "jz   3f",
            "mov  cr3, rax",
            "3:",
            "mov  rax, gs:[0x50]",
            "1:",
            "push rax",
            "push rbx",
            "push rcx",
            "push rdx",
            "push rsi",
            "push rdi",
            "push rbp",
            "push r8",
            "push r9",
            "push r10",
            "push r11",
            "push r12",
            "push r13",
            "push r14",
            "push r15",
            "mov  rdi, rsp",
            "mov  r12, rsp",
            "and  rsp, -16",
            concat!("call ", stringify!($rust_handler)),
            "mov  rsp, r12",
            "pop  r15",
            "pop  r14",
            "pop  r13",
            "pop  r12",
            "pop  r11",
            "pop  r10",
            "pop  r9",
            "pop  r8",
            "pop  rbp",
            "pop  rdi",
            "pop  rsi",
            "pop  rdx",
            "pop  rcx",
            "pop  rbx",
            "pop  rax",
            "add  rsp, 8",
            // Après add rsp,8 : [rsp+0]=RIP, [rsp+8]=CS
            "test qword ptr [rsp + 8], 3", // CS RPL bits
            "jz   2f",
            "mov  gs:[0x50], rax",
            "mov  rax, gs:[0x48]", // kpti_user_cr3
            "test rax, rax",
            "jz   4f",
            "mov  cr3, rax",
            "4:",
            "mov  rax, gs:[0x50]",
            "swapgs",
            "2:",
            "iretq",
        );
    };
}

// Stubs ASM pour toutes les exceptions
define_exception_handler_no_errcode!(exc_divide_error_handler, do_divide_error);
define_exception_handler_no_errcode!(exc_debug_handler, do_debug);
define_exception_handler_no_errcode!(exc_nmi_handler, do_nmi);
define_exception_handler_no_errcode!(exc_breakpoint_handler, do_breakpoint);
define_exception_handler_no_errcode!(exc_overflow_handler, do_overflow);
define_exception_handler_no_errcode!(exc_bound_range_handler, do_bound_range);
define_exception_handler_no_errcode!(exc_invalid_opcode_handler, do_invalid_opcode);
define_exception_handler_no_errcode!(exc_device_not_avail_handler, do_device_not_avail);
define_exception_handler_errcode!(exc_double_fault_handler, do_double_fault);
define_exception_handler_errcode!(exc_invalid_tss_handler, do_invalid_tss);
define_exception_handler_errcode!(exc_segment_not_present_handler, do_segment_not_present);
define_exception_handler_errcode!(exc_stack_fault_handler, do_stack_fault);
define_exception_handler_errcode!(exc_general_protection_handler, do_general_protection);
define_exception_handler_errcode!(exc_page_fault_handler, do_page_fault);
define_exception_handler_no_errcode!(exc_x87_fp_handler, do_x87_fp);
define_exception_handler_errcode!(exc_alignment_check_handler, do_alignment_check);
define_exception_handler_no_errcode!(exc_machine_check_handler, do_machine_check);
define_exception_handler_no_errcode!(exc_simd_fp_handler, do_simd_fp);
define_exception_handler_no_errcode!(exc_virtualization_handler, do_virtualization);
define_exception_handler_errcode!(exc_ctrl_protection_handler, do_ctrl_protection);

// IRQ et IPI
define_exception_handler_no_errcode!(irq_timer_handler, do_irq_timer);
define_exception_handler_no_errcode!(irq_1_handler, do_irq_1);
define_exception_handler_no_errcode!(irq_2_handler, do_irq_2);
define_exception_handler_no_errcode!(irq_3_handler, do_irq_3);
define_exception_handler_no_errcode!(irq_4_handler, do_irq_4);
define_exception_handler_no_errcode!(irq_5_handler, do_irq_5);
define_exception_handler_no_errcode!(irq_6_handler, do_irq_6);
define_exception_handler_no_errcode!(irq_7_handler, do_irq_7);
define_exception_handler_no_errcode!(irq_8_handler, do_irq_8);
define_exception_handler_no_errcode!(irq_9_handler, do_irq_9);
define_exception_handler_no_errcode!(irq_10_handler, do_irq_10);
define_exception_handler_no_errcode!(irq_11_handler, do_irq_11);
define_exception_handler_no_errcode!(irq_12_handler, do_irq_12);
define_exception_handler_no_errcode!(irq_13_handler, do_irq_13);
define_exception_handler_no_errcode!(irq_14_handler, do_irq_14);
define_exception_handler_no_errcode!(irq_15_handler, do_irq_15);
define_exception_handler_no_errcode!(irq_spurious_handler, do_irq_spurious);
define_exception_handler_no_errcode!(ipi_wakeup_handler, do_ipi_wakeup);
define_exception_handler_no_errcode!(ipi_reschedule_handler, do_ipi_reschedule);
define_exception_handler_no_errcode!(ipi_tlb_shootdown_handler, do_ipi_tlb_shootdown);
define_exception_handler_no_errcode!(ipi_cpu_hotplug_handler, do_ipi_cpu_hotplug);
define_exception_handler_no_errcode!(ipi_panic_handler, do_ipi_panic);
define_exception_handler_no_errcode!(exophoenix_freeze_handler, do_exophoenix_freeze);
define_exception_handler_no_errcode!(exophoenix_pmc_handler, do_exophoenix_pmc);
define_exception_handler_no_errcode!(exophoenix_tlb_handler, do_exophoenix_tlb);

// ── Handlers Rust d'exceptions ────────────────────────────────────────────────

#[inline(always)]
fn current_tcb_raw_checked() -> u64 {
    // SAFETY: la lecture vérifie d'abord que MSR_GS_BASE pointe sur la zone
    // per-CPU kernel avant de toucher `gs:[0x20]`.
    unsafe { super::smp::percpu::try_read_current_tcb().unwrap_or(0) }
}

#[inline(always)]
fn current_cpu_id_checked() -> u32 {
    super::smp::percpu::try_current_cpu_id().unwrap_or(0)
}

/// Retour vers userspace après exception depuis Ring 3
///
/// ## RÈGLE SIGNAL-01 (DOC1)
/// Point d'orchestration des signaux après préemption ou exception.
/// Vérifie `signal_pending` dans le TCB et orchestre la livraison.
/// La livraison effective est déléguée à `process::signal::delivery`.
fn exception_return_to_user(frame: &mut ExceptionFrame) {
    let tcb_ptr = current_tcb_raw_checked();
    if tcb_ptr == 0 {
        return;
    }
    // SAFETY: proc_signal_on_exception_return thread-safe; exclu par cli implicite dans handler.
    unsafe {
        proc_signal_on_exception_return(
            tcb_ptr as *mut u8,
            frame as *mut ExceptionFrame as *mut u8,
        );
    }

    // Les IRQ timer/IPI ne font que poser NEED_RESCHED. Le retour Ring3 est le
    // point stable où l'on peut basculer vers un autre thread, en conservant la
    // frame d'exception sur la pile kernel du thread préempté.
    // SAFETY: appelé au retour d'IRQ, point de préemption stable ; la frame
    // d'exception reste sur la pile kernel du thread préempté pendant le switch.
    unsafe {
        let _ = crate::scheduler::core::switch::schedule_current_if_needed();
    }
}

#[inline]
fn sync_kpti_user_fault_mapping(_fault_addr: u64, source_cr3: u64) {
    if !crate::arch::x86_64::spectre::kpti::kpti_enabled() {
        return;
    }

    let tcb_raw = current_tcb_raw_checked();
    if tcb_raw == 0 {
        return;
    }
    // SAFETY: tcb_raw != 0 vérifié ; pointe vers le TCB du thread courant publié
    // par le scheduler pour ce CPU, vivant pendant le handler.
    let tcb = unsafe { &*(tcb_raw as *const crate::scheduler::core::task::ThreadControlBlock) };
    let mut user_cr3 = tcb.kpti_user_cr3();
    if user_cr3 == 0 {
        user_cr3 = crate::arch::x86_64::spectre::kpti::current_user_cr3();
    }
    if user_cr3 == 0 {
        let cpu_id = crate::arch::x86_64::cpu::topology::current_cpu_id().0 as usize;
        user_cr3 =
            crate::memory::virt::page_table::kpti_split::user_cr3_for_cpu(cpu_id).unwrap_or(0);
    }
    let kernel_cr3 = if source_cr3 != 0 {
        source_cr3
    } else {
        tcb.cr3_phys
    };
    const PML4_PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    let k = kernel_cr3 & PML4_PHYS_MASK;
    let u = user_cr3 & PML4_PHYS_MASK;
    if k == 0 || u == 0 || k == u {
        return;
    }
    // SAFETY: k/u = PML4 valides (ring0).
    unsafe {
        crate::memory::virt::page_table::kpti_split::sync_user_region_to_shadow(
            crate::memory::core::PhysAddr::new(k),
            crate::memory::core::PhysAddr::new(u),
        );
    }
}

fn queue_signal_for_current(sig: crate::process::signal::Signal) {
    let tcb_raw = current_tcb_raw_checked();
    if tcb_raw == 0 {
        return;
    }
    // SAFETY: tcb_raw != 0 vérifié ; pointe vers le TCB du thread courant publié
    // par le scheduler pour ce CPU, vivant pendant le handler.
    let tcb = unsafe { &*(tcb_raw as *const crate::scheduler::core::task::ThreadControlBlock) };
    let pid = crate::process::core::pid::Pid(tcb.pid.0);
    let _ = crate::process::signal::delivery::send_signal_to_pid(pid, sig);
}

#[cfg(all(debug_assertions, exo_kernel_trace))]
fn debug_hex64(value: u64) {
    let mut buf = [0u8; 16];
    let mut shift = 60u32;
    for byte in &mut buf {
        let nibble = ((value >> shift) & 0x0f) as u8;
        *byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
        shift = shift.saturating_sub(4);
    }
    crate::arch::x86_64::terminal::debug_write(&buf);
}

#[cfg(all(debug_assertions, exo_kernel_trace))]
fn debug_read_cr3() -> u64 {
    let cr3: u64;
    // SAFETY: lecture de CR3 en Ring 0, instruction sans effet mémoire.
    unsafe {
        core::arch::asm!(
            "mov {v}, cr3",
            v = out(reg) cr3,
            options(nostack, nomem, preserves_flags),
        );
    }
    cr3 & !0xFFFu64
}

#[cfg(all(debug_assertions, exo_kernel_trace))]
fn debug_user_page_fault(
    frame: &ExceptionFrame,
    fault_addr_raw: u64,
    error_code: u64,
    user_vma_found: bool,
    user_as_for_fault: *const crate::memory::virt::UserAddressSpace,
) {
    if USER_PF_DEBUG_COUNT.fetch_add(1, Ordering::Relaxed) >= 16 {
        return;
    }

    let tcb_ptr = current_tcb_raw_checked();
    let mut pid = 0u64;
    let mut tcb_cr3 = 0u64;
    if tcb_ptr != 0 {
        // SAFETY: tcb_ptr != 0 vérifié ; pointe vers le TCB du thread courant
        // publié par le scheduler pour ce CPU (chemin debug uniquement).
        unsafe {
            let tcb = &*(tcb_ptr as *const crate::scheduler::core::task::ThreadControlBlock);
            pid = tcb.pid.0 as u64;
            tcb_cr3 = tcb.cr3_phys;
        }
    }

    let mut pcb_ptr = 0u64;
    let mut pcb_as = 0u64;
    let mut pcb_cr3 = 0u64;
    if pid != 0 {
        if let Some(pcb) = crate::process::core::registry::PROCESS_REGISTRY
            .find_by_pid(crate::process::core::pid::Pid(pid as u32))
        {
            pcb_ptr = pcb as *const _ as u64;
            pcb_as = pcb.address_space_ptr() as u64;
            pcb_cr3 = pcb.cr3.load(Ordering::Relaxed);
        }
    }

    let walk_cr3 = if !user_as_for_fault.is_null() {
        // SAFETY: pointeur non-null (vérifié), désigne l'UserAddressSpace du
        // processus en faute, vivant le temps du handler (chemin debug).
        let user_as = unsafe { &*user_as_for_fault };
        user_as.pml4_phys().as_u64()
    } else {
        tcb_cr3
    };

    let mut rip_pte = 0u64;
    let mut rsp_pte = 0u64;
    let mut cr2_pte = 0u64;
    let mut rip_frame = 0u64;
    let mut pcb_frame = 0u64;
    if walk_cr3 != 0 {
        use crate::memory::core::{PhysAddr, VirtAddr, PAGE_SIZE};
        use crate::memory::virt::page_table::PageTableWalker;

        let walker = PageTableWalker::new(PhysAddr::new(walk_cr3));
        rip_pte = walker.read_pte_raw(VirtAddr::new(frame.rip));
        rsp_pte = walker.read_pte_raw(VirtAddr::new(frame.rsp));
        cr2_pte = walker.read_pte_raw(VirtAddr::new(fault_addr_raw));
        rip_frame = rip_pte & 0x000F_FFFF_FFFF_F000;
        pcb_frame = if pcb_ptr >= crate::memory::core::layout::PHYS_MAP_BASE.as_u64() {
            (pcb_ptr - crate::memory::core::layout::PHYS_MAP_BASE.as_u64())
                & !(PAGE_SIZE as u64 - 1)
        } else {
            0
        };
    }

    let mut rip_bytes = 0u64;
    let rip_bytes_valid =
        frame.rip < crate::memory::core::layout::USER_END.as_u64() && (rip_pte & 1) != 0;
    if rip_bytes_valid {
        for i in 0..8u64 {
            // SAFETY: rip_bytes_valid garantit frame.rip < USER_END et PTE présente
            // (rip_pte & 1) ; lecture volatile d'octets user mappés (chemin debug).
            let byte = unsafe { core::ptr::read_volatile((frame.rip + i) as *const u8) };
            rip_bytes |= (byte as u64) << (i * 8);
        }
    }

    let out = crate::arch::x86_64::terminal::debug_write;
    out(b"pf: user pid=0x");
    debug_hex64(pid);
    out(b" tcb=0x");
    debug_hex64(tcb_ptr);
    out(b" tcb_cr3=0x");
    debug_hex64(tcb_cr3);
    out(b" cur_cr3=0x");
    debug_hex64(debug_read_cr3());
    out(b" pcb=0x");
    debug_hex64(pcb_ptr);
    out(b" pcb_as=0x");
    debug_hex64(pcb_as);
    out(b" pcb_cr3=0x");
    debug_hex64(pcb_cr3);
    out(b" rip=0x");
    debug_hex64(frame.rip);
    out(b" rsp=0x");
    debug_hex64(frame.rsp);
    out(b" cr2=0x");
    debug_hex64(fault_addr_raw);
    out(b" err=0x");
    debug_hex64(error_code);
    out(b" vma=");
    out(if user_vma_found { b"1" } else { b"0" });
    out(b" bytes=0x");
    if rip_bytes_valid {
        debug_hex64(rip_bytes);
    } else {
        out(b"unmapped");
    }

    if walk_cr3 != 0 {
        out(b" walk_cr3=0x");
        debug_hex64(walk_cr3);
        out(b" rip_pte=0x");
        debug_hex64(rip_pte);
        out(b" rsp_pte=0x");
        debug_hex64(rsp_pte);
        out(b" cr2_pte=0x");
        debug_hex64(cr2_pte);
        out(b" rip_frame=0x");
        debug_hex64(rip_frame);
        out(b" pcb_frame=0x");
        debug_hex64(pcb_frame);
    }
    out(b"\n");
}

/// Handler #DE — Division par zéro
#[no_mangle]
extern "C" fn do_divide_error(frame: *mut ExceptionFrame) {
    // SAFETY: `frame` est un pointeur non-null passé par le stub ASM, aligné 16 B,
    // unique pour ce contexte d'exception. Sa durée de vie est garantie par la
    // frame de pile que le CPU a poussée avant l'appel au handler.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[0].fetch_add(1, Ordering::Relaxed);

    if frame.from_userspace() {
        // Envoyer SIGFPE au processus courant via exception_return_to_user
        // (proc_signal_on_exception_return → process::signal::delivery — RÈGLE SIGNAL-01)
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("Division par zéro kernel", frame);
    }
}

/// Handler #DB — Debug exception
#[no_mangle]
extern "C" fn do_debug(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[1].fetch_add(1, Ordering::Relaxed);

    if frame.from_userspace() {
        // SIGTRAP → ptrace/GDB
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("#DB kernel", frame);
    }
}

/// Handler #NMI — Non-Maskable Interrupt
///
/// NMI utilise IST2 (pile dédiée indépendante de la pile courante).
/// NE PAS appeler de code qui pourrait provoquer une exception.
#[no_mangle]
extern "C" fn do_nmi(frame: *mut ExceptionFrame) {
    // SAFETY: `frame` est fourni par le stub d'interruption NMI sur IST2, pointe
    // vers une ExceptionFrame valide construite par le CPU à l'entrée du handler.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[2].fetch_add(1, Ordering::Relaxed);
    NMI_COUNT.fetch_add(1, Ordering::Relaxed);

    if crate::exophoenix::resurrection::handle_nmi(frame) {
        return;
    }

    crate::security::exonmi::exonmi_check_idt_integrity();
}

/// Handler #BP — Breakpoint (INT3)
#[no_mangle]
extern "C" fn do_breakpoint(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[3].fetch_add(1, Ordering::Relaxed);

    if frame.from_userspace() {
        // SIGTRAP
        exception_return_to_user(frame);
    }
    // Kernel : kprobe ou debug noyau
}

/// Handler #OF — Overflow (INTO)
#[no_mangle]
extern "C" fn do_overflow(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[4].fetch_add(1, Ordering::Relaxed);
    if frame.from_userspace() {
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("Overflow kernel", frame);
    }
}

/// Handler #BR — Bound Range Exceeded
#[no_mangle]
extern "C" fn do_bound_range(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[5].fetch_add(1, Ordering::Relaxed);
    if frame.from_userspace() {
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("Bound Range kernel", frame);
    }
}

/// Handler #UD — Invalid Opcode
#[no_mangle]
extern "C" fn do_invalid_opcode(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[6].fetch_add(1, Ordering::Relaxed);

    if frame.from_userspace() {
        // FIX-UD-SIGILL : livrer réellement SIGILL. Sans ça, on retournait au RIP
        // fautif tel quel → l'instruction invalide (typiquement `ud2` d'un panic
        // Rust côté serveur) re-déclenche immédiatement #UD → livelock noyau
        // (boucle do_invalid_opcode → iretq → même opcode) gelant tout le système.
        // Comme #PF/#GP, on met SIGILL en attente puis on repasse en Ring 3 : le
        // signal est délivré (handler ou terminaison) au lieu de boucler.
        queue_signal_for_current(crate::process::signal::Signal::SIGILL);
        exception_return_to_user(frame);
    } else {
        // Vérifier si c'est une instruction XTEST (TSX) — retpoline parfois génère #UD
        // Pour l'instant : kernel panic
        kernel_panic_exception("Invalid Opcode kernel", frame);
    }
}

/// Handler #NM — Device Not Available (FPU lazy)
///
/// Déclenché quand CR0.TS=1 et qu'un thread tente d'utiliser la FPU.
/// scheduler/fpu/lazy.rs gère la logique — arch/ gère l'exception.
#[no_mangle]
extern "C" fn do_device_not_avail(frame: *mut ExceptionFrame) {
    let _ = frame;
    EXC_COUNTERS[7].fetch_add(1, Ordering::Relaxed);
    FPU_DEVICE_NOT_AVAIL_COUNT.fetch_add(1, Ordering::Relaxed);

    let tcb_ptr = current_tcb_raw_checked();

    // Déléguer au scheduler (RÈGLE FPU-02 DOC3) :
    //   • Efface CR0.TS (autorise l'accès FPU/SIMD).
    //   • Appelle xrstor pour restaurer le contexte FPU du thread courant.
    //   • Met à jour fpu_loaded = true dans le TCB.
    // Si tcb_ptr == 0 (boot / idle) : simple clts sans xrstor.
    // SAFETY: sched_fpu_handle_nm() est thread-safe pour le CPU courant.
    unsafe {
        sched_fpu_handle_nm(tcb_ptr as *mut u8);
    }
}

/// Handler #DF — Double Fault
///
/// Utilise IST1 (pile dédiée). Si on arrive ici, la pile kernel principale
/// est probablement corrompue ou overflow.
///
/// NE PAS allouer, NE PAS prendre de verrous.
#[no_mangle]
extern "C" fn do_double_fault(frame: *mut ExceptionFrame) {
    // DIAG: marqueur brut inconditionnel à l'entrée (#DF sur IST1).
    // SAFETY: port E9, sans effet mémoire.
    unsafe { core::arch::asm!("out 0xE9, al", in("al") b'D', options(nomem, nostack)) };
    EXC_COUNTERS[8].fetch_add(1, Ordering::Relaxed);
    df_debug_write(b"\n[#DF] double fault");
    if !frame.is_null() {
        // SAFETY: frame non-null (vérifié) ; ExceptionFrame construite par le CPU
        // sur la pile IST du #DF, valide pour lecture pendant le handler.
        let frame = unsafe { &*frame };
        df_debug_field(b" rip=0x", frame.rip);
        df_debug_field(b" cs=0x", frame.cs);
        df_debug_field(b" rsp=0x", frame.rsp);
        df_debug_field(b" rflags=0x", frame.rflags);
        df_debug_field(b" err=0x", frame.error_code);
    }
    df_debug_field(
        b" cpu=0x",
        crate::arch::x86_64::cpu::topology::current_cpu_id().0 as u64,
    );
    df_debug_write(b"\n");

    // RÈGLE NO-ALLOC : cette fonction ne peut faire aucune allocation
    // Elle ne peut qu'arrêter le CPU
    // SAFETY: situation non-récupérable — halt immédiat
    super::halt_cpu();
}

#[inline(always)]
fn df_debug_write(bytes: &[u8]) {
    crate::arch::x86_64::terminal::debug_write(bytes);
}

fn df_debug_hex64(value: u64) {
    let mut out = [0u8; 16];
    for (idx, byte) in out.iter_mut().enumerate() {
        let shift = 60 - (idx as u32 * 4);
        let nibble = ((value >> shift) & 0x0f) as u8;
        *byte = if nibble < 10 {
            b'0' + nibble
        } else {
            b'a' + (nibble - 10)
        };
    }
    df_debug_write(&out);
}

fn df_debug_field(label: &[u8], value: u64) {
    df_debug_write(label);
    df_debug_hex64(value);
}

/// Handler #TS — Invalid TSS
#[no_mangle]
extern "C" fn do_invalid_tss(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[10].fetch_add(1, Ordering::Relaxed);
    kernel_panic_exception("Invalid TSS", frame);
}

/// Handler #NP — Segment Not Present
#[no_mangle]
extern "C" fn do_segment_not_present(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[11].fetch_add(1, Ordering::Relaxed);
    if frame.from_userspace() {
        // SIGBUS
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("Segment Not Present kernel", frame);
    }
}

/// Handler #SS — Stack Fault
#[no_mangle]
extern "C" fn do_stack_fault(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[12].fetch_add(1, Ordering::Relaxed);
    if frame.from_userspace() {
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("Stack Fault kernel", frame);
    }
}

/// Handler #GP — General Protection Fault
#[no_mangle]
extern "C" fn do_general_protection(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[13].fetch_add(1, Ordering::Relaxed);
    GP_FAULT_COUNT.fetch_add(1, Ordering::Relaxed);

    if frame.from_userspace() {
        // SIGSEGV
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("#GP kernel", frame);
    }
}

/// Handler #PF — Page Fault
///
/// Dispatcher vers les handlers de la couche memory/ :
/// - CoW break              → memory::virt::fault::cow
/// - Demand paging          → memory::virt::fault::demand_paging
/// - Swap-in                → memory::virt::fault::swap_in
/// - Violation d'accès      → SIGSEGV (Ring 3) ou KernelFault (Ring 0)
///
/// ## Intégration memory/ (RÈGLE MEM-01 DOC2)
/// `memory::virt::fault::handler::handle_page_fault()` est le seul point
/// d'entrée pour tous les faults. Il prend un `FaultContext` construit ici
/// et un `FaultAllocator` (implémenté par `KernelFaultAllocator`).
///
/// ## Intégration process/ (RÈGLE DOC1)
/// Quand process/ sera intégré, l'allocateur utilisera l'espace d'adressage
/// du processus courant. Pour l'instant, `KernelFaultAllocator` est utilisé.
#[no_mangle]
extern "C" fn do_page_fault(frame: *mut ExceptionFrame) {
    // SAFETY: `frame` est un pointeur non-null passé par le stub ASM, aligné 16 B,
    // unique pour ce contexte d'exception.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[14].fetch_add(1, Ordering::Relaxed);
    super::paging::inc_page_fault();

    // CR2 contient l'adresse virtuelle qui a causé le fault.
    let fault_addr_raw = super::read_cr2();
    let error_code = frame.error_code;
    // Décomposition de l'error code x86_64 :
    // bit 0 = P  (page présente — protection violation)
    // bit 1 = W  (écriture)
    // bit 2 = U  (depuis Ring 3)
    // bit 3 = RSVD (bit réservé corrompu dans le PTE)
    // bit 4 = I  (instruction fetch)
    // bit 5 = PK (protection key violation)
    let is_present = error_code & 1 != 0;
    let is_write = error_code & 2 != 0;
    let _is_user = error_code & 4 != 0;
    let is_instr_fetch = error_code & 16 != 0;
    let _ = is_present; // Utilisé implicitement via FaultCause + FaultContext

    // Construire le FaultContext
    use super::memory_iface::{UserFaultAllocator, KERNEL_FAULT_ALLOC};
    use crate::memory::core::VirtAddr;
    use crate::memory::virt::fault::{FaultCause, FaultContext, FaultResult};
    use crate::memory::virt::UserAddressSpace;

    let cause = if is_instr_fetch {
        FaultCause::Execute
    } else if is_write {
        FaultCause::Write
    } else {
        FaultCause::Read
    };

    let fault_addr = VirtAddr::new(fault_addr_raw);
    let from_kernel = frame.from_kernel();
    let mut ctx = FaultContext::new(fault_addr, cause, from_kernel).with_present(is_present);
    let mut user_as_for_fault: *const UserAddressSpace = core::ptr::null();
    let mut user_vma_found = false;
    if fault_addr.is_user() {
        let tcb_raw = current_tcb_raw_checked();
        if tcb_raw != 0 {
            // SAFETY: tcb_raw != 0 vérifié ; TCB du thread courant publié par le
            // scheduler pour ce CPU, vivant pendant le handler de #PF.
            let tcb =
                unsafe { &*(tcb_raw as *const crate::scheduler::core::task::ThreadControlBlock) };
            // FIX-CR3-FAULT-RESYNC : au bootstrap, une faute Ring 3 peut survenir
            // alors que le CR3 matériel ne correspond pas à l'espace d'adressage du
            // thread courant (`tcb.cr3_phys`, source de vérité maintenue par
            // create/execve). On recharge alors le bon CR3 : la résolution de faute
            // (demand-paging dans l'AS du thread) ET la reprise (iretq, KPTI off) se
            // font dès lors dans la bonne table → fin de la boucle de #PF d'init.
            if frame.from_userspace() && tcb.cr3_phys != 0 {
                const CR3_MASK: u64 = 0x000F_FFFF_FFFF_F000;
                let hw_cr3: u64;
                // SAFETY: lecture CR3, ring0.
                unsafe {
                    core::arch::asm!("mov {}, cr3", out(reg) hw_cr3, options(nostack, nomem));
                }
                if hw_cr3 & CR3_MASK != tcb.cr3_phys & CR3_MASK {
                    // SAFETY: tcb.cr3_phys est une PML4 valide du thread courant ;
                    // les pages noyau (code/pile/handler) sont mappées dans toutes
                    // les AS, le switch est donc sûr pendant le handler.
                    unsafe {
                        core::arch::asm!("mov cr3, {}", in(reg) tcb.cr3_phys & CR3_MASK, options(nostack, nomem));
                    }
                }
            }
            if let Some(pcb) = crate::process::core::registry::PROCESS_REGISTRY
                .find_by_pid(crate::process::core::pid::Pid(tcb.pid.0))
            {
                let as_ptr = pcb.address_space_ptr();
                if !as_ptr.is_null() {
                    // SAFETY: as_ptr non-null (vérifié), publié par lifecycle/create
                    // comme UserAddressSpace du PCB trouvé ; le PCB est vivant dans
                    // PROCESS_REGISTRY pendant le handler.
                    let user_as = unsafe { &*(as_ptr as *const UserAddressSpace) };
                    user_as_for_fault = user_as as *const UserAddressSpace;
                    user_as.record_fault();
                    if let Some(vma) = user_as.find_vma(fault_addr) {
                        ctx = ctx.with_vma(vma);
                        user_vma_found = true;
                    }
                }
            }
        }
    }
    #[cfg(all(debug_assertions, exo_kernel_trace))]
    if frame.from_userspace() {
        debug_user_page_fault(
            frame,
            fault_addr_raw,
            error_code,
            user_vma_found,
            user_as_for_fault,
        );
    }

    // Dispatcher vers le sous-système memory/
    //
    // Une faute sur une adresse userspace peut arriver avec CS=kernel pendant
    // un copy_from_user/copy_to_user ou une lecture d'argv. Elle reste une faute
    // de l'espace utilisateur courant: si une VMA existe, on la résout via le
    // même chemin demand-paging/CoW qu'une faute Ring 3, puis on reprend
    // l'instruction noyau qui accédait au pointeur user.
    let resolve_as_user = fault_addr.is_user()
        && !user_as_for_fault.is_null()
        && (frame.from_userspace() || user_vma_found);
    if resolve_as_user {
        ctx.from_kernel = false;
    }

    let result = if resolve_as_user {
        // SAFETY: resolve_as_user implique user_as_for_fault non-null ; pointe vers
        // l'UserAddressSpace du processus en faute, vivant pendant le handler.
        let user_as = unsafe { &*user_as_for_fault };
        let user_alloc = UserFaultAllocator::new(user_as);
        crate::memory::virt::fault::handler::handle_page_fault(&ctx, &user_alloc)
    } else {
        crate::memory::virt::fault::handler::handle_page_fault(&ctx, &KERNEL_FAULT_ALLOC)
    };
    match result {
        FaultResult::Handled => {
            if resolve_as_user {
                let source_cr3 = if !user_as_for_fault.is_null() {
                    // SAFETY: pointeur non-null (vérifié) ; UserAddressSpace du
                    // processus en faute, vivant pendant le handler.
                    unsafe { (&*user_as_for_fault).pml4_phys().as_u64() }
                } else {
                    0
                };
                sync_kpti_user_fault_mapping(fault_addr_raw, source_cr3);
            }
            // Fault résolu (demand paging, CoW, swap-in) — reprendre l'exécution.
            if frame.from_userspace() {
                exception_return_to_user(frame);
            }
            // En mode kernel : retour direct via IRETQ (stub ASM)
        }
        FaultResult::Segfault { addr } => {
            // Violation d'accès mémoire.
            let _ = addr;
            if frame.from_userspace() {
                // Notify ExoShield NGAV of the memory access violation.
                let tcb_seg = current_tcb_raw_checked();
                let seg_pid = if tcb_seg != 0 {
                    // SAFETY: tcb_seg != 0 checked; pointer published by scheduler for this CPU.
                    unsafe {
                        (*(tcb_seg as *const crate::scheduler::core::task::ThreadControlBlock))
                            .pid
                            .0
                    }
                } else {
                    0u32
                };
                // DIAG-25 : tracer le segfault userspace (PID + CR2 + RIP) pour
                // confirmer/localiser le crash post-fork d'ipc_router (#25).
                {
                    let out = crate::arch::x86_64::terminal::debug_write;
                    out(b"<SEGV pid=");
                    let mut v = seg_pid as u64;
                    if v == 0 {
                        out(b"0");
                    } else {
                        let mut d = [0u8; 20];
                        let mut i = d.len();
                        while v != 0 && i > 0 {
                            i -= 1;
                            d[i] = b'0' + (v % 10) as u8;
                            v /= 10;
                        }
                        out(&d[i..]);
                    }
                    let hex = |val: u64| {
                        let lut = b"0123456789abcdef";
                        let mut hb = [0u8; 16];
                        let mut x = val;
                        let mut k = 16;
                        while k > 0 {
                            k -= 1;
                            hb[k] = lut[(x & 0xf) as usize];
                            x >>= 4;
                        }
                        hb
                    };
                    out(b" cr2=");
                    out(&hex(fault_addr_raw));
                    out(b" rip=");
                    out(&hex(frame.rip));
                    out(b" rsp=");
                    out(&hex(frame.rsp));
                    out(b" err=");
                    out(&hex(error_code));
                    // DIAG-25 : octets in-memory à RIP (la page RIP est présente —
                    // l'instruction a été fetchée avant la faute data). Comparer au
                    // binaire statique → détecte une corruption du .text d'init.
                    out(b" ripb=");
                    let mut rb = 0u64;
                    // SAFETY: lecture GARDÉE — uniquement si RIP est une adresse user
                    // plausible. Sinon lire (p.ex. RIP=0x130) re-fault en KERNEL et
                    // déclenche une résurrection ExoPhoenix (perte du dump #25).
                    if frame.rip >= 0x1000 && frame.rip < 0x0000_8000_0000_0000 {
                        for bi in 0..8u64 {
                            let byte =
                                unsafe { core::ptr::read_volatile((frame.rip + bi) as *const u8) };
                            rb |= (byte as u64) << (bi * 8);
                        }
                    }
                    out(&hex(rb));
                    // DIAG-25 : contexte GP complet — révèle si les registres d'init
                    // sont corrompus (zéro / stale / décalés) au resume post-fork.
                    out(b" rax=");
                    out(&hex(frame.rax));
                    out(b" rbx=");
                    out(&hex(frame.rbx));
                    out(b" rcx=");
                    out(&hex(frame.rcx));
                    out(b" rdx=");
                    out(&hex(frame.rdx));
                    out(b" rsi=");
                    out(&hex(frame.rsi));
                    out(b" rdi=");
                    out(&hex(frame.rdi));
                    out(b" rbp=");
                    out(&hex(frame.rbp));
                    out(b" cs=");
                    out(&hex(frame.cs));
                    out(b" ss=");
                    out(&hex(frame.ss));
                    out(b" rfl=");
                    out(&hex(frame.rflags));
                    // DIAG-25 : 8 mots de la pile user à RSP — révèle la chaîne de
                    // retour (d'où provient le saut vers le RIP corrompu).
                    out(b" stk=");
                    if frame.rsp >= 0x1000 && frame.rsp < 0x0000_8000_0000_0000 {
                        for wi in 0..8u64 {
                            // SAFETY: RSP user plausible ; KPTI off ; lecture volatile.
                            let w = unsafe {
                                core::ptr::read_volatile((frame.rsp + wi * 8) as *const u64)
                            };
                            out(&hex(w));
                            out(b" ");
                        }
                    }
                    out(b">\n");
                }
                crate::security::shield_feed::push_event(
                    seg_pid,
                    crate::security::shield_feed::event_type::MEMORY,
                    crate::security::shield_feed::severity::CRITICAL,
                    0xDE, // pseudo-opcode: SIGSEGV
                    fault_addr_raw,
                    0,
                );
                queue_signal_for_current(crate::process::signal::Signal::SIGSEGV);
                exception_return_to_user(frame);
            } else {
                kernel_panic_exception("#PF kernel : accès invalide", frame);
            }
        }
        FaultResult::Oom { addr } => {
            // Out of memory — OOM killer notifié.
            let _ = addr;
            if frame.from_userspace() {
                queue_signal_for_current(crate::process::signal::Signal::SIGKILL);
                exception_return_to_user(frame);
            } else {
                kernel_panic_exception("#PF kernel : OOM", frame);
            }
        }
        FaultResult::KernelFault { addr } => {
            // Fault kernel — consulter la table de fixup P1-03.
            // Si copy_from/to_user_safe est en cours sur ce CPU, signaler
            // le fault plutôt que paniquer (la copie retournera EFAULT).
            let _ = addr;
            let cpu_id = crate::arch::x86_64::cpu::topology::current_cpu_id().0 as usize;
            if crate::syscall::fixup::fixup_lookup(cpu_id).is_some() {
                crate::syscall::fixup::fixup_signal_fault(cpu_id);
                // Retour normal — la boucle de copie verra FAULTED=true
                // et retournera false → EFAULT côté syscall.
            } else {
                kernel_panic_exception("#PF kernel : non récupérable", frame);
            }
        }
    }
}

/// Handler #MF — x87 FP Exception
#[no_mangle]
extern "C" fn do_x87_fp(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[16].fetch_add(1, Ordering::Relaxed);
    if frame.from_userspace() {
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("#MF x87 kernel", frame);
    }
}

/// Handler #AC — Alignment Check
#[no_mangle]
extern "C" fn do_alignment_check(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[17].fetch_add(1, Ordering::Relaxed);
    if frame.from_userspace() {
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("#AC kernel", frame);
    }
}

/// Handler #MC — Machine Check
///
/// Utilise IST3 (pile dédiée).
/// Ne peut pas se récupérer. Arrêt immédiat.
#[no_mangle]
extern "C" fn do_machine_check(_frame: *mut ExceptionFrame) {
    EXC_COUNTERS[18].fetch_add(1, Ordering::Relaxed);
    MC_COUNT.fetch_add(1, Ordering::Relaxed);
    // SAFETY: machine check = hardware non-récupérable
    super::halt_cpu();
}

/// Handler #XM — SIMD FP Exception
#[no_mangle]
extern "C" fn do_simd_fp(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[19].fetch_add(1, Ordering::Relaxed);
    if frame.from_userspace() {
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("#XM SIMD FP kernel", frame);
    }
}

/// Handler #VE — Virtualization Exception
#[no_mangle]
extern "C" fn do_virtualization(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[20].fetch_add(1, Ordering::Relaxed);
    if frame.from_userspace() {
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("#VE virtualization kernel", frame);
    }
}

/// Handler #CP — Control Protection Exception (CET)
#[no_mangle]
extern "C" fn do_ctrl_protection(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    EXC_COUNTERS[21].fetch_add(1, Ordering::Relaxed);
    crate::security::exocage::cp_handler(frame as *mut ExceptionFrame as usize, frame.error_code);

    if frame.from_userspace() {
        exception_return_to_user(frame);
    } else {
        kernel_panic_exception("#CP Control Protection kernel (post ExoCage)", frame);
    }
}

// ── IRQ Handlers ──────────────────────────────────────────────────────────────

#[inline(always)]
fn do_irq_generic(frame: *mut ExceptionFrame, vector: u8) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    super::idt::irq_counter_inc(vector);

    // Routage vers l'architecture GI-03
    crate::arch::x86_64::irq::routing::dispatch_irq(vector, None);

    // Conserver la même sémantique de retour userspace que les autres handlers.
    if frame.from_userspace() {
        exception_return_to_user(frame);
    }
}

macro_rules! define_generic_irq_handler {
    ($name:ident, $vector:expr) => {
        #[no_mangle]
        extern "C" fn $name(frame: *mut ExceptionFrame) {
            do_irq_generic(frame, $vector);
        }
    };
}

define_generic_irq_handler!(do_irq_1, 33);
define_generic_irq_handler!(do_irq_2, 34);
define_generic_irq_handler!(do_irq_3, 35);
define_generic_irq_handler!(do_irq_4, 36);
define_generic_irq_handler!(do_irq_5, 37);
define_generic_irq_handler!(do_irq_6, 38);
define_generic_irq_handler!(do_irq_7, 39);
define_generic_irq_handler!(do_irq_8, 40);
define_generic_irq_handler!(do_irq_9, 41);
define_generic_irq_handler!(do_irq_10, 42);
define_generic_irq_handler!(do_irq_11, 43);
define_generic_irq_handler!(do_irq_12, 44);
define_generic_irq_handler!(do_irq_13, 45);
define_generic_irq_handler!(do_irq_14, 46);
define_generic_irq_handler!(do_irq_15, 47);

/// Handler IRQ timer (vecteur 32, APIC timer)
#[no_mangle]
extern "C" fn do_irq_timer(frame: *mut ExceptionFrame) {
    // SAFETY: identique à do_divide_error — pointeur valide passé par le stub ASM.
    let frame = unsafe { &mut *frame };
    super::idt::irq_counter_inc(32);
    TIMER_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);

    // 1. EOI APIC — acquitté en premier pour minimiser la latence APIC.
    // SAFETY: LAPIC initialisé avant que les IRQ timer soient activées.
    super::apic::eoi();

    if super::apic::local_apic::lapic_timer_owner()
        == super::apic::local_apic::LapicTimerOwner::ExoNmiWatchdog
    {
        crate::security::exonmi::tick();
        return;
    }

    super::apic::local_apic::rearm_scheduler_timer_tick();

    // 2. Tick scheduler : avance les quantum CPU et décide des préemptions.
    let cpu_id = current_cpu_id_checked();
    let tcb_ptr = current_tcb_raw_checked();
    // SAFETY: scheduler_tick est thread-safe ; cli implicite dans handler IRQ.
    unsafe {
        scheduler_tick(cpu_id, tcb_ptr as *mut u8);
    }

    // 3. Si retour vers Ring 3 : vérifier préemption + signaux.
    if frame.from_userspace() {
        exception_return_to_user(frame);
    }
}

/// Handler IRQ spurious (vecteur 0xFF)
#[no_mangle]
extern "C" fn do_irq_spurious(_frame: *mut ExceptionFrame) {
    // IRQ spurious : ne PAS envoyer EOI (c'est une fausse interruption)
    SPURIOUS_IRQ_COUNT.fetch_add(1, Ordering::Relaxed);
}

// ── IPI Handlers ──────────────────────────────────────────────────────────────

/// IPI wakeup thread
#[no_mangle]
extern "C" fn do_ipi_wakeup(_frame: *mut ExceptionFrame) {
    super::idt::irq_counter_inc(super::idt::VEC_IPI_WAKEUP);
    // Réutiliser sched_ipi_reschedule : positionne NEED_RESCHED sur le thread
    // courant (RÈGLE IPI-01) — le reschedule effectif a lieu à l'IRET.
    let tcb_ptr = current_tcb_raw_checked();
    // SAFETY: sched_ipi_reschedule est thread-safe pour le CPU courant.
    unsafe {
        sched_ipi_reschedule(tcb_ptr as *mut u8);
    }
    // EOI Local APIC — acquitter l'IPI avant le retour d'interruption.
    // SAFETY: LAPIC initialisé avant tout IPI SMP.
    super::apic::eoi();
}

/// IPI reschedule
#[no_mangle]
extern "C" fn do_ipi_reschedule(frame: *mut ExceptionFrame) {
    let _ = frame;
    super::idt::irq_counter_inc(super::idt::VEC_IPI_RESCHEDULE);

    let tcb_ptr = current_tcb_raw_checked();

    // Positionner NEED_RESCHED sur le thread courant (RÈGLE IPI-01 DOC3).
    // Le reschedule effectif aura lieu au retour d'interruption quand le code
    // kernel vérifiera le flag (ou à l'IRET vers Ring 3).
    // Si le scheduler n'est pas encore initialisé (tcb_ptr == 0), ignoré.
    // SAFETY: sched_ipi_reschedule() est thread-safe pour le CPU courant.
    unsafe {
        sched_ipi_reschedule(tcb_ptr as *mut u8);
    }

    // EOI Local APIC — acquitter l'IPI avant le retour d'interruption.
    // SAFETY: LAPIC initialisé avant tout IPI SMP.
    super::apic::eoi();
}

/// IPI TLB shootdown
///
/// ## Intégration memory/ (RÈGLE TLB-01 DOC2)
/// 1. Récupérer l'identifiant CPU courant depuis le GS per-CPU.
/// 2. Appeler `TLB_QUEUE.handle_remote(cpu_id)` qui :
///    - Lit la requête de flush depuis la queue TLB partagée.
///    - Exécute `invlpg` ou reload CR3 selon `TlbFlushType`.
///    - Détache le bit correspondant dans le champ `completed`.
/// 3. EOI Local APIC (acquitter l'interruption).
///
/// ## Règle de précédence
/// JAMAIS appeler free_pages() avant que TOUS les CPUs aient acquitté
/// (c'est `tlb::shootdown()` qui attend l'acquittement, pas ce handler).
#[no_mangle]
extern "C" fn do_ipi_tlb_shootdown(_frame: *mut ExceptionFrame) {
    super::idt::irq_counter_inc(super::idt::VEC_IPI_TLB_SHOOTDOWN);
    super::paging::inc_tlb_shootdown();

    // Identifiant logique du CPU courant (0-based).
    let cpu_id = super::smp::percpu::current_cpu_id() as u8;

    // Exécuter le flush TLB demandé par l'émetteur du shootdown.
    // SAFETY: appelé depuis handler IRQ (cli implicite); TLB_QUEUE thread-safe par spinlock.
    unsafe {
        crate::memory::virt::address_space::tlb::TLB_QUEUE.handle_remote(cpu_id);
    }

    // EOI Local APIC — signale la fin du traitement de l'interruption.
    // SAFETY: LAPIC initialisé avant tout IPI ; EOI est idempotent à ce stade.
    super::apic::eoi();
}

/// IPI hotplug CPU
#[no_mangle]
extern "C" fn do_ipi_cpu_hotplug(_frame: *mut ExceptionFrame) {
    super::idt::irq_counter_inc(super::idt::VEC_IPI_CPU_HOTPLUG);

    // EOI avant halt pour que le BSP ne reste pas bloqué en attente.
    // SAFETY: LAPIC initialisé avant tout IPI hotplug.
    super::apic::eoi();
    // Identifier ce CPU et le mettre hors ligne (→ ! — ce CPU ne revient pas).
    let cpu_id = super::smp::percpu::current_cpu_id();
    // SAFETY: hotplug_cpu_halt est idempotent et -> ! (arrêt irréversible).
    super::smp::hotplug::hotplug_cpu_halt(cpu_id);
}

/// IPI panic broadcast (0xFE)
///
/// Reçu par tous les APs lors d'un kernel panic.
/// Arrêt immédiat sans tentative de sauvegarde.
#[no_mangle]
extern "C" fn do_ipi_panic(_frame: *mut ExceptionFrame) {
    // SAFETY: réponse à un panic — arrêt irréversible requis
    super::halt_cpu();
}

#[no_mangle]
extern "C" fn do_exophoenix_freeze(_frame: *mut ExceptionFrame) {
    super::idt::irq_counter_inc(super::idt::VEC_EXOPHOENIX_FREEZE);
    // SAFETY: handler d'IPI ExoPhoenix FREEZE en contexte interruption Ring 0.
    unsafe { crate::exophoenix::interrupts::handle_freeze_ipi() };
}

#[no_mangle]
extern "C" fn do_exophoenix_pmc(_frame: *mut ExceptionFrame) {
    super::idt::irq_counter_inc(super::idt::VEC_EXOPHOENIX_PMC);
    // SAFETY: handler d'IPI ExoPhoenix PMC snapshot en contexte interruption Ring 0.
    unsafe { crate::exophoenix::interrupts::handle_pmc_snapshot_ipi() };
}

#[no_mangle]
extern "C" fn do_exophoenix_tlb(_frame: *mut ExceptionFrame) {
    super::idt::irq_counter_inc(super::idt::VEC_EXOPHOENIX_TLB);
    // SAFETY: handler d'IPI ExoPhoenix TLB flush en contexte interruption Ring 0.
    unsafe { crate::exophoenix::interrupts::handle_tlb_flush_ipi() };
}

// ── Kernel Panic ──────────────────────────────────────────────────────────────

/// Affiche les informations de l'exception et arrête le CPU
///
/// # RÈGLE NO-ALLOC
/// Cette fonction ne peut PAS allouer de mémoire.
/// Elle affiche uniquement les registres depuis la frame.
#[cold]
#[inline(never)]
fn kernel_panic_exception(msg: &str, frame: &mut ExceptionFrame) {
    if crate::exophoenix::resurrection::try_recover_exception(msg, frame) {
        return;
    }

    // Dans une implémentation complète : écrire sur un port série ou VGA buffer.
    // Pour l'instant : consommer les paramètres pour éviter les warnings.
    let _ = msg;
    let _ = frame;

    // Broadcaster l'IPI panic vers tous les APs pour les arrêter.
    // SAFETY: situation non-récupérable ; broadcast_ipi_panic() n'alloue pas.
    super::apic::ipi::broadcast_ipi_panic();

    // SAFETY: situation non-récupérable — HLT en boucle.
    super::halt_cpu()
}

// ── Instrumentations ──────────────────────────────────────────────────────────

/// Compteurs per-vecteur (vecteurs 0–31 seulement ici)
static EXC_COUNTERS: [AtomicU64; 32] = {
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; 32]
};

static NMI_COUNT: AtomicU64 = AtomicU64::new(0);
static MC_COUNT: AtomicU64 = AtomicU64::new(0);
static GP_FAULT_COUNT: AtomicU64 = AtomicU64::new(0);
static TIMER_IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
static SPURIOUS_IRQ_COUNT: AtomicU64 = AtomicU64::new(0);
static FPU_DEVICE_NOT_AVAIL_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(debug_assertions)]
#[cfg(all(debug_assertions, exo_kernel_trace))]
static USER_PF_DEBUG_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn exc_count(vector: u8) -> u64 {
    if (vector as usize) < 32 {
        EXC_COUNTERS[vector as usize].load(Ordering::Relaxed)
    } else {
        0
    }
}
pub fn nmi_count() -> u64 {
    NMI_COUNT.load(Ordering::Relaxed)
}
pub fn machine_check_count() -> u64 {
    MC_COUNT.load(Ordering::Relaxed)
}
pub fn gp_fault_count() -> u64 {
    GP_FAULT_COUNT.load(Ordering::Relaxed)
}
pub fn timer_irq_count() -> u64 {
    TIMER_IRQ_COUNT.load(Ordering::Relaxed)
}
pub fn spurious_irq_count() -> u64 {
    SPURIOUS_IRQ_COUNT.load(Ordering::Relaxed)
}
pub fn fpu_device_not_avail_count() -> u64 {
    FPU_DEVICE_NOT_AVAIL_COUNT.load(Ordering::Relaxed)
}
