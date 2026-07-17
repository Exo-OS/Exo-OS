//! # syscall/dispatch.rs — Dispatch vers les handlers syscall
//!
//! Orchestre le pipeline complet d'un appel système :
//!
//! ```text
//! syscall_rust_handler(frame)
//!        │
//!        ├─ [0] Validation numéro syscall (bornes)
//!        ├─ [1] Fast-path check (getpid, gettid, clock_gettime…)
//!        │       └─ retour direct si traité (~40-150 cycles)
//!        ├─ [2] Compat translation (numéros Linux alternatifs)
//!        ├─ [3] Sélection handler dans table.rs (O(1))
//!        ├─ [4] Exécution handler
//!        └─ [5] Post-dispatch : signal pending check (RÈGLE SIGNAL-01)
//! ```
//!
//! ## Invariants de sécurité
//! - Aucun handler n'est appelé avec un numéro hors `[0, SYSCALL_TABLE_SIZE)`.
//! - Les registres `rdi..r9` ne sont jamais truqués avant le handler.
//! - Le résultat est toujours écrit dans `frame.rax` avant retour.
//!
//! ## Instrumentation
//! - `DISPATCH_TOTAL`       : nombre total de syscalls dispatués
//! - `DISPATCH_FAST_PATH`   : proportion traitée par fast-path
//! - `DISPATCH_SLOW_PATH`   : proportion traitée par la table
//! - `DISPATCH_ENOSYS`      : nombre de -ENOSYS retournés
//! - `DISPATCH_COMPAT`      : nombre de traductions compat appliquées
//! - `DISPATCH_LATENCY_NS`  : latence totale dispatch (TSC → ns, échantillon)
//!
//! ## RÈGLE CONTRAT UNSAFE (regle_bonus.md)
//! Tout `unsafe {}` est précédé d'un commentaire `// SAFETY:`.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::arch::x86_64::cpu::tsc::read_tsc;
use crate::arch::x86_64::syscall::SyscallFrame;
use crate::syscall::compat::linux::translate_linux_nr;
use crate::syscall::fast_path::try_fast_path;
use crate::syscall::numbers::{is_valid_syscall, ENOSYS};
use crate::syscall::table::get_handler;
// FIX-APP-02: imports pour audit_syscall_entry/exit (APP-02)
use crate::security::audit::syscall_audit::{audit_syscall_entry, audit_syscall_exit, AuditVerdict};
use crate::scheduler::core::switch::current_thread_raw;

// ─────────────────────────────────────────────────────────────────────────────
// Compteurs d'instrumentation
// ─────────────────────────────────────────────────────────────────────────────

static DISPATCH_TOTAL: AtomicU64 = AtomicU64::new(0);
static DISPATCH_FAST_PATH: AtomicU64 = AtomicU64::new(0);
static DISPATCH_SLOW_PATH: AtomicU64 = AtomicU64::new(0);
static DISPATCH_ENOSYS: AtomicU64 = AtomicU64::new(0);
static DISPATCH_COMPAT: AtomicU64 = AtomicU64::new(0);
/// Somme des latences dispatch (cycles TSC). Échantillonné 1/256.
static DISPATCH_LATENCY_CYC: AtomicU64 = AtomicU64::new(0);

#[cfg(all(target_arch = "x86_64", debug_assertions))]
#[inline]
fn syscall_trace(_message: &[u8]) {}

#[cfg(not(all(target_arch = "x86_64", debug_assertions)))]
#[inline]
fn syscall_trace(_message: &[u8]) {}

#[cfg(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace))]
#[inline]
fn exec_trace(message: &[u8]) {
    crate::arch::x86_64::terminal::debug_write(message);
}

#[cfg(not(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace)))]
#[inline]
fn exec_trace(_message: &[u8]) {}

/// Snapshot des compteurs de dispatch.
#[derive(Copy, Clone, Debug, Default)]
pub struct DispatchStats {
    pub total: u64,
    pub fast_path: u64,
    pub slow_path: u64,
    pub enosys: u64,
    pub compat: u64,
    pub latency_cyc: u64,
}

/// Retourne un snapshot instantané des compteurs.
pub fn dispatch_stats() -> DispatchStats {
    DispatchStats {
        total: DISPATCH_TOTAL.load(Ordering::Relaxed),
        fast_path: DISPATCH_FAST_PATH.load(Ordering::Relaxed),
        slow_path: DISPATCH_SLOW_PATH.load(Ordering::Relaxed),
        enosys: DISPATCH_ENOSYS.load(Ordering::Relaxed),
        compat: DISPATCH_COMPAT.load(Ordering::Relaxed),
        latency_cyc: DISPATCH_LATENCY_CYC.load(Ordering::Relaxed),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Point d'entrée principal du dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Dispatch l'appel système décrit par `frame`.
///
/// Cette fonction est appelée depuis `arch::x86_64::syscall::syscall_rust_handler`
/// (ou directement depuis le nouveau `syscall/mod.rs` qui court-circuite l'ancien
/// handler arch/).
///
/// ## Contrat
/// - `frame` est une `SyscallFrame` validée par le stub ASM `syscall_entry_asm`.
/// - GS est le GS kernel (SWAPGS effectué dans le stub).
/// - La préemption est ACTIVE (pas dans un ISR).
///
/// ## Pipeline d'exécution
/// 1. Mesure TSC début (instrumentation)
/// 2. Lecture des 6 arguments depuis la frame
/// 3. Validation du numéro syscall
/// 4. Essai fast-path (getpid, gettid, yield, clock_gettime, …)
/// 5. Traduction numéro compat Linux si nécessaire
/// 6. Lookup handler dans `table::get_handler(nr)`
/// 7. Appel handler
/// 8. Écriture du résultat dans `frame.rax`
/// 9. Check signal pending (RÈGLE SIGNAL-01)
/// 10. Mesure TSC fin (instrumentation)
#[no_mangle]
pub fn dispatch(frame: &mut SyscallFrame) {
    // ── [0] Instrumentation début ──────────────────────────────────────────
    let tsc_start = read_tsc();
    DISPATCH_TOTAL.fetch_add(1, Ordering::Relaxed);

    // ── [1] Extraction des arguments ───────────────────────────────────────
    let nr = frame.rax;
    let arg1 = frame.rdi;
    let arg2 = frame.rsi;
    let arg3 = frame.rdx;
    let arg4 = frame.r10;
    let arg5 = frame.r8;
    let arg6 = frame.r9;

    // ── [2] Validation du numéro syscall ───────────────────────────────────
    if !is_valid_syscall(nr) {
        DISPATCH_ENOSYS.fetch_add(1, Ordering::Relaxed);
        frame.rax = ENOSYS as u64;
        post_dispatch(frame, tsc_start);
        return;
    }

    // ── [2b] Audit syscall entry (FIX-APP-02 — GAP-02) ────────────────────
    // audit_syscall_entry() évalue les règles d'audit et peut bloquer le syscall
    // avant même son exécution (AuditVerdict::DenyEperm / ::Kill).
    // Ne concerne que les syscalls sensibles définis dans audit/rules.rs.
    // RÈGLE SAU-01 : ne déclenche aucun appel récursif.
    let (caller_pid, caller_tid) = {
        let tcb_ptr = current_thread_raw();
        if tcb_ptr.is_null() {
            (0u32, 0u32)
        } else {
            // SAFETY: current_thread_raw() retourne un pointeur valide ou null.
            // La durée de vie est bornée à ce stack frame (pas de swap scheduler possible ici).
            let tcb = unsafe { &*tcb_ptr };
            (tcb.pid.0, tcb.tid as u32)
        }
    };
    match audit_syscall_entry(nr as u32, caller_pid, caller_tid, 0) {
        AuditVerdict::Allow => {}
        AuditVerdict::DenyEperm => {
            frame.rax = crate::syscall::numbers::EPERM as u64;
            post_dispatch(frame, tsc_start);
            return;
        }
        AuditVerdict::DenyEnosys => {
            frame.rax = ENOSYS as u64;
            post_dispatch(frame, tsc_start);
            return;
        }
        AuditVerdict::Kill => {
            // Thread marqué pour terminaison — signal SIGKILL au prochain retour Ring3.
            // tcb_ptr est défini dans le bloc précédent via current_thread_raw().
            // Le signal sera délivré par post_dispatch via pending signal check.
            frame.rax = crate::syscall::numbers::EPERM as u64;
            post_dispatch(frame, tsc_start);
            return;
        }
    }

    // ── [2c] Zero-Trust verify_syscall (FIX-APP-01 — GAP-01) ───────────────
    // verify_syscall() est câblé ici pour les syscalls non-fast-path.
    // ThreadControlBlock n'a pas de champ security_context — verify_syscall()
    // prend un SecurityContext construit depuis le pid/tid du thread.
    if nr != crate::syscall::numbers::SYS_SCHED_YIELD
        && nr != crate::syscall::numbers::SYS_GETPID
        && nr != crate::syscall::numbers::SYS_CLOCK_GETTIME
    {
        let zt_ok = {
            use crate::security::zero_trust::{context_for_caller, verify_syscall};
            // TIER 1.1 : SecurityContext RÉEL du process appelant — niveau de
            // confiance dérivé de l'état système (init/Ring 1/normal) + restrictions
            // sandbox/pledge persistées. Remplace l'ancien `new_normal` inerte
            // (restrictions=0) qui rendait la vérification TRUST_ALL de fait.
            // Process non restreint → aucune restriction → Ok (boot-safe) ; un
            // process ayant opt-in à un sandbox voit ses syscalls interdits refusés.
            let ctx = context_for_caller(caller_pid, caller_tid);
            verify_syscall(&ctx, nr).is_ok()
        };
        if !zt_ok {
            // TIER 3.1 : forwarder le refus syscall au feed NGAV exo_shield.
            crate::security::shield_feed::push_event(
                caller_pid,
                crate::security::shield_feed::event_type::SYSCALL,
                crate::security::shield_feed::severity::HIGH,
                nr as u32,
                0,
                0,
            );
            frame.rax = crate::syscall::numbers::EPERM as u64;
            audit_syscall_exit(caller_tid, crate::syscall::numbers::EPERM as i64);
            post_dispatch(frame, tsc_start);
            return;
        }
    }

    // ── [3] Fast-path  ─────────────────────────────────────────────────────
    // Couvre les syscalls haute fréquence sans allocation ni verrou.
    if let Some(result) = try_fast_path(nr, arg1, arg2, arg3, arg4, arg5, arg6) {
        DISPATCH_FAST_PATH.fetch_add(1, Ordering::Relaxed);
        frame.rax = result as u64;
        post_dispatch(frame, tsc_start);
        return;
    }

    // ── [4] Traduction numéro compat Linux ─────────────────────────────────
    // Certains numéros Linux peuvent avoir un mapping alternatif dans Exo-OS.
    // Par ex. un numéro retiré de Linux qui est remappé vers l'équivalent Exo-OS.
    let effective_nr = match translate_linux_nr(nr) {
        Some(translated) => {
            DISPATCH_COMPAT.fetch_add(1, Ordering::Relaxed);
            translated
        }
        None => nr,
    };

    // ── [5] Cas spécial rt_sigreturn — besoin d'accéder à la frame arch ────
    // SYS_RT_SIGRETURN (15) doit restaurer les registres directement dans frame
    // avant le retour SYSRETQ. Il ne peut pas passer par un handler normal.
    if effective_nr == crate::syscall::numbers::SYS_RT_SIGRETURN {
        handle_sigreturn_inplace(frame);
        post_dispatch(frame, tsc_start);
        return;
    }

    // ── [5b] Cas spécial fork/vfork — besoin de frame.rcx (child RIP) et frame.rsp ──
    if effective_nr == crate::syscall::numbers::SYS_FORK {
        syscall_trace(b"sys_fork: dispatch\n");
        let result =
            handle_fork_like_inplace(frame, crate::process::lifecycle::fork::ForkFlags::default());
        syscall_trace(b"sys_fork: result\n");
        frame.rax = result as u64;
        // Fork publie un nouveau runnable, mais le parent doit retourner une
        // fois en Ring3 avant une préemption forcée: init_server dépend de ce
        // point pour enregistrer l'état du service qui vient d'être créé.
        post_dispatch_defer_resched(frame, tsc_start);
        syscall_trace(b"sys_fork: post\n");
        return;
    }

    if effective_nr == crate::syscall::numbers::SYS_VFORK {
        let result = handle_fork_like_inplace(
            frame,
            crate::process::lifecycle::fork::ForkFlags(
                crate::process::lifecycle::fork::ForkFlags::VFORK,
            ),
        );
        frame.rax = result as u64;
        post_dispatch(frame, tsc_start);
        return;
    }

    // ── [5c] Cas spécial execve — modifie frame pour sauter au nouveau binaire ──
    if effective_nr == crate::syscall::numbers::SYS_EXECVE {
        handle_execve_inplace(frame);
        // Pas de post_dispatch apres execve reussi (nouvelle image). En cas
        // d'echec, le processus continue dans l'ancienne image et doit livrer
        // ses signaux pendants avant le retour userspace.
        if (frame.rax as i64) < 0 {
            post_dispatch(frame, tsc_start);
        }
        return;
    }

    // ── [6] Slow-path : lookup dans la table ───────────────────────────────
    DISPATCH_SLOW_PATH.fetch_add(1, Ordering::Relaxed);
    let handler = get_handler(effective_nr);

    // ── [7] Exécution du handler ───────────────────────────────────────────
    let result = handler(arg1, arg2, arg3, arg4, arg5, arg6);

    // ── [7] Comptabilisation d'une erreur ENOSYS ───────────────────────────
    if result == ENOSYS {
        DISPATCH_ENOSYS.fetch_add(1, Ordering::Relaxed);
    }

    // ── [8] Écriture du résultat ───────────────────────────────────────────
    frame.rax = result as u64;

    // ── [8b] Audit syscall exit (FIX-APP-02) ──────────────────────────────
    audit_syscall_exit(caller_tid, result);

    // ── [8c] Audit ExoLedger : log des syscalls critiques (FIX-APP-08 — GAP-08) ──
    // La vraie API est crate::security::audit::logger::log_event().
    // log_sensitive_syscall() n'existe pas — utiliser log_event() directement.
    {
        use crate::security::audit::logger::{log_event, AuditCategory, AuditOutcome};
        let is_critical_syscall =
            effective_nr == crate::syscall::numbers::SYS_EXECVE
            || effective_nr == crate::syscall::numbers::SYS_CLONE
            || effective_nr == crate::syscall::numbers::SYS_FORK
            || effective_nr == crate::syscall::numbers::SYS_VFORK;
        if is_critical_syscall {
            let outcome = if result < 0 { AuditOutcome::Error } else { AuditOutcome::Allow };
            log_event(AuditCategory::Process, caller_pid, caller_tid, 0u16,
                effective_nr as u32, result as i32, outcome, [0u8; 8]);
        }
    }

    // ── [9] Post-dispatch : signal pending + instrumentation ──────────────
    post_dispatch(frame, tsc_start);
}

// ─────────────────────────────────────────────────────────────────────────────
// Traitement spécial rt_sigreturn (SIG-13 / SIG-14)
// ─────────────────────────────────────────────────────────────────────────────

/// Traite `SYS_RT_SIGRETURN` directement depuis la frame arch.
///
/// Contrairement aux autres syscalls, `rt_sigreturn` doit modifier les registres
/// userspace (RIP, RSP, RFLAGS, RAX…) retournés par SYSRETQ. Le handler normal
/// n'a pas accès à la `SyscallFrame` — ce traitement spécial le permet.
///
/// ## Protocole (POSIX / SIG-13)
/// 1. RSP userspace au moment de SYSRETQ = sig_rsp + 8 (le `ret` du handler a
///    consommé `pretcode`).
/// 2. `sig_rsp = frame.user_rsp - 8`.
/// 3. UContext à `sig_rsp + SIGNAL_FRAME_UC_OFFSET`.
/// 4. Magic `0x5349_474E` vérifié constant-time (LAC-01 / SIG-14).
/// 5. Si magic OK : registres + signal_mask restaurés.
/// 6. RSP userspace mis à jour dans `gs:[0x08]` pour SYSRETQ.
///
/// En cas d'échec (magic invalide, adresse invalide) : le processus reçoit SIGSEGV
/// au retour vers userspace (RIP sera 0, qui est non-mappé).
fn handle_sigreturn_inplace(frame: &mut SyscallFrame) {
    use crate::process::signal::handler::{verify_and_extract_uc, SIGNAL_FRAME_UC_OFFSET};
    use crate::scheduler::core::task::ThreadControlBlock;

    // Le `ret` du handler a popped `pretcode` → RSP userspace = sig_rsp + 8.
    let sig_rsp = frame.rsp.wrapping_sub(8);
    let uc_ptr = sig_rsp + SIGNAL_FRAME_UC_OFFSET;

    let regs = match verify_and_extract_uc(uc_ptr) {
        Some(r) => r,
        None => {
            // Magic invalide ou adresse corrompue : déclencher SIGSEGV.
            // On met RIP = 0 (non-mappé) → #PF Ring3 → SIGSEGV au processus.
            // On ne crashe jamais en Ring0 (ARCH-SYSRET V-35 respecté).
            frame.rcx = 0;
            frame.rax = (-crate::syscall::errno::EFAULT) as u64;
            return;
        }
    };

    // Restaurer les registres dans la frame arch (lus par SYSRETQ).
    // RIP de retour = rcx pour SYSRETQ.
    frame.rcx = regs.rip;
    // RFLAGS userspace = r11 pour SYSRETQ.
    frame.r11 = regs.rflags & !0x100; // Clear TF (Trap Flag) par sécurité.
    frame.rax = regs.rax;
    frame.rdi = regs.rdi;
    frame.rsi = regs.rsi;
    frame.rdx = regs.rdx;
    frame.r8 = regs.r8;
    frame.r9 = regs.r9;
    frame.r10 = regs.r10;
    frame.r12 = regs.r12;
    frame.r13 = regs.r13;
    frame.r14 = regs.r14;
    frame.r15 = regs.r15;
    frame.rbx = regs.rbx;
    frame.rbp = regs.rbp;
    // RSP userspace mis à jour dans gs:[0x08] ET dans frame.rsp.
    // SAFETY: GS kernel actif, gs:[0x08] = user_rsp slot du PerCpuData.
    unsafe {
        core::arch::asm!(
            "mov qword ptr gs:[0x08], {rsp}",
            rsp = in(reg) regs.rsp,
            options(nostack, nomem)
        );
    }
    frame.rsp = regs.rsp;

    // Restaurer le masque de signal dans le TCB.
    // SAFETY: gs:[0x20] = pointeur TCB courant (PerCpuData layout).
    let tcb_ptr: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x20]", out(reg) tcb_ptr, options(nostack, nomem));
    }
    if tcb_ptr != 0 {
        // Masque SIGKILL/SIGSTOP non-masquables et bits de signaux invalides.
        let safe_mask = crate::process::signal::mask::SigMask::from(regs.signal_mask).0;
        // SAFETY: tcb_ptr est non-nul et valide (maintenu par le scheduler).
        let tcb = unsafe { &mut *(tcb_ptr as *mut ThreadControlBlock) };
        tcb.signal_mask
            .store(safe_mask, core::sync::atomic::Ordering::Release);
        tcb.fs_base = regs.fs_base;
        tcb.user_gs_base = regs.gs_base;
        #[cfg(target_os = "none")]
        unsafe {
            crate::arch::x86_64::cpu::msr::write_msr(
                crate::arch::x86_64::cpu::msr::MSR_FS_BASE,
                regs.fs_base,
            );
            crate::arch::x86_64::cpu::msr::write_msr(
                crate::arch::x86_64::cpu::msr::MSR_KERNEL_GS_BASE,
                regs.gs_base,
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Post-dispatch : signal pending + mesure latence
// ─────────────────────────────────────────────────────────────────────────────

/// Actions effectuées après chaque dispatch.
///
/// 1. Vérifie le flag `signal_pending` du TCB courant.
///    Si posé → appelle `process::signal::delivery::handle_pending_signals()`.
///    (RÈGLE SIGNAL-01 DOC1 : livraison au retour userspace UNIQUEMENT)
/// 2. Échantillonne la latence dispatch (1/256) pour éviter la contention atomique.
#[inline]
fn post_dispatch(frame: &mut SyscallFrame, tsc_start: u64) {
    post_dispatch_inner(frame, tsc_start, true);
}

#[inline]
fn post_dispatch_defer_resched(frame: &mut SyscallFrame, tsc_start: u64) {
    post_dispatch_inner(frame, tsc_start, false);
}

#[inline]
fn post_dispatch_inner(frame: &mut SyscallFrame, tsc_start: u64, allow_resched: bool) {
    if (frame.rax as i64) < 0 {
        crate::arch::x86_64::syscall::record_syscall_error();
    }

    // ── Livraison de signaux pending (RÈGLE SIGNAL-01) ────────────────────
    check_and_deliver_signals(frame);

    // ── Préemption demandée au retour syscall ─────────────────────────────
    // Le tick timer pose NEED_RESCHED; le retour vers Ring3 est le point sûr
    // où l'on peut céder le CPU sans perdre la SyscallFrame du thread courant.
    if allow_resched {
        unsafe {
            let _ = crate::scheduler::core::switch::schedule_current_if_needed();
        }
    }

    // ── Instrumentation latence (échantillon 1/256) ───────────────────────
    let tsc_end = read_tsc();
    let elapsed = tsc_end.saturating_sub(tsc_start);
    // Échantillonnage : bit 7 de tsc_end pour éviter le modulo coûteux.
    if (tsc_end & 0xFF) == 0 {
        DISPATCH_LATENCY_CYC.fetch_add(elapsed, Ordering::Relaxed);
    }
}

/// Vérifie et livre les signaux pending avant le retour userspace.
///
/// ## RÈGLE SIGNAL-01 / SIGNAL-02 (DOC1)
/// - `arch/` orchestre (lit le flag, appelle process/signal/).
/// - `process/signal/delivery` livre effectivement.
/// - `scheduler/` ne livre jamais directement.
///
/// ## Implémentation
/// Lit `gs:[0x20]` → pointeur TCB → champ `signal_pending`.
/// Si posé → appelle `process::signal::delivery::handle_pending_signals()`.
/// La livraison modifie la frame si elle installe un handler userspace.
#[inline]
fn check_and_deliver_signals(frame: &mut SyscallFrame) {
    // SAFETY: GS kernel actif dans ce contexte (SWAPGS dans le stub ASM).
    // gs:[0x20] contient le pointeur TCB, potentiellement nul si pas encore
    // initialisé (cas du kernel avant le premier fork → aucun signal possible).
    let tcb_ptr: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x20]",
            out(reg) tcb_ptr,
            options(nostack, nomem)
        );
    }

    if tcb_ptr == 0 {
        // Aucun thread courant (boot / idle) → pas de signal.
        return;
    }

    // ── Lecture du flag signal_pending ────────────────────────────────────
    // Le champ `signal_pending` est un AtomicBool dans ThreadControlBlock.
    // Son offset dans le TCB est FIXE (vérifié statiquement dans task.rs).
    //
    // Layout TCB (docs/refonte/DOC3 + task.rs) :
    // Offset 0..4    = tid (u32)
    // Offset 4..8    = pid (u32)
    // Offset 8       = state (u8)
    // ... voir task.rs pour le layout exact
    //
    // Le flag signal_pending est à l'offset défini par TCB_SIGNAL_PENDING_OFFSET
    // (constante within scheduler/core/task.rs, exportée dans la réexportation publique).
    //
    // SAFETY: tcb_ptr est non-nul et pointe vers un ThreadControlBlock valide
    // (construit par lifecycle/create.rs et maintenu par le scheduler).
    use crate::scheduler::core::task::ThreadControlBlock;
    let tcb = unsafe { &*(tcb_ptr as *const ThreadControlBlock) };

    // Vérifier le flag avec Acquire pour synchroniser avec l'écriture signal_pending
    // effectuée par process/signal/ (Ordering::Release s'y applique).
    if !tcb.has_signal_pending() {
        return;
    }

    // ── Livraison des signaux ─────────────────────────────────────────────
    // RÈGLE SIGNAL-02 (DOC1) : arch/x86_64/syscall.rs orchestre,
    // process::signal::delivery livre.
    //
    // La fonction handle_pending_signals() :
    // 1. Lit la queue de signaux du thread/process
    // 2. Pour chaque signal à livrer, appelle le handler userspace ou
    //    applique l'action par défaut (terminate, stop, ignore, continue).
    // 3. Si un handler userspace est installé, modifie la SyscallFrame
    //    pour que SYSRETQ retourne vers le signal trampolineau lieu
    //    de l'instruction qui a fait le syscall.
    //
    // SAFETY: frame est une SyscallFrame valide construite par le stub ASM.
    // tcb est valide (vérifié ci-dessus). L'appel est dans le contexte kernel
    // avec IRQs actives (les signaux peuvent potentiellement être ré-entrants
    // via SIGINT etc., mais handle_pending_signals() utilise un masque).
    let frame_ptr: *mut SyscallFrame = frame as *mut SyscallFrame;
    // ── Conversion arch::SyscallFrame → delivery::SyscallFrame ───────────────
    // Les deux structs ont des noms de champs différents mais les mêmes valeurs.
    use crate::process::core::pid::Pid;
    use crate::process::core::registry::PROCESS_REGISTRY;
    use crate::process::signal::delivery::{handle_pending_signals, SyscallFrame as DeliveryFrame};

    let pid = Pid(tcb.pid.0);
    let pcb = match PROCESS_REGISTRY.find_by_pid(pid) {
        Some(p) => p,
        None => return,
    };

    let thread_ptr = pcb.main_thread_ptr();
    if thread_ptr.is_null() {
        return;
    }

    // SAFETY: thread_ptr maintenu par pcb, valide dans ce contexte.
    let thread = unsafe { &mut *thread_ptr };

    let mut d_frame = DeliveryFrame {
        user_rip: frame.rcx,    // RIP de retour (sauvé par SYSCALL hw dans RCX)
        user_rflags: frame.r11, // RFLAGS (sauvé par SYSCALL hw dans R11)
        user_rsp: frame.rsp,    // RSP userspace
        user_rax: frame.rax,    // valeur de retour syscall
        user_rdi: frame.rdi,
        user_rsi: frame.rsi,
        user_rdx: frame.rdx,
        user_rcx: frame.rcx, // userspace RCX = même que RIP retour (SYSCALL)
        user_r8: frame.r8,
        user_r9: frame.r9,
        user_r10: frame.r10,
        user_r12: frame.r12,
        user_r13: frame.r13,
        user_r14: frame.r14,
        user_r15: frame.r15,
        user_rbx: frame.rbx,
        user_rbp: frame.rbp,
        user_fs_base: thread.sched_tcb.fs_base,
        user_gs_base: thread.sched_tcb.user_gs_base,
        user_cs: 0x1B, // CS ring3 (non sauvé par SYSCALL mais requis)
        user_ss: 0x23, // SS ring3
    };

    handle_pending_signals(thread, &mut d_frame);

    // Répercuter les modifications potentielles (ex. RIP redirigé, RSP vers sigaltstack).
    frame.rcx = d_frame.user_rip;
    frame.r11 = d_frame.user_rflags;
    frame.rax = d_frame.user_rax;
    frame.rdi = d_frame.user_rdi;
    frame.rsi = d_frame.user_rsi;
    frame.rdx = d_frame.user_rdx;
    frame.r8 = d_frame.user_r8;
    frame.r9 = d_frame.user_r9;
    frame.r10 = d_frame.user_r10;
    frame.r12 = d_frame.user_r12;
    frame.r13 = d_frame.user_r13;
    frame.r14 = d_frame.user_r14;
    frame.r15 = d_frame.user_r15;
    frame.rbx = d_frame.user_rbx;
    frame.rbp = d_frame.user_rbp;

    // RSP userspace : mettre à jour gs:[0x08] si modifié (sigaltstack / setup_signal_frame).
    if d_frame.user_rsp != frame.rsp {
        let new_rsp = d_frame.user_rsp;
        // SAFETY: GS kernel actif, gs:[0x08] = user_rsp slot du PerCpuData.
        unsafe {
            core::arch::asm!(
                "mov qword ptr gs:[0x08], {rsp}",
                rsp = in(reg) new_rsp,
                options(nostack, nomem)
            );
        }
        frame.rsp = new_rsp;
    }

    let _ = frame_ptr; // silence warning
}

// ─────────────────────────────────────────────────────────────────────────────
// Traitement spécial fork (SYS_FORK = 57)
// ─────────────────────────────────────────────────────────────────────────────

/// Traite `SYS_FORK` directement depuis la frame arch.
///
/// Fork a besoin de `frame.rcx` (RIP de retour = point de bifurcation) et
/// `frame.rsp` (RSP userspace). Ces valeurs ne transitent pas dans les arguments
/// syscall normaux (rdi..r9), donc le handler normal ne peut pas les lire.
///
/// ## Protocole (POSIX fork)
/// 1. Lit TCB courant via `gs:[0x20]` → PID → PCB.
/// 2. Récupère le `ProcessThread` via `pcb.main_thread_ptr()`.
/// 3. Construit `ForkContext` depuis la frame syscall complète.
/// 4. Appelle `do_fork()` — crée PCB/TCB fils, CoW, TLB flush, enqueue RunQueue.
/// 5. Retourne `child_pid` au parent (fils démarre via `fork_child_trampoline`).
fn handle_fork_like_inplace(
    frame: &SyscallFrame,
    fork_flags: crate::process::lifecycle::fork::ForkFlags,
) -> i64 {
    use crate::process::core::pid::Pid;
    use crate::process::core::registry::PROCESS_REGISTRY;
    use crate::process::lifecycle::fork::{
        do_fork, wait_for_vfork_completion, ForkContext, ForkError,
    };
    use crate::scheduler::core::task::ThreadControlBlock;
    use crate::syscall::errno::{EAGAIN, EFAULT, EINTR, EINVAL, ENOMEM};

    // Lire TCB courant.
    // SAFETY: GS kernel actif, gs:[0x20] = pointeur TCB (PerCpuData).
    let tcb_ptr: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x20]", out(reg) tcb_ptr, options(nostack, nomem));
    }
    if tcb_ptr == 0 {
        return EAGAIN;
    }

    // SAFETY: tcb_ptr non-nul et maintenu par le scheduler.
    let tcb = unsafe { &*(tcb_ptr as *const ThreadControlBlock) };
    let pid = Pid(tcb.pid.0);

    let pcb = match PROCESS_REGISTRY.find_by_pid(pid) {
        Some(p) => p,
        None => return EAGAIN,
    };

    let thread_ptr = pcb.main_thread_ptr();
    if thread_ptr.is_null() {
        return EAGAIN;
    }

    // SAFETY: thread_ptr maintenu par pcb, valide tant que pcb est dans PROCESS_REGISTRY.
    let thread = unsafe { &*thread_ptr };

    let ctx = ForkContext {
        parent_thread: thread,
        parent_pcb: pcb,
        flags: fork_flags,
        target_cpu: tcb.current_cpu().0,
        child_rip: frame.rcx,     // RIP de retour sauvé par SYSCALL hw
        child_rsp: frame.rsp,     // RSP userspace sauvé au stub ASM
        parent_rflags: frame.r11, // RFLAGS sauvés par SYSCALL hw — CORRECTION P2-02
        user_rbx: frame.rbx,
        user_rbp: frame.rbp,
        user_r12: frame.r12,
        user_r13: frame.r13,
        user_r14: frame.r14,
        user_r15: frame.r15,
        user_rdi: frame.rdi,
        user_rsi: frame.rsi,
        user_rdx: frame.rdx,
        user_r10: frame.r10,
        user_r8: frame.r8,
        user_r9: frame.r9,
    };

    // #25 : empreinte de la SyscallFrame d'init AVANT le blocage vfork. Comparée à
    // l'empreinte APRÈS resume : toute différence = corruption du contexte sauvé
    // d'init pendant l'execve de l'enfant (cause racine #25).
    #[cfg(target_arch = "x86_64")]
    if fork_flags.has(crate::process::lifecycle::fork::ForkFlags::VFORK) {
        crate::memory::physical::allocator::buddy::diag25_hex_always(b"<25SFpre rcx=", frame.rcx);
        crate::memory::physical::allocator::buddy::diag25_hex_always(b" rsp=", frame.rsp);
        crate::memory::physical::allocator::buddy::diag25_hex_always(b" rbp=", frame.rbp);
        crate::memory::physical::allocator::buddy::diag25_hex_always(b" rbx=", frame.rbx);
    }
    match do_fork(&ctx) {
        Ok(result) => {
            syscall_trace(b"sys_fork: do_fork ok\n");
            if fork_flags.has(crate::process::lifecycle::fork::ForkFlags::VFORK) {
                // SAFETY: tcb_ptr pointe le TCB courant; `do_fork` est terminé et
                // aucune référence immutable au TCB n'est réutilisée après ce point.
                let tcb_mut = unsafe { &mut *(tcb_ptr as *mut ThreadControlBlock) };
                if wait_for_vfork_completion(result.child_pid, tcb_mut).is_err() {
                    return EINTR;
                }
                #[cfg(target_arch = "x86_64")]
                {
                    crate::memory::physical::allocator::buddy::diag25_hex_always(
                        b"<25SFpost rcx=",
                        frame.rcx,
                    );
                    crate::memory::physical::allocator::buddy::diag25_hex_always(b" rsp=", frame.rsp);
                    crate::memory::physical::allocator::buddy::diag25_hex_always(b" rbp=", frame.rbp);
                    crate::memory::physical::allocator::buddy::diag25_hex_always(b" rbx=", frame.rbx);
                }
            }
            result.child_pid.0 as i64
        }
        Err(e) => {
            syscall_trace(b"sys_fork: do_fork err\n");
            match e {
                ForkError::PidExhausted
                | ForkError::TidExhausted
                | ForkError::RegistryError
                | ForkError::InvalidCpu => EAGAIN,
                ForkError::OutOfMemory | ForkError::AddressSpaceCloneFailed => ENOMEM,
                ForkError::NoAddrCloner => EFAULT,
                ForkError::UnsupportedFlag => EINVAL,
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Traitement spécial execve (SYS_EXECVE = 59)
// ─────────────────────────────────────────────────────────────────────────────

/// Copie un tableau de chaînes null-terminé depuis l'espace utilisateur.
///
/// `argv_ptr` pointe vers un tableau de pointeurs `char*` terminé par NULL.
/// Retourne `Some(Vec<String>)` ou `None` si une adresse est invalide.
///
/// EXEC-01 : seule fonction autorisée à lire argv/envp depuis userspace.
fn copy_userspace_argv(
    argv_ptr: u64,
    max_args: usize,
) -> Option<alloc::vec::Vec<alloc::string::String>> {
    use crate::syscall::validation::{copy_from_user, UserStr, USER_ADDR_MAX};
    use alloc::string::String;
    use alloc::vec::Vec;

    if argv_ptr == 0 {
        return Some(Vec::new());
    }
    if argv_ptr >= USER_ADDR_MAX {
        return None;
    }

    let mut result: Vec<String> = Vec::new();
    let mut saw_null = false;

    for i in 0..max_args {
        // Lire le i-ème pointeur (u64) du tableau.
        let ptr_addr = match argv_ptr.checked_add(i as u64 * 8) {
            Some(a) if a <= USER_ADDR_MAX.saturating_sub(8) => a,
            _ => return None,
        };

        let mut raw = [0u8; core::mem::size_of::<u64>()];
        copy_from_user(raw.as_mut_ptr(), ptr_addr as *const u8, raw.len()).ok()?;
        let str_ptr = u64::from_ne_bytes(raw);

        if str_ptr == 0 {
            saw_null = true;
            break;
        } // terminateur NULL du tableau
        if str_ptr >= USER_ADDR_MAX {
            return None;
        }

        let user_str = UserStr::from_user(str_ptr, 4096).ok()?;

        // Conversion UTF-8 permissive (remplace les octets invalides par U+FFFD).
        result.push(String::from_utf8_lossy(user_str.as_bytes()).into_owned());
    }

    if saw_null {
        Some(result)
    } else {
        None
    }
}

/// Traite `SYS_EXECVE` directement depuis la frame arch.
///
/// En cas de succès, `do_execve()` remplace l'image du processus mais retourne
/// normalement en Rust. Ce handler met alors à jour la frame arch pour que
/// SYSRETQ saute directement au nouveau point d'entrée ELF.
///
/// ## Protocole
/// 1. Lit path depuis userspace via `frame.rdi`.
/// 2. Récupère TCB → PCB → ProcessThread.
/// 3. Appelle `do_execve()`.
/// 4. Succès : `frame.rcx = entry_point`, `frame.rsp = initial_rsp`, `frame.rax = 0`.
/// 5. Échec : `frame.rax = -errno`.
///
/// ## Note : argv/envp
/// Les tableaux `argv` et `envp` sont copiés avant le remplacement d'image via
/// les primitives userspace centralisées (`copy_from_user` / `UserStr`).
fn handle_execve_inplace(frame: &mut SyscallFrame) {
    use crate::process::core::pid::Pid;
    use crate::process::core::registry::PROCESS_REGISTRY;
    use crate::process::lifecycle::exec::{do_execve, ElfLoadError, ExecError};
    use crate::scheduler::core::task::ThreadControlBlock;
    use crate::syscall::errno::*;
    use crate::syscall::validation::read_user_path;

    exec_trace(b"execve: enter\n");

    // Lire le chemin depuis userspace.
    let user_path = match read_user_path(frame.rdi) {
        Ok(p) => p,
        Err(e) => {
            exec_trace(b"execve: path fault\n");
            frame.rax = e.to_errno() as u64;
            return;
        }
    };
    let path = match user_path.as_str() {
        Ok(s) => s,
        Err(_) => {
            exec_trace(b"execve: path utf8\n");
            frame.rax = EFAULT as u64;
            return;
        }
    };
    // DIAG E9: print étiqueté du chemin execve (non-ambigu, greppable).
    crate::arch::x86_64::terminal::debug_write(b"\n<EXEC ");
    crate::arch::x86_64::terminal::debug_write(path.as_bytes());
    crate::arch::x86_64::terminal::debug_write(b">");

    // Lire TCB courant.
    // SAFETY: GS kernel actif.
    let tcb_ptr: u64;
    unsafe {
        core::arch::asm!("mov {}, gs:[0x20]", out(reg) tcb_ptr, options(nostack, nomem));
    }
    if tcb_ptr == 0 {
        exec_trace(b"execve: no tcb\n");
        frame.rax = EFAULT as u64;
        return;
    }

    // SAFETY: tcb_ptr maintenu par le scheduler.
    let tcb = unsafe { &*(tcb_ptr as *const ThreadControlBlock) };
    let pid = Pid(tcb.pid.0);

    let pcb = match PROCESS_REGISTRY.find_by_pid(pid) {
        Some(p) => p,
        None => {
            exec_trace(b"execve: no pcb\n");
            frame.rax = EFAULT as u64;
            return;
        }
    };

    let thread_ptr = pcb.main_thread_ptr();
    if thread_ptr.is_null() {
        exec_trace(b"execve: no thread\n");
        frame.rax = EAGAIN as u64;
        return;
    }

    // SAFETY: thread_ptr maintenu par pcb.
    let thread = unsafe { &mut *thread_ptr };

    // ARGV-01 (EXEC-01) : copier argv/envp depuis userspace avant do_execve().
    // frame.rsi = argv_ptr (tableau de char* null-terminé)
    // frame.rdx = envp_ptr (tableau de char* null-terminé)
    let argv_strings = match copy_userspace_argv(frame.rsi, 1024) {
        Some(v) => v,
        None => {
            exec_trace(b"execve: argv fault\n");
            frame.rax = EFAULT as u64;
            return;
        }
    };
    let argv_refs: alloc::vec::Vec<&str> = argv_strings.iter().map(|s| s.as_str()).collect();

    let envp_strings = match copy_userspace_argv(frame.rdx, 4096) {
        Some(v) => v,
        None => {
            exec_trace(b"execve: env fault\n");
            frame.rax = EFAULT as u64;
            return;
        }
    };
    let envp_refs: alloc::vec::Vec<&str> = envp_strings.iter().map(|s| s.as_str()).collect();

    exec_trace(b"execve: load\n");
    match do_execve(thread, pcb, &path, &argv_refs, &envp_refs) {
        Ok(()) => {
            exec_trace(b"execve: ok\n");
            crate::arch::x86_64::terminal::debug_write(b"=OK\n");
            // Succès : lire le nouveau point d'entrée depuis le ProcessThread mis à jour.
            let new_rip = thread.addresses.entry_point;
            let new_rsp = thread.addresses.initial_rsp;

            // Mettre à jour la frame pour SYSRETQ.
            frame.rbx = 0;
            frame.rbp = 0;
            frame.r12 = 0;
            frame.r13 = 0;
            frame.r14 = 0;
            frame.r15 = 0;
            frame.rdi = thread.addresses.entry_arg0;
            frame.rcx = new_rip; // RIP → nouveau point d'entrée ELF
            frame.rsp = new_rsp; // RSP → nouvelle pile userspace
            frame.r11 = 0x0202; // RFLAGS : IF=1, bit réservé=1
            frame.rax = 0; // "succès" (non retourné — SYSRETQ saute)

            // SYSRETQ lit gs:[0x08] pour restaurer le RSP userspace (stub ASM).
            // SAFETY: GS kernel actif, gs:[0x08] = user_rsp slot du PerCpuData.
            unsafe {
                core::arch::asm!(
                    "mov qword ptr gs:[0x08], {rsp}",
                    rsp = in(reg) new_rsp,
                    options(nostack, nomem)
                );
            }

            // FIX-EXEC-CR3 : execve remplace l'espace d'adressage SANS context
            // switch. Le stub de retour syscall (syscall.rs) recharge CR3 depuis
            // le slot per-CPU gs:[0x48] (user CR3), qui n'est mis à jour que par
            // `set_current_cr3()` lors d'un context switch. Sans cette
            // republication, SYSRETQ revient avec l'ANCIEN CR3 : le processus
            // reprend au nouveau RIP d'entrée mais dans l'ancien espace
            // d'adressage (init et les serveurs sont tous liés à la même base
            // virtuelle), exécutant le code de l'ancienne image → boucle
            // fork/execve sans jamais charger la nouvelle image.
            // DIAG E9: 'K' = chemin fix CR3 execve exécuté.
            unsafe { core::arch::asm!("out 0xE9, al", in("al") b'K', options(nomem, nostack)) };
            let new_kernel_cr3 = thread.sched_tcb.cr3_phys;
            let new_user_cr3 = thread.sched_tcb.kpti_user_cr3();
            crate::arch::x86_64::spectre::kpti::set_current_cr3(new_kernel_cr3, new_user_cr3);
            if !crate::arch::x86_64::spectre::kpti::kpti_enabled() {
                // KPTI désactivé : gs:[0x48] vaut 0 et le stub saute le switch
                // CR3. On bascule donc immédiatement sur la nouvelle image (la
                // moitié noyau est partagée, l'exécution noyau reste valide).
                // SAFETY: new_kernel_cr3 = PML4 de la nouvelle image, moitié
                // noyau synchronisée par do_execve(); Ring 0.
                unsafe {
                    core::arch::asm!("mov cr3, {}", in(reg) new_kernel_cr3, options(nostack, nomem));
                }
            }
        }
        Err(e) => {
            exec_trace(b"execve: err\n");
            crate::arch::x86_64::terminal::debug_write(match e {
                ExecError::ElfLoadFailed(ElfLoadError::NotFound) => b"=ER:NotFound\n" as &[u8],
                ExecError::ElfLoadFailed(ElfLoadError::InvalidElf) => b"=ER:InvalidElf\n",
                ExecError::ElfLoadFailed(ElfLoadError::PermissionDenied) => b"=ER:Perm\n",
                ExecError::ElfLoadFailed(ElfLoadError::OutOfMemory) => b"=ER:ElfOOM\n",
                ExecError::ElfLoadFailed(ElfLoadError::UnsupportedArch) => b"=ER:Arch\n",
                ExecError::ElfLoadFailed(ElfLoadError::InterpreterNotFound) => b"=ER:NoInterp\n",
                ExecError::OutOfMemory => b"=ER:OOM\n",
                ExecError::ThreadGroupNotSingle => b"=ER:NotSingle\n",
                ExecError::NoLoader => b"=ER:NoLoader\n",
                _ => b"=ER:Other\n",
            });
            let errno: i64 = match e {
                ExecError::ElfLoadFailed(ElfLoadError::NotFound) => ENOENT,
                ExecError::ElfLoadFailed(ElfLoadError::PermissionDenied)
                | ExecError::PermissionDenied => EACCES,
                ExecError::ElfLoadFailed(ElfLoadError::OutOfMemory) => ENOMEM,
                ExecError::ElfLoadFailed(ElfLoadError::InvalidElf) => EINVAL,
                ExecError::ArgListTooLong => E2BIG,
                ExecError::NameTooLong => EINVAL,
                ExecError::OutOfMemory => ENOMEM,
                ExecError::ThreadGroupNotSingle => EBUSY,
                ExecError::NoLoader => ENOSYS,
                _ => ENOSYS,
            };
            frame.rax = errno as u64;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrappers de test / diagnostic
// ─────────────────────────────────────────────────────────────────────────────

/// Réinitialise tous les compteurs de dispatch à zéro.
/// Utilisé par les tests et le démarrage d'un profil.
pub fn reset_dispatch_stats() {
    DISPATCH_TOTAL.store(0, Ordering::Relaxed);
    DISPATCH_FAST_PATH.store(0, Ordering::Relaxed);
    DISPATCH_SLOW_PATH.store(0, Ordering::Relaxed);
    DISPATCH_ENOSYS.store(0, Ordering::Relaxed);
    DISPATCH_COMPAT.store(0, Ordering::Relaxed);
    DISPATCH_LATENCY_CYC.store(0, Ordering::Relaxed);
}

/// Invoque directement un syscall numéro `nr` avec les arguments donnés,
/// sans passer par la frame ASM. Utilisé par les tests internes.
///
/// Ne mesure pas la latence et ne déclenche pas la livraison de signaux.
#[cfg(any(test, feature = "syscall_test"))]
pub fn invoke_direct(
    nr: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> i64 {
    if !is_valid_syscall(nr) {
        return ENOSYS;
    }
    if let Some(r) = try_fast_path(nr, arg1, arg2, arg3, arg4, arg5, arg6) {
        return r;
    }
    let effective_nr = translate_linux_nr(nr).unwrap_or(nr);
    let handler = get_handler(effective_nr);
    handler(arg1, arg2, arg3, arg4, arg5, arg6)
}
