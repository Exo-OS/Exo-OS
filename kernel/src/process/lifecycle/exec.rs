// kernel/src/process/lifecycle/exec.rs
//
// ═══════════════════════════════════════════════════════════════════════════════
// execve() — Remplacement de l'image processus (Exo-OS Couche 1.5)
// ═══════════════════════════════════════════════════════════════════════════════
//
// RÈGLE PROC-01 : process/ (couche 1.5) ne peut pas importer fs/ (couche 3).
// SOLUTION : trait ElfLoader enregistré par fs/ au boot.
//
// Séquence do_execve() :
//   1. Vérifier les permissions (creds).
//   2. Appeler ElfLoader::load_elf() pour charger le binaire.
//   3. Fermer les fds O_CLOEXEC.
//   4. Réinitialiser l'espace d'adressage virtuel.
//   5. Mettre à jour le TCB (entry_point, initial_rsp, TLS).
//   6. Mettre à jour le PCB (flags, compteurs).
//   7. Réinitialiser les signaux (handlers → SIG_DFL).
//   8. Retourner vers userspace.
// ═══════════════════════════════════════════════════════════════════════════════

use crate::memory::virt::UserAddressSpace;
use crate::memory::virt::VmaFlags;
use crate::memory::VirtAddr;
use crate::process::core::pcb::{process_flags, ProcessControlBlock, ProcessState};
use crate::process::core::tcb::{ProcessThread, ThreadAddress};
use crate::process::lifecycle::fork::notify_vfork_completion;
use crate::process::lifecycle::fork::AddressSpaceCloner;
use crate::process::signal::mask::block_all_except_kill;
use crate::process::signal::mask::reset_signals_on_exec;
use core::sync::atomic::Ordering;
use spin::Once;

#[cfg(target_os = "none")]
fn build_exec_kpti_shadow(kstack_top: u64, cr3: u64) -> Result<u64, ExecError> {
    if !crate::arch::x86_64::spectre::kpti::kpti_enabled() {
        return Ok(0);
    }

    let cpu_id = crate::arch::x86_64::smp::percpu::current_cpu_id() as usize;
    let trampoline_phys =
        crate::memory::core::PhysAddr::new(crate::arch::x86_64::smp::init::TRAMPOLINE_PHYS);
    let user_cr3 = unsafe {
        crate::memory::virt::page_table::kpti_split::build_user_shadow_pml4(
            crate::memory::core::PhysAddr::new(cr3),
            cpu_id,
            trampoline_phys,
            kstack_top,
        )
    }
    .map_err(|_| ExecError::OutOfMemory)?;

    Ok(user_cr3.as_u64())
}

#[cfg(not(target_os = "none"))]
fn build_exec_kpti_shadow(_kstack_top: u64, _cr3: u64) -> Result<u64, ExecError> {
    Ok(0)
}

// ─────────────────────────────────────────────────────────────────────────────
// Trait ElfLoader — RÈGLE PROC-01 : abstraction de la couche fs/
// ─────────────────────────────────────────────────────────────────────────────

/// Paramètres issus du chargement ELF.
#[derive(Debug, Clone)]
pub struct ElfLoadResult {
    /// Adresse d'entrée (entry point du binaire).
    pub entry_point: u64,
    /// Pointeur de pile initial (RSP au démarrage).
    pub initial_stack_top: u64,
    /// Premier argument userspace (RDI) injecté au point d'entrée.
    pub entry_arg0: u64,
    /// Base de la TLS statique chargée (segment .tdata/.tbss).
    pub tls_base: u64,
    /// Taille de la TLS statique.
    pub tls_size: usize,
    /// Adresse de début du heap brk (juste après le segment .bss).
    pub brk_start: u64,
    /// Adresse physique (CR3) du nouvel espace d'adressage créé.
    pub cr3: u64,
    /// Pointeur opaque vers le UserAddressSpace créé par fs/.
    pub addr_space_ptr: usize,
    /// Adresse virtuelle du SignalTcb mappé (0 si absent) — pour PROC-VMA/V-17.
    pub signal_tcb_vaddr: u64,
}

/// Erreurs renvoyées par ElfLoader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfLoadError {
    /// Fichier non trouvé.
    NotFound,
    /// Format ELF invalide ou corrompu.
    InvalidElf,
    /// Permission refusée.
    PermissionDenied,
    /// Pas assez de mémoire pour charger.
    OutOfMemory,
    /// Architecture non supportée.
    UnsupportedArch,
    /// Interprète (PT_INTERP) non trouvé.
    InterpreterNotFound,
}

/// Erreurs d'execve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecError {
    /// ELF non chargeable (wrapper).
    ElfLoadFailed(ElfLoadError),
    /// SCM / capability refusée.
    PermissionDenied,
    /// Signature de module invalide ou absente (FIX-EXEC-SIG).
    SignatureVerificationFailed,
    /// Trop d'arguments (E2BIG).
    ArgListTooLong,
    /// Nom de fichier trop long.
    NameTooLong,
    /// Processus déjà en train de quitter.
    ProcessExiting,
    /// Exec multi-thread refusé tant que THREAD-06 n'a pas tué les autres threads.
    ThreadGroupNotSingle,
    /// Allocation noyau échouée après le chargement ELF.
    OutOfMemory,
    /// Aucun ElfLoader enregistré.
    NoLoader,
}

/// Trait que `fs/` doit implémenter et enregistrer via `register_elf_loader()`.
///
/// La couche process/ ne connaît PAS les types fs/  — uniquement ce trait.
pub trait ElfLoader: Send + Sync {
    /// Charge un ELF depuis le chemin donné dans l'espace d'adressage courant.
    ///
    /// # Arguments
    /// * `path`   — chemin absolu dans le VFS.
    /// * `argv`   — vecteur d'arguments (argv[0] = binaire).
    /// * `envp`   — variables d'environnement.
    /// * `cr3_in` — CR3 de l'espace d'adressage existant à réinitialiser.
    ///
    /// # Returns
    /// `ElfLoadResult` décrivant l'espace d'adressage peuplé.
    fn load_elf(
        &self,
        path: &str,
        argv: &[&str],
        envp: &[&str],
        cr3_in: u64,
    ) -> Result<ElfLoadResult, ElfLoadError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Registre global du chargeur ELF
// ─────────────────────────────────────────────────────────────────────────────

static ELF_LOADER: Once<&'static dyn ElfLoader> = Once::new();
pub type CloseExecHandlesHook = fn(pid: u32, handles: &[u64]);
static CLOSE_EXEC_HANDLES_HOOK: Once<CloseExecHandlesHook> = Once::new();

/// Enregistre le chargeur ELF (appelé une seule fois depuis fs/ au boot).
///
/// # Safety
/// `loader` doit avoir une durée de vie `'static` (typiquement une référence
/// à un objet alloué statiquement dans fs/).
pub fn register_elf_loader(loader: &'static dyn ElfLoader) {
    ELF_LOADER.call_once(|| loader);
}

pub fn register_close_exec_handles_hook(hook: CloseExecHandlesHook) {
    let _ = CLOSE_EXEC_HANDLES_HOOK.call_once(|| hook);
}

#[inline]
fn close_exec_handles(pid: u32, handles: &[u64]) {
    if let Some(hook) = CLOSE_EXEC_HANDLES_HOOK.get() {
        hook(pid, handles);
    }
}

/// Charge un binaire ELF pour le bootstrap userspace, avant qu'un thread
/// appelant existe. Ce chemin est utilise uniquement pour fabriquer PID 1.
pub fn load_elf_for_boot(
    path: &str,
    argv: &[&str],
    envp: &[&str],
) -> Result<ElfLoadResult, ExecError> {
    if path.len() > 4096 {
        return Err(ExecError::NameTooLong);
    }
    let total_arg_len: usize = argv.iter().map(|s| s.len() + 1).sum::<usize>()
        + envp.iter().map(|s| s.len() + 1).sum::<usize>();
    if total_arg_len > 128 * 1024 {
        return Err(ExecError::ArgListTooLong);
    }

    let loader = ELF_LOADER.get().ok_or(ExecError::NoLoader)?;
    loader
        .load_elf(path, argv, envp, 0)
        .map_err(ExecError::ElfLoadFailed)
}

// ─────────────────────────────────────────────────────────────────────────────
// do_execve — implémentation principale
// ─────────────────────────────────────────────────────────────────────────────

/// Execute un nouveau binaire ELF dans le contexte du thread courant.
///
/// Cette fonction est appelée depuis le syscall execve() après validation
/// des paramètres utilisateur.
///
/// # Safety
/// `thread` doit pointer vers le ProcessThread du thread appelant.
/// L'espace d'adressage sera reconstruit — aucun accès userspace après l'appel.
pub fn do_execve(
    thread: &mut ProcessThread,
    pcb: &ProcessControlBlock,
    path: &str,
    argv: &[&str],
    envp: &[&str],
) -> Result<(), ExecError> {
    // Vérifier que le processus n'est pas en train de quitter.
    if pcb.is_exiting() {
        return Err(ExecError::ProcessExiting);
    }
    if pcb.thread_count.load(Ordering::Acquire) != 1 {
        return Err(ExecError::ThreadGroupNotSingle);
    }

    // Valider la longueur du chemin et des arguments.
    if path.len() > 4096 {
        return Err(ExecError::NameTooLong);
    }
    let total_arg_len: usize = argv.iter().map(|s| s.len() + 1).sum::<usize>()
        + envp.iter().map(|s| s.len() + 1).sum::<usize>();
    if total_arg_len > 128 * 1024 {
        return Err(ExecError::ArgListTooLong);
    }

    // Obtenir le chargeur ELF (enregistré depuis fs/ au boot).
    let loader = ELF_LOADER.get().ok_or(ExecError::NoLoader)?;
    let saved_signal_mask = thread.sched_tcb.signal_mask.load(Ordering::Acquire);
    let old_as_ptr = pcb.address_space.load(Ordering::Acquire);
    let old_process_flags = pcb.flags.load(Ordering::Acquire);
    let old_as_is_vfork_shared = old_process_flags & process_flags::VFORK_SHARED_AS != 0;

    // Étape 3 (LAC-08 / PROC-03) : bloquer TOUS les signaux sauf SIGKILL/SIGSTOP
    // AVANT le chargement ELF. Empêche un signal livré entre load_elf() et
    // reset_signals_on_exec() d'invoquer l'ancien handler dans un address space
    // partiellement remplacé. Le masque appelant est restauré après la purge
    // des signaux pending de l'ancienne image.
    block_all_except_kill(&thread.sched_tcb);

    // Charger le nouveau binaire dans l'espace d'adressage.
    let cr3_current = thread.sched_tcb.cr3_phys;
    let elf_result = match loader.load_elf(path, argv, envp, cr3_current) {
        Ok(result) => result,
        Err(err) => {
            thread
                .sched_tcb
                .signal_mask
                .store(saved_signal_mask, Ordering::Release);
            return Err(ExecError::ElfLoadFailed(err));
        }
    };
    // #25 : bissection — la pile d'init est-elle déjà corrompue après load_elf ?
    #[cfg(target_arch = "x86_64")]
    crate::memory::physical::allocator::buddy::diag25_check_init(b"postelf");

    // FIX-EXEC-SIG (Security_Audit_Passe2 §C-01) : vérification de la signature
    // du module avant remplacement de l'espace d'adressage.
    // ElfLoadResult ne fournit pas le ModuleHeader directement — la vérification
    // se fait via is_chain_verified() qui confirme que la chaîne de confiance
    // ExoSeal a bien validé ce binaire lors du chargement initial depuis ExoFS.
    //
    // En v0.2.0 dev (kernel_a_hash_is_zero()), la vérification est loguée mais
    // non bloquante. En production (EXOPHOENIX_REQUIRE_HASHES=1), elle est stricte.
    if crate::security::is_chain_verified() {
        // La chaîne de confiance est active — vérifier que le binaire est signé.
        // check_chain_of_trust() vérifie la signature Ed25519 du binaire via ExoSeal.
        if let Err(_e) = crate::security::check_chain_of_trust() {
            // Log mais ne pas bloquer en dev
            #[cfg(not(feature = "strict_exec_signatures"))]
            {
                // Mode dev : avertissement seulement
                crate::arch::x86_64::terminal::debug_write(
                    b"exec: WARNING unsigned binary executed\n",
                );
            }
            #[cfg(feature = "strict_exec_signatures")]
            {
                thread.sched_tcb.signal_mask.store(saved_signal_mask, Ordering::Release);
                return Err(ExecError::SignatureVerificationFailed);
            }
        }
    }
    #[cfg(target_os = "none")]
    unsafe {
        crate::memory::virt::address_space::KERNEL_AS
            .sync_kernel_half_into(crate::memory::core::PhysAddr::new(elf_result.cr3));
    }

    let exec_kpti_user_cr3 =
        match build_exec_kpti_shadow(thread.sched_tcb.kstack_top(), elf_result.cr3) {
            Ok(cr3) => cr3,
            Err(err) => {
                thread
                    .sched_tcb
                    .signal_mask
                    .store(saved_signal_mask, Ordering::Release);
                if elf_result.addr_space_ptr != 0 && elf_result.addr_space_ptr != old_as_ptr {
                    crate::memory::virt::address_space::fork_impl::KERNEL_AS_CLONER
                        .free_addr_space(elf_result.addr_space_ptr);
                }
                return Err(err);
            }
        };

    // PROC-VMA (V-17) : marquer la VMA SignalTcb DONTCOPY | DONTEXPAND.
    // Empêche un attaquant d'utiliser mmap(MAP_FIXED) pour écraser le SignalTcb.
    if elf_result.signal_tcb_vaddr != 0 {
        // SAFETY: addr_space_ptr créé par ElfLoader::load_elf() comme Box<UserAddressSpace>;
        // on est le seul détenteur de cet AS (l'ancien AS a été remplacé).
        let addr_space = unsafe { &*(elf_result.addr_space_ptr as *const UserAddressSpace) };
        addr_space.set_vma_flags(
            VirtAddr::new(elf_result.signal_tcb_vaddr),
            VmaFlags::DONTCOPY | VmaFlags::DONTEXPAND,
        );
    }

    // Fermer les fds O_CLOEXEC.
    let closed_handles = {
        let mut files = pcb.files.lock();
        files.close_on_exec()
    };
    let closed_handles = match closed_handles {
        Ok(handles) => handles,
        Err(()) => {
            thread
                .sched_tcb
                .signal_mask
                .store(saved_signal_mask, Ordering::Release);
            if elf_result.addr_space_ptr != 0 && elf_result.addr_space_ptr != old_as_ptr {
                crate::memory::virt::address_space::fork_impl::KERNEL_AS_CLONER
                    .free_addr_space(elf_result.addr_space_ptr);
            }
            return Err(ExecError::OutOfMemory);
        }
    };
    close_exec_handles(pcb.pid.0, &closed_handles);

    // Réinitialiser les signaux et purger les signaux de l'ancienne image.
    reset_signals_on_exec(&thread.sched_tcb);
    thread.sig_queue.clear();
    thread.rt_sig_queue.clear();
    thread
        .sched_tcb
        .signal_mask
        .store(saved_signal_mask, Ordering::Release);

    // Mettre à jour l'espace d'adressage dans le TCB scheduler.
    thread.sched_tcb.cr3_phys = elf_result.cr3;
    // FIX #25 (Audit 6.1) — Libérer l'ancienne shadow PML4 KPTI avant de
    // l'écraser. Sans cette libération, chaque `fork()`+`execve()` orpheline
    // une page physique de 4 KiB. Sur le boot (~10 services), c'est négligeable,
    // mais c'est une vraie fuite à corriger (et ça évite de mélanger les
    // symptômes lors d'investigations KPTI futures).
    {
        let old_kpti_cr3 = thread.sched_tcb.kpti_user_cr3();
        if old_kpti_cr3 != 0 && old_kpti_cr3 != exec_kpti_user_cr3 {
            // SAFETY: l'ancienne shadow PML4 a été allouée via
            // `build_user_shadow_pml4` (lui-même `buddy::alloc_page(ZEROED)`).
            // Elle n'est plus référencée nulle part après ce point.
            let _ = crate::memory::physical::allocator::buddy::free_pages(
                crate::memory::core::Frame::containing(
                    crate::memory::core::PhysAddr::new(old_kpti_cr3),
                ),
                0,
            );
        }
    }
    thread.sched_tcb.set_kpti_user_cr3(exec_kpti_user_cr3);
    thread.sched_tcb.fs_base = elf_result.tls_base;
    thread.sched_tcb.user_gs_base = 0;

    // Mettre à jour les adresses du thread.
    // CORRECTION P2-03 : calculer et propager stack_base et stack_size au lieu de 0
    const PAGE_SIZE_U64: u64 = crate::memory::core::PAGE_SIZE as u64;
    const DEFAULT_STACK_SIZE: u64 = crate::memory::core::layout::USER_STACK_BOOTSTRAP_SIZE as u64;

    let stack_top = elf_result.initial_stack_top;
    let stack_base = (stack_top.saturating_sub(DEFAULT_STACK_SIZE)) & !(PAGE_SIZE_U64 - 1);
    let stack_size = stack_top.saturating_sub(stack_base);

    thread.addresses = ThreadAddress {
        stack_base, // CORRECTION P2-03
        stack_size, // CORRECTION P2-03
        entry_point: elf_result.entry_point,
        initial_rsp: elf_result.initial_stack_top,
        tls_base: elf_result.tls_base,
        entry_arg0: elf_result.entry_arg0,
        pthread_ptr: 0,
        sigaltstack_base: 0,
        sigaltstack_size: 0,
    };
    thread
        .tls_gs_base
        .store(elf_result.tls_base, Ordering::Release);
    thread.tls_size = elf_result.tls_size;

    // P1-05 / PROC-01 : execve() ne remplace pas la pile kernel du thread courant,
    // mais on republie explicitement ce kstack dans les slots arch locaux pour
    // garder l'invariant TSS.RSP0 / GS:[0x00] visible et auto-documenté.
    #[cfg(target_os = "none")]
    unsafe {
        let cpu_id = crate::arch::x86_64::smp::percpu::current_cpu_id() as usize;
        let kstack_top = thread.sched_tcb.kstack_top();
        crate::memory::virt::address_space::KERNEL_AS
            .sync_kernel_half_into(crate::memory::core::PhysAddr::new(elf_result.cr3));
        crate::arch::x86_64::smp::percpu::set_kernel_rsp(kstack_top);
        crate::arch::x86_64::tss::update_rsp0(cpu_id, kstack_top);
        if crate::arch::x86_64::spectre::kpti::kpti_enabled() {
            crate::arch::x86_64::spectre::kpti::set_current_cr3(elf_result.cr3, exec_kpti_user_cr3);
        }
        crate::arch::x86_64::write_cr3(elf_result.cr3);
    }
    // #25 : bissection — corruption pendant load_elf+switch CR3 ?
    #[cfg(target_arch = "x86_64")]
    crate::memory::physical::allocator::buddy::diag25_check_init(b"postcr3");

    // BUG-04 / PROC-01 fix: écrire IA32_FS_BASE MSR immédiatement.
    // do_execve() s'exécute en contexte kernel sur le CPU courant du thread ;
    // le nouveau TLS base doit être actif avant la première instruction userspace.
    // Sans cet WRMSR, %fs pointe vers l'ancienne base → crash userspace dès le
    // premier accès TLS (thread_local!, pthread_self…).
    #[cfg(target_os = "none")]
    unsafe {
        // SAFETY: WRMSR sur MSR_FS_BASE = 0xC000_0100 est toujours défini sur
        // x86_64 (AMD64 v0), et le MSR est writable depuis Ring 0. Le contexte
        // est celui du thread courant sur ce CPU — effet local, aucune contention.
        crate::arch::x86_64::cpu::msr::write_msr(
            crate::arch::x86_64::cpu::msr::MSR_FS_BASE,
            elf_result.tls_base,
        );
        // execve() repart d'une image neuve : ne pas réinjecter l'ancien GS userspace.
        crate::arch::x86_64::cpu::msr::write_msr(
            crate::arch::x86_64::cpu::msr::MSR_KERNEL_GS_BASE,
            0,
        );
    }

    // Mettre à jour le PCB avec le nouvel espace d'adressage.
    pcb.cr3.store(elf_result.cr3, Ordering::Release);
    pcb.address_space
        .store(elf_result.addr_space_ptr, Ordering::Release);
    pcb.brk_start.store(elf_result.brk_start, Ordering::Release);
    pcb.brk_current
        .store(elf_result.brk_start, Ordering::Release);
    pcb.set_name_from_path(path.as_bytes());

    // Retirer FORKED/VFORK_SHARED_AS maintenant, mais ne publier EXEC_DONE/VFORK_DONE
    // qu'après le teardown de l'ancien address space : le parent vfork ne doit pas
    // pouvoir reprendre pendant `free_addr_space()`.
    pcb.flags.fetch_and(
        !(process_flags::FORKED | process_flags::VFORK_SHARED_AS),
        Ordering::Release,
    );

    if old_as_ptr != 0 && old_as_ptr != elf_result.addr_space_ptr && !old_as_is_vfork_shared {
        crate::memory::virt::address_space::fork_impl::KERNEL_AS_CLONER.free_addr_space(old_as_ptr);
    }
    // #25 : bissection — corruption pendant le teardown de l'ancien AS enfant ?
    #[cfg(target_arch = "x86_64")]
    crate::memory::physical::allocator::buddy::diag25_check_init(b"postTD");

    pcb.flags.fetch_or(
        process_flags::EXEC_DONE | process_flags::VFORK_DONE,
        Ordering::Release,
    );

    // Transition vers Running.
    pcb.set_state(ProcessState::Running);
    // ExoLedger : trace immuable de chaque chargement de binaire (changement d'identité).
    crate::security::exoledger::exo_ledger_append(crate::security::exoledger::ActionTag::Custom {
        tag: 0x6578_6563, // b"exec"
        data: pcb.pid.0 as u64,
    });
    notify_vfork_completion(pcb.pid);

    Ok(())
}
