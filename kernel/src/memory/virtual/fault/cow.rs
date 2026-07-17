// kernel/src/memory/virtual/fault/cow.rs
//
// CoW fault handler — gère un write sur une page marquée Copy-on-Write.
// Couche 0 — aucune dépendance externe sauf `spin`.

use super::handler::FaultAllocator;
use super::{FaultContext, FaultResult};
use crate::memory::core::{PageFlags, VirtAddr, PAGE_SIZE};
use crate::memory::cow::tracker::COW_TRACKER;
use crate::memory::virt::address_space::tlb::flush_single;
use crate::memory::virt::page_table::PageTableEntry;
use crate::memory::virt::vma::VmaDescriptor;

/// Traite un CoW fault (write sur page en lecture seule avec flag COW).
pub fn handle_cow_fault<A: FaultAllocator>(
    ctx: &FaultContext,
    vma: &VmaDescriptor,
    alloc: &A,
) -> FaultResult {
    let page_addr = VirtAddr::new(ctx.fault_addr.as_u64() & !(PAGE_SIZE as u64 - 1));

    let old_raw = alloc.read_pte_raw(page_addr);
    let old_entry = PageTableEntry::from_raw(old_raw);
    let old_frame = match old_entry.frame() {
        Some(frame) => frame,
        None => match alloc.translate(page_addr) {
            Some(phys) => crate::memory::core::Frame::containing(phys),
            None => {
                // Page pas encore mappée + flag COW → demand paging d'abord.
                return super::demand_paging::handle_demand_paging(ctx, vma, alloc);
            }
        },
    };

    let writable_flags = old_entry
        .to_page_flags()
        .clear(PageFlags::COW)
        .set(PageFlags::WRITABLE)
        .set(PageFlags::PRESENT);

    let tracked_ref_count = COW_TRACKER.tracked_ref_count(old_frame);
    let can_restore_in_place = tracked_ref_count.is_some_and(|rc| rc <= 1) || !old_entry.is_cow();

    if can_restore_in_place {
        let new_raw = PageTableEntry::from_page_flags(old_frame, writable_flags).raw();
        match alloc.compare_exchange_pte_raw(page_addr, old_raw, new_raw) {
            Ok(_) => {
                if tracked_ref_count.is_some() {
                    let _ = COW_TRACKER.dec(old_frame);
                }
                vma.record_cow_break();
                // SAFETY: adresse canonique.
                unsafe {
                    flush_single(page_addr);
                }
                return FaultResult::Handled;
            }
            Err(actual_raw) => {
                let actual = PageTableEntry::from_raw(actual_raw);
                if actual.is_present() && !actual.is_cow() {
                    // Un autre CPU a déjà restauré l'écriture en place.
                    unsafe {
                        flush_single(page_addr);
                    }
                    return FaultResult::Handled;
                }
            }
        }
    }

    // La page est encore partagée : copier vers un nouveau frame puis publier
    // le PTE par CAS pour sérialiser les fautes concurrentes.
    let new_frame = match alloc.alloc_nonzeroed() {
        Ok(f) => f,
        Err(_) => {
            return FaultResult::Oom {
                addr: ctx.fault_addr,
            }
        }
    };

    // Copier les données de l'ancien frame vers le nouveau.
    // SAFETY: Les deux frames sont mappés dans le physmap kernel.
    //
    // FIX #25 (Audit 5.3) — Diagnostic défensif : vérifier que new_frame n'est
    // PAS une frame de pile d'init vivante. Si new_frame (alloué via
    // alloc_nonzeroed) a été corrompu, ou si le buddy a retourné une frame
    // vivante d'init, cette copie écraserait le contenu de la page d'init. On
    // panic pour capturer le coupable.
    #[cfg(target_arch = "x86_64")]
    {
        use core::sync::atomic::Ordering;
        let dst_phys = new_frame.start_address().as_u64();
        let mut i = 0usize;
        while i < 24 {
            let initf = crate::memory::physical::allocator::buddy::DIAG25_INITF[i]
                .load(Ordering::Relaxed);
            if initf != 0 && initf == dst_phys {
                panic!(
                    "#25 CAUGHT handle_cow_fault: new_frame={:#x} == DIAG25_INITF[{}]",
                    dst_phys, i
                );
            }
            i += 1;
        }
    }
    unsafe {
        let src = (crate::memory::core::layout::PHYS_MAP_BASE.as_u64()
            + old_frame.start_address().as_u64()) as *const u8;
        let dst = (crate::memory::core::layout::PHYS_MAP_BASE.as_u64()
            + new_frame.start_address().as_u64()) as *mut u8;
        // SAFETY: src et dst sont des frames physiques distincts, taille PAGE_SIZE.
        core::ptr::copy_nonoverlapping(src, dst, PAGE_SIZE);
    }

    // Remap la page avec les nouveaux flags (writable, supprimer COW).
    let new_raw = PageTableEntry::from_page_flags(new_frame, writable_flags).raw();
    match alloc.compare_exchange_pte_raw(page_addr, old_raw, new_raw) {
        Ok(_) => {
            let remaining = COW_TRACKER.dec(old_frame);
            if remaining == 0 {
                alloc.free_frame(old_frame);
            }
            vma.record_cow_break();
            // SAFETY: adresse canonique.
            unsafe {
                flush_single(page_addr);
            }
            // DIAG #25 (Bochs watchpoint) : émet le frame physique (F') des pages
            // de pile USER cassées-CoW, pour poser un watchpoint physique Bochs sur
            // F'+0xae8 (slot return-address corrompu). Plage pile user uniquement.
            #[cfg(target_arch = "x86_64")]
            if page_addr.as_u64() >= 0x7fff_0000_0000 {
                use crate::arch::x86_64::terminal::debug_write;
                debug_write(b"<F25 p=");
                diag_f25_hex(page_addr.as_u64());
                debug_write(b" f=");
                diag_f25_hex(new_frame.start_address().as_u64());
                debug_write(b" cr3=");
                // SAFETY: lecture du registre CR3 — aucun accès mémoire (nomem correct,
                // contrairement à gs:[..]). Permet de distinguer la cassure CoW d'init
                // (cr3 = AS d'init) de celle de l'enfant pour cibler le watchpoint #25.
                let cr3v: u64;
                unsafe {
                    core::arch::asm!("mov {}, cr3", out(reg) cr3v, options(nomem, nostack));
                }
                diag_f25_hex(cr3v);
                debug_write(b">");
            }
            FaultResult::Handled
        }
        Err(actual_raw) => {
            alloc.free_frame(new_frame);
            let actual = PageTableEntry::from_raw(actual_raw);
            if actual.is_present() {
                // Un autre CPU a probablement gagné la course et a déjà cassé le CoW.
                unsafe {
                    flush_single(page_addr);
                }
                FaultResult::Handled
            } else {
                super::demand_paging::handle_demand_paging(ctx, vma, alloc)
            }
        }
    }
}

/// DIAG #25 : émission hex 16 digits sur le port debug E9 (Bochs/QEMU).
#[cfg(target_arch = "x86_64")]
fn diag_f25_hex(mut v: u64) {
    use crate::arch::x86_64::terminal::debug_write;
    let mut buf = [0u8; 16];
    let mut i = 16usize;
    while i > 0 {
        i -= 1;
        let nib = (v & 0xf) as u8;
        buf[i] = if nib < 10 { b'0' + nib } else { b'a' + nib - 10 };
        v >>= 4;
    }
    debug_write(&buf);
}
