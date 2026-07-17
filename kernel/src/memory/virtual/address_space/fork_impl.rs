// kernel/src/memory/virtual/address_space/fork_impl.rs
//
// Implémentation de AddressSpaceCloner pour l'espace utilisateur.
// CORRECTION P0-01 : débloque fork() en clonant l'espace d'adressage en CoW.
//
// Cette implémentation :
//   1. Alloue un nouveau PML4 pour le processus fils
//   2. Copie les entrées kernel (PML4[256:512]) depuis le parent
//   3. Copie les pages userspace et les marque CoW
//   4. Fournit les primitives de libération pour les chemins d'erreur

use crate::memory::core::{AllocError, AllocFlags, Frame, PhysAddr};
use crate::memory::cow::tracker::COW_TRACKER;
use crate::memory::physical::allocator::buddy;
use crate::memory::virt::address_space::tlb::flush_all;
use crate::memory::virt::page_table::builder::PageTableBuilder;
use crate::memory::virt::page_table::walker::FrameAllocatorForWalk;
use crate::memory::virt::page_table::x86_64::{
    phys_to_table_mut, phys_to_table_ref, PageTableEntry,
};
use crate::memory::virt::UserAddressSpace;
use alloc::alloc::{alloc, Layout};
use alloc::boxed::Box;

fn try_box_new<T>(value: T) -> Option<Box<T>> {
    let layout = Layout::new::<T>();
    if layout.size() == 0 {
        return None;
    }

    // SAFETY: `layout` matches T. Null is converted to None, and a non-null
    // allocation is initialized exactly once before Box takes ownership.
    let raw = unsafe { alloc(layout) as *mut T };
    if raw.is_null() {
        return None;
    }
    // SAFETY: `raw` is a unique allocation large enough for T.
    unsafe {
        raw.write(value);
        Some(Box::from_raw(raw))
    }
}

#[inline]
fn track_cow_frame(frame: Frame) -> Result<(), AddrSpaceCloneError> {
    COW_TRACKER
        .try_inc(frame)
        .map(|_| ())
        .map_err(|_| AddrSpaceCloneError::OutOfMemory)
}

struct ForkWalkAllocator;

impl FrameAllocatorForWalk for ForkWalkAllocator {
    fn alloc_frame(&self, flags: AllocFlags) -> Result<Frame, AllocError> {
        buddy::alloc_pages(0, flags)
    }

    fn free_frame(&self, frame: Frame) {
        let _ = buddy::free_pages(frame, 0);
    }
}

/// Résultat de la duplication CoW de l'espace d'adressage.
pub struct ClonedAddressSpace {
    /// CR3 du nouvel espace d'adressage (fils).
    pub cr3: u64,
    /// Pointeur opaque vers le UserAddressSpace fils.
    pub addr_space_ptr: usize,
}

/// Erreur de clonage de l'espace d'adressage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrSpaceCloneError {
    OutOfMemory,
    InvalidSource,
}

/// Trait injecté dans process/ pour dupliquer un espace d'adressage en CoW.
pub trait AddressSpaceCloner: Send + Sync {
    /// Clone l'espace d'adressage référencé par `src_cr3`.
    fn clone_cow(
        &self,
        src_cr3: u64,
        src_space_ptr: usize,
    ) -> Result<ClonedAddressSpace, AddrSpaceCloneError>;

    /// Flush le TLB d'un espace d'adressage après marquage CoW.
    fn flush_tlb_after_fork(&self, cr3: u64);

    /// Libère un espace d'adressage cloné (appelé sur erreur post-clone).
    fn free_addr_space(&self, addr_space_ptr: usize);
}

pub struct KernelAddressSpaceCloner;

unsafe impl Send for KernelAddressSpaceCloner {}
unsafe impl Sync for KernelAddressSpaceCloner {}

impl AddressSpaceCloner for KernelAddressSpaceCloner {
    fn clone_cow(
        &self,
        src_cr3: u64,
        src_space_ptr: usize,
    ) -> Result<ClonedAddressSpace, AddrSpaceCloneError> {
        if src_cr3 == 0 {
            return Err(AddrSpaceCloneError::InvalidSource);
        }
        let child_pml4_frame = buddy::alloc_pages(0, crate::memory::AllocFlags::ZEROED)
            .map_err(|_| AddrSpaceCloneError::OutOfMemory)?;
        let child_cr3 = child_pml4_frame.start_address().as_u64();
        let child_pml4_phys = PhysAddr::new(child_cr3);

        unsafe {
            let src_pml4 = phys_to_table_ref(PhysAddr::new(src_cr3));
            let dst_pml4 = phys_to_table_mut(child_pml4_phys);
            for i in 256..512 {
                dst_pml4[i] = src_pml4[i];
            }
            if clone_userspace_tables(PhysAddr::new(src_cr3), child_pml4_phys).is_err() {
                free_userspace_tables(child_pml4_phys);
                return Err(AddrSpaceCloneError::OutOfMemory);
            }
            let fork_alloc = ForkWalkAllocator;
            if PageTableBuilder::from_existing(PhysAddr::new(src_cr3), &fork_alloc)
                .remap_low_kernel_identity()
                .is_err()
            {
                free_userspace_tables(child_pml4_phys);
                return Err(AddrSpaceCloneError::OutOfMemory);
            }
            if PageTableBuilder::from_existing(child_pml4_phys, &fork_alloc)
                .remap_low_kernel_identity()
                .is_err()
            {
                free_userspace_tables(child_pml4_phys);
                return Err(AddrSpaceCloneError::OutOfMemory);
            }
        }

        let parent_as = if src_space_ptr != 0 {
            Some(unsafe { &*(src_space_ptr as *const UserAddressSpace) })
        } else {
            None
        };
        if let Some(parent_as) = parent_as {
            parent_as.mark_all_writable_vmas_cow();
        }

        let inherited_heap_start = parent_as
            .map(|parent_as| {
                parent_as
                    .heap_start
                    .load(core::sync::atomic::Ordering::Acquire)
            })
            .unwrap_or(0);
        let inherited_heap_end = parent_as
            .map(|parent_as| {
                parent_as
                    .heap_end
                    .load(core::sync::atomic::Ordering::Acquire)
            })
            .unwrap_or(0);

        let child_as = match try_box_new(UserAddressSpace::new(child_pml4_phys, 0)) {
            Some(addr_space) => addr_space,
            None => {
                unsafe {
                    free_userspace_tables(child_pml4_phys);
                }
                return Err(AddrSpaceCloneError::OutOfMemory);
            }
        };
        if let Some(parent_as) = parent_as {
            if !parent_as.clone_inner_for_fork(&child_as) {
                unsafe {
                    free_userspace_tables(child_pml4_phys);
                }
                return Err(AddrSpaceCloneError::OutOfMemory);
            }
        }
        if inherited_heap_start != 0 || inherited_heap_end != 0 {
            child_as
                .heap_start
                .store(inherited_heap_start, core::sync::atomic::Ordering::Release);
            child_as
                .heap_end
                .store(inherited_heap_end, core::sync::atomic::Ordering::Release);
        }

        Ok(ClonedAddressSpace {
            cr3: child_cr3,
            addr_space_ptr: Box::into_raw(child_as) as usize,
        })
    }

    fn flush_tlb_after_fork(&self, _parent_cr3: u64) {
        unsafe {
            flush_all();
        }
    }

    fn free_addr_space(&self, addr_space_ptr: usize) {
        if addr_space_ptr == 0 {
            return;
        }
        let addr_space = unsafe { Box::from_raw(addr_space_ptr as *mut UserAddressSpace) };
        unsafe {
            free_userspace_tables(addr_space.pml4_phys());
        }
    }
}

/// Instance statique du clonage d'espace d'adressage.
pub static KERNEL_AS_CLONER: KernelAddressSpaceCloner = KernelAddressSpaceCloner;

unsafe fn clone_userspace_tables(
    src_pml4_phys: PhysAddr,
    dst_pml4_phys: PhysAddr,
) -> Result<(), AddrSpaceCloneError> {
    let src_pml4 = phys_to_table_ref(src_pml4_phys);
    let dst_pml4 = phys_to_table_mut(dst_pml4_phys);

    for l4_idx in 0..256 {
        let src_entry = src_pml4[l4_idx];
        if !src_entry.is_present() {
            continue;
        }
        if !src_entry.is_user() {
            dst_pml4[l4_idx] = src_entry;
            continue;
        }

        let dst_pdpt_phys = alloc_zeroed_table()?;
        if let Err(err) = clone_pdpt(src_entry.phys_addr(), dst_pdpt_phys) {
            free_pdpt_tree(dst_pdpt_phys);
            return Err(err);
        }
        dst_pml4[l4_idx] = repoint_table_entry(src_entry, dst_pdpt_phys);
    }

    Ok(())
}

unsafe fn clone_pdpt(
    src_pdpt_phys: PhysAddr,
    dst_pdpt_phys: PhysAddr,
) -> Result<(), AddrSpaceCloneError> {
    let src_pdpt = phys_to_table_mut(src_pdpt_phys);
    let dst_pdpt = phys_to_table_mut(dst_pdpt_phys);

    for l3_idx in 0..512 {
        let src_entry = src_pdpt[l3_idx];
        if !src_entry.is_present() {
            continue;
        }
        if !src_entry.is_user() {
            dst_pdpt[l3_idx] = src_entry;
            continue;
        }
        if src_entry.is_huge() {
            if let Some(frame) = src_entry.frame() {
                track_cow_frame(frame)?;
            }
            let shared = shared_leaf_entry(src_entry);
            src_pdpt[l3_idx] = shared;
            dst_pdpt[l3_idx] = shared;
            continue;
        }

        let dst_pd_phys = alloc_zeroed_table()?;
        if let Err(err) = clone_pd(src_entry.phys_addr(), dst_pd_phys) {
            free_pd_tree(dst_pd_phys);
            return Err(err);
        }
        dst_pdpt[l3_idx] = repoint_table_entry(src_entry, dst_pd_phys);
    }

    Ok(())
}

unsafe fn clone_pd(
    src_pd_phys: PhysAddr,
    dst_pd_phys: PhysAddr,
) -> Result<(), AddrSpaceCloneError> {
    let src_pd = phys_to_table_mut(src_pd_phys);
    let dst_pd = phys_to_table_mut(dst_pd_phys);

    for l2_idx in 0..512 {
        let src_entry = src_pd[l2_idx];
        if !src_entry.is_present() {
            continue;
        }
        if !src_entry.is_user() {
            dst_pd[l2_idx] = src_entry;
            continue;
        }
        if src_entry.is_huge() {
            if let Some(frame) = src_entry.frame() {
                track_cow_frame(frame)?;
            }
            let shared = shared_leaf_entry(src_entry);
            src_pd[l2_idx] = shared;
            dst_pd[l2_idx] = shared;
            continue;
        }

        let dst_pt_phys = alloc_zeroed_table()?;
        if let Err(err) = clone_pt(src_entry.phys_addr(), dst_pt_phys) {
            free_pt_tree(dst_pt_phys);
            return Err(err);
        }
        dst_pd[l2_idx] = repoint_table_entry(src_entry, dst_pt_phys);
    }

    Ok(())
}

unsafe fn clone_pt(
    src_pt_phys: PhysAddr,
    dst_pt_phys: PhysAddr,
) -> Result<(), AddrSpaceCloneError> {
    let src_pt = phys_to_table_mut(src_pt_phys);
    let dst_pt = phys_to_table_mut(dst_pt_phys);

    for l1_idx in 0..512 {
        let src_entry = src_pt[l1_idx];
        if src_entry.is_present() {
            if !src_entry.is_user() {
                dst_pt[l1_idx] = src_entry;
                continue;
            }
            if let Some(frame) = src_entry.frame() {
                #[cfg(target_arch = "x86_64")]
                crate::memory::physical::allocator::buddy::diag25_trace(
                    b"<25CLPT ",
                    frame.phys_addr().as_u64(),
                    1,
                );
                track_cow_frame(frame)?;
            }
            let shared = shared_leaf_entry(src_entry);
            src_pt[l1_idx] = shared;
            dst_pt[l1_idx] = shared;
        }
    }
    Ok(())
}

#[inline]
fn shared_leaf_entry(src_entry: PageTableEntry) -> PageTableEntry {
    // FIX #25 (Audit 3.3) — Poser FLAG_COW sur TOUTE entrée leaf présente+user
    // (y compris les pages RO comme le code ELF), au lieu de ne le faire que
    // pour les pages writable ou déjà-CoW.
    //
    // Sans FLAG_COW, la condition `will_free = (remaining == u32::MAX && !cow)`
    // pourrait devenir VRAIE pour un frame RO partagé si un déséquilibre de
    // refcount le rend untracked — le teardown libérerait alors une frame
    // encore utilisée par init. Avec FLAG_COW systématique, `!cow` est
    // toujours false pour un frame partagé → le teardown fuit (leak) plutôt
    // que de corrompre init. Le leak est non-fatal et détectable.
    if src_entry.is_present() && src_entry.is_user() {
        PageTableEntry::from_raw(
            (src_entry.raw() & !PageTableEntry::FLAG_WRITABLE) | PageTableEntry::FLAG_COW,
        )
    } else {
        src_entry
    }
}

fn alloc_zeroed_table() -> Result<PhysAddr, AddrSpaceCloneError> {
    buddy::alloc_pages(0, crate::memory::AllocFlags::ZEROED)
        .map(|frame| frame.start_address())
        .map_err(|_| AddrSpaceCloneError::OutOfMemory)
}

fn repoint_table_entry(src_entry: PageTableEntry, new_phys: PhysAddr) -> PageTableEntry {
    const ENTRY_FLAG_MASK: u64 = !0x000F_FFFF_FFFF_F000u64;
    PageTableEntry::from_raw(new_phys.as_u64() | (src_entry.raw() & ENTRY_FLAG_MASK))
}

unsafe fn free_userspace_tables(root_pml4_phys: PhysAddr) {
    #[cfg(target_arch = "x86_64")]
    crate::memory::physical::allocator::buddy::diag25_tag_hex(
        b"<25TD pml4=",
        root_pml4_phys.as_u64(),
    );
    let pml4 = phys_to_table_ref(root_pml4_phys);
    for l4_idx in 0..256 {
        let entry = pml4[l4_idx];
        if entry.is_present() && entry.is_user() && !entry.is_huge() {
            free_pdpt_tree(entry.phys_addr());
        }
    }
    let _ = buddy::free_pages(Frame::containing(root_pml4_phys), 0);
}

unsafe fn free_pdpt_tree(pdpt_phys: PhysAddr) {
    let pdpt = phys_to_table_ref(pdpt_phys);
    for l3_idx in 0..512 {
        let entry = pdpt[l3_idx];
        if !entry.is_present() {
            continue;
        }
        if !entry.is_user() {
            continue;
        }
        if entry.is_huge() {
            release_huge_frame(entry, 18);
        } else {
            free_pd_tree(entry.phys_addr());
        }
    }
    let _ = buddy::free_pages(Frame::containing(pdpt_phys), 0);
}

unsafe fn free_pd_tree(pd_phys: PhysAddr) {
    let pd = phys_to_table_ref(pd_phys);
    for l2_idx in 0..512 {
        let entry = pd[l2_idx];
        if !entry.is_present() {
            continue;
        }
        if !entry.is_user() {
            continue;
        }
        if entry.is_huge() {
            release_huge_frame(entry, 9);
        } else {
            free_pt_tree(entry.phys_addr());
        }
    }
    let _ = buddy::free_pages(Frame::containing(pd_phys), 0);
}

unsafe fn free_pt_tree(pt_phys: PhysAddr) {
    let pt = phys_to_table_ref(pt_phys);
    for l1_idx in 0..512 {
        let entry = pt[l1_idx];
        if !entry.is_present() {
            continue;
        }
        if !entry.is_user() {
            continue;
        }
        release_leaf_frame(entry);
    }
    let _ = buddy::free_pages(Frame::containing(pt_phys), 0);
}

fn release_leaf_frame(entry: PageTableEntry) {
    let Some(frame) = entry.frame() else {
        return;
    };
    let remaining = COW_TRACKER.dec(frame);
    let will_free = remaining == u32::MAX && !entry.is_cow();
    // #25 : ne jamais libérer un frame encore marqué CoW. Si le comptage tombe à 0
    // alors que l'entrée est toujours CoW, on préfère fuiter plutôt que réallouer
    // un frame potentiellement encore visible par le parent.
    #[cfg(target_arch = "x86_64")]
    if will_free && entry.is_cow() {
        crate::memory::physical::allocator::buddy::diag25_hex_always(
            b"<25TDCF f=",
            frame.phys_addr().as_u64(),
        );
        crate::memory::physical::allocator::buddy::diag25_hex_always(b" rem=", remaining as u64);
    }
    // FIX #25 (Audit 3.5) — Guard DIAG25_INITF avant buddy::free_pages.
    // Defense-in-depth runtime : si, malgré les fixes 2.1/2.2/3.3, un
    // déséquilibre de refcount rendait un frame init « éligible » au free,
    // ce guard l'empêche physiquement. On émet `<25GUARD-LEAK>` et on fuit
    // volontairement le frame (non-fatal, détectable dans les stats buddy).
    #[cfg(target_arch = "x86_64")]
    if will_free {
        use core::sync::atomic::Ordering;
        let fp = frame.phys_addr().as_u64();
        let mut j = 0usize;
        while j < 24 {
            let initf = crate::memory::physical::allocator::buddy::DIAG25_INITF[j]
                .load(Ordering::Relaxed);
            if initf != 0 && initf == fp {
                use crate::arch::x86_64::terminal::debug_write;
                use crate::memory::physical::allocator::buddy::{diag25_dec, diag25_hex};
                debug_write(b"<25GUARD-LEAK f=");
                diag25_hex(fp);
                debug_write(b" rem=");
                diag25_dec(remaining as u64);
                debug_write(b">\n");
                return; // NE PAS libérer — fuite volontaire
            }
            j += 1;
        }
    }
    if will_free {
        let _ = buddy::free_pages(frame, 0);
    }
}

fn release_huge_frame(entry: PageTableEntry, order: usize) {
    let Some(frame) = entry.frame() else {
        return;
    };
    let remaining = COW_TRACKER.dec(frame);
    if remaining == u32::MAX && !entry.is_cow() {
        // FIX #25 (Audit 3.5) — Même guard DIAG25_INITF pour les huge frames.
        #[cfg(target_arch = "x86_64")]
        {
            use core::sync::atomic::Ordering;
            let fp = frame.phys_addr().as_u64();
            let span = (4096usize << order) as u64;
            let mut j = 0usize;
            while j < 24 {
                let initf = crate::memory::physical::allocator::buddy::DIAG25_INITF[j]
                    .load(Ordering::Relaxed);
                if initf != 0 && initf >= fp && initf < fp + span {
                    use crate::arch::x86_64::terminal::debug_write;
                    use crate::memory::physical::allocator::buddy::{diag25_dec, diag25_hex};
                    debug_write(b"<25GUARD-LEAK-HUGE f=");
                    diag25_hex(fp);
                    debug_write(b" ord=");
                    diag25_dec(order as u64);
                    debug_write(b" rem=");
                    diag25_dec(remaining as u64);
                    debug_write(b">\n");
                    return; // NE PAS libérer — fuite volontaire
                }
                j += 1;
            }
        }
        let _ = buddy::free_pages(frame, order);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_entry_turns_writable_page_into_cow() {
        let frame = Frame::containing(PhysAddr::new(0x20_000));
        let entry = PageTableEntry::new(
            frame,
            PageTableEntry::FLAG_PRESENT
                | PageTableEntry::FLAG_WRITABLE
                | PageTableEntry::FLAG_USER,
        );

        let shared = shared_leaf_entry(entry);

        assert!(shared.is_present());
        assert!(shared.is_user());
        assert!(shared.is_cow());
        assert!(!shared.is_writable());
        assert_eq!(shared.phys_addr().as_u64(), entry.phys_addr().as_u64());
    }

    #[test]
    fn shared_entry_preserves_read_only_mapping_with_cow_flag() {
        // FIX #25 (Audit 3.3) — Les pages RO partagées portent désormais
        // FLAG_COW systématiquement (défense en profondeur contre la
        // libération de frames partagés par le teardown).
        let frame = Frame::containing(PhysAddr::new(0x24_000));
        let entry = PageTableEntry::new(
            frame,
            PageTableEntry::FLAG_PRESENT | PageTableEntry::FLAG_USER,
        );

        let shared = shared_leaf_entry(entry);

        assert!(shared.is_present());
        assert!(shared.is_user());
        assert!(shared.is_cow()); // ← maintenant FLAG_COW posé
        assert!(!shared.is_writable());
        assert_eq!(shared.phys_addr().as_u64(), entry.phys_addr().as_u64());
    }

    #[test]
    fn shared_entry_preserves_existing_cow_mapping() {
        let frame = Frame::containing(PhysAddr::new(0x28_000));
        let entry = PageTableEntry::new(
            frame,
            PageTableEntry::FLAG_PRESENT | PageTableEntry::FLAG_USER | PageTableEntry::FLAG_COW,
        );

        let shared = shared_leaf_entry(entry);

        assert!(shared.is_present());
        assert!(shared.is_user());
        assert!(shared.is_cow());
        assert!(!shared.is_writable());
        assert_eq!(shared.phys_addr().as_u64(), entry.phys_addr().as_u64());
    }
}
