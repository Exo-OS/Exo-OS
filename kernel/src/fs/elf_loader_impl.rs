// kernel/src/fs/elf_loader_impl.rs
//
// Implémentation de ElfLoader pour charger les binaires ELF depuis ExoFS.
// CORRECTION P0-02 : débloque execve() en fournissant le chargement des binaires.
//
// Corrections appliquées (FIX-4) :
//   - resolve_blob_id : appelle resolve_path_to_blob() au lieu de toujours retourner NotFound
//   - Lecture cache   : BLOB_CACHE.get(&BlobId) — API correcte (plus get_blob_data)
//   - PT_LOAD         : demand paging pur via VMA File-backed + FileFaultProvider
//   - map_stack_pages : alloc frames ZEROED + map_page() via PageTableBuilder
//   - ElfLoadError    : InvalidElf/UnsupportedArch (variants qui existent dans l'enum)

use crate::arch::constants::USER_ELF_BASE_MIN;
use crate::fs::exofs::core::types::BlobId;
use crate::fs::exofs::syscall::object_store;
use crate::fs::exofs::syscall::path_resolve::resolve_path_to_blob;
use crate::memory::core::layout::{
    USER_END, USER_STACK_BOOTSTRAP_PAGES, USER_STACK_BOOTSTRAP_SIZE, USER_STACK_TOP,
};
use crate::memory::core::AllocError;
use crate::memory::core::PageFlags;
use crate::memory::physical::allocator::buddy;
use crate::memory::virt::fault::demand_paging::FileFaultProvider;
use crate::memory::virt::page_table::builder::PageTableBuilder;
use crate::memory::virt::page_table::walker::FrameAllocatorForWalk;
use crate::memory::virt::vma::{VmaBacking, VmaDescriptor, VmaFlags};
use crate::memory::virt::UserAddressSpace;
use crate::memory::{phys_to_virt, AllocFlags, Frame, PhysAddr, VirtAddr, PAGE_SIZE};
use crate::process::lifecycle::exec::{ElfLoadError, ElfLoadResult, ElfLoader};
use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
#[cfg(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace))]
use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

const USER_ELF_BASE_MAX: u64 = USER_END.as_u64();
const _: () = assert!(USER_ELF_BASE_MIN < USER_ELF_BASE_MAX);
const _: () = assert!(USER_ELF_BASE_MIN == 0x0040_0000);
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_PHDR: u32 = 6;
const PF_X: u32 = 0x1;
const PF_W: u32 = 0x2;
const PF_R: u32 = 0x4;
const PHDR_SIZE: usize = 56;
const DYNAMIC_LOADER_HANDOFF_MAGIC: u64 = 0x5845_4f4c_4459_4e01; // "XEOLDYN\1"
const DYNAMIC_LOADER_HANDOFF_VERSION: u32 = 1;
const DYNAMIC_LOADER_PATH_MAX: usize = 128;
const DYNAMIC_LOADER_HANDOFF_STACK_GAP: u64 = 16 * 1024;
const DEFAULT_DYNAMIC_LOADER_PATH: &[u8] = b"/lib/ld-exo.so";
const ELF_BLOB_REGISTRY_CAP: usize = 1024;
const ELF_MAX_SEGMENTS_PER_BLOB: usize = 8;

#[cfg(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace))]
static ELF_TRACE_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace))]
#[inline(always)]
fn debug_byte(byte: u8) {
    unsafe {
        core::arch::asm!("out 0xE9, al", in("al") byte, options(nomem, nostack));
    }
}

#[cfg(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace))]
fn debug_write(bytes: &[u8]) {
    for &byte in bytes {
        debug_byte(byte);
    }
}

#[cfg(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace))]
fn debug_usize(mut value: usize) {
    let mut buf = [0u8; 20];
    let mut len = 0usize;
    if value == 0 {
        debug_byte(b'0');
        return;
    }
    while value != 0 && len < buf.len() {
        buf[len] = b'0' + (value % 10) as u8;
        value /= 10;
        len += 1;
    }
    while len != 0 {
        len -= 1;
        debug_byte(buf[len]);
    }
}

#[cfg(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace))]
fn debug_blob_prefix(blob_id: &BlobId) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in &blob_id.as_bytes()[..6] {
        debug_byte(HEX[(byte >> 4) as usize]);
        debug_byte(HEX[(byte & 0x0f) as usize]);
    }
}

#[inline]
fn trace_path(prefix: &[u8], path: &str) {
    let _ = (prefix, path);
    #[cfg(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace))]
    {
        if ELF_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 96 {
            return;
        }
        debug_write(prefix);
        debug_write(path.as_bytes());
        debug_write(b"\n");
    }
}

#[inline]
fn trace_blob(prefix: &[u8], blob_id: &BlobId) {
    let _ = (prefix, blob_id);
    #[cfg(all(target_arch = "x86_64", debug_assertions, exo_kernel_trace))]
    {
        if ELF_TRACE_COUNT.fetch_add(1, Ordering::Relaxed) >= 96 {
            return;
        }
        debug_write(prefix);
        debug_blob_prefix(blob_id);
        debug_write(b" entries=");
        debug_usize(BLOB_CACHE.n_entries());
        debug_write(b"\n");
    }
}

#[derive(Clone, Copy)]
struct ElfSegmentMeta {
    file_data_start: u64,
    file_data_end: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct DynamicLoaderHandoff {
    magic: u64,
    version: u32,
    flags: u32,
    executable_base: u64,
    executable_entry: u64,
    executable_phdr: u64,
    executable_phnum: u64,
    executable_phent: u64,
    executable_dynamic: u64,
    executable_dynamic_count: u64,
    interpreter_base: u64,
    interpreter_entry: u64,
    page_size: u64,
    executable_stack_top: u64,
    executable_path_len: u32,
    interpreter_path_len: u32,
    executable_path: [u8; DYNAMIC_LOADER_PATH_MAX],
    interpreter_path: [u8; DYNAMIC_LOADER_PATH_MAX],
}

#[derive(Clone, Copy)]
struct LoadedElfImage {
    entry_point: u64,
    base: u64,
    phdr_vaddr: u64,
    phnum: u64,
    phent: u64,
    dynamic_vaddr: u64,
    dynamic_count: u64,
    brk_end: u64,
}

#[derive(Clone, Copy)]
struct InterpreterPath {
    bytes: [u8; DYNAMIC_LOADER_PATH_MAX],
    len: usize,
}

impl InterpreterPath {
    fn from_bytes(bytes: &[u8]) -> Result<Self, ElfLoadError> {
        if bytes.is_empty() || bytes.len() >= DYNAMIC_LOADER_PATH_MAX {
            return Err(ElfLoadError::InvalidElf);
        }
        let mut out = [0u8; DYNAMIC_LOADER_PATH_MAX];
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            bytes: out,
            len: bytes.len(),
        })
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

impl ElfSegmentMeta {
    const fn empty() -> Self {
        Self {
            file_data_start: 0,
            file_data_end: 0,
        }
    }
}

struct ElfBlobRegistry {
    ids: [BlobId; ELF_BLOB_REGISTRY_CAP],
    segments: [[ElfSegmentMeta; ELF_MAX_SEGMENTS_PER_BLOB]; ELF_BLOB_REGISTRY_CAP],
    segment_counts: [u8; ELF_BLOB_REGISTRY_CAP],
    count: usize,
}

impl ElfBlobRegistry {
    const fn new() -> Self {
        Self {
            ids: [BlobId::ZERO; ELF_BLOB_REGISTRY_CAP],
            segments: [[ElfSegmentMeta::empty(); ELF_MAX_SEGMENTS_PER_BLOB]; ELF_BLOB_REGISTRY_CAP],
            segment_counts: [0; ELF_BLOB_REGISTRY_CAP],
            count: 0,
        }
    }

    fn intern(&mut self, blob_id: BlobId) -> Option<u64> {
        for idx in 0..self.count {
            if self.ids[idx] == blob_id {
                return Some((idx + 1) as u64);
            }
        }
        if self.count >= ELF_BLOB_REGISTRY_CAP {
            return None;
        }
        let idx = self.count;
        self.ids[idx] = blob_id;
        self.segment_counts[idx] = 0;
        self.count += 1;
        Some((idx + 1) as u64)
    }

    fn get(&self, file_id: u64) -> Option<BlobId> {
        let idx = file_id.checked_sub(1)? as usize;
        if idx >= self.count {
            return None;
        }
        Some(self.ids[idx])
    }

    fn clear_segments(&mut self, file_id: u64) {
        let Some(idx) = file_id.checked_sub(1).map(|v| v as usize) else {
            return;
        };
        if idx >= self.count {
            return;
        }
        self.segment_counts[idx] = 0;
    }

    fn add_segment(&mut self, file_id: u64, p_offset: u64, p_filesz: u64) -> bool {
        let Some(idx) = file_id.checked_sub(1).map(|v| v as usize) else {
            return false;
        };
        if idx >= self.count {
            return false;
        }
        let slot = self.segment_counts[idx] as usize;
        if slot >= ELF_MAX_SEGMENTS_PER_BLOB {
            return false;
        }
        self.segments[idx][slot] = ElfSegmentMeta {
            file_data_start: p_offset,
            file_data_end: p_offset.saturating_add(p_filesz),
        };
        self.segment_counts[idx] = self.segment_counts[idx].saturating_add(1);
        true
    }

    fn segments_for(&self, file_id: u64) -> ([ElfSegmentMeta; ELF_MAX_SEGMENTS_PER_BLOB], usize) {
        let Some(idx) = file_id.checked_sub(1).map(|v| v as usize) else {
            return ([ElfSegmentMeta::empty(); ELF_MAX_SEGMENTS_PER_BLOB], 0);
        };
        if idx >= self.count {
            return ([ElfSegmentMeta::empty(); ELF_MAX_SEGMENTS_PER_BLOB], 0);
        }
        (
            self.segments[idx],
            (self.segment_counts[idx] as usize).min(ELF_MAX_SEGMENTS_PER_BLOB),
        )
    }
}

static ELF_BLOB_REGISTRY: Mutex<ElfBlobRegistry> = Mutex::new(ElfBlobRegistry::new());

fn register_elf_blob(blob_id: BlobId) -> Option<u64> {
    ELF_BLOB_REGISTRY.lock().intern(blob_id)
}

fn lookup_elf_blob(file_id: u64) -> Option<BlobId> {
    ELF_BLOB_REGISTRY.lock().get(file_id)
}

fn clear_elf_segments(file_id: u64) {
    ELF_BLOB_REGISTRY.lock().clear_segments(file_id);
}

fn register_elf_segment(file_id: u64, p_offset: u64, p_filesz: u64) -> Result<(), ElfLoadError> {
    if ELF_BLOB_REGISTRY
        .lock()
        .add_segment(file_id, p_offset, p_filesz)
    {
        Ok(())
    } else {
        Err(ElfLoadError::OutOfMemory)
    }
}

fn lookup_elf_segments(file_id: u64) -> ([ElfSegmentMeta; ELF_MAX_SEGMENTS_PER_BLOB], usize) {
    ELF_BLOB_REGISTRY.lock().segments_for(file_id)
}

// ─────────────────────────────────────────────────────────────────────────────
// Allocateur de frames pour les walks de table de pages de l'ELF loader
// ─────────────────────────────────────────────────────────────────────────────

struct ElfWalkAllocator;

impl FrameAllocatorForWalk for ElfWalkAllocator {
    fn alloc_frame(&self, flags: AllocFlags) -> Result<Frame, AllocError> {
        buddy::alloc_pages(0, flags)
    }

    fn free_frame(&self, frame: Frame) {
        let _ = buddy::free_pages(frame, 0);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Implémentation du chargeur ELF
// ─────────────────────────────────────────────────────────────────────────────

/// Implémentation du chargeur ELF via ExoFS.
pub struct ExoFsElfLoader;

unsafe impl Send for ExoFsElfLoader {}
unsafe impl Sync for ExoFsElfLoader {}

impl ElfLoader for ExoFsElfLoader {
    fn load_elf(
        &self,
        path: &str,
        argv: &[&str],
        envp: &[&str],
        _cr3_in: u64,
    ) -> Result<ElfLoadResult, ElfLoadError> {
        // ── 1. Résoudre le chemin ExoFS → BlobId ────────────────────────────
        trace_path(b"elf: load ", path);
        let blob_id = resolve_blob_id(path.as_bytes())?;
        trace_blob(b"elf: resolved ", &blob_id);
        let file_id = register_elf_blob(blob_id).ok_or(ElfLoadError::OutOfMemory)?;
        clear_elf_segments(file_id);

        // ── 2. Lire le blob depuis le cache ──────────────────────────────────
        let elf_data = read_blob_from_cache(&blob_id)?;

        // ── 3. Valider l'en-tête ELF et détecter PT_INTERP ───────────────────
        // FIX-LOADER-STATIC : ne charger /lib/ld-exo.so QUE si le binaire déclare
        // réellement un PT_INTERP. Les serveurs Exo-OS sont des EXEC statiques
        // (aucune section dynamique) : leur forcer un interpréteur chargeait un
        // second gros ELF (le linker dynamique complet) à CHAQUE exec, doublait le
        // demand-paging et compliquait le chemin de chargement sans aucun bénéfice
        // (runtime_entry est un no-op pour un EXEC sans relocations). Un binaire
        // dynamique (vrai PT_INTERP) continue d'utiliser son interpréteur.
        validate_elf_header(&elf_data)?;
        let interp_path = read_interpreter_path(&elf_data)?;
        let _ = default_interpreter_path; // conservé pour usage dynamique futur

        // ── 5. Créer le nouvel espace d'adressage ────────────────────────────
        let alloc = ElfWalkAllocator;
        let mut builder = PageTableBuilder::new(&alloc).map_err(|_| ElfLoadError::OutOfMemory)?;
        // Copier les entrées kernel (PML4[256..512]) pour que le fils puisse
        // atteindre le kernel lors des appels système
        unsafe {
            builder
                .copy_kernel_entries()
                .map_err(|_| ElfLoadError::OutOfMemory)?;
        }
        let pml4_phys = builder.pml4_phys();
        let child_as = Box::new(UserAddressSpace::new(pml4_phys, 0));

        // ── 6. Charger l'exécutable et éventuellement son interpréteur ───────
        let main_image = install_elf_image(&elf_data, file_id, &child_as, 0)?;
        let mut entry_point = main_image.entry_point;
        let mut entry_arg0 = 0u64;
        let mut interp_image = None;

        if let Some(interp) = interp_path {
            let interp_blob = resolve_blob_id(interp.as_bytes()).map_err(|err| {
                if err == ElfLoadError::NotFound {
                    ElfLoadError::InterpreterNotFound
                } else {
                    err
                }
            })?;
            let interp_file_id = register_elf_blob(interp_blob).ok_or(ElfLoadError::OutOfMemory)?;
            clear_elf_segments(interp_file_id);
            let interp_data = read_blob_from_cache(&interp_blob)?;
            validate_elf_header(&interp_data)?;
            let image = install_elf_image(&interp_data, interp_file_id, &child_as, 0)?;
            entry_point = image.entry_point;
            interp_image = Some((interp, image));
        }

        // ── 7. brk_start = page suivante au-dessus du dernier segment ────────
        let brk_start =
            main_image.brk_end.saturating_add(PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
        child_as.init_heap_bounds(brk_start);

        // ── 8. Pile utilisateur : bootstrap eager minimal, plafond layout partagé ─
        const STACK_TOP: u64 = USER_STACK_TOP.as_u64();
        const STACK_SIZE: usize = USER_STACK_BOOTSTRAP_SIZE;
        let stack_size = STACK_SIZE;
        let stack_base = STACK_TOP.saturating_sub(stack_size as u64);

        let stack_frames = map_stack_pages(&mut builder, &alloc, stack_base, stack_size)?;
        install_stack_vma(&child_as, stack_base, stack_size)?;
        let executable_stack_top =
            build_initial_process_stack(&stack_frames, stack_base, STACK_TOP, argv, envp)?;
        if let Some((interp, image)) = interp_image {
            let handoff =
                build_dynamic_handoff(path, &interp, &main_image, &image, executable_stack_top);
            let handoff_bytes = unsafe {
                core::slice::from_raw_parts(
                    &handoff as *const DynamicLoaderHandoff as *const u8,
                    core::mem::size_of::<DynamicLoaderHandoff>(),
                )
            };
            let handoff_vaddr = (executable_stack_top
                .saturating_sub(DYNAMIC_LOADER_HANDOFF_STACK_GAP)
                .saturating_sub(handoff_bytes.len() as u64))
                & !15u64;
            write_stack_bytes(&stack_frames, stack_base, handoff_vaddr, handoff_bytes)?;
            entry_arg0 = handoff_vaddr;
        }

        // User ELF mappings are kept outside PML4[0]. Re-apply the low
        // supervisor window last so every userspace CR3 can safely run syscall
        // and IRQ paths while the kernel is still linked in low memory.
        builder
            .remap_low_kernel_identity()
            .map_err(|_| ElfLoadError::OutOfMemory)?;

        // ── 9. Finaliser ─────────────────────────────────────────────────────
        let child_cr3 = pml4_phys.as_u64();
        let addr_space_ptr = Box::into_raw(child_as) as usize;

        Ok(ElfLoadResult {
            entry_point,
            // `_start` est une fonction Rust normale atteinte par iretq, sans
            // adresse de retour pushée par `call`. L'ABI SysV veut donc
            // RSP % 16 == 8 à l'entrée pour que les frames internes restent
            // alignées 16 B avant les appels et les `movaps`.
            initial_stack_top: executable_stack_top,
            entry_arg0,
            tls_base: 0,
            tls_size: 0,
            brk_start,
            cr3: child_cr3,
            addr_space_ptr,
            signal_tcb_vaddr: 0,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// FIX-25-DEMANDPAGE : cache de blobs ELF pour le demand paging
// ─────────────────────────────────────────────────────────────────────────────
//
// Sans cache, `load_file_page` relisait + re-hashait TOUT le blob exécutable
// (jusqu'à ~12 Mio) à CHAQUE faute de page de 4 Kio → mettre un seul binaire en
// page coûtait O(pages × taille_blob) ≈ des milliers de relectures+hash du même
// blob = boot **apparemment figé** (cause réelle de #25 dans son état actuel : le
// demand paging était CORRECT — chaque page se mappait — mais pathologiquement
// lent). On garde quelques blobs récents : les fautes consécutives d'un même
// exécutable (et de son linker `ld-exo.so`) réutilisent les octets déjà lus+
// vérifiés → O(taille_blob) au total.
//
// Sécurité (≠ collision DMA résolue de BLOB_CACHE) : pas de BTreeMap, donc aucun
// nœud heap durable plaçable sur une page tampon DMA virtio ; les octets sont
// épinglés par l'`Arc` (jamais rendus au buddy → jamais réutilisés en DMA).
const ELF_BLOB_CACHE_SLOTS: usize = 4;

struct ElfBlobCache {
    slots: [Option<(BlobId, Arc<[u8]>)>; ELF_BLOB_CACHE_SLOTS],
    next: usize,
}

static ELF_BLOB_CACHE: Mutex<ElfBlobCache> = Mutex::new(ElfBlobCache {
    slots: [None, None, None, None],
    next: 0,
});

/// Octets d'un blob ELF : cache ELF dédié → disque (lu + hashé UNE seule fois,
/// puis réutilisé pour toutes les fautes de page suivantes).
///
/// FIX #25 (Audit 3.4) — On ne consulte PLUS `BLOB_CACHE.get()` du tout.
/// Raison : chaque `BLOB_CACHE.get()` écrit `last_accessed`/`access_count` sur
/// un nœud BTreeMap SLUB et peut allouer un `Arc<[u8]>` via
/// `materialize_snapshot`. Cette pression SLUB pendant le demand-paging ELF
/// de l'enfant peut forcer le buddy à fournir une page ambiguë. En lisant
/// directement depuis `object_store::load_blob_data_if_available`, on élimine
/// la « classe qui persiste » identifiée dans l'audit.
fn load_blob_cached(blob_id: &BlobId) -> Result<Arc<[u8]>, AllocError> {
    // 1. Hit dans le cache ELF dédié (Arc<[u8]> — pas de BTreeMap SLUB).
    {
        let cache = ELF_BLOB_CACHE.lock();
        for slot in cache.slots.iter() {
            if let Some((id, arc)) = slot.as_ref() {
                if id == blob_id {
                    return Ok(Arc::clone(arc));
                }
            }
        }
    }
    // 2. Miss : lecture directe depuis object_store (PAS de BLOB_CACHE.get()).
    let data = object_store::load_blob_data_if_available(blob_id)
        .map_err(|_| AllocError::InvalidParams)?
        .ok_or(AllocError::InvalidParams)?;
    let arc: Arc<[u8]> = Arc::from(data.into_boxed_slice());
    // 3. Insertion round-robin (re-vérifie l'absence pour éviter un doublon).
    {
        let mut cache = ELF_BLOB_CACHE.lock();
        let already = cache
            .slots
            .iter()
            .any(|s| s.as_ref().map_or(false, |(id, _)| id == blob_id));
        if !already {
            let idx = cache.next % ELF_BLOB_CACHE_SLOTS;
            cache.next = cache.next.wrapping_add(1);
            cache.slots[idx] = Some((blob_id.clone(), Arc::clone(&arc)));
        }
    }
    Ok(arc)
}

impl FileFaultProvider for ExoFsElfLoader {
    fn load_file_page(
        &self,
        file_id: u64,
        file_offset: u64,
        dest_frame: Frame,
    ) -> Result<(), AllocError> {
        let blob_id = lookup_elf_blob(file_id).ok_or(AllocError::InvalidParams)?;
        // FIX-25 : octets via cache (plus de relecture+rehash intégral par faute).
        let data_arc = load_blob_cached(&blob_id)?;
        let data = &data_arc[..];
        let dst_virt = phys_to_virt(dest_frame.start_address());
        let dst =
            unsafe { core::slice::from_raw_parts_mut(dst_virt.as_u64() as *mut u8, PAGE_SIZE) };

        // FIX #25 (Audit 5.1) — Diagnostic défensif : `dst.fill(0)` ci-dessous
        // est la SEULE écriture physmap PAGE_SIZE sur le chemin live (demand-
        // paging execve) qui contourne le détecteur ZEROINIT du buddy
        // (dest_frame est alloué via alloc_nonzeroed, pas ZEROED). Si dest_frame
        // est corrompu (frame pile d'init vivante), cette écriture zéroe la
        // page d'init → SEGV rip=0. On vérifie donc ici que dest_frame n'est PAS
        // une frame de pile d'init avant d'écrire.
        #[cfg(target_arch = "x86_64")]
        {
            use core::sync::atomic::Ordering;
            let dest_phys = dest_frame.start_address().as_u64();
            let mut i = 0usize;
            while i < 24 {
                let initf = crate::memory::physical::allocator::buddy::DIAG25_INITF[i]
                    .load(Ordering::Relaxed);
                if initf != 0 && initf == dest_phys {
                    panic!(
                        "#25 CAUGHT load_file_page: dest_frame={:#x} == DIAG25_INITF[{}]",
                        dest_phys, i
                    );
                }
                i += 1;
            }
        }

        dst.fill(0);

        let (segments, segment_count) = lookup_elf_segments(file_id);
        if segment_count == 0 {
            let start = file_offset as usize;
            if start >= data.len() {
                return Ok(());
            }
            let end = start.saturating_add(PAGE_SIZE).min(data.len());
            let len = end.saturating_sub(start);
            dst[..len].copy_from_slice(&data[start..end]);
            return Ok(());
        }

        let page_start = file_offset;
        let page_end = page_start.saturating_add(PAGE_SIZE as u64);
        for segment in segments.iter().take(segment_count) {
            if page_end <= segment.file_data_start || page_start >= segment.file_data_end {
                continue;
            }

            let copy_start = page_start.max(segment.file_data_start);
            let copy_end = page_end.min(segment.file_data_end);
            if copy_start >= copy_end || copy_start > usize::MAX as u64 {
                continue;
            }

            let src_start = copy_start as usize;
            if src_start >= data.len() {
                continue;
            }
            let src_end = (copy_end as usize).min(data.len());
            if src_start >= src_end {
                continue;
            }

            let dst_start = copy_start.saturating_sub(page_start) as usize;
            let len = src_end.saturating_sub(src_start);
            if dst_start.saturating_add(len) <= PAGE_SIZE {
                dst[dst_start..dst_start + len].copy_from_slice(&data[src_start..src_end]);
            }
        }
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers privés
// ─────────────────────────────────────────────────────────────────────────────

/// Résout un chemin ExoFS en BlobId.
/// Délègue à resolve_path_to_blob() (pub(crate)) qui fait Blake3 du chemin canonique.
fn resolve_blob_id(path_bytes: &[u8]) -> Result<BlobId, ElfLoadError> {
    resolve_path_to_blob(path_bytes, 0)
        .map(|r| BlobId(r.blob_id))
        .map_err(|_| {
            trace_path(
                b"elf: resolve failed ",
                core::str::from_utf8(path_bytes).unwrap_or("<non-utf8>"),
            );
            ElfLoadError::NotFound
        })
}

/// Lit le contenu complet d'un blob depuis le disque ExoFS.
///
/// FIX #25 (Audit 3.4) — On ne consulte PLUS `BLOB_CACHE.get()` du tout.
/// Le chargeur ELF lit chaque blob UNE seule fois. L'aller-retour
/// `insert()+get()` dans BLOB_CACHE est du travail redondant (double stockage,
/// matérialisation Arc) et — surtout — il place un nœud BTreeMap durable sur
/// la page heap réutilisée comme tampon DMA virtio (collision DMA/heap qui
/// corrompt le nœud → memmove géant). De plus, chaque `get()` écrit
/// `last_accessed`/`access_count` sur le nœud (mutation SLUB) qui crée la
/// « classe qui persiste » identifiée dans l'audit. On renvoie donc directement
/// les octets disque sans passer par le cache partagé.
fn read_blob_from_cache(blob_id: &BlobId) -> Result<Arc<[u8]>, ElfLoadError> {
    trace_blob(b"elf: disk direct ", blob_id);
    let Some(data) =
        object_store::load_blob_data_if_available(blob_id).map_err(|_| ElfLoadError::NotFound)?
    else {
        return Err(ElfLoadError::NotFound);
    };
    Ok(Arc::from(data.into_boxed_slice()))
}

/// Valide magic, classe ELF et architecture.
fn validate_elf_header(data: &[u8]) -> Result<(), ElfLoadError> {
    if data.len() < 64 {
        return Err(ElfLoadError::InvalidElf);
    }
    if &data[0..4] != b"\x7FELF" {
        return Err(ElfLoadError::InvalidElf);
    }
    // EI_CLASS = 2 → 64-bit
    if data[4] != 2 {
        return Err(ElfLoadError::UnsupportedArch);
    }
    // EI_DATA = 1 → little-endian
    if data[5] != 1 {
        return Err(ElfLoadError::UnsupportedArch);
    }
    // e_machine = 0x3E → EM_X86_64
    let e_machine = u16::from_le_bytes([data[18], data[19]]);
    if e_machine != 0x3E {
        return Err(ElfLoadError::UnsupportedArch);
    }
    Ok(())
}

fn elf_u16(data: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([data[off], data[off + 1]])
}

fn elf_u32(data: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([data[off], data[off + 1], data[off + 2], data[off + 3]])
}

fn elf_u64(data: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
}

fn phdr_span(data: &[u8]) -> Result<(usize, usize, usize), ElfLoadError> {
    if data.len() < 64 {
        return Err(ElfLoadError::InvalidElf);
    }
    let e_phoff = elf_u64(data, 32) as usize;
    let e_phentsize = elf_u16(data, 54) as usize;
    let e_phnum = elf_u16(data, 56) as usize;
    if e_phentsize < PHDR_SIZE {
        return Err(ElfLoadError::InvalidElf);
    }
    let table_bytes = e_phentsize
        .checked_mul(e_phnum)
        .ok_or(ElfLoadError::InvalidElf)?;
    let end = e_phoff
        .checked_add(table_bytes)
        .ok_or(ElfLoadError::InvalidElf)?;
    if end > data.len() {
        return Err(ElfLoadError::InvalidElf);
    }
    Ok((e_phoff, e_phnum, e_phentsize))
}

fn phdr_at(
    data: &[u8],
    e_phoff: usize,
    e_phentsize: usize,
    idx: usize,
) -> Result<&[u8], ElfLoadError> {
    let off = e_phoff
        .checked_add(idx.saturating_mul(e_phentsize))
        .ok_or(ElfLoadError::InvalidElf)?;
    let end = off.checked_add(PHDR_SIZE).ok_or(ElfLoadError::InvalidElf)?;
    if end > data.len() {
        return Err(ElfLoadError::InvalidElf);
    }
    Ok(&data[off..end])
}

fn read_interpreter_path(data: &[u8]) -> Result<Option<InterpreterPath>, ElfLoadError> {
    let (e_phoff, e_phnum, e_phentsize) = phdr_span(data)?;
    let mut i = 0usize;
    while i < e_phnum {
        let ph = phdr_at(data, e_phoff, e_phentsize, i)?;
        if elf_u32(ph, 0) == PT_INTERP {
            let offset = elf_u64(ph, 8) as usize;
            let filesz = elf_u64(ph, 32) as usize;
            if filesz == 0 || filesz > DYNAMIC_LOADER_PATH_MAX {
                return Err(ElfLoadError::InvalidElf);
            }
            let end = offset.checked_add(filesz).ok_or(ElfLoadError::InvalidElf)?;
            if end > data.len() {
                return Err(ElfLoadError::InvalidElf);
            }
            let raw = &data[offset..end];
            let len = raw.iter().position(|b| *b == 0).unwrap_or(raw.len());
            if len == 0 || len >= DYNAMIC_LOADER_PATH_MAX {
                return Err(ElfLoadError::InvalidElf);
            }
            let mut bytes = [0u8; DYNAMIC_LOADER_PATH_MAX];
            bytes[..len].copy_from_slice(&raw[..len]);
            return Ok(Some(InterpreterPath { bytes, len }));
        }
        i += 1;
    }
    Ok(None)
}

fn default_interpreter_path(path: &str) -> Result<Option<InterpreterPath>, ElfLoadError> {
    if path.as_bytes() == DEFAULT_DYNAMIC_LOADER_PATH {
        return Ok(None);
    }
    InterpreterPath::from_bytes(DEFAULT_DYNAMIC_LOADER_PATH).map(Some)
}

fn install_elf_image(
    elf_data: &[u8],
    file_id: u64,
    child_as: &UserAddressSpace,
    load_bias: u64,
) -> Result<LoadedElfImage, ElfLoadError> {
    let entry_point = elf_u64(elf_data, 24).saturating_add(load_bias);
    let phent = elf_u16(elf_data, 54) as u64;
    let (e_phoff, e_phnum, e_phentsize) = phdr_span(elf_data)?;
    let mut brk_end = 0u64;
    let mut phdr_vaddr = 0u64;
    let mut dynamic_vaddr = 0u64;
    let mut dynamic_count = 0u64;

    let mut i = 0usize;
    while i < e_phnum {
        let ph = phdr_at(elf_data, e_phoff, e_phentsize, i)?;
        let p_type = elf_u32(ph, 0);
        let p_flags = elf_u32(ph, 4);
        let p_offset = elf_u64(ph, 8) as usize;
        let p_vaddr = elf_u64(ph, 16).saturating_add(load_bias);
        let p_filesz = elf_u64(ph, 32) as usize;
        let p_memsz = elf_u64(ph, 40) as usize;

        if p_type == PT_PHDR {
            phdr_vaddr = p_vaddr;
        } else if p_type == PT_DYNAMIC {
            dynamic_vaddr = p_vaddr;
            dynamic_count = (p_filesz / 16) as u64;
        }

        if p_type != PT_LOAD {
            i += 1;
            continue;
        }
        if p_memsz == 0 {
            i += 1;
            continue;
        }
        validate_load_segment_flags(p_flags)?;
        if p_filesz > p_memsz || p_offset.saturating_add(p_filesz) > elf_data.len() {
            return Err(ElfLoadError::InvalidElf);
        }
        validate_user_segment_range(p_vaddr, p_memsz)?;
        register_elf_segment(file_id, p_offset as u64, p_filesz as u64)?;

        install_elf_vma(
            child_as,
            p_vaddr,
            p_memsz,
            p_flags,
            p_offset as u64,
            file_id,
        )?;

        let seg_end = p_vaddr.saturating_add(p_memsz as u64);
        if seg_end > brk_end {
            brk_end = seg_end;
        }
        i += 1;
    }

    if phdr_vaddr == 0 {
        phdr_vaddr = load_bias.saturating_add(e_phoff as u64);
    }

    Ok(LoadedElfImage {
        entry_point,
        base: load_bias,
        phdr_vaddr,
        phnum: e_phnum as u64,
        phent,
        dynamic_vaddr,
        dynamic_count,
        brk_end,
    })
}

fn build_dynamic_handoff(
    executable_path: &str,
    interpreter_path: &InterpreterPath,
    executable: &LoadedElfImage,
    interpreter: &LoadedElfImage,
    executable_stack_top: u64,
) -> DynamicLoaderHandoff {
    let mut handoff = DynamicLoaderHandoff {
        magic: DYNAMIC_LOADER_HANDOFF_MAGIC,
        version: DYNAMIC_LOADER_HANDOFF_VERSION,
        flags: 0,
        executable_base: executable.base,
        executable_entry: executable.entry_point,
        executable_phdr: executable.phdr_vaddr,
        executable_phnum: executable.phnum,
        executable_phent: executable.phent,
        executable_dynamic: executable.dynamic_vaddr,
        executable_dynamic_count: executable.dynamic_count,
        interpreter_base: interpreter.base,
        interpreter_entry: interpreter.entry_point,
        page_size: PAGE_SIZE as u64,
        executable_stack_top,
        executable_path_len: 0,
        interpreter_path_len: interpreter_path.len as u32,
        executable_path: [0; DYNAMIC_LOADER_PATH_MAX],
        interpreter_path: [0; DYNAMIC_LOADER_PATH_MAX],
    };

    let exe = executable_path.as_bytes();
    let exe_len = exe.len().min(DYNAMIC_LOADER_PATH_MAX);
    handoff.executable_path[..exe_len].copy_from_slice(&exe[..exe_len]);
    handoff.executable_path_len = exe_len as u32;
    handoff.interpreter_path[..interpreter_path.len].copy_from_slice(interpreter_path.as_bytes());
    handoff
}

fn validate_user_segment_range(p_vaddr: u64, p_memsz: usize) -> Result<(), ElfLoadError> {
    let Some(end_unaligned) = p_vaddr.checked_add(p_memsz as u64) else {
        return Err(ElfLoadError::InvalidElf);
    };
    let page_mask = PAGE_SIZE as u64 - 1;
    let start = p_vaddr & !page_mask;
    let end = end_unaligned.saturating_add(page_mask) & !page_mask;

    if start < USER_ELF_BASE_MIN {
        return Err(ElfLoadError::InvalidElf);
    }

    if end > USER_ELF_BASE_MAX {
        return Err(ElfLoadError::InvalidElf);
    }

    Ok(())
}

fn validate_load_segment_flags(p_flags: u32) -> Result<(), ElfLoadError> {
    if (p_flags & (PF_W | PF_X)) == (PF_W | PF_X) {
        return Err(ElfLoadError::PermissionDenied);
    }
    Ok(())
}

fn elf_page_flags(p_flags: u32) -> PageFlags {
    debug_assert!(validate_load_segment_flags(p_flags).is_ok());

    let exec = (p_flags & PF_X) != 0;
    let write = (p_flags & PF_W) != 0;

    match (exec, write) {
        (true, true) => PageFlags::USER_DATA,
        (true, false) => PageFlags::USER_CODE,
        (false, true) => PageFlags::USER_DATA,
        (false, false) => PageFlags::PRESENT | PageFlags::USER | PageFlags::NO_EXECUTE,
    }
}

fn elf_vma_flags(p_flags: u32) -> VmaFlags {
    debug_assert!(validate_load_segment_flags(p_flags).is_ok());

    let mut flags = VmaFlags::NONE;
    if (p_flags & PF_R) != 0 {
        flags |= VmaFlags::READ;
    }
    if (p_flags & PF_W) != 0 {
        flags |= VmaFlags::WRITE;
    }
    if (p_flags & PF_X) != 0 {
        flags |= VmaFlags::EXEC;
    }
    flags
}

fn install_elf_vma(
    user_as: &UserAddressSpace,
    p_vaddr: u64,
    p_memsz: usize,
    p_flags: u32,
    file_offset: u64,
    file_id: u64,
) -> Result<(), ElfLoadError> {
    if p_memsz == 0 {
        return Ok(());
    }

    let start = p_vaddr & !(PAGE_SIZE as u64 - 1);
    let end_unaligned = p_vaddr.saturating_add(p_memsz as u64);
    let end = end_unaligned.saturating_add(PAGE_SIZE as u64 - 1) & !(PAGE_SIZE as u64 - 1);
    let mut vma = Box::new(VmaDescriptor::new(
        VirtAddr::new(start),
        VirtAddr::new(end),
        elf_vma_flags(p_flags),
        elf_page_flags(p_flags),
        VmaBacking::File,
    ));
    vma.inode_id = file_id;
    vma.file_offset = file_offset & !(PAGE_SIZE as u64 - 1);
    let vma_ptr = Box::into_raw(vma);
    let inserted = unsafe { user_as.insert_vma(vma_ptr) };
    if !inserted {
        let _ = unsafe { Box::from_raw(vma_ptr) };
        return Err(ElfLoadError::OutOfMemory);
    }
    Ok(())
}

fn install_stack_vma(
    user_as: &UserAddressSpace,
    stack_base: u64,
    stack_size: usize,
) -> Result<(), ElfLoadError> {
    let vma = Box::new(VmaDescriptor::new(
        VirtAddr::new(stack_base),
        VirtAddr::new(stack_base.saturating_add(stack_size as u64)),
        VmaFlags::READ | VmaFlags::WRITE | VmaFlags::ANONYMOUS | VmaFlags::STACK,
        PageFlags::USER_DATA,
        VmaBacking::Anonymous,
    ));
    let vma_ptr = Box::into_raw(vma);
    let inserted = unsafe { user_as.insert_vma(vma_ptr) };
    if !inserted {
        let _ = unsafe { Box::from_raw(vma_ptr) };
        return Err(ElfLoadError::OutOfMemory);
    }
    Ok(())
}

/// Alloue et mappe les pages de pile utilisateur (toutes ZEROED, USER_DATA).
fn map_stack_pages<A: FrameAllocatorForWalk>(
    builder: &mut PageTableBuilder<A>,
    _alloc: &A,
    stack_base: u64,
    stack_size: usize,
) -> Result<[Frame; USER_STACK_BOOTSTRAP_PAGES], ElfLoadError> {
    let n_pages = stack_size / PAGE_SIZE;
    if n_pages != USER_STACK_BOOTSTRAP_PAGES {
        return Err(ElfLoadError::InvalidElf);
    }
    let mut frames = [Frame::containing(PhysAddr::new(0)); USER_STACK_BOOTSTRAP_PAGES];
    for page_idx in 0..n_pages {
        let frame =
            buddy::alloc_pages(0, AllocFlags::ZEROED).map_err(|_| ElfLoadError::OutOfMemory)?;
        let virt = VirtAddr::new(stack_base.saturating_add((page_idx * PAGE_SIZE) as u64));
        builder
            .map_page(virt, frame, PageFlags::USER_DATA)
            .map_err(|_| ElfLoadError::OutOfMemory)?;
        frames[page_idx] = frame;
    }
    Ok(frames)
}

fn write_stack_bytes(
    stack_frames: &[Frame; USER_STACK_BOOTSTRAP_PAGES],
    stack_base: u64,
    user_vaddr: u64,
    bytes: &[u8],
) -> Result<(), ElfLoadError> {
    let stack_len = USER_STACK_BOOTSTRAP_SIZE as u64;
    let start_off = user_vaddr
        .checked_sub(stack_base)
        .ok_or(ElfLoadError::InvalidElf)?;
    let end_off = start_off
        .checked_add(bytes.len() as u64)
        .ok_or(ElfLoadError::InvalidElf)?;
    if end_off > stack_len {
        return Err(ElfLoadError::InvalidElf);
    }

    let mut copied = 0usize;
    while copied < bytes.len() {
        let off = start_off as usize + copied;
        let page_idx = off / PAGE_SIZE;
        let page_off = off % PAGE_SIZE;
        let n = (bytes.len() - copied).min(PAGE_SIZE - page_off);
        let dst_virt = phys_to_virt(stack_frames[page_idx].start_address());

        // FIX #25 (Audit 5.2) — Diagnostic défensif : vérifier que
        // stack_frames[page_idx] n'est PAS une frame de pile d'init vivante.
        // Si stack_frames (sur la pile noyau de l'enfant) a été corrompu,
        // write_stack_bytes écrirait via physmap sur une frame d'init →
        // corruption. On panic pour capturer le coupable.
        #[cfg(target_arch = "x86_64")]
        {
            use core::sync::atomic::Ordering;
            let dest_phys = stack_frames[page_idx].start_address().as_u64();
            let mut i = 0usize;
            while i < 24 {
                let initf = crate::memory::physical::allocator::buddy::DIAG25_INITF[i]
                    .load(Ordering::Relaxed);
                if initf != 0 && initf == dest_phys {
                    panic!(
                        "#25 CAUGHT write_stack_bytes: stack_frames[{}]={:#x} == DIAG25_INITF[{}]",
                        page_idx, dest_phys, i
                    );
                }
                i += 1;
            }
        }

        let dst = unsafe {
            core::slice::from_raw_parts_mut((dst_virt.as_u64() as usize + page_off) as *mut u8, n)
        };
        dst.copy_from_slice(&bytes[copied..copied + n]);
        copied += n;
    }
    Ok(())
}

fn write_stack_u64(
    stack_frames: &[Frame; USER_STACK_BOOTSTRAP_PAGES],
    stack_base: u64,
    user_vaddr: u64,
    value: u64,
) -> Result<(), ElfLoadError> {
    write_stack_bytes(stack_frames, stack_base, user_vaddr, &value.to_ne_bytes())
}

fn push_stack_bytes(
    stack_frames: &[Frame; USER_STACK_BOOTSTRAP_PAGES],
    stack_base: u64,
    sp: &mut u64,
    bytes: &[u8],
) -> Result<u64, ElfLoadError> {
    let len = bytes.len().checked_add(1).ok_or(ElfLoadError::InvalidElf)? as u64;
    *sp = sp.checked_sub(len).ok_or(ElfLoadError::InvalidElf)?;
    write_stack_bytes(stack_frames, stack_base, *sp, bytes)?;
    write_stack_bytes(stack_frames, stack_base, *sp + bytes.len() as u64, &[0])?;
    Ok(*sp)
}

fn push_stack_u64(
    stack_frames: &[Frame; USER_STACK_BOOTSTRAP_PAGES],
    stack_base: u64,
    sp: &mut u64,
    value: u64,
) -> Result<(), ElfLoadError> {
    *sp = sp.checked_sub(8).ok_or(ElfLoadError::InvalidElf)?;
    write_stack_u64(stack_frames, stack_base, *sp, value)
}

fn build_initial_process_stack(
    stack_frames: &[Frame; USER_STACK_BOOTSTRAP_PAGES],
    stack_base: u64,
    stack_top: u64,
    argv: &[&str],
    envp: &[&str],
) -> Result<u64, ElfLoadError> {
    let mut sp = stack_top;
    let mut argv_ptrs: Vec<u64> = Vec::new();
    let mut envp_ptrs: Vec<u64> = Vec::new();
    argv_ptrs
        .try_reserve(argv.len())
        .map_err(|_| ElfLoadError::OutOfMemory)?;
    envp_ptrs
        .try_reserve(envp.len())
        .map_err(|_| ElfLoadError::OutOfMemory)?;

    for arg in argv {
        argv_ptrs.push(push_stack_bytes(
            stack_frames,
            stack_base,
            &mut sp,
            arg.as_bytes(),
        )?);
    }
    for env in envp {
        envp_ptrs.push(push_stack_bytes(
            stack_frames,
            stack_base,
            &mut sp,
            env.as_bytes(),
        )?);
    }

    sp &= !15u64;

    // AT_NULL, puis envp/argv, puis argc. Les binaires no_std Exo-OS lisent
    // argc/argv/envp directement depuis ce contrat de pile. Le slot de padding
    // conserve RSP % 16 == 8 sans déplacer argc hors de [RSP].
    let pointer_slots = argv_ptrs.len() + envp_ptrs.len() + 5;
    if pointer_slots & 1 == 0 {
        push_stack_u64(stack_frames, stack_base, &mut sp, 0)?;
    }
    push_stack_u64(stack_frames, stack_base, &mut sp, 0)?;
    push_stack_u64(stack_frames, stack_base, &mut sp, 0)?;

    push_stack_u64(stack_frames, stack_base, &mut sp, 0)?;
    let mut idx = envp_ptrs.len();
    while idx != 0 {
        idx -= 1;
        push_stack_u64(stack_frames, stack_base, &mut sp, envp_ptrs[idx])?;
    }

    push_stack_u64(stack_frames, stack_base, &mut sp, 0)?;
    idx = argv_ptrs.len();
    while idx != 0 {
        idx -= 1;
        push_stack_u64(stack_frames, stack_base, &mut sp, argv_ptrs[idx])?;
    }
    push_stack_u64(stack_frames, stack_base, &mut sp, argv.len() as u64)?;
    Ok(sp)
}

/// Instance statique du chargeur ELF.
pub static EXO_ELF_LOADER: ExoFsElfLoader = ExoFsElfLoader;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_load_segment_flags_rejects_write_exec() {
        assert_eq!(
            validate_load_segment_flags(PF_R | PF_W | PF_X),
            Err(ElfLoadError::PermissionDenied)
        );
    }

    #[test]
    fn test_validate_load_segment_flags_allows_standard_segments() {
        assert_eq!(validate_load_segment_flags(PF_R | PF_X), Ok(()));
        assert_eq!(validate_load_segment_flags(PF_R | PF_W), Ok(()));
        assert_eq!(validate_load_segment_flags(PF_R), Ok(()));
    }
}
