// kernel/src/memory/physical/allocator/buddy.rs
//
// Buddy Allocator — allocateur physique principal O(log n).
// Implémentation classique du système de buddy avec free-lists par ordre.
// Couche 0 — aucune dépendance externe.
//
// Principe :
//   La RAM est divisée en blocs de taille 2^order × PAGE_SIZE.
//   Chaque ordre dispose d'une free-list doublement chaînée.
//   Allocation  : parcours des ordres de bas en haut jusqu'au premier
//                 bloc disponible, puis division des blocs supérieurs.
//   Libération  : recherche du buddy et fusion récursive (coalescing).
//
// Invariants :
//   - Un bloc d'ordre k a une adresse alignée sur 2^k pages.
//   - Le buddy d'un bloc d'adresse P est P ⊕ (1 << k).
//   - Jamais de fragmentation externe au-delà de 1 bloc de chaque ordre.

use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use spin::Mutex;

use crate::memory::core::{
    is_aligned, AllocError, AllocFlags, Frame, PhysAddr, ZoneType, BUDDY_MAX_ORDER,
    BUDDY_ORDER_COUNT, PAGE_SIZE,
};
use crate::memory::physical::frame::descriptor::{FrameFlags, FRAME_DESCRIPTORS};

// ─────────────────────────────────────────────────────────────────────────────
// FREE LIST NODE — nœud de liste chaînée dans un buddy bloc libre
// ─────────────────────────────────────────────────────────────────────────────

/// Nœud de liste chaînée embedding dans un bloc libre.
/// Stocké directement dans les premiers octets du bloc (page physique libre).
///
/// SAFETY: Ce nœud est lisible uniquement quand le bloc est LIBRE.
/// Dès qu'un bloc est alloué, son contenu est indéfini pour l'allocateur.
#[repr(C)]
struct FreeNode {
    next: *mut FreeNode,
    prev: *mut FreeNode,
    order: u8,
    _pad: [u8; 7],
}

impl FreeNode {
    #[inline]
    unsafe fn init(ptr: *mut FreeNode, order: u8) {
        (*ptr).next = ptr;
        (*ptr).prev = ptr;
        (*ptr).order = order;
    }

    #[inline]
    unsafe fn insert_after(list_head: *mut FreeNode, node: *mut FreeNode) {
        let next = (*list_head).next;
        (*node).prev = list_head;
        (*node).next = next;
        (*next).prev = node;
        (*list_head).next = node;
    }

    #[inline]
    unsafe fn remove(node: *mut FreeNode) {
        let prev = (*node).prev;
        let next = (*node).next;
        (*prev).next = next;
        (*next).prev = prev;
        (*node).next = node;
        (*node).prev = node;
    }

    #[inline]
    unsafe fn is_empty(list_head: *const FreeNode) -> bool {
        if list_head.is_null() {
            return true;
        }
        (*list_head).next == list_head as *mut FreeNode
    }

    #[inline]
    unsafe fn pop(list_head: *mut FreeNode) -> Option<*mut FreeNode> {
        if Self::is_empty(list_head) {
            return None;
        }
        let node = (*list_head).next;
        Self::remove(node);
        Some(node)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BUDDY ORDER LEVEL — une free-list pour un ordre donné
// ─────────────────────────────────────────────────────────────────────────────

/// Tête de free-list pour un ordre donné.
#[repr(C, align(64))]
struct BuddyOrderLevel {
    /// Tête sentinelle (nœud vide — next/prev pointent vers elle-même si vide).
    head: FreeNode,
    /// Nombre de blocs libres à cet ordre.
    count: AtomicUsize,
}

impl BuddyOrderLevel {
    const fn new() -> Self {
        BuddyOrderLevel {
            head: FreeNode {
                next: null_mut(),
                prev: null_mut(),
                order: 0,
                _pad: [0; 7],
            },
            count: AtomicUsize::new(0),
        }
    }

    /// Initialise la sentinelle (ne peut pas être fait en const, besoin de pointeur).
    unsafe fn init(&mut self) {
        let h = &mut self.head as *mut FreeNode;
        (*h).next = h;
        (*h).prev = h;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BUDDY ZONE — allocateur buddy pour une zone mémoire
// ─────────────────────────────────────────────────────────────────────────────

/// Allocateur buddy pour une zone mémoire donnée.
///
/// Chaque zone (DMA, DMA32, Normal, Movable) dispose de sa propre instance.
/// L'allocation est protégée par un spinlock par zone, ce qui permet
/// la concurrence inter-zones sans contention croisée.
pub struct BuddyZone {
    /// Zone mémoire gérée par cet allocateur.
    zone_type: ZoneType,
    /// Nœud NUMA.
    numa_node: u8,
    /// Adresse physique de début.
    phys_start: PhysAddr,
    /// Adresse physique de fin (exclusive).
    phys_end: PhysAddr,
    /// Nombre total de frames dans cette zone.
    total_frames: usize,
    /// Free-lists protégées par spinlock.
    /// L'usage de spin::Mutex est autorisé dans memory/ (Couche 0).
    inner: Mutex<BuddyZoneInner>,
    /// Nombre de frames libres (snapshot approximatif, cache-friendly).
    free_frames: AtomicUsize,
    /// Compteur d'allocations.
    alloc_count: AtomicUsize,
    /// Compteur de libérations.
    free_count: AtomicUsize,
    /// Compteur d'échecs (fragmentation ou mémoire épuisée).
    fail_count: AtomicUsize,
    /// Compteur de scissions (splits).
    split_count: AtomicUsize,
    /// Compteur de fusions (merges/coalescing).
    merge_count: AtomicUsize,
    /// Indicateur d'initialisation.
    initialized: AtomicBool,
}

struct BuddyZoneInner {
    /// Free-lists par ordre (0..=BUDDY_MAX_ORDER).
    orders: [BuddyOrderLevel; BUDDY_ORDER_COUNT],
    /// Bitmap de disponibilité par frame (1 bit par frame).
    /// Alloué dans un buffer statique fourni au boot.
    /// Null si non configuré.
    ///
    /// SAFETY: Le bitmap est accessible uniquement sous le spinlock.
    bitmap_ptr: *mut u64,
    bitmap_words: usize,
}

// SAFETY: BuddyZoneInner n'est accessible que sous le spinlock de BuddyZone.
unsafe impl Send for BuddyZoneInner {}

impl BuddyZoneInner {
    const fn new() -> Self {
        BuddyZoneInner {
            orders: [const { BuddyOrderLevel::new() }; BUDDY_ORDER_COUNT],
            bitmap_ptr: null_mut(),
            bitmap_words: 0,
        }
    }

    /// Marque le frame `pfn` comme libre dans le bitmap.
    #[inline(always)]
    unsafe fn bitmap_clear(&self, pfn: usize) {
        if self.bitmap_ptr.is_null() {
            return;
        }
        let word = pfn / 64;
        let bit = pfn % 64;
        if word < self.bitmap_words {
            (*self.bitmap_ptr.add(word)) &= !(1u64 << bit);
        }
    }

    /// Marque le frame `pfn` comme alloué dans le bitmap.
    #[inline(always)]
    unsafe fn bitmap_set(&self, pfn: usize) {
        if self.bitmap_ptr.is_null() {
            return;
        }
        let word = pfn / 64;
        let bit = pfn % 64;
        if word < self.bitmap_words {
            (*self.bitmap_ptr.add(word)) |= 1u64 << bit;
        }
    }

    /// Retourne `true` si le frame `pfn` est libre dans le bitmap.
    #[inline(always)]
    unsafe fn bitmap_is_free(&self, pfn: usize) -> bool {
        if self.bitmap_ptr.is_null() {
            return false;
        }
        let word = pfn / 64;
        let bit = pfn % 64;
        if word >= self.bitmap_words {
            return false;
        }
        ((*self.bitmap_ptr.add(word)) & (1u64 << bit)) == 0
    }

    /// Retourne `true` si le frame `pfn` est marqué alloué dans le bitmap.
    #[inline(always)]
    unsafe fn bitmap_is_allocated(&self, pfn: usize) -> bool {
        if self.bitmap_ptr.is_null() {
            return false;
        }
        let word = pfn / 64;
        let bit = pfn % 64;
        if word >= self.bitmap_words {
            return false;
        }
        ((*self.bitmap_ptr.add(word)) & (1u64 << bit)) != 0
    }

    #[inline(always)]
    unsafe fn bitmap_range_is_free(&self, pfn: usize, count: usize) -> bool {
        (0..count).all(|i| self.bitmap_is_free(pfn + i))
    }

    #[inline(always)]
    unsafe fn bitmap_range_is_allocated(&self, pfn: usize, count: usize) -> bool {
        (0..count).all(|i| self.bitmap_is_allocated(pfn + i))
    }
}

#[inline(always)]
fn reserve_frame_descriptor(frame: Frame) {
    let desc = FRAME_DESCRIPTORS.get(frame);
    desc.set_flag(FrameFlags::PINNED);
    desc.set_flag(FrameFlags::RESERVED);
    desc.clear_flag(FrameFlags::FREE);
}

impl BuddyZone {
    /// Crée une instance non initialisée.
    pub const fn new_uninit() -> Self {
        BuddyZone {
            zone_type: ZoneType::Normal,
            numa_node: 0,
            phys_start: PhysAddr::new(0),
            phys_end: PhysAddr::new(0),
            total_frames: 0,
            inner: Mutex::new(BuddyZoneInner::new()),
            free_frames: AtomicUsize::new(0),
            alloc_count: AtomicUsize::new(0),
            free_count: AtomicUsize::new(0),
            fail_count: AtomicUsize::new(0),
            split_count: AtomicUsize::new(0),
            merge_count: AtomicUsize::new(0),
            initialized: AtomicBool::new(false),
        }
    }

    /// Initialise l'allocateur buddy pour une zone.
    ///
    /// `bitmap_buf` : buffer alloué statiquement pour le bitmap de disponibilité.
    ///               Taille requise : ceil(total_pages / 64) × 8 bytes.
    ///
    /// SAFETY: Doit être appelé une seule fois depuis un contexte single-CPU
    ///         (avant l'init SMP).
    pub unsafe fn init(
        &self,
        zone_type: ZoneType,
        numa_node: u8,
        phys_start: PhysAddr,
        phys_end: PhysAddr,
        bitmap_buf: *mut u64,
        bitmap_words: usize,
    ) {
        // Stocker les paramètres de zone
        let s = self as *const BuddyZone as *mut BuddyZone;
        (*s).zone_type = zone_type;
        (*s).numa_node = numa_node;
        (*s).phys_start = phys_start;
        (*s).phys_end = phys_end;
        (*s).total_frames = ((phys_end.as_u64() - phys_start.as_u64()) / PAGE_SIZE as u64) as usize;

        // Initialiser l'inner sous lock
        let mut inner = self.inner.lock();
        for order in &mut inner.orders {
            order.init();
        }
        inner.bitmap_ptr = bitmap_buf;
        inner.bitmap_words = bitmap_words;

        // Initialiser le bitmap à "tout alloué" (bits = 1)
        if !bitmap_buf.is_null() {
            for i in 0..bitmap_words {
                *bitmap_buf.add(i) = u64::MAX;
            }
        }

        drop(inner);

        self.initialized.store(true, Ordering::Release);
    }

    /// Ajoute une plage de frames libres à l'allocateur (boot: après init).
    ///
    /// Appelé par le détecteur de mémoire E820 pour peupler l'allocateur
    /// avec les régions RAM disponibles.
    ///
    /// SAFETY: Doit être appelé avant l'init SMP. `first_pfn..last_pfn`
    /// doit être une plage valide. Les recouvrements éventuels avec des plages
    /// déjà ajoutées sont ignorés au niveau page pour préserver l'unicité des
    /// frames dans les free-lists.
    pub unsafe fn add_free_range(&self, first_pfn: usize, last_pfn: usize) {
        debug_assert!(self.initialized.load(Ordering::Acquire));
        debug_assert!(first_pfn < last_pfn);

        let mut pfn = first_pfn;
        while pfn < last_pfn {
            // Déterminer l'ordre maximal utilisable depuis ce pfn
            let remaining = last_pfn - pfn;
            let max_order_by_align = if pfn == 0 {
                BUDDY_MAX_ORDER
            } else {
                pfn.trailing_zeros() as usize
            };
            let max_order_by_count = (usize::BITS - remaining.leading_zeros() - 1) as usize;
            let mut order = max_order_by_align
                .min(max_order_by_count)
                .min(BUDDY_MAX_ORDER);

            loop {
                let count = 1usize << order;
                let still_unclaimed = {
                    let inner = self.inner.lock();
                    unsafe { inner.bitmap_range_is_allocated(pfn, count) }
                };

                if still_unclaimed {
                    let phys =
                        PhysAddr::new(self.phys_start.as_u64() + pfn as u64 * PAGE_SIZE as u64);
                    self.add_free_block(phys, order);
                    pfn += count;
                    break;
                }

                if order == 0 {
                    // Page déjà libre dans le buddy : probablement recouvrement
                    // de la carte mémoire. Ne jamais réinsérer le même nœud.
                    pfn += 1;
                    break;
                }
                order -= 1;
            }
        }
    }

    /// Ajoute un bloc libre à la free-list de l'ordre correspondant.
    ///
    /// SAFETY: `phys` doit être aligné sur 2^order pages et appartenir
    /// à cette zone. Appelé uniquement pendant l'init ou la libération.
    unsafe fn add_free_block(&self, phys: PhysAddr, order: usize) {
        if order > BUDDY_MAX_ORDER || !self.contains_aligned_block(phys, order) {
            self.fail_count.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let mut inner = self.inner.lock();
        let pfn = ((phys.as_u64() - self.phys_start.as_u64()) / PAGE_SIZE as u64) as usize;
        let count = 1usize << order;
        if unsafe { !inner.bitmap_range_is_allocated(pfn, count) } {
            // L'ajout des régions firmware peut contenir des recouvrements.
            // Réinsérer un bloc déjà libre créerait deux entrées de free-list
            // pour la même frame physique.
            return;
        }

        let node_ptr = phys_to_virt_buddy(phys) as *mut FreeNode;
        FreeNode::init(node_ptr, order as u8);
        FreeNode::insert_after(&mut inner.orders[order].head as *mut FreeNode, node_ptr);
        inner.orders[order].count.fetch_add(1, Ordering::Relaxed);

        // Marquer comme libre dans le bitmap
        for i in 0..count {
            inner.bitmap_clear(pfn + i);
        }
        self.mark_descriptors_free(pfn, count);

        self.free_frames.fetch_add(count, Ordering::Relaxed);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ALLOCATION
    // ─────────────────────────────────────────────────────────────────────────

    /// Alloue `2^order` pages contiguës depuis cette zone.
    ///
    /// Algorithme :
    ///   1. Vérifier les hints NUMA IA (lookup statique .rodata).
    ///   2. Parcourir les ordres de `order` vers `BUDDY_MAX_ORDER`.
    ///   3. Si un bloc est trouvé à un ordre supérieur `found_order` :
    ///      - Diviser (split) jusqu'à l'ordre demandé.
    ///      - Ajouter les demi-blocs supérieurs à leurs free-lists.
    ///   4. Marquer les pages comme allouées dans le bitmap.
    ///   5. Mettre à jour les statistiques.
    pub fn alloc_pages(&self, order: usize, flags: AllocFlags) -> Result<Frame, AllocError> {
        if order > BUDDY_MAX_ORDER {
            self.fail_count.fetch_add(1, Ordering::Relaxed);
            return Err(AllocError::InvalidParams);
        }

        if !self.initialized.load(Ordering::Acquire) {
            return Err(AllocError::NotInitialized);
        }

        // RÈGLE NO-ALLOC : pas d'allocation, tout se passe sous le lock.
        let result = {
            let mut inner = self.inner.lock();
            self.alloc_inner(&mut inner, order, flags)
        };

        match result {
            Ok(phys) => {
                self.free_frames.fetch_sub(1 << order, Ordering::Relaxed);
                self.alloc_count.fetch_add(1, Ordering::Relaxed);
                if flags.contains(AllocFlags::ZEROED) {
                    // SAFETY: Le frame vient d'être alloué, nous en sommes l'unique propriétaire.
                    unsafe {
                        zero_pages(phys, order);
                    }
                }
                let frame = Frame::containing(phys);
                // #25 : détecteur double-alloc au CHOKEPOINT zone — couvre alloc_on_node
                // (NUMA) et tous les fallbacks, contrairement au wrapper top-level qui
                // était court-circuité par alloc_on_node.
                #[cfg(target_arch = "x86_64")]
                diag25_on_alloc(frame, order);
                // V-05 / MEM-05 : poser DMA_PINNED sur tous les frames DMA jusqu'à
                // wait_dma_complete() — protège contre reclaim et swap.
                if flags.contains(AllocFlags::DMA) || flags.contains(AllocFlags::DMA32) {
                    FRAME_DESCRIPTORS
                        .get(frame)
                        .set_flag(FrameFlags::DMA_PINNED);
                }
                Ok(frame)
            }
            Err(e) => {
                self.fail_count.fetch_add(1, Ordering::Relaxed);
                Err(e)
            }
        }
    }

    /// Logique d'allocation interne (sous spinlock).
    fn alloc_inner(
        &self,
        inner: &mut BuddyZoneInner,
        order: usize,
        _flags: AllocFlags,
    ) -> Result<PhysAddr, AllocError> {
        // Chercher le premier ordre >= `order` avec un bloc disponible
        for current_order in order..=BUDDY_MAX_ORDER {
            // SAFETY: Sous le spinlock, accès exclusif aux free-lists.
            unsafe {
                let head = &mut inner.orders[current_order].head as *mut FreeNode;
                match FreeNode::pop(head) {
                    None => continue, // Pas de bloc à cet ordre
                    Some(node) => {
                        inner.orders[current_order]
                            .count
                            .fetch_sub(1, Ordering::Relaxed);

                        let phys = virt_to_phys_buddy(node as usize);
                        if !self.contains_aligned_block(phys, current_order) {
                            self.fail_count.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        let popped_pfn = self.phys_to_pfn(phys);
                        if self.descriptors_range_has_reserved(popped_pfn, 1usize << current_order) {
                            self.fail_count.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        if !inner.bitmap_range_is_free(popped_pfn, 1usize << current_order) {
                            self.fail_count.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }
                        if !self.descriptors_range_is_free(popped_pfn, 1usize << current_order) {
                            self.fail_count.fetch_add(1, Ordering::Relaxed);
                            continue;
                        }

                        // Diviser (split) si nous sommes à un ordre supérieur
                        let block_phys = phys;
                        for split_order in (order..current_order).rev() {
                            // Le buddy de `block_phys` à l'ordre `split_order + 1`
                            // est `block_phys + 2^split_order × PAGE_SIZE`
                            let buddy_phys = PhysAddr::new(
                                block_phys.as_u64() + (PAGE_SIZE << split_order) as u64,
                            );

                            // Remettre le buddy dans la free-list
                            let buddy_node = phys_to_virt_buddy(buddy_phys) as *mut FreeNode;
                            FreeNode::init(buddy_node, split_order as u8);
                            let buddy_head = &mut inner.orders[split_order].head as *mut FreeNode;
                            FreeNode::insert_after(buddy_head, buddy_node);
                            inner.orders[split_order]
                                .count
                                .fetch_add(1, Ordering::Relaxed);

                            // Vider le bitmap du buddy (il est libre maintenant)
                            let buddy_pfn = self.phys_to_pfn(buddy_phys);
                            for i in 0..(1usize << split_order) {
                                inner.bitmap_clear(buddy_pfn + i);
                            }

                            self.split_count.fetch_add(1, Ordering::Relaxed);
                        }

                        // Marquer les pages allouées dans le bitmap
                        let pfn = self.phys_to_pfn(block_phys);
                        for i in 0..(1usize << order) {
                            inner.bitmap_set(pfn + i);
                        }
                        self.mark_descriptors_allocated(pfn, 1usize << order);

                        return Ok(block_phys);
                    }
                }
            }
        }

        Err(AllocError::OutOfMemory)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LIBÉRATION + COALESCING
    // ─────────────────────────────────────────────────────────────────────────

    /// Libère un bloc de `2^order` pages commençant à `frame`.
    ///
    /// Algorithme de coalescing :
    ///   1. Calculer l'adresse du buddy.
    ///   2. Si le buddy est libre (dans le bitmap) et au même ordre :
    ///      - Retirer le buddy de sa free-list.
    ///      - Fusionner les deux blocs (prendre le plus petit pfn).
    ///      - Incrémenter l'ordre et recommencer.
    ///   3. Sinon, insérer dans la free-list à l'ordre courant.
    pub fn free_pages(&self, frame: Frame, order: usize) -> Result<(), AllocError> {
        if order > BUDDY_MAX_ORDER {
            self.fail_count.fetch_add(1, Ordering::Relaxed);
            return Err(AllocError::InvalidParams);
        }

        if !self.initialized.load(Ordering::Acquire) {
            return Err(AllocError::NotInitialized);
        }

        let phys = frame.start_address();
        if !self.contains_block(phys, order) {
            self.fail_count.fetch_add(1, Ordering::Relaxed);
            return Err(AllocError::InvalidParams);
        }
        let zone_relative = phys.as_u64().saturating_sub(self.phys_start.as_u64()) as usize;
        if !is_aligned(zone_relative, PAGE_SIZE << order) {
            self.fail_count.fetch_add(1, Ordering::Relaxed);
            return Err(AllocError::InvalidParams);
        }

        // FIX #25 (Audit 1.B) — Refuser de libérer une frame marquée RESERVED.
        // Les frames de pile d'init sont marquées RESERVED dès leur attribution
        // (via `reserve_frames` dans `map_stack_pages`). Si un chemin corrompu
        // tente de libérer Fa, le buddy refuse au lieu de remettre Fa en
        // circulation. Cela ferme la fenêtre de course même si un déséquilibre
        // de refcount rend Fa « éligible » au free.
        {
            let pfn_check = self.phys_to_pfn(phys);
            let count = 1usize << order;
            for k in 0..count {
                let desc = FRAME_DESCRIPTORS.get(self.pfn_to_frame(pfn_check + k));
                let flags = desc.flags();
                if flags.contains(FrameFlags::RESERVED) {
                    #[cfg(target_arch = "x86_64")]
                    {
                        use crate::arch::x86_64::terminal::debug_write;
                        debug_write(b"<25RSVD-REFUSE f=");
                        diag25_hex(phys.as_u64());
                        debug_write(b" ord=");
                        diag25_dec(order as u64);
                        debug_write(b">\n");
                    }
                    self.fail_count.fetch_add(1, Ordering::Relaxed);
                    return Err(AllocError::InvalidParams);
                }
            }
        }

        {
            let mut inner = self.inner.lock();
            let pfn = self.phys_to_pfn(phys);
            if unsafe { !inner.bitmap_range_is_allocated(pfn, 1usize << order) } {
                self.fail_count.fetch_add(1, Ordering::Relaxed);
                return Err(AllocError::InvalidParams);
            }
            if !self.descriptors_range_is_allocated(pfn, 1usize << order) {
                self.fail_count.fetch_add(1, Ordering::Relaxed);
                return Err(AllocError::InvalidParams);
            }
            self.mark_descriptors_free(pfn, 1usize << order);
            // SAFETY: Sous spinlock, accès exclusif.
            unsafe {
                self.free_inner(&mut inner, phys, order);
            }
        }

        self.free_frames.fetch_add(1 << order, Ordering::Relaxed);
        self.free_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    unsafe fn free_inner(&self, inner: &mut BuddyZoneInner, phys: PhysAddr, order: usize) {
        let mut current_phys = phys;
        let mut current_order = order;

        // Marquer les pages comme libres dans le bitmap
        let pfn = self.phys_to_pfn(current_phys);
        for i in 0..(1usize << order) {
            inner.bitmap_clear(pfn + i);
        }

        // Tentatives de fusion (coalescing)
        while current_order < BUDDY_MAX_ORDER {
            let buddy_phys = self.buddy_of(current_phys, current_order);

            // Le buddy doit être dans la même zone
            if buddy_phys < self.phys_start || buddy_phys >= self.phys_end {
                break;
            }

            // Vérifier si le buddy est libre dans le bitmap
            let buddy_pfn = self.phys_to_pfn(buddy_phys);
            let buddy_free =
                (0..(1usize << current_order)).all(|i| inner.bitmap_is_free(buddy_pfn + i));

            if !buddy_free {
                break; // Le buddy est alloué → pas de fusion possible
            }

            // Retirer le buddy de sa free-list
            let buddy_node = phys_to_virt_buddy(buddy_phys) as *mut FreeNode;
            // Vérifier que le buddy est bien dans une free-list (ordre cohérent)
            if (*buddy_node).order != current_order as u8 {
                break;
            }
            FreeNode::remove(buddy_node);
            inner.orders[current_order]
                .count
                .fetch_sub(1, Ordering::Relaxed);

            // Fusionner : prendre l'adresse la plus basse des deux blocs
            current_phys = if current_phys < buddy_phys {
                current_phys
            } else {
                buddy_phys
            };
            current_order += 1;
            self.merge_count.fetch_add(1, Ordering::Relaxed);
        }

        // Insérer le bloc (éventuellement fusionné) dans la free-list
        let node_ptr = phys_to_virt_buddy(current_phys) as *mut FreeNode;
        FreeNode::init(node_ptr, current_order as u8);
        let head = &mut inner.orders[current_order].head as *mut FreeNode;
        FreeNode::insert_after(head, node_ptr);
        inner.orders[current_order]
            .count
            .fetch_add(1, Ordering::Relaxed);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UTILITAIRES
    // ─────────────────────────────────────────────────────────────────────────

    /// Calcule l'adresse physique du buddy d'un bloc.
    /// Le buddy d'un bloc à l'ordre k, adresse P, est P ⊕ (2^k × PAGE_SIZE).
    #[inline(always)]
    fn buddy_of(&self, phys: PhysAddr, order: usize) -> PhysAddr {
        let relative = phys.as_u64() - self.phys_start.as_u64();
        let buddy_relative = relative ^ ((PAGE_SIZE << order) as u64);
        PhysAddr::new(self.phys_start.as_u64() + buddy_relative)
    }

    #[inline(always)]
    fn contains_block(&self, phys: PhysAddr, order: usize) -> bool {
        if order > BUDDY_MAX_ORDER || phys < self.phys_start {
            return false;
        }
        let bytes = (PAGE_SIZE as u64) << order;
        match phys.as_u64().checked_add(bytes) {
            Some(end) => end <= self.phys_end.as_u64(),
            None => false,
        }
    }

    #[inline(always)]
    fn contains_aligned_block(&self, phys: PhysAddr, order: usize) -> bool {
        if !self.contains_block(phys, order) {
            return false;
        }
        let zone_relative = phys.as_u64().saturating_sub(self.phys_start.as_u64()) as usize;
        is_aligned(zone_relative, PAGE_SIZE << order)
    }

    /// Retourne le PFN relatif au début de cette zone.
    #[inline(always)]
    fn phys_to_pfn(&self, phys: PhysAddr) -> usize {
        ((phys.as_u64() - self.phys_start.as_u64()) / PAGE_SIZE as u64) as usize
    }

    #[inline(always)]
    fn pfn_to_frame(&self, pfn: usize) -> Frame {
        Frame::containing(PhysAddr::new(
            self.phys_start.as_u64() + pfn as u64 * PAGE_SIZE as u64,
        ))
    }

    #[inline(always)]
    fn descriptors_range_is_free(&self, pfn: usize, count: usize) -> bool {
        (0..count).all(|i| {
            let flags = FRAME_DESCRIPTORS.get(self.pfn_to_frame(pfn + i)).flags();
            flags.contains(FrameFlags::FREE) && !flags.contains(FrameFlags::RESERVED)
        })
    }

    #[inline(always)]
    fn descriptors_range_is_allocated(&self, pfn: usize, count: usize) -> bool {
        (0..count).all(|i| {
            !FRAME_DESCRIPTORS
                .get(self.pfn_to_frame(pfn + i))
                .flags()
                .contains(FrameFlags::FREE)
        })
    }

    #[inline(always)]
    fn descriptors_range_has_reserved(&self, pfn: usize, count: usize) -> bool {
        (0..count).any(|i| {
            FRAME_DESCRIPTORS
                .get(self.pfn_to_frame(pfn + i))
                .flags()
                .contains(FrameFlags::RESERVED)
        })
    }

    #[inline(always)]
    fn mark_descriptors_free(&self, pfn: usize, count: usize) {
        for i in 0..count {
            FRAME_DESCRIPTORS
                .get(self.pfn_to_frame(pfn + i))
                .swap_flags(FrameFlags::FREE);
        }
    }

    #[inline(always)]
    fn mark_descriptors_allocated(&self, pfn: usize, count: usize) {
        for i in 0..count {
            FRAME_DESCRIPTORS
                .get(self.pfn_to_frame(pfn + i))
                .clear_flag(FrameFlags::FREE);
        }
    }

    /// Retourne le nombre de frames libres (snapshot approximatif).
    #[inline(always)]
    pub fn free_frames(&self) -> usize {
        self.free_frames.load(Ordering::Relaxed)
    }

    /// Retourne le nombre total de frames gérées par cette zone.
    #[inline(always)]
    pub fn total_frames_count(&self) -> usize {
        self.total_frames
    }

    /// Retourne les statistiques de l'allocateur.
    pub fn stats(&self) -> BuddyZoneStats {
        let inner = self.inner.lock();
        let mut free_by_order = [0usize; BUDDY_ORDER_COUNT];
        for (i, order) in inner.orders.iter().enumerate() {
            free_by_order[i] = order.count.load(Ordering::Relaxed);
        }
        BuddyZoneStats {
            zone_type: self.zone_type,
            numa_node: self.numa_node,
            total_frames: self.total_frames,
            free_frames: self.free_frames.load(Ordering::Relaxed),
            alloc_count: self.alloc_count.load(Ordering::Relaxed),
            free_count: self.free_count.load(Ordering::Relaxed),
            fail_count: self.fail_count.load(Ordering::Relaxed),
            split_count: self.split_count.load(Ordering::Relaxed),
            merge_count: self.merge_count.load(Ordering::Relaxed),
            free_by_order,
        }
    }

    /// Vérifie si l'allocateur gère la zone donnée.
    #[inline(always)]
    pub fn manages_zone(&self, zone: ZoneType) -> bool {
        self.zone_type == zone
    }

    /// Vérifie si l'allocateur est initialisé.
    #[inline(always)]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// STATISTIQUES
// ─────────────────────────────────────────────────────────────────────────────

/// Statistiques d'une zone buddy.
#[derive(Copy, Clone, Debug)]
pub struct BuddyZoneStats {
    pub zone_type: ZoneType,
    pub numa_node: u8,
    pub total_frames: usize,
    pub free_frames: usize,
    pub alloc_count: usize,
    pub free_count: usize,
    pub fail_count: usize,
    pub split_count: usize,
    pub merge_count: usize,
    /// Nombre de blocs libres par ordre (0..BUDDY_ORDER_COUNT).
    pub free_by_order: [usize; BUDDY_ORDER_COUNT],
}

impl BuddyZoneStats {
    /// Pourcentage de mémoire libre (0.0-100.0).
    pub fn free_percent(&self) -> f32 {
        if self.total_frames == 0 {
            return 0.0;
        }
        self.free_frames as f32 * 100.0 / self.total_frames as f32
    }

    /// Taux de fragmentation (0.0 = aucune, 1.0 = maximale).
    /// Mesure l'écart entre la mémoire libre totale et les blocs de grand ordre.
    pub fn fragmentation_ratio(&self) -> f32 {
        if self.free_frames == 0 {
            return 0.0;
        }
        let largest_order = (0..BUDDY_ORDER_COUNT)
            .rev()
            .find(|&o| self.free_by_order[o] > 0)
            .unwrap_or(0);
        let max_contiguous = self.free_by_order[largest_order] * (1 << largest_order);
        1.0 - (max_contiguous as f32 / self.free_frames as f32)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ALLOCATEUR BUDDY GLOBAL — couvre toutes les zones
// ─────────────────────────────────────────────────────────────────────────────

/// Allocateur buddy global couvrant toutes les zones et tous les nœuds NUMA.
///
/// Routage des allocations selon les flags :
///   - AllocFlags::DMA    → BuddyZone DMA
///   - AllocFlags::DMA32  → BuddyZone DMA32
///   - Default           → BuddyZone Normal (NUMA-preferred)
pub struct GlobalBuddyAllocator {
    // Une zone par ZoneType par nœud NUMA
    // Simplifié : tableau [ZoneType::COUNT] (NUMA node 0 par défaut pour l'instant)
    zones: [BuddyZone; 4], // DMA, DMA32, Normal, Movable
    initialized: AtomicBool,
}

// SAFETY: GlobalBuddyAllocator est thread-safe via ses spinlocks internes.
unsafe impl Sync for GlobalBuddyAllocator {}
unsafe impl Send for GlobalBuddyAllocator {}

impl GlobalBuddyAllocator {
    pub const fn new() -> Self {
        GlobalBuddyAllocator {
            zones: [const { BuddyZone::new_uninit() }; 4],
            initialized: AtomicBool::new(false),
        }
    }

    /// Alloue `2^order` pages contiguës selon les flags.
    /// Sélectionne automatiquement la zone appropriée.
    #[inline]
    pub fn alloc_pages(&self, order: usize, flags: AllocFlags) -> Result<Frame, AllocError> {
        debug_assert!(
            self.initialized.load(Ordering::Acquire),
            "GlobalBuddyAllocator non initialisé"
        );

        let zone_idx = self.zone_index_for(flags);
        let result = self.zones[zone_idx].alloc_pages(order, flags);

        // Fallback vers zone supérieure si la zone cible est épuisée
        if result.is_err() && !flags.contains(AllocFlags::DMA) {
            for fallback_idx in (zone_idx + 1)..4 {
                let r = self.zones[fallback_idx].alloc_pages(order, flags);
                if r.is_ok() {
                    return r;
                }
            }
        }

        // Fallback vers zone inférieure (Normal → DMA32 sur systèmes avec < 4 GiB RAM).
        // Standard x86_64 : Normal est vide quand toute la RAM est < 4 GiB.
        // Ne descend pas en-dessous de DMA32 (idx=1) pour les allocations non-DMA.
        if result.is_err() && zone_idx > 1 {
            for fallback_idx in (1..zone_idx).rev() {
                let r = self.zones[fallback_idx].alloc_pages(order, flags);
                if r.is_ok() {
                    return r;
                }
            }
        }

        result
    }

    /// Libère un bloc de `2^order` pages.
    #[inline]
    pub fn free_pages(&self, frame: Frame, order: usize) -> Result<(), AllocError> {
        let phys = frame.start_address();
        // Déterminer la zone d'appartenance
        for zone in &self.zones {
            if zone.is_initialized() && zone.phys_start <= phys && phys < zone.phys_end {
                return zone.free_pages(frame, order);
            }
        }
        Err(AllocError::ZoneUnavailable)
    }

    /// Alloue depuis le nœud NUMA demandé.
    ///
    /// Itère les zones initialisées dont `numa_node` correspond à `numa_node`.
    /// Si aucune zone NUMA-locale ne peut satisfaire la demande, replie sur
    /// l'allocation globale (premier fallback).
    pub fn alloc_on_node(
        &self,
        order: usize,
        flags: AllocFlags,
        numa_node: u8,
    ) -> Result<Frame, AllocError> {
        debug_assert!(
            self.initialized.load(Ordering::Acquire),
            "GlobalBuddyAllocator non initialisé"
        );

        // Phase 1 : essai dans les zones NUMA-locales.
        for zone in &self.zones {
            if !zone.is_initialized() {
                continue;
            }
            if zone.numa_node != numa_node {
                continue;
            }
            if let Ok(frame) = zone.alloc_pages(order, flags) {
                return Ok(frame);
            }
        }

        // Phase 2 : fallback global (allocation cross-NUMA).
        self.alloc_pages(order, flags)
    }

    #[inline]
    fn zone_index_for(&self, flags: AllocFlags) -> usize {
        match flags.required_zone() {
            ZoneType::Dma => 0,
            ZoneType::Dma32 => 1,
            ZoneType::Movable => 3,
            _ => 2, // Normal par défaut
        }
    }

    /// Retourne le nombre total de frames libres dans toutes les zones.
    pub fn total_free_frames(&self) -> usize {
        self.zones
            .iter()
            .filter(|z| z.is_initialized())
            .map(|z| z.free_frames())
            .sum()
    }

    /// Retourne le nombre total de frames physiques gérées (libres + utilisées).
    pub fn total_frames(&self) -> usize {
        self.zones
            .iter()
            .filter(|z| z.is_initialized())
            .map(|z| z.total_frames_count())
            .sum()
    }

    /// Marque l'allocateur comme initialisé.
    pub fn mark_initialized(&self) {
        self.initialized.store(true, Ordering::Release);
    }

    /// Initialise une zone de l'allocateur (appelé au boot, single-CPU).
    ///
    /// `zone_type` détermine l'index de la zone (0=DMA, 1=DMA32, 2=Normal, 3=Movable).
    /// `bitmap_buf` doit pointer vers un buffer statique de `bitmap_words` u64.
    ///
    /// # Safety
    /// - Doit être appelé UNE SEULE FOIS par zone, avant SMP.
    /// - `bitmap_buf` doit être valide pour `bitmap_words` × 8 bytes.
    pub unsafe fn init_zone(
        &self,
        zone_type: ZoneType,
        phys_start: PhysAddr,
        phys_end: PhysAddr,
        bitmap_buf: *mut u64,
        bitmap_words: usize,
    ) {
        let idx = (zone_type.index()).min(3);
        self.zones[idx].init(
            zone_type,
            0, /* NUMA node 0 */
            phys_start,
            phys_end,
            bitmap_buf,
            bitmap_words,
        );
    }

    /// Ajoute une plage de frames libres aux zones initialisées qui couvrent cette plage.
    ///
    /// Appelé pour chaque région E820/UEFI utilisable, après `init_zone()`.
    ///
    /// # Safety
    /// - Zones concernées doivent être initialisées.
    /// - La plage ne doit pas contenir de mémoire kernel active.
    pub unsafe fn add_free_zone_region(&self, start: PhysAddr, end: PhysAddr) {
        for zone in &self.zones {
            if !zone.is_initialized() {
                continue;
            }
            let zs = zone.phys_start.as_u64();
            let ze = zone.phys_end.as_u64();
            let rs = start.as_u64();
            let re = end.as_u64();
            if rs >= ze || re <= zs {
                continue;
            } // pas d'overlap
            let cs = rs.max(zs);
            let ce = re.min(ze);
            if cs >= ce {
                continue;
            }
            let first_pfn = ((cs - zs) / PAGE_SIZE as u64) as usize;
            let last_pfn = ((ce - zs) / PAGE_SIZE as u64) as usize;
            zone.add_free_range(first_pfn, last_pfn);
        }
    }

    /// Retourne une référence à la zone pour un type donné.
    pub fn zone(&self, zone_type: ZoneType) -> Option<&BuddyZone> {
        let idx = match zone_type {
            ZoneType::Dma => 0,
            ZoneType::Dma32 => 1,
            ZoneType::Normal => 2,
            ZoneType::Movable => 3,
            ZoneType::High => return None,
        };
        let z = &self.zones[idx];
        if z.is_initialized() {
            Some(z)
        } else {
            None
        }
    }

    /// Accès mutant à une zone (initialisation uniquement).
    ///
    /// SAFETY: Doit être appelé uniquement pendant l'init, en single-CPU.
    pub unsafe fn zone_mut(&self, zone_type: ZoneType) -> Option<&BuddyZone> {
        self.zone(zone_type)
    }
}

/// Allocateur buddy global.
pub static BUDDY: GlobalBuddyAllocator = GlobalBuddyAllocator::new();

/// Alloue `2^order` pages physiques contiguës.
#[inline(always)]
pub fn alloc_pages(order: usize, flags: AllocFlags) -> Result<Frame, AllocError> {
    // #25 : diag25_on_alloc est désormais au chokepoint BuddyZone::alloc_pages
    // (couvre alloc_on_node), plus ici, pour éviter le double-marquage.
    BUDDY.alloc_pages(order, flags)
}

/// Libère un bloc de `2^order` pages.
#[inline(always)]
pub fn free_pages(frame: Frame, order: usize) -> Result<(), AllocError> {
    #[cfg(target_arch = "x86_64")]
    diag25_on_free(frame, order);
    BUDDY.free_pages(frame, order)
}

// ── DIAG #25 : détecteur de DOUBLE-ALLOCATION générique (auto-calibré) ──────────
//
// Bitmap 1 bit/frame (256 Mo = 65536 frames = 1024 u64). À chaque alloc on marque
// les frames ; si une frame est allouée alors qu'elle l'est DÉJÀ (sans free
// intermédiaire) → double-alloc = bug #25 (réutilisation d'une frame vivante,
// p.ex. la pile d'init). Émet la frame + la chaîne d'appel (balayage de pile) du
// coupable. Robuste au déplacement des frames entre builds (rien codé en dur).
#[cfg(target_arch = "x86_64")]
static DIAG25_ALLOC_BITMAP: [core::sync::atomic::AtomicU64; 1024] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 1024];

// Bitmap des frames ayant DÉJÀ servi de tampon DMA (« DMA-tainted »). Si une telle
// frame est ré-allouée par le buddy pour un usage non-DMA (p.ex. la pile CoW d'init),
// une écriture DMA tardive du périphérique la corrompt → bug #25.
#[cfg(target_arch = "x86_64")]
static DIAG25_DMA_TAINT: [core::sync::atomic::AtomicU64; 1024] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 1024];

/// DIAG #25 : frame de pile USER d'init à surveiller (F'), capturé au moment du
/// CoW-break dans `cow.rs`. Tout `free` de ce frame APRÈS sa capture = libération
/// erronée du frame VIVANT d'init = cause racine de #25 (le buddy le recycle
/// ensuite pour une alloc ZEROED de l'execve enfant qui l'écrase à 0). 0 = désarmé.
// Armé DÈS LE BOOT sur 0x582d000 (F' de ce build) pour capter TOUT le cycle de vie
// du frame de pile d'init : alloc → [free erroné] → ré-alloc enfant. Le 1er FREEF
// après l'alloc d'init = la libération fautive (cause racine #25).
#[cfg(target_arch = "x86_64")]
pub static DIAG25_WATCH_FRAME: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// DIAG #25 : trace une opération de refcount/free sur le frame surveillé (F').
/// `tag` doit se terminer par le préfixe ; on émet la valeur décimale puis `>`.
#[cfg(target_arch = "x86_64")]
pub fn diag25_trace(tag: &[u8], frame_phys: u64, val: u32) {
    use core::sync::atomic::Ordering;
    let wf = DIAG25_WATCH_FRAME.load(Ordering::Relaxed);
    if wf == 0 || frame_phys != wf {
        return;
    }
    use crate::arch::x86_64::terminal::debug_write;
    debug_write(tag);
    diag25_dec(val as u64);
    debug_write(b">");
}

/// DIAG #25 : émet `tag` + un u64 en hex + `>` INCONDITIONNELLEMENT (non gardé).
#[cfg(target_arch = "x86_64")]
pub fn diag25_hex_always(tag: &[u8], v: u64) {
    use crate::arch::x86_64::terminal::debug_write;
    debug_write(tag);
    diag25_hex(v);
    debug_write(b">");
}

// ── DIAG #25 : empreinte des frames de pile d'init (bissection execve) ───────────
// On capture ~24 frames physiques de la pile d'init au vfork + un checksum pondéré
// par position. On le re-vérifie entre chaque sous-étape de l'execve enfant : la
// première étape qui CHANGE le checksum contient l'écriture sauvage (#25).
#[cfg(target_arch = "x86_64")]
pub static DIAG25_INITF: [core::sync::atomic::AtomicU64; 24] =
    [const { core::sync::atomic::AtomicU64::new(0) }; 24];
#[cfg(target_arch = "x86_64")]
pub static DIAG25_INITSUM: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[cfg(target_arch = "x86_64")]
fn diag25_init_sum() -> u64 {
    use core::sync::atomic::Ordering;
    let mut s = 0u64;
    let mut idx = 1u64;
    for i in 0..24 {
        let f = DIAG25_INITF[i].load(Ordering::Relaxed);
        if f == 0 {
            idx += 512;
            continue;
        }
        let base = phys_to_virt_buddy(PhysAddr::new(f));
        for w in 0..512u64 {
            // SAFETY: physmap d'une frame d'init capturée (mappée tout le boot).
            let v = unsafe { core::ptr::read_volatile((base + (w as usize) * 8) as *const u64) };
            s = s.wrapping_add(v.wrapping_mul(idx));
            idx += 1;
        }
    }
    s
}

/// #25 : enregistre le checksum baseline (appelé au vfork après capture des frames).
#[cfg(target_arch = "x86_64")]
pub fn diag25_init_baseline() {
    use core::sync::atomic::Ordering;
    DIAG25_INITSUM.store(diag25_init_sum(), Ordering::Relaxed);
}

/// #25 : vérifie l'intégrité des frames d'init ; émet `<25CORRUPT tag ...>` si changé,
/// puis re-baseline (ne signale que le PREMIER changement par étape).
#[cfg(target_arch = "x86_64")]
pub fn diag25_check_init(tag: &[u8]) {
    use core::sync::atomic::Ordering;
    let base = DIAG25_INITSUM.load(Ordering::Relaxed);
    if base == 0 {
        return;
    }
    let now = diag25_init_sum();
    if now != base {
        use crate::arch::x86_64::terminal::debug_write;
        debug_write(b"<25CORRUPT ");
        debug_write(tag);
        debug_write(b">");
        DIAG25_INITSUM.store(now, Ordering::Relaxed);
    }
}

/// DIAG #25 : émet `tag` + un u64 en hex + `>` si le détecteur est armé.
#[cfg(target_arch = "x86_64")]
pub fn diag25_tag_hex(tag: &[u8], v: u64) {
    use core::sync::atomic::Ordering;
    if DIAG25_WATCH_FRAME.load(Ordering::Relaxed) == 0 {
        return;
    }
    use crate::arch::x86_64::terminal::debug_write;
    debug_write(tag);
    diag25_hex(v);
    debug_write(b">");
}

/// Marque les frames d'un tampon DMA comme « tainted » (appelé par le HAL virtio).
#[cfg(target_arch = "x86_64")]
pub fn diag25_taint_dma(phys: u64, count: u64) {
    use core::sync::atomic::Ordering;
    let base = phys / 4096;
    let mut k = 0u64;
    while k < count {
        let idx = base + k;
        if idx >= 65536 {
            return;
        }
        let word = (idx / 64) as usize;
        DIAG25_DMA_TAINT[word].fetch_or(1u64 << (idx % 64), Ordering::Relaxed);
        k += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn diag25_on_alloc(frame: Frame, order: usize) {
    use core::sync::atomic::Ordering;
    let base = frame.phys_addr().as_u64() / 4096;
    let count = 1u64 << order;
    let mut dbl = false;
    let mut k = 0u64;
    while k < count {
        let idx = base + k;
        if idx >= 65536 {
            return;
        }
        let word = (idx / 64) as usize;
        let mask = 1u64 << (idx % 64);
        let prev = DIAG25_ALLOC_BITMAP[word].fetch_or(mask, Ordering::Relaxed);
        if prev & mask != 0 {
            dbl = true;
        }
        k += 1;
    }
    if dbl {
        diag25_report(b"DBL", frame, order);
    }
    // FIX #25 (Audit 1.B) — Vérifier DIAG25_INITF au moment de l'alloc.
    // Si une frame de pile d'init vivante est ré-allouée par le buddy, c'est
    // le smoking gun d'un `free_pages(Fa)` erroné. On PANIC pour capturer la
    // chaîne d'appel du coupable (plutôt que de laisser la corruption se
    // propager silencieusement via `vmalloc::kalloc` ou un autre chemin).
    {
        let fp = frame.phys_addr().as_u64();
        let span = count * 4096;
        let mut j = 0usize;
        while j < 24 {
            let initf = DIAG25_INITF[j].load(Ordering::Relaxed);
            if initf != 0 && initf >= fp && initf < fp + span {
                diag25_report(b"REALLOCINIT", frame, order);
                panic!(
                    "#25 CAUGHT buddy::alloc_pages: frame={:#x} ord={} chevauche DIAG25_INITF[{}]={:#x} — une frame de pile d'init vivante est ré-allouée",
                    fp, order, j, initf
                );
            }
            j += 1;
        }
    }
    // Une frame ré-allouée alors qu'elle a déjà servi au DMA = candidate à la
    // corruption par écriture DMA tardive (#25). La chaîne d'appel révèle l'usage.
    let mut tainted = false;
    let mut k = 0u64;
    while k < count {
        let idx = base + k;
        if idx >= 65536 {
            break;
        }
        let word = (idx / 64) as usize;
        if DIAG25_DMA_TAINT[word].load(Ordering::Relaxed) & (1u64 << (idx % 64)) != 0 {
            tainted = true;
        }
        k += 1;
    }
    if tainted {
        diag25_report(b"TAINT", frame, order);
    }
    // #25 : tracer chaque alloc du frame surveillé (cycle de vie complet).
    let wf = DIAG25_WATCH_FRAME.load(Ordering::Relaxed);
    if wf != 0 {
        let widx = wf / 4096;
        if widx >= base && widx < base + count {
            diag25_report(b"ALLOC", frame, order);
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn diag25_on_free(frame: Frame, order: usize) {
    use core::sync::atomic::Ordering;
    let base = frame.phys_addr().as_u64() / 4096;
    let count = 1u64 << order;
    // #25 : qui libère le frame VIVANT de la pile d'init (F') ? La chaîne d'appel
    // (return addresses balayées) révèle le chemin fautif (teardown execve, etc.).
    let wf = DIAG25_WATCH_FRAME.load(Ordering::Relaxed);
    if wf != 0 && frame.phys_addr().as_u64() == wf {
        diag25_report(b"FREEF", frame, order);
    }
    // #25 : ce free touche-t-il UNE des frames de pile VIVANTE d'init (les 24
    // capturées au vfork) ? La corruption frappe une page ALÉATOIRE → on surveille
    // toutes les pages de pile d'init, pas seulement Fa.
    {
        let fp = frame.phys_addr().as_u64();
        let span = count * 4096;
        let mut j = 0usize;
        while j < 24 {
            let initf = DIAG25_INITF[j].load(Ordering::Relaxed);
            if initf != 0 && initf >= fp && initf < fp + span {
                diag25_report(b"FREEINIT", frame, order);
                break;
            }
            j += 1;
        }
    }
    let mut k = 0u64;
    while k < count {
        let idx = base + k;
        if idx >= 65536 {
            return;
        }
        let word = (idx / 64) as usize;
        let mask = 1u64 << (idx % 64);
        DIAG25_ALLOC_BITMAP[word].fetch_and(!mask, Ordering::Relaxed);
        k += 1;
    }
}

#[cfg(target_arch = "x86_64")]
#[inline(never)]
fn diag25_report(tag: &[u8], frame: Frame, order: usize) {
    use crate::arch::x86_64::terminal::debug_write;
    debug_write(b"<25");
    debug_write(tag);
    debug_write(b" f=");
    diag25_hex(frame.phys_addr().as_u64());
    debug_write(b" ord=");
    diag25_dec(order as u64);
    debug_write(b" chain=");
    // Balaye la pile courante pour les adresses de retour (plage code kernel).
    let mut rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
    }
    let mut i = 0u64;
    while i < 64 {
        // SAFETY: lecture dans la pile noyau courante (déjà allouée).
        let v = unsafe { *((rsp + i * 8) as *const u64) };
        if (0x100000..0x500000).contains(&v) {
            debug_write(b" ");
            diag25_hex(v);
        }
        i += 1;
    }
    debug_write(b">\n");
}

#[cfg(target_arch = "x86_64")]
pub fn diag25_hex(mut v: u64) {
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

#[cfg(target_arch = "x86_64")]
pub fn diag25_dec(mut v: u64) {
    use crate::arch::x86_64::terminal::debug_write;
    let mut buf = [0u8; 20];
    let mut pos = 20usize;
    if v == 0 {
        pos -= 1;
        buf[pos] = b'0';
    }
    while v > 0 && pos > 0 {
        pos -= 1;
        buf[pos] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    debug_write(&buf[pos..]);
}

/// Alloue exactement 1 page physique (ordre 0).
#[inline(always)]
pub fn alloc_page(flags: AllocFlags) -> Result<Frame, AllocError> {
    alloc_pages(0, flags)
}

/// Libère exactement 1 page physique.
#[inline(always)]
pub fn free_page(frame: Frame) -> Result<(), AllocError> {
    free_pages(frame, 0)
}

/// Réserve un frame physique contre toute libération/réallocation buddy.
///
/// Le frame reste utilisable par ses mappings existants, mais le buddy
/// refusera ensuite toute tentative de free/reuse.
#[inline(always)]
pub fn reserve_frame(frame: Frame) {
    reserve_frame_descriptor(frame);
}

/// Réserve une série de frames physiques contiguës.
#[inline(always)]
pub fn reserve_frames(frames: &[Frame]) {
    for &frame in frames {
        reserve_frame_descriptor(frame);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UTILITAIRES INTERNES (bridge physmap temporaire)
// ─────────────────────────────────────────────────────────────────────────────

/// Traduit une adresse physique en pointeur virtuel pour accéder aux FreeNodes.
/// Utilise la physmap directe (PHYS_MAP_BASE + phys).
///
/// SAFETY: La physmap doit être initialisée avant l'utilisation du buddy.
#[inline(always)]
fn phys_to_virt_buddy(phys: PhysAddr) -> usize {
    use crate::memory::core::layout::PHYS_MAP_BASE;
    PHYS_MAP_BASE.as_usize() + phys.as_usize()
}

/// Traduit un pointeur virtuel (dans la physmap) en adresse physique.
#[inline(always)]
fn virt_to_phys_buddy(virt: usize) -> PhysAddr {
    use crate::memory::core::layout::PHYS_MAP_BASE;
    PhysAddr::new((virt - PHYS_MAP_BASE.as_usize()) as u64)
}

/// Remplit une plage de pages de zéros.
///
/// SAFETY: `phys` doit être l'adresse de `2^order` pages allouées exclusivement
/// par l'appelant. La physmap doit être accessible.
#[inline]
unsafe fn zero_pages(phys: PhysAddr, order: usize) {
    let size = PAGE_SIZE << order;
    // #25 : zero_pages va-t-il écraser Fa (pile VIVANTE d'init) ? Si le frame
    // surveillé est dans la plage zéroée APRÈS l'armement (vfork) → corruption :
    // le buddy a re-remis Fa en circulation pour une alloc ZEROED. La chaîne révèle
    // l'appelant (execve enfant ? FS blob ?).
    #[cfg(target_arch = "x86_64")]
    {
        use core::sync::atomic::Ordering;
        let lo = phys.as_u64();
        let hi = lo + size as u64;
        let mut j = 0usize;
        while j < 24 {
            let initf = DIAG25_INITF[j].load(Ordering::Relaxed);
            if initf != 0 && initf >= lo && initf < hi {
                diag25_report(b"ZEROINIT", Frame::containing(phys), order);
                break;
            }
            j += 1;
        }
    }
    let virt = phys_to_virt_buddy(phys) as *mut u8;
    // SAFETY: Les pages sont allouées et mappées en physmap.
    core::ptr::write_bytes(virt, 0, size);
}
