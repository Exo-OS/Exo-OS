//! Boucle sentinelle ExoPhoenix (Phase 3.5).
//!
//! Contraintes clés:
//! - Détection SMI (S-N2): cycle trop long => compteur SMI++, skip, pas d'escalade.
//! - PT walker itératif strict (S4): aucune récursion.
//! - Liveness nonce Release/Acquire sur SSR (S9).
//! - PMC: contribution positive uniquement (S5), jamais de score négatif.

use core::ptr::read_volatile;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use crate::arch::x86_64::apic::{local_apic, x2apic};
use crate::arch::x86_64::cpu::msr;
use crate::arch::x86_64::time::ktime_get_ns;
use crate::exophoenix::{handoff, ssr, stage0, PhoenixState, PHOENIX_STATE};
use crate::memory::core::{KERNEL_IMAGE_MAX_SIZE, KERNEL_LOAD_PHYS_ADDR, PAGE_SIZE, PHYS_MAP_BASE};
use crate::memory::virt::page_table::{phys_to_table_ref, read_cr3};

const T_DETECTION_US: u64 = 10_000;
const SMI_MULTIPLIER: u64 = 3;
const LIVENESS_TIMEOUT_US: u64 = 200;

const PF_THRESHOLD_HIGH: u32 = 256;

const SCORE_PA_REMAP: u32 = 90;
const SCORE_PF_FLOOD: u32 = 60;
const SCORE_LIVENESS: u32 = 50;
const SCORE_PMC_ANOMALY: u32 = 10;
const THREAT_THRESHOLD: u32 = 100;

const B_REGION_PHYS_BASE: u64 = KERNEL_LOAD_PHYS_ADDR;
// FIX #25 (Audit 6.2) — `KERNEL_IMAGE_MAX_SIZE` (2 GiB) est une borne haute de
// budget de lien, PAS la taille réelle de l'image chargée. L'ancien code
// retournait `true` pour toute adresse physique entre 1 Mio et ~2049 Mio, soit
// la quasi-totalité de la RAM allouée par le buddy. Maintenant on calcule la
// taille réelle via le symbole linker `__kernel_end` (lazy-init dans
// `b_region_phys_end()`). On garde un plafond prudent sur
// `KERNEL_IMAGE_MAX_SIZE` uniquement si `__kernel_end` est absent ou invalide
// (fallback défensif).
static B_REGION_PHYS_END: AtomicU64 = AtomicU64::new(0);

const SSR_CMD_PHYS_START: u64 = ssr::SSR_BASE + ssr::SSR_CMD_B2A as u64;
const SSR_CMD_PHYS_END: u64 = SSR_CMD_PHYS_START + 64;

/// Zone connue côté mémoire A (PULL) pour miroir du nonce SSR.
///
/// Prototype actuel: offset fixe dans l'image kernel A chargée en physique.
const A_LIVENESS_MIRROR_PHYS: u64 =
    KERNEL_LOAD_PHYS_ADDR + exo_phoenix_ssr::A_LIVENESS_MIRROR_OFFSET;

static SMI_COUNTER: AtomicU64 = AtomicU64::new(0);
static THREAT_COUNTER: AtomicU64 = AtomicU64::new(0);
static LIVENESS_FALLBACK_COUNTER: AtomicU64 = AtomicU64::new(1);
static PMC_BASELINE: [AtomicU64; 4] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
static PMC_BASELINE_SET: AtomicBool = AtomicBool::new(false);

/// FIX #25 (Audit 6.2) — Calcule la taille RÉELLE de l'image kernel chargée
/// via le symbole linker `__kernel_end`. Retourne la taille en octets, bornée
/// par `KERNEL_IMAGE_MAX_SIZE` par sécurité (fallback défensif si le symbole
/// est absent ou incohérent).
fn real_kernel_image_size() -> usize {
    // Symbole linker fourni par le linker script kernel.
    extern "C" {
        static __kernel_end: u8;
    }
    // Lecture purement adresse — pas de déréférencement.
    let end_addr = (&raw const __kernel_end) as usize as u64;
    let start_addr = KERNEL_LOAD_PHYS_ADDR;
    if end_addr > start_addr {
        let size = (end_addr - start_addr) as usize;
        // Plafond défensif pour éviter toute régression si le symbole linker
        // venait à mal se résoudre (borne haute de budget de lien).
        if size < KERNEL_IMAGE_MAX_SIZE {
            size
        } else {
            KERNEL_IMAGE_MAX_SIZE
        }
    } else {
        // Fallback : borne haute conservatrice.
        KERNEL_IMAGE_MAX_SIZE
    }
}

/// Retourne `B_REGION_PHYS_END`, en l'initialisant paresseusement à la première
/// invocation via `real_kernel_image_size()`. Once-init simple via CAS.
#[inline(always)]
fn b_region_phys_end() -> u64 {
    let cached = B_REGION_PHYS_END.load(Ordering::Acquire);
    if cached != 0 {
        return cached;
    }
    let computed = KERNEL_LOAD_PHYS_ADDR + real_kernel_image_size() as u64;
    let _ = B_REGION_PHYS_END.compare_exchange(
        0,
        computed,
        Ordering::Release,
        Ordering::Relaxed,
    );
    B_REGION_PHYS_END.load(Ordering::Acquire)
}

#[inline(always)]
fn read_apic_timestamp_ticks() -> u32 {
    match stage0::B_FEATURES.apic_mode() {
        stage0::BootApicMode::X2Apic => {
            // SAFETY: lecture MSR x2APIC du compteur courant.
            unsafe { msr::read_msr(x2apic::X2APIC_TIMER_CCR) as u32 }
        }
        stage0::BootApicMode::XApic => local_apic::timer_current_count(),
    }
}

#[inline(always)]
fn apic_elapsed_us(start_ticks: u32, end_ticks: u32) -> u64 {
    let ticks_per_us = stage0::ticks_per_us();
    if ticks_per_us == 0 {
        return 0;
    }
    let elapsed_ticks = start_ticks.wrapping_sub(end_ticks) as u64;
    elapsed_ticks / ticks_per_us
}

#[inline(always)]
fn is_b_region(pa: u64) -> bool {
    let pool_r3_base = stage0::pool_r3_base_phys();
    let pool_r3_end = pool_r3_base.saturating_add(stage0::pool_r3_alloc_bytes());

    let in_b_region = pa >= B_REGION_PHYS_BASE && pa < b_region_phys_end();
    let in_pool_r3 = pa >= pool_r3_base && pa < pool_r3_end;
    let in_ssr_cmd = pa >= SSR_CMD_PHYS_START && pa < SSR_CMD_PHYS_END;

    in_b_region || in_pool_r3 || in_ssr_cmd
}

fn walk_a_page_tables_iterative() -> u32 {
    let mut score = 0u32;
    let mut pf_count = 0u32;
    let mut steps = 0usize;
    let max_steps = (KERNEL_IMAGE_MAX_SIZE / PAGE_SIZE).saturating_mul(4);

    let pml4_phys = read_cr3();
    // SAFETY: CR3 courant doit pointer sur une PML4 valide en contexte noyau.
    let pml4 = unsafe { phys_to_table_ref(pml4_phys) };

    'walk: for p4i in 0..512 {
        steps = steps.saturating_add(1);
        if steps > max_steps {
            break;
        }

        let l4e = pml4[p4i];
        if !l4e.is_present() {
            pf_count = pf_count.saturating_add(1);
            if pf_count > PF_THRESHOLD_HIGH {
                score = score.saturating_add(SCORE_PF_FLOOD);
                break;
            }
            continue;
        }

        let pdpt_phys = l4e.phys_addr().as_u64();
        if is_b_region(pdpt_phys) {
            score = score.saturating_add(SCORE_PA_REMAP);
        }

        // SAFETY: entrée présente => table niveau 3 attendue.
        let pdpt = unsafe { phys_to_table_ref(l4e.phys_addr()) };
        for p3i in 0..512 {
            steps = steps.saturating_add(1);
            if steps > max_steps {
                break 'walk;
            }

            let l3e = pdpt[p3i];
            if !l3e.is_present() {
                pf_count = pf_count.saturating_add(1);
                if pf_count > PF_THRESHOLD_HIGH {
                    score = score.saturating_add(SCORE_PF_FLOOD);
                    break 'walk;
                }
                continue;
            }

            let pd_phys = l3e.phys_addr().as_u64();
            if is_b_region(pd_phys) {
                score = score.saturating_add(SCORE_PA_REMAP);
            }

            if l3e.is_huge() {
                continue;
            }

            // SAFETY: entrée présente non huge => table niveau 2 attendue.
            let pd = unsafe { phys_to_table_ref(l3e.phys_addr()) };
            for p2i in 0..512 {
                steps = steps.saturating_add(1);
                if steps > max_steps {
                    break 'walk;
                }

                let l2e = pd[p2i];
                if !l2e.is_present() {
                    pf_count = pf_count.saturating_add(1);
                    if pf_count > PF_THRESHOLD_HIGH {
                        score = score.saturating_add(SCORE_PF_FLOOD);
                        break 'walk;
                    }
                    continue;
                }

                let pt_phys = l2e.phys_addr().as_u64();
                if is_b_region(pt_phys) {
                    score = score.saturating_add(SCORE_PA_REMAP);
                }

                if l2e.is_huge() {
                    let huge_base = l2e.phys_addr().as_u64();
                    if is_b_region(huge_base) {
                        score = score.saturating_add(SCORE_PA_REMAP);
                    }
                    continue;
                }

                // SAFETY: entrée présente non huge => table niveau 1 attendue.
                let pt = unsafe { phys_to_table_ref(l2e.phys_addr()) };
                for p1i in 0..512 {
                    steps = steps.saturating_add(1);
                    if steps > max_steps {
                        break 'walk;
                    }

                    let l1e = pt[p1i];
                    if !l1e.is_present() {
                        continue;
                    }

                    let page_phys = l1e.phys_addr().as_u64();
                    if is_b_region(page_phys) {
                        score = score.saturating_add(SCORE_PA_REMAP);
                    }
                }
            }
        }
    }

    score
}

#[inline(always)]
fn generate_liveness_nonce() -> u64 {
    if crate::arch::x86_64::cpu::features::cpu_features_or_none()
        .map_or(false, |features| features.has_rdrand())
    {
        for _ in 0..10 {
            let value: u64;
            let ok: u8;
            // SAFETY: RDRAND en ring0, avec vérification explicite du CF via setc.
            unsafe {
                core::arch::asm!(
                    "rdrand {val}",
                    "setc {ok}",
                    val = out(reg) value,
                    ok = out(reg_byte) ok,
                    options(nostack, nomem),
                );
            }
            if ok != 0 {
                return value;
            }
            core::hint::spin_loop();
        }
    }

    LIVENESS_FALLBACK_COUNTER.fetch_add(1, Ordering::Relaxed)
}

#[inline(always)]
fn read_a_liveness_mirror_pull() -> u64 {
    let mirror_virt = PHYS_MAP_BASE
        .as_u64()
        .saturating_add(A_LIVENESS_MIRROR_PHYS);
    // SAFETY: lecture volatile d'une zone physique connue via physmap (PULL explicite).
    unsafe { read_volatile(mirror_virt as *const u64) }
}

fn check_liveness_nonce() -> u32 {
    let nonce = generate_liveness_nonce();

    // SAFETY: offset SSR valide et mappé ; Release obligatoire sur champ critique.
    unsafe {
        ssr::ssr_atomic(ssr::SSR_LIVENESS_NONCE).store(nonce, Ordering::Release);
    }

    let deadline_ns = ktime_get_ns().saturating_add(LIVENESS_TIMEOUT_US.saturating_mul(1000));
    loop {
        let mirrored = read_a_liveness_mirror_pull();
        if mirrored == nonce {
            return 0;
        }

        if ktime_get_ns() >= deadline_ns {
            return SCORE_LIVENESS;
        }

        core::hint::spin_loop();
    }
}

fn pmc_anomaly_score() -> u32 {
    if !stage0::B_FEATURES.pmc_available() {
        return 0;
    }

    let base = ssr::SSR_BASE as usize + ssr::pmc_snapshot_offset(0);
    let mut ctrs = [0u64; 4];

    // Layout snapshot PMC: [evtsel0, ctr0, evtsel1, ctr1, ...]
    // On ne score que les compteurs CTR (offset +8 dans chaque paire de 16 bytes).
    for i in 0..4usize {
        let ptr = (base + i * 16 + 8) as *const u64;
        // SAFETY: lecture volatile dans SSR slot 0.
        ctrs[i] = unsafe { read_volatile(ptr) };
    }

    if !PMC_BASELINE_SET.load(Ordering::Acquire) {
        for i in 0..4 {
            PMC_BASELINE[i].store(ctrs[i], Ordering::Relaxed);
        }
        PMC_BASELINE_SET.store(true, Ordering::Release);
        return 0;
    }

    const PMC_DELTA_THRESHOLD: u64 = 1_000_000;
    let mut anomalies = 0u32;
    for i in 0..4 {
        let baseline = PMC_BASELINE[i].load(Ordering::Relaxed);
        let delta = ctrs[i].wrapping_sub(baseline);
        if delta > PMC_DELTA_THRESHOLD {
            anomalies = anomalies.saturating_add(1);
        }
        PMC_BASELINE[i].store(ctrs[i], Ordering::Relaxed);
    }

    if anomalies >= 3 {
        SCORE_PMC_ANOMALY
    } else {
        0
    }
}

fn run_introspection_cycle() -> u32 {
    let mut score = 0u32;
    score = score.saturating_add(walk_a_page_tables_iterative());
    score = score.saturating_add(check_liveness_nonce());
    score = score.saturating_add(pmc_anomaly_score());
    score
}

#[inline(always)]
fn wait_until_next_detection_window() {
    let deadline_ns = ktime_get_ns().saturating_add(T_DETECTION_US.saturating_mul(1000));
    while ktime_get_ns() < deadline_ns {
        core::hint::spin_loop();
    }
}

/// Exécute la boucle sentinelle infinie (Phase 3.5).
pub fn run_forever() -> ! {
    loop {
        let cycle_start_ns = ktime_get_ns();
        let apic_t0 = read_apic_timestamp_ticks();

        let score = run_introspection_cycle();

        let apic_t1 = read_apic_timestamp_ticks();
        let mut elapsed_us = apic_elapsed_us(apic_t0, apic_t1);

        // Fallback si APIC ticks indisponibles (ex: tpu=0): conserver la détection SMI.
        if elapsed_us == 0 {
            elapsed_us = ktime_get_ns().wrapping_sub(cycle_start_ns) / 1000;
        }

        // S-N2 : un cycle anormalement long est traité comme SMI firmware probable.
        if elapsed_us > T_DETECTION_US.saturating_mul(SMI_MULTIPLIER) {
            SMI_COUNTER.fetch_add(1, Ordering::Relaxed);
            continue;
        }

        if score >= THREAT_THRESHOLD {
            PHOENIX_STATE.store(PhoenixState::Threat as u8, Ordering::Release);
            let _ = handoff::begin_isolation_soft();
            THREAT_COUNTER.fetch_add(1, Ordering::Relaxed);
        }

        wait_until_next_detection_window();
    }
}

pub fn smi_counter() -> u64 {
    SMI_COUNTER.load(Ordering::Relaxed)
}
