# Task 9b — VERIFICATION of Top Critical Findings

**Auditor:** Sub-agent 9b (general-purpose, sandboxed)
**Method:** Direct code reading for each finding. Verbatim snippets. No reliance on prior audit reports.
**Scope:** 25 findings from C-01/D-01/D-02/D-03/GAP-06/BOOT-001..003/INTEG-001/004/CRYPTO-001/POLICY-001/003/004/005/KERN-016/023/024/029/SHIELD-001..004/CRYPTOSRV-001/002/DRV-001..003/006/POLICY-009/GAP-02.
**Date:** 2026-07

---

## Summary table

| # | Finding ID | Verdict | Severity (revised) |
|---|---|---|---|
| 1 | C-01 / INTEG-002 | **CONFIRMED** | Critical |
| 2 | D-01 / SRV-023 | **PARTIALLY FIXED** | High (down from Critical) |
| 3 | D-02 / SRV-033 | **PARTIALLY FIXED** | High |
| 4 | D-03 / SRV-014 | **CONFIRMED** (one path) | High |
| 5 | GAP-06 / SRV-015 | **CONFIRMED** | High |
| 6 | BOOT-001 | **CONFIRMED** (dead code) | High |
| 7 | BOOT-002 | **REFUTED** (FIXED) | n/a |
| 8 | BOOT-003 | **CONFIRMED** | High |
| 9 | INTEG-001 | **CONFIRMED** | Critical |
| 10 | INTEG-004 | **PARTIALLY CONFIRMED** | Medium |
| 11 | CRYPTO-001 | **FIXED** | Low |
| 12 | POLICY-001 | **CONFIRMED** | Critical |
| 13 | POLICY-003 (CFG) | **CONFIRMED** (dead code) | High |
| 13 | POLICY-004 (CET) | **CONFIRMED** (SS never enabled) | High |
| 13 | POLICY-005 (stack canary) | **PARTIALLY CONFIRMED** | Medium |
| 14 | KERN-016 | **CONFIRMED** | High |
| 15 | KERN-023 | **CONFIRMED** | High |
| 16 | KERN-024 | **CONFIRMED** | High |
| 17 | KERN-029 | **CONFIRMED** (graceful degrade) | Medium |
| 18 | SHIELD-001 | **CONFIRMED** | High |
| 19 | SHIELD-002/003/004 | **PARTIALLY CONFIRMED** | Medium |
| 20 | CRYPTOSRV-001 | **FIXED** | n/a |
| 21 | CRYPTOSRV-002 | **CONFIRMED** | High |
| 22 | DRV-001/002/003 | **CONFIRMED** | Critical |
| 23 | DRV-006 | **CONFIRMED** (spec violation) | Medium |
| 24 | POLICY-009 / A-01 | **FIXED** (different mechanism) | n/a |
| 25 | GAP-02 | **REFUTED** (FIXED) | n/a |

---

## 1. C-01 / INTEG-002 — `do_execve` signature verification

**File read:** `kernel/src/process/lifecycle/exec.rs:212-340`
**Path:** `sys_execve` (legacy, returns ENOSYS) → `dispatch::handle_execve_inplace` (dispatch.rs:826) → `do_execve` (exec.rs:212)

**Verbatim (exec.rs:267-293):**
```rust
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
```

**`is_chain_verified` / `check_chain_of_trust` bodies** (secure_boot.rs:202-209, 245-247):
```rust
pub fn check_chain_of_trust() -> Result<(), SecureBootError> {
    if !CHAIN_VERIFIED.load(Ordering::Acquire) {
        if SECBOOT_ENFORCE.load(Ordering::Relaxed) {
            return Err(SecureBootError::ChainNotVerified);
        }
    }
    Ok(())
}
pub fn is_chain_verified() -> bool {
    CHAIN_VERIFIED.load(Ordering::Acquire)
}
```

`verify_module_signature()` exists at `code_signing.rs:194` but is **never called** from `do_execve` (grep `verify_module_signature` in `process/lifecycle/exec.rs` → 0 matches). The exec path only checks the **global** `CHAIN_VERIFIED` flag (which is never set true — see §9 INTEG-001), not the signature of the **specific binary** being exec'd.

**Verdict: CONFIRMED.** `do_execve` does not call `verify_module_signature()`. The check is reduced to reading a single global atomic flag. Unsigned binaries can be exec'd in dev (default) mode. Strict mode requires a compile-time feature `strict_exec_signatures` and `CHAIN_VERIFIED=true` (never set).
**Severity: CRITICAL (unchanged).**

---

## 2. D-01 / SRV-023 — SOCK_RAW CAP_NET_RAW

**File read:** `servers/network_server/src/socket_table.rs:1-65`, `servers/network_server/src/main.rs:437-461`

**Verbatim (socket_table.rs:14-59):**
```rust
/// PID du résolveur DNS interne — seul service Ring1 autorisé à créer des sockets raw.
/// FIX-SOCK-RAW : liste des PIDs autorisés à SOCK_RAW (équivalent CAP_NET_RAW Linux).
/// En v0.2.0 : seul init_server (PID 1) et network_server lui-même peuvent créer
/// des sockets raw. Tout autre PID reçoit EPERM.
const RAW_SOCKET_ALLOWED_PIDS: &[u32] = &[
    1,  // init_server — supervision réseau
    7,  // network_server lui-même (auto-référence pour ICMP interne)
];
...
    pub fn from_domain_type_privileged(
        domain: u32,
        ty: u32,
        protocol: u32,
        sender_pid: u32,
    ) -> Result<Self, i64> {
        if domain != AF_INET {
            return Err(syscall::EAFNOSUPPORT);
        }
        match ty & SOCK_TYPE_MASK {
            SOCK_STREAM => Ok(Self::Tcp),
            SOCK_DGRAM  => Ok(Self::Udp),
            SOCK_RAW if protocol == 0 || protocol == 1 => {
                if RAW_SOCKET_ALLOWED_PIDS.contains(&sender_pid) {
                    Ok(Self::Raw)
                } else {
                    Err(syscall::EPERM)
                }
            }
```

main.rs:442 confirms the caller passes `msg.sender_pid` (not hardcoded 1).

**Verdict: PARTIALLY FIXED.** SOCK_RAW now requires sender_pid ∈ {1, 7}. Capability (CAP_NET_RAW) is NOT used — it's a hardcoded PID allowlist. Problems remaining:
- Cannot grant CAP_NET_RAW to legitimate future services (e.g. a DHCP relay, tcpdump).
- Any compromise of PID 1 (init) or PID 7 (network_server) gives full raw-socket power.
- PID 1 is broadly trusted for many other ops (memory, scheduler, vfs) — a single compromise is catastrophic.

**Severity: HIGH (down from CRITICAL — capability gate exists but is shallow).**

---

## 3. D-02 / SRV-033 — `attach_shared_region` sender_pid check

**File read:** `servers/memory_server/src/mmap_service.rs:375-411`

**Verbatim:**
```rust
    pub fn attach_shared_region(&mut self, sender_pid: u32, payload: &[u8]) -> MemoryReply {
        let handle = match payload_u64(payload, 0) { ... };
        let Some(idx) = self.region_index(handle) else { ... };
        let region = &mut self.regions[idx];
        if region.kind != RegionKind::Shared { ... }

        // FIX-SHM-ATTACH (Security_Audit_Passe2 §D-02) : ...
        // Règle : attacher est autorisé si :
        //   1. sender_pid == owner_pid (propriétaire attache sa propre région)
        //   2. sender_pid == 1 (init_server, supervision système)
        //   3. share_count > 0 (propriétaire a publié la région via IPC)
        let is_owner     = region.owner_pid == sender_pid;
        let is_init      = sender_pid == 1;
        let is_published = region.share_count > 0;
        if !is_owner && !is_init && !is_published {
            return MemoryReply::error(syscall::EACCES);
        }

        region.share_count = region.share_count.saturating_add(1);
```

**Verdict: PARTIALLY FIXED.** sender_pid is now checked. The check is:
- OK: `owner == sender`
- OK: `sender == 1` (init_server can attach anything — broad trust)
- WEAK: `share_count > 0` means once a region has been published ONCE (to any party), ANY process knowing the u64 handle can attach. No per-target ACL.

The handle is a 64-bit value; if leaked (e.g. via uninitialized memory, log, or side-channel), any process can attach a "published" region. Init_server override gives PID 1 universal SHM access.

**Severity: HIGH (down from CRITICAL — partial fix in place, residual risk via share_count).**

---

## 4. D-03 / SRV-014 — SCHED_REALTIME capability

**File read:** `servers/scheduler_server/src/realtime_admit.rs:1-147`, `servers/scheduler_server/src/main.rs:170-202` and `main.rs:340-372`

**Verbatim — Path A (`set_class`, main.rs:178-202):**
```rust
        if matches!(class, SchedulingClass::Realtime | SchedulingClass::Deadline) {
            // FIX-SCHED-RT (Security_Application_Audit §GAP-05 + Passe2 §D-03) : ...
            // Règle : seuls sont autorisés à demander Realtime/Deadline :
            //   PID 1  (init_server — démarre les serveurs critiques en RT)
            //   PID 8  (scheduler_server lui-même — auto-configuration)
            //   PID == owner_pid == sender_pid ET sender_pid <= 10
            const RT_ALLOWED_PIDS: &[u32] = &[1, 8];
            let is_rt_privileged = RT_ALLOWED_PIDS.contains(&sender_pid)
                || (sender_pid == owner_pid && sender_pid <= 10);
            if !is_rt_privileged {
                return SchedulerReply::error(exo_syscall_abi::EPERM);
            }
            if let Err(err) = self.realtime.admit(tid, runtime_us, period_us) { ... }
        }
```

**Verbatim — Path B (`handle_realtime_admit`, main.rs:340-372):**
```rust
    fn handle_realtime_admit(&mut self, sender_pid: u32, payload: &[u8]) -> SchedulerReply {
        let tid = match read_u32(payload, 0) {
            Ok(0) => sender_pid,
            Ok(value) => value,
            Err(err) => return SchedulerReply::error(err),
        };
        let runtime_us = match read_u32(payload, 4) { ... };
        let period_us = match read_u32(payload, 8) { ... };
        let owner_pid = match self.threads.owner_pid(tid) {
            Some(pid) if pid == sender_pid => pid,
            Some(_) => return SchedulerReply::error(exo_syscall_abi::EPERM),
            None => return SchedulerReply::error(exo_syscall_abi::ENOENT),
        };

        match self.realtime.admit(tid, runtime_us, period_us) { ... }
    }
```

**Verdict: CONFIRMED for Path B.** The dispatch table routes `SCHED_MSG_REALTIME_ADMIT` directly to `handle_realtime_admit` (main.rs:431-432), which has **NO capability check** beyond `owner_pid == sender_pid`. Any process can call this on its own TID (`tid=0` defaults to `sender_pid`) and become SCHED_REALTIME — DoS by CPU starvation (utilization limit 95% may block but is per-call). Path A has a PID allowlist, but Path B bypasses it.

**Severity: HIGH (unchanged).**

---

## 5. GAP-06 / SRV-015 — VFS CapToken

**File read:** `servers/vfs_server/src/main.rs:310-372` (open), `:484-558` (read/write), `:755-803` (request dispatch)

**Verbatim (handle_open, main.rs:310-372):**
```rust
fn handle_open(payload: &[u8]) -> VfsReply {
    // NOTE: pas de sender_pid argument !
    let (flags, path_payload) = match ops::open_payload_parts(payload) { ... };
    let mut path = [0u8; ops::PATH_PAYLOAD_MAX + 1];
    let path_len = match ops::path_payload_to_cstr(path_payload, &mut path) { ... };
    let rights = ops::exofs_rights_for_open(flags);
    let fd = unsafe { syscall::exofs_open_by_path_raw(path.as_ptr() as u64, flags, 0, rights) };
    if fd < 0 { ... } else {
        ...
        VfsReply { status: 0, blob_id, fd, _pad: [0; 40] }
    }
}
```

**Verbatim (check_vfs_write_access, main.rs:759-762):**
```rust
fn check_vfs_write_access(sender_pid: u32) -> bool {
    const WRITE_ALLOWED: &[u32] = &[1, 3];
    WRITE_ALLOWED.contains(&sender_pid) || sender_pid >= 10
}
```

`grep` for `CapToken|cap_check|exo_cap|capability|CAP_` in vfs_server/src/main.rs → **0 matches**.

**Verdict: CONFIRMED.** No capability token is verified anywhere in VFS. `handle_open` doesn't even take `sender_pid`. Permissions come from user-supplied POSIX `flags` (O_RDONLY/O_WRONLY/etc.). Write access is gated only by a coarse PID allowlist (`{1,3}` or `pid >= 10`). Any Ring1/Ring3 process can read ANY file via VFS. Mount/umount check only `sender_pid == 1`.

**Severity: HIGH (unchanged).**

---

## 6. BOOT-001 — `isolate_kernel_a_memory()` callers

**File read:** `kernel/src/exophoenix/isolate.rs:231-243`

**Verbatim:**
```rust
/// Applique la cage mémoire complète sur Kernel A.
/// Appelé par handoff.rs après confirmation des ACK freeze et drain IOMMU.
/// Ordre strict — ne pas modifier.
pub fn isolate_kernel_a_memory() {
    // 1. Marquer pages de A !PRESENT
    mark_a_pages_not_present();
    // 2. TLB shootdown sur tous les cores de A (S8)
    tlb_shootdown_all_a_cores();
    // 3. Hard revoke IOMMU + IOTLB flush (S-N1)
    iommu_hard_revoke_and_flush();
    // 4. Override IDT de A
    override_a_idt_with_b_handlers();
}
```

`grep -rn "isolate_kernel_a_memory" /home/z/my-project/audit --include="*.rs"` → only the definition line; no callers in `.rs` files (only docs in `docs/FIX/...`).

**handoff.rs** (the file the doc claims calls it) `begin_isolation_soft()` (line 511) and `begin_isolation_hard()` (line 545) call `stage_soft_revoke_iommu`, `stage_hard_revoke_iommu`, `try_forge_reconstruct_with_policy` — never `isolate_kernel_a_memory`.

**Verdict: CONFIRMED.** Function is fully defined (4 real steps) but is **dead code** — no caller. The Phoenix handoff path does NOT mark Kernel A pages `!PRESENT`, does NOT override A's IDT. Kernel A keeps full access to its memory during "isolation". (The Kimi-AI doc note about "empty body" is REFUTED — the body is real; what's missing is the call site.)

**Severity: HIGH (Kernel A is not actually isolated during Phoenix handoff).**

---

## 7. BOOT-002 — `stage0_init()` callers

**File read:** `kernel/src/lib.rs:270-286`, `kernel/src/exophoenix/stage0.rs:1013-1160`

**Verbatim (lib.rs:270-286):**
```rust
    // ── Phase 5b : ExoPhoenix Stage0 (domaine IOMMU de blocage) ─────────────
    // FIX-STAGE0 (rapport_analyse_kernel_exo_os.md §4.1) :
    // stage0_init_all_steps() n'était jamais appelé, laissant
    // IOMMU_BLOCKED_DOMAIN_ID = 0 (domaine identité VT-d par défaut).
    ...
    let _stage0_summary = crate::exophoenix::stage0::stage0_init_all_steps(true);
    kdb(b'S'); // Stage0 ExoPhoenix done
    crate::arch::x86_64::boot_display::stage_ok("STAGE0");
```

**Verdict: REFUTED (FIXED).** `stage0_init_all_steps(true)` IS called from `kernel_init()` (lib.rs:284). The argument `kernel_a_boot=true` skips Kernel-B-only steps (B-stack/TSS/IDT/timer). Stage0 summary is discarded (`let _stage0_summary = ...`) — errors within `stage0_init_all_steps` set `PHOENIX_STATE=Degraded` but the boot continues; this is intentional per FIX-BOOT-STAGE0-HANG comments.

**Severity: n/a — finding is obsolete.**

---

## 8. BOOT-003 — `SECURE_BOOT_ACTIVE` read by kernel?

**File read:** `exo-boot/src/main.rs:180-189`, `kernel/src/arch/x86_64/boot/memory_map.rs:660-684`

**Verbatim — exo-boot (sets the bit):**
```rust
    boot_info_ref.boot_flags = {
        use kernel_loader::handoff::boot_flags::*;
        let mut flags = UEFI_BOOT;
        if cfg.kaslr_enabled                       { flags |= KASLR_ENABLED; }
        if cfg.secure_boot_required                { flags |= SECURE_BOOT_ACTIVE; }
        if boot_info_ref.framebuffer.is_present()  { flags |= FRAMEBUFFER_PRESENT; }
        if boot_info_ref.acpi_rsdp != 0            { flags |= ACPI2_PRESENT; }
        flags
    };
```

**Verbatim — kernel's view of ExoBootInfo (memory_map.rs:669-684):**
```rust
#[repr(C, align(4096))]
struct ExoBootInfo {
    magic: u64,                          // offset   0
    version: u32,                        // offset   8
    memory_region_count: u32,            // offset  12
    memory_regions: [ExoMemRegion; 256], // offset 16, 256 × 24 = 6144 bytes
    // FramebufferInfo (40 bytes, offset 6160)
    fb_phys_addr: u64,  // offset 6160
    fb_width: u32,      // offset 6168
    fb_height: u32,     // offset 6172
    fb_stride: u32,     // offset 6176
    fb_bpp: u32,        // offset 6180
    fb_format: u32,     // offset 6184 (PixelFormat repr u32)
    _fb_pad: u32,       // offset 6188 (align u64)
    fb_size_bytes: u64, // offset 6192
    acpi_rsdp: u64,     // offset 6200
}
```

`grep` for `boot_flags|BootFlags|SECURE_BOOT_ACTIVE|secure_boot_active` in `kernel/src/` → **0 matches**.

**Verdict: CONFIRMED.** The kernel's `ExoBootInfo` mirror struct does NOT include `boot_flags`. The `SECURE_BOOT_ACTIVE` bit set by exo-boot is **never read** by the kernel. Kernel-side secure boot enforcement (`SECBOOT_ENFORCE` in `integrity_check/secure_boot.rs:126`) is initialized to `true` but `CHAIN_VERIFIED` stays `false` (see §9). Result: kernel never learns from firmware whether Secure Boot was actually active.

**Severity: HIGH (silent loss of trust anchor).**

---

## 9. INTEG-001 — `verify_boot_attestation()` callers

**File read:** `kernel/src/security/integrity_check/secure_boot.rs:174-197`, `kernel/src/security/mod.rs:322-430`

**Verbatim (secure_boot.rs:174-197):**
```rust
pub fn verify_boot_attestation(attestation: &BootAttestation) -> Result<(), SecureBootError> {
    // (body checks signature, hashes, extends PCR)
    ...
    CHAIN_VERIFIED.store(true, Ordering::Release);
    Ok(())
}
```

`grep -rn "verify_boot_attestation(" /home/z/my-project/audit/kernel/src` → **only the definition line**. `security_init()` (mod.rs:322-430) calls `integrity_init()`, `capability::init_capability_subsystem()`, `crypto_init()`, `mitigations_init()`, `audit_init()`, `access_control::init()`, `exoledger::exo_ledger_init()`, `exokairos::init_kernel_secret()`, `exoargos_init()`, `exonmi_init()`, `exoseal_boot_complete()` — **never** `verify_boot_attestation()`.

`grep -rn "CHAIN_VERIFIED.store" kernel/src` → only inside `verify_boot_attestation` (line 195). So `CHAIN_VERIFIED` is **never set to true** at runtime. `is_chain_verified()` always returns `false`. `check_chain_of_trust()` returns `Ok(())` because `SECBOOT_ENFORCE` is bypassed by the early return when `CHAIN_VERIFIED == false`.

**Verdict: CONFIRMED.** The entire boot-attestation chain is **dead code**. This compounds with C-01 (§1): the `do_execve` check `if is_chain_verified()` always evaluates `false`, so the inner `check_chain_of_trust()` is never executed. Unsigned binaries always run.

**Severity: CRITICAL (entire secure boot chain is no-op).**

---

## 10. INTEG-004 — `get_kernel_secret()` uninitialized fallback

**File read:** `kernel/src/security/exokairos.rs:693-719`

**Verbatim:**
```rust
static KERNEL_SECRET: Once<[u8; 32]> = Once::new();

pub fn init_kernel_secret(secret: &[u8; 32]) {
    let _guard = unsafe { exoveil::scoped_domain_access(PksDomain::Credentials, PksPermission::ReadWrite) };
    KERNEL_SECRET.call_once(|| *secret);
}

fn get_kernel_secret() -> [u8; 32] {
    let _guard = unsafe { exoveil::scoped_domain_access(PksDomain::Credentials, PksPermission::ReadOnly) };
    KERNEL_SECRET.get().copied().unwrap_or([0u8; 32])
}
```

`security_init()` calls `exokairos::init_kernel_secret(&secret)` at mod.rs:395 (always — fallback uses `blake3_hash` if `rng_fill` fails, so secret is always set to a non-zero value at boot).

**Verdict: PARTIALLY CONFIRMED.** The `unwrap_or([0u8; 32])` is a real footgun — if `get_kernel_secret()` were called before `security_init()` step 10, ALL ExoKairos deadline MACs would be HMAC-Blake3 with a known all-zero key. In practice `security_init()` runs before any userspace, so the issue is dormant. The risk materializes only if (a) a future caller invokes `get_kernel_secret()` during very early boot, or (b) `init_kernel_secret` is removed from `security_init` by accident.

**Severity: MEDIUM (latent — fixed in practice, fragile by design).** Recommend: panic instead of `unwrap_or([0u8;32])`, or assert `KERNEL_SECRET.get().is_some()`.

---

## 11. CRYPTO-001 — X25519 weak-order subgroup check

**File read:** `kernel/src/security/crypto/x25519.rs:84-101`

**Verbatim:**
```rust
pub fn x25519_diffie_hellman(
    our_private: &[u8; 32],
    their_public: &[u8; 32],
) -> Result<[u8; 32], X25519Error> {
    let secret = StaticSecret::from(*our_private);
    let their_pk = PublicKey::from(*their_public);

    let dh_result = secret.diffie_hellman(&their_pk);
    let shared = dh_result.to_bytes();

    // Vérification contre low-order points (all-zeros = point neutre)
    let is_zero = shared.iter().fold(0u8, |acc, &b| acc | b);
    if is_zero == 0 {
        return Err(X25519Error::InvalidDhResult);
    }

    Ok(shared)
}
```

Tests at line 132-140 confirm the `[0u8; 32]` low-order point is rejected. `x25519-dalek` performs clamping per RFC 7748 §5.

**Verdict: FIXED.** RFC 7748 §6 specifies that clients MAY either reject the all-zero output OR check against the 11 known bad public keys. The all-zero check implemented here is the standard compliant approach. No further action needed.

**Severity: LOW (was Medium — fully fixed).**

---

## 12. POLICY-001 — `sys_exo_ipc_publish` capability check for service-class claim

**File read:** `kernel/src/syscall/table.rs:3100-3160`

**Verbatim (sys_exo_ipc_create, table.rs:3101-3159):**
```rust
pub fn sys_exo_ipc_create(
    name_ptr: u64, name_len: u64, endpoint: u64, _a4: u64, _a5: u64, _a6: u64,
) -> i64 {
    stat_inc(SYS_EXO_IPC_CREATE);
    let len = name_len as usize;
    if len == 0 || len > 128 { return EINVAL; }
    let caller_pid = crate::syscall::fast_path::syscall_current_pid();
    if caller_pid == 0 { return EACCES; }
    let ep = match EndpointId::new(endpoint) { ... };
    ...
    let mut name = match zeroed_user_vec(len) { ... };
    if copy_from_user(name.as_mut_ptr(), name_ptr as *const u8, len).is_err() { return EFAULT; }

    let replaced_dead_owner = match reserve_ipc_endpoint_owner(endpoint, caller_pid) { ... };
    ...
    if crate::ipc::channel::raw::mailbox_open(ep) {
        if let Err(err) = crate::ipc::endpoint::register_endpoint(&name, ep) { ... }
        if let Some(class) = service_class_for_endpoint_name(&name) {
            let _ = crate::security::register_service_class(Pid(caller_pid), class);
        }
        ...
    }
}
```

`reserve_ipc_endpoint_owner` (table.rs:2821-2863) only checks that the high 32 bits of `endpoint` either equal 0 or equal `caller_pid` (line 2826-2829). The caller controls `endpoint` and can simply pass `endpoint=0` (or with high 32 bits = caller_pid) to bypass this. No capability check on the *class* being claimed (CryptoServer, ExoShield, etc.).

**Verdict: CONFIRMED.** Any Ring3 process can call `sys_exo_ipc_create` with `name="crypto_server"`, get registered as `ServiceClass::CryptoServer`, and start receiving IPC traffic intended for the crypto server (intercepting key-derivation / signature requests). This is a critical privilege-escalation primitive — IPC DAG policy at `security/ipc_policy.rs` consults `ServiceClass` to authorize edges, so a fake CryptoServer can both receive victim traffic and emit traffic as a trusted Ring1 identity.

**Severity: CRITICAL (unchanged).**

---

## 13. POLICY-003/004/005 — Exploit mitigations wiring

### 13a. POLICY-003 — CFG

**File read:** `kernel/src/security/exploit_mitigations/cfg.rs:120-180`

**Verbatim (cfg_validate_indirect_call, cfg.rs:169-179):**
```rust
pub fn cfg_validate_indirect_call(target: u64) -> Result<(), CfgError> {
    CFG_CHECKS.fetch_add(1, Ordering::Relaxed);
    let valid = CFG_TABLE.lock().is_valid(target);
    if valid {
        Ok(())
    } else {
        CFG_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
        Err(CfgError::InvalidTarget(target))
    }
}
```

`grep -rn "cfg_validate_indirect_call|cfg_assert_indirect_call|cfg_lock\(" kernel/src` → only definitions in cfg.rs and re-exports in mod.rs. **Zero call sites.**

**Verdict: CONFIRMED.** CFG bitmap infrastructure exists but is **dead code** — no indirect call is ever validated, the table is never locked. CFG provides zero runtime protection.

### 13b. POLICY-004 — CET Shadow Stack

**File read:** `kernel/src/security/exploit_mitigations/cet.rs:104-156`, `mod.rs:62-77`

**Verbatim (mod.rs:62-77):**
```rust
    // 4. CET — activer si supporté matériellement
    let (ss_ok, ibt_ok) = cet_is_supported();
    let cet_active = ss_ok;
    if ss_ok {
        // L'adresse du Shadow Stack est allouée par le memory manager
        // avant cet appel (passée via boot protocol) ; ici on ne l'active
        // pas directement pour ne pas dépendre du memory manager à ce stade.
        // L'activation effective se fait dans arch_init() après alloc.
        let _ = ss_ok; // marqué comme géré
    }
    if ibt_ok {
        // SAFETY: enable_ibt() vérifie le support CET avant d'écrire MSR_IA32_S_CET.
        unsafe {
            let _ = enable_ibt();
        }
    }
```

`grep -rn "enable_shadow_stack" kernel/src` → only definition (cet.rs:111) and re-export (mod.rs:34). **Zero call sites.** Comment says "L'activation effective se fait dans arch_init()" — but `arch_init` does NOT call it either.

**Verdict: CONFIRMED.** `enable_shadow_stack()` is **never called**. Only `enable_ibt()` is wired (and only if CPU supports IBT). CET Shadow Stack protection is no-op.

### 13c. POLICY-005 — Stack canary

**File read:** `kernel/src/security/exploit_mitigations/stack_protector.rs:28-193`, `kernel/src/process/core/tcb.rs:110-348`

**Verbatim (stack_protector.rs:28-38, 185-193):**
```rust
#[no_mangle]
pub static __stack_chk_guard: AtomicU64 = AtomicU64::new(0);

#[no_mangle]
pub extern "C" fn __stack_chk_fail() -> ! {
    CANARY_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    panic!("STACK PROTECTOR: stack smashing detected — kernel halted");
}

pub fn stack_protector_init() {
    let global_canary = loop {
        let v = rng_u64().unwrap_or(0);
        if v != 0 { break v; }
    };
    __stack_chk_guard.store(global_canary, Ordering::SeqCst);
}
```

**Verbatim (tcb.rs:115-116, 337-341):**
```rust
/// Canari de stack pour détecter les débordements.
const STACK_CANARY: u64 = 0xDEAD_BEEF_CAFE_BABE;
...
    /// Vérifie le canari — retourne false si débordement détecté.
    pub fn check_canary(&self) -> bool {
        unsafe { core::ptr::read(self.base as *const u64) == STACK_CANARY }
    }
```

**Verdict: PARTIALLY CONFIRMED.**
- Compiler-level `__stack_chk_guard` is **FIXED** (random via `rng_u64()` at `stack_protector_init()`).
- Kernel-stack per-thread canary at `tcb.rs:116` is **STILL CONSTANT** `0xDEAD_BEEF_CAFE_BABE`. Every kernel stack starts with this magic value; `KernelStack::check_canary()` (tcb.rs:338) compares against the constant. Attacker knows the value ahead of time — overflow detection is bypassable by writing `0xDEAD_BEEF_CAFE_BABE` at the bottom of the corrupted stack.

**Severity: MEDIUM (compiler canary fixed; per-thread kernel stack canary still predictable).**

---

## 14. KERN-016 — `shm_map` capability check

**File read:** `kernel/src/ipc/shared_memory/mapping.rs:253-380`

**Verbatim (shm_map, mapping.rs:253-300):**
```rust
pub fn shm_map(
    desc_idx: usize,
    pid: ProcessId,
    hint_virt: VirtAddr,
    requested_perms: ShmPermissions,
) -> Result<ShmMapResult, IpcError> {
    #[cfg(not(feature = "dev_no_vmm"))]
    if !vmm_hooks_ready() {
        return Err(IpcError::MappingFailed);
    }

    // Vérifier que la région existe et est active
    let (n_pages, region_perms, size_bytes) = {
        let dir = SHM_DESC_DIR.lock();
        let desc = unsafe { dir.get(desc_idx) }.ok_or(IpcError::InvalidHandle)?;
        if !desc.is_active() {
            return Err(IpcError::InvalidHandle);
        }
        // Calculer les permissions effectives (intersection)
        let rp = ShmPermissions(requested_perms.0 & desc.permissions);
        let n = desc.page_count();
        let sz = desc.size_bytes;
        desc.add_mapping();
        (n, rp, sz)
    };

    // Vérifier que les permissions demandées sont accordées
    if requested_perms.can_write() && !region_perms.can_write() {
        ...
        return Err(IpcError::PermissionDenied);
    }
    ...
}
```

`grep -rn "CapToken|cap_check|check_token_owner" kernel/src/ipc/shared_memory/mapping.rs` → **0 matches**.

**Verdict: CONFIRMED.** `shm_map` only checks:
1. Region exists and is active
2. Requested perms ⊆ region perms (intersection)
3. Write requires region_perms.can_write()

There is **no capability check**. The `pid` parameter is only used for tracking (whose AS to map into) and the `requested_perms` is supplied by the caller themselves — the "intersection" is meaningless because the caller controls both inputs. Anyone with the `desc_idx` integer can map the region.

**Severity: HIGH (unchanged).**

---

## 15. KERN-023 — `sys_arch_prctl(ARCH_SET_FS, ...)` user-address validation

**File read:** `kernel/src/syscall/handlers/misc.rs:153-198`

**Verbatim:**
```rust
pub fn sys_arch_prctl(code: u64, addr: u64, _a3: u64, _a4: u64, _a5: u64, _a6: u64) -> i64 {
    const ARCH_SET_GS: u64 = 0x1001;
    const ARCH_SET_FS: u64 = 0x1002;
    const ARCH_GET_FS: u64 = 0x1003;
    const ARCH_GET_GS: u64 = 0x1004;
    match code {
        ARCH_SET_FS => {
            // Écrire IA32_FS_BASE MSR — initialise le TLS Ring3.
            unsafe {
                core::arch::x86_64::_mm_mfence();
                core::arch::asm!(
                    "wrmsr",
                    in("ecx") 0xC000_0100u32,
                    in("eax") (addr & 0xFFFF_FFFF) as u32,
                    in("edx") (addr >> 32) as u32,
                    options(nomem, nostack),
                );
            }
            0
        }
        ARCH_SET_GS => { /* similar, no validation */ }
        ARCH_GET_FS | ARCH_GET_GS => {
            if addr == 0 || addr >= USER_ADDR_MAX {
                return EFAULT;
            }
            ENOSYS
        }
        _ => EINVAL,
    }
}
```

**Verdict: CONFIRMED.** `ARCH_SET_FS` and `ARCH_SET_GS` write the MSR with `addr` directly, **no validation** that `addr < USER_ADDR_MAX`. Only `ARCH_GET_FS`/`ARCH_GET_GS` validate. An attacker can set FS_BASE (or GS_BASE — note: not kernel_GS_BASE, the user one) to a kernel address, then use `%fs:`-relative memory access from userspace to potentially read kernel memory through aliased mappings (subject to SMEP/SMAP, but KPTI bypass or similar could leverage this). At minimum, this enables setting up a fake TLS at an arbitrary address.

**Severity: HIGH.**

---

## 16. KERN-024 — `sys_kill` CAP_KILL / same-UID check

**File read:** `kernel/src/syscall/handlers/signal.rs:231-275`, `kernel/src/process/signal/delivery.rs:62-97`

**Verbatim (sys_kill, signal.rs:231-275):**
```rust
pub fn sys_kill(pid: u64, signum: u64, _a3: u64, _a4: u64, _a5: u64, _a6: u64) -> i64 {
    use crate::process::signal::delivery::{send_signal_number_to_pid, SendError};
    let signed_pid = pid as i64;
    if signed_pid > i32::MAX as i64 || signed_pid < i32::MIN as i64 { return ESRCH; }
    let target_pid = signed_pid as i32;
    let real_pid: u32 = if target_pid <= 0 {
        if target_pid == 0 {
            unsafe { /* gs:[0x20] → tcb → pid */ }
        } else { return ESRCH; }
    } else { target_pid as u32 };

    if signum == 0 {
        let found = PROCESS_REGISTRY.find_by_pid(Pid(real_pid)).is_some();
        return if found { 0 } else { ESRCH };
    }
    let sig = match validate_signal(signum) { ... };

    match send_signal_number_to_pid(Pid(real_pid), sig as u8) {
        Ok(()) => 0,
        Err(SendError::PermissionDenied) => EPERM,
        Err(_) => ESRCH,
    }
}
```

**Verbatim (send_signal_number_to_pid, delivery.rs:62-97):** see code in main reading above — only validates `sig_n` range and PCB existence. **No CAP_KILL or same-UID check.** The `SendError::PermissionDenied` variant is never returned by this function.

`grep -rn "CAP_KILL|same.*uid|euid.*uid" kernel/src/process/signal kernel/src/syscall/handlers/signal.rs` → **0 matches**.

**Verdict: CONFIRMED.** Any Ring3 process can send ANY signal (including SIGKILL, SIGSTOP) to ANY other process — including PID 1 (init_server), which would halt the system. No CAP_KILL check, no UID match.

**Severity: HIGH (denial of service / process-killing primitive for any unprivileged process).**

---

## 17. KERN-029 — `alloc_fpu_state` failure handling

**File read:** `kernel/src/scheduler/fpu/lazy.rs:115-135`, `kernel/src/scheduler/fpu/save_restore.rs:58-114, 138-168`

**Verbatim (handle_nm_exception, lazy.rs:115-135):**
```rust
pub unsafe fn handle_nm_exception(tcb: &mut ThreadControlBlock) {
    cr0_clear_ts();

    // BUG-FIX M : allouer FpuState avant la première utilisation FPU.
    ...
    if tcb.fpu_state_ptr == 0 {
        super::save_restore::alloc_fpu_state(tcb);
        // Si l'allocation échoue (IN_RECLAIM ou OOM), fpu_state_ptr reste NULL.
        // xrstor_for() gérera ce cas : init par défaut, FPU_LOADED = true, mais
        // l'état sera perdu au prochain switch (dégradation gracieuse).
    }
    super::save_restore::xrstor_for(tcb);
}
```

**Verbatim (xrstor_for, save_restore.rs:95-114):**
```rust
pub unsafe fn xrstor_for(tcb: &mut ThreadControlBlock) {
    let state_ptr = tcb.fpu_state_ptr as *mut FpuState;
    if state_ptr.is_null() {
        init_fpu_registers();
        tcb.set_fpu_loaded(true);
        return;
    }
    ...
}
```

**Verbatim (xsave_current, save_restore.rs:58-85):**
```rust
pub unsafe fn xsave_current(tcb: &mut ThreadControlBlock) {
    let state_ptr = tcb.fpu_state_ptr as *mut FpuState;
    if state_ptr.is_null() {
        // FpuState pas encore allouée — rien à sauvegarder.
        ...
        tcb.set_fpu_loaded(false);
        return;
    }
    ... // actual xsave
}
```

**Verdict: CONFIRMED (graceful degradation but silent).** If `alloc_fpu_state` fails:
- `xrstor_for` initializes FPU to defaults → thread runs FP code with default state.
- On context switch, `xsave_current` sees `state_ptr == NULL`, sets `fpu_loaded=false`, returns WITHOUT saving → **thread's FPU state is silently lost**.
- No log, no error to userspace, no SIGBUS/SIGFPE.

This causes silent data corruption in FP/SIMD computation (cryptography, vectorized math). The comment acknowledges this as "dégradation gracieuse" but in security-sensitive contexts (kernel crypto using SSE/AVX2) silent corruption is unacceptable.

**Severity: MEDIUM (silent correctness failure, may impact crypto RNG or BLAKE3 vectorized paths under memory pressure).**

---

## 18. SHIELD-001 — `PhoenixSafe` implementation in `exo_shield/`

**Search:** `grep -rn "PhoenixSafe|phoenix_safe|on_pre_switch|on_post_switch" /home/z/my-project/audit/servers/exo_shield/` → **0 matches.**

`grep -rn "PhoenixSafe" /home/z/my-project/audit --include="*.rs"`:
- `servers/init_server/src/boot_info.rs:99` — `impl PhoenixSafe for BootInfo` (one of two known implementations).
- `tools/semgrep-rules/exoos.yaml:73` — semgrep rule (not code).
- No matches in `servers/exo_shield/`.

**Verdict: CONFIRMED.** `exo_shield` does NOT implement `PhoenixSafe`. Per `SPEC-EXOSHIELD-STRATA.md` §6 and `VISION-STRATA.md` §129, ExoShield must implement `on_pre_switch()` (flush alerts, snapshot profiles, suspend hooks) and `on_post_switch()` (re-scan post-switch) for ExoPhoenix handoff. None of this exists. A Phoenix A↔B switch would lose ExoShield state (alert queues, behavioral baselines, sandbox state) with no callback.

**Severity: HIGH (ExoPhoenix recovery is incomplete — EDR state is lost on kernel switch).**

---

## 19. SHIELD-002/003/004 — behavioral/network/signatures wiring

**File read:** `servers/exo_shield/src/main.rs:33, 435-535, 687-728, 1505-1531`, `servers/exo_shield/src/signatures/mod.rs`, `servers/exo_shield/src/engine/scanner.rs:620-720`

**Verbatim (main.rs:1505-1531 — module init):**
```rust
    engine::engine_init();
    boot_log(b"exo_shield: engine ready\n");
    signatures::database::database_init();
    boot_log(b"exo_shield: signature database ready\n");
    signatures::yara::yara_init();
    boot_log(b"exo_shield: yara ready\n");
    signatures::update::update_init();
    boot_log(b"exo_shield: signature update ready\n");
    boot_log(b"exo_shield: signatures ready\n");
    behavioral::behavioral_init();
    boot_log(b"exo_shield: behavioral ready\n");
    hooks::exec_hooks_init();
    hooks::net_hooks_init();
    hooks::mem_hooks_init();
    hooks::syscall_hooks_init();
    boot_log(b"exo_shield: hooks ready\n");
    sandbox::sandbox_init();
    network::firewall_init();
    forensics::memory_dump_init();
    forensics::timeline_init();
    forensics::report_init();
    boot_log(b"exo_shield: containment ready\n");
    ml::ensemble_init(0xE505_C117);
```

**Verbatim (main.rs:447-495 — network event dispatch):**
```rust
        engine::EventType::Network => {
            let (src_ip, dst_ip, src_port, dst_port, protocol, byte_count) =
                decode_network_tuple(event);
            let pid_blocked = network::is_pid_blocked(event.pid);
            let hook_blocked =
                hooks::pre_connect_check(event.pid, src_ip, dst_ip, src_port, dst_port, protocol);
            if !pid_blocked && !hook_blocked {
                hooks::post_connect_monitor(...);
            }
            ...
            if let Some(count) = hooks::detect_port_scan(src_ip) { ... }
            if let Some(total) = hooks::detect_exfiltration(event.pid) { ... }
        }
```

**Engine scanner (scanner.rs:652-680) uses its own `SIG_DB` static array, NOT `signatures::database` or `signatures::matcher`:**
```rust
    // Phase 1: Signature matching
    if run_signature_phase {
        let db = SIG_DB.lock();
        for i in 0..MAX_SIGNATURES {
            let sig = &db.entries[i];
            ...
            let matches = match_pattern(scan_data, &sig.pattern[..pat_len]);
            ...
        }
    }
```

`grep -rn "matcher::scan_buffer|matcher::scan_with_signature|signatures::matcher::scan|yara::scan|yara::match|yara::rules" servers/exo_shield/src` → **0 matches**.

**Verdict: PARTIALLY CONFIRMED.**
- ✅ behavioral IS wired: `behavioral::behavioral_init()` called; events dispatched via `engine::submit_event` and `process_security_hooks` (which uses hooks::*).
- ✅ network IS wired: `network::is_pid_blocked`, `hooks::pre_connect_check`, `hooks::detect_port_scan`, `hooks::detect_exfiltration` all called from main.rs.
- ❌ signatures::matcher and signatures::yara matching functions are **dead code**. The engine uses its own built-in `match_pattern` over its own `SIG_DB`. The dedicated YARA rule engine (`signatures::yara`) and fuzzy/wildcard matcher (`signatures::matcher::scan_buffer`, `match_wildcard`, `fuzzy_score`, `match_threshold`) are initialized but never called.
- `signatures::database::database_init()` populates a separate DB that no scanner reads.

**Severity: MEDIUM (engine has *some* signature scanning, but the sophisticated YARA + fuzzy matcher is dead — false sense of defense-in-depth).**

---

## 20. CRYPTOSRV-001 — `PHOENIX_WAKE_ENTROPY` capability gate

**File read:** `servers/crypto_server/src/main.rs:50, 371-395, 555-575, 920-932`

**Verbatim (main.rs:563-574):**
```rust
    let caller_principal = if req.msg_type == PHOENIX_WAKE_ENTROPY {
        0
    } else {
        match authorize_request(req) {
            Ok(principal) => principal,
            Err(status) => {
                reply.status = status;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            }
        }
    };
```

**Verbatim (main.rs:920-932):**
```rust
        PHOENIX_WAKE_ENTROPY => {
            let authenticated_kernel_wake =
                req.sender_pid == 0 || (req.reply_endpoint & KERNEL_EPHEMERAL_REPLY_BIT) != 0;
            if !authenticated_kernel_wake {
                reply.status = CRYPTO_ERR_CAP;
            } else if let Some(entropy) = phoenix_wake_entropy_from_request(req, payload) {
                xchacha20::xchacha20_reseed(entropy);
                let _ = keystore::revoke_all_pre_phoenix();
                reply.status = CRYPTO_OK;
            } else {
                reply.status = CRYPTO_ERR_ARGS;
            }
        }
```

`sys_exo_ipc_send` (table.rs:2974-2978) forces `payload[..4] = caller_pid` for non-trusted callers, so `sender_pid == 0` from userspace is impossible. `KERNEL_EPHEMERAL_REPLY_BIT` (bit 63) is reserved for kernel reply endpoints (table.rs:3364).

**Verdict: FIXED.** The PHOENIX_WAKE_ENTROPY path is now gated: only kernel-originated IPC (sender_pid == 0 or kernel ephemeral reply endpoint) can trigger reseed. Non-kernel callers get `CRYPTO_ERR_CAP`. The previous audit's concern is resolved.

**Severity: n/a (fixed).**

---

## 21. CRYPTOSRV-002 — TLS handshake certificate verification

**File read:** `servers/crypto_server/src/tls.rs:371-493, 675-678`

**Verbatim (tls_handshake_initiate, tls.rs:371-418):**
```rust
pub fn tls_handshake_initiate(peer_pid: u32) -> (u32, [u8; 67]) {
    let mut hello = [0u8; 67];
    let mut pool = SESSION_POOL.lock();
    let mut session_handle = 0u32;
    for (idx, session) in pool.iter_mut().enumerate() {
        if session.state == TlsState::Closed as u8 {
            session_handle = (idx + 1) as u32;
            if !fill_random(&mut session.client_random) { return (0, hello); }
            let (private_key, public_key) = match generate_x25519_keypair() { ... };
            session.server_random[..32].copy_from_slice(&private_key);
            // Construire le ClientHello
            hello[0] = 1; // msg_type = ClientHello
            hello[1..3].copy_from_slice(&(CipherSuite::XChaCha20Blake3 as u16).to_le_bytes());
            hello[3..35].copy_from_slice(&session.client_random);
            hello[35..67].copy_from_slice(&public_key);
            ...
        }
    }
    (session_handle, hello)
}
```

**Verbatim (tls_handshake_complete_client, tls.rs:427-493):** see main reading above — only validates `msg_type==2`, cipher suite, and computes DH. **No certificate exchange, no identity verification.** Sets `session.state = TlsState::Verified` without any peer authentication.

**`tls_verify_certificate` (tls.rs:675-678):**
```rust
pub fn tls_verify_certificate(cert: &crate::pki::Certificate) -> bool {
    crate::pki::pki_init();
    crate::pki::verify_certificate(cert)
}
```
`grep -rn "tls_verify_certificate\(" servers/crypto_server/src` → only the definition. **Zero callers.**

**Verdict: CONFIRMED.** The TLS implementation is **anonymous X25519 DH** with no certificate or identity verification. `tls_verify_certificate` exists but is dead code. Any MITM can intercept the handshake and present their own X25519 public key — both sides will compute a "Verified" session with the attacker. The `pki.rs` module (996 lines) is also dead code per the previous audit (06_crypto_server.md).

**Severity: HIGH (active MITM vulnerability on every "TLS" session).**

---

## 22. DRV-001/002/003 — `DMA_MAP_FLAGS_BYPASS_IOMMU` from userspace

**File read:** `drivers/network/virtio_net/src/virtqueue.rs:11, 86-95`, `drivers/network/e1000/src/main.rs:25, 555-560`, `servers/network_server/src/buf_pool.rs:16, 49-64`, `kernel/src/memory/dma/core/mapping.rs:195-205`, `kernel/src/syscall/table.rs:4624-4674`

**Verbatim (virtqueue.rs:11, 86-95):**
```rust
const DMA_MAP_FLAGS_BYPASS_IOMMU: u64 = 1 << 4;
...
        let iova = unsafe {
            syscall::syscall5(
                syscall::SYS_DMA_ALLOC,
                bytes as u64,
                2,
                &mut virt as *mut u64 as u64,
                DMA_MAP_FLAGS_BYPASS_IOMMU,
                0,
            )
        };
```

**Verbatim (kernel honoring the flag, mapping.rs:195-205):**
```rust
        let iova = if flags.contains(DmaMapFlags::BYPASS_IOMMU) {
            IovaAddr::new(phys.as_u64())
        } else {
            let iova = IovaAddr::new(inner.next);
            inner.next = inner.next.wrapping_add(size_aligned as u64);
            ...
            iova
        };
```

**Verbatim (sys_dma_alloc, table.rs:4624-4674):** see main reading — `map_flags` from userspace is passed verbatim to `sys_dma_alloc_for_pid(... DmaMapFlags(map_flags as u32) ...)`. **No capability check** (no `CAP_BYPASS_IOMMU`, no `cap_check`, no `if caller_pid != ...`).

`grep -rn "BYPASS_IOMMU" kernel/src/syscall` → 0 matches in syscall code. The flag is consumed only in `memory/dma/core/mapping.rs:195`.

**Verdict: CONFIRMED.** All three drivers (virtio_net, e1000, network_server/buf_pool) AND the network_server pass `DMA_MAP_FLAGS_BYPASS_IOMMU` to `SYS_DMA_ALLOC`. The kernel honors the flag from **any** userspace caller — no capability gate. Any userspace process that knows about `SYS_DMA_ALLOC` can request DMA memory that bypasses IOMMU translation (IOVA = phys). Combined with a malicious PCI device (or even virtio-net RX/TX descriptor ring control), this gives direct DMA to arbitrary physical memory — kernel code, kernel data, other processes' memory.

**Severity: CRITICAL (kernel honors attacker-controllable bypass flag from userspace).**

---

## 23. DRV-006 — fscrypt AEAD primitive

**File read:** `drivers/storage/fscrypt/src/lib.rs:13-14, 31, 115-187`

**Verbatim (lib.rs:13-14, 31):**
```rust
//! - **AEAD** : XChaCha20 (flux) + MAC BLAKE3 keyé (contexte
//!   `ExoOS-Kernel-XChaCha20-BLAKE3-MAC-v1`), tag tronqué 16 octets.
...
const MAC_CONTEXT: &str = "ExoOS-Kernel-XChaCha20-BLAKE3-MAC-v1";
```

**Verbatim (compute_tag, lib.rs:138-153):**
```rust
fn compute_tag(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut ikm = [0u8; KEY_LEN + NONCE_LEN];
    ikm[..KEY_LEN].copy_from_slice(key);
    ikm[KEY_LEN..].copy_from_slice(nonce);
    let mac_key = blake3::derive_key(MAC_CONTEXT, &ikm);

    let mut hasher = blake3::Hasher::new_keyed(&mac_key);
    hasher.update(&(aad.len() as u64).to_le_bytes());
    hasher.update(aad);
    hasher.update(&(ct.len() as u64).to_le_bytes());
    hasher.update(ct);
    let full = hasher.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full.as_bytes()[..TAG_LEN]);
    tag
}
```

**Verbatim (aead_seal, lib.rs:156-164):** encrypt-then-MAC, AAD length-prefixed (correct order).

**Verdict: CONFIRMED (spec non-conformance, not a vulnerability).** The AEAD is **XChaCha20 + BLAKE3 keyed MAC**, not the mandated `XChaCha20-Poly1305 AEAD` (per `01_architecture.md` "Crypto mandate"). Encrypt-then-MAC ordering and length-prefixed AAD are correct; BLAKE3-MAC is also a secure MAC. So this is a violation of the architecture spec, not a cryptographic weakness per se. Tag is truncated to 16 bytes (TAG_LEN).

**Severity: MEDIUM (spec non-conformance; interop with kernel `xchacha20_poly1305.rs` is broken — same algorithm name, different MAC).**

---

## 24. POLICY-009 / A-01 — `send_raw` vs `send_raw_checked`

**File read:** `kernel/src/syscall/table.rs:2915-3006`, `kernel/src/syscall/table.rs:3301-3361`

**Verbatim (sys_exo_ipc_send, table.rs:2987-3005):**
```rust
    // FIX-IPC-SEND-RAW (Security_Audit_Passe2 §A-01) : remplace send_raw() par
    // FIX-A-01 (Security_Audit_Passe2 §A-01) : la vérification de capability
    // IPC_SEND est réalisée par validate_ipc_envelope_auth() ci-dessus qui
    // retourne EACCES si le token est invalide ou absent.
    ...
    // Ici on utilise send_raw car
    // la vérification de capability a déjà été faite dans la fonction validate.
    match crate::ipc::channel::raw::send_raw(endpoint_id, &payload, raw_flags) {
        Ok(_) => 0,
        Err(err) => ipc_error_to_errno(err),
    }
```

**Verbatim (validate_ipc_envelope_auth, table.rs:3301-3361):**
```rust
fn validate_ipc_envelope_auth(
    endpoint: u64, caller_pid: u32, caller_can_inject: bool, payload: &[u8],
) -> Result<IpcEnvelopeAuth, i64> {
    ...
    if is_kernel_ephemeral_reply_endpoint(endpoint) {
        return Ok(IpcEnvelopeAuth::NotRequired);
    }
    if caller_can_inject {
        return Ok(IpcEnvelopeAuth::TrustedCaller);
    }
    // Messages hors-format ABI non éphémères → refus explicite.
    if payload.len() != ABI_IPC_ENVELOPE_SIZE {
        return Err(EACCES);
    }
    ...
    crate::security::capability::check_token_owner(
        token,
        crate::security::Rights::IPC_SEND.bits(),
        caller_pid,
        target_pid,
        crate::security::CapObjectType::IpcEndpoint as u32,
    )
    .map_err(|_| EACCES)?;

    Ok(IpcEnvelopeAuth::ValidToken)
}
```

**Verdict: FIXED (different mechanism).** `sys_exo_ipc_send` does still call `send_raw()` (not `send_raw_checked()`), BUT the capability check is performed upfront by `validate_ipc_envelope_auth()` which calls `check_token_owner()` with `Rights::IPC_SEND`. The check is real: non-trusted callers without a valid CapToken get `EACCES`. The previous audit's concern is resolved by an explicit validation step before the raw send.

**Severity: n/a (fixed).** (Note: the long comment block at lines 2987-3001 is noisy — the actual mechanism is the upfront `validate_ipc_envelope_auth` call at line 2953.)

---

## 25. GAP-02 — `audit_syscall_entry` / `audit_syscall_exit` wiring

**File read:** `kernel/src/syscall/dispatch.rs:147-183, 215, 223-228, 295-305`

**Verbatim (dispatch.rs:163-183):**
```rust
    match audit_syscall_entry(nr as u32, caller_pid, caller_tid, 0) {
        AuditVerdict::Allow => {}
        AuditVerdict::DenyEperm => {
            frame.rax = crate::syscall::numbers::EPERM as u64;
            post_dispatch(frame, tsc_start);
            return;
        }
        AuditVerdict::DenyEnosys => { ... }
        AuditVerdict::Kill => { ... }
    }
```

**Verbatim (dispatch.rs:304-305):**
```rust
    // ── [8b] Audit syscall exit (FIX-APP-02) ──────────────────────────────
    audit_syscall_exit(caller_tid, result);
```

`audit_syscall_entry` is called BEFORE fast_path (line 223), so even fast-path syscalls (getpid/gettid/etc.) are audited on entry.

**Verdict: REFUTED (FIXED).** Both `audit_syscall_entry` (line 163) and `audit_syscall_exit` (line 305) are wired into the syscall dispatch path.

**Minor inconsistency:** `audit_syscall_exit` is NOT called on:
- audit-deny paths (lines 168/173/181) — correct, entry already recorded
- ZT-deny path (line 215) — but it explicitly calls `audit_syscall_exit` (line 215)
- fast-path return (line 226-227) — exit audit is missed for fast-path syscalls

The fast-path gap is minor: fast-path syscalls (getpid/gettid/getuid/.../sched_yield/clock_gettime) are benign and unlikely to be in audit rules.

**Severity: n/a (fixed).**

---

## Cross-cutting observations

1. **Trust anchor collapse**: BOOT-003 + INTEG-001 + C-01 form a chain of failures. The kernel never reads `SECURE_BOOT_ACTIVE` from the bootloader; `verify_boot_attestation()` is never called so `CHAIN_VERIFIED` stays `false`; `do_execve` checks `if is_chain_verified()` which is always false, so unsigned binaries always run with at most a dev-mode warning. **Net effect: no enforced code-signing chain from firmware to userspace binaries.**

2. **Capability system is selectively enforced**: 
   - ✅ `sys_exo_ipc_send` does check CapToken (via `validate_ipc_envelope_auth`).
   - ❌ `sys_exo_ipc_create` does NOT check CapToken before registering a privileged ServiceClass (POLICY-001).
   - ❌ `shm_map` does NOT check CapToken (KERN-016).
   - ❌ `sys_dma_alloc` does NOT check capability before honoring `BYPASS_IOMMU` (DRV-001..003).
   - ❌ `sys_kill` does NOT check CAP_KILL (KERN-024).
   - ❌ VFS does NOT check CapToken (GAP-06).
   - ❌ `handle_realtime_admit` (Path B) does NOT check capability (D-03).

3. **Dead-code security modules**:
   - `isolate_kernel_a_memory()` (BOOT-001)
   - `verify_boot_attestation()` (INTEG-001)
   - `cfg_validate_indirect_call()` / `cfg_lock()` (POLICY-003)
   - `enable_shadow_stack()` (POLICY-004)
   - `tls_verify_certificate()` (CRYPTOSRV-002)
   - `signatures::matcher::scan_buffer` and `signatures::yara` matching functions (SHIELD-004)
   - `pki.rs` module in crypto_server (per previous audit)

4. **PID-based gates masquerading as capabilities**: D-01 (PIDs {1,7}), D-02 (PID 1), D-03 Path A (PIDs {1,8} or ≤10), GAP-06 (PIDs {1,3} or ≥10). These are not capabilities — they're hardcoded allowlists that don't survive service restructuring and grant universal power to init_server (PID 1).

5. **Genuine fixes confirmed**:
   - BOOT-002: `stage0_init_all_steps(true)` is called.
   - CRYPTO-001: X25519 rejects all-zero DH result.
   - CRYPTOSRV-001: PHOENIX_WAKE_ENTROPY requires kernel-origin IPC.
   - POLICY-009/A-01: `validate_ipc_envelope_auth` enforces CapToken.
   - GAP-02: audit_syscall_entry/exit are wired.
   - POLICY-005 (partial): compiler `__stack_chk_guard` is random.

---

## Recommended next actions (priority order)

| # | Action | Files to touch |
|---|---|---|
| 1 | Wire `verify_boot_attestation()` from `security_init()` step 1 (after `integrity_init()`). Read `SECURE_BOOT_ACTIVE` bit from BootInfo; refuse boot if absent in production. | `kernel/src/security/mod.rs`, `kernel/src/arch/x86_64/boot/memory_map.rs:669` (add `boot_flags` field) |
| 2 | Call `verify_module_signature()` from `do_execve` against the loaded ELF's ModuleHeader (per-binary, not global flag). | `kernel/src/process/lifecycle/exec.rs:267` |
| 3 | Add CapToken check to `sys_exo_ipc_create` before `register_service_class`. Mint the right to claim `CryptoServer`/`ExoShield`/etc. only at init_server boot. | `kernel/src/syscall/table.rs:3149` |
| 4 | Add capability gate (`CAP_BYPASS_IOMMU`) to `sys_dma_alloc` when `map_flags & BYPASS_IOMMU != 0`. | `kernel/src/syscall/table.rs:4624` |
| 5 | Wire `isolate_kernel_a_memory()` into `begin_isolation_hard()` before `try_forge_reconstruct_with_policy`. | `kernel/src/exophoenix/handoff.rs:545` |
| 6 | Add CAP_KILL or same-UID check to `send_signal_number_to_pid` (or in `sys_kill` before the call). | `kernel/src/process/signal/delivery.rs:62` |
| 7 | Add `addr < USER_ADDR_MAX` check to `ARCH_SET_FS`/`ARCH_SET_GS` cases of `sys_arch_prctl`. | `kernel/src/syscall/handlers/misc.rs:163` |
| 8 | Add CapToken verification to `shm_map` (caller must present a token whose `target_pid == desc.owner_pid` and whose rights include `SHM_ATTACH`). | `kernel/src/ipc/shared_memory/mapping.rs:253` |
| 9 | Wire CFG: call `cfg_validate_indirect_call` from at least the indirect-call hotspots (rpc dispatch, syscall table dispatch, hook dispatch); call `cfg_lock()` at end of `security_init`. | `kernel/src/security/mod.rs:430`, dispatch sites |
| 10 | Wire CET Shadow Stack: allocate shadow stack pages per CPU and call `enable_shadow_stack()` from `mitigations_init` step 4 when `ss_ok`. | `kernel/src/security/exploit_mitigations/mod.rs:65` |
| 11 | Replace `STACK_CANARY` constant in `tcb.rs` with per-thread `rng_u64()` (mirror `stack_protector.rs`). | `kernel/src/process/core/tcb.rs:116` |
| 12 | Implement `PhoenixSafe` for `exo_shield::Engine` (flush alerts, snapshot profiles, suspend hooks, re-scan post-switch). Register with `exo_phoenix_ssr::register_phoenix_safe`. | `servers/exo_shield/src/main.rs` (new module) |
| 13 | Replace anonymous X25519 DH in TLS with authenticated handshake (call `tls_verify_certificate` from `tls_handshake_complete_client`/`tls_handshake_respond`); or document the protocol as "raw X25519, no MITM protection" and forbid use over untrusted links. | `servers/crypto_server/src/tls.rs:427, 500` |
| 14 | Replace D-01/D-02/D-03 Path A PID allowlists with real `CapToken` checks (`CAP_NET_RAW`, `CAP_SHM_ATTACH`, `CAP_SCHED_RT`). | `servers/network_server/src/socket_table.rs:50`, `servers/memory_server/src/mmap_service.rs:402`, `servers/scheduler_server/src/main.rs:340` |
| 15 | Wire `signatures::matcher::scan_buffer` and `signatures::yara` into `engine::scanner::execute_scan` (replace or augment built-in `match_pattern`). | `servers/exo_shield/src/engine/scanner.rs:652` |
| 16 | Switch fscrypt AEAD from BLAKE3-MAC to `XChaCha20-Poly1305` (or update `01_architecture.md` to document the divergence). | `drivers/storage/fscrypt/src/lib.rs:138` |
| 17 | Make `get_kernel_secret()` panic if `KERNEL_SECRET.get().is_none()` instead of silently returning `[0u8; 32]`. | `kernel/src/security/exokairos.rs:714` |
| 18 | Log/error on `alloc_fpu_state` failure: at minimum emit a `crate::arch::x86_64::terminal::debug_write` warning; consider returning SIGFPE to the thread instead of silent degradation. | `kernel/src/scheduler/fpu/lazy.rs:125` |
