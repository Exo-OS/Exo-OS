# ExoOS — Architecture de Sécurité (Synthèse)

## Modèle
- 8 couches : Boot Integrity (ExoSeal) → Isolation HW (ExoCage) → Zero Trust → CapToken → ExoKairos → ExoLedger → IOMMU (ExoShield-IOMMU) → ExoNMI → ExoShield Ring1 EDR
- MLS Bell-LaPadula + Biba (sensitivity + integrity + compartment)
- Capability-based 24B tokens, 512 slots, ct_eq
- Pledge (16 flags), Sandbox exo compat
- IPC DAG 92 paires kernel, 5 edges userspace (GAP-03)
- ExoKairos: 1s window, 100% throttle, 200% kill, HMAC-Blake3 deadline

## Crypto mandate
- Ed25519 verify_strict (anti-malleability, cofactor 8)
- X25519 RFC 7748 §6 (reject all-zero + weak-order)
- AES-GCM GHASH constant-time, ct_eq tag, verify-before-decrypt
- XChaCha20-Poly1305 AEAD encrypt-then-MAC, AAD length-prefixed
- BLAKE3 (constant_time_eq, derive_key)
- HKDF-Blake3 (toutes rotations, remplace XOR+FNV)
- SHA-512 (hash corps kernel signature)
- Argon2id (fscrypt, m=64MiB t=3 p=4)
- RNG: RDSEED×4 + RDRAND×6 + jitter TSC + stack ptr, BLAKE3-conditioned, reseed 4096 calls, zeroization
- ChaCha20 kernel maison (RFC 8439 KAT)

## Boot chain
UEFI SecureBoot → exo-boot.efi (PE32+ sig) → kernel.elf (Ed25519+SHA-512 footer EXOSIG01 256B) → BootInfo integrity → ExoSeal phase0 (BLAKE3 hash kernel + Ring1)
- KernelVerdict enum (Verified/Unsigned/Tampered/NoVerifierKey), fail-closed
- Compile-time guard: pas de clé de test
- KASLR: EFI_RNG or RDRAND/TSC, 1GiB..256GiB, align 2MiB, PIE

## ExoShield (NGAV)
- Ring1, endpoint "exo_shield" PID 10 (dynamique)
- 8 modules: engine, behavioral, hooks (sys/exec/mem/net), network (fw/ids/dns/traffic), sandbox (container/fs/net/syscall), signatures (db/matcher/yara/update Ed25519), ml (32→16 Q16.16), forensics (memory_dump CRC32, timeline, report)
- 7 IPC ops: SCAN_REQUEST, EVENT_REPORT (no cap), QUARANTINE, THREAT_QUERY, POLICY_UPDATE (CAP_EXOSHIELD_ADMIN), HEARTBEAT, PMC_ANOMALY
- PhoenixSafe: flush alerts, snapshot profiles, suspend hooks, re-scan post-switch
- YARA: patterns 8B fast path, 64B after CORR-75; yara-x v0.3.0

## ExoPhoenix (résurrection)
- Dual kernel A↔B, recovery <500ms, 100% caps survivantes
- SSR 4KiB @ 0x0100_0000, magic 0xEXO_PHXF, BLAKE3-hashed
- active_cores [u64;4] (256 cores) — mais modules kernel hard-cappent à 64
- Sentinel triggers: NMI heartbeat >2s, double fault, MCE, watchdog, stack canary
- PhoenixWakeEntropy NON wired (reseed post-Phoenix manquant) — RISQUE NONCE REUSE

## Open Issues (synthèse précédents audits)
- A-01: sys_exo_ipc_send appelait send_raw au lieu de send_raw_checked
- A-02: bypass taille IPC (résolu FIX-IPC-AUTH)
- B-01: IBPB context-switch (résolu)
- C-01: do_execve n'appelle pas verify_module_signature — TOUJOURS OUVERT
- C-02: forge::verify_merkle degraded mode si hash=0
- D-01: network_server SOCK_RAW sans CAP_NET_RAW — TOUJOURS OUVERT
- D-02: memory_server attach_shared_region ignore sender_pid — TOUJOURS OUVERT
- D-03: scheduler_server escalade SCHED_REALTIME sans cap
- GAP-03: ExoCordon userspace 5 edges vs 92
- GAP-04/05/06: memory/scheduler/vfs_server zero cap
- SEC-04: 5 modules exo_shield non déclarés lib.rs (CORR-75 P0)
- PhoenixWakeEntropy non wired
- exo_shield/signatures/update.rs: crypto locale au lieu de crypto_server
- CAP-01 crypto_server non enforced
- 43 unsafe sans SAFETY contracts dans security/
- TIER 3.1: kernel→shield feed non wired
- TIER 3.2: privileged requests sans cap réelle
- TIER 5.3: ExoPhoenix physical reload + huge page isolation
- 2.1-b/c: PKI réelle + bootloader attestation
