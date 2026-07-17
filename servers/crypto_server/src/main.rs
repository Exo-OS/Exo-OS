#![no_std]
#![no_main]

//! # crypto_server — Service de cryptographie (SRV-04)
//!
//! Seul service Ring 1 autorisé à exposer des primitives cryptographiques.
//! Les autres serveurs délèguent ici les opérations de dérivation, chiffrement,
//! signature, vérification et rotation/révocation des clés.

extern crate blake3;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use exo_syscall_abi as syscall;
use keystore::{KeyType, KEY_SIZE};
use xchacha20::{NONCE_SIZE, TAG_SIZE};

mod keystore;
mod pki;
mod tls;
mod xchacha20;

const CRYPTO_SERVER_ENDPOINT: u64 = 4;
const CRYPTO_SERVER_PID: u32 = 5;
const CRYPTO_PROTOCOL_VERSION: u8 = 3;
const CRYPTO_REQUEST_PAYLOAD_SIZE: usize = 200;
const CRYPTO_REPLY_DATA_SIZE: usize = 224;
const VERIFY_CONTEXTS: usize = 4;
const VERIFY_MAX_MESSAGE: usize = 4096;

const CRYPTO_DERIVE_KEY: u32 = 0;
const CRYPTO_RANDOM: u32 = 1;
const CRYPTO_ENCRYPT: u32 = 2;
const CRYPTO_DECRYPT: u32 = 3;
const CRYPTO_HASH: u32 = 4;
const CRYPTO_SIGN: u32 = 5;
const CRYPTO_VERIFY: u32 = 6;
const CRYPTO_TLS_INIT: u32 = 7;
const CRYPTO_TLS_HANDSHAKE: u32 = 8;
const CRYPTO_TLS_CLOSE: u32 = 9;
const CRYPTO_KEY_REVOKE: u32 = 10;

const CRYPTO_KEY_ROTATE: u32 = 11;
const CRYPTO_KEY_REVOKE_OWNER: u32 = 12;
const CRYPTO_KEY_STATS: u32 = 13;
const CRYPTO_TLS_ENCRYPT: u32 = 14;
const CRYPTO_TLS_DECRYPT: u32 = 15;
const PHOENIX_WAKE_ENTROPY: u32 = 255;
const KERNEL_EPHEMERAL_REPLY_BIT: u64 = 1u64 << 63;

const VERIFY_OP_BEGIN: u8 = 0;
const VERIFY_OP_UPDATE: u8 = 1;
const VERIFY_OP_FINAL: u8 = 2;
const TLS_OP_RESPOND: u8 = 0;
const TLS_OP_COMPLETE_CLIENT: u8 = 1;

const CRYPTO_OK: u32 = 0;
const CRYPTO_ERR_ARGS: u32 = 1;
const CRYPTO_ERR_CAP: u32 = 2;
const CRYPTO_ERR_KEY_INVALID: u32 = 3;
const CRYPTO_ERR_AUTH: u32 = 4;
const CRYPTO_ERR_BUSY: u32 = 5;
const IPC_RECV_TIMEOUT_MS: u64 = 5_000;
const IPC_FLAG_TIMEOUT: u64 = syscall::IPC_FLAG_TIMEOUT;
const ETIMEDOUT: i64 = syscall::ETIMEDOUT;

#[inline]
fn boot_log(bytes: &[u8]) {
    unsafe {
        let _ = syscall::syscall3(
            syscall::SYS_EXO_LOG,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            1,
        );
    }
}

fn halt_forever() -> ! {
    loop {
        unsafe {
            core::arch::asm!("hlt", options(nostack, nomem));
        }
    }
}

/// Entropie cryptographique RÉELLE via le CSPRNG kernel (`getrandom` → RNG durci
/// RDSEED/RDRAND + conditionnement Blake3 + ChaCha20). Retourne `false` en cas
/// d'échec — l'appelant DOIT alors abandonner (jamais de clé d'une source faible).
///
/// FIX-SEC-2C : remplace les générateurs faibles (LCG seedé TSC, clé racine PKI
/// tout-zéros) par la seule source d'aléa cryptographique du système.
pub(crate) fn secure_random(buf: &mut [u8]) -> bool {
    let r = unsafe {
        syscall::syscall3(
            syscall::SYS_GETRANDOM,
            buf.as_mut_ptr() as u64,
            buf.len() as u64,
            0,
        )
    };
    r >= 0 && (r as usize) == buf.len()
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CryptoRequest {
    sender_pid: u32,
    msg_type: u32,
    reply_endpoint: u64,
    payload_len: u16,
    version: u8,
    flags: u8,
    cap_token: syscall::ExoCapTokenWire,
    payload: [u8; CRYPTO_REQUEST_PAYLOAD_SIZE],
}

const _: () = assert!(core::mem::size_of::<CryptoRequest>() <= syscall::IPC_KERNEL_MAX_MSG_SIZE);

#[repr(C)]
#[derive(Clone, Copy)]
struct CryptoReply {
    sender_pid: u32,
    status: u32,
    key_handle: u32,
    data_len: u16,
    version: u8,
    flags: u8,
    data: [u8; CRYPTO_REPLY_DATA_SIZE],
}

impl CryptoReply {
    const fn new(status: u32) -> Self {
        Self {
            sender_pid: 0,
            status,
            key_handle: 0,
            data_len: 0,
            version: CRYPTO_PROTOCOL_VERSION,
            flags: 0,
            data: [0u8; CRYPTO_REPLY_DATA_SIZE],
        }
    }

    fn write_data(&mut self, data: &[u8]) {
        let copy_len = data.len().min(self.data.len());
        self.data[..copy_len].copy_from_slice(&data[..copy_len]);
        self.data_len = copy_len as u16;
    }
}

const _: () = assert!(core::mem::size_of::<CryptoReply>() <= syscall::IPC_KERNEL_MAX_MSG_SIZE);

static REQUESTS_TOTAL: AtomicU64 = AtomicU64::new(0);
static REQUESTS_OK: AtomicU64 = AtomicU64::new(0);
static REQUESTS_ERR: AtomicU64 = AtomicU64::new(0);
static IPC_RECV_TIMEOUTS: AtomicU32 = AtomicU32::new(0);

#[derive(Clone, Copy)]
struct VerifyContext {
    in_use: bool,
    owner_principal: u64,
    public_key: [u8; 32],
    signature: [u8; 64],
    total_len: u16,
    received_len: u16,
    message: [u8; VERIFY_MAX_MESSAGE],
}

impl VerifyContext {
    const fn empty() -> Self {
        Self {
            in_use: false,
            owner_principal: 0,
            public_key: [0u8; 32],
            signature: [0u8; 64],
            total_len: 0,
            received_len: 0,
            message: [0u8; VERIFY_MAX_MESSAGE],
        }
    }
}

static VERIFY_TABLE: spin::Mutex<[VerifyContext; VERIFY_CONTEXTS]> =
    spin::Mutex::new([VerifyContext::empty(); VERIFY_CONTEXTS]);

#[inline(always)]
fn wipe_bytes(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::fence(Ordering::SeqCst);
}

#[inline(always)]
fn read_u16_le(buf: &[u8], offset: usize) -> Option<u16> {
    if offset + 2 > buf.len() {
        return None;
    }
    Some(u16::from_le_bytes([buf[offset], buf[offset + 1]]))
}

#[inline(always)]
fn read_u32_le(buf: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 > buf.len() {
        return None;
    }
    Some(u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ]))
}

#[inline(always)]
fn read_u64_le(buf: &[u8], offset: usize) -> Option<u64> {
    if offset + 8 > buf.len() {
        return None;
    }
    Some(u64::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ]))
}

#[inline(always)]
fn write_u32_le(buf: &mut [u8], offset: usize, value: u32) -> bool {
    if offset + 4 > buf.len() {
        return false;
    }
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    true
}

fn derive_key_hkdf(material: &[u8], output: &mut [u8; KEY_SIZE]) {
    let salt = [0u8; 32];
    let prk = blake3::keyed_hash(&salt, material);
    let okm = blake3::derive_key("Exo-OS SRV-04 KDF v1", prk.as_bytes());
    output.copy_from_slice(&okm);
}

fn hash_blake3(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

fn reset_verify_context(ctx: &mut VerifyContext) {
    *ctx = VerifyContext::empty();
}

fn alloc_verify_context(
    owner_principal: u64,
    public_key: [u8; 32],
    signature: [u8; 64],
    total_len: usize,
) -> u32 {
    if total_len == 0 || total_len > VERIFY_MAX_MESSAGE {
        return 0;
    }

    let mut table = VERIFY_TABLE.lock();
    for (idx, ctx) in table.iter_mut().enumerate() {
        if ctx.in_use {
            continue;
        }
        *ctx = VerifyContext {
            in_use: true,
            owner_principal,
            public_key,
            signature,
            total_len: total_len as u16,
            received_len: 0,
            message: [0u8; VERIFY_MAX_MESSAGE],
        };
        return (idx + 1) as u32;
    }
    0
}

fn append_verify_context(ctx_handle: u32, owner_principal: u64, chunk: &[u8]) -> bool {
    if ctx_handle == 0 {
        return false;
    }

    let idx = (ctx_handle - 1) as usize;
    if idx >= VERIFY_CONTEXTS {
        return false;
    }

    let mut table = VERIFY_TABLE.lock();
    let ctx = &mut table[idx];
    if !ctx.in_use || ctx.owner_principal != owner_principal {
        return false;
    }

    let start = ctx.received_len as usize;
    let end = start.saturating_add(chunk.len());
    if end > ctx.total_len as usize || end > VERIFY_MAX_MESSAGE {
        return false;
    }

    ctx.message[start..end].copy_from_slice(chunk);
    ctx.received_len = end as u16;
    true
}

fn finalize_verify_context(ctx_handle: u32, owner_principal: u64) -> Option<bool> {
    if ctx_handle == 0 {
        return None;
    }

    let idx = (ctx_handle - 1) as usize;
    if idx >= VERIFY_CONTEXTS {
        return None;
    }

    let mut table = VERIFY_TABLE.lock();
    let ctx = &mut table[idx];
    if !ctx.in_use || ctx.owner_principal != owner_principal {
        return None;
    }

    if ctx.received_len != ctx.total_len {
        reset_verify_context(ctx);
        return Some(false);
    }

    let verify_result = VerifyingKey::from_bytes(&ctx.public_key)
        .ok()
        .map(|vk| {
            let sig = Signature::from_bytes(&ctx.signature);
            // FIX-DEEP-CRYPTO : verify_strict (PAS verify) — rejette les clés
            // faibles (low-order) et la malléabilité de signature. C'est la
            // vérification Ed25519 CENTRALE du système (exo_shield et tous les
            // serveurs y délèguent) : elle doit être stricte comme le kernel.
            vk.verify_strict(&ctx.message[..ctx.total_len as usize], &sig)
                .is_ok()
        })
        .unwrap_or(false);

    reset_verify_context(ctx);
    Some(verify_result)
}

fn send_reply(destination: u64, reply: &CryptoReply) {
    if destination == 0 {
        return;
    }

    let _ = unsafe {
        syscall::syscall6(
            syscall::SYS_IPC_SEND,
            destination,
            reply as *const CryptoReply as u64,
            core::mem::size_of::<CryptoReply>() as u64,
            0,
            0,
            0,
        )
    };
}

fn authorize_request(req: &CryptoRequest) -> Result<u64, u32> {
    if req.cap_token.is_empty() {
        return Err(CRYPTO_ERR_CAP);
    }

    let rc = unsafe {
        syscall::exo_cap_check(
            &req.cap_token,
            syscall::EXO_CAP_RIGHT_IPC_SEND,
            CRYPTO_SERVER_PID,
            syscall::EXO_CAP_TYPE_IPC_ENDPOINT,
        )
    };
    if rc < 0 {
        return Err(CRYPTO_ERR_CAP);
    }

    let principal = req.cap_token.object_id();
    if principal == 0 {
        return Err(CRYPTO_ERR_CAP);
    }
    Ok(principal)
}

fn phoenix_wake_entropy_from_request(req: &CryptoRequest, payload: &[u8]) -> Option<u64> {
    let compact_entropy = read_u64_le(&req.cap_token.bytes, 0).unwrap_or(0);
    if req.reply_endpoint == 0 && compact_entropy != 0 {
        return Some(compact_entropy);
    }
    read_u64_le(payload, 0)
}

fn caller_peer_pid(caller_principal: u64) -> u32 {
    caller_principal.min(u32::MAX as u64) as u32
}

fn tls_init_reply(payload: &[u8], caller_principal: u64, reply: &mut CryptoReply) {
    let peer_pid = read_u32_le(payload, 0).unwrap_or_else(|| caller_peer_pid(caller_principal));
    let (session_handle, client_hello) = tls::tls_handshake_initiate(peer_pid);
    if session_handle == 0 {
        reply.status = CRYPTO_ERR_BUSY;
        return;
    }
    reply.status = CRYPTO_OK;
    reply.key_handle = session_handle;
    reply.write_data(&client_hello);
}

fn tls_handshake_reply(payload: &[u8], caller_principal: u64, reply: &mut CryptoReply) {
    if payload.is_empty() {
        reply.status = CRYPTO_ERR_ARGS;
        return;
    }

    // Compatibilité simple: un ClientHello brut peut être envoyé directement.
    if payload[0] == 1 && payload.len() >= 67 {
        let (session_handle, server_hello) =
            tls::tls_handshake_respond(&payload[..67], caller_peer_pid(caller_principal));
        if session_handle == 0 {
            reply.status = CRYPTO_ERR_AUTH;
            return;
        }
        reply.status = CRYPTO_OK;
        reply.key_handle = session_handle;
        reply.write_data(&server_hello);
        return;
    }

    match payload[0] {
        TLS_OP_RESPOND => {
            let peer_pid =
                read_u32_le(payload, 1).unwrap_or_else(|| caller_peer_pid(caller_principal));
            let Some(hello_len) = read_u16_le(payload, 5) else {
                reply.status = CRYPTO_ERR_ARGS;
                return;
            };
            let hello_len = hello_len as usize;
            if 7 + hello_len > payload.len() {
                reply.status = CRYPTO_ERR_ARGS;
                return;
            }
            let (session_handle, server_hello) =
                tls::tls_handshake_respond(&payload[7..7 + hello_len], peer_pid);
            if session_handle == 0 {
                reply.status = CRYPTO_ERR_AUTH;
                return;
            }
            reply.status = CRYPTO_OK;
            reply.key_handle = session_handle;
            reply.write_data(&server_hello);
        }
        TLS_OP_COMPLETE_CLIENT => {
            let Some(session_handle) = read_u32_le(payload, 1) else {
                reply.status = CRYPTO_ERR_ARGS;
                return;
            };
            let Some(hello_len) = read_u16_le(payload, 5) else {
                reply.status = CRYPTO_ERR_ARGS;
                return;
            };
            let hello_len = hello_len as usize;
            if 7 + hello_len > payload.len() {
                reply.status = CRYPTO_ERR_ARGS;
                return;
            }
            if tls::tls_handshake_complete_client(session_handle, &payload[7..7 + hello_len]) {
                reply.status = CRYPTO_OK;
                reply.key_handle = session_handle;
            } else {
                reply.status = CRYPTO_ERR_AUTH;
            }
        }
        _ => {
            reply.status = CRYPTO_ERR_ARGS;
        }
    }
}

fn tls_encrypt_reply(payload: &[u8], reply: &mut CryptoReply) {
    let Some(session_handle) = read_u32_le(payload, 0) else {
        reply.status = CRYPTO_ERR_ARGS;
        return;
    };
    let Some(data_len) = read_u16_le(payload, 4) else {
        reply.status = CRYPTO_ERR_ARGS;
        return;
    };
    let data_len = data_len as usize;
    if 6 + data_len > payload.len() || data_len + 24 + TAG_SIZE > CRYPTO_REPLY_DATA_SIZE {
        reply.status = CRYPTO_ERR_ARGS;
        return;
    }
    let data = &payload[6..6 + data_len];
    let mut output = [0u8; CRYPTO_REPLY_DATA_SIZE];
    if tls::tls_encrypt_record(session_handle, data, &mut output) {
        reply.status = CRYPTO_OK;
        reply.key_handle = session_handle;
        reply.write_data(&output[..24 + data_len + TAG_SIZE]);
    } else {
        reply.status = CRYPTO_ERR_AUTH;
    }
}

fn tls_decrypt_reply(payload: &[u8], reply: &mut CryptoReply) {
    let Some(session_handle) = read_u32_le(payload, 0) else {
        reply.status = CRYPTO_ERR_ARGS;
        return;
    };
    let Some(input_len) = read_u16_le(payload, 4) else {
        reply.status = CRYPTO_ERR_ARGS;
        return;
    };
    let input_len = input_len as usize;
    if 6 + input_len > payload.len() || input_len < 24 + TAG_SIZE {
        reply.status = CRYPTO_ERR_ARGS;
        return;
    }
    let input = &payload[6..6 + input_len];
    let mut plaintext = [0u8; CRYPTO_REPLY_DATA_SIZE];
    if tls::tls_decrypt_record(session_handle, input, &mut plaintext) {
        let pt_len = input_len - 24 - TAG_SIZE;
        reply.status = CRYPTO_OK;
        reply.key_handle = session_handle;
        reply.write_data(&plaintext[..pt_len]);
    } else {
        reply.status = CRYPTO_ERR_AUTH;
    }
}

fn tls_close_reply(payload: &[u8], reply: &mut CryptoReply) {
    let Some(session_handle) = read_u32_le(payload, 0) else {
        reply.status = CRYPTO_ERR_ARGS;
        return;
    };
    if tls::tls_close(session_handle) {
        reply.status = CRYPTO_OK;
        reply.key_handle = session_handle;
    } else {
        reply.status = CRYPTO_ERR_KEY_INVALID;
    }
}

fn handle_request(req: &CryptoRequest) -> CryptoReply {
    let mut reply = CryptoReply::new(CRYPTO_ERR_ARGS);
    REQUESTS_TOTAL.fetch_add(1, Ordering::Relaxed);

    if req.version != CRYPTO_PROTOCOL_VERSION || req.payload_len as usize > req.payload.len() {
        REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
        return reply;
    }

    let payload = &req.payload[..req.payload_len as usize];
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

    match req.msg_type {
        CRYPTO_DERIVE_KEY => {
            if payload.is_empty() {
                reply.status = CRYPTO_ERR_ARGS;
            } else {
                let key_type = KeyType::from_u8(payload[0]).unwrap_or(KeyType::Derived);
                let mut derived_key = [0u8; KEY_SIZE];
                derive_key_hkdf(&payload[1..], &mut derived_key);

                let handle = keystore::insert_key(&derived_key, key_type, caller_principal);
                wipe_bytes(&mut derived_key);

                if handle != 0 {
                    reply.status = CRYPTO_OK;
                    reply.key_handle = handle;
                } else {
                    reply.status = CRYPTO_ERR_BUSY;
                }
            }
        }
        CRYPTO_RANDOM => {
            if payload.is_empty() {
                reply.status = CRYPTO_ERR_ARGS;
            } else {
                let n = (payload[0] as usize).min(reply.data.len());
                let r = unsafe {
                    syscall::syscall3(
                        syscall::SYS_GETRANDOM,
                        reply.data.as_mut_ptr() as u64,
                        n as u64,
                        0,
                    )
                };
                if r >= 0 {
                    reply.status = CRYPTO_OK;
                    reply.data_len = n as u16;
                }
            }
        }
        CRYPTO_ENCRYPT => {
            let Some(key_handle) = read_u32_le(payload, 0) else {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };
            let Some(pt_len) = read_u16_le(payload, 4) else {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };
            let pt_len = pt_len as usize;

            if !keystore::is_valid_handle(key_handle) {
                reply.status = CRYPTO_ERR_KEY_INVALID;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            }

            if 6 + pt_len > payload.len()
                || pt_len > reply.data.len().saturating_sub(NONCE_SIZE + TAG_SIZE)
            {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            }

            let Some((mut key, _)) = keystore::get_key(key_handle, caller_principal) else {
                reply.status = CRYPTO_ERR_KEY_INVALID;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };

            let plaintext = &payload[6..6 + pt_len];
            let mut nonce = [0u8; NONCE_SIZE];
            let mut sealed = [0u8; CRYPTO_REPLY_DATA_SIZE];
            let sealed_len = xchacha20::xchacha20_seal(
                &key,
                plaintext,
                &[],
                &mut nonce,
                &mut sealed[NONCE_SIZE..],
            );
            wipe_bytes(&mut key);

            if sealed_len == pt_len + TAG_SIZE {
                sealed[..NONCE_SIZE].copy_from_slice(&nonce);
                reply.status = CRYPTO_OK;
                reply.key_handle = key_handle;
                reply.write_data(&sealed[..NONCE_SIZE + sealed_len]);
            } else {
                reply.status = CRYPTO_ERR_ARGS;
            }
        }
        CRYPTO_DECRYPT => {
            let Some(key_handle) = read_u32_le(payload, 0) else {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };
            let Some(sealed_len) = read_u16_le(payload, 4) else {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };
            let sealed_len = sealed_len as usize;

            if !keystore::is_valid_handle(key_handle) {
                reply.status = CRYPTO_ERR_KEY_INVALID;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            }

            if 6 + sealed_len > payload.len() || sealed_len < NONCE_SIZE + TAG_SIZE {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            }

            let Some((mut key, _)) = keystore::get_key(key_handle, caller_principal) else {
                reply.status = CRYPTO_ERR_KEY_INVALID;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };

            let nonce: &[u8; NONCE_SIZE] = match payload[6..6 + NONCE_SIZE].try_into() {
                Ok(n) => n,
                Err(_) => {
                    wipe_bytes(&mut key);
                    reply.status = CRYPTO_ERR_ARGS;
                    REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                    return reply;
                }
            };

            let ciphertext = &payload[6 + NONCE_SIZE..6 + sealed_len];
            let mut plaintext = [0u8; CRYPTO_REPLY_DATA_SIZE];
            let opened = xchacha20::xchacha20_open(&key, nonce, ciphertext, &[], &mut plaintext);
            wipe_bytes(&mut key);

            if opened != 0 {
                reply.status = CRYPTO_OK;
                reply.key_handle = key_handle;
                reply.write_data(&plaintext[..opened]);
            } else {
                reply.status = CRYPTO_ERR_AUTH;
            }
        }
        CRYPTO_HASH => {
            let hash = hash_blake3(payload);
            reply.status = CRYPTO_OK;
            reply.write_data(&hash);
        }
        CRYPTO_SIGN => {
            let Some(key_handle) = read_u32_le(payload, 0) else {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };
            let Some(msg_len) = read_u16_le(payload, 4) else {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };
            let msg_len = msg_len as usize;

            if !keystore::is_valid_handle(key_handle) {
                reply.status = CRYPTO_ERR_KEY_INVALID;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            }

            if 6 + msg_len > payload.len() {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            }

            let Some((mut key_seed, _)) = keystore::get_key(key_handle, caller_principal) else {
                reply.status = CRYPTO_ERR_KEY_INVALID;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };

            let signing_key = SigningKey::from_bytes(&key_seed);
            let signature = signing_key.sign(&payload[6..6 + msg_len]).to_bytes();
            wipe_bytes(&mut key_seed);

            reply.status = CRYPTO_OK;
            reply.key_handle = key_handle;
            reply.write_data(&signature);
        }
        CRYPTO_VERIFY => {
            if payload.is_empty() {
                reply.status = CRYPTO_ERR_ARGS;
            } else {
                match payload[0] {
                    VERIFY_OP_BEGIN => {
                        if payload.len() < 99 {
                            reply.status = CRYPTO_ERR_ARGS;
                        } else {
                            let mut public_key = [0u8; 32];
                            public_key.copy_from_slice(&payload[1..33]);
                            let mut signature = [0u8; 64];
                            signature.copy_from_slice(&payload[33..97]);
                            let Some(total_len) = read_u16_le(payload, 97) else {
                                reply.status = CRYPTO_ERR_ARGS;
                                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                                return reply;
                            };

                            let ctx = alloc_verify_context(
                                caller_principal,
                                public_key,
                                signature,
                                total_len as usize,
                            );
                            if ctx == 0 {
                                reply.status = CRYPTO_ERR_BUSY;
                            } else {
                                reply.status = CRYPTO_OK;
                                reply.key_handle = ctx;
                            }
                        }
                    }
                    VERIFY_OP_UPDATE => {
                        let Some(ctx_handle) = read_u32_le(payload, 1) else {
                            reply.status = CRYPTO_ERR_ARGS;
                            REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                            return reply;
                        };
                        let Some(chunk_len) = read_u16_le(payload, 5) else {
                            reply.status = CRYPTO_ERR_ARGS;
                            REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                            return reply;
                        };
                        let chunk_len = chunk_len as usize;
                        if 7 + chunk_len > payload.len() {
                            reply.status = CRYPTO_ERR_ARGS;
                        } else if append_verify_context(
                            ctx_handle,
                            caller_principal,
                            &payload[7..7 + chunk_len],
                        ) {
                            reply.status = CRYPTO_OK;
                            reply.key_handle = ctx_handle;
                        } else {
                            reply.status = CRYPTO_ERR_ARGS;
                        }
                    }
                    VERIFY_OP_FINAL => {
                        let Some(ctx_handle) = read_u32_le(payload, 1) else {
                            reply.status = CRYPTO_ERR_ARGS;
                            REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                            return reply;
                        };

                        match finalize_verify_context(ctx_handle, caller_principal) {
                            Some(true) => {
                                reply.status = CRYPTO_OK;
                                reply.key_handle = ctx_handle;
                            }
                            Some(false) => {
                                reply.status = CRYPTO_ERR_AUTH;
                            }
                            None => {
                                reply.status = CRYPTO_ERR_ARGS;
                            }
                        }
                    }
                    _ => {
                        reply.status = CRYPTO_ERR_ARGS;
                    }
                }
            }
        }
        CRYPTO_TLS_INIT => {
            tls_init_reply(payload, caller_principal, &mut reply);
        }
        CRYPTO_TLS_HANDSHAKE => {
            tls_handshake_reply(payload, caller_principal, &mut reply);
        }
        CRYPTO_TLS_CLOSE => {
            tls_close_reply(payload, &mut reply);
        }
        CRYPTO_TLS_ENCRYPT => {
            tls_encrypt_reply(payload, &mut reply);
        }
        CRYPTO_TLS_DECRYPT => {
            tls_decrypt_reply(payload, &mut reply);
        }
        CRYPTO_KEY_REVOKE => {
            let Some(key_handle) = read_u32_le(payload, 0) else {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };

            if !keystore::is_valid_handle(key_handle)
                || keystore::get_key(key_handle, caller_principal).is_none()
            {
                reply.status = CRYPTO_ERR_KEY_INVALID;
            } else if keystore::revoke_key(key_handle) {
                reply.status = CRYPTO_OK;
                reply.key_handle = key_handle;
            } else {
                reply.status = CRYPTO_ERR_KEY_INVALID;
            }
        }
        CRYPTO_KEY_ROTATE => {
            let Some(key_handle) = read_u32_le(payload, 0) else {
                reply.status = CRYPTO_ERR_ARGS;
                REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
                return reply;
            };

            let rotated = if keystore::is_valid_handle(key_handle) {
                keystore::rotate_key(key_handle, caller_principal)
            } else {
                0
            };
            if rotated != 0 {
                reply.status = CRYPTO_OK;
                reply.key_handle = rotated;
            } else {
                reply.status = CRYPTO_ERR_KEY_INVALID;
            }
        }
        CRYPTO_KEY_REVOKE_OWNER => {
            let revoked = keystore::revoke_all_for_owner(caller_principal);
            reply.status = CRYPTO_OK;
            reply.key_handle = revoked;
        }
        CRYPTO_KEY_STATS => {
            let stats = keystore::get_stats();
            let active_counter = keystore::active_key_count();
            let mut encoded = [0u8; 20];
            let _ = write_u32_le(&mut encoded, 0, stats.active);
            let _ = write_u32_le(&mut encoded, 4, stats.expired);
            let _ = write_u32_le(&mut encoded, 8, stats.revoked);
            let _ = write_u32_le(&mut encoded, 12, stats.free);
            let _ = write_u32_le(&mut encoded, 16, active_counter);
            reply.status = CRYPTO_OK;
            reply.write_data(&encoded);
        }
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
        _ => {
            reply.status = CRYPTO_ERR_ARGS;
        }
    }

    if reply.status == CRYPTO_OK {
        REQUESTS_OK.fetch_add(1, Ordering::Relaxed);
    } else {
        REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
    }

    reply
}

// FIX-SRV-M7 (ANALYSE_SERVERS §M7) : NOTE architecturale importante.
// crypto_server s'enregistre avec ENDPOINT_ID=4 (SYS_IPC_CREATE) mais son PID
// assigné par init_server est dynamique (typiquement 5, après ipc_broker=2+memory=3+vfs=4).
// Cette divergence endpoint(4)/PID(5) peut causer de la confusion dans exocordon.rs
// où ServiceId::Crypto=5 et dans ipc_policy.rs où le check porte sur les PIDs.
// RÉSOLUTION : utiliser SYS_GETPID() pour obtenir le vrai PID au runtime,
// et SYS_IPC_REGISTER() pour associer le nom "crypto_server" à l'endpoint réel.
// L'endpoint ID (4) est la constante d'interface publique ; le PID est interne.
#[no_mangle]
pub extern "C" fn _start() -> ! {
    boot_log(b"crypto_server: boot\n");
    xchacha20::xchacha20_init();
    keystore::keystore_init();
    tls::tls_init();

    let name = b"crypto_server";
    let register_rc = unsafe {
        syscall::syscall3(
            syscall::SYS_IPC_REGISTER,
            name.as_ptr() as u64,
            name.len() as u64,
            CRYPTO_SERVER_ENDPOINT,
        )
    };
    if register_rc < 0 {
        boot_log(b"crypto_server: register failed\n");
        halt_forever();
    }
    boot_log(b"crypto_server: registered\n");

    let mut req = CryptoRequest {
        sender_pid: 0,
        msg_type: 0,
        reply_endpoint: 0,
        payload_len: 0,
        version: CRYPTO_PROTOCOL_VERSION,
        flags: 0,
        cap_token: syscall::ExoCapTokenWire::empty(),
        payload: [0u8; CRYPTO_REQUEST_PAYLOAD_SIZE],
    };

    loop {
        let r = unsafe {
            syscall::syscall4(
                syscall::SYS_EXO_IPC_RECV,
                CRYPTO_SERVER_ENDPOINT,
                &mut req as *mut CryptoRequest as u64,
                core::mem::size_of::<CryptoRequest>() as u64,
                IPC_FLAG_TIMEOUT | IPC_RECV_TIMEOUT_MS,
            )
        };

        if r == ETIMEDOUT {
            IPC_RECV_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            let _ = keystore::expire_check();
            continue;
        }
        if r < 0 {
            continue;
        }

        let reply = handle_request(&req);
        send_reply(req.reply_endpoint, &reply);
    }
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    boot_log(b"crypto_server: panic\n");
    halt_forever();
}
