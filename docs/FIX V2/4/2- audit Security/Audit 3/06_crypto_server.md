# ExoOS Audit — Task 06 : `crypto_server` (autorité cryptographique Ring 1)

**Auditeur :** sub-agent Task ID 6
**Cible :** `audit/servers/crypto_server/` (PID 5, endpoint 4)
**Périmètre :** `Cargo.toml` + `src/{main,xchacha20,keystore,tls,pki}.rs`
**Méthode :** lecture exhaustive ligne-par-ligne, cross-référence des call sites, vérification des mandats crypto de `01_architecture.md`

---

## 1. Inventaire des fichiers audités

| Fichier | Lignes | Rôle |
|---|---:|---|
| `Cargo.toml` | 26 | Dépendances : `blake3`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `hkdf`, `spin`, `exo-syscall-abi` |
| `src/main.rs` | 1017 | Boucle IPC, dispatch des 17 ops, authn capability, contextes de verify streaming |
| `src/xchacha20.rs` | 229 | Wrapper XChaCha20-Poly1305 AEAD + sel nonce + reseed Phoenix |
| `src/keystore.rs` | 632 | 64 slots, quota owner, TTL 300s, shredding DoD, rotation HKDF-Blake3 |
| `src/tls.rs` | 739 | « TLS 1.3 » minimal (suite custom XChaCha20-BLAKE3), pool 16 sessions |
| `src/pki.rs` | 996 | PKI Ed25519 : root/intermediate/leaf, CRL, registry — **dead code** |
| **Total** | **3639** | |

---

## 2. Conformité par module

### 2.1 `main.rs` — IPC dispatch & auth

| Point de contrôle | Implémenté | Enforcé | Sûr |
|---|:---:|:---:|:---:|
| 17 ops IPC (derive/random/encrypt/decrypt/hash/sign/verify + 3×TLS ctrl + 2×TLS data + revoke/rotate/revoke-owner/stats + phoenix) | ✅ | — | ✅ |
| `authorize_request` → `exo_cap_check(IPC_SEND, PID=5, IPC_ENDPOINT)` | ✅ | ⚠️ PARTIEL | ✅ |
| CAP-01 enforced sur TOUS les ops | — | ❌ NON (PHOENIX bypassé) | ❌ |
| `phoenix-reseed` op existe | ✅ | — | ❌ |
| Kernel→crypto_server event wired | ❌ NON (cf. `01_architecture.md` PhoenixWakeEntropy NON wired) | — | ❌ |
| `verify_strict` Ed25519 | ✅ ligne 344 | — | ✅ |
| Zeroization des clés après usage | ✅ `wipe_bytes` (586, 658, 713, 761) | — | ✅ |
| Bounds checking IPC désérialisation | ✅ `read_u16/u32/u64_le` + checks longueur | — | ✅ |
| Pas de `unwrap`/`expect` sur crypto | ✅ uniquement `unwrap_or` sûrs | — | ✅ |
| Pas de from-scratch crypto | ✅ toutes via crates | — | ✅ |
| `unsafe` avec SAFETY contracts | ❌ aucun | — | ❌ |

**Note sur le nombre d'ops :** le cahier des charges de la tâche mentionnait « 14 ops » ; le code en implémente **17** (les 2 ops TLS data `TLS_ENCRYPT`/`TLS_DECRYPT` opcode 14/15 + phoenix 255 n'étaient pas dans le décompte initial). Toutes sont implémentées.

### 2.2 `xchacha20.rs`

| Point | Implémenté | Enforcé | Sûr |
|---|:---:|:---:|:---:|
| `getrandom_u64` : 16 tentatives + repli explicite | ✅ l.59-92 | — | ⚠️ |
| XChaCha20-Poly1305 AEAD encrypt-then-MAC | ✅ `encrypt_in_place_detached` | — | ✅ |
| MAC séparé (tag Poly1305 après chiffrement) | ✅ | — | ✅ |
| Clé MAC dérivée séparément | N/A (AEAD dérive interne) | — | ✅ |
| AAD length-prefixed | ❌ AAD toujours `&[]` côté main.rs | — | ⚠️ |
| Nonce uniqueness (counter monotone + sel) | ✅ `NONCE_COUNTER.fetch_add` | — | ✅ |
| Nonce reuse cross-session après reseed | ✅ saut de 1M dans le compteur | — | ✅ |
| Zeroization clé cipher XChaCha20Poly1305 | ❌ non-zeroized on drop | — | ❌ |
| Reseed via HKDF-Blake3 | ❌ XOR mixing (l.117-118) | — | ❌ |

### 2.3 `keystore.rs`

| Point | Implémenté | Enforcé | Sûr |
|---|:---:|:---:|:---:|
| 64 slots | ✅ `MAX_KEYS=64` | ✅ | ✅ |
| Quota 8 clés/owner | ✅ `MAX_KEYS_PER_OWNER=8` l.292 | ✅ | ✅ |
| TTL 300 s (`KEY_MAX_LIFETIME_TSC=9e11` @3GHz) | ✅ | ✅ (expire_check + on-access) | ✅ |
| Clés jamais exportées (handles opaques) | ✅ `get_key` retourne une **copie interne** | — | ✅ |
| `wipe_bytes` après usage (caller main.rs) | ✅ | — | ✅ |
| DoD 5220.22-M 3-pass shredding | ✅ `crypto_shred` (zeros/random/zeros) | — | ⚠️ |
| `rotate_key` HKDF-Blake3 (plus XOR+FNV) | ✅ l.458-459 `blake3::keyed_hash` + `derive_key` | — | ✅ |
| `revoke_key` / `rotate_key` / `expire_check` / `revoke_all_for_owner` / `revoke_all_pre_phoenix` | ✅ tous présents | — | ✅ |
| Contrôle owner CAP-01 | ✅ via `get_key` (owner check) | ⚠️ `revoke_key` interne ne check pas owner | ⚠️ |
| Brute-force slot indices | ✅ owner check bloque | — | ✅ |
| Constant-time compare | ❌ `!=` simple (l.357, 434, 573) | — | ❌ |
| PKS/TPM sealing | ❌ pas implémenté (isolation processus seule) | — | ❌ |
| Clés owner=0 (kernel) accessibles à tous | ⚠️ design choice | — | ⚠️ |

### 2.4 `tls.rs`

| Point | Implémenté | Enforcé | Sûr |
|---|:---:|:---:|:---:|
| X25519 éphémère CSPRNG (plus LCG) | ✅ `fill_random` → `secure_random` l.353 | — | ✅ |
| Cipher suite modern TLS 1.3 AEAD | ❌ suite custom `0xE701` (non IANA) | — | ❌ |
| Validation certificat chain | ❌ **JAMAIS appelée** dans handshake | — | ❌ CRIT |
| Pinning / anti self-signed MITM | ❌ aucun cert échangé | — | ❌ CRIT |
| Replay protection (transcript hash) | ❌ `handshake_hash` jamais mis à jour | — | ❌ |
| `recv_counter` / `send_counter` utilisés | ❌ jamais lus pour nonce/replay | — | ❌ |
| Fail-closed (pas de fallback faible) | ✅ suite unique refusée si ≠ 0xE701 | — | ✅ |
| Zeroization clés session (close/cleanup) | ✅ `shred_keys` | — | ✅ |
| Cleanup sessions expirées | ✅ `cleanup_expired_sessions` existe | ❌ **jamais appelée** | ❌ |
| Zeroization clé locale stack (encrypt/decrypt) | ❌ `key: [u8;32]` non wipe (l.594-632) | — | ❌ |

### 2.5 `pki.rs`

| Point | Implémenté | Enforcé | Sûr |
|---|:---:|:---:|:---:|
| Root CA priv key générée par CSPRNG (plus `[0u8;32]`) | ✅ l.963 `secure_random` | — | ✅ |
| Root priv key jamais exportée | ⚠️ en RAM processus (pas offline) | — | ⚠️ |
| `verify_strict` Ed25519 | ✅ l.693 | — | ✅ |
| Intermediate CA malveillant possible | ❌ si root key leak → forge totale | — | ⚠️ |
| Chain depth limit | ✅ `MAX_CHAIN_DEPTH=8` | — | ✅ |
| Algo complexity attack | ✅ O(N²) avec N≤8 | — | ✅ |
| Serial uniqueness | ❌ hardcoded `serial=1` pour root, pas d'API issue | — | ⚠️ |
| CRL check | ✅ `is_revoked` dans `verify_certificate` | — | ✅ |
| Revoked cert accepted | ✅ rejeté si dans CRL | — | ✅ |
| **pki_init appelée au boot** | ❌ **JAMAIS** (dead code) | — | ❌ CRIT |
| PKI utilisée par TLS | ❌ **JAMAIS** | — | ❌ CRIT |

---

## 3. Tableau des findings (trié par sévérité)

| ID | Severity | File:line | Résumé | Statut audit précédent |
|---|---|---|---|---|
| CRYPTOSRV-001 | **CRITICAL** | main.rs:921-923 | Bypass auth `PHOENIX_WAKE_ENTROPY` via bit 63 de `reply_endpoint` contrôlable par l'appelant → reseed XChaCha20 + `revoke_all_pre_phoenix` par tout userspace | Nouveau (PhoenixWakeEntropy marqué « NON wired » mais atteignable) |
| CRYPTOSRV-002 | **CRITICAL** | tls.rs:371-573 | TLS sans authentification du pair : ni cert envoyé, ni vérifié → MITM trivial sur tout tunnel inter-serveurs | Nouveau |
| CRYPTOSRV-003 | **CRITICAL** | main.rs:956-975 ; pki.rs:953 | `pki_init()` jamais appelée au boot ; PKI = 996 lignes de dead code ; `tls_verify_certificate` jamais invoquée | Nouveau (CAP-01 partiellement résolu mais la PKI réelle reste non-wired) |
| CRYPTOSRV-004 | **CRITICAL** | pki.rs:658, 986 | Root CA private key conservée en RAM du service (pas offline) → compromission processus = forge de toute la chaîne | Nouveau |
| CRYPTOSRV-005 | **HIGH** | xchacha20.rs:108-123 | `xchacha20_reseed` mélange l'entropie par XOR (pas HKDF-Blake3) ; couplé à CRYPTOSRV-001, un attaquant peut prédire le nouveau sel de nonce | Mandat « HKDF-Blake3 toutes rotations » contourné pour le reseed |
| CRYPTOSRV-006 | **HIGH** | tls.rs:171, 294-335 | `handshake_hash` jamais alimenté ; `client_random‖server_random` seul contexte HKDF → pas de binding transcript → swap/replay de messages handshake possible | Nouveau |
| CRYPTOSRV-007 | **HIGH** | tls.rs:181-183, 580-642 | `send_counter`/`recv_counter` jamais utilisés pour le nonce ni le replay check → rejeu d'enregistrements TLS indétecté | Nouveau |
| CRYPTOSRV-008 | **HIGH** | tls.rs:697-724 ; main.rs:999-1003 | `cleanup_expired_sessions` jamais appelée depuis la main loop → 16 sessions occupées = DoS permanent (CRYPTO_ERR_BUSY) | Nouveau |
| CRYPTOSRV-009 | **HIGH** | keystore.rs:229-253 | `crypto_shred` passe 2 utilise un LCG seedé par TSC (pas RDRAND comme commenté) ; commentaire menteur « RDRAND ou compteur mélangé » | Nouveau |
| CRYPTOSRV-010 | **HIGH** | tls.rs:594-598, 628-632 | Clé TLS `key: [u8;32]` copiée localement puis **non zeroized** après `tls_encrypt_record`/`tls_decrypt_record` → leak stack | Nouveau |
| CRYPTOSRV-011 | **HIGH** | xchacha20.rs:163-181 | Cipher `XChaCha20Poly1305` construit puis drop sans zeroization (pas de feature `zeroize`) → key schedule residuel sur stack | Nouveau |
| CRYPTOSRV-012 | **MEDIUM** | main.rs:596-613 | `CRYPTO_RANDOM` ne valide pas `r == n` (seulement `r >= 0`) → `data_len` peut sur-déclarer la taille d'aléa servi | Nouveau |
| CRYPTOSRV-013 | **MEDIUM** | keystore.rs:357, 434, 573 | Comparaisons owner non constant-time (`!=`) → timing side-channel sur principal ID | Architecture : « 43 unsafe sans SAFETY » connexe |
| CRYPTOSRV-014 | **MEDIUM** | keystore.rs:386-409 | `revoke_key` ne vérifie pas l'owner (s'appuie sur `get_key` côté main.rs) → risque si futur call site oublie le pre-check | Nouveau |
| CRYPTOSRV-015 | **MEDIUM** | pki.rs:803-814 | `validate_chain` fallback « issuer_id==0 ⇒ root » → si un attaquant inscrit un faux cert avec `issuer_id=[0;16]` dans le registry, il est accepté comme signé-par-root (mais `register_certificate` vérifie la signature d'abord, donc exige la root key) | Nouveau |
| CRYPTOSRV-016 | **MEDIUM** | tls.rs:88-99, 509-512 | Cipher suite `0xE701` non IANA, non interop TLS 1.3 réel ; dénomination « TLS 1.3 minimal » trompeuse | Nouveau |
| CRYPTOSRV-017 | **MEDIUM** | keystore.rs:355-358 | Clés owner=0 (kernel) accessibles à tout caller authentifié → si le kernel dérive une clé partagée, tout process peut l'utiliser | Nouveau |
| CRYPTOSRV-018 | **MEDIUM** | main.rs:71, 83, 96, 358, 963, 989 ; xchacha20.rs:62, 86 ; keystore.rs:210, 232 ; tls.rs:59, 225 ; pki.rs:640, 988 | **Aucun** bloc `unsafe` n'a de SAFETY contract (12+ sites) | Architecture : « 43 unsafe sans SAFETY contracts dans security/ » — toujours ouvert |
| CRYPTOSRV-019 | **MEDIUM** | keystore.rs:458-459, 478 ; main.rs:244-249 ; tls.rs:276-285 | Fonctions nommées `derive_key_hkdf` / `hkdf_expand` utilisent en réalité `blake3::keyed_hash`+`derive_key` (BLAKE3 KDF mode), **pas HKDF** ; crate `hkdf` déclarée mais jamais importée | Nouveau (architecture mandate HKDF-Blake3 — interprétable) |
| CRYPTOSRV-020 | **LOW** | xchacha20.rs:171-181 | Sur échec `encrypt_in_place_detached`, `out_buf` contient le plaintext XORé avec keystream (récupérable avec la clé) ; caller ne lit pas sur erreur mais défense en profondeur absente | Nouveau |
| CRYPTOSRV-021 | **LOW** | keystore.rs:556-563 | `is_valid_handle` ne vérifie pas l'owner → leak timing d'occupation des slots (1..64) | Nouveau |
| CRYPTOSRV-022 | **LOW** | pki.rs:978 | Serial root hardcodé `serial=1` ; aucune API d'émission → pas d'unicité garantie si future extension | Nouveau |
| CRYPTOSRV-023 | **LOW** | main.rs:395-401 | `phoenix_wake_entropy_from_request` lit l'entropie depuis `cap_token.bytes[0..8]` (= object_id) qui est normalement l'identité du caller — champ surchargé sémantiquement | Nouveau |
| CRYPTOSRV-024 | **LOW** | keystore.rs:265-330 | `insert_key` shred une entrée réutilisée même si elle était déjà `Revoked`/`Expired` (déjà shred à la révocation) → double shred inutile mais pas une vuln | Nouveau |
| CRYPTOSRV-025 | **LOW** | tls.rs:393-395 | Clé privée X25519 temporairement stockée dans `session.server_random[..32]` (hack de prod-to-do) ; si handshake abandonné, la clé privée survit jusqu'au cleanup | Commenté « en production, ceci sera dans un slot sécurisé du keystore » |

---

## 4. Détail des findings CRITIQUES et HIGH

### CRYPTOSRV-001 — Bypass authentification `PHOENIX_WAKE_ENTROPY` (CRITICAL)

**File:** `main.rs:563-574` + `main.rs:920-932`

```rust
// main.rs:563
let caller_principal = if req.msg_type == PHOENIX_WAKE_ENTROPY {
    0  // ← authorize_request() completely skipped
} else {
    match authorize_request(req) { ... }
};

// main.rs:920
PHOENIX_WAKE_ENTROPY => {
    let authenticated_kernel_wake =
        req.sender_pid == 0 || (req.reply_endpoint & KERNEL_EPHEMERAL_REPLY_BIT) != 0;
    if !authenticated_kernel_wake {
        reply.status = CRYPTO_ERR_CAP;
    } else if let Some(entropy) = phoenix_wake_entropy_from_request(req, payload) {
        xchacha20::xchacha20_reseed(entropy);
        let _ = keystore::revoke_all_pre_phoenix();
        reply.status = CRYPTO_OK;
    } ...
}
```

**Vulnérabilité :** `reply_endpoint` est un champ du `CryptoRequest` **fourni par l'appelant** (le client IPC le positionne pour indiquer où expédier la réponse). Le bit 63 (`KERNEL_EPHEMERAL_REPLY_BIT = 1u64 << 63`) est trivial à positionner par n'importe quel process userspace. `sender_pid == 0` est kernel-set (sûr), mais la seconde branche du OU court-circuite l'authentification.

**Scénario d'attaque concret :**
1. Un process malveillant (même non privilégié) envoie un `CryptoRequest` avec `msg_type = 255`, `reply_endpoint = 1<<63`, `payload[0..8] = entropy_attaquante`.
2. Aucun `cap_token` requis (le chemin `caller_principal = 0` bypass `authorize_request`).
3. `authenticated_kernel_wake` devient `true` via le bit 63.
4. `xchacha20_reseed(entropy_attaquante)` : le sel de nonce global est mélangé par XOR avec une valeur contrôlée par l'attaquant (cf. CRYPTOSRV-005). Si l'attaquant connaît l'ancien sel (par ex. via un leak précédent), il peut prédire le nouveau sel et donc l'espace de nonces futur — couplé à une clé compromise, **nonce reuse**.
5. `revoke_all_pre_phoenix()` détruit **toutes** les clés actives du keystore → DoS système global : tous les services qui ont délégué des clés (ExoFS volume keys, IPC channel keys, KEKs) perdent leur matériel instantanément.

**Audit précédent :** `01_architecture.md` ligne 41 indique « PhoenixWakeEntropy NON wired » (le kernel ne déclenche pas l'op automatiquement). Mais le handler est **reachable** par tout userspace via le bypass du bit 63. Le risque est donc pire que « non wired » : il est exploitable activement. **Ouvert.**

**Fix recommandé :**
- Supprimer la condition `(req.reply_endpoint & KERNEL_EPHEMERAL_REPLY_BIT) != 0` OU exiger que ce bit ne puisse être positionné que par le kernel (vérifier via un mécanisme kernel-set similaire à `sender_pid`).
- Exiger un `cap_token` spécifique de type `EXO_CAP_TYPE_PHOENIX` délivré uniquement au kernel.
- Mieux : que le kernel envoie `PHOENIX_WAKE_ENTROPY` uniquement sur un endpoint privé non exposé aux userspace, et que `crypto_server` valide `sender_pid == 0` strictement (sans OU).

---

### CRYPTOSRV-002 — TLS sans authentification du pair → MITM trivial (CRITICAL)

**File:** `tls.rs:371-573` (toutes les fonctions de handshake)

```rust
// tls_handshake_initiate (client) — l.371
pub fn tls_handshake_initiate(peer_pid: u32) -> (u32, [u8; 67]) {
    // Génère client_random + X25519 éphémère
    // Envoie : msg_type=1 || suite || client_random || client_public_key
    // AUCUNE signature, AUCUN certificat envoyé
}

// tls_handshake_respond (serveur) — l.500
pub fn tls_handshake_respond(client_hello: &[u8], peer_pid: u32) -> (u32, [u8; 67]) {
    // Vérifie suite == 0xE701
    // Génère server_random + X25519 éphémère
    // Calcule shared_secret = X25519(server_priv, client_pub)
    // Envoie : msg_type=2 || suite || server_random || server_public_key
    // AUCUNE signature du serveur, AUCUN certificat
}

// tls_handshake_complete_client — l.427
pub fn tls_handshake_complete_client(session_handle: u32, server_hello: &[u8]) -> bool {
    // Vérifie msg_type==2 et suite
    // Calcule shared_secret = X25519(client_priv, server_pub)
    // AUCUNE vérification que server_pub appartient au serveur attendu
}
```

**Vulnérabilité :** Le handshake est un **Diffie-Hellman anonyme**. Aucune des deux parties ne prouve son identité. La fonction `tls_verify_certificate` (l.675) existe mais n'est jamais appelée par les fonctions de handshake.

**Scénario d'attaque concret :**
1. Alice (client) initie un handshake vers Bob (serveur).
2. Mallory (MITM) intercepte le ClientHello d'Alice, envoie son propre ClientHello à Bob.
3. Bob répond à Mallory ; Mallory répond à Alice avec sa propre clé X25519 éphémère.
4. Deux sessions établies : Alice↔Mallory et Mallory↔Bob. Mallory voit tout le trafic en clair.
5. Comme il n'y a **aucune** vérification de certificat ou de pinning, Mallory n'a besoin d'aucune clé, juste de la capacité à intercepter l'IPC.

**Audit précédent :** Architecture « 2.1-b/c: PKI réelle + bootloader attestation » marqué OPEN. La PKI existe en code mais n'est pas branchée. **Toujours ouvert, aggravé.**

**Fix recommandé :**
- Brancher `tls_verify_certificate` dans `tls_handshake_complete_client` : le serveur DOIT envoyer un certificat leaf (signé par l'intermediate CA lui-même signé par root) et une signature Ed25519 du handshake transcript avec sa clé privée leaf.
- Côté serveur, authentifier le client symétriquement (mTLS) si l'architecture le requiert.
- Inclure le transcript hash dans la dérivation HKDF (cf. CRYPTOSRV-006).

---

### CRYPTOSRV-003 — `pki_init()` jamais appelée ; PKI = dead code (CRITICAL)

**File:** `main.rs:956-975` (`_start`), `pki.rs:953`, `tls.rs:675-678`

```rust
// main.rs _start — initialisation
xchacha20::xchacha20_init();
keystore::keystore_init();
tls::tls_init();
// ❌ AUCUN appel à pki::pki_init()

// tls.rs:675 — seul call site de pki_init dans tout le codebase
pub fn tls_verify_certificate(cert: &crate::pki::Certificate) -> bool {
    crate::pki::pki_init();  // lazy init, mais cette fonction n'est JAMAIS appelée
    crate::pki::verify_certificate(cert)
}
```

**Vulnérabilité :** Le module `pki.rs` (996 lignes) implémente une PKI complète (root CA, intermediate, leaf, CRL, registry, `verify_strict`) mais :
- `pki_init` n'est appelée que depuis `tls_verify_certificate` (tls.rs:676)
- `tls_verify_certificate` n'est **jamais** appelée depuis aucun handshake TLS (cf. CRYPTOSRV-002)
- `root_sign`, `validate_chain`, `revoke_certificate`, `unrevoke_certificate`, `register_certificate` ne sont jamais appelés depuis l'extérieur de `pki.rs`

Conséquence : la « PKI réelle » promise par l'architecture n'existe pas en runtime. Les certificats ne sont ni émis, ni vérifiés, ni révoqués. Tout le mécanisme de confiance inter-serveurs est absent.

**Audit précédent :** `01_architecture.md` « 2.1-b/c: PKI réelle + bootloader attestation » — **toujours ouvert, code présent mais inactif.**

**Fix recommandé :**
- Appeler `pki::pki_init()` dans `_start` après `tls::tls_init()`.
- Exposer une opération IPC `CRYPTO_PKI_ISSUE` / `CRYPTO_PKI_VERIFY` (avec cap token administrateur).
- Brancher `tls_verify_certificate` dans le handshake.

---

### CRYPTOSRV-004 — Root CA private key en RAM service (pas offline) (CRITICAL)

**File:** `pki.rs:654-665, 986`

```rust
/// Clé privée Root CA — générée par CSPRNG au boot, **jamais exportée** hors du
/// crypto_server (réside en mémoire isolée du service).
static ROOT_PRIVATE_KEY: spin::Once<[u8; 32]> = spin::Once::new();

pub fn root_sign(message: &[u8]) -> Option<[u8; SIGNATURE_SIZE]> {
    let key = ROOT_PRIVATE_KEY.get()?;
    Some(sign_data(key, message))  // ← root key used online pour signer
}
```

**Vulnérabilité :** Le commentaire d'en-tête du module (l.8) promet « Root CA : clé intégrée au binaire, signature hors-ligne uniquement ». En réalité :
- La clé root est **régénérée** à chaque boot via CSPRNG (l.962-965) — pas d'identité persistante.
- La clé root est **conservée en RAM** du service crypto_server (`ROOT_PRIVATE_KEY`).
- `root_sign` expose cette clé en ligne pour signer des intermediate CAs.

Toute compromission du process crypto_server (kernel exploit, memory disclosure, ExoPhoenix physical reload compromis) permet de forger **n'importe quel** certificat du système. Un CA root devrait être généré offline, scellé (TPM/PKS), et la clé privée ne devrait jamais résider en mémoire d'un service en ligne.

**Audit précédent :** Non mentionné explicitement. Le fix `FIX-SEC-2C-PKI` a corrigé le `[0u8;32]` mais a introduit ce nouveau risque architecturalement plus subtil.

**Fix recommandé :**
- Soit générer la root key offline, embarquer uniquement la root public key dans le binaire (const), et faire signer les intermediate CAs offline au build-time.
- Soit utiliser un KEK scellé TPM pour dériver une root key stable au boot, et **never** exposer `root_sign` en ligne — l'émission d'intermediate CAs doit être une opération administrative rare avec cap token dédié.

---

### CRYPTOSRV-005 — `xchacha20_reseed` mélange par XOR (pas HKDF-Blake3) (HIGH)

**File:** `xchacha20.rs:108-123`

```rust
pub fn xchacha20_reseed(entropy: u64) {
    if !XCHACHA_INITIALIZED.load(Ordering::Acquire) { xchacha20_init(); }
    let counter = NONCE_COUNTER.fetch_add(1_000_000, Ordering::AcqRel);
    let old_lo = NONCE_SALT_LO.load(Ordering::Acquire);
    let old_hi = NONCE_SALT_HI.load(Ordering::Acquire);
    let mixed_lo = old_lo ^ entropy ^ counter;           // ← XOR
    let mixed_hi = old_hi ^ entropy.rotate_left(17) ^ counter.rotate_left(31);  // ← XOR
    NONCE_SALT_LO.store(mixed_lo, Ordering::Release);
    NONCE_SALT_HI.store(mixed_hi, Ordering::Release);
}
```

**Vulnérabilité :** Le mandat crypto (`01_architecture.md` ligne 17) exige « HKDF-Blake3 (toutes rotations, remplace XOR+FNV) ». `rotate_key` dans keystore.rs respecte ce mandat (l.458-459), mais `xchacha20_reseed` utilise un simple XOR. L'entropie fournie est sur seulement **64 bits** (un `u64`), et le mélange XOR n'apporte aucune propriété cryptographique (pas de PRK, pas de diffusion).

Couplé à CRYPTOSRV-001 (attaquant peut appeler `xchacha20_reseed` avec entropy contrôlée), l'attaquant peut :
- Forcer `mixed_lo = old_lo ^ attacker_entropy ^ counter` — s'il connaît `old_lo` (par ex. via une fuite précédente), il prédit exactement le nouveau sel.
- Le sel ne sert qu'à l'unicité inter-sessions (le compteur monotone garantit l'unicité intra-session), donc l'impact direct est limité. Mais en combinaison avec une clé compromise, la prédiction du sel réduit l'entropie effective du nonce à celle du compteur seul.

**Fix recommandé :**
```rust
pub fn xchacha20_reseed(entropy: u64) {
    let mut material = [0u8; 32];
    material[..8].copy_from_slice(&NONCE_SALT_LO.load(Ordering::Acquire).to_le_bytes());
    material[8..16].copy_from_slice(&NONCE_SALT_HI.load(Ordering::Acquire).to_le_bytes());
    material[16..24].copy_from_slice(&entropy.to_le_bytes());
    material[24..32].copy_from_slice(&NONCE_COUNTER.fetch_add(1_000_000, Ordering::AcqRel).to_le_bytes());
    let prk = blake3::keyed_hash(&[0u8;32], &material);
    let new_salt = blake3::derive_key("Exo-OS xchacha20 reseed v1", prk.as_bytes());
    NONCE_SALT_LO.store(u64::from_le_bytes(new_salt[..8].try_into().unwrap()), Ordering::Release);
    NONCE_SALT_HI.store(u64::from_le_bytes(new_salt[8..16].try_into().unwrap()), Ordering::Release);
}
```

---

### CRYPTOSRV-006 — `handshake_hash` jamais alimenté ; pas de binding transcript (HIGH)

**File:** `tls.rs:171` (champ), `tls.rs:294-335` (`derive_traffic_keys`)

```rust
pub struct TlsSession {
    pub handshake_hash: [u8; 32],  // ← jamais écrit hors de new()
    ...
}

fn derive_traffic_keys(session: &mut TlsSession) {
    let mut full_context = [0u8; 64];
    full_context[..32].copy_from_slice(&session.client_random);
    full_context[32..64].copy_from_slice(&session.server_random);
    // ← full_context ne contient PAS handshake_hash ni les clés publiques échangées
    hkdf_expand(&session.shared_secret, b"derived", &full_context, &mut derived_secret);
    ...
}
```

**Vulnérabilité :** En TLS 1.3 réel, le key schedule dérive d'un `transcript_hash` qui couvre **tous** les messages de handshake (ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished). Ici, le contexte HKDF est uniquement `client_random ‖ server_random` — 64 octets aléatoires mais qui ne bindent **pas** les clés publiques X25519 échangées.

Un attaquant qui contrôle le canal peut substituer la clé publique X25519 du ServerHello (attaque de type « key compromise impersonation » si une clé est compromises ultérieurement), car `client_random` et `server_random` sont transmis en clair et le `shared_secret` est recalculé avec la clé publique de l'attaquant sans que le transcript le détecte.

**Fix recommandé :** Maintenir un `handshake_hash` incrémental via `blake3::Hasher`, update après chaque message handshake (ClientHello, ServerHello), et l'utiliser comme contexte HKDF.

---

### CRYPTOSRV-007 — Compteurs TLS `send_counter`/`recv_counter` jamais utilisés (HIGH)

**File:** `tls.rs:181-183`, `tls.rs:580-642`

```rust
pub struct TlsSession {
    pub send_counter: AtomicU64,  // ← set to 1 at handshake, never read for nonce
    pub recv_counter: AtomicU64,  // ← set to 1 at handshake, never read for replay check
    ...
}

pub fn tls_encrypt_record(session_handle: u32, data: &[u8], output: &mut [u8]) -> bool {
    // nonce vient de xchacha20::build_nonce() (compteur global)
    // send_counter n'est PAS utilisé
}

pub fn tls_decrypt_record(session_handle: u32, input: &[u8], plaintext: &mut [u8]) -> bool {
    // decrypt avec nonce reçu dans input[..24]
    // recv_counter n'est PAS vérifié → rejeu indétecté
}
```

**Vulnérabilité :** Le nonce de chiffrement vient du compteur global `NONCE_COUNTER` (xchacha20.rs), pas de `send_counter`. Les compteurs par-session sont stockés mais jamais utilisés. Conséquence : **aucune protection contre le rejeu d'enregistrements TLS**. Un attaquant qui capture un `tls_encrypt_record` output peut le rejouer indéfiniment — `tls_decrypt_record` l'acceptera à chaque fois (même nonce, même clé, même ciphertext = tag Poly1305 valide).

Le format d'enregistrement (`content_type[1] || counter[8] || encrypted[N] || tag[16]`, commentaire l.579) suggère que le `counter` devait être le sequence number, mais l'implémentation utilise `nonce[24]` à la place, sans recorder ce sequence number dans `recv_counter`.

**Fix recommandé :** Avant déchiffrement, extraire le sequence number du record, le comparer à `recv_counter`, rejeter si ≤. Incrémenter après succès.

---

### CRYPTOSRV-008 — `cleanup_expired_sessions` jamais appelée → DoS par épuisement du pool (HIGH)

**File:** `tls.rs:697-724`, `main.rs:999-1003`

```rust
// main.rs loop de réception IPC
if r == ETIMEDOUT {
    IPC_RECV_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    let _ = keystore::expire_check();  // ← appelé
    continue;                          // ← mais PAS tls::cleanup_expired_sessions()
}
```

```rust
// tls.rs:697 — fonction existe mais dead code
pub fn cleanup_expired_sessions() -> u32 { ... }
```

**Vulnérabilité :** Le pool TLS est de 16 sessions. `tls_handshake_initiate` et `tls_handshake_respond` ne réutilisent que les sessions `Closed`. Si 16 handshakes sont initiés et jamais fermés explicitement (client qui meurt sans `TLS_CLOSE`, ou attaquant qui ouvre 16 handshakes et déconnecte), toutes les sessions restent en état `Verified` ou `HandshakePending` indéfiniment. Tout handshake ultérieur échoue avec `CRYPTO_ERR_BUSY` (l.411).

**Scénario d'attaque :** Un process malveillant ouvre 16 handshakes TLS (via 16 IPC `CRYPTO_TLS_INIT`) sans jamais les fermer. Le crypto_server devient incapable d'établir de nouvelles sessions TLS pour **tous** les autres services légitimes — DoS permanent jusqu'au reboot du crypto_server.

**Fix recommandé :** Appeler `tls::cleanup_expired_sessions()` dans la branche `ETIMEDOUT` de la main loop, à côté de `keystore::expire_check()`.

---

### CRYPTOSRV-009 — `crypto_shred` passe 2 : LCG seedé TSC, commentaire menteur (HIGH)

**File:** `keystore.rs:223-253`

```rust
/// Shredding cryptographique 3 passes :
///   Passe 2 : écrire des octets aléatoires (via RDRAND si disponible)
fn crypto_shred(buf: &mut [u8; KEY_SIZE]) {
    // Passe 1 : zéros ✓
    // Passe 2 : pseudo-aléatoire (RDRAND ou compteur mélangé)  ← commentaire
    let mut seed: u64 = read_tsc();
    for b in buf.iter_mut() {
        // xoshiro256** minimal : mélange rapide  ← faux, c'est un LCG
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let val = (seed ^ (seed >> 25)) as u8;
        unsafe { core::ptr::write_volatile(b, val) };
    }
    // Passe 3 : zéros ✓
}
```

**Vulnérabilités :**
1. Le commentaire prétend « RDRAND ou compteur mélangé » — il n'y a **aucun** appel à RDRAND. Le seed est `read_tsc()` uniquement.
2. L'algorithme prétendu « xoshiro256** minimal » est en réalité un **LCG** (Linear Congruential Generator) sur 64 bits, avec extraction du seul octet bas `as u8`. Un LCG est prédictible et inversible.
3. Le seed `read_tsc()` est observable par l'attaquant (instructions `rdtsc` non privilégiées) — si l'attaquant peut mesurer le TSC au moment du shredding, il peut reconstituer le flux LCG et théoriquement distinguer des résidus magnétiques (sur stockage persistant, pas sur RAM moderne).

Sur RAM moderne, le DoD 5220.22-M 3-pass est **déjà** superflu (une seule passe suffit pour la RAM), mais la fausse promesse « RDRAND » est un problème de documentation de sécurité. Sur SSD/flash (si crypto_server déverse des clés sur disque, ce qui n'est pas le cas ici), le LCG predictable serait un vrai problème.

**Fix recommandé :** Soit utiliser `secure_random` pour la passe 2 (cohérent avec le reste), soit supprimer la passe 2 et documenter explicitement « RAM-only, single-pass volatile zeroization suffices per NIST SP 800-88 Rev.1 ».

---

### CRYPTOSRV-010 — Clé TLS locale non zeroized après `tls_encrypt_record`/`tls_decrypt_record` (HIGH)

**File:** `tls.rs:594-611`, `tls.rs:628-641`

```rust
pub fn tls_encrypt_record(session_handle: u32, data: &[u8], output: &mut [u8]) -> bool {
    ...
    let key: [u8; 32] = if session.flags & TLS_ROLE_SERVER != 0 {
        session.server_write_key   // ← copie locale sur la stack
    } else {
        session.client_write_key
    };
    drop(pool);
    ...
    crate::xchacha20::xchacha20_seal(&key, data, &aad, &mut nonce, &mut output[24..]);
    // ← key est drop ici SANS zeroization
    true
}
```

**Vulnérabilité :** La clé de trafic TLS est copiée sur la stack (`let key: [u8; 32]`) pour libérer le lock du pool. Après l'opération, `key` est drop sans zeroization. La stack frame peut être réutilisée par un appel ultérieur, laissant la clé résiduelle lisible via une vulnérabilité de lecture stack (kernel exploit, infoleak ultérieur).

Le keystore et main.rs utilisent `wipe_bytes` systématiquement, mais tls.rs ne le fait pas pour ces clés locales.

**Fix recommandé :**
```rust
let mut key: [u8; 32] = ... ;
// ... opération ...
crate::xchacha20::xchacha20_seal(&key, ...);
// zeroize avant retour
for b in key.iter_mut() { unsafe { core::ptr::write_volatile(b, 0) }; }
core::sync::atomic::fence(Ordering::SeqCst);
```

---

### CRYPTOSRV-011 — `XChaCha20Poly1305` cipher non zeroized on drop (HIGH)

**File:** `xchacha20.rs:163-181`, `xchacha20.rs:210-228`

```rust
pub fn xchacha20_seal(...) -> usize {
    let cipher = match XChaCha20Poly1305::new_from_slice(key) {
        Ok(c) => c,  // ← contient le key schedule étendu (8x u32 state)
        Err(_) => return 0,
    };
    ...
    // cipher drop sans zeroization
}
```

**Vulnérabilité :** Le type `XChaCha20Poly1305` de la crate `chacha20poly1305` contient un état interne `chacha20::State` (8 × u32 = 32 octets dérivés de la clé). Lorsque `cipher` est drop, cet état n'est zeroized que si la feature `zeroize` est activée sur la crate. Le `Cargo.toml` (l.23) déclare `chacha20poly1305.workspace = true` sans feature explicite — il faut vérifier le workspace `Cargo.toml`.

Même si la clé d'origine est wipe par le caller (`wipe_bytes(&mut key)` dans main.rs), le **key schedule étendu** reste résiduel sur la stack jusqu'à réutilisation de la frame.

**Fix recommandé :** Activer la feature `zeroize` sur `chacha20poly1305` dans le workspace (et idem pour `blake3`, `ed25519-dalek`, `x25519-dalek`). Vérifier :
```
chacha20poly1305 = { version = "...", features = ["zeroize"] }
```

---

## 5. Verdict

### Le `crypto_server` fonctionne-t-il comme une autorité cryptographique sécurisée ?

**NON — des primitives cryptographiques solides sont noyées dans une architecture d'autorité défaillante.**

**Points forts (résolus depuis les audits précédents) :**
- ✅ Aucune crypto from-scratch : tout via `blake3`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek` (mandat SRV-CRYPTO-01 respecté).
- ✅ Ed25519 `verify_strict` partout (main.rs:344, pki.rs:693) — anti-malléabilité et anti-clés-faibles.
- ✅ `getrandom_u64` : 16 tentatives CSPRNG + repli explicite documenté (plus de LCG caché).
- ✅ X25519 éphémère via `secure_random` (plus de LCG seedé TSC).
- ✅ Root CA key générée par CSPRNG (plus de `[0u8;32]`).
- ✅ `rotate_key` utilise `blake3::keyed_hash`+`derive_key` (plus de XOR+FNV).
- ✅ AEAD XChaCha20-Poly1305 : encrypt-then-MAC correct, nonce counter monotone.
- ✅ Keystore : 64 slots, quota 8/owner, TTL 300s, shredding DoD 3-pass, contrôle owner.
- ✅ `authorize_request` appelé sur 16 des 17 ops (CAP-01 partiellement résolu).
- ✅ Bounds checking IPC rigoureux, pas de `unwrap`/`expect` panic-prone sur les paths crypto.

**Défaillances majeures (CRITICAL) :**
- ❌ **CRYPTOSRV-001** : `PHOENIX_WAKE_ENTROPY` est **reachable par tout userspace** via le bit 63 de `reply_endpoint` — bypass complet de `authorize_request`. Permet de forcer un reseed XChaCha20 contrôlé par l'attaquant **et** de détruire toutes les clés actives (`revoke_all_pre_phoenix`). DoS global instantané + risque de prédiction de sel de nonce.
- ❌ **CRYPTOSRV-002** : TLS = Diffie-Hellman **anonymme**, aucune authentification du pair, aucun certificat vérifié → **MITM trivial** sur tout tunnel inter-serveurs.
- ❌ **CRYPTOSRV-003** : La PKI (996 lignes) est du **dead code** — `pki_init` jamais appelée au boot, `tls_verify_certificate` jamais invoquée. L'architecture promet une « PKI réelle » qui n'existe pas en runtime.
- ❌ **CRYPTOSRV-004** : Root CA private key en RAM du service (pas offline) — compromotion process = forge de toute la chaîne. Contredit la doc d'en-tête du module.

**Défaillances significatives (HIGH) :**
- ❌ Reseed XChaCha20 par XOR (pas HKDF-Blake3) — contournement du mandat.
- ❌ `handshake_hash` jamais alimenté — pas de binding transcript.
- ❌ Compteurs TLS `send_counter`/`recv_counter` jamais utilisés — **pas de protection rejeu**.
- ❌ `cleanup_expired_sessions` jamais appelée — **DoS par épuisement du pool 16 sessions**.
- ❌ `crypto_shred` passe 2 : LCG seedé TSC avec commentaire menteur « RDRAND ».
- ❌ Clés TLS locales + cipher `XChaCha20Poly1305` non zeroized sur stack.

**Conclusion :** Les primitives cryptographiques individuelles sont correctes et les fixes précédents (`FIX-SEC-2C`, `FIX-DEEP-CRYPTO`, `FIX-SEC-2C-PKI`, `FIX-SEC-2C-TLS`) ont éliminé les faiblesses cryptographiques directes (clés tout-zéros, LCG, `verify` non-strict). **Mais l'architecture d'autorité reste défaillante** :
1. Le bypass `PHOENIX_WAKE_ENTROPY` (CRYPTOSRV-001) permet à tout userspace de détruire le keystore — inacceptable pour une « autorité ».
2. Le TLS n'authentifie personne (CRYPTOSRV-002) — inacceptable pour un « TLS 1.3 ».
3. La PKI est inerte (CRYPTOSRV-003) — inacceptable pour une « PKI réelle ».

Le `crypto_server` actuel est **une bibliothèque crypto correcte dans un service d'autorité non fiable**. Il ne peut pas être considéré comme une autorité cryptographique sécurisée tant que CRYPTOSRV-001/002/003 ne sont pas résolus.

---

## 6. Actions prioritaires recommandées (tri)

| Priorité | Finding | Action |
|---|---|---|
| P0 | CRYPTOSRV-001 | Restreindre `PHOENIX_WAKE_ENTROPY` à `sender_pid == 0` strict ; supprimer le OU sur `reply_endpoint & bit63` |
| P0 | CRYPTOSRV-002 | Brancher `tls_verify_certificate` + signature Ed25519 du transcript dans le handshake TLS |
| P0 | CRYPTOSRV-003 | Appeler `pki::pki_init()` dans `_start` ; exposer `CRYPTO_PKI_ISSUE`/`CRYPTO_PKI_VERIFY` via IPC |
| P0 | CRYPTOSRV-004 | Soit root key offline embarquée (const pub key), soit scellée TPM/PKS |
| P1 | CRYPTOSRV-008 | Appeler `tls::cleanup_expired_sessions()` dans la main loop |
| P1 | CRYPTOSRV-007 | Utiliser `recv_counter` pour anti-rejeu dans `tls_decrypt_record` |
| P1 | CRYPTOSRV-006 | Maintenir `handshake_hash` cumulatif et l'inclure dans `derive_traffic_keys` |
| P1 | CRYPTOSRV-005 | Remplacer le XOR mixing de `xchacha20_reseed` par `blake3::derive_key` |
| P1 | CRYPTOSRV-010/011 | Zeroizer clés TLS locales + activer feature `zeroize` sur `chacha20poly1305` |
| P2 | CRYPTOSRV-009 | Soit `secure_random` pour passe 2 de `crypto_shred`, soit single-pass documenté NIST SP 800-88 |
| P2 | CRYPTOSRV-012 | `CRYPTO_RANDOM` doit valider `r == n` (utiliser `secure_random`) |
| P2 | CRYPTOSRV-013 | Comparaisons owner constant-time via `subtle::ConstantTimeEq` ou équivalent |
| P2 | CRYPTOSRV-018 | Ajouter SAFETY contracts à tous les blocs `unsafe` |
| P3 | CRYPTOSRV-016/019/022/023/024/025 | Documentation, nommage, cleanup mineur |

**Fin du rapport Task 06.**
