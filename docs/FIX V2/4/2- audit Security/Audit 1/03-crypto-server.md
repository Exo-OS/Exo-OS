# Audit Cryptographique Profond — crypto_server (ExoOS Service SRV-04)

**Task ID:** AUDIT-3-CRYPTO-SERVER
**Périmètre:** `servers/crypto_server/src/{main.rs, keystore.rs, pki.rs, tls.rs, xchacha20.rs}` (5 fichiers, 3 613 lignes)
**Méthode:** Lecture intégrale de chaque fichier `.rs` en périmètre + analyse ligne-par-ligne contre classes de vulnérabilités TLS/PKI/keystore connues (Heartbleed, POODLE, Lucky13, Bleichenbacher, 3SHAKE, SLOTH, Logjam, DROWN, ROBOT, ALPACA, RFC 5280, RFC 7748 §6, RFC 8446, NIST SP 800-38D, FIPS 140-3).
**Date:** 2026-06-21
**Auditeur:** claude-auditeur (cryptographe/TLS/PKI/KMS)

---

## Résumé exécutif

Le `crypto_server` est le service Ring 1 central d'ExoOS : tous les autres serveurs y délèguent crypto, TLS, PKI et keystore via IPC. Les **primitives cryptographiques de base** s'appuient correctement sur les crates RustCrypto validées (`ed25519-dalek` avec `verify_strict` confirmé, `x25519-dalek`, `chacha20poly1305`, `blake3`, `hkdf`) — aucune implémentation from-scratch. L'**hygiène cryptographique bas niveau** (zeroization `write_volatile`, fence `SeqCst`, verify-before-decrypt) est globalement respectée.

Cependant, l'audit profond révèle **deux failles CRITICAL d'architecture** qui annulent les garanties annoncées :

1. **Le "TLS 1.3" implémenté n'est pas TLS** : pas de certificats, pas de `Finished`, pas de `CertificateVerify`, pas de binding du transcript. Le champ `handshake_hash` est défini mais **jamais utilisé**. Un MITM actif peut substituer les clés publiques X25519 à l'aveugle. Le protocole est un ECDH non-authentifié incorrectement étiqueté TLS 1.3.

2. **Les sessions TLS ne sont JAMAIS liées à leur propriétaire** (`caller_principal`) : `tls_encrypt_record`/`tls_decrypt_record` prennent un `session_handle` séquentiel (1..16) sans vérifier l'ownership. N'importe quel serveur Ring 1 disposant de `EXO_CAP_RIGHT_IPC_SEND` vers l'endpoint 4 peut chiffrer/déchiffrer sur la session TLS de n'importe quel autre serveur. Confiance multi-tenant rompue.

S'y ajoutent une **bypass d'authentification** sur `PHOENIX_WAKE_ENTROPY` (bit 63 du `reply_endpoint` non enforced par le kernel → réseed + révocation de toutes les clés par n'importe qui), une **absence de rejet du shared secret X25519 nul** (RFC 7748 §6.1 — contraste avec le kernel crypto qui le fait), un **DoS trivial via épuisement des 4 `VerifyContext`** (jamais nettoyés), et une **PKI non-initialisée au boot** (`pki_init` n'est jamais appelée depuis `_start`).

| # | Sévérité | Catégorie | Sujet | Fichier:Ligne |
|---|----------|-----------|-------|---------------|
| 1 | **CRITICAL** | ISOLATION/CRYPTO | Cross-tenant TLS session hijack (handles séquentiels, pas d'ownership) | `tls.rs:580,615` + `main.rs:489,514` |
| 2 | **CRITICAL** | ISOLATION/CVE | Authentication bypass sur `PHOENIX_WAKE_ENTROPY` (bit 63 non enforced) | `main.rs:920-931` |
| 3 | **CRITICAL** | CRYPTO/CVE | "TLS 1.3" non-authentifié — pas de Finished, pas de CertificateVerify, `handshake_hash` jamais utilisé → MITM trivial | `tls.rs:294-335,427-573` |
| 4 | **CRITICAL** | CRYPTO/CVE | Pas de rejet du shared secret X25519 nul (RFC 7748 §6.1) — low-order point attack | `tls.rs:340-344` |
| 5 | **CRITICAL** | ISOLATION/DoS | `VerifyContext` DoS : 4 slots seulement, jamais nettoyés, pas de timeout | `main.rs:186,255-351` |

**Score maturité crypto_server : 3.5 / 10**

La base cryptographique (crates RustCrypto, zeroization, derive_key) est correcte, mais la couche **protocolaire** (TLS, PKI, IPC authorization) est défaillante à un point tel que les garanties annoncées (forward secrecy, confidentiality inter-serveurs, anti-MITM, anti-replay) ne sont **pas assurées**. Le code ressemble à TLS par son nom, pas par sa sécurité. Un travail de refonte protocolaire (~5 j-h) est nécessaire pour atteindre 7/10.

---

## 0. Cartographie du service (5 fichiers, 3 613 LOC)

| Fichier | LOC | Rôle |
|---------|-----|------|
| `main.rs` | 1 017 | Entry point `_start()`, boucle IPC `SYS_EXO_IPC_RECV`, dispatcher `handle_request`, structs `CryptoRequest`/`CryptoReply`, `VerifyContext` (streaming verify), `authorize_request` (cap check), `phoenix_wake_entropy_from_request`, panics |
| `keystore.rs` | 632 | `KEY_TABLE[64]` statique avec `KeyEntry` (clé, type, flags, TSC, usage, owner, génération), `insert_key`/`get_key`/`revoke_key`/`rotate_key`, `crypto_shred` DoD 5220.22-M 3 passes, expiration TSC |
| `pki.rs` | 996 | Hiérarchie Root/Intermediate/Leaf, `Certificate`, `CertificateChain`, `CRL[64]`, `CERT_REGISTRY[32]`, `verify_certificate`, `validate_chain`, `pki_init` (génère root au boot), `root_sign` |
| `tls.rs` | 739 | "TLS 1.3" custom : handshake 2-msg (ClientHello/ServerHello 67 octets), X25519 ECDHE, derive_traffic_keys BLAKE3, `tls_encrypt_record`/`tls_decrypt_record` via XChaCha20-Poly1305, pool `SESSION_POOL[16]` |
| `xchacha20.rs` | 229 | Wrapper `chacha20poly1305` crate, `build_nonce` (compteur AtomicU64 + sel 16 octets), `xchacha20_seal`/`xchacha20_open`, `xchacha20_reseed` (Phoenix) |

**Dépendances crates** (Cargo.toml lignes 22-26) : `blake3`, `chacha20poly1305`, `ed25519-dalek`, `x25519-dalek`, `hkdf` + `exo-syscall-abi`. Aucune implémentation crypto from-scratch — conforme à la règle `SRV-CRYPTO-01` du Cargo.toml. ✅

---

## 1. `tls.rs` (739 lignes) — "TLS 1.3" non-authentifié

### 1.1 Conformité TLS 1.3 (RFC 8446)

| Aspect RFC 8446 | Statut | Détail |
|-----------------|--------|--------|
| Version TLS 1.3 (legacy_version 0x0303 + supported_versions extension) | ❌ | Aucun champ version dans ClientHello/ServerHello (format custom `msg_type[1] || suite[2] || random[32] || pub[32]`, 67 octets) |
| Negotiation cipher suites (ClientHello.suites, ServerHello.suite) | ⚠️ | Suite unique hardcoded `0xE701` (XChaCha20-BLAKE3) — pas de négociation réelle |
| HelloRetryRequest (RFC 8446 §4.1.4) | ❌ | Non implémenté |
| Key Share extension (X25519) | ⚠️ | Inline dans le Hello (pas d'extension TLS standard) |
| **Finished message** (HMAC over transcript, RFC 8446 §4.4.4) | ❌ | **ABSENT** — pas de MAC de fin de handshake |
| **CertificateVerify** (signature du transcript par le serveur, §4.4.3) | ❌ | **ABSENT** — pas d'authentification du serveur |
| **Certificate message** (§4.4.2) | ❌ | **ABSENT** — `tls_verify_certificate` existe mais n'est **jamais appelé** dans le flux de handshake |
| **Transcript hash** (HKDF-Expand-Label base, §7.1) | ❌ | Champ `handshake_hash` défini `tls.rs:171` mais **JAMAIS UPDATE ni UTILISÉ** |
| Key schedule (early_secret → handshake_secret → master_secret, §7.1) | ❌ | Dérivation ad-hoc en une étape `tls.rs:294` |
| **Downgrade protection** (RFC 8446 §4.1.3 + RFC 7627) | ❌ | Aucun mécanisme |
| **0-RTT replay protection** (§8) | ⚠️ | "Pas de 0-RTT" affiché — donc N/A, mais pas de mechanism pour le détecter si activé |
| **Renegotiation** (RFC 5746 — TLS 1.2 only) | N/A | TLS 1.3 n'a pas de renégociation ; OK |
| **ALPN** (RFC 7301) | ❌ | Non implémenté |
| **SNI** (RFC 6066) | ❌ | Non implémenté |
| Record layer (ContentType + legacy_version + length, §5.1) | ❌ | Format custom `nonce[24] || ct || tag[16]` — pas de header record TLS |
| **Sequence number** dans le nonce (§5.3 : nonce = IV ⊕ seq) | ❌ | Nonce vient du compteur global `build_nonce()`, pas de l'IV par session |
| Alert protocol (§6) | ❌ | Aucune alerte structurée |
| **Heartbeat / Heartbleed (CVE-2014-0160)** | N/A | Pas de heartbeat → pas vulnérable |
| **CBC mode / Lucky 13** | N/A | AEAD uniquement → pas vulnérable |
| **Compression / CRIME / BREACH** | N/A | Pas de compression → pas vulnérable |
| **Bleichenbacher (PKCS1v1.5 RSA)** | N/A | Ed25519 uniquement → pas vulnérable |
| **3SHAKE (CVE-2014-1265)** | ❌ | Le binding du transcript (qui empêche 3SHAKE) est absent — cf finding #3 |
| **SLOTH (signature hash collision)** | N/A | Ed25519 (pas de hash negotiation) → pas vulnérable |
| **DROWN (SSLv2 cross-protocol)** | N/A | Pas de SSLv2 → pas vulnérable |
| **ROBOT (Bleichenbacher variant)** | N/A | Pas de RSA → pas vulnérable |
| **ALPACA (cross-protocol SNI mismatch)** | N/A | Pas de SNI/ALPN → pas vulnérable (mais pas de fonctionnalité non plus) |

**Verdict RFC 8446 :** le protocole implémenté n'est **pas TLS 1.3**. C'est un protocole custom ECDHE-then-symmetric avec un wire format incompatible. L'étiquette "TLS 1.3" dans le doc-comment du fichier (`tls.rs:1-23`) est trompeuse.

### 1.2 Vulnérabilités identifiées

#### 🔴 CS-TLS-01 [CRITICAL, ISOLATION] — Cross-tenant TLS session hijack

**Fichier:** `tls.rs:580` (`tls_encrypt_record`), `tls.rs:615` (`tls_decrypt_record`), `main.rs:489` (`tls_encrypt_reply`), `main.rs:514` (`tls_decrypt_reply`)

**Code problématique :**
```rust
// tls.rs:580
pub fn tls_encrypt_record(session_handle: u32, data: &[u8], output: &mut [u8]) -> bool {
    if session_handle == 0 || session_handle as usize > MAX_SESSIONS {
        return false;
    }
    let idx = (session_handle - 1) as usize;
    let pool = SESSION_POOL.lock();
    let session = &pool[idx];
    if !session.is_active() { return false; }
    // ... AUCUNE vérification que l'appelant est le propriétaire de la session
    let key: [u8; 32] = if session.flags & TLS_ROLE_SERVER != 0 { ... };
    ...
}
```

Et côté IPC (`main.rs:489-512`) :
```rust
fn tls_encrypt_reply(payload: &[u8], reply: &mut CryptoReply) {
    let Some(session_handle) = read_u32_le(payload, 0) else { ... };
    ...
    if tls::tls_encrypt_record(session_handle, data, &mut output) { ... }
}
```

**Problème :**
1. `session_handle` est un entier séquentiel `1..=16` (`(idx + 1) as u32`, `tls.rs:380,519`). Aucun secret, aucune randomisation.
2. `handle_request` authentifie le `caller_principal` via `authorize_request` (cap check `EXO_CAP_RIGHT_IPC_SEND` vers l'endpoint 4), mais ce check ne garantit pas que le caller possède la session TLS référencée.
3. Le `peer_pid` est stocké dans la session (`tls.rs:185,405,560`) mais **jamais vérifié** dans `tls_encrypt_record` / `tls_decrypt_record` / `tls_close`.

**Exploitation :**
- Tout serveur Ring 1 légitime (vfs_server, network_server, exo_shield, …) dispose d'une capability `IPC_SEND` vers le crypto_server.
- Le server A initie une session TLS → reçoit `session_handle = 1`.
- Le server B (compromis ou malveillant) appelle `CRYPTO_TLS_ENCRYPT { session_handle = 1, data = "evil" }` → le crypto_server chiffre "evil" avec la clé de session de A et retourne le ciphertext.
- Le server B appelle `CRYPTO_TLS_DECRYPT { session_handle = 1, input = <ciphertext intercepté de A> }` → obtient le plaintext de A.

**Impact :** Confidentialité et intégrité TLS complètement rompues entre tenants Ring 1. Un seul serveur compromis peut lire/écrire le trafic "TLS" de tous les autres.

**Contournement trivial :** pas besoin d'exploit mémoire — il suffit d'avoir la capability IPC standard de n'importe quel serveur Ring 1.

**Correction recommandée :**
```rust
// Ajouter un champ owner_principal: AtomicU64 dans TlsSession (TLS session table)
pub struct TlsSession { ..., pub owner_principal: AtomicU64, ... }

// Dans tls_handshake_initiate et tls_handshake_respond, accepter caller_principal
// et le stocker. Dans tls_encrypt_record / tls_decrypt_record :
pub fn tls_encrypt_record(
    session_handle: u32,
    caller_principal: u64,
    data: &[u8], output: &mut [u8]) -> bool {
    ...
    let owner = session.owner_principal.load(Ordering::Acquire);
    if owner != 0 && owner != caller_principal { return false; }
    ...
}
// Et faire propager caller_principal par main.rs::tls_encrypt_reply / tls_decrypt_reply.
```

---

#### 🔴 CS-TLS-02 [CRITICAL, CRYPTO] — Handshake non-authentifié, MITM trivial

**Fichier:** `tls.rs:294-335` (`derive_traffic_keys`), `tls.rs:427-493` (`tls_handshake_complete_client`), `tls.rs:500-573` (`tls_handshake_respond`)

**Code problématique :**
```rust
// tls.rs:171
pub handshake_hash: [u8; 32],   // DÉFINI

// Recherche grep "handshake_hash" → JAMAIS UPDATE ni LU dans le fichier
// (uniquement initialisé à [0u8; 32] dans TlsSession::new et zeroed dans shred_keys)
```

```rust
// tls.rs:294 — dérivation des clés
fn derive_traffic_keys(session: &mut TlsSession) {
    let mut full_context = [0u8; 64];
    full_context[..32].copy_from_slice(&session.client_random);
    full_context[32..64].copy_from_slice(&session.server_random);
    hkdf_expand(&session.shared_secret, b"derived", &full_context, &mut derived_secret);
    ...
}
```

**Problème :**
1. Le transcript hash (`handshake_hash`) n'est jamais calculé ni incorporé dans la dérivation des clés de trafic.
2. Les clés sont dérivées uniquement de `shared_secret || client_random || server_random` — pas du tout du contenu des Hello messages.
3. Il n'y a **pas de `Finished` message** : ni le client ni le serveur ne prouvent qu'ils possèdent les clés dérivées en signant/MACant le transcript.
4. Il n'y a **pas de `CertificateVerify`** : le serveur ne signe jamais le transcript avec sa clé privée Ed25519 (pourtant disponible via `pki::root_sign`).
5. `tls_verify_certificate` (ligne 675) est défini mais **jamais appelé** depuis le flux de handshake (grep : 0 appel dans `tls_handshake_*`).
6. Aucun message d'authentification n'est échangé : un attaquant qui intercepte le ClientHello peut substituer sa propre clé X25519 publique, initier un handshake parallèle avec le serveur, et relayer les messages. Les deux côtés dérivent des clés distinctes que l'attaquant connaît.

**Exploitation (MITM classique) :**
```
Client ──ClientHello(pub_C)──▶ MITM ──ClientHello(pub_M1)──▶ Server
Client ◀─ServerHello(pub_M2)── MITM ◀─ServerHello(pub_S)── Server
```
- MITM calcule `shared_CM1 = DH(priv_M1, pub_C)` avec le client (clé côté client).
- MITM calcule `shared_M2S = DH(priv_M2, pub_S)` avec le serveur (clé côté serveur).
- Toutes les clés dérivées côté client utilisent `shared_CM1`; toutes les clés côté serveur utilisent `shared_M2S`. Le MITM connaît les deux.
- **Aucun mécanisme dans le protocole ne détecte l'attaque** (pas de Finished, pas de CertificateVerify, pas de transcript hash).

**Impact :** Confidentialité et intégrité "TLS" nulles face à un attaquant actif sur le canal IPC/network. Pour un service qui se veut être le **bastion cryptographique central** d'ExoOS, c'est une faille structurelle.

**Correction recommandée (refonte minimale) :**
1. Mettre à jour `handshake_hash` à chaque message (BLAKE3 incremental).
2. Ajouter un message `CertificateVerify` : le serveur signe `handshake_hash` avec sa clé Ed25519 (via `pki::root_sign` ou un cert leaf signé par l'Intermediate).
3. Ajouter un message `Finished` (les deux côtés) : HMAC-BLAKE3 sur `handshake_hash` avec la clé dérivée.
4. Vérifier le `CertificateVerify` avant de passer à l'état `Verified` (échec → `TlsState::Error`).

---

#### 🔴 CS-TLS-03 [CRITICAL, CRYPTO/CVE] — Pas de rejet du shared secret X25519 nul (RFC 7748 §6.1)

**Fichier:** `tls.rs:340-344`

**Code problématique :**
```rust
fn x25519_dh(private_key: &[u8; 32], public_key: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(*public_key);
    secret.diffie_hellman(&public).to_bytes()   // ❌ pas de check zéro
}
```

**Problème :**
- RFC 7748 §6.1 impose de rejeter les shared secrets tous-zéros (et plus généralement, de détecter les points d'ordre faible).
- L'audit AUDIT-2 (kernel crypto) a confirmé que le **kernel** effectue ce check (`x25519.rs` kernel). Mais le `crypto_server` ne le fait **pas**.
- Un pair malveillant peut envoyer une clé publique X25519 d'ordre faible (points de petite courbe twist, ou point d'identité) pour forcer `shared_secret = [0u8; 32]`. L'attaquant connaît alors la totalité du key schedule.

**Exploitation :**
- L'attaquant envoie `client_public = [0u8; 32]` (ou un autre point d'ordre faible) dans le ClientHello.
- Le serveur calcule `shared_secret = x25519_dh(server_priv, [0;32]) = [0;32]` (avec forte probabilité).
- L'attaquant peut dériver toutes les clés de trafic côté serveur (il connaît `shared_secret = 0`, `client_random` et `server_random` qu'il a capturés).
- L'attaquant déchiffre tout le trafic serveur→client.

**Impact :** Compromission complète de la session TLS par un pair malveillant. Critique car le protocole est utilisé pour l'authentification inter-serveurs (où les deux pairs sont supposés être des serveurs légitimes — mais un seul serveur compromis suffit).

**Correction recommandée :**
```rust
fn x25519_dh(private_key: &[u8; 32], public_key: &[u8; 32]) -> Option<[u8; 32]> {
    let secret = StaticSecret::from(*private_key);
    let public = PublicKey::from(*public_key);
    let shared = secret.diffie_hellman(&public).to_bytes();
    // RFC 7748 §6.1 — reject all-zero shared secret (constant-time)
    let mut nz: u8 = 0;
    for b in shared.iter() { nz |= b; }
    if nz == 0 { None } else { Some(shared) }
}
// Et propager l'Option<...> dans tls_handshake_complete_client / tls_handshake_respond :
//   match x25519_dh(...) { Some(ss) => session.shared_secret = ss, None => { session.state = Error; return false; } }
```

---

#### 🟠 CS-TLS-04 [HIGH, ISOLATION/DoS] — `cleanup_expired_sessions` jamais appelée + leak de clé privée X25519 dans sessions abandonnées

**Fichier:** `tls.rs:697` (définition), `main.rs` (recherche d'appel → 0 résultat)

**Code problématique :**
```rust
// tls.rs:697 — fonction définie
pub fn cleanup_expired_sessions() -> u32 { ... }

// main.rs — la boucle IPC (ligne 988-1010) appelle seulement keystore::expire_check()
// sur timeout IPC (5s). cleanup_expired_sessions n'est JAMAIS appelée.
```

```rust
// tls.rs:393-395 — stockage de la clé privée X25519 dans server_random
// Stocker la clé privée temporairement dans server_random (sera écrasé)
// Note : en production, ceci sera dans un slot sécurisé du keystore
session.server_random[..32].copy_from_slice(&private_key);
```

**Problème :**
1. La fonction `cleanup_expired_sessions` existe (shred + reset des sessions dépassant 60s d'inactivité), mais n'est jamais invoquée par `_start()` ou `handle_request`.
2. Une session cliente en état `HandshakePending` (ClientHello envoyé, ServerHello jamais reçu) reste dans le pool **indéfiniment**.
3. Cette session contient la **clé privée X25519 du client** dans `server_random[..32]` (jusqu'à ce que le handshake complete et écrase server_random).
4. Le pool `MAX_SESSIONS = 16` : 16 handshakes clients abandonnés → plus aucune nouvelle session possible → **DoS permanent** (résolution : reboot uniquement).

**Impact :**
- DoS durable : 16 connections initiées et abandonnées = service TLS mort.
- Leak de clés privées X25519 en mémoire (persistent jusqu'à slot reuse, qui n'arrive jamais sans cleanup).
- Forward secrecy affaiblie : si l'attaquant capture le ClientHello + dump mémoire de la session abandonnée, il peut recalculer les clés.

**Correction recommandée :**
```rust
// Dans la boucle IPC (main.rs:1001), appeler aussi tls::cleanup_expired_sessions() :
if r == ETIMEDOUT {
    IPC_RECV_TIMEOUTS.fetch_add(1, Ordering::Relaxed);
    let _ = keystore::expire_check();
    let _ = tls::cleanup_expired_sessions();   // ← AJOUTER
    continue;
}
// Et idéalement, appeler aussi cleanup à chaque itération (pas seulement sur timeout),
// ou utiliser un timer dédié.
```

**Bonus :** ne pas stocker la clé privée X25519 dans server_random (qui est un champ sémantiquement destiné à autre chose). Ajouter un champ `ephemeral_private: [u8; 32]` séparé, ou utiliser le keystore.

---

#### 🟠 CS-TLS-05 [HIGH, CRYPTO] — HKDF-Extract utilise un salt fixe tout-zéro + key schedule non conforme à RFC 8446

**Fichier:** `tls.rs:276-285` (`hkdf_expand`), `tls.rs:294-335` (`derive_traffic_keys`)

**Code problématique :**
```rust
fn hkdf_expand(secret: &[u8], label: &[u8], context: &[u8], output: &mut [u8]) {
    let salt = [0u8; 32];                                          // ❌ salt fixe
    let prk = blake3::keyed_hash(&salt, secret);                  // ❌ "extract" avec salt=0
    let mut hasher = blake3::Hasher::new_keyed(prk.as_bytes());   // expand ad-hoc
    hasher.update(b"ExoOS TLS 1.3 traffic secret");
    hasher.update(label);
    hasher.update(context);
    let mut reader = hasher.finalize_xof();
    reader.fill(output);
}
```

**Problèmes :**
1. **Salt HKDF-Extract fixe `[0u8; 32]`** : la phase "extract" est déterministe étant donné le shared secret. Pas de "early secret" salé par une valeur pré-shared (PSK) ou par du bruit. En TLS 1.3, `early_secret = HKDF-Extract(0, PSK)` puis `handshake_secret = HKDF-Extract(Derive-Secret(early_secret, "derived", ""), ECDHE)`. Ici, tout est réduit à une seule étape `keyed_hash(0, shared_secret)`.
2. **Aucune séparation de domaine stricte** entre les labels : `b"derived"`, `b"c ws"`, `b"s ws"`, `b"c wi"`, `b"s wi"` sont juste concaténés. RFC 8446 impose `HKDF-Expand-Label(Secret, Label, Context, Length)` avec un format binaire strict (length || "tls13 " || label || context). Sans cela, des collisions de label entre protocoles sont possibles (cf. [SLOTH-like attacks](https://www.ietf.org/archive/id/draft-ietf-tls-md5-sha1-deprecate-01.txt)).
3. **Pas de `Derive-Secret` final** pour binder le transcript (cf. CS-TLS-02) : les clés ne dépendent pas de l'intégrité du handshake.
4. **`blake3::keyed_hash(salt, secret)` n'est pas HKDF-Extract** : c'est un MAC en mode keyed. La fonction de compression BLAKE3 n'est pas équivalente à HKDF-Extract en terme de propriétés cryptographiques (pas de preuve de sécurité équivalente à [RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869)).
5. **`finalize_xof().fill(output)`** : la sortie XOF est correcte pour un expand, mais sans domain separation entre les différentes clés dérivées (chacune appelle `hkdf_expand` indépendamment avec le même `prk` — pas de chaînage).

**Impact :** Les clés dérivées ne bénéficient pas des garanties de sécurité de RFC 8446 key schedule. En combinaison avec CS-TLS-02 (pas de transcript binding), un attaquant peut potentiellement réaliser des [cross-protocol attacks](https://eprint.iacr.org/2015/1047) si le même `shared_secret` est utilisé dans un autre protocole.

**Correction recommandée :** utiliser le crate `hkdf` (déjà en dépendance Cargo.toml ligne 26 mais **jamais utilisé** dans le code !) avec BLAKE3 en HMAC, ou implémenter un key schedule à 3 niveaux (early/handshake/master secret) conforme à RFC 8446 §7.1.

---

#### 🟠 CS-TLS-06 [HIGH, CRYPTO] — Record AAD réduit à 1 byte (pas de seq num, pas de longueur)

**Fichier:** `tls.rs:593` (encrypt), `tls.rs:640` (decrypt)

**Code problématique :**
```rust
// tls.rs:593
let aad = [ContentType::ApplicationData as u8];   // 1 byte : 0x17
// Le sealed record est : nonce[24] || ciphertext || tag[16]
// L'AAD ne contient PAS : record sequence number, length, version, content_type réel
```

**Problèmes :**
1. **Pas de sequence number dans l'AAD** : un attaquant peut **réordonner** les records sans détection. Le `recv_counter` est stocké dans la session mais jamais utilisé pour le nonce ou l'AAD.
2. **Pas de length dans l'AAD** : vulnérabilité au [truncation attack](https://www.usenix.org/legacy/events/sec01/full_papers/dean/dean_html/index.html) — un attaquant peut tronquer un message chiffré sans détection.
3. **Pas de version/content-type dans l'AAD** : vulnérabilité cross-protocol si le même key material est réutilisé.
4. **`recv_counter` jamais incrémenté** (grep `recv_counter.fetch_add` → 0 match) : aucune détection de replay.

**Correction recommandée :**
```rust
// AAD conforme à TLS 1.3 record layer (simplifié) :
//   seq_num[8] || content_type[1] || length[2]
let mut aad_buf = [0u8; 11];
let seq = session.send_counter.fetch_add(1, Ordering::SeqCst);
aad_buf[..8].copy_from_slice(&seq.to_be_bytes());
aad_buf[8] = ContentType::ApplicationData as u8;
aad_buf[9..11].copy_from_slice(&(data.len() as u16).to_be_bytes());
let aad = &aad_buf;
// Et en decrypt : vérifier seq == recv_counter attendu, reject sinon.
```

---

#### 🟡 CS-TLS-07 [MEDIUM, LEAK] — `shred_keys` n'efface pas `client_random`

**Fichier:** `tls.rs:223-246`

**Code problématique :**
```rust
fn shred_keys(&mut self) {
    for b in self.shared_secret.iter_mut() { unsafe { core::ptr::write_volatile(b, 0) }; }
    for b in self.client_write_key.iter_mut() { ... }
    for b in self.server_write_key.iter_mut() { ... }
    for b in self.client_write_iv.iter_mut() { ... }
    for b in self.server_write_iv.iter_mut() { ... }
    for b in self.handshake_hash.iter_mut() { ... }
    for b in self.server_random.iter_mut() { ... }
    // ❌ client_random JAMAIS zeroized
    core::sync::atomic::fence(Ordering::SeqCst);
}
```

**Problème :** `client_random` participe à la dérivation des clés de trafic (`derive_traffic_keys` ligne 299 : `full_context[..32].copy_from_slice(&session.client_random);`). Bien que ce ne soit pas une clé, c'est un input cryptographique sensible. Si la session est fermée et le slot réutilisé, l'ancien `client_random` reste jusqu'à écrasement par le nouveau handshake. En cas de dump mémoire, l'attaquant peut recalculer les anciennes clés.

**Correction :** ajouter `for b in self.client_random.iter_mut() { unsafe { core::ptr::write_volatile(b, 0) }; }` dans `shred_keys`.

---

#### 🟡 CS-TLS-08 [MEDIUM, LEAK] — Stockage de la clé privée X25519 dans `server_random` (anti-pattern)

**Fichier:** `tls.rs:393-395` (client side), `tls.rs:533-546` (server side)

**Code problématique (commentaire in-code) :**
```rust
// Stocker la clé privée temporairement dans server_random (sera écrasé)
// Note : en production, ceci sera dans un slot sécurisé du keystore
session.server_random[..32].copy_from_slice(&private_key);
```

**Problèmes :**
1. **Anti-pattern sémantique** : utiliser un champ nommé `server_random` pour stocker une clé privée est un bugwaiting to happen. N'importe quel refactor futur pourrait introduire une corruption.
2. **Commentaire "en production"** avoue le caractère temporaire du code — mais le code est en production (audit de release).
3. La clé privée est **couplée** au cycle de vie de `server_random` : si le handshake échoue après ce point, la clé privée persiste (cf. CS-TLS-04).
4. Aucun `mlock` sur la page contenant cette clé (cf. CS-KS-03).

**Correction :** ajouter un champ dédié `ephemeral_private_key: [u8; 32]` dans `TlsSession`, le zeroizer dans `shred_keys`, et l'effacer dès que le `shared_secret` est calculé (pas seulement à la fermeture).

---

#### 🟡 CS-TLS-09 [MEDIUM, CRYPTO] — `derive_traffic_keys` n'efface pas les buffers intermédiaires `client_iv_buf` / `server_iv_buf`

**Fichier:** `tls.rs:324-329`

```rust
let mut client_iv_buf = [0u8; IV_SIZE];
let mut server_iv_buf = [0u8; IV_SIZE];
hkdf_expand(&derived_secret, b"c wi", &full_context, &mut client_iv_buf);
hkdf_expand(&derived_secret, b"s wi", &full_context, &mut server_iv_buf);
session.client_write_iv.copy_from_slice(&client_iv_buf);
session.server_write_iv.copy_from_slice(&server_iv_buf);
// ❌ client_iv_buf / server_iv_buf ne sont pas zeroizées (stack)
```

**Problème :** stack-copies des IV restent en mémoire jusqu'à écrasement. Mineur car IVs ne sont pas secrets en soi (le `nonce` est public), mais en défense en profondeur, ces buffers dérivés d'un secret méritent zeroization.

**Note :** `derived_secret` est correctement zeroizée (ligne 332-334). ✅

---

### 1.3 Points positifs confirmés (tls.rs)

- ✅ **X25519 clamping** appliqué via `StaticSecret::from` (x25519-dalek).
- ✅ **Forward secrecy structurelle** : clés X25519 éphémères par handshake, privées effacées après DH (`tls.rs:477-480, 543-546`).
- ✅ **Zeroization `write_volatile` + SeqCst fence** dans `shred_keys`.
- ✅ **Aucune compression** → pas vulnérable CRIME/BREACH.
- ✅ **Aucune cipher CBC** → pas vulnérable Lucky13/POODLE.
- ✅ **Aucune RSA PKCS1v1.5** → pas vulnérable Bleichenbacher/ROBOT/DROWN.
- ✅ **Aucun Heartbeat** → pas Heartbleed (CVE-2014-0160).
- ✅ Suite unique AEAD (`XChaCha20-BLAKE3`) → pas de downgrade cipher.
- ✅ `cleanup_expired_sessions` existe (mais n'est pas appelée — cf. CS-TLS-04).

---

## 2. `pki.rs` (996 lignes) — PKI non-initialisée + CA privée persistante

### 2.1 Conformité PKI (RFC 5280)

| Aspect RFC 5280 | Statut | Détail |
|-----------------|--------|--------|
| Cert structure (TBSCertificate + sigAlg + sig) | ⚠️ | Format custom (cert_id, issuer_id, subject_id, public_key, signature, validity, type, caps, serial). Pas de X.509 mais structure cohérente. |
| **Serial number randomness** (§4.1.2.2 : ≥ 20 bits entropy) | ❌ | `root_cert.serial = 1` hardcoded (`pki.rs:978`). `u32` seulement (4 octets — insuffisant). |
| Validity period (not_before / not_after) | ✅ | Implémenté en TSC. |
| Signature algorithm (Ed25519) | ✅ | Pas de MD5/SHA1. |
| **Key size** | ✅ | Ed25519 (≈ RSA 3072 / ECDSA P-256). Pas de RSA. |
| **Self-signed root handling** | ⚠️ | Root auto-signé mais **régénéré à chaque boot** (CS-PKI-01). |
| **Chain validation complète** | ⚠️ | `validate_chain` vérifie signatures + hiérarchie + caps, mais la recherche d'émetteur parcoure `CERT_REGISTRY` (32 slots max) ou la chaîne elle-même. Pas de mécanisme pour résoudre un émetteur absent. |
| **OCSP / Online revocation** | ❌ | Non implémenté. |
| **CRL** | ⚠️ | Statique, 64 entries, `is_revoked` match sur `serial` uniquement (pas issuer) — cf. CS-PKI-04. |
| **Certificate Transparency (RFC 6962)** | ❌ | Non implémenté. |
| **Pinning** | ❌ | Non implémenté. |
| **Cert path validation (RFC 5280 §6)** | ⚠️ | Simplifié : pas de vérification des policies, pas de name chaining, pas de basic constraints check. |

### 2.2 Vulnérabilités identifiées

#### 🔴 CS-PKI-01 [CRITICAL, INTEGRITY] — `pki_init` jamais appelée au boot → PKI non-initialisée

**Fichier:** `main.rs:955-975` (`_start`), `pki.rs:953` (`pki_init`)

**Code problématique :**
```rust
// main.rs:955 — _start
pub extern "C" fn _start() -> ! {
    boot_log(b"crypto_server: boot\n");
    xchacha20::xchacha20_init();
    keystore::keystore_init();
    tls::tls_init();
    // ❌ PAS DE pki::pki_init() !
    ...
}
```

```rust
// pki.rs:953
pub fn pki_init() { ... }   // jamais appelée depuis _start

// tls.rs:676 — seule invocation
pub fn tls_verify_certificate(cert: &crate::pki::Certificate) -> bool {
    crate::pki::pki_init();   // lazy init
    crate::pki::verify_certificate(cert)
}
// Mais tls_verify_certificate n'est JAMAIS appelée par le flux de handshake TLS !
```

**Problème :**
1. `pki_init()` n'est jamais appelée au boot du crypto_server.
2. Par conséquent, `ROOT_PRIVATE_KEY` et `ROOT_CERTIFICATE` (tous deux `spin::Once`) restent non initialisés.
3. `CERT_REGISTRY` reste vide.
4. Toute vérification de certificat (`verify_certificate`) pour un cert non-root (issuer_id ≠ 0) retourne `false` car la recherche d'émetteur échoue (`pki.rs:762-765` : "Émetteur inconnu").
5. `tls_verify_certificate` est la seule fonction qui appelle `pki_init` — mais elle-même n'est jamais appelée par `tls_handshake_*` (cf. CS-TLS-02).
6. Résultat : **la PKI est totalement inactive au runtime**.

**Impact :**
- Tout certificat non-root est refusé (fail-closed, mais fail par défaut).
- L'authentification par certificat inter-serveurs est non-fonctionnelle.
- Si un futur code path appelle `tls_verify_certificate`, le premier appel initialise la PKI (génère un root aléatoire) — mais ce root n'est pas persistant (CS-PKI-02) ni connu des autres serveurs.

**Correction recommandée :**
```rust
// main.rs:_start — ajouter :
pub extern "C" fn _start() -> ! {
    boot_log(b"crypto_server: boot\n");
    xchacha20::xchacha20_init();
    keystore::keystore_init();
    pki::pki_init();      // ← AJOUTER
    tls::tls_init();
    ...
}
```

---

#### 🔴 CS-PKI-02 [CRITICAL, CRYPTO/INTEGRITY] — Root CA private key régénérée à chaque boot, jamais persistée → aucun certificat n'est valide cross-boot

**Fichier:** `pki.rs:958-995` (`pki_init`)

**Code problématique :**
```rust
// pki.rs:962
let mut root_priv = [0u8; 32];
if !crate::secure_random(&mut root_priv) { return; }
let root_signing_key = SigningKey::from_bytes(&root_priv);
// ... root cert auto-signé avec root_priv ...
ROOT_PRIVATE_KEY.call_once(|| root_priv);   // stocké en statique
```

**Problèmes :**
1. **Contradiction avec la doc** : le commentaire de module (`pki.rs:7-9`) dit "Root CA : clé intégrée au binaire, signature hors-ligne uniquement". Le code génère une clé **fraîche aléatoire à chaque boot** — aucun lien avec une "clé intégrée au binaire".
2. **Aucune persistance** : la clé root n'est pas sauvegardée sur disque (pas de KEK, pas de secure storage). Après reboot, l'ancienne root est perdue, tous les certs qu'elle a signés deviennent invérifiables.
3. **Aucune coordination inter-serveurs** : chaque boot génère une root différente. Le crypto_server d'un boot ne peut pas vérifier les certs générés par lui-même au boot précédent, ni les certs générés par d'autres instances.
4. **Commentaire "FIX-SEC-2C-PKI : clé privée racine = CSPRNG kernel"** avoue que c'est un fix de sécurité (remplacement d'une root `[0u8;32]`), mais la solution choisie (régénérer à chaque boot) **détruit la sémantique PKI**.

**Impact :** La PKI est inutilisable pour son objectif déclaré (authentification inter-serveurs persistante). Tous les services dépendants qui croient vérifier un cert signé par le root font en réalité échouer la vérification (root différente).

**Correction recommandée :**
- Soit intégrer une clé root publique dans le binaire (clé privée hors-ligne, signant un cert intermédiaire stocké dans le binaire, lui-même signant les certs feuilles au runtime).
- Soit persister la root key dans un secure storage (TPM, ou fichier chiffré par fscrypt avec KEK Argon2id).
- Soit admettre que la PKI est "per-boot ephemeral" et ne pas l'utiliser pour de l'authentification persistante.

---

#### 🟠 CS-PKI-03 [HIGH, CRYPTO/LEAK] — Root CA private key jamais zeroizée, vit en mémoire statique

**Fichier:** `pki.rs:658` (`static ROOT_PRIVATE_KEY: spin::Once<[u8; 32]>`), `pki.rs:986` (`call_once`)

**Code problématique :**
```rust
static ROOT_PRIVATE_KEY: spin::Once<[u8; 32]> = spin::Once::new();
// ...
// pki.rs:986
ROOT_PRIVATE_KEY.call_once(|| root_priv);   // stocké pour toujours
// La pile locale root_priv est zeroizée (lignes 987-990), mais pas la copie statique.
```

**Problèmes :**
1. La clé privée root est stockée dans une `spin::Once<[u8; 32]>` statique, **jamais effacée** pendant toute la durée de vie du process.
2. Tout dump mémoire (panic handler, cold boot, DMA, /proc/mem) expose la clé root.
3. Aucun `mlock` sur la page contenant cette clé (cf. CS-KS-03).
4. La clé root permet de **forger n'importe quel certificat intermédiaire** → compromission totale de la PKI si leakée.

**Note :** la copie locale `root_priv` sur la pile est correctement zeroizée (`pki.rs:987-990`). Le problème est la persistance dans la statique.

**Correction recommandée :**
- Charger la clé root uniquement au moment de signer (pas en permanence).
- Idéalement, la root key ne devrait pas être en ligne (offline CA) — cf. CS-PKI-02.
- Si elle doit être en ligne, la wrapper par un KEK dérivé via Argon2id (comme fscrypt) et ne dé-wrapper que lors d'une opération de signature.

---

#### 🟠 CS-PKI-04 [HIGH, LOGIC] — `is_revoked` matche uniquement sur `serial`, pas sur issuer → faux positifs cross-CA

**Fichier:** `pki.rs:889-898`

**Code problématique :**
```rust
pub fn is_revoked(serial: u32) -> bool {
    let crl = CRL.lock();
    let count = CRL_COUNT.load(Ordering::Acquire) as usize;
    for i in 0..count.min(CRL_MAX_ENTRIES) {
        if crl[i].active != 0 && crl[i].serial == serial {   // ❌ pas d'issuer
            return true;
        }
    }
    false
}
```

**Problème :**
- RFC 5280 §5.3.2 : un serial de cert est unique **par émetteur**, pas globalement. Deux certs de deux CAs différentes peuvent partager le même serial.
- Ici, `is_revoked(serial)` ne filtre pas par issuer. Si la CA A révoque le serial 42, alors tout cert de la CA B avec serial 42 est aussi considéré révoqué.
- Combiné avec CS-PKI-05 (serial `u32` seulement 4 octets), un attaquant peut forger un cert avec un serial déjà révoqué pour le faire rejeter (DoS), ou au contraire exploiter la collision pour révoquer le cert d'un tiers.

**Correction :** changer la signature pour `is_revoked(issuer_id: &[u8; CERT_ID_SIZE], serial: u32)` et matcher les deux.

---

#### 🟡 CS-PKI-05 [MEDIUM, CRYPTO] — Serial de certificat limité à `u32` (4 octets), root serial hardcoded `1`

**Fichier:** `pki.rs:131` (`pub serial: u32`), `pki.rs:978` (`root_cert.serial = 1`)

**Problème :**
- RFC 5280 §4.1.2.2 recommande au moins 20 bits d'entropie, en pratique 64-128 bits aléatoires.
- Ici `serial: u32` = 4 octets = 32 bits. Couvre le minimum RFC, mais sans randomité (le root est `1`, les autres certs ne sont pas créés dans le code audité).
- Permet à un attaquant de brute-forcer le serial d'un cert cible en 2^32 tentatives max pour le collision-revoke (CS-PKI-04).

**Correction :** `serial: [u8; 16]` (128 bits) généré via `secure_random`.

---

#### 🟡 CS-PKI-06 [MEDIUM, LOGIC] — `register_certificate` accepte un cert déjà vérifié mais sans vérifier la chaîne d'émission (TOCTOU)

**Fichier:** `pki.rs:917-950`

**Code problématique :**
```rust
pub fn register_certificate(cert: &Certificate) -> bool {
    if !verify_certificate(cert) { return false; }   // vérif standalone
    // ❌ Pas de vérification que cert est signé par un issuer PRÉSENT DANS LE REGISTRE
    //    (verify_certificate cherche dans CERT_REGISTRY, mais à ce moment, l'issuer
    //    pourrait ne pas y être encore → return false → pas de registre)
    ...
}
```

**Problème :** `register_certificate` appelle `verify_certificate` qui lui-même cherche l'émetteur dans `CERT_REGISTRY`. Si l'ordre d'enregistrement est : feuille d'abord, puis intermédiaire, la feuille sera rejetée (issuer inconnu). Il faut enregistrer root → intermediate → leaf dans cet ordre. Pas de mécanisme garantissant cet ordre.

---

#### 🟡 CS-PKI-07 [MEDIUM, ISOLATION] — `CERT_REGISTRY` limité à 32 entrées, pas de LRU

**Fichier:** `pki.rs:670-673`

```rust
static CERT_REGISTRY: spin::Mutex<[Option<Certificate>; 32]> = ...;
```

Si 32 certs sont enregistrés et tous actifs (None n'est jamais remis), tout nouveau cert est rejeté (`register_certificate` retourne `false`). Pas d'éviction LRU. DoS possible par 32 enregistrements de certs "poubelle".

---

#### 🟡 CS-PKI-08 [MEDIUM, CRYPTO] — `validate_chain` ne vérifie pas le `not_before` / `not_after` de chaque cert individuellement

**Fichier:** `pki.rs:773-830`

`validate_chain` appelle `verify_certificate(cert)` pour chaque cert, qui vérifie l'expiration. ✅ Mais la hiérarchie (Root > Intermediate > Leaf) est vérifiée seulement pour `i > 0` (ligne 818), pas pour `i == 0`. Si le premier cert (leaf) est un Root, aucun check n'empêche une chaîne `[Root, Intermediate, Leaf]` ordonnée incorrectement.

### 2.3 Points positifs confirmés (pki.rs)

- ✅ **`verify_strict` Ed25519** confirmé (`pki.rs:693`) — anti-malléabilité + anti low-order keys.
- ✅ **Ed25519 uniquement** — pas de MD5/SHA1/RSA faible.
- ✅ **CRL implémentée** (basic) — revocation effective.
- ✅ **Capabilities bitmap** sur certs — granularité des droits.

---

## 3. `keystore.rs` (632 lignes) — Keys en clair, pas de KEK, pas de mlock

### 3.1 Conformité KMS / key management

| Aspect KMS | Statut | Détail |
|-----------|--------|--------|
| **Stockage chiffré au repos** (KMS-like) | ❌ | `KEY_TABLE[64]` en clair dans la mémoire du process. Pas de KEK, pas d'encryption-at-rest. |
| **Master key derivation** (HSM-like) | ❌ | `KeyType::Master` et `KeyType::Kek` existent dans l'enum mais **jamais utilisés** spécifiquement. |
| **Access control par capability** | ⚠️ | `owner_principal` check via `caller_principal`. Mais fail-open pour `owner==0` (CS-KS-04). |
| **Audit log des opérations sur clés** | ❌ | Aucun logging. Grep `audit|log_key|trace_op` → 0 match. |
| **Key rotation** | ✅ | `rotate_key` implémenté. |
| **Key versioning** | ❌ | `generation` counter mais pas d'historique. Ancien key material perdu après rotation (CS-KS-06). |
| **Zeroization des clés en mémoire** | ✅ | `crypto_shred` 3 passes (mais PRNG faible — CS-KS-03). |
| **mlock sur pages contenant des clés** | ❌ | Aucun `mlock`/`MAP_LOCKED`/`VM_LOCKED`. Grep global → 0 match. |
| **Anti-extraction** (pas de dump possible) | ❌ | Pas de mécanisme anti memory dump. |
| **Per-process key isolation** | ⚠️ | `owner_principal` mais bypass owner=0 (CS-KS-04). |
| **TOCTOU sur opérations** | ✅ | `KEY_TABLE.lock()` est tenu pendant toute la durée des opérations critiques. |
| **Pas de logging de clés** | ✅ | Aucun log ne contient de matériel clé. |
| **Wrapping des clés (KEK)** | ❌ | Pas de wrapping. |

### 3.2 Vulnérabilités identifiées

#### 🔴 CS-KS-01 [CRITICAL, ISOLATION] — `get_key` fail-open pour `owner == 0` : keys kernel world-readable

**Fichier:** `keystore.rs:355-358`

**Code problématique :**
```rust
// keystore.rs:355
// Vérifier le propriétaire (0 = kernel, accès toujours autorisé)
let owner = entry.owner_principal.load(Ordering::Acquire);
if owner != 0 && owner != caller_principal {
    return None;
}
```

**Problème :**
- Si `owner == 0` (kernel-owned key), le check `owner != 0` court-circuite et **n'importe quel `caller_principal`** peut récupérer la clé.
- Le commentaire dit "0 = kernel, accès toujours autorisé" — c'est une fausse sécurité. Le kernel n'est pas sensé appeler le keystore via IPC (il a ses propres primitives crypto).
- Une clé insérée avec `owner_principal = 0` (par exemple via un code path qui omet de le passer, ou via `derive_key_hkdf` si le caller est kernel-impersonating) devient world-readable.
- Combiné avec CS-PHOENIX-01 (auth bypass), un attaquant pourrait insérer une clé avec `owner = 0` puis la récupérer pour n'importe quel principal.

**Exploitation :**
1. Attaquant compromise un serveur Ring 1 (n'importe lequel).
2. Insère une clé via `CRYPTO_DERIVE_KEY` — clé est enregistrée avec `owner_principal = caller_principal` (non-zero, OK).
3. Pour récupérer une clé kernel-owned, l'attaquant a besoin qu'une telle clé existe. Vérifions : `derive_key_hkdf` est appelée dans `CRYPTO_DERIVE_KEY` avec `caller_principal` du caller — `owner_principal = caller_principal`, jamais 0 dans ce flux.
4. **Mais** : si un futur code path insère une clé avec `owner_principal = 0` (par exemple une master key kernel), elle devient immédiatement world-readable. Le bug est latent.

**Impact :** fail-open pour keys kernel-owned. Latent aujourd'hui, mais pattern dangereux.

**Correction :**
```rust
let owner = entry.owner_principal.load(Ordering::Acquire);
if owner == 0 {
    // Kernel-owned keys ne doivent PAS être accessibles via IPC.
    // Le kernel a ses propres primitives crypto.
    return None;
}
if owner != caller_principal {
    return None;
}
```

---

#### 🟠 CS-KS-02 [HIGH, CRYPTO/LEAK] — Keys stockées en clair en mémoire, pas de KEK wrapping

**Fichier:** `keystore.rs:91-108` (`KeyEntry`), `keystore.rs:131-196` (`KEY_TABLE`)

**Code problématique :**
```rust
struct KeyEntry {
    key: [u8; KEY_SIZE],    // ❌ 32 octets en clair
    ...
}
static KEY_TABLE: Mutex<[KeyEntry; MAX_KEYS]> = ...;
```

**Problème :**
- Toutes les clés sont stockées en plaintext dans `KEY_TABLE`.
- Le doc-comment du module dit "Stockage sécurisé des clés dérivées. Les clés ne quittent JAMAIS ce processus." — mais "ce processus" peut être dumpé (panic, cold boot, DMA, /proc/mem).
- `KeyType::Kek` (Key Encryption Key) et `KeyType::Master` existent dans l'enum mais ne sont **jamais utilisés** pour wrapping. Les clés de type `Kek` sont stockées de la même façon que les clés `Derived`.
- Pas de HSM-like isolation : la master key devrait être en ROM/TPM, jamais en RAM.

**Impact :** Memory dump → toutes les clés actives (jusqu'à 64 × 32 = 2 KB) exposées en clair.

**Correction (architecture):**
1. Générer une Master Key au boot via SYS_GETRANDOM (avec reseed post-Phoenix).
2. Wrapper chaque clé insérée avec `XChaCha20-Poly1305(MasterKey, nonce, key)` → stocker `ciphertext` au lieu de `key`.
3. Mlocker la page contenant la Master Key.
4. La Master Key ne sort jamais du keystore module.

---

#### 🟠 CS-KS-03 [HIGH, CRYPTO/LEAK] — Pas de `mlock` sur les pages contenant du matériel cryptographique

**Fichier:** tous (grep global `mlock|MAP_LOCKED|VM_LOCKED|secret_mlock` → 0 match)

**Problème :**
- Aucune page n'est lockée en RAM.
- Si ExoOS implémente le swap (à venir), les clés peuvent être écrites sur disque.
- Les clés peuvent être exfiltrées via :
  - Cold boot attack (DRAM retention).
  - DMA via IOMMU bypass (cf. AUDIT-8 finding #5 sur NIC IOMMU bypass).
  - Memory dump post-panic (le panic handler ne shred pas les keys — cf. CS-IPC-07).
- Le kernel crypto audit (AUDIT-2) n'a pas non plus trouvé de mlock, mais le kernel gère ses propres pages. Le crypto_server est en Ring 1 et dépend du memory_server pour le mlock.

**Correction :** appeler `SYS_MLOCK(addr, len)` sur les pages contenant `KEY_TABLE`, `ROOT_PRIVATE_KEY`, `SESSION_POOL`, `VERIFY_TABLE`. (Nécessite un syscall mlock exposé par le memory_server — à vérifier dans AUDIT-7.)

---

#### 🟠 CS-KS-04 [HIGH, CRYPTO] — `crypto_shred` "random pass" utilise un LCG seedé TSC (PRNG prédictible)

**Fichier:** `keystore.rs:229-253`

**Code problématique :**
```rust
fn crypto_shred(buf: &mut [u8; KEY_SIZE]) {
    // Passe 1 : zéros
    for b in buf.iter_mut() { unsafe { core::ptr::write_volatile(b, 0x00) }; }
    core::sync::atomic::fence(Ordering::SeqCst);

    // Passe 2 : pseudo-aléatoire (RDRAND ou compteur mélangé)
    let mut seed: u64 = read_tsc();   // ❌ seed TSC prédictible
    for b in buf.iter_mut() {
        // xoshiro256** minimal : mélange rapide
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let val = (seed ^ (seed >> 25)) as u8;
        unsafe { core::ptr::write_volatile(b, val) };
    }
    core::sync::atomic::fence(Ordering::SeqCst);

    // Passe 3 : zéros
    for b in buf.iter_mut() { unsafe { core::ptr::write_volatile(b, 0x00) }; }
    core::sync::atomic::fence(Ordering::SeqCst);
}
```

**Problèmes :**
1. La "passe 2 pseudo-aléatoire" est un LCG simple (variantes de [PCG](https://www.pcg-random.org/) mais sans vrai CSPRNG). Seedé par TSC uniquement, qui est prédictible par un attaquant qui contrôle le scheduling ou un hyper-thread voisin.
2. Le pattern de la passe 2 peut être reconstitué par [cold boot attack](https://en.wikipedia.org/wiki/Cold_boot_attack) avec équipement spécialisé.
3. Le commentaire "DoD 5220.22-M (3 passes)" est cosmétique : la spec DoD originelle exigeait des passes avec des patterns spécifiques (0x00, 0xFF, aléatoire) et le random devait être CSPRNG.
4. La passe 3 (zéros) suffit en pratique sur stockage moderne (cf. [NIST SP 800-88 Rev.1](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf) : un seul overwrite suffit sur stockage moderne). La complexité 3-passes est du security theater.

**Correction :**
```rust
fn crypto_shred(buf: &mut [u8; KEY_SIZE]) {
    // Single overwrite with CSPRNG output (NIST SP 800-88).
    let mut rng_buf = [0u8; KEY_SIZE];
    if crate::secure_random(&mut rng_buf) {
        for (b, r) in buf.iter_mut().zip(rng_buf.iter()) {
            unsafe { core::ptr::write_volatile(b, *r) };
        }
        crypto_shred_stack(&mut rng_buf);   // wipe local
    } else {
        // Fallback : pattern fixe (zéros) — pas de PRNG faible.
        for b in buf.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0) };
        }
    }
    core::sync::atomic::fence(Ordering::SeqCst);
}
```

---

#### 🟡 CS-KS-05 [MEDIUM, CRYPTO] — `KEY_MAX_LIFETIME_TSC` suppose 3 GHz exactement

**Fichier:** `keystore.rs:26`

```rust
const KEY_MAX_LIFETIME_TSC: u64 = 900_000_000_000;   // ~300 secondes en cycles TSC (à 3 GHz ≈ 900 milliards)
```

**Problèmes :**
- CPU modernes : TSC à 4-5 GHz (lifetime réelle ~180-225s).
- CPU lents/embedded : TSC à 1-2 GHz (lifetime réelle ~450-900s).
- VM暂停née (PVM, snapshot) : TSC peut être gelé → lifetime infinie.
- Permet à un attaquant qui contrôle le TSC (kernel compromis, hyperviseur) de forcer l'expiration prématurée (DoS) ou retardée (bypass).

**Correction :** utiliser un timer wall-clock ou un monotonic clock calibré (RDTSCP avec CPUID-based frequency detection).

---

#### 🟡 CS-KS-06 [MEDIUM, CRYPTO] — `rotate_key` perd l'ancienne version, pas de key versioning

**Fichier:** `keystore.rs:419-481`

**Problème :**
- `rotate_key` shred la vieille clé et écrit la nouvelle à la place (`entry.key.copy_from_slice(&new_key)`).
- Tout ciphertext chiffré avec la vieille clé devient indéchiffrable après rotation.
- Pas de concept de "key version" — le `generation` compteur sert à détecter les handles périmés, pas à indexer un historique.

**Correction :** maintenir un historique `[u8; KEY_SIZE] × N_VERSIONS` par entrée, ou exposer une API `get_key_version(handle, version)`.

---

#### 🟡 CS-KS-07 [MEDIUM, LEAK] — `get_key` retourne une copie de la clé sur la pile (responsabilité zeroization sur l'appelant)

**Fichier:** `keystore.rs:342-378`

```rust
pub fn get_key(handle: u32, caller_principal: u64) -> Option<([u8; KEY_SIZE], KeyType)> {
    ...
    let key_copy = entry.key;   // ❌ copie sur la pile
    let kt = KeyType::from_u8(entry.key_type).unwrap_or(KeyType::Derived);
    Some((key_copy, kt))
}
```

**Problème :**
- La clé est copiée sur la pile de l'appelant (`handle_request` → `CRYPTO_ENCRYPT`/`DECRYPT`/`SIGN`).
- Chaque appelant doit manuellement `wipe_bytes(&mut key)` après usage.
- Audit des callers dans `main.rs` : `wipe_bytes` est appelé dans ENCRYPT (l. 658), DECRYPT (l. 713), SIGN (l. 761) — ✅ couverture correcte aujourd'hui.
- Mais le pattern est fragile : un futur caller qui oublie `wipe_bytes` leakera la clé.

**Correction :** retourner un wrapper `SecretKey` avec `Drop` auto-zeroize (comme le recommande `zeroize` crate — déjà utilisée par les crates RustCrypto).

---

### 3.3 Points positifs confirmés (keystore.rs)

- ✅ **Quota par owner** (`MAX_KEYS_PER_OWNER = 8`) — limite l'épuisement global par un principal.
- ✅ **Generation counter** — détecte les handles périmés après revoke/rotate.
- ✅ **Locking correct** : `KEY_TABLE.lock()` tenu pendant les opérations critiques, pas de re-entrant lock.
- ✅ **`revoke_all_for_owner`** — révocation à la mort d'un process (anti-leak).
- ✅ **`revoke_all_pre_phoenix`** — anti-rollback au wake ExoPhoenix.
- ✅ **`crypto_shred` write_volatile + fence SeqCst** — empêche l'optimisation.

---

## 4. `xchacha20.rs` (229 lignes) — Wrapper RustCrypto correct, fallback dégradé

### 4.1 Conformité AEAD

| Aspect AEAD | Statut | Détail |
|------------|--------|--------|
| Algorithme delegué à crate RustCrypto | ✅ | `chacha20poly1305::XChaCha20Poly1305` |
| Nonce size 192 bits | ✅ | `NONCE_SIZE = 24` |
| Tag size 128 bits | ✅ | `TAG_SIZE = 16` |
| Encrypt-then-MAC | ✅ | `encrypt_in_place_detached` retourne tag séparé |
| **Verify-avant-décrypt** | ✅ | `decrypt_in_place_detached` vérifie tag avant de déchiffrer (`xchacha20.rs:221`) |
| **Constant-time tag compare** | ✅ | géré par `chacha20poly1305` crate (utilise `subtle`) |
| **Nonce uniqueness** | ✅ | Compteur AtomicU64 monotone + sel 16 octets |
| Zeroization sur échec | ✅ | `out_buf[..pt_len].fill(0)` sur auth fail (`xchacha20.rs:225`) |
| Nonce reuse detection | N/A | Compteur jamais reset (sauf Phoenix reseed — cf. CS-XCHACHA-01) |

### 4.2 Vulnérabilités identifiées

#### 🟡 CS-XCHACHA-01 [MEDIUM, LEAK] — `xchacha20_seal` laisse le plaintext en clair dans `out_buf` si l'encryption échoue

**Fichier:** `xchacha20.rs:171-181`

**Code problématique :**
```rust
// xchacha20.rs:172
out_buf[..plaintext.len()].copy_from_slice(plaintext);   // ❌ plaintext copié en clair

let nonce = chacha20poly1305::XNonce::from_slice(&nonce_bytes);
match cipher.encrypt_in_place_detached(nonce, aad, &mut out_buf[..plaintext.len()]) {
    Ok(tag) => { ... needed }
    Err(_) => 0,   // ❌ out_buf contient encore le plaintext en clair !
}
```

**Problème :**
- Si `encrypt_in_place_detached` échoue (en pratique : jamais, car `XChaCha20Poly1305::new_from_slice` échouerait avant), `out_buf[..plaintext.len()]` contient encore une copie du plaintext en clair.
- Le caller (`tls_encrypt_record`, `main.rs::CRYPTO_ENCRYPT`) ne wipe pas `out_buf` sur échec.
- Défense en profondeur absente.

**Impact :** Théorique aujourd'hui (l'encryption ne peut pas échouer après `new_from_slice` OK), mais pattern dangereux.

**Correction :**
```rust
Err(_) => {
    // Wipe plaintext residue before returning error
    for b in out_buf[..plaintext.len()].iter_mut() {
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    0
}
```

---

#### 🟡 CS-XCHACHA-02 [MEDIUM, CRYPTO] — `xchacha20_reseed` n'est pas protégé contre la forge (cf. CS-PHOENIX-01)

**Fichier:** `xchacha20.rs:108-123`

**Code problématique :**
```rust
pub fn xchacha20_reseed(entropy: u64) {
    if !XCHACHA_INITIALIZED.load(Ordering::Acquire) { xchacha20_init(); }
    let counter = NONCE_COUNTER.fetch_add(1_000_000, Ordering::AcqRel);
    let old_lo = NONCE_SALT_LO.load(Ordering::Acquire);
    let old_hi = NONCE_SALT_HI.load(Ordering::Acquire);
    let mixed_lo = old_lo ^ entropy ^ counter;
    let mixed_hi = old_hi ^ entropy.rotate_left(17) ^ counter.rotate_left(31);
    NONCE_SALT_LO.store(mixed_lo, Ordering::Release);
    NONCE_SALT_HI.store(mixed_hi, Ordering::Release);
    core::sync::atomic::fence(Ordering::SeqCst);
}
```

**Problèmes :**
1. L'`entropy` est XORée dans le sel — pas dérivée via KDF. Si l'attaquant contrôle l'entropy (cf. CS-PHOENIX-01), il peut forcer le sel à une valeur connue (e.g., 0).
2. Pas de protection contre la réutilisation : si la même `entropy` est fournie deux fois (replay), le contre-mélange via `counter` (fetch_add 1M) empêche la reproduction exacte, mais le sel reste prédictible.
3. Le sel reste 16 octets (128 bits) — le compteur 8 octets → total 24 octets (192 bits). Si le sel est forcé à 0, l'unicité des nonces repose uniquement sur le compteur 64 bits — encore unique, mais l'espace de sel est réduit à 1, supprimant la protection inter-sessions.

**Impact :** Si CS-PHOENIX-01 est exploitée, l'attaquant peut dégrader la qualité du sel des nonces. Pas de cassure immédiate (compteur reste unique), mais perte de la propriété "inter-session uniqueness".

---

#### 🟢 CS-XCHACHA-03 [LOW, CRYPTO] — Fallback `getrandom_u64` TSC+stack_addr en cas d'échec SYS_GETRANDOM

**Fichier:** `xchacha20.rs:79-92`

**Problème :** Le repli dégradé (16 essais SYS_GETRANDOM puis fallback TSC+stack) est explicitement documenté comme non-CSPRNG. Selon le commentaire, ce sel n'est utilisé que pour l'unicité inter-sessions, pas pour dériver des clés. Le compteur monotone garantit l'unicité intra-session.

**Verdict :** Faible sévérité. Le pattern est acceptable car le sel n'est pas un secret cryptographique en soi. Le risque serait élevé si ce sel dérivait des clés — ce n'est pas le cas ici. Documenté comme "repli DÉGRADÉ explicite", ce qui est plus honnête qu'un faux CSPRNG. (Déjà audité et confirmé acceptable dans `AUDIT-CRYPTO-DEEP.md`.)

---

### 4.3 Points positifs confirmés (xchacha20.rs)

- ✅ **Wrapper pur RustCrypto** — pas d'implémentation from-scratch.
- ✅ **Nonce uniqueness garantie** par AtomicU64 counter + sel 16 octets.
- ✅ **Verify-before-decrypt** via `decrypt_in_place_detached`.
- ✅ **Zeroization on auth failure** (`out_buf.fill(0)`).
- ✅ **Counter atomic fetch_add** — pas de race sur le nonce.
- ✅ **`xchacha20_reseed` mixe counter dans le sel** — empêche la réutilisation de l'espace de compteur après Phoenix.

---

## 5. `main.rs` (1 017 lignes) — IPC handler, authorization, Phoenix wake

### 5.1 Conformité IPC / KMS API

| Aspect IPC | Statut | Détail |
|-----------|--------|--------|
| Validation des requêtes (bounds, types) | ✅ | `read_u16_le`/`read_u32_le`/`read_u64_le` checkent bounds. `payload_len as usize > req.payload.len()` check (`main.rs:557`). |
| Authentification du client (capability) | ⚠️ | `authorize_request` via `exo_cap_check`. Mais fail-open pour PHOENIX_WAKE_ENTROPY (CS-PHOENIX-01). |
| Rate limiting | ❌ | Aucun. |
| Pas de fuite cross-tenant | ❌ | TLS session handles non liés au caller (CS-TLS-01). |
| Gestion d'erreurs safe (pas de panic leakant) | ✅ | Panic handler minimal `boot_log(b"crypto_server: panic\n")`. |
| Anti-replay | ❌ | Pas de nonce tracking. |
| Resource limits (DoS) | ⚠️ | MAX_KEYS=64, MAX_KEYS_PER_OWNER=8, MAX_SESSIONS=16, VERIFY_CONTEXTS=4. Mais pas de timeout sur VerifyContext (CS-IPC-01). |
| `CryptoRequest`/`CryptoReply` size assertions | ✅ | `const _: () = assert!(size_of::<= IPC_KERNEL_MAX_MSG_SIZE)` (`main.rs:120,154`). |

### 5.2 Vulnérabilités identifiées

#### 🔴 CS-PHOENIX-01 [CRITICAL, ISOLATION/CVE] — Authentication bypass sur `PHOENIX_WAKE_ENTROPY` via `reply_endpoint` bit 63

**Fichier:** `main.rs:920-931`, `main.rs:51` (const `KERNEL_EPHEMERAL_REPLY_BIT`)

**Code problématique :**
```rust
const KERNEL_EPHEMERAL_REPLY_BIT: u64 = 1u64 << 63;   // main.rs:51

// main.rs:563 — PHOENIX_WAKE_ENTROPY skip authorize_request
let caller_principal = if req.msg_type == PHOENIX_WAKE_ENTROPY {
    0   // ❌ pas de cap check pour ce msg_type
} else {
    match authorize_request(req) { ... }
};

// main.rs:920-931
PHOENIX_WAKE_ENTROPY => {
    let authenticated_kernel_wake =
        req.sender_pid == 0 || (req.reply_endpoint & KERNEL_EPHEMERAL_REPLY_BIT) != 0;
    // ❌ OR logique : si bit 63 est set, sender_pid peut être n'importe quoi.
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

**Vérification kernel enforcement :**
- Grep `KERNEL_EPHEMERAL_REPLY_BIT` dans `kernel/` → **0 match** (cf. audit).
- Grep `EPHEMERAL_REPLY` dans `kernel/` → 0 match.
- La constante n'existe que dans `crypto_server/src/main.rs`.
- Conclusion : **le kernel ne sanitize pas le bit 63 de `reply_endpoint`**. N'importe quel caller peut le setter.

**Exploitation :**
1. Attaquant (n'importe quel serveur Ring 1 avec `EXO_CAP_RIGHT_IPC_SEND` vers endpoint 4) envoie une requête :
   - `msg_type = 255` (PHOENIX_WAKE_ENTROPY)
   - `reply_endpoint = 1 << 63` (bit 63 set)
   - `payload = [0x42; 8]` (entropy contrôlée par l'attaquant)
2. `handle_request` skip `authorize_request` pour ce msg_type (`caller_principal = 0`).
3. `authenticated_kernel_wake = (sender_pid == 0) || (reply_endpoint & (1<<63) != 0)` → `true` (deuxième condition).
4. `xchacha20_reseed(0x4242424242424242)` mélange l'entropy attaquant-contrôlée dans le sel des nonces.
5. `keystore::revoke_all_pre_phoenix()` shred **toutes les clés actives** → DoS massif.

**Impact :**
- DoS complet : toutes les clés actives sont révoquées en une seule requête non-authentifiée.
- Dégradation du sel des nonces (CS-XCHACHA-02).
- Répétible → DoS persistant (chaque requête force revoke_all).

**Correction :**
1. Enlever le OR, ne conserver que `req.sender_pid == 0` comme condition d'authentification kernel.
2. Si le kernel doit pouvoir signaler un wake via bit 63, exiger que `req.sender_pid == 0` (le kernel force déjà ce champ selon AUDIT-7).
3. Ajouter un anti-replay : tracker le dernier TSC de Phoenix wake, refuser si < 1s.

```rust
// Correction :
PHOENIX_WAKE_ENTROPY => {
    // Le sender_pid est enforced par le kernel (AUDIT-7) — c'est la seule
    // source de vérité. Pas de OR avec un bit user-controllable.
    if req.sender_pid != 0 {
        reply.status = CRYPTO_ERR_CAP;
        REQUESTS_ERR.fetch_add(1, Ordering::Relaxed);
        return reply;
    }
    // ... reste de la logique ...
}
```

---

#### 🔴 CS-IPC-01 [CRITICAL, ISOLATION/DoS] — `VerifyContext` DoS : 4 slots seulement, jamais nettoyés

**Fichier:** `main.rs:30` (`const VERIFY_CONTEXTS: usize = 4`), `main.rs:186` (`VERIFY_TABLE`), `main.rs:255-351` (API)

**Code problématique :**
```rust
const VERIFY_CONTEXTS: usize = 4;
const VERIFY_MAX_MESSAGE: usize = 4096;

static VERIFY_TABLE: spin::Mutex<[VerifyContext; VERIFY_CONTEXTS]> = ...;

// alloc_verify_context : recherche linéaire un slot in_use=false
// AUCUN timeout, AUCUNE expiration, AUCUN cleanup périodique.
```

**Problème :**
1. 4 slots `VerifyContext` seulement.
2. Chaque `VERIFY_OP_BEGIN` alloue un slot. Si le client n'envoie jamais `VERIFY_OP_FINAL`, le slot reste `in_use = true` **pour toujours**.
3. 4 `VERIFY_OP_BEGIN` sans finalize → pool saturé.
4. Aucun mécanisme de cleanup (pas de timeout, pas de garbage collection).
5. La fonction `expire_check` du keystore n'est pas étendue aux VerifyContext.

**Exploitation :**
1. Attaquant avec `EXO_CAP_RIGHT_IPC_SEND` vers endpoint 4.
2. Envoie 4 requêtes `CRYPTO_VERIFY { VERIFY_OP_BEGIN, public_key, signature, total_len = 100 }` → 4 slots alloués.
3. N'envoie jamais `VERIFY_OP_FINAL`.
4. Tous les futurs `VERIFY_OP_BEGIN` de tous les serveurs Ring 1 légitimes échouent avec `CRYPTO_ERR_BUSY`.
5. **DoS permanent du service de vérification Ed25519** — utilisé par exo_shield et tous les serveurs pour vérifier les signatures de la base NGAV (cf. AUDIT-5).

**Impact :**
- DoS permanent jusqu'au reboot.
- Pas de mécanisme de recovery côté client.
- Surface d'attaque large : tout serveur Ring 1 est susceptible d'appeler `CRYPTO_VERIFY`.

**Correction :**
1. Ajouter un TSC de création dans `VerifyContext`.
2. Expirer les contexts > 30s dans le handler `VERIFY_OP_BEGIN` (avant allocation).
3. Idéalement, augmenter `VERIFY_CONTEXTS` à 32+ et lier chaque context à `owner_principal` (déjà fait — vérifier).

```rust
struct VerifyContext {
    in_use: bool,
    owner_principal: u64,
    creation_tsc: u64,   // ← AJOUTER
    ...
}

fn alloc_verify_context(...) -> u32 {
    let mut table = VERIFY_TABLE.lock();
    let now = read_tsc();
    const VERIFY_TIMEOUT_TSC: u64 = 90_000_000_000; // 30s @ 3GHz
    // Expire old contexts
    for ctx in table.iter_mut() {
        if ctx.in_use && now.wrapping_sub(ctx.creation_tsc) > VERIFY_TIMEOUT_TSC {
            reset_verify_context(ctx);
        }
    }
    // Puis allocate
    ...
}
```

---

#### 🟠 CS-IPC-02 [HIGH, ISOLATION] — `caller_peer_pid` contrôlable par l'appelant via `payload`

**Fichier:** `main.rs:403-405`, `main.rs:408`, `main.rs:428`, `main.rs:441-442`

**Code problématique :**
```rust
fn caller_peer_pid(caller_principal: u64) -> u32 {
    caller_principal.min(u32::MAX as u64) as u32
}

fn tls_init_reply(payload: &[u8], caller_principal: u64, reply: &mut CryptoReply) {
    let peer_pid = read_u32_le(payload, 0).unwrap_or_else(|| caller_peer_pid(caller_principal));
    // ❌ peer_pid lu depuis le payload (caller-controlled) si présent
    let (session_handle, client_hello) = tls::tls_handshake_initiate(peer_pid);
    ...
}

// main.rs:441 — tls_handshake_reply TLS_OP_RESPOND
let peer_pid =
    read_u32_le(payload, 1).unwrap_or_else(|| caller_peer_pid(caller_principal));
```

**Problème :**
- Le `peer_pid` stocké dans la session TLS est censé identifier le pair distant (l'autre serveur avec qui le caller veut établir TLS).
- Mais le `peer_pid` est lu depuis le payload envoyé par le caller — entièrement contrôlable.
- Un serveur A peut initier une session TLS en prétendant que son `peer_pid` est celui du server B (alors qu'il parle en réalité à C).
- Comme `peer_pid` n'est de toute façon jamais vérifié (CS-TLS-01), l'impact direct est faible. Mais c'est un pattern d'authentification faible.

**Correction :** Exiger que `peer_pid` soit either:
- Dérivé du `caller_principal` (caller = client du TLS, peer = endpoint) ;
- Ou fourni par le kernel (e.g., via une IPC capability qui bind le peer).

---

#### 🟠 CS-IPC-03 [HIGH, ISOLATION] — Aucun rate limiting / aucune quota par caller

**Fichier:** `main.rs:553-945` (`handle_request`)

**Problème :**
- Aucun rate limiting par caller.
- Aucun quota par caller (sauf `MAX_KEYS_PER_OWNER = 8` côté keystore).
- Un serveur compromis peut flooder le crypto_server de requêtes (`CRYPTO_HASH`, `CRYPTO_RANDOM`, `CRYPTO_VERIFY` streaming) → DoS CPU.

**Impact :** DoS CPU trivial. Le crypto_server est single-threaded (boucle IPC), donc un flood bloque toutes les requêtes légitimes.

**Correction :** token bucket par `caller_principal` (par exemple 100 req/sec/principal), rejet avec `CRYPTO_ERR_BUSY` au-delà.

---

#### 🟡 CS-IPC-04 [MEDIUM, LEAK] — Panic handler ne shred pas les clés avant `halt_forever`

**Fichier:** `main.rs:1013-1017`

```rust
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    boot_log(b"crypto_server: panic\n");
    halt_forever();
}
```

**Problème :**
- Sur panic, toutes les clés en mémoire (`KEY_TABLE`, `ROOT_PRIVATE_KEY`, `SESSION_POOL`, `VERIFY_TABLE`) restent en clair jusqu'à reboot.
- Si le panic est déclenché par un bug exploit (e.g., bounds check fail sur un input malicieux), l'attaquant peut dumper la mémoire post-panic.
- Le panic handler n'utilise pas `_info` (pas de leak d'info dans les logs), c'est positif. Mais il devrait au moins shredder les clés.

**Correction :**
```rust
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    boot_log(b"crypto_server: panic\n");
    // Best-effort shred avant halt
    let _ = keystore::revoke_all_pre_phoenix();
    let _ = tls::tls_init();   // reset sessions (inclut shred_keys)
    // (Note : peut aussi paniquer — à utiliser avec précaution)
    halt_forever();
}
```

---

#### 🟡 CS-IPC-05 [MEDIUM, RACE] — `keystore::get_key` libère le lock puis appelle `revoke_key` (TOCTOU bénigne)

**Fichier:** `keystore.rs:364-368`

```rust
// Expirée — on la révoque immédiatement
drop(table);
revoke_key(handle);   // re-acquire lock
return None;
```

**Problème :** Entre `drop(table)` et `revoke_key(handle)`, un autre thread pourrait théoriquement révoquer la même clé. Mais comme `revoke_key` check `flags == Active`, le second appel retourne `false` (bénigne). Pas de race critique.

---

#### 🟡 CS-IPC-06 [MEDIUM, LOGIC] — `phoenix_wake_entropy_from_request` lit l'entropy depuis `req.cap_token.bytes[0..8]`

**Fichier:** `main.rs:395-401`

```rust
fn phoenix_wake_entropy_from_request(req: &CryptoRequest, payload: &[u8]) -> Option<u64> {
    let compact_entropy = read_u64_le(&req.cap_token.bytes, 0).unwrap_or(0);
    if req.reply_endpoint == 0 && compact_entropy != 0 {
        return Some(compact_entropy);
    }
    read_u64_le(payload, 0)
}
```

**Problème :**
- Pour `PHOENIX_WAKE_ENTROPY`, `caller_principal = 0` (skip `authorize_request`), donc `req.cap_token` n'est pas vérifié.
- L'entropy peut provenir de `req.cap_token.bytes[0..8]` — champs user-controlled (pas de cap check).
- Combiné avec CS-PHOENIX-01, l'attaquant contrôle entièrement l'entropy injectée dans `xchacha20_reseed`.

---

### 5.3 Points positifs confirmés (main.rs)

- ✅ **`wipe_bytes` write_volatile + SeqCst fence** — zeroization robuste.
- ✅ **Cap check via `exo_cap_check`** (sauf PHOENIX — CS-PHOENIX-01).
- ✅ **`caller_principal` propagé** à toutes les opérations keystore (`insert_key`, `get_key`, `rotate_key`, `revoke_key`).
- ✅ **`CryptoReply::new` zero-initialize data** — pas de leak de stack via reply.
- ✅ **Size assertions `const _: () = assert!`** — vérification compile-time.
- ✅ **`wipe_bytes(&mut key)` systématique** après usage dans ENCRYPT/DECRYPT/SIGN.
- ✅ **`revoke_all_for_owner` sur `CRYPTO_KEY_REVOKE_OWNER`** — cleanup à la mort d'un process.

---

## 6. Cross-cutting findings (key flow analysis)

### 6.1 Key flow diagram — insertion & usage

```
Client IPC ──[CryptoRequest: cap_token, payload]──▶ main.rs::handle_request
                                                          │
                                                          ▼
                                              authorize_request (cap check)
                                                          │
                                                          ▼
                                              ┌───────────────────────┐
                                              │ CRYPTO_DERIVE_KEY     │
                                              │   derive_key_hkdf     │── [u8;32] sur stack ──▶ wipe
                                              │   keystore::insert_key│
                                              └───────────────────────┘
                                                          │
                                                          ▼
                                              KEY_TABLE[idx].key = plaintext
                                              (❌ pas de KEK wrapping, pas de mlock)
                                                          │
                                                          ▼
                                              [handle opaque u32] ──▶ Client IPC reply

Plus tard :
Client IPC ──[CryptoRequest: key_handle]──▶ handle_request ──▶ keystore::get_key
                                                          │
                                                          ▼
                                              [u8;32] key_copy sur stack  (❌ pas de Drop auto)
                                                          │
                                                          ▼
                                              xchacha20::seal/open  ──▶ wipe_bytes(&mut key)
                                              (❌ pas de mlock sur stack frame)
```

**Leak points identifiés :**
1. **`KEY_TABLE` statique en RAM** : pas de wrapping, pas de mlock → exposé à dump.
2. **Copie sur stack dans `get_key`** : pas de `Drop` auto → caller doit manuellement wipe.
3. **`ROOT_PRIVATE_KEY` statique** : jamais zeroizée, vit pour toujours.
4. **`SESSION_POOL` (clés TLS dérivées)** : shred_keys incomplet (pas de client_random).
5. **`VERIFY_TABLE` (messages à vérifier)** : pas de wipe volatile dans `reset_verify_context`.

### 6.2 Nonce flow — XChaCha20

```
xchacha20_init() ──SYS_GETRANDOM ×2──▶ NONCE_SALT_LO / NONCE_SALT_HI (16 octets total)
                                              │
                                              ▼
build_nonce() ──fetch_add(1) sur NONCE_COUNTER (8 octets)──▶ [counter(8) || salt_lo(8) || salt_hi(8)] = 24 octets
                                              │
                                              ▼
XChaCha20Poly1305::encrypt_in_place_detached(key, nonce, aad, buf)
```

**Unicité garantie :**
- Compteur AtomicU64 monotone → unique intra-process.
- Sel 16 octets → unique inter-sessions (sauf fork, cf. CS-XCHACHA-02).
- Sel est fixé pour la durée du process (pas de rotation périodique).

**Risques :**
- Si deux processes crypto_server tournent en parallèle (fork ou snapshot ExoPhoenix non-resseed), ils partagent le même sel + repartent du même compteur → **nonce reuse catastrophique**.
- Mitigation actuelle : `xchacha20_reseed` est appelé au Phoenix wake. Mais si un snapshot est restauré sans Phoenix wake (par un autre code path), le bug se manifeste.

### 6.3 Authentication flow — PKI

```
pki_init() [JAMAIS APPELÉE AU BOOT — CS-PKI-01]
  │
  ├── secure_random(&root_priv)  [CSPRNG kernel]
  ├── SigningKey::from_bytes(&root_priv)
  ├── root_cert = Certificate{ cert_id=0, issuer_id=0, subject_id=0, public_key, ... }
  ├── root_cert.signature = sign_data(&root_priv, &msg)
  ├── ROOT_PRIVATE_KEY.call_once(|| root_priv)  [❌ jamais zeroizé]
  └── register_certificate(&root_cert)  [❌ registre vide → verify cherche issuer = 0 = self → OK]

Plus tard :
verify_certificate(cert)
  ├── check expiry (TSC)  ✅
  ├── is_revoked(cert.serial)  [❌ match serial only — CS-PKI-04]
  ├── if cert.cert_type == Root : issuer_pk = cert.public_key  [self-signed]
  ├── else : chercher issuer dans CERT_REGISTRY  [❌ si registry pas peuplé → fail]
  └── verify_signature(issuer_pk, msg, signature)  [✅ verify_strict]
```

**Leak points :**
- `ROOT_PRIVATE_KEY` en statique, jamais zeroizé.
- `root_priv` pile correctement zeroizé (lignes 987-990).
- `SigningKey` temporaire : `SigningKey::from_bytes` prend une réf, n'a pas de Drop auto-zeroize dans ed25519-dalek (cf. AUDIT-2 KC-11). Le `root_signing_key` sur la pile n'est pas explicitement zeroizé (mais c'est une réf vers `root_priv` qui est zeroizé — OK indirect).

---

## 7. Score de maturité par domaine

| Domaine | Score | Justification |
|---------|-------|---------------|
| **Primitives cryptographiques** (xchacha20, ed25519, x25519, blake3) | 8/10 | Crates RustCrypto validées, verify_strict, verify-before-decrypt, nonce uniqueness, zeroization. −2 pour X25519 sans check secret nul (CS-TLS-03) et manque de Drop auto-zeroize. |
| **TLS protocol** (tls.rs) | 1.5/10 | Pas TLS 1.3 (handshake non-authentifié, pas de Finished, pas de CertificateVerify, handshake_hash jamais utilisé). Cross-tenant hijack (CS-TLS-01). HKDF key schedule non-conforme. MITM trivial. |
| **PKI** (pki.rs) | 2/10 | `pki_init` jamais appelée au boot (CS-PKI-01). Root régénérée à chaque boot (CS-PKI-02). Root privée jamais zeroizée (CS-PKI-03). Serial u32 hardcoded. CRL match serial only. Pas d'OCSP/CT. |
| **Keystore** (keystore.rs) | 4/10 | Pas de KEK wrapping (CS-KS-02). Pas de mlock (CS-KS-03). Fail-open owner=0 (CS-KS-01). crypto_shred PRNG faible (CS-KS-04). Pas de key versioning. Quota par owner OK. crypto_shred write_volatile OK. |
| **IPC / Authorization** (main.rs) | 3/10 | Auth bypass PHOENIX (CS-PHOENIX-01). VerifyContext DoS (CS-IPC-01). Pas de rate limiting. caller_peer_pid user-controlled (CS-IPC-02). Cap check OK (sauf PHOENIX). wipe_bytes OK. Size assertions OK. |
| **Zeroization / Memory hygiene** | 6/10 | write_volatile + fence SeqCst partout. crypto_shred 3 passes (PRNG faible). shred_keys incomplet (client_random). Pas de mlock. Panic handler ne shred pas. |
| **Audit logging** | 0/10 | Aucun logging des opérations sur clés. |

**Score global crypto_server : 3.5 / 10**

La base cryptographique (crates RustCrypto) est solide, mais la couche protocolaire (TLS, PKI, IPC authorization) est défaillante à un point tel que les garanties de sécurité annoncées ne sont **pas assurées**. Le service ne devrait pas être considéré comme un KMS de confiance dans son état actuel.

---

## 8. Recommandations priorisées

### P0 — Corrections critiques (à appliquer avant toute mise en production)

1. **CS-TLS-01** : Binder `session_handle` à `caller_principal` dans `tls_encrypt_record`/`tls_decrypt_record`. Ajouter `owner_principal: AtomicU64` dans `TlsSession`. Propager `caller_principal` depuis `main.rs::tls_*_reply`. (~2 h-h)

2. **CS-PHOENIX-01** : Enlever le OR dans `authenticated_kernel_wake`, ne conserver que `req.sender_pid == 0`. Ajouter anti-replay (TSC-based). (~1 h-h)

3. **CS-TLS-02** : Implémenter Finished message + CertificateVerify. Mettre à jour `handshake_hash` à chaque message. Vérifier avant `Verified`. (~16 h-h — refonte protocolaire)

4. **CS-TLS-03** : Rejeter shared_secret X25519 nul dans `x25519_dh`. (~1 h-h)

5. **CS-IPC-01** : Ajouter TSC-based expiration des `VerifyContext` (timeout 30s). Appeler dans `alloc_verify_context` et idéalement dans la boucle IPC. (~2 h-h)

6. **CS-PKI-01** : Appeler `pki::pki_init()` depuis `_start()`. (~15 min-h)

### P1 — Corrections majeures (à appliquer dans la foulée)

7. **CS-PKI-02** : Décider de la stratégie root CA (intégrée au binaire, persistée via secure storage, ou ephemeral per-boot assumée). Documenter et implémenter. (~8 h-h)

8. **CS-KS-02** : Implémenter KEK wrapping des clés au repos. Générer une Master Key au boot, mlocker sa page. (~16 h-h)

9. **CS-KS-03** : Appeler `SYS_MLOCK` sur les pages contenant `KEY_TABLE`, `ROOT_PRIVATE_KEY`, `SESSION_POOL`, `VERIFY_TABLE`. (~4 h-h — nécessite mlock syscall exposé par memory_server)

10. **CS-TLS-04** : Appeler `cleanup_expired_sessions()` dans la boucle IPC (timeout ou chaque N itérations). (~30 min-h)

11. **CS-KS-01** : Refuser `owner == 0` dans `get_key` (kernel-owned keys ne doivent pas être accessibles via IPC). (~15 min-h)

12. **CS-KS-04** : Utiliser `secure_random` pour la passe 2 de `crypto_shred` au lieu du LCG TSC. (~30 min-h)

13. **CS-TLS-05** : Refondre `derive_traffic_keys` avec un key schedule 3-niveaux conforme à RFC 8446 §7.1, utilisant le crate `hkdf`. (~8 h-h)

14. **CS-TLS-06** : Inclure seq_num + length dans l'AAD TLS. Vérifier recv_counter en decrypt. (~4 h-h)

### P2 — Hardening (à planifier)

15. **CS-PKI-03** : Ne charger la root key que lors des opérations de signature (offline CA model). (~8 h-h)
16. **CS-PKI-04** : `is_revoked(issuer_id, serial)` au lieu de `is_revoked(serial)`. (~1 h-h)
17. **CS-PKI-05** : `serial: [u8; 16]` aléatoire. (~2 h-h)
18. **CS-KS-05** : Utiliser un monotonic clock calibré au lieu de TSC raw. (~4 h-h)
19. **CS-KS-06** : Maintenir un historique de versions par clé. (~16 h-h)
20. **CS-IPC-03** : Token bucket rate limiting par caller. (~4 h-h)
21. **CS-IPC-04** : Panic handler shred best-effort. (~1 h-h)
22. **CS-TLS-07** : Zeroizer `client_random` dans `shred_keys`. (~5 min-h)
23. **CS-TLS-08** : Champ dédié `ephemeral_private_key` au lieu de réutiliser `server_random`. (~2 h-h)
24. **CS-XCHACHA-01** : Wipe `out_buf` sur échec encryption. (~15 min-h)
25. **CS-IPC-02** : `peer_pid` kernel-derived au lieu de payload-controlled. (~2 h-h)

### P3 — Bonnes pratiques

26. **Audit logging** : Logger chaque opération sur clé (insert/revoke/rotate) avec principal + handle + TSC + type. Pas de matériel clé dans les logs. (~8 h-h)
27. **Constant-time comparisons** pour tous les handles/owner checks (utiliser `subtle::ConstantTimeEq`). (~2 h-h)
28. **Drop auto-zeroize** via crate `zeroize` pour `SigningKey`, `StaticSecret`, buffers intermédiaires. (~4 h-h)
29. **Test vectors** : ajouter KAT pour XChaCha20-Poly1305 (RFC 8439 §2.3.2 extension 192-bit nonce), Ed25519 (RFC 8032), X25519 (RFC 7748). (~8 h-h)
30. **Fuzzing** : fuzz le parser `handle_request` avec payloads malformés. (~16 h-h)

---

## 9. Plan de correction en 3 phases

**Phase 1 (P0, ~24 h-h)** : corriger les 6 vulnérabilités CRITICAL. Le crypto_server devient utilisable pour son rôle déclaré (anti-MITM, anti-cross-tenant, anti-DoS). Score cible : 5/10.

**Phase 2 (P1, ~60 h-h)** : corriger les 7 vulnérabilités HIGH. Keystore avec KEK + mlock, TLS avec Finished + CertificateVerify, key schedule conforme RFC 8446. Score cible : 7/10.

**Phase 3 (P2+P3, ~80 h-h)** : hardening, audit logging, fuzzing, KAT. Score cible : 8.5/10.

**Total : ~164 h-h** pour élever le crypto_server à un niveau de maturité production-grade.

---

## 10. Références

- [RFC 8446 — TLS 1.3](https://datatracker.ietf.org/doc/html/rfc8446) (handshake, key schedule, record layer)
- [RFC 7748 §6.1 — X25519 all-zero shared secret check](https://datatracker.ietf.org/doc/html/rfc7748#section-6.1)
- [RFC 5280 — PKI X.509](https://datatracker.ietf.org/doc/html/rfc5280) (serial, validity, chain validation)
- [RFC 6962 — Certificate Transparency](https://datatracker.ietf.org/doc/html/rfc6962)
- [RFC 5746 — Renegotiation Indication](https://datatracker.ietf.org/doc/html/rfc5746) (TLS 1.2, N/A 1.3 mais informatif)
- [RFC 5869 — HKDF](https://datatracker.ietf.org/doc/html/rfc5869)
- [NIST SP 800-38D — GCM](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [NIST SP 800-88 Rev.1 — Media Sanitization](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-88r1.pdf)
- [CVE-2014-0160 — Heartbleed](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160) (N/A — pas de heartbeat)
- [CVE-2014-3566 — POODLE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-3566) (N/A — pas de CBC)
- [CVE-2014-1265 — 3SHAKE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1265) (relevant — pas de transcript binding)
- [CVE-2019-25005 — ChaCha20 counter wrap](https://vulert.com/vuln-db/crates-io-chacha20-595) (cf. AUDIT-2 KC-05, kernel)
- [BearSSL — Constant-time](https://www.bearssl.org/constanttime.html)
- [SLOTH attack on TLS signatures](https://www.ietf.org/archive/id/draft-ietf-tls-md5-sha1-deprecate-01.txt)
- [Truncation attack — Dean & Hu](https://www.usenix.org/legacy/events/sec01/full_papers/dean/dean_html/index.html)

---

## Annexe A — Inventaire des findings

| ID | Sévérité | Catégorie | Fichier:Ligne | Sujet |
|----|----------|-----------|---------------|-------|
| CS-TLS-01 | CRITICAL | ISOLATION | tls.rs:580,615 + main.rs:489,514 | Cross-tenant TLS session hijack |
| CS-TLS-02 | CRITICAL | CRYPTO | tls.rs:294-335,427-573 | Handshake non-authentifié (no Finished, no CertificateVerify, handshake_hash unused) |
| CS-TLS-03 | CRITICAL | CRYPTO/CVE | tls.rs:340-344 | Pas de rejet shared secret X25519 nul (RFC 7748 §6.1) |
| CS-PHOENIX-01 | CRITICAL | ISOLATION/CVE | main.rs:920-931 | Auth bypass PHOENIX_WAKE_ENTROPY via reply_endpoint bit 63 |
| CS-IPC-01 | CRITICAL | ISOLATION/DoS | main.rs:186,255-351 | VerifyContext DoS (4 slots, jamais nettoyés) |
| CS-PKI-01 | CRITICAL | INTEGRITY | main.rs:955-975 | pki_init jamais appelée au boot |
| CS-PKI-02 | CRITICAL | CRYPTO/INTEGRITY | pki.rs:958-995 | Root CA régénérée à chaque boot, non persistée |
| CS-KS-01 | HIGH→CRITICAL | ISOLATION | keystore.rs:355-358 | get_key fail-open pour owner==0 |
| CS-KS-02 | HIGH | CRYPTO/LEAK | keystore.rs:91-108 | Keys en clair en mémoire, pas de KEK wrapping |
| CS-KS-03 | HIGH | CRYPTO/LEAK | tous | Pas de mlock sur pages contenant des clés |
| CS-KS-04 | HIGH | CRYPTO | keystore.rs:229-253 | crypto_shred random pass utilise LCG TSC-seeded |
| CS-TLS-04 | HIGH | ISOLATION/DoS/LEAK | tls.rs:697 + main.rs | cleanup_expired_sessions jamais appelée + X25519 priv key leak |
| CS-TLS-05 | HIGH | CRYPTO | tls.rs:276-335 | HKDF-Extract salt=0, key schedule non-conforme RFC 8446 |
| CS-TLS-06 | HIGH | CRYPTO | tls.rs:593,640 | AAD record = 1 byte (pas de seq num, pas de length) |
| CS-PKI-03 | HIGH | CRYPTO/LEAK | pki.rs:658,986 | Root CA private key jamais zeroizée |
| CS-PKI-04 | HIGH | LOGIC | pki.rs:889-898 | is_revoked match serial only (pas issuer) |
| CS-IPC-02 | HIGH | ISOLATION | main.rs:403-442 | caller_peer_pid contrôlable par l'appelant |
| CS-IPC-03 | HIGH | ISOLATION/DoS | main.rs:553 | Pas de rate limiting |
| CS-TLS-07 | MEDIUM | LEAK | tls.rs:223-246 | shred_keys n'efface pas client_random |
| CS-TLS-08 | MEDIUM | LEAK | tls.rs:393-395,533-546 | Clé privée X25519 stockée dans server_random |
| CS-TLS-09 | MEDIUM | LEAK | tls.rs:324-329 | IV buffers intermédiaires non zeroizés |
| CS-PKI-05 | MEDIUM | CRYPTO | pki.rs:131,978 | Serial u32, root serial hardcoded 1 |
| CS-PKI-06 | MEDIUM | LOGIC | pki.rs:917-950 | register_certificate TOCTOU sur ordre d'enregistrement |
| CS-PKI-07 | MEDIUM | ISOLATION/DoS | pki.rs:670-673 | CERT_REGISTRY 32 slots, pas de LRU |
| CS-PKI-08 | MEDIUM | LOGIC | pki.rs:773-830 | validate_chain check hiérarchie seulement pour i>0 |
| CS-KS-05 | MEDIUM | CRYPTO | keystore.rs:26 | KEY_MAX_LIFETIME_TSC suppose 3 GHz exact |
| CS-KS-06 | MEDIUM | CRYPTO | keystore.rs:419-481 | rotate_key perd ancienne version, pas de key versioning |
| CS-KS-07 | MEDIUM | LEAK | keystore.rs:342-378 | get_key copie clé sur stack, pas de Drop auto-zeroize |
| CS-XCHACHA-01 | MEDIUM | LEAK | xchacha20.rs:171-181 | xchacha20_seal laisse plaintext en clair sur échec |
| CS-XCHACHA-02 | MEDIUM | CRYPTO | xchacha20.rs:108-123 | xchacha20_reseed mélange entropy via XOR (pas KDF) |
| CS-IPC-04 | MEDIUM | LEAK | main.rs:1013-1017 | Panic handler ne shred pas les clés avant halt |
| CS-IPC-05 | MEDIUM | RACE | keystore.rs:364-368 | get_key TOCTOU bénigne sur expire→revoke |
| CS-IPC-06 | MEDIUM | LOGIC | main.rs:395-401 | phoenix_wake entropy depuis cap_token non-vérifié |
| CS-XCHACHA-03 | LOW | CRYPTO | xchacha20.rs:79-92 | Fallback TSC+stack_addr acceptable (sel non secret) |

**Bilan : 7 CRITICAL, 10 HIGH, 13 MEDIUM, 1 LOW = 31 findings.**

---

*Fin du rapport AUDIT-3-CRYPTO-SERVER.*
