# Audit Cryptographique Profond — Kernel Crypto Stack ExoOS

**Task ID:** AUDIT-2-KERNEL-CRYPTO
**Périmètre:** `kernel/src/security/crypto/*`, `drivers/security/verity`, `drivers/storage/fscrypt`, + callers (`fs/exofs/crypto/*`)
**Méthode:** Lecture intégrale de chaque fichier .rs en périmètre + analyse algorithme-par-algorithme contre classes de vulnérabilités connues.
**Date:** 2026-06-21
**Auditeur:** claude-auditeur (cryptographe)

---

## Résumé exécutif

La stack crypto kernel ExoOS est **globalement solide** — les primitives principales s'appuient sur des crates RustCrypto validées (ed25519-dalek `verify_strict`, x25519-dalek, hkdf, blake3, argon2) et les points clés de l'audit précédent (GHASH constant-time, verify-avant-décrypt, rejet secret-partagé nul) sont **confirmés corrects**.

Cependant, l'audit profond révèle **5 classes de faiblesses**:

| # | Sévérité | Catégorie | Sujet | Fichier |
|---|----------|-----------|-------|---------|
| 1 | **HIGH**  | CRYPTO | Compteur ChaCha20 32-bit wrap sans garde (CVE-2019-25005 pattern) | `xchacha20_poly1305.rs:130` |
| 2 | **HIGH**  | CRYPTO | Fallback PRNG faible (LCG) dans `entropy.rs` lorsque `rng_fill` échoue | `fs/exofs/crypto/entropy.rs:187-202` |
| 3 | **MEDIUM** | LEAK | AES-GCM software path NON constant-time (`aes_xtime` branche + S-Box cache-timing) | `aes_gcm.rs:174-208` |
| 4 | **MEDIUM** | CRYPTO | Zéroïsation manquante : `Aes256GcmCipher`, `Ed25519KeyPair`, `X25519KeyPair`, `mac_key`, `kek`, `Argon2 memory` | multiples |
| 5 | **MEDIUM** | CRYPTO | RNG non FIPS 800-90A compliant : pas de health checks (RCT/APT), pas de protection fork/VM-fork | `rng.rs` |

**Score maturité crypto global : 7/10**

La crypto de base est correcte et l'architecture est saine (séparation des domaines BLAKE3, verify-before-decrypt partout, `verify_strict`). Les problèmes sont dans les **chemins aux limites** (counter overflow, fallback dégradé, zeroization manquante) — pas dans les algorithmes eux-mêmes. Un durcissement ciblé (5 corrections) élèverait le score à 8.5/10.

---

## 1. AES-256-GCM (`aes_gcm.rs`, 866 lignes)

### 1.1 Algorithme — vérifications

| Aspect | Statut | Détail |
|--------|--------|--------|
| Construction J0 = IV ‖ 0³¹ ‖ 1 (96-bit IV) | ✅ | Conforme NIST SP 800-38D §5.2.1.1 (`aes_gcm.rs:612-614`, `656-657`) |
| H = AES_K(0¹²⁸) sous-clé de hachage | ✅ | `aes_gcm.rs:607-609`, `650-652` |
| CTR démarre à `inc32(J0)` (counter=2) | ✅ | `aes_gcm.rs:617-619`, `672-673` — conforme NIST |
| `gcm_inc32` wrap 2³² | ✅ | `aes_gcm.rs:548-552` — conforme spec |
| GHASH: A ‖ C ‖ len(A)‖64 ‖ len(C)‖64 | ✅ | `aes_gcm.rs:694-707` — conforme |
| Tag = GHASH ⊕ AES_K(J0) | ✅ | `aes_gcm.rs:713-717` |
| **Tag verification constant-time** | ✅ | `subtle::ConstantTimeEq` (`aes_gcm.rs:661`) |
| **Verify-avant-décrypt** | ✅ | Tag vérifié lignes 660-669, déchiffrement ligne 674 |
| Zéroïsation H en cas d'auth fail | ✅ | `aes_gcm.rs:662-667` (`write_volatile`) |
| **GHASH `gf128_mul` constant-time** | ✅ | Branche masquée `0 - bit` (`aes_gcm.rs:467-495`) — correctement corrigé depuis l'audit précédent |

### 1.2 Vulnérabilités identifiées

#### 🔴 AUDIT-2-KC-01 [HIGH, CRYPTO] — AES software path non constant-time

**Localisation:** `aes_gcm.rs:202-208` (`aes_xtime`) + `aes_gcm.rs:174-178` (`aes_sub_bytes`)

```rust
fn aes_xtime(x: u8) -> u8 {
    if x & 0x80 != 0 {        // ← branche data-dépendante
        (x << 1) ^ 0x1B
    } else {
        x << 1
    }
}
fn aes_sub_bytes(state: &mut [u8; 16]) {
    for byte in state.iter_mut() {
        *byte = AES_SBOX[*byte as usize];   // ← lookup table data-dépendant (cache-timing)
    }
}
```

**Problème:** Le chemin software AES (utilisée quand AES-NI n'est pas disponible — VMs anciennes, certains hyperviseurs qui masquent AES-NI, émulateurs) contient:
1. **Branchement data-dépendant** dans `aes_xtime` (utilisée par MixColumns) — fuite l'état AES via timing.
2. **Lookup S-Box data-dépendant** dans `aes_sub_bytes` — fuite l'état AES via cache-timing.

L'état AES après AddRoundKey dépend de la clé secrète → fuite de la **clé AES** par canal cache. C'est l'attaque classique Osvik/Shamir/Tromer 2006. Pendant CTR, l'input AES est le compteur (public), mais après AddRoundKey l'état = compteur ⊕ round_key — donc le timing fuit `compteur ⊕ round_key`, et avec suffisamment de counters observés, on récupère la round_key.

**Mitigation actuelle:** Le dispatch (`aes_gcm.rs:435-444`) privilégie AES-NI si disponible. Sur tout x86_64 moderne (post-2010 Westmere), AES-NI est présent. Le risque est réel uniquement sur CPUs/VMs sans AES-NI.

**Recommandation:**
- **Correctif 1 (court terme):** Remplacer `aes_xtime` par une version sans branche:
  ```rust
  fn aes_xtime(x: u8) -> u8 {
      (x << 1) ^ (0x1B & (0u8.wrapping_sub(x >> 7)))
  }
  ```
  Pour la S-Box, utiliser une implémentation bitslice ou isochrono (Bonnetain-Florey-Schindler implicant), ou à défaut documenter que le software path n'est pas sécurisé contre attaques cache-timing locales.
- **Correctif 2 (moyen terme):** Exiger AES-NI au boot (taint flag `crypto::AES_GCM_SOFT_PATH`) et refuser les opérations sensibles si absent.

#### 🟡 AUDIT-2-KC-02 [MEDIUM, LEAK] — Pas de zéroïsation des round keys

**Localisation:** `aes_gcm.rs:109-160` (`Aes256RoundKeys`), `aes_gcm.rs:417-445` (`Aes256GcmCipher`)

```rust
struct Aes256RoundKeys { keys: [[u8; 16]; 15], }   // pas de Drop
struct Aes256GcmCipher { round_keys: Aes256RoundKeys, has_aesni: bool, }   // pas de Drop
```

`Aes256GcmCipher::new(key)` dérive 240 octets de round keys depuis `key` (lignes 425-432). Ni `Aes256RoundKeys`, ni `Aes256GcmCipher` n'implémentent `Drop`. À chaque appel `aes_gcm_seal`/`aes_gcm_open`, les round keys sont allouées sur la pile (stack frame de la fonction appelante), et **ne sont pas effacées** après retour. Un dump mémoire ultérieur (attaque cold-boot, lecture /proc/kcore, UAF) expose la clé.

**Recommandation:**
```rust
impl Drop for Aes256GcmCipher {
    fn drop(&mut self) {
        for k in self.round_keys.keys.iter_mut() {
            for b in k.iter_mut() {
                unsafe { core::ptr::write_volatile(b, 0); }
            }
        }
        core::sync::atomic::fence(Ordering::SeqCst);
    }
}
```

#### 🟡 AUDIT-2-KC-03 [LOW, CRYPTO] — Pas de limite explicite sur taille message (2³²-2 blocs max par IV)

**Localisation:** `aes_gcm.rs:562-580` (`gcm_ctr_encrypt`)

`gcm_inc32` wrap à 2³² (ligne 551). NIST SP 800-38D §8.3 limite à 2³²-2 invocations GCTR par IV. L'implémentation n'a pas de garde — un message de ≥64 GiB cause une réutilisation silencieuse de counter (et donc de keystream), compromettant la confidentialité + authenticité (le tag GHASH est également affecté).

**Recommandation:** Ajouter en haut de `aes_gcm_seal`/`aes_gcm_open`:
```rust
let max_blocks = (1u64 << 32) - 2;
let blocks_needed = (plaintext.len() as u64 + 15) / 16;
if blocks_needed > max_blocks { return Err(InvalidParameter); }
```

#### 🟢 AUDIT-2-KC-04 [LOW, CRYPTO] — Pas de vecteurs de test KAT (NIST)

**Localisation:** `aes_gcm.rs:726-867` (tests)

Les tests vérifient roundtrip + tamper, mais il n'y a **pas de Known-Answer Test** contre les vecteurs NIST SP 800-38D (Appendix B). Pour une implémentation AES-GCM maison (roll-your-own, justifiée par contrainte target), l'absence de KAT est un risque: un bug subtil dans le GHASH ou la CTR ne serait pas détecté.

**Recommandation:** Ajouter au moins 2-3 vecteurs NIST GCM Test Case 3, 4, 6 (clés non-triviales, AAD non-vide).

---

## 2. XChaCha20-Poly1305 / XChaCha20-BLAKE3 (`xchacha20_poly1305.rs`, 294 lignes)

### 2.1 Algorithme — vérifications

> **Note importante:** Le module est nommé `xchacha20_poly1305` mais utilise **BLAKE3 keyed-hash** (pas Poly1305) pour l'authentification — workaround pour contrainte target `x86_64-unknown-none` (pas de SIMD/SSE2 pour Poly1305). **Poly1305 clamping N/A** (pas de Poly1305). Documenté en tête de fichier.

| Aspect | Statut | Détail |
|--------|--------|--------|
| Nonce 24 octets (192-bit XChaCha20) | ✅ | `xchacha20_poly1305.rs:15` |
| HChaCha20 (subkey dérivation) | ✅ | `xchacha20_poly1305.rs:135-168` — 20 rounds, retourne state[0..3,12..15] conforme RFC 8439 §2.3 |
| ChaCha20 block: 20 rounds, counter=state[12] | ✅ | `xchacha20_poly1305.rs:170-205` — **testé contre RFC 8439 §2.3.2 KAT** (`xchacha20_poly1305.rs:271-293`) |
| Counter initial = 1 | ✅ | `xchacha20_poly1305.rs:122` (XChaCha20 convention) |
| Encrypt-then-MAC | ✅ | Seal: chiffre (`:53`) puis tag (`:54`); tag couvre ciphertext |
| Verify-avant-décrypt | ✅ | `xchacha20_poly1305.rs:66-71` — tag vérifié avant XOR |
| Tag comparison constant-time | ✅ | `constant_time_eq` via `subtle::ConstantTimeEq` (`xchacha20_poly1305.rs:67`) |
| MAC key séparé (BLAKE3 derive_key context "ExoOS-Kernel-XChaCha20-BLAKE3-MAC-v1") | ✅ | `xchacha20_poly1305.rs:99-100` — séparation de domaine explicite |
| AAD préfixé par longueur | ✅ | `xchacha20_poly1305.rs:104-107` — empêche ambiguïté |
| Tag 16 octets (128-bit) | ✅ | Truncation acceptable depuis BLAKE3 256-bit (≥128 bits sécurité) |
| `xchacha20_xor` (longueur-préservant) documenté sûr uniquement si (key,nonce) une seule utilisation | ✅ | Commentaire `:74-83`, garanti par ExoFS blobs immuables |

### 2.2 Vulnérabilités identifiées

#### 🔴 AUDIT-2-KC-05 [HIGH, CRYPTO] — Compteur ChaCha20 32-bit wrap sans garde

**Localisation:** `xchacha20_poly1305.rs:122-132`

```rust
let mut counter = 1u32;
let mut offset = 0usize;
while offset < data.len() {
    let keystream = chacha20_block(&subkey, &chacha_nonce, counter);
    // ...
    counter = counter.wrapping_add(1);   // ← wrap silencieux à 2³²
    offset += chunk_len;
}
```

**Problème:** Après 2³²-1 blocs de 64 octets = **256 GiB - 64 octets** dans un seul message, le compteur wrap à 0, puis à 1 → collision avec le premier bloc (counter=1). Le keystream se répète → **perte catastrophique de confidentialité** (XOR des clairs révélé) + le tag MAC reste valide car le tag est calculé sur le ciphertext (qui lui ne se répète pas, mais le keystream répété permet à l'attaquant de déduire la relation entre deux blocs clairs).

Ce pattern est exactement **CVE-2019-25005** (chacha20 crate < 0.3.0). La correction upstream a été d'ajouter un check explicite.

**Mitigation actuelle:** Aucune. Aucun garde, aucune erreur, le wrap est silencieux.

**Exploitabilité:** Pour un kernel, 256 GiB dans un seul `seal`/`open` est peu réaliste aujourd'hui, mais :
- Une syscall `rng_fill(256 GiB)` est concevable si la limite n'est pas vérifiée côté appelant.
- Pour fscrypt (cf. §9), si un blob dépasse 256 GiB, `xchacha20_xor` réutilise le keystream.

**Recommandation:**
```rust
const MAX_BLOCKS: u32 = u32::MAX - 1;  // 2³²-2 par safety margin
fn xchacha20_apply(...) {
    let max_bytes = (MAX_BLOCKS as u64) * (CHACHA20_BLOCK_SIZE as u64);
    if (data.len() as u64) > max_bytes {
        // caller must chunk or re-key
        panic!("XChaCha20: message exceeds 2³²-2 block limit");
    }
    // ...
}
```
Ou mieux: exiger un `Result<(), AeadError>` et propager l'erreur.

#### 🟡 AUDIT-2-KC-06 [MEDIUM, LEAK] — Pas de zéroïsation du matériel intermédiaire

**Localisation:** `xchacha20_poly1305.rs:89-115` (`compute_tag`), `:117-133` (`xchacha20_apply`)

`compute_tag` alloue sur la pile: `ikm` (56 octets, contient key+nonce), `mac_key` (32 octets dérivés), `full_tag` (32 octets). Aucun n'est effacé avant retour. De même `xchacha20_apply` alloue `subkey` (32 octets) et `keystream` (64 octets) sans les effacer.

**Recommandation:** Wrapper dans un scope interne + zeroize:
```rust
fn compute_tag(...) -> [u8; TAG_LEN] {
    let result = {
        let mut ikm = [0u8; KEY_LEN + XCHACHA20_NONCE_LEN];
        // ...
        let out = ...;
        for b in ikm.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
        for b in mac_key.iter_mut() { unsafe { core::ptr::write_volatile(b, 0); } }
        out
    };
    result
}
```

#### 🟢 AUDIT-2-KC-07 [LOW, CRYPTO] — `xchacha20_xor` public n'a pas de garde anti-réutilisation

**Localisation:** `xchacha20_poly1305.rs:84-87`

La fonction est publique et documentée comme sûre seulement si (key,nonce) chiffre un seul plaintext. Cependant, aucun runtime check n'empêche un appelant (ExoFS ou autre) de réutiliser accidentellement. Pour les blobs immuables content-addressed c'est sûr ; pour un autre usage ce serait catastrophique.

**Recommandation:** Renommer en `xchacha20_xor_blob_immutable` ou ajouter un type marker `ImmutableBlob` pour rendre l'API type-safe.

#### 🟢 AUDIT-2-KC-08 [LOW, CRYPTO] — Code duplication fscrypt

**Localisation:** `drivers/storage/fscrypt/src/lib.rs:34-132` duplique intégralement `chacha20_block`, `hchacha20`, `xchacha20_xor` depuis `kernel/src/security/crypto/xchacha20_poly1305.rs`.

Le commentaire (fscrypt `:9-12`) indique que c'est intentionnel pour le partage kernel/outil-host. Le test `chacha20_block_matches_rfc8439` vérifie la conformité. Cependant, **toute correction de bug doit être appliquée aux deux endroits** — le risque de divergence est réel.

**Recommandation:** Extraire `chacha20_block` + `hchacha20` dans une crate `exo-chacha20` partagée (no_std) consommée par kernel + fscrypt.

---

## 3. BLAKE3 (`blake3.rs`, 257 lignes)

### 3.1 Algorithme — vérifications

| Aspect | Statut | Détail |
|--------|--------|--------|
| Wrapper sur crate `blake3` (pure) | ✅ | `blake3.rs:35-48` — pas d'implémentation maison |
| Mode hash (`new`) | ✅ | `:40-42` |
| Mode MAC/keyed (`new_keyed`) | ✅ | `:46-48` — clés 32B, BLAKE3 keyed_hash |
| Mode KDF (`new_derive_key`) avec contexte | ✅ | `:57-60` — domain separation natif BLAKE3 |
| `derive_key` rejection de contexte non-UTF8 → repli "ExoOS-KDF-Blake3" | ⚠️ | `:58` — voir INFO-01 |
| XOF (sortie >32B via `finalize_xof`) | ✅ | `:75-83` |
| `constant_time_eq` via `subtle` | ✅ | `:193-202` — correct |
| KAT: BLAKE3("") = `af1349b9...` | ✅ | `:213-220` — vérifié |
| Domain separation test | ✅ | `:249-256` |

### 3.2 Vulnérabilités identifiées

#### 🟢 AUDIT-2-KC-09 [LOW, INFO] — Repli silencieux sur contexte KDF dégradé

**Localisation:** `blake3.rs:58` et `:175`

```rust
let ctx = core::str::from_utf8(context).unwrap_or("ExoOS-KDF-Blake3");
```

Si l'appelant passe un contexte non-UTF8 (bug), BLAKE3 utilise silencieusement le contexte par défaut `"ExoOS-KDF-Blake3"`. Deux KDFs avec des contextes non-UTF8 différents produiraient la **même clé dérivée** → collision de domaine.

**Recommandation:** Retourner une erreur (`Result<_, KdfError>`) si le contexte est invalide, plutôt que de silently fallback. Ou `panic!` en debug, log en release.

#### 🟢 AUDIT-2-KC-10 [LOW, LEAK] — `Blake3Hasher::new_keyed` ne zeroize pas

`Blake3Hasher` wrappe `blake3::Hasher` mais n'implémente pas `Drop`. La crate `blake3` elle-même ne zeroize pas l'état interne (le `Hasher` contient le bloc en cours + le contexte keyed). En pratique, l'état interne BLAKE3 contient la clé après `new_keyed`. Pas de Drop → la clé persiste en mémoire.

**Recommandation:** Wrapper pour zeroize au Drop, ou documenter que la responsabilité incombe à l'appelant.

---

## 4. Ed25519 (`ed25519.rs`, 184 lignes)

### 4.1 Algorithme — vérifications

| Aspect | Statut | Détail |
|--------|--------|--------|
| Crate `ed25519-dalek` v2 (RustCrypto) | ✅ | Conforme RFC 8032 |
| `verify_strict` (anti-malléabilité + anti-clés-faibles) | ✅ | `ed25519.rs:133` — correctement appliqué (confirmé depuis audit précédent) |
| Validation clé publique via `VerifyingKey::from_bytes` | ✅ | `:130` — point sur courbe validé par la crate |
| Signatures déterministes (RFC 8032 §5.1.6) | ✅ | `ed25519-dalek::SigningKey::sign` — dérivation de nonce déterministe standard |
| Pas de RNG faible pour nonce | ✅ | Déterministe par design (sûr si seed secret) |
| Constant-time scalar mult | ✅ | Garanti par `ed25519-dalek` |
| `ed25519_keypair_from_seed`: clamping RFC 8032 §5.1.5 | ✅ | `:89-92` (mais voir KC-12 sur dead code) |

### 4.2 Vulnérabilités identifiées

#### 🟡 AUDIT-2-KC-11 [MEDIUM, LEAK] — Pas de Drop auto, zeroize manuel oubliable

**Localisation:** `ed25519.rs:29-45`

```rust
pub struct Ed25519KeyPair {
    pub seed: [u8; 32],
    pub public_key: [u8; 32],
    pub expanded: [u8; 64],
}
impl Ed25519KeyPair {
    pub fn zeroize(&mut self) { ... }   // MANUEL
}
```

`Ed25519KeyPair` contient `seed` (clé privée 32B) et `expanded` (clé étendue 64B = SHA-512(seed) avec clamping). Pas de `Drop`. L'appelant doit appeler `zeroize()` explicitement — facile à oublier.

Comparé à `XChaCha20Key` dans `fs/exofs/crypto/xchacha20.rs:65-75` qui implémente `Drop` avec `write_volatile`, c'est une incohérence.

**Recommandation:** Implémenter `Drop`:
```rust
impl Drop for Ed25519KeyPair {
    fn drop(&mut self) {
        for b in self.seed.iter_mut().chain(self.expanded.iter_mut()) {
            unsafe { core::ptr::write_volatile(b, 0); }
        }
        core::sync::atomic::fence(Ordering::SeqCst);
    }
}
```

#### 🟢 AUDIT-2-KC-12 [LOW, LEAK] — Champ `expanded` est dead code contenant du matériel secret

**Localisation:** `ed25519.rs:36-37`, `:84-93`

Le champ `expanded` est calculé (`Sha512::digest(seed)` + clamping) mais **jamais utilisé** par le code — le commentaire `:34-35` dit "pour compatibilité API". `ed25519_sign` (`:105-109`) recrée un `SigningKey::from_bytes(&keypair.seed)` à chaque appel, donc `expanded` est superflu.

`expanded` contient la première moitié = scalar clampé (clé privée Curve25519 équivalente) — matériel secret.

**Recommandation:** Supprimer le champ `expanded`, ou le dériver on-demand. Si maintenu pour compat binaire, l'exclure des `Debug` impl.

#### 🟢 AUDIT-2-KC-13 [LOW, INFO] — `Ed25519KeyPair` n'implémente pas `Zeroize` (crate `zeroize`)

Le projet utilise déjà `write_volatile` manuel, mais la crate `zeroize` (RustCrypto) fournit un trait `Zeroize` + derive macro. Pour cohérence avec l'écosystème RustCrypto déjà utilisé, adopter `zeroize::Zeroize` partout.

---

## 5. X25519 (`x25519.rs`, 141 lignes)

### 5.1 Algorithme — vérifications

| Aspect | Statut | Détail |
|--------|--------|--------|
| Crate `x25519-dalek` v2 (RustCrypto) | ✅ | Conforme RFC 7748 |
| Clamping automatique du scalar | ✅ | `StaticSecret::from` applique le clamping RFC 7748 §5 |
| Constant-time scalar mult | ✅ | Garanti par `x25519-dalek` |
| **Rejet du shared secret tout-zéro** (RFC 7748 §6) | ✅ | `x25519.rs:94-98` — vérifie `acc |= b`, retourne `InvalidDhResult` |
| Test low-order point (clé publique = 0) | ✅ | `x25519.rs:132-140` |
| `StaticSecret` zeroize au Drop | ✅ | Garanti par `x25519-dalek` (`StaticSecret: ZeroizeOnDrop`) |

### 5.2 Vulnérabilités identifiées

#### 🟡 AUDIT-2-KC-14 [MEDIUM, LEAK] — `X25519KeyPair` ne zeroize pas au Drop

**Localisation:** `x25519.rs:24-36`

```rust
pub struct X25519KeyPair {
    pub public_key: [u8; 32],
    pub private_key: [u8; 32],   // ← secret
}
impl X25519KeyPair {
    pub fn zeroize(&mut self) { ... }   // MANUEL
}
```

Même problème que `Ed25519KeyPair`. La `private_key` (32B) persiste en mémoire après Drop si l'appelant oublie `zeroize()`. `StaticSecret` interne est zeroized mais la copie dans `X25519KeyPair.private_key` ne l'est pas.

**Recommandation:** Implémenter `Drop` similaire à KC-11.

#### 🟢 AUDIT-2-KC-15 [LOW, CRYPTO] — Pas de validation de clé publique au-delà du shared-secret zero check

**Localisation:** `x25519.rs:84-101`

La validation actuelle: après `diffie_hellman`, vérifie si le résultat est tout-zéro. C'est suffisant pour RFC 7748 §6 (rejette les low-order points et le point à l'infini). X25519 est conçu pour être "twist-secure" (Montgomery ladder est constant-time et résistant aux invalid-curve attacks). Cependant:

- Un attaquant pourrait envoyer une clé publique ≠ 0 mais d'ordre faible (e.g., points d'ordre 4, 8) qui ne produisent pas un shared secret zero. X25519 gère cela correctement grâce au clamping (le résultat est dans le sous-groupe d'ordre premier `(q-1)/8` ou `(twist_q-1)/4`), donc le résultat serait soit 0 (rejeté) soit un élément d'ordre premier.

**Conclusion:** La validation est **suffisante** pour X25519. Pas de correction nécessaire — juste INFO pour la traçabilité.

---

## 6. HKDF-BLAKE3 (`kdf.rs`, 253 lignes)

### 6.1 Algorithme — vérifications

| Aspect | Statut | Détail |
|--------|--------|--------|
| `hkdf` v0.12 + `sha2` v0.10 (RustCrypto) | ✅ | Conforme RFC 5869 |
| HKDF-SHA256 extract/expand | ✅ | `kdf.rs:79-108` |
| HKDF-SHA512 expand 64B | ✅ | `:98-108` |
| BLAKE3 KDF (derive_key natif) | ✅ | `:182-205` — domain separation natif |
| Domain separation: chaque KDF spécialisé a un `info`/context unique | ✅ | `derive_enc_mac_keys` (b"ExoOS 2025 enc-key" / "mac-key"), `derive_ipc_channel_key` (b"ExoOS-IPC-2025"), `derive_fs_block_key` (b"ExoOS-FS-2025"), `derive_tcb_attestation_key` (b"ExoOS 2025 tcb-attest"), `derive_key_encryption_key` (b"ExoOS-KEK-2025") |
| Salt en option (None → sel zéros selon RFC 5869) | ✅ | Conforme |
| Tests domain separation | ✅ | `:215-247` |

### 6.2 Vulnérabilités identifiées

#### 🟢 AUDIT-2-KC-16 [LOW, CRYPTO] — `derive_subkey` accepte `salt=None` et `context` vide

**Localisation:** `kdf.rs:114-122`

Si un appelant passe `salt=None` ET `context=b""`, HKDF-SHA256 produit une clé dérivée uniquement depuis `ikm`. C'est RFC 5869 compliant (sel vide = sel de zéros), mais pour des usages spécialisés où `derive_subkey` est exposée publiquement, le risque est qu'un appelant produise des clés non séparées par domaine.

**Mitigation actuelle:** Toutes les fonctions spécialisées (`derive_enc_mac_keys`, etc.) passent des `info`/`context` non-vides. Donc le risque est théorique (uniquement si appel direct de `derive_subkey`).

**Recommandation:** Ajouter un assert `debug_assert!(!context.is_empty())` ou retourner `Err(KdfError::InvalidInput)` si `context` est vide.

#### 🟢 AUDIT-2-KC-17 [LOW, CRYPTO] — `info` channel_id encodé en little-endian sans tag de longueur

**Localisation:** `kdf.rs:138-146` (`derive_ipc_channel_key`)

```rust
let mut info = [0u8; 8 + 18]; // channel_id (8B) + label
info[..8].copy_from_slice(&channel_id.to_le_bytes());
info[8..].copy_from_slice(b"ExoOS IPC channel ");
```

L'`info` est `channel_id_le(8) || "ExoOS IPC channel "`. Sans tag de longueur entre les deux, deux paires `(channel_id, label)` pourraient théoriquement produire le même `info` si la longueur du label variait. Ici le label est fixe, donc sûr en pratique.

**Recommandation:** Adopter un format `len(channel_id) || channel_id || len(label) || label` (HKDF best practice) pour la défense en profondeur.

#### 🟢 AUDIT-2-KC-18 [LOW, INFO] — `DerivedKey32`/`DerivedKey64` zeroize manuel, pas de Drop

Même pattern que KC-11/KC-14: `zeroize()` méthode manuelle, pas de `Drop` automatique. Pour des clés dérivées stockées dans des structs, facile à oublier.

---

## 7. RNG / CSPRNG (`rng.rs`, 530 lignes)

### 7.1 Algorithme — vérifications

| Aspect | Statut | Détail |
|--------|--------|--------|
| Source primaire: RDSEED ×4 + RDRAND ×6 (10 essais chacune) | ✅ | `rng.rs:211-223` |
| Source secondaire: jitter TSC (8 lectures + PAUSE) | ✅ | `:225-232` |
| Source tertiaire: stack pointer (KASLR entropy) | ✅ | `:233` |
| **Conditionnement BLAKE3** du pool → seed 32B whitened | ✅ | `:236-237` — pas d'ad-hoc mixing |
| Flag `hw_seeded` (détection mode dégradé) | ✅ | `:208, 214, 221, 380, 481-483` — exposé en lecture |
| CSPRNG: ChaCha20 block function (RFC 8439) | ✅ | `:260-350` |
| Reseed toutes les 4096 blocs (256 KiB) | ✅ | `:29, 400-413` |
| Zéroïsation pool + seed après usage | ✅ | `:240-246, 383-389, 405-411` (`write_volatile` + `fence(SeqCst)`) |
| `RNG_INIT` AtomicBool empêche double-init | ✅ | `:421, 431-433` (`swap(true, SeqCst)`) |
| Reseed via XOR de nouvelle entropie dans key | ⚠️ | `:305-308` — acceptable, mais KDF serait meilleur (voir KC-21) |

### 7.2 Vulnérabilités identifiées

#### 🟡 AUDIT-2-KC-19 [MEDIUM, CRYPTO] — RNG non FIPS 800-90A compliant : pas de health checks

**Localisation:** `rng.rs` (tout le fichier)

FIPS 800-90A §4.2 exige deux health tests sur les sources d'entropie:
1. **Repetition Count Test (RCT)** — rejette une source qui produit N bits identiques consécutifs (signe de panne).
2. **Adaptive Proportion Test (APT)** — rejette une source biaisée sur une fenêtre de N échantillons.

L'implémentation actuelle ne fait ni l'un ni l'autre. Si RDRAND tombe en panne (défaillance matérielle, attaque Rowhammer sur le DRBG AMD/Intel), le kernel continue à l'accepter comme source d'entropie "matérielle" (`hw=true`) même si elle retourne systématiquement 0xCAFEBABE.

De plus, FIPS 140-3 (IG 9.X) exige ces tests pour toute certification crypto. Si ExoOS vise un jour FIPS (ou si des appelants critiques dépendent de la qualité d'entropie), c'est un blocker.

**Recommandation:** Implémenter RCT (fenêtre 2, rejet si bit identique) + APT (fenêtre 1024, rejet si biais > seuil C = 512 + k·√1024) sur les sorties RDRAND/RDSEED avant de les inclure dans le pool.

#### 🔴 AUDIT-2-KC-20 [HIGH, CRYPTO] — Pas de protection fork/VM-fork

**Localisation:** `rng.rs` (architecture globale)

Si la VM est clonée/snapshotée (KVM `virsh snapshot-create`, VMware clone, container CRIU checkpoint/restore), l'état du CSPRNG (`key`, `nonce`, `counter`, `buffer`) est **duplicqué**. Les deux forks produisent **le même keystream** → toutes les clés dérivées, nonces, IVs sont identiques entre les deux forks.

C'est la vulnérabilité qui a touché Linux (CVE-2013-4335, forks sans reseed) et Debian (CVE-2008-0166, PRNG cassé). Sur un OS cloud-native avec snapshots VM fréquents, c'est critique.

L'API actuelle `rng_fill` ne reseed qu'après 4096 blocs générés. Si la VM est forkée juste après un reseed, les deux forks utilisent le même keystream pendant 256 KiB.

**Mitigation actuelle:** Aucune.

**Recommandations:**
1. **Court terme:** Exiger un reseed explicite après fork via un hook VM-fork (consultation de l'hypercall `VMGENID` sur QEMU/KVM — un ID change à chaque fork, déclenche un reseed forcé).
2. **Moyen terme:** Inclure un compteur "instances" global dans le pool d'entropie, incrémenté à chaque `rng_init()`.
3. **Défense en profondeur:** Mélanger un marqueur temporel (TSC) à chaque `rng_fill` — pas parfait mais augmente la divergence post-fork.

#### 🟡 AUDIT-2-KC-21 [MEDIUM, CRYPTO] — Reseed par XOR (pas de KDF)

**Localisation:** `rng.rs:305-317`

```rust
fn reseed(&mut self, extra: &[u8; 32]) {
    for i in 0..32 {
        self.key[i] ^= extra[i];   // ← XOR simple
    }
    self.nonce[11] = self.nonce[11].wrapping_add(1);
    // ...
}
```

Le reseed XOR la nouvelle entropie dans la clé. Si `extra` est biaisé (e.g., RDRAND défaillant retourne 0xAAAA...), la clé précédente reste partiellement préservée. La pratique standard (Fortuna, NIST SP 800-90A CTR_DRBG) est de **re-deriver la clé** via `key = SHA-256(key || extra)` ou `key = HMAC(key, extra)`.

**Recommandation:**
```rust
fn reseed(&mut self, extra: &[u8; 32]) {
    let mut h = Blake3Hasher::new_keyed(&self.key);
    h.update(extra);
    let mut new_key = [0u8; 32];
    h.finalize(&mut new_key);
    // zeroize old key
    for b in self.key.iter_mut() { unsafe { write_volatile(b, 0); } }
    self.key = new_key;
    // advance nonce (keep)
    // ...
}
```

#### 🟡 AUDIT-2-KC-22 [MEDIUM, CRYPTO] — Mutex global = contention + DoS potentiel

**Localisation:** `rng.rs:421`

```rust
static KERNEL_RNG: Mutex<KernelRng> = Mutex::new(KernelRng::new());
```

Chaque `rng_fill` prend le Mutex global. Sur un système multi-coeur avec des appels fréquents (chaque IPC, chaque nonce, chaque clé), c'est un point de contention sérieux:
- Performance: serialization de tous les appels RNG cross-CPU.
- DoS: un thread qui prend le Mutex et est préempté bloque tous les autres.
- Deadlock potentiel: `rng_fill` ne doit JAMAIS être appelé depuis un contexte où le Mutex est déjà tenu (la doc RNG-01 l'interdit pour NMI, mais pas pour les autres contextes irq).

**Recommandation:** Per-CPU RNG state (comme Linux `get_random_u32`/`batched_entropy`), avec un pool global pour le reseed. Ou utiliser `ChaCha20Csprng` par CPU + reseed périodique depuis le pool global.

#### 🟢 AUDIT-2-KC-23 [LOW, LEAK] — `rng_is_ready()` prend le Mutex pour un check rapide

**Localisation:** `rng.rs:472-474`

```rust
pub fn rng_is_ready() -> bool {
    RNG_INIT.load(Ordering::Acquire) && KERNEL_RNG.lock().initialized
}
```

Pour une fonction supposée "rapide" (`#[inline(always)]`), elle prend le Mutex global. Le `RNG_INIT` AtomicBool seul pourrait suffire si `KernelRng::init` met `initialized=true` avant `RNG_INIT.store(true)` (ordering à respecter).

**Recommandation:** 
```rust
pub fn rng_is_ready() -> bool {
    RNG_INIT.load(Ordering::Acquire)  // init() met initialized=true avant swap(RNG_INIT)
}
```

#### 🟢 AUDIT-2-KC-24 [LOW, CRYPTO] — Counter wrap à 2³² sans garde (RNG)

**Localisation:** `rng.rs:322-325` (`refill_buffer`)

```rust
fn refill_buffer(&mut self) {
    self.buffer = chacha20_block(&self.key, &self.nonce, self.counter);
    self.counter = self.counter.wrapping_add(1);   // ← wrap silencieux
    // ...
}
```

Same issue que KC-05. Cependant, le reseed toutes les 4096 blocs (256 KiB) prévient l'exploitation pratique: counter max atteint = 4096, très loin de 2³². **Non exploitable** mais à corriger pour cohérence.

**Recommandation:** Assert `counter < 2^32-1` ou retourner `Err` si atteint.

#### 🟢 AUDIT-2-KC-25 [LOW, CRYPTO] — Pas d'estimation d'entropie

L'implementation ne maintient pas d'estimateur d'entropie (FIPS 800-90B §3.1.5). C'est optionnel pour un OS kernel non-certifié, mais c'est une défense en profondeur: si toutes les sources matérielles échouent, l'estimateur pourrait déclencher un mode "low entropy" refusant certaines opérations.

Le flag `hw_seeded` est un proxy binaire mais ne distingue pas "RDSEED OK" (entropie vraie) vs "RDRAND OK" (CSPRNG matériel) vs "TSC seulement" (entropie faible).

---

## 8. dm-verity (`drivers/security/verity/src/lib.rs`, 334 lignes)

> ⚠️ **Note de périmètre:** Le fichier s'appelle `drivers/security/verity/src/lib.rs` mais ce n'est PAS une implémentation dm-verity (hash tree de blocks filesystem). C'est un **vérificateur de signature d'image kernel/boot** (Ed25519 + SHA-512 footer-based). Le nom est trompeur.

### 8.1 Algorithme — vérifications

| Aspect | Statut | Détail |
|--------|--------|--------|
| Fail-closed: enum `KernelVerdict` explicite | ✅ | `lib.rs:64-76` — pas de `bool` ambigu |
| `verify_strict` (anti-clés-faibles + anti-malléabilité) | ✅ | `lib.rs:200` |
| Recalcul du hash du corps (pas de confiance au stored_sha) | ✅ | `lib.rs:186-189` |
| `key_is_usable` refuse clés nulles + vecteurs de test RFC 8032 | ✅ | `lib.rs:104-145` — `const fn` utilisable en garde de compilation |
| Pas d'allocation, pas de panic | ✅ | `lib.rs:159-204` |
| TOCTOU: image en slice immutable | ✅ | Pas de race possible |
| Tests: sign-then-verify, tampered, wrong-key, unsigned, unusable keys | ✅ | `lib.rs:278-332` |

### 8.2 Vulnérabilités identifiées

#### 🟡 AUDIT-2-KC-26 [MEDIUM, CRYPTO] — Ed25519 "ph" non-standard (pré-hash sans domain separation RFC 8032)

**Localisation:** `lib.rs:251-252` (sign), `lib.rs:186-200` (verify)

```rust
let digest = sha512_of(body);          // SHA-512(body)
let sig = sk.sign(&digest);            // ← signe le hash, pas le body
// ...
match vk.verify_strict(&digest, &sig) { ... }
```

L'implémentation signe `SHA-512(body)` au lieu de `body`. C'est conceptuellement **Ed25519ph** (pre-hashed EdDSA, RFC 8032 §5.1). Cependant:

1. **Pas de domain separation RFC 8032:** Ed25519ph standard préfixe le hash avec `"SigEd25519 no Ed25519 collisions" || 0x01 || 0x01` avant signature. Sans ce préfixe, **un attaquant qui ferait signer `body` directement à la même clé** (via `sk.sign(body)`) produirait une signature valide pour un message `body' = SHA-512(body)`. Si la même clé est utilisée pour signer à la fois des images kernel (via ce module) et d'autres messages (via `ed25519_sign` direct), il y a **risque de confusion de contexte**.
2. **Collision résistance:** L'attaque théorique "find body' with SHA-512(body') = digest" reste impraticable (SHA-512 est collision-resistant), donc ce n'est pas une faille pratique immédiate. Mais c'est non-standard.

**Recommandation:**
- Soit utiliser `SigningKey::sign(body)` directement (PureEdDSA, signe le message complet). Pour des images kernel de plusieurs Mo, c'est plus lent mais standard.
- Soit implémenter Ed25519ph conforme RFC 8032 (préfixe `"SigEd25519 no Ed25519 collisions"`) si le pre-hash est nécessaire pour performance.
- Soit documenter explicitement que la clé ne doit servir qu'au secure boot (pas de réusage).

#### 🟡 AUDIT-2-KC-27 [MEDIUM, LEAK] — Comparaison `digest != stored_sha` non constant-time

**Localisation:** `lib.rs:187-189`

```rust
if digest.as_slice() != stored_sha {
    return KernelVerdict::Tampered;
}
```

`!=` sur slices fait une comparaison byte-à-byte early-exit (non constant-time). En contexte secure boot, l'attaquant contrôle potentiellement `stored_sha` (dans le footer de l'image). Théoriquement, un attaquant timing-observant pourrait brute-forcer byte-à-byte en mesurant le temps de rejet.

**Exploitabilité pratique:** Faible. L'attaquant n'a généralement qu'une tentative par image (le bootloader ne réessaie pas avec des images modifiées). Et l'objectif final (passer `verify_strict`) nécessite une signature valide, pas juste un hash matching. Mais c'est un manque de rigueur.

**Recommandation:**
```rust
use subtle::ConstantTimeEq;
if !bool::from(digest.as_slice().ct_eq(stored_sha)) {
    return KernelVerdict::Tampered;
}
```

#### 🟢 AUDIT-2-KC-28 [LOW, INFO] — `arrays_eq_32` n'est pas constant-time mais compare des valeurs publiques

**Localisation:** `lib.rs:116-125`

```rust
const fn arrays_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if a[i] != b[i] { return false; }   // early-exit
        i += 1;
    }
    true
}
```

Non constant-time, mais comparaison de `pubkey` (config publique du bootloader) contre `RFC8032_TEST_PUB` et `RFC8032_TEST_SEED_AS_PUB` (constantes publiques). Aucun secret impliqué → pas de timing leak.

**Conclusion:** Pas une vulnérabilité. Juste documenté pour la traçabilité.

---

## 9. fscrypt (`drivers/storage/fscrypt/src/lib.rs`, 399 lignes)

### 9.1 Algorithme — vérifications

| Aspect | Statut | Détail |
|--------|--------|--------|
| AEAD: XChaCha20 (flux) + BLAKE3 keyed MAC (identique kernel) | ✅ | `lib.rs:34-153` — duplication du kernel |
| KAT RFC 8439 §2.3.2 | ✅ | `lib.rs:316-331` |
| Verify-avant-décrypt | ✅ | `lib.rs:175-187` (`aead_open` vérifie tag avant XOR) |
| Tag comparison constant-time | ✅ | `lib.rs:178-184` (`diff |= expected[i] ^ tag[i]`) |
| Tag tronqué 16B (128-bit) | ✅ | Acceptable depuis BLAKE3 256-bit |
| **KEK: Argon2id m=64MiB t=3 p=4** | ✅ | `lib.rs:206-207` — paramètres memory-hard raisonnables |
| Allocation mémoire Argon2 contrôlée (`try_reserve`) | ✅ | `lib.rs:209-213` |
| Wrap format: magic ‖ ver ‖ source ‖ salt ‖ nonce ‖ ct ‖ tag (110 octets) | ✅ | `lib.rs:223-253` |
| AAD du wrap: `"exofs-volume-key-wrap-v1"` | ✅ | `lib.rs:226` — domain separation explicite |
| **Clé de blob dérivée par fichier (pas hardcoded)** | ✅ | `lib.rs:286-291` — `blake3::derive_key("exofs-atrest-key-v1", volume_key ‖ blob_id)` |
| IV par bloc: déterministe `(blob_id, disk_offset)` via BLAKE3 | ✅ | `lib.rs:294-302` — sûr pour blobs immuables content-addressed |
| Tests roundtrip + tamper | ✅ | `lib.rs:333-397` |

### 9.2 Vulnérabilités identifiées

#### 🟡 AUDIT-2-KC-29 [MEDIUM, LEAK] — KEK et Argon2 memory non zeroisés

**Localisation:** `lib.rs:202-217` (`derive_kek`), `:234-253` (`wrap_volume_key`), `:257-278` (`unwrap_volume_key`)

```rust
pub fn derive_kek(...) -> Result<[u8; 32], FsCryptError> {
    // ...
    let mut out = [0u8; 32];           // ← KEK
    let mut memory: Vec<argon2::Block> = Vec::new();   // ← 64 MiB contenant l'état Argon2
    // ...
    a2.hash_password_into_with_memory(passphrase, salt, &mut out, memory.as_mut_slice())?;
    Ok(out)                            // ← pas de zeroize de `memory` ou `out` (mais out est retourné)
}
```

Problèmes:
1. **`memory` (Vec de 64 MiB)** contient l'état intermédiaire d'Argon2id — du matériel dérivé de la passphrase. La `Vec` est dropped à la fin de `derive_kek` mais **pas zeroized** — le contenu persiste dans l'allocateur jusqu'à réutilisation du slot. Sur un système avec swap ou un attaquant qui peut lire la mémoire après coup, c'est une fuite.
2. **`kek` (32B)** retourné par `derive_kek` est utilisé dans `wrap_volume_key`/`unwrap_volume_key` sur la pile, mais **pas zeroized** après usage.

**Recommandation:**
```rust
pub fn derive_kek(...) -> Result<[u8; 32], FsCryptError> {
    // ...
    let mut memory: Vec<argon2::Block> = Vec::new();
    // ...
    a2.hash_password_into_with_memory(passphrase, salt, &mut out, memory.as_mut_slice())?;
    // Zeroize Argon2 memory
    for block in memory.iter_mut() {
        unsafe { core::ptr::write_volatile(block, argon2::Block::default()); }
    }
    core::sync::atomic::fence(Ordering::SeqCst);
    Ok(out)
}
// wrap_volume_key / unwrap_volume_key:
// let mut kek = derive_kek(...)?;
// ... use kek ...
// for b in kek.iter_mut() { unsafe { write_volatile(b, 0); } }
```

#### 🟡 AUDIT-2-KC-30 [MEDIUM, LEAK] — Pas de memory locking (mlock) pour clés et Argon2 memory

**Localisation:** `lib.rs:202-217`, `:234-278`

L'Argon2 memory (64 MiB) et le KEK ne sont pas mlock-ed. Sur un système avec swap (kernel userspace via `exofs-mkroot`), ces buffers pourraient être paginés sur disque, exposant le matériel dérivé de passphrase.

En contexte kernel bare-metal, le kernel memory n'est pas swapped, donc le risque est moindre. Mais le code fscrypt est **partagé** entre kernel et outil host (`exofs-mkroot`), et côté host le swap est un risque réel.

**Recommandation:**
- Côté host: utiliser `memsec::mlock` ou `zeroize::Zeroizing` wrapper.
- Côté kernel: pas pertinent (pas de swap kernel).
- Distinguer via `#[cfg(feature = "std")]`.

#### 🟢 AUDIT-2-KC-31 [LOW, CRYPTO] — Pas de policy enforcement au niveau fscrypt

**Localisation:** `lib.rs` (architecture)

Le module expose uniquement des primitives. La policy enforcement (e.g., "ce répertoire doit être chiffré", "clé expirée après X") est déléguée à l'appelant. C'est un design acceptable, mais il faut s'assurer que l'appelant kernel (`fs/exofs/...`) implémente bien la policy.

**Recommandation:** Auditer les appelants pour confirmer que la policy est bien enforced (hors périmètre de cet audit).

#### 🟢 AUDIT-2-KC-32 [LOW, CRYPTO] — `unwrap_volume_key` laisse `ct` en ciphertext sur échec

**Localisation:** `lib.rs:257-278`

Sur `AuthFailed`, `ct` reste contenant le ciphertext non déchiffré (le XOR n'est pas appliqué). C'est bon pour ne pas révéler d'info sur l'emplacement de l'erreur, mais il faudrait aussi zeroizer `kek` avant retour (cf. KC-29).

#### 🟢 AUDIT-2-KC-33 [LOW, INFO] — `block_nonce` tronque BLAKE3 256→192 bits

**Localisation:** `lib.rs:294-302`

```rust
let h = blake3::hash(&material);   // 32 bytes
let mut nonce = [0u8; 24];
nonce.copy_from_slice(&h.as_bytes()[..24]);   // ← truncate 32→24
```

Troncature de 256 à 192 bits. 192 bits reste ≥112 bits de sécurité (birthday bound) — acceptable pour un nonce XChaCha20. Pas de problème cryptographique, juste documenté.

---

## 10. Caller concern — ExoFS entropy fallback (`kernel/src/fs/exofs/crypto/entropy.rs`)

> Hors périmètre strict mais identifié comme dépendant de la stack crypto kernel.

### 🔴 AUDIT-2-KC-34 [HIGH, CRYPTO] — Fallback PRNG faible (LCG) dans `fill_best_effort`

**Localisation:** `kernel/src/fs/exofs/crypto/entropy.rs:187-202`

```rust
fn fill_best_effort(buf: &mut [u8]) {
    ensure_rng_ready();
    if rng_fill(buf).is_ok() {
        return;
    }

    let mut seed = fallback_entropy_u64();   // ← TSC + stack_addr (faible)
    for chunk in buf.chunks_mut(8) {
        seed = seed
            .rotate_left(7)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15)   // ← LCG-style!
            .wrapping_add(0xA076_1D64_78BD_642F);
        let bytes = seed.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
}
```

**Problème:** Si `rng_fill` (le CSPRNG kernel) échoue — ce qui peut arriver en début de boot avant `rng_init()`, ou en cas de Mutex poisoned — `fill_best_effort` dégrade silencieusement vers un **générateur linéaire congruentiel (LCG)** seedé uniquement par TSC + adresse de pile.

Le LCG `seed = rotate(seed, 7) * K1 + K2` est prédictible: à partir d'une seule sortie, un attaquant qui connaît l'algorithme peut prédire toutes les sorties suivantes. Ce LCG est utilisé pour générer:
- Des nonces XChaCha20 (via `nonce_for_object_id` → `random_u64` → `fill_best_effort`)
- Des salts pour HKDF (via `random_32` → `fill_best_effort`)

Si l'attaquant peut observer un nonce, il peut prédire le suivant → réutilisation de keystream XChaCha20 entre deux messages distincts (le keystream pour nonce₁ ⊕ plaintext₁ révèle plaintext₁, et idem pour nonce₂).

L'audit prompt liste explicitement: *"Pas de PRNG faible fallback (LCG, Mersenne)"* — c'est exactement ce pattern.

**Mitigation actuelle:** La constante magique `0xD1CE_FA11_BA0C_0001` sur non-x86_64 (ligne 229) indique un ack humoristique du problème, mais pas de correction.

**Recommandation:**
1. **Court terme:** Si `rng_fill` échoue, **panic** (ou retourner `ExofsError::EntropyUnavailable`) plutôt que de produire du pseudo-aléa faible. Mieux vaut crasher que d'émettre des nonces prédictibles.
2. **Moyen terme:** `ensure_rng_ready()` devrait bloquer jusqu'à ce que le RNG soit initialisé (avec timeout), au lieu de silently fallback.
3. **Défense en profondeur:** Si fallback vraiment nécessaire, hasher `seed` avec BLAKE3 avant expansion (pas parfait, mais élève la barrière).

---

## 11. Synthèse par catégorie

### 11.1 CRYPTO (algorithmes, modes, IV/nonce, key mgmt)

| ID | Sévérité | Sujet | Statut |
|----|----------|-------|--------|
| KC-01 | HIGH | AES software non constant-time (`aes_xtime` branche + S-Box) | À corriger |
| KC-03 | LOW | Pas de garde 2³²-2 blocs AES-GCM | À corriger |
| KC-05 | HIGH | Compteur ChaCha20 wrap 2³² sans garde (CVE-2019-25005 pattern) | À corriger |
| KC-07 | LOW | `xchacha20_xor` pas type-safe | Hardening |
| KC-19 | MEDIUM | RNG pas de health checks (RCT/APT) | Hardening FIPS |
| KC-20 | HIGH | RNG pas de protection fork/VM-fork | À corriger |
| KC-21 | MEDIUM | Reseed RNG par XOR (pas de KDF) | Hardening |
| KC-26 | MEDIUM | Ed25519ph non-standard (pas de domain separation RFC 8032) | À corriger |
| KC-34 | HIGH | Fallback LCG dans entropy.rs | À corriger |

### 11.2 LEAK (timing, zeroization, logging)

| ID | Sévérité | Sujet | Statut |
|----|----------|-------|--------|
| KC-02 | MEDIUM | AES round keys non zeroizées | À corriger |
| KC-06 | MEDIUM | MAC key/ikm/tag XChaCha non zeroizés | À corriger |
| KC-10 | LOW | `Blake3Hasher` keyed non zeroizé | Hardening |
| KC-11 | MEDIUM | `Ed25519KeyPair` pas de Drop auto | À corriger |
| KC-12 | LOW | `Ed25519KeyPair.expanded` dead code secret | Cleanup |
| KC-14 | MEDIUM | `X25519KeyPair` pas de Drop auto | À corriger |
| KC-22 | MEDIUM | RNG Mutex global = DoS potentiel | Hardening |
| KC-23 | LOW | `rng_is_ready` prend Mutex inutilement | Hardening |
| KC-27 | MEDIUM | Verity `digest != stored_sha` non CT | À corriger |
| KC-29 | MEDIUM | KEK + Argon2 memory non zeroizés | À corriger |
| KC-30 | MEDIUM | Pas de mlock pour clés (côté host) | Hardening |

### 11.3 INTEGRITY (signature, hash, attestation)

| ID | Sévérité | Sujet | Statut |
|----|----------|-------|--------|
| KC-26 | MEDIUM | Ed25519ph confusion de contexte (réusage clé) | À corriger |
| KC-28 | LOW | Verity `arrays_eq_32` non CT (mais valeurs publiques) | OK |

### 11.4 Domain separation & key reuse

| ID | Sévérité | Sujet | Statut |
|----|----------|-------|--------|
| KC-09 | LOW | Repli silencieux contexte KDF BLAKE3 non-UTF8 | Hardening |
| KC-16 | LOW | `derive_subkey` accepte context vide | Hardening |
| KC-17 | LOW | `info` sans tag de longueur | Hardening |

### 11.5 Code quality / hardening

| ID | Sévérité | Sujet | Statut |
|----|----------|-------|--------|
| KC-04 | LOW | AES-GCM pas de KAT NIST | Hardening |
| KC-08 | LOW | Code duplication fscrypt/kernel ChaCha20 | Refactor |
| KC-13 | LOW | Adopter crate `zeroize` | Hardening |
| KC-15 | LOW | X25519 validation shared-secret-zero suffisante | OK |
| KC-18 | LOW | DerivedKey32/64 pas de Drop | Hardening |
| KC-24 | LOW | RNG counter wrap sans garde | Hardening |
| KC-25 | LOW | RNG pas d'estimation d'entropie | Hardening |
| KC-31 | LOW | fscrypt pas de policy enforcement | OK (caller) |
| KC-32 | LOW | `unwrap_volume_key` laisse `ct` sur échec | OK (info) |
| KC-33 | LOW | `block_nonce` truncate 256→192 | OK |

---

## 12. Top 5 vulnérabilités crypto (priorité de correction)

1. **🔴 KC-34 [HIGH]** — Fallback LCG dans `entropy.rs` lorsque `rng_fill` échoue. Prédiction de nonces/salts → réutilisation keystream XChaCha20. **Correctif: panic au lieu de LCG fallback.**

2. **🔴 KC-20 [HIGH]** — RNG sans protection fork/VM-fork. Snapshot VM → duplication d'état RNG → clés identiques entre forks. **Correctif: hook VMGENID + reseed forcé au fork.**

3. **🔴 KC-05 [HIGH]** — Compteur ChaCha20 32-bit wrap sans garde. Messages >256 GiB → réutilisation keystream (CVE-2019-25005 pattern). **Correctif: assert `len ≤ 2³²-2 blocks` ou retourner Err.**

4. **🟡 KC-01 [MEDIUM]** — AES software path non constant-time (`aes_xtime` branche + S-Box cache-timing) quand AES-NI absent. Fuite de clé AES par cache-timing. **Correctif: `aes_xtime` sans branche + exiger AES-NI au boot.**

5. **🟡 KC-29 [MEDIUM]** — KEK et Argon2 memory (64 MiB) non zeroizés dans fscrypt. Persiste en mémoire après usage, risque de dump/swap. **Correctif: zeroize Argon2 memory + kek avant retour.**

## 13. Bonnes pratiques confirmées (pas de correction nécessaire)

- ✅ `verify_strict` Ed25519 partout (kernel + verity) — anti-malléabilité + anti-clés-faibles
- ✅ X25519 rejet shared-secret tout-zéro (RFC 7748 §6)
- ✅ GHASH `gf128_mul` constant-time (corrigé audit précédent, vérifié)
- ✅ Tag verification `subtle::ConstantTimeEq` pour AES-GCM et XChaCha20-BLAKE3
- ✅ Verify-avant-décrypt partout (AES-GCM, XChaCha20-BLAKE3, fscrypt AEAD)
- ✅ Encrypt-then-MAC pour XChaCha20-BLAKE3
- ✅ MAC key séparé (BLAKE3 derive_key context)
- ✅ AAD préfixé par longueur (anti-longueur-extension)
- ✅ Argon2id (m=64 MiB, t=3, p=4) pour KEK — memory-hard
- ✅ Argon2 `try_reserve` avant allocation (OOM-safe)
- ✅ Wrapping clé de volume avec AAD de domaine "exofs-volume-key-wrap-v1"
- ✅ KAT RFC 8439 §2.3.2 pour ChaCha20 kernel + fscrypt
- ✅ Conditionnement BLAKE3 du pool d'entropie RNG (pas d'ad-hoc mixing)
- ✅ Zéroïsation pool + seed RNG après usage (`write_volatile` + fence)
- ✅ `hw_seeded` flag RNG (mode dégradé détectable)
- ✅ RDSEED ×4 + RDRAND ×6 avec retry 10 + PAUSE
- ✅ Domain separation BLAKE3 (`derive_key` contextes uniques)
- ✅ Domain separation HKDF (info labels uniques par usage)
- ✅ `key_is_usable` refuse clés de test RFC 8032 (anti-déploiement clé de test)
- ✅ Fail-closed enum `KernelVerdict` (pas de `bool` ambigu)
- ✅ `XChaCha20Key` (ExoFS) implémente `Drop` avec `write_volatile`

## 14. Score de maturité crypto

| Critère | Note /10 | Commentaire |
|---------|----------|-------------|
| Choix d'algorithmes | 9/10 | Toutes primitives modernes (Ed25519, X25519, ChaCha20, BLAKE3, AES-GCM, Argon2id, HKDF). Pas de RC4/DES/MD5/SHA1. |
| Implémentation | 7/10 | Mostly via crates RustCrypto (excellent). ChaCha20 maison mais KAT-validé. AES-GCM software path non constant-time. |
| Gestion clés/nonces | 7/10 | Domain separation OK, MAC key séparé. Pas de garde counter overflow. Fallback LCG dans entropy.rs. |
| Side-channel resistance | 7/10 | GHASH/AES-NI OK, mais AES software non CT, et quelques `==` sur hashes. |
| Zéroïsation | 6/10 | Partiel: XChaCha20Key OK, mais Ed25519/X25519/AesGcmCipher/KEK non auto-zeroizés. |
| RNG | 6/10 | Bonne base (RDSEED+RDRAND+BLAKE3), mais pas FIPS compliant, pas de fork protection, reseed XOR simple. |
| Tests & validation | 7/10 | KAT RFC 8439 OK. Manque KAT NIST AES-GCM. Manque tests de performance/fuzz. |
| Documentation | 9/10 | Excellente documentation des choix, références aux specs, règles nommées (CRYPTO-01..05). |

**Score global : 7/10** — Solide base, durcissement ciblé nécessaire (5 corrections pour atteindre 8.5/10).

---

## 15. Plan de correction suggéré (priorité décroissante)

### Phase 1 (critique, < 1 jour-homme)
- **KC-34** (`entropy.rs`): remplacer `fill_best_effort` LCG par panic/Err.
- **KC-05** (`xchacha20_poly1305.rs`): ajout garde `len ≤ 2³²-2 blocks`.
- **KC-20** (`rng.rs`): hook VMGENID + reseed forcé après fork.
- **KC-29** (`fscrypt/lib.rs`): zeroize Argon2 memory + kek après usage.

### Phase 2 (important, ~2 jours-homme)
- **KC-01** (`aes_gcm.rs`): `aes_xtime` sans branche + taint si AES-NI absent.
- **KC-11, KC-14, KC-02** (ed25519, x25519, aes_gcm): implémenter `Drop` avec `write_volatile`.
- **KC-26** (`verity`): adopter PureEdDSA (signer body directement) ou Ed25519ph conforme RFC 8032.
- **KC-27** (`verity`): `digest.ct_eq(stored_sha)` via `subtle`.
- **KC-19** (`rng.rs`): health checks RCT + APT.

### Phase 3 (durcissement, ~3 jours-homme)
- **KC-21** (`rng.rs`): reseed via KDF (BLAKE3) au lieu de XOR.
- **KC-22** (`rng.rs`): per-CPU RNG state.
- **KC-06, KC-10, KC-30** (xchacha20, blake3, fscrypt): zeroize matériel intermédiaire.
- **KC-04, KC-08**: KAT NIST AES-GCM + extraction crate `exo-chacha20` partagée.
- Adopter crate `zeroize` partout (KC-13, KC-18).

---

## 16. Références

- NIST SP 800-38D (GCM)
- NIST SP 800-90A/B (DRBG / entropy sources)
- RFC 7748 (X25519) §6 — validation low-order points
- RFC 8032 (Ed25519) §5.1 — Ed25519ph domain separation
- RFC 8439 (ChaCha20-Poly1305) §2.3.2 — KAT
- RFC 5869 (HKDF)
- CVE-2019-25005 (chacha20 crate counter overflow)
- CVE-2013-4335 (Linux fork PRNG reseed)
- Bonnetain-Florey-Schindler (AES bitslice implementations)
- BearSSL constant-time notes (https://www.bearssl.org/constanttime.html)
- ed25519-dalek `verify_strict` doc (clés faibles + malléabilité)
