# AUDIT-V020 — Incohérences Kernel ExoOS

| Champ | Valeur |
|---|---|
| Projet | ExoOS v0.2.0 "Strata" |
| Dépôt | `github.com/darkfireeee/Exo-OS` |
| HEAD audité | `601f4457cecd588a75eeecc58e21580f871d0dc4` |
| Date d'audit | 2026-06-10 |
| Méthode | Analyse statique croisée Python (pas de compilateur Rust) |
| Périmètre indexé | 1 081 fichiers `.rs` — 19 320 fn — 479 enums — 4 396 constantes |
| Auditeur | claude-alpha |

> **Note de contexte :** le HEAD audité est 5 commits plus récent que le `SESSION_MEMORY_SNAPSHOT.md` (qui pointait `4b6a4d7c`). Plusieurs blocages du snapshot ont été résolus entre-temps (voir §5).

---

## 0. Méthodologie

Quatre passes d'analyse statique ont été appliquées sur l'arbre source complet (hors `target/`), après suppression des commentaires et chaînes pour éviter les faux positifs :

1. **Pass 1 — Index symbolique.** Extraction de toutes les définitions : fonctions (avec marquage `impl Trait` pour exclure le dispatch dynamique), enums + variantes, constantes (nom/type/valeur), statics, blocs `impl ... for ...`.
2. **Pass 2 — Conflits de définition.** Variantes `Enum::X` référencées mais inexistantes ; constantes de même nom à valeurs divergentes ; numéros de syscall ; features `cfg` non déclarées dans un `Cargo.toml`.
3. **Pass 3 — Code mort / non câblé.** Fonctions définies mais jamais référencées ailleurs qu'à leur site de définition (classe « wired but not connected »), priorisées par mots-clés sécurité/boot/wiring.
4. **Pass 4 — Vérification contextuelle.** Lecture du source réel autour de chaque candidat pour trancher vrai bug vs faux positif (test, crate externe, formatage).

Sévérités : **P0** = sécurité ou boot cassé en production · **P1** = fonctionnalité de sécurité morte · **P2** = dette/fragilité sans bug actif · **⚪** = faux positif écarté.

---

## 1. P0 — Bugs critiques

### P0-1 · Les APs ne reçoivent aucune mitigation Spectre

**Fichier :** `kernel/src/arch/x86_64/smp/init.rs` — `ap_entry()`
**Classe :** wired but not connected + régression

Dans le chemin de démarrage d'un Application Processor, l'étape 6c (`init_ap`) est suivie d'un commentaire annonçant les mitigations Spectre, puis directement de l'activation des interruptions. **Aucun appel n'existe entre les deux.**

```rust
180|    crate::scheduler::init_ap(cpu_id);
181|
182|    // 7. Mitigations spectre
183|                                       // <-- VIDE : aucun appel
184|    // 9. Activer les interruptions et entrer dans la boucle idle scheduler
185|    // SAFETY: toutes les structures sont initialisées sur cet AP
186|    core::arch::asm!("sti", options(nostack, nomem));
```

La fonction `apply_mitigations_ap()` **existe** mais n'est **jamais appelée** :

```
kernel/src/arch/x86_64/spectre/mod.rs:43
    43| pub fn apply_mitigations_ap() {
    44|     apply_mitigations_bsp();
    45| }
```

Le BSP, lui, est correctement protégé via `early_init.rs:356` (`apply_mitigations_bsp()`).

**Impact :** sur toute machine multi-cœurs, seul le cœur de boot a IBRS / STIBP / SSBD / KPTI actifs. Tous les APs exécutent du code Ring0 **sans mitigation Spectre v2/v4 et sans KPTI**, exposant le kernel à des fuites cross-process via les cœurs secondaires. Correspond à la régression du P0-2 (« APs MSRs ») que le snapshot marquait résolu.

**Correctif :** insérer à la ligne 183 :
```rust
    // 7. Mitigations spectre (IBRS/STIBP/SSBD + KPTI) sur cet AP
    crate::arch::x86_64::spectre::apply_mitigations_ap();
```

---

### P0-2 · `EXO_SHIELD_PID` diverge entre le kernel et le serveur ExoShield

**Fichiers :**
- `servers/exo_shield/src/ipc_gate/policy.rs:46`
- `kernel/src/security/ipc_policy.rs` (registre dynamique)

**Classe :** split-brain d'identité (constante divergente)

Le serveur ExoShield a été corrigé pour utiliser `EXO_SHIELD_PID = 10` (commentaire FIX-SHIELD-PID expliquant que `12` valait `TTY_SERVER_ENDPOINT` et appliquait par erreur les règles d'ExoShield sur `tty_server`) :

```rust
servers/exo_shield/src/ipc_gate/policy.rs:46
    46| pub const EXO_SHIELD_PID: u32 = 10;
```

**Côté kernel, il n'existe aucune constante équivalente.** Le PID est attribué **dynamiquement à l'enregistrement** dans `SERVICE_REGISTRY` (ipc_policy.rs:42), un tableau de 16 slots rempli à l'ordre de boot. Les seules occurrences de `1102` côté kernel sont **locales à un `#[test]`** (capability/mod.rs:398), sans rapport avec le PID de production.

**Impact :** ExoShield installe ses politiques IPC en supposant que son identité est `10`. Si le kernel ne lui assigne pas exactement `10` au boot (ou si l'ordre d'enregistrement change), `main.rs` évalue la politique avec une identité ne matchant aucune règle installée → le défaut `Deny` retombe sur **toutes** les requêtes d'ExoShield, neutralisant le monitor de sécurité. C'est une dépendance d'ordre de boot **non vérifiée**.

**Correctif recommandé :** soit figer l'assignation du PID `exo_shield` côté kernel à une constante partagée, soit faire négocier ExoShield son PID réel au démarrage au lieu de le coder en dur. À investiguer : quel PID `SERVICE_REGISTRY` attribue réellement à `exo_shield`.

---

## 2. P1 — Fonctionnalités de sécurité mortes

### P1-1 · `strict_exec_signatures` : feature fantôme → signature de binaire cosmétique

**Fichier :** `kernel/src/process/lifecycle/exec.rs:277-288`
**Classe :** feature `cfg` non déclarée

La feature `strict_exec_signatures` est utilisée en `#[cfg(...)]` mais **n'est déclarée dans aucun `Cargo.toml`** du workspace.

```rust
275|     if let Err(_e) = crate::security::check_chain_of_trust() {
277|         #[cfg(not(feature = "strict_exec_signatures"))]
278|         {
279|             // Mode dev : avertissement seulement
281|             b"exec: WARNING unsigned binary executed\n",
283|         }
284|         #[cfg(feature = "strict_exec_signatures")]
285|         {
286|             thread.sched_tcb.signal_mask.store(saved_signal_mask, Ordering::Release);
287|             return Err(ExecError::SignatureVerificationFailed);
288|         }
```

**Impact :** comme la feature n'existe pas, la branche `#[cfg(feature = ...)]` n'est **jamais** compilée. La branche `not(feature)` est donc **toujours** active, même dans un build dit « production ». Conséquence : un binaire dont la chaîne de confiance ED25519 échoue passe **systématiquement** avec un simple warning. **La vérification de signature de binaire ne protège rien.** C'est un masquage de type `TEST_ARMED` au niveau du build.

**Correctif :** déclarer la feature dans le `[features]` du crate kernel et l'activer dans le profil de production :
```toml
[features]
strict_exec_signatures = []
```

### P1-2 · Vecteurs ExoPhoenix activés nulle part

**Fichier :** `kernel/src/exophoenix/stage0.rs`
**Classe :** wired but not connected

Le flag `EXOPHOENIX_VECTORS_ACTIVE` (stage0.rs:138, init `false`) garde l'activation des vecteurs de récupération 0xF1/0xF2/0xF3. Or :

- `setup_b_idt_with_stubs()` (étape 4 du boot) appelle **`deactivate_exophoenix_vectors()`** (ligne 398).
- `stage0_init_all_steps()` (étapes 1a→12) ne rappelle **jamais** `activate_exophoenix_vectors()`.
- **Aucun lecteur** de `exophoenix_vectors_active()` n'existe dans tout le code (hors la fonction elle-même).

```rust
1180| pub fn activate_exophoenix_vectors() {        // jamais appelée
1181|     EXOPHOENIX_VECTORS_ACTIVE.store(true, Ordering::Release);
1185| pub fn deactivate_exophoenix_vectors() {      // appelée à l'étape 4
1190| pub fn exophoenix_vectors_active() -> bool {  // jamais lue
```

**Impact :** le flag passe à `false` et y reste. Les stubs d'exception ExoPhoenix sont installés dans l'IDT mais leur garde logicielle est fermée en permanence. Même squelette que le bug historique `reconstruct_kernel_a()` (existait, jamais appelée).

**Correctif :** appeler `activate_exophoenix_vectors()` à la fin de l'étape 12 de `stage0_init_all_steps()`, **et** brancher un lecteur `exophoenix_vectors_active()` dans le handler d'exception concerné (sinon le flag reste décoratif des deux côtés).

### P1-3 · Secure Boot : statut lu mais jamais appliqué (exo-boot)

**Fichier :** `exo-boot/src/uefi/secure_boot.rs:107`
**Classe :** wired but not connected

`enforce_secure_boot_policy()` est **jamais appelée**. Le bootloader interroge bien l'état Secure Boot (`query_secure_boot_status()`, entry.rs:74) et le range dans une structure de diagnostic, mais la promesse de `config/defaults.rs:23` — *« si `secure_boot_required=true` et pas de Secure Boot → panic »* — **n'est implémentée nulle part**.

```rust
exo-boot/src/config/defaults.rs:23
    23| /// Secure Boot obligatoire (si `true` et pas de Secure Boot -> panic).
    24| pub secure_boot_required:  bool,
    49| secure_boot_required:  false,  // Désactivé -- pour compatibilite dev
```

**Impact :** le défaut étant `false` (dev), l'effet est invisible aujourd'hui. Mais un déploiement passant `secure_boot_required=true` croira être protégé alors qu'aucun enforcement n'a lieu — faux sentiment de sécurité au boot.

**Correctif :** appeler `enforce_secure_boot_policy()` après `query_secure_boot_status()` dans le chemin UEFI, et panic/refuser le boot si requis-mais-absent.

---

## 3. P2 — Dette technique et fragilités

### P2-1 · Magic numbers on-disk / ABI incohérents

Plusieurs structures **persistées sur disque** ou **échangées entre composants** possèdent deux+ définitions de magic avec des **octets réellement différents**. Risque : refus de relire des données valides, ou pire, acceptation de données corrompues.

| Constante | Valeurs en conflit | Localisation | Gravité |
|---|---|---|---|
| `OBJECT_HEADER_MAGIC` | `0x4558_4F42` (writer) vs `0x4F424A45` (constants) | `storage/object_writer.rs:32` vs `core/constants.rs:19` | **Élevée** — writer/reader désaccordés |
| `BLOB_HEADER_MAGIC` | `0x4558424C` / `0x424C4F42` / `0x5244484C424F5845` | `storage/blob_writer.rs:32`, `core/constants.rs:121`, `recovery/fsck_phase2.rs:30` | **Élevée** — 3 valeurs sur le format blob |
| `RELATION_MAGIC` | `0x52454C41` vs `0x524C544E` | `syscall/relation_create.rs:20` vs `relation/relation.rs:16` | Moyenne |
| `EXOAR_MAGIC` | `0x4558_4F41_525F_4152` vs `0x4558_4F41_5200_0001` | `export/exoar_format.rs:17` vs `core/constants.rs:408` | Moyenne — format d'export |
| `VFS_NAMESPACE_MAGIC` | `0x5646_534E` (kernel) vs `0x5654_4654` (serveur) | `posix_bridge/vfs_compat.rs:37` vs `vfs_server/compat/mod.rs:14` | Moyenne — kernel↔serveur |

**Les deux prioritaires** sont `OBJECT_HEADER_MAGIC` et `BLOB_HEADER_MAGIC` : tant qu'aucune donnée réelle n'est écrite, c'est rattrapable ; une fois des objets/blobs persistés avec le mauvais magic, la migration devient nécessaire.

**Correctif :** désigner `core/constants.rs` comme **source unique** et faire que writers, readers et fsck importent la constante depuis là (jamais de redéfinition locale).

> ✅ **Cohérent — pas un conflit :** `BOOT_INFO_MAGIC` concorde entre exo-boot (`0x4F42_5F53_4F4F_5845`) et le kernel (`EXOBOOT_BOOT_INFO_MAGIC`, même valeur, vérifié à `memory_map.rs:719`). Le `0x424F_4F54_5F49_4E46` d'`init_server/boot_info.rs:9` est un **magic distinct** (structure BootInfo userspace de PID 1), pas une divergence.

> ✅ **Faux positif de formatage :** `EXOFS_MAGIC` apparaît comme `0x4558_4F46` et `0x45584F46` — **valeur identique**, seul le formatage des underscores diffère.

### P2-2 · `RING_SIZE` triple, dont un buffer IPC à 16 slots

`RING_SIZE` existe avec trois tailles selon le module :

| Valeur | Module | Statut |
|---|---|---|
| **16** | `ipc/core/constants.rs:68` | ⚠ **Problème connu** — doc annonçait 4096, réalité 16 |
| 1024 / 65536 | `fs/exofs/audit/audit_log.rs:27,30` | ✅ Correct — gardé `#[cfg(test)]` vs prod |
| 65536 | `security/audit/logger.rs:115` | ✅ Cohérent avec l'audit prod |

De même `AUDIT_RING_SIZE` vaut **256 / 1024 / 2048** selon `crypto_audit` / `core/constants` / `quota_audit` — trois capacités non coordonnées pour des journaux d'audit.

**Correctif :** redimensionner le ring IPC (16 est très petit pour du MPMC sous charge) et coordonner les tailles `AUDIT_RING_SIZE`.

### P2-3 · Constantes MSR dupliquées (cohérentes mais fragiles)

Cinq registres MSR ont **deux définitions chacun**, avec valeurs concordantes mais sources multiples :

| MSR | Déf. 1 | Déf. 2 |
|---|---|---|
| `MSR_FS_BASE` | `cpu/msr.rs:51` = `0xC000_0100` | `thread/local_storage.rs:203` = `0xC0000100` |
| `MSR_GS_BASE` | `cpu/msr.rs:45` | `thread/local_storage.rs:206` |
| `MSR_KERNEL_GS_BASE` | `cpu/msr.rs:48` | `thread/local_storage.rs:209` |
| `MSR_IA32_PKRS` | `cpu/msr.rs:60` = `0x0000_06E1` | `security/exoveil.rs:47` = `0x6E1` |
| `MSR_IA32_PL0_SSP` | `cpu/msr.rs:66` = `0x0000_06A4` | `security/exocage.rs:49` + `cet.rs:66` = `0x6A4` |

**Impact :** aucun bug aujourd'hui (valeurs égales). Mais toute modification d'une seule copie crée un MSR fantôme silencieux.

**Correctif :** ré-exporter exclusivement depuis `cpu/msr.rs` ; supprimer les redéfinitions dans `local_storage.rs`, `exoveil.rs`, `exocage.rs`, `cet.rs`.

### P2-4 · `CRYPTO_PID` divergent dans capability/mod.rs

`CRYPTO_PID` vaut `1101` (mod.rs:397) **et** `1111` (mod.rs:447) dans le même fichier. Les deux sont **locaux à des `#[test]` distincts**, donc sans impact production — mais c'est un signe de copier-coller de fixtures de test à harmoniser.

---

## 4. Faux positifs écartés (ne PAS patcher)

| Élément | Pourquoi c'est un faux positif |
|---|---|
| `fs_bridge.rs` / `as_bytes()` | **Résolu.** `BlobId`/`ObjectId` (`core/types.rs:52,97`) exposent bien `as_bytes() -> &[u8;32]`. Le `.as_bytes()` problématique sur `Vec<u8>` a été remplacé par `.as_slice()` (FIX commenté ligne 4084). `NameTooLong`/`OutOfMemory` absents du fichier compilé. **Build propre.** |
| `Error::ConfigSpaceTooSmall`, `Error::InvalidParam`, `Error::ConfigSpaceMissing` | Enum `virtio_drivers::Error` — **crate externe** (`legacy_pci.rs:5`). L'indexeur ne voyait pas ses variantes. |
| `PixelFormat::Rgb/Bgr/Bitmask/BltOnly` | Enum `uefi::proto::console::gop::PixelFormat` — **crate externe** (`graphics.rs:16`). |
| `sys_fork`/`sys_execve` dans `table.rs` | Code mort **connu et documenté** (commentaire ligne 2167). `dispatch.rs:241+` route ces syscalls avant la table. Inoffensif — à supprimer pour la propreté seulement. |
| `SERVER_ENDPOINT_ID` = 1/3/6/7 | Valeur **par serveur** (chaque serveur définit son endpoint). Comportement normal, pas un conflit. |
| `TEST_ARMED` (resurrection.rs:14) | **Déjà corrigé.** La garde de production est désormais `phoenix_ready` (PATCH-P0-PHOENIX, ligne 98) ; `TEST_ARMED` n'est plus la seule condition. `handle_nmi` réel est gardé `#[cfg(exophoenix_resurrection_test)]`. |
| Doublons `IPC_CAP_TOKEN_*`, `ABI_IPC_*` | Valeurs **concordantes** entre `kernel/ipc/core/constants.rs`, `servers/syscall_abi`, `libs/exo_types` (token=20, payload=192, header=8, envelope=200). Aliasing voulu ABI↔serveur. |

---

## 5. Évolution depuis le snapshot (`4b6a4d7c` → `601f445`)

| Élément du snapshot | Statut au HEAD audité |
|---|---|
| `fs_bridge.rs` méthodes inexistantes | ✅ **Résolu** (as_slice, BlobId::as_bytes présent) |
| `TEST_ARMED` toujours false en prod | ✅ **Résolu** (garde `phoenix_ready`) |
| `stage0_init_all_steps()` jamais appelé | ✅ **Câblé** (`lib.rs:277`, FIX-STAGE0) |
| `validate_ipc_envelope_auth` bypass | ✅ **Corrigé** (FIX-IPC-AUTH, table.rs:3296) |
| IBPB au context-switch | ✅ **Présent** (`scheduler/core/switch.rs:256`, gardé `has_ibpb` + changement de PID) |
| P0-2 « APs MSRs » | 🔴 **Régressé** → voir P0-1 (mitigations AP absentes) |
| `reconstruct_kernel_a()` jamais appelée | ⚠ Pattern réapparu sous une autre forme → P1-2 (vecteurs ExoPhoenix) |
| RING_SIZE IPC = 16 (doc dit 4096) | ⚠ **Toujours présent** → P2-2 |

---

## 6. Priorisation du prochain cycle de patch

1. **P0-1 — AP Spectre** (`smp/init.rs:183`) : une ligne, impact sécurité maximal sur multi-cœurs. **À faire en premier.**
2. **P1-1 — `strict_exec_signatures`** : déclarer la feature + l'activer en prod, sinon la signature ED25519 est cosmétique.
3. **P0-2 — `EXO_SHIELD_PID` kernel↔serveur** : figer ou négocier le PID réel pour éviter le `Deny` global.
4. **P2-1 — Magics `OBJECT_HEADER`/`BLOB_HEADER`** : unifier sur `core/constants.rs` avant que des données soient écrites.
5. **P1-2 — Vecteurs ExoPhoenix** : câbler `activate` à l'étape 12 + brancher un lecteur.
6. **P1-3 — Secure Boot enforcement** : appeler `enforce_secure_boot_policy()`.
7. **P2 (dette)** : dé-dupliquer MSR, redimensionner rings, nettoyer fork/execve morts. Non urgent.

---

*AUDIT-V020-INCOHERENCES-KERNEL.md — ExoOS v0.2.0 Strata — HEAD `601f445` — 2026-06-10 — claude-alpha*
