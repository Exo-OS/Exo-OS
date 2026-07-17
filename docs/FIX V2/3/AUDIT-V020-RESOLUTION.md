# AUDIT-V020 — Résolution des incohérences kernel

**Base :** `AUDIT-V020-INCOHERENCES-KERNEL.md` (HEAD `601f445`, claude-alpha)
**Traité le :** 2026-06-11 · **Build/test :** WSL · **Méthode :** vérification du
code réel avant correction (l'audit source était une analyse statique sans
compilateur ⇒ faux positifs attendus et confirmés sur plusieurs points).

## P0 — corrigés

### P0-1 · Mitigations Spectre AP — ✅ CORRIGÉ
`kernel/src/arch/x86_64/smp/init.rs` `ap_entry()` : la section « 7. Mitigations
spectre » était vide. `apply_mitigations_ap()` (spectre/mod.rs:43) existait mais
n'était jamais appelée ⇒ les APs tournaient sans IBRS/SSBD ni KPTI.
**Vérifié :** `init_kpti()` est per-CPU (`register_cpu(cpu_id, …)`, shadow PML4
par cœur) ⇒ l'appel par-AP est le design voulu, pas une double-init.
**Fix (FIX-AUDIT-V020-P0-1) :** insertion de
`crate::arch::x86_64::spectre::apply_mitigations_ap();` à l'étape 7.

### P0-2 · `EXO_SHIELD_PID` kernel↔serveur — ⚪ FAUX POSITIF (déjà sain)
L'audit confond **endpoint IPC** et **PID**. Le « 10 » est l'endpoint IPC fixe
qu'exo_shield enregistre lui-même (`SYS_IPC_REGISTER(name, EXO_SHIELD_ENDPOINT=10)`,
main.rs:1415) et sur lequel il reçoit. Côté kernel, il n'y a pas (et ne doit pas
y avoir) de constante PID figée : `sys_exo_ipc_create` mappe le **PID dynamique**
réel → `ServiceClass::ExoShield` via `service_class_for_endpoint_name("exo_shield")`.
La politique kernel raisonne en `ServiceClass`, pas en PID brut. La seule vraie
divergence (12 vs 10) avait déjà été corrigée (FIX-SHIELD-PID, policy.rs:43) et
le chemin `exo_cap_check` utilise le PID runtime via `SYS_GETPID` (FIX antérieur).
**Aucune correction kernel nécessaire** ; identité interne cohérente.

## P1 — corrigés

### P1-1 · `strict_exec_signatures` feature fantôme — ✅ CORRIGÉ
La feature était utilisée en `#[cfg(...)]` dans `exec.rs:do_execve` mais absente
de tout `[features]` ⇒ la branche stricte n'était jamais compilée, la signature
ED25519 restait cosmétique.
**Fix (FIX-AUDIT-V020-P1-1) :** déclaration de `strict_exec_signatures = []` dans
`kernel/Cargo.toml`. Build durci : `cargo build --release --features
strict_exec_signatures`. **Validé :** `cargo check --features strict_exec_signatures`
OK (la branche `SignatureVerificationFailed` compile désormais).

### P1-2 · Vecteurs ExoPhoenix jamais armés — ✅ CORRIGÉ
`activate_exophoenix_vectors()` n'était jamais appelée (seul `deactivate` l'était
à l'étape 4 IDT) et `exophoenix_vectors_active()` jamais lue ⇒ garde morte.
**Vérifié :** les handlers freeze/pmc/tlb tournent sur les cœurs de **Kernel A**
(chemin de résurrection PROUVÉ) — non gatés pour ne pas régresser. `stage0_init_
all_steps()` est inconditionnel dans `kernel_init` (lib.rs:277), bien avant que le
sentinel n'appelle `begin_isolation_soft` (sentinel.rs:343).
**Fix (FIX-AUDIT-V020-P1-2) :**
1. `activate_exophoenix_vectors()` ajouté en fin de `stage0_init_all_steps` (étape 13).
2. Lecteur fail-safe dans `begin_isolation_soft()` : refuse de diffuser l'IPI
   freeze (qui gèle tous les cœurs) si les vecteurs ne sont pas armés. En
   exploitation normale le flag est toujours vrai ⇒ aucune régression du chemin prouvé.

### P1-3 · Secure Boot lu mais jamais appliqué (exo-boot) — ✅ CORRIGÉ
`enforce_secure_boot_policy()` existait (logique correcte) mais n'était jamais
appelée ; seul `query_secure_boot_status()` alimentait un diagnostic.
**Fix (FIX-AUDIT-V020-P1-3) :**
- ajout de `verify_kernel_signature() -> bool` (non-bloquant) dans verify.rs ;
- câblage dans `efi_main` : `enforce_secure_boot_policy(sb_status, sig_valid,
  cfg.secure_boot_required)` après chargement kernel, panic si refus. Dev permissif
  (flag=false + UEFI SB inactif) ⇒ kernel non signé accepté avec avertissement ;
  prod (flag=true OU UEFI SB enforcing) ⇒ refus.
**Validé :** `cargo check --target x86_64-unknown-uefi` (exo-boot) OK.

## P2 — traités / qualifiés

### P2-1 · Magics on-disk — ✅ partiel + ⚪ faux positifs
- **OBJECT_HEADER_MAGIC / BLOB_HEADER_MAGIC :** ⚪ writer/reader N'étaient PAS
  désaccordés. `object_reader.rs` importe `OBJECT_HEADER_MAGIC` **depuis
  `object_writer`** (pas depuis core/constants) ; idem blob_reader←blob_writer.
  Le chemin live est cohérent. Les définitions de `core/constants.rs` étaient des
  **doublons morts** (re-exportés dans core/mod.rs mais consommés par aucun
  lecteur). **Fix :** valeurs alignées sur les writers canoniques pour supprimer le
  footgun latent (FIX-AUDIT-V020-P2-1).
- **RELATION_MAGIC :** ⚪ faux positif. `relation_create/query` écrivent ET lisent
  le *registry blob* avec `0x52454C41` (cohérent) ; `relation/relation.rs` utilise
  `0x524C544E` pour une *structure différente* (`RelationOnDisk`, cohérente).
  Même nom, structures distinctes — pas une divergence de champ. Non modifié.
- **VFS_NAMESPACE_MAGIC / EXOAR_MAGIC :** même motif (crates/couches distinctes,
  chacune cohérente). Non modifiés (risque de casser un protocole fonctionnel
  pour zéro gain).

### P2-2 · RING_SIZE IPC = 16 — ⚪ choix de conception documenté
Le commentaire (constants.rs:66) explique : 16 slots pour le chemin rapide, les
gros volumes passent par le ring SHM zero-copy. Slot = 256 o ; 4096 slots = 1 MiB/
ring = régression mémoire sans bénéfice. La « doc disant 4096 » était périmée.
**Non modifié** (le code est correct et auto-documenté).

### P2-3 · MSR dupliqués — ⚪ cohérents, non-urgent (concorde avec l'audit)
Valeurs identiques entre `cpu/msr.rs` et les redéfinitions locales. Aucun bug
actif ; dé-dupliquer touche 5 fichiers pour un gain cosmétique. **Non modifié**
(l'audit lui-même le classe « non urgent »).

### P2-4 · `CRYPTO_PID` 1101/1111 — ⚪ fixtures de test
Local à des `#[test]` distincts, zéro impact production. **Non modifié.**

## Validation
- `cargo check -p exo-os-kernel` OK (+ `--features strict_exec_signatures` OK).
- `cargo check --target x86_64-unknown-uefi` (exo-boot) OK.
- Détail build/test final : voir `docs/FIX V2/3/RESOLUTION_TRACKING.md`.
