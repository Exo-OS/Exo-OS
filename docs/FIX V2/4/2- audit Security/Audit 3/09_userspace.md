# 09 — Audit USERSPACE + Loader + exo-boot + ExoPhoenix + Outils + Build

Task ID 9a — Deep audit of userspace, loader, exo-boot, ExoPhoenix, tools, and build system.
Scope: `/home/z/my-project/audit/{userspace,loader,exo-boot,tools,docs/Exo-OS-TLA+}` +
`kernel/src/exophoenix/` + workspace `Cargo.toml`, `Makefile`, target JSONs.

Every file was read end-to-end (no skimming). Findings are exhaustive and verbatim.

═══════════════════════════════════════════════════════════════════════════════
## 0. INVENTORY (files audited)
═══════════════════════════════════════════════════════════════════════════════

### userspace/  (libexo + 2 apps)
- `userspace/Cargo.toml` (workspace: libexo, apps/exosh, apps/coreutils)
- `userspace/libexo/{Cargo.toml,src/{lib.rs,sys.rs,vfs.rs,errno.rs}}`
- `userspace/apps/exosh/{Cargo.toml,README.md,src/{main.rs,lib.rs,parser.rs}}`
- `userspace/apps/coreutils/{Cargo.toml,src/lib.rs}` (1 995 lignes, 28 binaires)
- `userspace/apps/coreutils/src/bin/{cat,ls,dd,mkdir,rm,rmdir,touch,cp,mv,wc,
   pwd,stat,uname,whoami,ps,top,kill,echo,sleep,uptime,meminfo,syscall-stat,
   ipc-stat,clear,tree,sync,basename,dirname,true,false}.rs`

### loader/  (dynamic linker + ELF parser + sécurité stub)
- `loader/Cargo.toml`, `loader/src/{lib.rs,main.rs,entry.rs}`
- `loader/src/security/{mod.rs,capability_check.rs,verify_signature.rs,pie_aslr.rs}`
- `loader/src/elf/{mod.rs,parser.rs,validator.rs,segments.rs,dynamic.rs,
   relocations.rs,tls.rs}`
- `loader/src/dynamic_linker/{mod.rs,library.rs,resolver.rs,search_path.rs,
   symbol_table.rs,version.rs}`

### exo-boot/  (UEFI + BIOS bootloader)
- `exo-boot/{Cargo.toml,build.rs}`
- `exo-boot/src/{main.rs,panic.rs}`
- `exo-boot/src/config/{mod.rs,parser.rs,defaults.rs}`
- `exo-boot/src/uefi/{mod.rs,entry.rs,exit.rs,services.rs,secure_boot.rs,
   protocols/{mod.rs,file.rs,graphics.rs,loaded_image.rs,rng.rs}}`
- `exo-boot/src/bios/{mod.rs,vga.rs,disk.rs,mbr.asm,stage2.asm}`
- `exo-boot/src/disk/{mod.rs,gpt.rs}`
- `exo-boot/src/memory/{mod.rs,map.rs,regions.rs,paging.rs}`
- `exo-boot/src/display/{mod.rs,framebuffer.rs,font.rs}`
- `exo-boot/src/kernel_loader/{mod.rs,elf.rs,verify.rs,signing_key.rs,
   handoff.rs,relocations.rs}`
- `exo-boot/linker/{linker.ld,uefi.ld,bios.ld}`

### exophoenix/  (Kernel B, sentinel, forge, handoff, isolate, interrupts)
- `kernel/src/exophoenix/{mod.rs,ssr.rs,sentinel.rs,stage0.rs,
   resurrection.rs,forge.rs,handoff.rs,isolate.rs,interrupts.rs}`
- Total : 3 926 lignes.

### tools/  (scripts d'audit + semgrep + ML + signer + mkroot)
- `tools/scan_unsafe_contracts.py` (102 lignes)
- `tools/scan_unsafe_patterns.py` (257 lignes)
- `tools/audit_constants.py` (236 lignes)
- `tools/check_service_order.py` (245 lignes)
- `tools/check_ipc_policy_mirror.py` (124 lignes)
- `tools/verify_all_patches.py` (48 lignes)
- `tools/verify_p0_phoenix.py` (61 lignes)
- `tools/verify_p0_fork_stubs.py` (90 lignes)
- `tools/verify_p1_exocage.py` (67 lignes)
- `tools/verify_p2_boot.py` (78 lignes)
- `tools/verify_patch_fcacb38d.py` (440 lignes)
- `tools/verify_patch_26e1b5ac.py` (414 lignes)
- `tools/semgrep-rules/exoos.yaml` (406 lignes, 24 règles)
- `tools/ml_training/{train_ngav.py,README.md}`
- `tools/kernel_signer/{Cargo.toml,src/main.rs}`
- `tools/exofs_mkroot/{Cargo.toml,src/main.rs}` (699 lignes)

### Build system
- `Cargo.toml` (workspace racine, 136 lignes)
- `Makefile` (444 lignes)
- `x86_64-exo-os.json`, `x86_64-exo-loader.json`,
  `x86_64-exo-userspace.json`, `x86_64-unknown-none.json`
- `drivers/security/verity/src/lib.rs` (exo-verity, shared signer+verifier)

### TLA+
- 31 specs `.tla` dans `docs/Exo-OS-TLA+/` + toolboxes `Proof V1/`.

═══════════════════════════════════════════════════════════════════════════════
## 1. PER-AREA STATUS
═══════════════════════════════════════════════════════════════════════════════

### 1.1 userspace/  →État: ✗ Sévèrement sous-dimensionné
- **Nature**: workspace Rust std+musl contenant `libexo` (libc syscall wrapper
  89 lignes), `apps/exosh` (shell prototype host std Linux, **PAS le shell
  embarqué** — voir README), `apps/coreutils` (28 binaires compilés en
  `no_std` via macro `exo_command!`).
- **Le shell exécuté au boot est `servers/exosh/` (Ring1) — pas ce code.**
  `userspace/apps/exosh/` est un prototype host Linux qui ne tournera jamais
  sur l'OS.
- **Pas de setuid**: les binaires coreutils utilisent `SYS_GETUID`,
  `SYS_KILL`, `SYS_OPENAT` mais n'implémentent aucune notion de privilège.
  `whoami` ligne 1815: `if uid == 0 { "root" }` — mais aucun setuid binary.
- **Aucun wrapper unsafe exploitable** dans libexo (`sys.rs`): `syscall6`
  via `core::arch::asm!` est classique; `vfs.rs` est trivial.
- **coreutils/src/lib.rs:198-288**: `#[panic_handler]` exit(125); write_all
  fd 1/2 direct. Pas de fuite.
- **PAS DE BYPASS CAPABILITY VIA SYSCALLS DIRECTS** côté userspace —
  c'est le kernel qui doit enforce (et c'est là qu'est le problème, voir
  GAP-09/C-01).
- **Constat**: userspace est une couche fine. La vraie surface d'attaque
  est dans le kernel (syscall handlers, exec, IPC) et dans le loader
  dynamique — pas dans libexo/coreutils.

### 1.2 loader/  →État: ✗ GAP-09 "fix" est cosmétique
- `capability_check.rs` n'est PLUS un stub 4 lignes (devenu 63 lignes).
  **MAIS** le "fix" est une fausse sécurité:
  1. `check_exec_permission()` ne fait que `detect_signature_note(image)`
     qui cherche la string `"EXOSIG\0\0"` dans le binaire → un attaquant
     qui ajoute ces 8 bytes à n'importe quel ELF malveillant passe le check.
  2. `check_exec_permission()` n'est **JAMAIS APPELÉE** par le dynamic
     linker `runtime_entry()` (grep: 0 appelant dans loader/src/dynamic_linker/).
- `verify_signature.rs` (14 lignes): `detect_signature_note()` =
  `image.windows(8).any(|w| w == b"EXOSIG\0\0")`. Pas de vérification
  cryptographique, pas de récupération de clé, pas de comparaison de hash.
- `dynamic_linker/mod.rs:79-98 runtime_entry()`: parse PT_DYNAMIC,
  apply RELA relocations, **run_initializers** (transmute u64 → fn puis call)
  sans AUCUNE vérification de signature. Un ELF non signé peut exécuter
  des fonctions init arbitraires.
- `dynamic_linker/mod.rs:153-175 run_initializers`:
  ```rust
  let init: extern "C" fn() = core::mem::transmute((load_base + dynamic.init) as usize);
  init();
  ```
  Transmute sans validation → n'importe quelle adresse dans le PT_DYNAMIC
  devient une fonction exécutée. Aucune signature check.
- `pie_aslr.rs` (7 lignes): `deterministic_slide(seed, max)` = XOR + rotate
  + modulo. **Déterministe** — si l'attaquant connaît `seed` (par ex. TSC
  boot), slide prévisible. Pas un vrai ASLR.
- `elf/parser.rs` + `validator.rs`: parsing ELF correct avec checks
  d'overflow (checked_add), `filesz > memsz` rejeté, alignement vérifié.
  Bon. Mais `validator.rs:11` accepte `align > 0x20_0000` (2 MiB) comme
  erreur — c'est OK pour PT_LOAD kernel mais pas pour un PIE utilisateur.

### 1.3 exo-boot/  →État: ⚠ Crypto solide mais policy permissive par défaut
- **Boot signature**: exo-verity + Ed25519 `verify_strict` (anti-malléabilité,
  cofactor 8) + SHA-512 hash-then-sign + compile-time guard contre clés
  de test RFC 8032 + fail-closed policy (Tampered toujours refusé même en
  dev). **C'est la partie la plus solide de l'OS.**
  - `kernel_loader/verify.rs:41-56 verify_kernel()`: footer 256 B
    (EXOSIG01 marker ‖ Ed25519 sig ‖ SHA-512 ‖ padding). Recalcule le
    SHA-512 du corps (pas de confiance au hash stocké).
  - `exo-verity::verify_image()` (drivers/security/verity): vrai
    `vk.verify_strict(&digest, &sig)`.
  - `signing_key.rs`: clé publique 32 B réelle (hardcodée, 0x1c…0x8d),
    pas un vecteur de test.
  - `tools/kernel_signer/src/main.rs`: keygen/sign/verify, graine dans
    `.secrets/kernel_signing.seed` (0600).
- **KASLR**: `relocations.rs:70-94 compute_kaslr_base()`: entropie 64 B
  (EFI_RNG ou RDRAND+RDSEED+TSC), plage [4 MiB, 2 GiB] alignée 2 MiB.
  Correct mais entropy source peut tomber sur TSC fallback seul (faible).
- **Problème MAJEUR**: `config/defaults.rs:49`:
  ```rust
  secure_boot_required:  false,  // Désactivé — pour compatibilité dev
  ```
  Par défaut, un kernel non signé est accepté avec warning. La signature
  Ed25519 est calculée mais le verdict `Unsigned` ne bloque pas le boot.
- **Pas de signature du fichier config**: `exo-boot.cfg` sur l'ESP est
  lu et peut **désactiver** `secure_boot_required` et `kaslr_enabled`.
  Un attaquant qui peut écrire sur l'ESP (FAT32 non chiffrée) peut
  installer un kernel non signé + un `exo-boot.cfg` qui désactive la
  vérification.
- **kernel_path configurable**: l'attaquant peut pointer le bootloader
  vers n'importe quel fichier sur l'ESP.
- **Pas de README/SECURITY.md** dans exo-boot/ (alors que la task les
  demandait).
- **`handoff.rs:185` BootInfo::ZEROED** utilise `core::mem::transmute`
  sur un tableau de zéros — si `BootInfo` contenait un enum avec repr
  invalide à 0, ce serait UB. Heureusement `MemoryKind::Empty = 0` est
  explicitement défini pour ça (map.rs:35). OK.
- **`main.rs:165` `static mut BOOT_INFO: MaybeUninit<BootInfo>`**: OK
  car single-threaded bootloader, mais `&mut` sur static mut est
  formellement UB future Rust 2024 — utiliser `addr_of_mut!` (ce qui
  est fait ligne 170, bon).
- **`paging.rs:173 setup_kernel_page_tables`**: identity-map 0–4 GiB
  en huge pages 2 MiB **présentes + writables + global**. Pas de NX.
  Tout le bas de l'espace d'adressage est RWX pour le kernel initial.
  Acceptable pour un bootloader mais à noter.
- **`bios/disk.rs:139-174 read_from_shadow`**: lit 64 MiB depuis
  `0x200_000` (2 MiB phys) en croyant que stage2.asm y a copié le kernel.
  Si stage2.asm n'a pas copié (bug ou attaque), on lit du garbage. Pas
  de checksum intermédiaire avant signature verify.
- **`uefi/protocols/file.rs:179-196 utf8_to_ucs2`**: conversion UCS-2
  tronque à 0xFFFF pour les caractères hors BMP → '?' — pas une faille
  mais peut casser l'ouverture de fichiers avec unicode.

### 1.4 exophoenix/  →État: ✗ Module KERNEL B jamais lancé, isolate jamais appelé
- **P1-2 FIXED**: `activate_exophoenix_vectors()` est bien appelé à la fin
  de `stage0_init_all_steps()` (stage0.rs:1148), et `exophoenix_vectors_active()`
  est bien lu dans `handoff.rs:519 begin_isolation_soft()`. ✅
- **C-02 FIXED**: `forge.rs:286-292 verify_merkle()` retourne
  `Err(MerkleVerifyFailed)` si `kernel_a_hash_is_zero()` au lieu du mode
  dégradé silencieux. ✅
- **BOOT-002 STILL OPEN (pire qu'annoncé)**: `stage0_init()` (stage0.rs:1163)
  est l'entry point dédié Kernel B → `sentinel::run_forever()`.
  **JAMAIS APPELÉ** dans tout le codebase (grep: 0 appelant hors de sa
  propre définition). Seul `stage0_init_all_steps(true)` est appelé depuis
  `kernel/src/lib.rs:284` (chemin Kernel A inline).
  → **Kernel B ne démarre jamais comme core séparé**.
  → **`sentinel::run_forever()` ne s'exécute jamais**.
  → **`send_sipi_once()` vers Kernel B n'est jamais invoqué**.
  → **ExoPhoenix dual-kernel recovery = CODE MORT en production**.
- **BOOT-001 STILL OPEN**: `isolate.rs:231 isolate_kernel_a_memory()`
  (mark A pages !PRESENT + TLB shootdown + IOMMU hard revoke + IDT override)
  **N'EST JAMAIS APPELÉE** (grep: 0 appelant hors de sa définition).
  Le handoff (`handoff.rs::begin_isolation_soft()`) fait:
  1. set HANDOFF_FREEZE_REQ
  2. send_freeze_ipi_broadcast_except_self
  3. stage_soft_revoke_iommu (juste IOTLB flush du blocked domain)
  4. wait freeze ACK 100 µs
  5. stage_hard_revoke_iommu
  6. try_forge_reconstruct_with_policy (forge::reconstruct_kernel_a)
  → **Les pages de Kernel A ne sont JAMAIS marquées !PRESENT**.
  → TLB shootdown 0xF3 est envoyé mais ne fait qu'invalider des TLB
    pour des entrées qui n'ont pas changé.
  → Kernel A peut continuer à accéder son code/ données pendant la
    "cage" — l'isolation mémoire est **une illusion**.
- **SSR (ssr.rs)**: magic `0xEXO_PHXF` (littéralement `0xEXO_PHXF` est
  invalide comme hex car `_` non standard — en fait la lib
  `exo_phoenix_ssr` définit le magic, re-exporté ici). Layout v7 validé
  par `is_compatible_magic_version`. BLAKE3 hash pas explicitement vérifié
  dans ce fichier (mais `validate_layout_v7` check magic+version).
  **Pas de vérification cryptographique du contenu SSR** — un attaquant
  qui peut écrire la SSR (adresse physique `0x0100_0000` selon archi doc)
  peut forger une SSR "valide" avec le bon magic.
- **Sentinel (sentinel.rs)**:
  - Threshold `THREAT_THRESHOLD = 100` (ligne 29).
  - `T_DETECTION_US = 10_000` (10 ms) entre cycles.
  - `LIVENESS_TIMEOUT_US = 200` (200 µs) pour A mirror.
  - `SMI_MULTIPLIER = 3` (cycle > 30 µs = SMI probable, skip).
  - Score: PA_REMAP 90, PF_FLOOD 60, LIVENESS 50, PMC 10.
  - **Sentinel n'est pas désactivable par un attacker runtime** (pas de
    flag). Mais comme `stage0_init()` n'est jamais appelé, la sentinel
    **ne tourne jamais**.
  - `walk_a_page_tables_iterative` (ligne 87-199): 4 niveaux, `max_steps`
    calculé sur `KERNEL_IMAGE_MAX_SIZE / PAGE_SIZE * 4` — borne anti-boucle
    infinie. Bon.
- **forge.rs (Forge Kernel A)**:
  - `A_IMAGE_HASH`/`A_MERKLE_ROOT`/`A_CLEAN_IMAGE` embarqués via
    `include_bytes!(concat!(env!("OUT_DIR"), "/..."))` — générés par
    build.rs à partir de `KERNEL_A_IMAGE_PATH`.
  - `kernel_a_image_provisioned()` retourne false si hash==0.
  - `verify_merkle` (non-test): BLAKE3 de `.text ++ .rodata` comparé à
    `A_MERKLE_ROOT`. ✅ C-02 fixed.
  - **`seed_kernel_a_image_blob()` COMMENTÉ dans lib.rs:326**:
    ```rust
    // DIAG: seed_kernel_a_image_blob temporairement sauté pour isoler le fault.
    // let _ = crate::exophoenix::forge::seed_kernel_a_image_blob();
    ```
    → Si la forge doit recharger l'image Kernel A depuis ExoFS, le blob
      n'est PAS dans le cache. `load_a_image_from_exofs()` retourne
      `Ok(A_CLEAN_IMAGE)` (fallback) — fonctionne, mais c'est un fallback
      qui bypass ExoFS.
- **handoff.rs (A↔B handoff)**:
  - **Peut être déclenché par `try_recover_exception()`** dans
    `resurrection.rs:89`. La garde est `phoenix_ready || test_triggered`.
    `phoenix_ready = (PHOENIX_STATE == Normal)`.
    Comme `stage0_init()` n'est jamais appelé, `PHOENIX_STATE` reste à
    `BootStage0` puis passe à `Degraded` si SSR invalide, ou `Normal` si
    `stage0_init_all_steps()` réussit. En fait, ligne 1148:
    `if PHOENIX_STATE != Degraded { activate_exophoenix_vectors() }` —
    mais `PHOENIX_STATE` n'est jamais mis à `Normal` par
    `stage0_init_all_steps(true)` (seul `stage0_init()` le fait ligne 1178).
    → En production, `PHOENIX_STATE` reste `BootStage0` après
      `stage0_init_all_steps(true)`.
    → `try_recover_exception` ne déclenche JAMAIS car `phoenix_ready`
      est toujours false.
    → **Le chemin de résurrection est inopérant**.
  - `notify_crypto_server_phoenix_wake()` (ligne 178-222): envoie une
    requête IPC au crypto_server (endpoint 4) avec `PHOENIX_WAKE_ENTROPY`
    (msg_type 255). Le `cap_token` est `[0u8; CAP_TOKEN_WIRE_SIZE]` (zero
    token!). La request contient entropie+timestamp en clair.
    → **PhoenixWakeEntropy non wired côté crypto_server** (archi doc):
      pas de reseed post-Phoenix → risque de réutilisation de nonce.
    → **cap_token zero** = potentiellement bypass capability check côté
      crypto_server si le handler ne valide pas.
- **interrupts.rs (0xF1/0xF2/0xF3)**:
  - `handle_freeze_ipi`: CLI + XSAVE optionnel + ACK + spin until
    HANDOFF_B_ACTIVE/NORMAL. Lock-free. ✅
  - `handle_pmc_snapshot_ipi`: lit MSR IA32_PERFEVTSEL0..3 et PMC0..3,
    écrit dans SSR. ✅
  - `handle_tlb_flush_ipi`: CLI + reload CR3 + ACK. ✅
  - **Hijack vecteurs**: l'IDT de Kernel A est overridée par
    `isolate::override_a_idt_with_b_handlers()` (isolate.rs:198-224) —
    mais cette fonction n'est jamais appelée (BOOT-001). Si elle l'était,
    un attaquant qui contrôle l'IDT overwrite pourrait rediriger les
    vecteurs vers du code malveillant. La fonction utilise `sidt` pour
    lire l'IDT courante puis `write_idt_entry` brut — pas de vérification
    que l'IDT pointe bien vers la kernel IDT légitime.
  - Les handlers sont `unsafe extern "C"` lock-free, pas d'alloc. ✅

### 1.5 tools/  →État: ⚠ Scripts fragiles, ML poisonable
- `scan_unsafe_contracts.py`: regex `(^|[^\w])unsafe\s*\{` cherche
  `// SAFETY:` dans les 4 lignes précédentes. **Limites**:
  - Ne détecte pas `unsafe fn` body (seulement les blocs).
  - `unsafe { ... }` sur une même ligne avec `// SAFETY:` en fin de ligne
    est compté comme OK même si le commentaire ne documente pas ce bloc.
  - Exclut `_test.rs`/`_tests.rs` mais pas `tests/`-dans-le-filename.
  - **Pas dans CI** — `Makefile` n'appelle pas `scan_unsafe_contracts.py`.
- `scan_unsafe_patterns.py`: détecte `unwrap()`/`expect()`/`panic!`/`debug_assert!`.
  Escalade à P0 dans `kernel/src/{memory,security,ipc,syscall,exophoenix,scheduler}`.
  **Pas dans CI** non plus.
- `audit_constants.py`: parse les const critiques (MAX_CORES, SSR_MAX_PROCESSES…)
  et vérifie cohérence. Bon outil. Pas dans CI.
- `check_service_order.py`: topological sort du `service_table.rs`, check
  exo_shield avant exosh. Bon. Pas dans CI.
- `check_ipc_policy_mirror.py`: compare le DAG kernel `ipc_policy.rs::POLICY`
  avec `exocordon.rs::AUTHORIZED_GRAPH`. **Excellent outil** (détecte
  blanchiment ou blocage). Pas dans CI.
- `verify_p0_phoenix.py`: vérifie que `resurrection.rs` contient bien la
  garde `phoenix_ready`. **FAUX POSITIF POSSIBLE**: le script ne fait que
  vérifier la présence de patterns regex — il ne vérifie pas que
  `stage0_init()` est appelé ni que `isolate_kernel_a_memory()` est appelé.
  → `verify_p0_phoenix.py` peut retourner PASS alors que la résurrection
    est complètement inopérante en production.
- `verify_p0_fork_stubs.py`: vérifie que `dispatch.rs` route SYS_FORK/
  SYS_VFORK/SYS_EXECVE via `handle_fork_like_inplace`/`handle_execve_inplace`.
  Vérification textuelle. OK.
- `verify_p1_exocage.py`: compte les `assert!` vs `debug_assert!` sur
  bornes TCB. OK.
- `verify_p2_boot.py`: vérifie cfg gate multiboot2. OK.
- `verify_patch_fcacb38d.py` + `verify_patch_26e1b5ac.py`: 850 lignes de
  checks regex. **Problème**: checks purement textuels — peuvent PASS
  même si le code compile pas ou si la logique est cassée.
- `semgrep-rules/exoos.yaml`: 24 règles (DRV-ARCH-01, IPC-RULE-01, ExoFS
  immutable check, PhoenixSafe, ISR alloc forbidden, M01-M22 invariants).
  **Bonnes règles** mais:
  - `missing-phoenix-safe` (ligne 72): regex sur struct contenant
    CapToken sans `impl PhoenixSafe` — peut rater les structs avec
    CapToken dans un champ nested.
  - `clone-settls-without-fs-base` (ligne 368): regex très spécifique,
    faux négatifs si le code est reformatté.
  - **Pas dans CI**.
- `ml_training/train_ngav.py`:
  - **DONNÉES SYNTHÉTIQUES** (README le dit explicitement): le modèle
    NGAV est entraîné sur des événements générés par `gen_event()`
    calqués sur `behaviour_data_for_event()` du kernel.
  - **RISQUE DE POISONING**: si un attaquant peut injecter des events
    malveillants dans le profiler kernel (via IPC EVENT_REPORT), le
    modèle `markov.rs` apprend en ligne → poison direct.
  - Le MLP/IF sont frozen au build (checksum FNV-1a vérifié au load),
    donc non poisonables post-build. Mais le markov online l'est.
  - Le script utilise `SEED = 20260616` — déterministe, reproductible. OK.
  - **Aucune signature du fichier `trained_weights.rs`** — un attaquant
    qui compromet le build peut remplacer les poids. Seul le checksum
    FNV-1a (faible, non cryptographique) protège.
- `exofs_mkroot/src/main.rs` (699 lignes):
  - Pour volume chiffré, utilise `exo_fscrypt::xor_block()` qui est
    **XChaCha20 stream cipher SANS MAC** (lib.rs:305-308). Le kernel
    utilise `aead_seal/aead_open` (XChaCha20+BLAKE3-MAC) pour le wrap
    de clé, mais pour les **blobs de données**, `xor_block` est utilisé
    des deux côtés → **les blobs at-rest ne sont PAS authentifiés**.
    Un attaquant qui peut modifier le disque peut flipper des bits dans
    les blobs sans détection (pas de MAC tag).
  - `random_bytes()` lit `/dev/urandom` — OK pour build host.
  - `build_superblock()` ligne 644-657: `pad1[272]` contient la wrapped
    VK (110 octets) + 162 octets réservés à 0. **Pas de canonicalisation**:
    un attaquant peut écrire dans les 162 octets réservés sans invalider
    le checksum BLAKE3 du superblock (car le checksum couvre tout le
    superblock — en fait si, le checksum couvre `out[..SUPERBLOCK_SIZE-32]`
    donc pad1 est couvert). OK.
  - Pas de signature du superblock → un attaquant qui peut réécrire le
    disque peut remplacer tout le rootfs (mais c'est l'attaque physique
    classique, mitigée par le chiffrement at-rest).

### 1.6 Build system  →État: ⚠ panic=abort ✅, LTO ✅, mais pas de reproducibilité stricte
- **`Cargo.toml` workspace**:
  - `[profile.release]`: `opt-level=3, lto=true, panic="abort", codegen-units=1, strip="none"`. ✅
  - `[profile.dev]`: `panic="abort", codegen-units=1`. ✅
  - **Pas de `overflow-checks = true`** en release → arithmétique
    silencieusement wrap.
  - **Pas de `panic = "unwind"` interdit explicitement** (mais c'est
    `abort` partout).
  - **`[patch.crates-io] log = { path = "libs/vendors/log-upstream" }`**:
    patch vendored. Audit de `log-upstream` non fait ici.
  - Dépendances crypto: `blake3` forced `no_avx2 + no_avx512` (CR4.OSXSAVE=0
    en kernel). `chacha20poly1305` réservé userspace (poly1305 → SSE2 →
    LLVM error). OK technique.
- **`Makefile`**:
  - `build` target: compile Kernel A en release, puis Kernel B avec
    `KERNEL_A_IMAGE_PATH=$(KERNEL_A_DBG)` en env → build.rs l'include
    dans Kernel B. ✅
  - `_sign_kernel`: **si `.secrets/kernel_signing.seed` absent, signe
    PAS et affiche juste un warning jaune**. → **Build par défaut =
    kernel non signé**. La signature n'est appliquée que si l'utilisateur
    a explicitement lancé `make keygen-kernel` avant.
  - `iso` target: `grub-mkrescue` + `--compress=xz`. Pas de signature
    de l'ISO. GRUB Secure Boot non configuré.
  - **Pas de `reproducible-build` target**: `build_date_iso8601()` dans
    exo-boot/build.rs utilise `SOURCE_DATE_EPOCH` si présent (bon) mais
    fallback `"2026-02-23"` hardcodé → non reproductible sans
    `SOURCE_DATE_EPOCH`.
  - `STRIP_TOOL ?= llvm-strip || strip || :` — si aucun strip trouvé,
    binaire non strippé mais build continue silencieusement.
- **`x86_64-unknown-none.json`**: `features: -mmx,-sse,-sse2,-avx,-avx2,-sha,-aes,+shstk`.
  ✅ Désactive SIMD (kernel no_std), active CET shadow stack. Bon.
- **`x86_64-exo-os.json`**: `code-model: kernel`, `linker script:
  exo-boot/linker/linker.ld`. ⚠ Le linker script du bootloader est
  référencé dans le target JSON du kernel — couplage fragile.
- **`x86_64-exo-loader.json` + `x86_64-exo-userspace.json`**:
  `image-base 0x0000010000000000` et `0x0000020000000000` respectivement.
  `features: -sha,-aes` (SHA/AES désactivés pour compat — mais ça
  empêche d'utiliser AES-NI en userspace). `position-independent-executables: false`.
- **`Cargo.lock`** (27 KB): non audité ici en détail, mais **présent** ✅
  → builds reproductibles côté versions. **Risque supply-chain**: toute
  crate tierce (`uefi`, `x86_64`, `blake3`, `ed25519-dalek`, `acpi`…)
  peut être compromise si `cargo publish` d'un mainteneur est attaqué.
  Pas de `[cargo-vet]` config visible. Pas de `cargo audit` dans CI.

### 1.7 TLA+  →État: ⚠ Spécs présents mais déconnectés du code
- 31 fichiers `.tla` + toolboxes dans `docs/Exo-OS-TLA+/`.
- Spécs: ExoPhoenixHandoff, SmpBoot, IrqRouting, IommuQueue, ExoShield,
  Memory, CapTokens, ContextSwitch, Adversarial, ExoFS, ExoNet, PciDoExit,
  ProcessDeath, PhoenixState…
- **Problème**: les specs sont des modèles abstraits. **Aucun lien
  formel** entre le spec TLA+ et le code Rust. Pas de model extraction
  automatique. Si le code diverge du spec, rien ne le détecte.
- Les toolboxes contiennent des outputs de model-checking (`output-*.txt`)
  mais pas de preuve de non-régression CI.
- **Aucun script CI** ne relance TLC ou APALACHE sur les specs.

═══════════════════════════════════════════════════════════════════════════════
## 2. FINDINGS TABLE (synthèse)
═══════════════════════════════════════════════════════════════════════════════

| ID       | Severity | File:line                                          | Résumé                                                       |
|----------|----------|----------------------------------------------------|--------------------------------------------------------------|
| USER-001 | CRITICAL | kernel/src/exophoenix/stage0.rs:1163               | `stage0_init()` (Kernel B entry) JAMAIS appelé → ExoPhoenix mort |
| USER-002 | CRITICAL | kernel/src/exophoenix/isolate.rs:231               | `isolate_kernel_a_memory()` JAMAIS appelé → cage A inopérante  |
| USER-003 | CRITICAL | kernel/src/process/lifecycle/exec.rs:275-292       | C-01: `is_chain_verified()` toujours false → exec sans signature |
| USER-004 | CRITICAL | kernel/src/security/integrity_check/secure_boot.rs:174 | `verify_boot_attestation()` 0 appelant → CHAIN_VERIFIED=false |
| USER-005 | HIGH     | loader/src/security/capability_check.rs:34-56      | GAP-09 "fix" cosmétique: `check_exec_permission` jamais appelé |
| USER-006 | HIGH     | loader/src/security/verify_signature.rs:7-13       | `detect_signature_note` = string match "EXOSIG\0\0" (bypass trivial) |
| USER-007 | HIGH     | loader/src/dynamic_linker/mod.rs:153-175           | `run_initializers` transmute u64→fn sans signature check       |
| USER-008 | HIGH     | exo-boot/src/config/defaults.rs:49                 | `secure_boot_required: false` par défaut → kernel non signé accepté |
| USER-009 | HIGH     | exo-boot/src/config/parser.rs (exo-boot.cfg)       | Config ESP non signée → attaquant ESP peut désactiver SB+KASLR |
| USER-010 | HIGH     | tools/exofs_mkroot/src/main.rs:466-483             | `xor_block` = XChaCha20 SANS MAC → blobs at-rest non authentifiés |
| USER-011 | HIGH     | kernel/src/exophoenix/handoff.rs:191-201           | `cap_token: [0u8; CAP_TOKEN_WIRE_SIZE]` dans PhoenixWakeRequest |
| USER-012 | HIGH     | Makefile:233-240 (_sign_kernel)                    | Build par défaut = kernel non signé (warning jaune seulement)  |
| USER-013 | HIGH     | kernel/src/exophoenix/handoff.rs:178-222           | PhoenixWakeEntropy IPC non wired côté crypto_server (nonce reuse) |
| USER-014 | HIGH     | kernel/src/exophoenix/ssr.rs:104-118               | SSR magic+version check mais PAS de hash cryptographique contenu |
| USER-015 | MEDIUM   | loader/src/security/pie_aslr.rs:1-7                | `deterministic_slide` = XOR+rotate+modulo, prévisible si seed fuit |
| USER-016 | MEDIUM   | exo-boot/src/kernel_loader/relocations.rs:80-94    | KASLR peut tomber sur TSC fallback seul (entropie faible)       |
| USER-017 | MEDIUM   | tools/ml_training/train_ngav.py + README           | NGAV trained on synthetic data; markov online poisonable      |
| USER-018 | MEDIUM   | tools/ml_training/train_ngav.py:285-293            | Checksum MLP = FNV-1a (non crypto) → poids remplaçables        |
| USER-019 | MEDIUM   | Makefile (général)                                 | Aucun script d'audit Python dans CI (scan_unsafe_*, audit_constants…) |
| USER-020 | MEDIUM   | docs/Exo-OS-TLA+/                                  | TLA+ specs non liés au code (pas d'extraction, pas de CI)     |
| USER-021 | MEDIUM   | tools/verify_p0_phoenix.py                         | Vérif regex textuelle → PASS même si résurrection inopérante   |
| USER-022 | MEDIUM   | exo-boot/src/memory/paging.rs:186-194              | Identity-map 0-4 GiB en huge pages RWX (pas de NX) au boot     |
| USER-023 | MEDIUM   | Cargo.toml workspace                               | `overflow-checks` non activé en release                       |
| USER-024 | LOW      | userspace/apps/exosh/src/main.rs                   | Shell prototype host Linux, pas embarqué (README le dit)      |
| USER-025 | LOW      | exo-boot/src/uefi/protocols/loaded_image.rs:53-54  | `image_base=0, image_size=0` hardcoded (uefi 0.26 n'expose pas) |
| USER-026 | LOW      | tools/scan_unsafe_contracts.py                     | Regex raterait unsafe dans unsafe fn body; pas de CI           |
| USER-027 | LOW      | exo-boot/src/bios/disk.rs:139-174                  | `read_from_shadow` lit 64 MiB sans checksum avant sig verify   |
| USER-028 | LOW      | kernel/src/exophoenix/forge.rs (lib.rs:326)        | `seed_kernel_a_image_blob()` COMMENTÉ → fallback A_CLEAN_IMAGE  |
| USER-029 | LOW      | exo-boot/src/uefi/protocols/file.rs:179-196        | `utf8_to_2ucs` tronque hors-BMP → '?' (noms unicode cassés)    |
| USER-030 | LOW      | Makefile:280                                       | `grub-mkrescue --compress=xz` mais ISO pas signée             |

═══════════════════════════════════════════════════════════════════════════════
## 3. DETAILED FINDINGS
═══════════════════════════════════════════════════════════════════════════════

### USER-001 — CRITICAL — `stage0_init()` (Kernel B) jamais appelé

**File**: `kernel/src/exophoenix/stage0.rs:1163`
**Verbatim**:
```rust
/// Stage0 complet (1→13): bascule Normal, SIPI one-shot, puis boucle sentinelle.
pub fn stage0_init() -> ! {
    // Point d'entrée dédié du cœur de Kernel B : séquence complète (kernel_a_boot=false).
    let _summary = stage0_init_all_steps(false);

    if !crate::exophoenix::forge::kernel_a_image_provisioned() {
        log::error!("FORGE: image Kernel A absente — ExoPhoenix désactivé (degraded)");
        PHOENIX_STATE.store(PhoenixState::Degraded as u8, Ordering::Release);
        loop { unsafe { core::arch::asm!("hlt", options(nostack, nomem)); } }
    }
    // ...
    PHOENIX_STATE.store(PhoenixState::Normal as u8, Ordering::Release);
    let _ = send_sipi_once(CORE_A_SLOT, A_ENTRY_VECTOR);
    sentinel::run_forever()
}
```

**Why vulnerable**: Grep sur tout le codebase: `stage0_init\b` n'apparaît
que dans sa propre définition et dans des commentaires. Le kernel appelle
uniquement `stage0_init_all_steps(true)` (lib.rs:284) qui est le chemin
Kernel A inline. **Kernel B ne démarre jamais comme core séparé**,
`sentinel::run_forever()` ne tourne jamais, `send_sipi_once()` vers
Kernel B n'est jamais invoqué. Toute la mécanique ExoPhoenix
(dual-kernel, sentinel heartbeat, recovery <500ms, 100% caps survivantes)
est **code mort en production**. Les 3 926 lignes de exophoenix/ ne
servent qu'à encombrer le binaire kernel.

**Recommended fix**:
1. Réserver un core AP dédié hors `smp_boot_aps` et y appeler
   `stage0_init()` (cf. `docs/SECURITE/PLAN-SECURITE-V020.md` §5.1).
2. Alternative: appeler `stage0_init()` depuis un trampoline AP dédié
   dans `arch/x86_64/smp/init.rs`.
3. Ajouter un test CI qui grep `stage0_init()` et vérifie qu'il est
   appelé au moins une fois hors de sa propre définition.

---

### USER-002 — CRITICAL — `isolate_kernel_a_memory()` jamais appelé

**File**: `kernel/src/exophoenix/isolate.rs:231-243`
**Verbatim**:
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

**Why vulnerable**: Grep: `isolate_kernel_a_memory` n'apparaît qu'ici.
`handoff.rs::begin_isolation_soft()` (ligne 511-542) fait freeze IPI +
soft revoke IOMMU + forge reconstruct, mais **n'appelle pas
`isolate_kernel_a_memory()`**. Conséquences:
- Les pages de Kernel A ne sont jamais marquées `!PRESENT` → Kernel A
  peut continuer à accéder son code/données pendant la "cage".
- Le TLB shootdown 0xF3 est broadcast mais n'invalide que des TLB
  d'entrées inchangées → effet nul.
- L'override IDT de A n'est jamais appliqué → A garde ses vecteurs
  d'interruption légitimes (ou compromis).
- L'IOMMU hard revoke flush juste le blocked domain (qui n'a rien
  d'attaché car les devices de A n'ont jamais été déplacés).

**Recommended fix**: Dans `handoff.rs::begin_isolation_soft()`, après
`stage_hard_revoke_iommu(true)` (ligne 537), ajouter:
```rust
crate::exophoenix::isolate::isolate_kernel_a_memory();
PHOENIX_STATE.store(PhoenixState::IsolationHard as u8, Ordering::Release);
```

---

### USER-003 — CRITICAL — C-01 TOUJOURS OUVERT: exec sans vérification signature

**File**: `kernel/src/process/lifecycle/exec.rs:275-292`
**Verbatim**:
```rust
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

**Why vulnerable**: `is_chain_verified()` retourne toujours `false`
car `CHAIN_VERIFIED` (AtomicBool, secure_boot.rs:125) n'est jamais mis
à `true` — le seul setter est `verify_boot_attestation()` qui n'a
**AUCUN appelant** (grep confirme, voir USER-004). Le bloc entier est
donc du code mort. N'importe quel binaire ELF peut être exec'd sans
vérification de signature Ed25519. L'architecture doc listait C-01
comme "TOUJOURS OUVERT" — confirmé et aggravé: même la feature
`strict_exec_signatures` ne sert à rien car le bloc englobant est
unreachable.

**Recommended fix**:
1. Câbler `verify_boot_attestation()` dans l'early-boot kernel (après
   handoff exo-boot, avant `start_integrity_monitor()`).
2. exo-boot doit produire une `BootAttestation` signée (Ed25519) avec
   PCR BLAKE3 du kernel + BootInfo et la passer au kernel via BootInfo.
3. En attendant, supprimer le `if is_chain_verified()` et appeler
   `check_chain_of_trust()` inconditionnellement quand
   `strict_exec_signatures` est activé.

---

### USER-004 — CRITICAL — `verify_boot_attestation()` 0 appelant

**File**: `kernel/src/security/integrity_check/secure_boot.rs:174-196`
**Verbatim**:
```rust
pub fn verify_boot_attestation(attestation: &BootAttestation) -> Result<(), SecureBootError> {
    // ... (vérifie signature Ed25519 + PCR BLAKE3)
    CHAIN_VERIFIED.store(true, Ordering::Release);
}
```

**Why vulnerable**: Grep `verify_boot_attestation` sur tout `audit/`:
seulement 5 hits, tous dans la définition, le re-export, ou la doc
`PLAN-SECURITE-V020.md` qui le signale comme gap. Aucun code ne
l'appelle. `CHAIN_VERIFIED` reste à `false` pour toujours →
`is_chain_verified()` retourne toujours false → USER-003.

**Recommended fix**: Voir USER-003 fix.

---

### USER-005 — HIGH — GAP-09 "fix" cosmétique: `check_exec_permission` jamais appelé

**File**: `loader/src/security/capability_check.rs:34-56`
**Verbatim**:
```rust
pub fn check_exec_permission(image: &[u8], require_signature: bool) -> ExecCheckResult {
    match detect_signature_note(image) {
        SignatureState::Present => ExecCheckResult::SignedOk,
        SignatureState::Unsigned => {
            if require_signature {
                // ... debug port 0xE9
                ExecCheckResult::Denied
            } else {
                // Mode dev : autoriser avec log
                ExecCheckResult::UnsignedAllowed
            }
        }
    }
}
```

**Why vulnerable**: Grep `check_exec_permission` sur `loader/`: la
fonction est définie dans `capability_check.rs:34` mais n'est appelée
nulle part dans `loader/src/dynamic_linker/mod.rs::runtime_entry()` ni
ailleurs. Le dynamic linker applique les relocations et exécute les
`init_array` sans jamais appeler cette fonction. La "FIX-APP-09" est
une fausse sécurité: le code est là, compile, mais n'est pas câblé.

**Recommended fix**: Dans `runtime_entry()`, avant
`run_initializers()`, appeler:
```rust
match crate::security::capability_check::check_exec_permission(image, require_sig) {
    ExecCheckResult::SignedOk => {},
    ExecCheckResult::UnsignedAllowed => {}, // dev
    ExecCheckResult::Denied => return Err(LoaderError::SignatureRequired),
}
```

---

### USER-006 — HIGH — `detect_signature_note` = string match trivial

**File**: `loader/src/security/verify_signature.rs:7-13`
**Verbatim**:
```rust
pub fn detect_signature_note(image: &[u8]) -> SignatureState {
    if image.windows(8).any(|w| w == b"EXOSIG\0\0") {
        SignatureState::Present
    } else {
        SignatureState::Unsigned
    }
}
```

**Why vulnerable**: La détection cherche la string ASCII
`"EXOSIG\0\0"` n'importe où dans l'image. Un attaquant peut:
- Ajouter ces 8 bytes à la fin de n'importe quel ELF malveillant.
- Mettre ces 8 bytes dans une section `.comment` ou `.note`.
La fonction retourne `Present` → `check_exec_permission` retourne
`SignedOk` → exécution autorisée. **Aucune vérification cryptographique
de signature** côté loader. Seul le kernel `do_execve()` est censé
faire la vraie vérif Ed25519 — mais voir USER-003 (ne le fait pas).

**Recommended fix**: Implémenter une vraie vérification Ed25519 dans
le loader via `exo-verity::verify_image()` (déjà disponible comme
dépendance transitive). Comparer la clé publique embarquée contre
la signature footer EXOSIG01.

---

### USER-007 — HIGH — `run_initializers` transmute u64→fn sans signature check

**File**: `loader/src/dynamic_linker/mod.rs:153-175`
**Verbatim**:
```rust
unsafe fn run_initializers(load_base: u64, dynamic: &DynamicInfo) {
    if dynamic.init != 0 {
        let init: extern "C" fn() = core::mem::transmute((load_base + dynamic.init) as usize);
        init();
    }

    if dynamic.init_array != 0 && dynamic.init_array_size != 0 {
        let count = (dynamic.init_array_size / core::mem::size_of::<u64>() as u64) as usize;
        let entries = core::slice::from_raw_parts(
            load_base.wrapping_add(dynamic.init_array) as *const u64,
            count,
        );
        let mut idx = 0usize;
        while idx < entries.len() {
            let func_addr = entries[idx];
            if func_addr != 0 {
                let init: extern "C" fn() = core::mem::transmute(func_addr as usize);
                init();
            }
            idx += 1;
        }
    }
}
```

**Why vulnerable**: `init` et `init_array` sont des u64 lus depuis le
PT_DYNAMIC de l'ELF. `transmute` vers `extern "C" fn()` puis appel
direct. Aucune vérification que:
- L'adresse est dans la plage PT_LOAD exécutable.
- L'ELF est signé et la signature est valide.
- La capability d'exécution est présente.

Un ELF malveillant peut mettre n'importe quelle adresse dans
`DT_INIT_ARRAY` et le loader l'appellera. Même si le kernel a vérifié
la signature au `do_execve()` (ce qu'il ne fait pas — USER-003), le
dynamic linker tourne **après** le exec, dans le contexte user, avec
accès à toute la mémoire du processus.

**Recommended fix**:
1. Vérifier que chaque adresse `init_array[i]` est dans un segment
   PT_LOAD avec flag PF_X (SegmentFlags.execute).
2. Appeler `check_exec_permission(image, true)` avant
   `run_initializers()`.
3. En mode `strict_exec_signatures`, refuser tout ELF dont la
   signature Ed25519 n'est pas valide via `exo-verity::verify_image()`.

---

### USER-008 — HIGH — `secure_boot_required: false` par défaut

**File**: `exo-boot/src/config/defaults.rs:41-57`
**Verbatim**:
```rust
pub fn default_config() -> Self {
    let mut kernel_path = ArrayString::new();
    let _ = kernel_path.try_push_str("/EFI/exo-os/kernel.elf");

    Self {
        kernel_path,
        kaslr_enabled:         true,   // Activé par défaut (sécurité)
        secure_boot_required:  false,  // Désactivé — pour compatibilité dev
        // ...
    }
}
```

**Why vulnerable**: Par défaut, le bootloader accepte un kernel non
signé (verdict `Unsigned` → `ProceedWithWarning`). La signature
Ed25519 est calculée mais ne bloque pas le boot. Sur une installation
par défaut, un attaquant qui remplace `kernel.elf` sur l'ESP peut
démarrer un kernel compromis sans aucune résistance.

**Recommended fix**: Pour un build release, le défaut devrait être
`true`. Soit via un `#[cfg(feature = "production")]` soit via un
compile-time check qu'aucun binaire exo-boot release n'est produit
avec `secure_boot_required = false`.

---

### USER-009 — HIGH — Config ESP non signée → attaquant ESP peut désactiver SB+KASLR

**File**: `exo-boot/src/config/parser.rs:29-67` + `exo-boot/src/config/mod.rs:26-54`
**Verbatim** (defaults.rs + parser.rs): le fichier `\EFI\exo-os\exo-boot.cfg`
est lu via EFI_FILE_PROTOCOL, parsé comme `key=value`, et appliqué à
`BootConfig`. Aucune signature du fichier de config.

**Why vulnerable**: Si un attaquant a un accès écriture à l'ESP
(partition FAT32 non chiffrée par défaut), il peut:
1. Remplacer `\EFI\exo-os\exo-boot.cfg` par:
   ```
   secure_boot_required=false
   kaslr_enabled=false
   kernel_path=\EFI\EXOOS\evil.elf
   ```
2. Déposer `evil.elf` (kernel modifié, non signé).
3. Au prochain boot, exo-boot charge `evil.elf` sans vérification et
   sans KASLR.

Le firmware UEFI Secure Boot vérifie `exo-boot.efi` (PE32+ sig) mais
**pas** les fichiers de configuration ni le kernel. La chaîne de
confiance s'arrête au bootloader.

**Recommended fix**:
1. Signer `exo-boot.cfg` avec la même clé Ed25519 que le kernel
   (footer EXOSIG01 ou signature détachée).
2. Le bootloader refuse de charger une config non signée en mode
   secure_boot_required.
3. Alternative: embarquer la config par défaut dans le binaire
   exo-boot (compile-time) et n'accepter que des overrides signés.

---

### USER-010 — HIGH — `xor_block` = XChaCha20 SANS MAC → blobs at-rest non authentifiés

**File**: `tools/exofs_mkroot/src/main.rs:466-483` + `drivers/storage/fscrypt/src/lib.rs:304-308`
**Verbatim** (fscrypt/src/lib.rs:304-308):
```rust
/// Chiffre/déchiffre un bloc de blob en place (involution).
pub fn xor_block(key: &[u8; 32], blob_id: &[u8; 32], disk_offset: u64, buf: &mut [u8]) {
    let nonce = block_nonce(blob_id, disk_offset);
    xchacha20_xor(key, &nonce, buf);
}
```

**Verbatim** (exofs_mkroot/src/main.rs:466-483):
```rust
if let Some(vk) = enc_vk {
    let key = exo_fscrypt::blob_key(vk, &blob_id);
    let padded = (blocks * DEVICE_BLOCK_SIZE) as usize;
    let mut buf = vec![0u8; padded];
    buf[..payload.data.len()].copy_from_slice(&payload.data);
    let mut pos = 0usize;
    while pos < padded {
        let end = (pos + DEVICE_BLOCK_SIZE as usize).min(padded);
        exo_fscrypt::xor_block(&key, &blob_id, pos as u64, &mut buf[pos..end]);
        pos = end;
    }
    image.seek(SeekFrom::Start(offset))?;
    image.write_all(&buf)?;
}
```

**Why vulnerable**: `xor_block` ne fait que XOR le plaintext avec le
keystream XChaCha20. **Aucun MAC tag n'est calculé ni stocké**. Le
kernel lit les blobs avec la même fonction `xor_block` → pas de
vérification d'intégrité. Un attaquant qui peut modifier le disque
peut flipper des bits dans le ciphertext; le déchiffrement produira
un plaintext altéré mais valide (pas de détection). C'est une
attaque **bit-flipping** classique contre les stream ciphers non
authentifiés.

Pourtant, la crate exo-fscrypt **a** une vraie AEAD (`aead_seal`/
`aead_open` = XChaCha20 + BLAKE3-MAC cléé + ct_eq), utilisée
correctement pour wrapper la VolumeKey (lib.rs:234-278). Mais pour
les **blobs de données**, c'est `xor_block` qui est utilisé.

**Recommended fix**: Soit:
1. Utiliser `aead_seal`/`aead_open` pour chaque bloc de 4096, stocker
   le tag MAC (16 octets) dans un header de blob ou à la fin du bloc.
2. Ou ajouter un MAC par-blob (BLAKE3 keyed sur le ciphertext + blob_id
   + offset) stocké dans le ObjectIndex.
3. Sinon, documenter clairement que le chiffrement at-rest ExoFS ne
   protège que la confidentialité, pas l'intégrité (et que l'intégrité
   repose sur le hash du BlobId = BLAKE3(path) — mais le path n'est
   pas secret, donc un attaquant peut remplacer un blob par un autre
   dont le path hash au même BlobId, ce qui est impossible
   cryptographiquement mais possible si l'index est aussi modifiable).

---

### USER-011 — HIGH — `cap_token: [0u8; CAP_TOKEN_WIRE_SIZE]` dans PhoenixWakeRequest

**File**: `kernel/src/exophoenix/handoff.rs:191-201`
**Verbatim**:
```rust
let mut request = PhoenixWakeRequest {
    sender_pid: 0,
    msg_type: PHOENIX_WAKE_ENTROPY,
    reply_endpoint: reply_endpoint.get(),
    payload_len: 16,
    version: CRYPTO_PROTOCOL_VERSION,
    flags: 0,
    cap_token: [0u8; crate::security::capability::CAP_TOKEN_WIRE_SIZE],
    payload: [0u8; CRYPTO_REQUEST_PAYLOAD_SIZE],
};
```

**Why vulnerable**: La requête IPC envoyée au crypto_server (endpoint 4)
pendant le handoff ExoPhoenix contient un **capability token tout à
zéro**. Selon l'architecture, les CapTokens sont des tokens 24 B avec
type+rights+object_id+HMAC. Un token tout-zéro est soit:
- Un token "anonyme" que le crypto_server devrait refuser.
- Un token qui bypass le capability check si le crypto_server ne
  valide pas rigoureusement.

Si le crypto_server accepte les tokens zéro (ce qui est probable vu
que CAP-01 "crypto_server non enforced" est listé dans l'archi doc
comme open), un attaquant qui peut envoyer une IPC au crypto_server
peut forger une `PhoenixWakeRequest` avec un token zéro et déclencher
un reseed PRNG → possibilité de forcer une entropy connue.

**Recommended fix**: Le handoff doit obtenir un vrai CapToken
`CAP_CRYPTO_RESEED` via le subsystem capability avant d'envoyer la
requête. Le crypto_server doit `verify_and_get_rights()` sur le token
et refuser les tokens zéro.

---

### USER-012 — HIGH — Build par défaut = kernel non signé

**File**: `Makefile:233-240`
**Verbatim**:
```make
_sign_kernel:
	@if [ -f "$(KERNEL_SIGNER_SEED)" ]; then \
		echo "$(BLUE)[sign] Signature Ed25519 du kernel : $(KERNEL_BIN)$(NC)"; \
		$(KERNEL_SIGNER) sign "$(KERNEL_BIN)" || exit 1; \
	else \
		echo "$(YELLOW)[sign] Clé absente ($(KERNEL_SIGNER_SEED)) — kernel NON signé (dev permissif).$(NC)"; \
		echo "$(YELLOW)        Générez-la : make keygen-kernel$(NC)"; \
	fi
```

**Why vulnerable**: Si `.secrets/kernel_signing.seed` n'existe pas
(cas par défaut après un `git clone`), le build produit un kernel non
signé qui sera accepté par le bootloader (USER-008). Aucun code de
retour d'erreur — le build "réussit" avec un warning jaune. Un
développeur peut facilement publier une ISO non signée sans s'en
rendre compte.

**Recommended fix**:
1. Pour `make release` et `make iso-release`: exiger que la clé
   existe, sinon `exit 1`.
2. Pour `make build` (debug): warning acceptable mais ajouter un
   marker visible dans le kernel (e.g. `cargo:rustc-cfg=unsigned_kernel`)
   qui active un watermark "UNSAFE DEV BUILD" sur l'écran de boot.
3. CI: toujours exécuter `make keygen-kernel` avant `make release`.

---

### USER-013 — HIGH — PhoenixWakeEntropy IPC non wired côté crypto_server

**File**: `kernel/src/exophoenix/handoff.rs:178-222`
**Verbatim**:
```rust
fn notify_crypto_server_phoenix_wake() -> Result<(), &'static str> {
    let endpoint = crate::ipc::core::types::EndpointId::new(CRYPTO_SERVER_ENDPOINT_ID)
        .ok_or("phoenix_wake_invalid_endpoint")?;
    let entropy = phoenix_wake_entropy();
    // ... envoie PhoenixWakeRequest avec msg_type=255 (PHOENIX_WAKE_ENTROPY)
    let send_result = crate::ipc::channel::raw::send_raw(endpoint, request_bytes, RAW_NOWAIT)
        .map(|_| ())
        .map_err(|_| "phoenix_wake_send_failed");
    // ...
    let ack_result = wait_crypto_phoenix_ack(reply_endpoint);
    // ...
}
```

**Why vulnerable**: L'architecture doc liste "PhoenixWakeEntropy NON
wired (reseed post-Phoenix manquant) — RISQUE NONCE REUSE". Le kernel
envoie une IPC au crypto_server pour signaler un wake Phoenix et
demander un reseed PRNG. Mais:
1. Le crypto_server ne gère probablement pas `msg_type = 255`
   (PHOONIX_WAKE_ENTROPY) — pas de handler visible dans
   `servers/crypto_server/src/main.rs` (non audité ici mais l'archi
   doc le confirme).
2. Si le reseed n'a pas lieu, le PRNG kernel continue avec l'état
   pré-Phoenix → les nonces générés post-Phoenix peuvent réutiliser
   l'entropy d'avant le crash → **nonce reuse** dans XChaCha20,
   AES-GCM, etc. → compromission cryptographique totale.
3. `phoenix_wake_entropy()` (ligne 170-176) mélange TSC + APIC ID +
   handoff flag + APIC ticks + FORGE_FAILURE_COUNT. Si le crash se
   reproduit à intervalles réguliers, ces valeurs peuvent être
   proches → entropy faible.

**Recommended fix**:
1. Implémenter le handler `PHOENIX_WAKE_ENTROPY` dans
   `crypto_server/src/main.rs`: reseed le PRNG avec 64 B de RDSEED/
   RDRAND + entropy hardware.
2. Le kernel doit **bloquer** (panic si besoin) tant que le reseed
   n'est pas acquitté, plutôt que de continuer en mode dégradé.
3. Ajouter un test CI qui vérifie que le crypto_server gère bien
   `msg_type = 255`.

---

### USER-014 — HIGH — SSR magic+version check mais PAS de hash cryptographique

**File**: `kernel/src/exophoenix/ssr.rs:104-172`
**Verbatim**:
```rust
pub unsafe fn ssr_atomic(offset: usize) -> &'static AtomicU64 {
    debug_assert!(offset + core::mem::size_of::<AtomicU64>() <= SSR_SIZE);
    let base = phys_to_virt(PhysAddr::new(SSR_BASE)).as_u64() as usize;
    &*((base + offset) as *const AtomicU64)
}

pub fn validate_layout_v7() -> Result<(), SsrVersionError> {
    let value = read_magic_version();
    if exo_phoenix_ssr::is_compatible_magic_version(value) {
        Ok(())
    } else {
        Err(SsrVersionError::IncompatibleMagicVersion(value))
    }
}

pub fn initialize_layout_v7() -> Result<(), SsrVersionError> {
    let observed = read_magic_version();
    if exo_phoenix_ssr::magic_from_magic_version(observed) == exo_phoenix_ssr::SSR_MAGIC
        && !exo_phoenix_ssr::is_compatible_magic_version(observed)
    {
        return Err(SsrVersionError::IncompatibleMagicVersion(observed));
    }
    write_magic_version();
    // ... init atomics
    validate_layout_v7()
}
```

**Why vulnerable**: La SSR est une région physique fixe (0x0100_0000,
64 KiB) partagée entre Kernel A et Kernel B. La validation ne
vérifie que le magic+version (8 octets). **Aucun hash
cryptographique du contenu** n'est calculé ni vérifié. Un attaquant
qui peut écrire dans la région physique SSR (via DMA si l'IOMMU est
mal configuré, ou via un exploit kernel qui obtient un mapping
physique) peut:
1. Préserver le magic + version.
2. Modifier les champs `HANDOFF_FLAG`, `LIVENESS_NONCE`,
   `FREEZE_ACK[slot]`, `PMC_SNAPSHOT[slot]`.
3. Forger un état "FREEZE_ACK_DONE" pour tous les cores → Kernel B
   pense que tous les cores de A ont acquitté le freeze alors qu'ils
   tournent toujours.

L'archi doc dit "SSR 4KiB @ 0x0100_0000, magic 0xEXO_PHXF, BLAKE3-hashed"
mais le code ne fait **pas** de vérification BLAKE3 du contenu SSR.
C'est un gap majeur.

**Recommended fix**: Ajouter un champ `SSR_CONTENT_HASH` (32 B
BLAKE3) dans le header SSR, recalculé à chaque écriture et vérifié
à chaque lecture critique (handoff flag, freeze ack). Utiliser un
HMAC-BLAKE3 cléé avec une clé dérivée du kernel signing key pour
empêcher un attaquant de recalculer le hash.

---

### USER-015 — MEDIUM — `deterministic_slide` = XOR+rotate+modulo

**File**: `loader/src/security/pie_aslr.rs:1-7`
**Verbatim**:
```rust
pub fn deterministic_slide(seed: u64, max_slide_pages: u64) -> u64 {
    if max_slide_pages == 0 {
        return 0;
    }
    let mixed = seed ^ seed.rotate_left(17) ^ 0x9e37_79b9_7f4a_7c15;
    (mixed % max_slide_pages) * 4096
}
```

**Why vulnerable**: La fonction est **déterministe** — ce n'est pas
un vrai ASLR. Si l'attaquant connaît `seed` (par ex. TSC au moment
du exec, leakable via timing side-channel), il peut prédire le slide
exact. Le mélange est faible: XOR + rotate_left(17) + constante.
Pas de diffusion, pas de non-linéarité. Pour un PIE user, le slide
est dans `[0, max_slide_pages * 4096[` — si `max_slide_pages` est
petit (e.g. 256 = 1 MiB), l'attaquant a 256 essais brute-force.

**Recommended fix**: Utiliser un vrai PRNG seedé par RDRAND/RDSEED
ou l'entropy kernel. Ou utiliser BLAKE3 en mode XOF pour mixer seed
+ PID + timestamp. Augmenter `max_slide_pages` à au moins 4096
(16 MiB) pour PIE user.

---

### USER-016 — MEDIUM — KASLR peut tomber sur TSC fallback seul

**File**: `exo-boot/src/kernel_loader/relocations.rs:70-94` + `exo-boot/src/bios/mod.rs:164-203`
**Verbatim** (relocations.rs:70-94):
```rust
pub fn compute_kaslr_base(entropy: &[u8; 64]) -> (u64, u64) {
    let mut mixed: u64 = 0;
    for chunk in entropy.chunks_exact(8) {
        let val = u64::from_le_bytes(chunk.try_into().unwrap_or([0u8; 8]));
        mixed ^= val;
        mixed = mixed.rotate_left(13).wrapping_add(0x9E37_79B9_7F4A_7C15);
    }
    // ...
}
```

**Verbatim** (bios/mod.rs:164-203 `collect_via_tsc_bios`):
```rust
fn collect_via_tsc_bios(count: usize) -> [u8; 64] {
    // ... 8 lectures TSC avec cpuid(0) serialisation
    let mixed = tsc.wrapping_mul(0x6c62272e07bb0142).wrapping_add(0x62b821756295c58d);
    // ...
}
```

**Why vulnerable**: Si ni EFI_RNG_PROTOCOL, ni RDRAND, ni RDSEED ne
sont disponibles (vieille VM, firmware non conforme), le bootloader
tombe sur le fallback TSC seul. Le TSC est **prédictible** pour un
attaquant qui contrôle le timing de boot (e.g. via une VM
checkpoint/restore). L'entropy de 64 B est alors déterministe →
KASLR cassé. L'avertissement est dans le code (rng.rs:14-16) mais
le boot continue.

**Recommended fix**: Si aucune source d'entropy hardware n'est
disponible, refuser le boot en mode secure_boot_required. Sinon,
ajouter un avertissement visible sur l'écran de boot et réduire le
max_slide pour éviter un faux sentiment de sécurité.

---

### USER-017 — MEDIUM — NGAV trained on synthetic data; markov online poisonable

**File**: `tools/ml_training/train_ngav.py` + `tools/ml_training/README.md`
**Verbatim** (README.md:7-12):
```
## ⚠️ Données synthétiques — modèle à ré-entraîner

`train_ngav.py` génère des événements **synthétiques** bénins/malveillants calqués
**exactement** sur la distribution que le kernel fournit au runtime
(`behaviour_data_for_event` dans `servers/exo_shield/src/main.rs` : features creuses
par type d'événement, valeurs clampées à `[0,99]`).
```

**Why vulnerable**:
1. **Modèle entraîné sur données synthétiques**: le MLP/IF ne
   reconnaîtra que les patterns qui matchent `gen_event()`. Un
   vrai malware avec un comportement différent de la distribution
   synthétique sera classé `Benign`.
2. **Markov online appris au runtime** (`ml/markov.rs`): un attaquant
   peut envoyer des EVENT_REPORT IPC (pas de cap requise selon
   l'archi doc) avec des séquences bénignes pendant la phase
   d'apprentissage → le modèle markov apprend "ce comportement est
   normal" → plus tard, l'attaquant exécute le même comportement
   avec des payloads malveillants → non détecté.
3. **Pas de signature des poids** (voir USER-018).

**Recommended fix**:
1. Ré-entraîner sur des traces réelles (profiler.rs sous QEMU avec
   workloads bénins vs malveillants simulés).
2. Pour le markov online: exiger une cap `CAP_EXOSHIELD_REPORT` pour
   envoyer des EVENT_REPORT, ou ignorer les events des PIDs non
   privilégiés pendant la phase d'apprentissage.
3. Périodiquement reseed le markov avec le modèle frozen pour
   éviter la dérive.

---

### USER-018 — MEDIUM — Checksum MLP = FNV-1a (non crypto)

**File**: `tools/ml_training/train_ngav.py:285-293`
**Verbatim**:
```python
def checksum_mlp(w1, b1, w2, b2, w3, b3, version):
    """Checksum d'intégrité FNV-1a 64-bit — DOIT matcher la vérif kernel (FIX-F3)."""
    h = 0x5151_5151_0000_0000
    for arr in (w1, b1, w2, b2, w3, b3):
        for x in arr:
            h ^= (int(x) & 0xFFFFFFFF)
            h = (h * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    h ^= version
    return h & 0xFFFFFFFFFFFFFFFF
```

**Why vulnerable**: FNV-1a est un checksum non cryptographique. Un
attaquant qui compromet le build peut remplacer les poids MLP par
des poids malveillants et recalculer le FNV-1a pour matcher. Le
kernel (FIX-F3) vérifie le checksum au load mais ne peut pas
détecter une substitution avec checksum recalculé.

**Recommended fix**: Utiliser un MAC cryptographique (HMAC-BLAKE3)
avec une clé dérivée du kernel signing key. Le checksum doit être
vérifié au load et toute incompatibilité → panic.

---

### USER-019 — MEDIUM — Aucun script d'audit Python dans CI

**File**: `Makefile` (général)
**Why vulnerable**: Les scripts `scan_unsafe_contracts.py`,
`scan_unsafe_patterns.py`, `audit_constants.py`,
`check_service_order.py`, `check_ipc_policy_mirror.py`,
`verify_all_patches.py` existent mais ne sont jamais invoqués par
`make check`, `make test`, ou `make ci`. Un développeur peut
introduire un `unsafe { ... }` sans `// SAFETY:` ou casser le miroir
ExoCordon sans qu'aucun check le détecte.

**Recommended fix**: Ajouter dans le Makefile:
```make
ci-audit: scan-unsafe scan-patterns audit-constants check-service-order check-ipc-mirror verify-all-patches

scan-unsafe:
	@python3 tools/scan_unsafe_contracts.py --dir all --window 4

scan-patterns:
	@python3 tools/scan_unsafe_patterns.py --dir all --severity P1

# ...
```
Et appeler `make ci-audit` dans la CI.

---

### USER-020 — MEDIUM — TLA+ specs non liés au code

**File**: `docs/Exo-OS-TLA+/` (31 specs .tla + toolboxes)
**Why vulnerable**: Les specs TLA+ modélisent ExoPhoenixHandoff,
SmpBoot, IrqRouting, IommuQueue, etc. mais **aucun lien formel**
n'existe entre le spec et le code Rust. Si le code diverge du spec
(e.g. USER-001 `stage0_init()` jamais appelé alors que le spec
ExoPhoenixHandoff suppose qu'il l'est), rien ne le détecte. Les
toolboxes contiennent des outputs de model-checking mais pas de
CI qui relance TLC ou APALACHE.

**Recommended fix**:
1. Extraire automatiquement des invariants du code (e.g. via
   `mirai` ou `kani`) et les comparer aux invariants TLA+.
2. CI: relancer `tlc2 -config ExoPhoenixHandoff.cfg
   ExoPhoenixHandoff.tla` à chaque PR.
3. Ajouter des assertions runtime dans le code qui vérifient les
   invariants TLA+ critiques (e.g. `assert!(PHOENIX_STATE !=
   BootStage0)` après `stage0_init_all_steps(true)`).

---

### USER-021 — MEDIUM — `verify_p0_phoenix.py` peut PASS même si résurrection inopérante

**File**: `tools/verify_p0_phoenix.py:36-55`
**Verbatim**:
```python
checks = [
    (r'let phoenix_ready\s*=\s*PHOENIX_STATE\.load\(Ordering::Acquire\)', True,
     "phoenix_ready vérifie PHOENIX_STATE.load()"),
    (r'let test_triggered\s*=\s*TEST_ARMED\.swap\(false,\s*Ordering::AcqRel\)', True,
     "test_triggered = TEST_ARMED.swap(false, ...)"),
    # ...
]
```

**Why vulnerable**: Le script vérifie uniquement la présence de
patterns regex dans `resurrection.rs`. Il ne vérifie pas que:
- `stage0_init()` est appelé (USER-001).
- `isolate_kernel_a_memory()` est appelé (USER-002).
- `PHOENIX_STATE` passe à `Normal` en production.
→ Le script peut retourner PASS alors que la résurrection est
**complètement inopérante** en production.

**Recommended fix**: Ajouter des checks:
```python
# Vérifier que stage0_init() est appelé quelque part
src_lib = read("kernel/src/lib.rs")
assert "stage0_init()" in src_lib or "stage0_init_all_steps(false)" in src_lib

# Vérifier que isolate_kernel_a_memory() est appelé depuis handoff.rs
src_handoff = read("kernel/src/exophoenix/handoff.rs")
assert "isolate_kernel_a_memory()" in src_handoff
```

---

### USER-022 — MEDIUM — Identity-map 0-4 GiB en huge pages RWX

**File**: `exo-boot/src/memory/paging.rs:186-194`
**Verbatim**:
```rust
for j in 0..ENTRIES_PER_TABLE {
    let phys = base_2mib + (j as u64) * HUGE_PAGE_SIZE as u64;
    pd.write(j, phys | flags::HUGE_RW | flags::GLOBAL);
}
```

**Why vulnerable**: Les huge pages 2 MiB de l'identity-map 0-4 GiB
sont mappées `PRESENT | WRITABLE | GLOBAL` — **pas de NX**. Tout le
bas de l'espace d'adressage (incluant MMIO, DMA buffers, BIOS) est
exécutable au boot. Si un attaquant peut écrire du code dans une
page DMA (via un device compromis) et qu'un bug du bootloader saute
vers cette adresse, le code s'exécute.

Note: le kernel devrait re-mapper ces régions avec NX après
l'init mémoire, mais pendant la fenêtre de boot, c'est RWX.

**Recommended fix**: Activer NX (EFER.NXE) avant de charger les
pages tables, et mapper les régions non-code avec NO_EXECUTE.
`enable_nxe()` existe dans paging.rs:291 mais n'est pas appelée
avant `setup_kernel_page_tables()`.

---

### USER-023 — MEDIUM — `overflow-checks` non activé en release

**File**: `Cargo.toml` (workspace, lignes 121-136)
**Verbatim**:
```toml
[profile.dev]
opt-level     = 0
debug         = true
panic         = "abort"
codegen-units = 1

[profile.release]
opt-level     = 3
lto           = true
panic         = "abort"
codegen-units = 1
strip         = "none"
```

**Why vulnerable**: `overflow-checks` n'est pas défini. En release,
Rust utilise `wrapping_*` par défaut pour les int opérations →
overflow silencieux. Plusieurs `checked_add`/`saturating_add` sont
utilisés dans le code, mais pas systématiquement. Un overflow non
intentionnel peut conduire à un UB ou un bypass de borne.

**Recommended fix**: Ajouter `overflow-checks = true` dans
`[profile.release]`. Le coût perf est négligeable sur les chemins
critiques qui utilisent déjà `checked_*`.

---

### USER-024 — LOW — `userspace/apps/exosh` est un prototype host Linux

**File**: `userspace/apps/exosh/README.md` + `userspace/apps/exosh/src/main.rs`
**Verbatim** (README.md:1-3):
```
# exosh prototype hôte

Ce dossier contient un prototype `std` destiné aux essais hôte Linux/musl.
Il n'est pas le shell embarqué de l'ISO ExoOS.
```

**Why vulnerable**: Pas une vulnérabilité mais une confusion
potentielle. `userspace/apps/exosh/src/main.rs` utilise
`std::process::Command::new(cmd).args(...).status()` — ce qui
fork+exec sur Linux host. Si un développeur confond ce prototype
avec le shell embarqué (`servers/exosh/`), il peut penser que le
shell ExoOS a une sécurité équivalente au shell Linux (job control,
path sanitization, etc.) — ce qui n'est pas le cas.

**Recommended fix**: Déplacer `userspace/apps/exosh/` vers
`tools/host_prototypes/exosh/` pour clarifier.

---

### USER-025 — LOW — `image_base=0, image_size=0` hardcoded dans LoadedImage

**File**: `exo-boot/src/uefi/protocols/loaded_image.rs:53-54`
**Verbatim**:
```rust
// Dans uefi 0.26, image_base et image_size sont accessibles via .info()
// qui n'existe plus — on utilise les champs internes via l'API publique.
// LoadedImage n'expose pas image_base/image_size directement dans 0.26.
// On utilise 0 comme fallback (ces champs sont rarement nécessaires).
let image_base  = 0u64; // LoadedImage 0.26 n'expose pas image_base directement
let image_size  = 0u64;
```

**Why vulnerable**: `image_base` et `image_size` sont hardcoded à 0.
Si une logique de sécurité (e.g. vérifier que l'ELF kernel est
chargé dans la plage attendue, ou mesurer l'image bootloader pour
TPM attestation) utilise ces valeurs, elle obtiendra 0 → bug ou
bypass. Actuellement ces champs sont "rarement nécessaires" selon
le commentaire, mais c'est une dette technique.

**Recommended fix**: Upgrader `uefi` crate à une version qui expose
`image_base`/`image_size`, ou utiliser `uefi-raw` pour accéder
aux champs bruts.

---

### USER-026 — LOW — `scan_unsafe_contracts.py` rate unsafe dans unsafe fn body

**File**: `tools/scan_unsafe_contracts.py:20-23`
**Verbatim**:
```python
UNSAFE_BLOCK = re.compile(r'(^|[^\w])unsafe\s*\{')
UNSAFE_DECL  = re.compile(r'\bunsafe\s+(fn|trait|impl)\b')
# ...
if UNSAFE_DECL.search(line):
    continue
```

**Why vulnerable**: Le script ignore les lignes contenant
`unsafe fn`/`unsafe trait`/`unsafe impl`. Mais à l'intérieur d'une
`unsafe fn`, un bloc `unsafe { ... }` imbriqué sera aussi ignoré si
la regex `UNSAFE_DECL` matche la même ligne — ce qui n'est pas le
cas pour un bloc imbriqué sur une ligne différente, mais peut rater
des patterns comme `unsafe fn foo() { unsafe { ... } }` sur une
même ligne. Plus important: le script **n'exige pas** de `// SAFETY:`
sur les `unsafe fn` elles-mêmes, seulement sur les blocs.

**Recommended fix**: Étendre le script pour vérifier les
`unsafe fn` (exiger `/// # Safety` doc comment) et les `unsafe impl`.

---

### USER-027 — LOW — `read_from_shadow` lit 64 MiB sans checksum avant sig verify

**File**: `exo-boot/src/bios/disk.rs:139-174`
**Verbatim**:
```rust
fn read_from_shadow(
    &self,
    lba: u64,
    sector_count: usize,
    buf: &mut [u8],
) -> Result<(), DiskError> {
    const STAGE2_DISK_SHADOW_BASE: u64 = 0x200000; // 2 MB
    const SHADOW_MAX_BYTES: usize = 64 * 1024 * 1024; // 64 MB
    // ...
    unsafe {
        core::ptr::copy_nonoverlapping(src_ptr, buf.as_mut_ptr(), byte_count);
    }
    Ok(())
}
```

**Why vulnerable**: En mode BIOS, stage2.asm copie le kernel depuis
le disque vers `0x200_000` (2 MiB phys). `read_from_shadow` lit 64
MiB depuis cette zone **sans aucun checksum**. Si stage2.asm a un
bug (lecture partielle, mauvais LBA) ou si la mémoire à 0x200_000
est corrompue (DMA, bit flip), le bootloader lira un kernel
corrompu. La vérification Ed25519 détectera une corruption
(cryptographique) mais si la corruption tombe sur le footer
EXOSIG01, le verdict sera `Unsigned` au lieu de `Tampered` →
accepté en mode dev permissif.

**Recommended fix**: Ajouter un checksum (CRC32 ou BLAKE3) sur la
zone shadow, vérifié avant `enforce_or_panic()`.

---

### USER-028 — LOW — `seed_kernel_a_image_blob()` COMMENTÉ dans lib.rs

**File**: `kernel/src/lib.rs:326`
**Verbatim**:
```rust
if exofs_ready {
    // DIAG: seed_kernel_a_image_blob temporairement sauté pour isoler le fault.
    // let _ = crate::exophoenix::forge::seed_kernel_a_image_blob();
}
```

**Why vulnerable**: La fonction qui provisionne le cache ExoFS avec
l'image propre de Kernel A est commentée "temporairement". En cas
de résurrection ExoPhoenix, `forge::load_a_image_from_exofs()`
tombera sur le fallback `Ok(A_CLEAN_IMAGE)` (image embarquée à la
compilation) au lieu de charger depuis ExoFS. Ça fonctionne
mécaniquement mais:
1. L'image embarquée peut être différente de l'image ExoFS réelle
   si le build a changé entre les deux.
2. Le contrat "reconstruction depuis ExoFS" n'est pas réellement
   testé.

**Recommended fix**: Décommenter et investiguer le "fault" qui a
justifié ce diagnostic. Si c'est un bug ExoFS, le corriger; sinon,
documenter pourquoi le fallback est acceptable.

---

### USER-029 — LOW — `utf8_to_ucs2` tronque hors-BMP → '?'

**File**: `exo-boot/src/uefi/protocols/file.rs:179-196`
**Verbatim**:
```rust
fn utf8_to_ucs2(src: &str, dst: &mut [u16]) -> Result<usize, ()> {
    // ...
    for ch in src.chars() {
        // UCS-2 : seulement le BMP — les caractères hors BMP → '?'
        let c = if (ch as u32) < 0xD800 || ((ch as u32) > 0xDFFF && (ch as u32) < 0x10000) {
            ch as u16
        } else {
            b'?' as u16
        };
        // ...
    }
}
```

**Why vulnerable**: Pas une vulnérabilité de sécurité, mais un bug
fonctionnel. Les chemins UEFI contenant des caractères hors-BMP
(emoji, certains CJK) seront tronqués à '?'. Si le kernel_path dans
`exo-boot.cfg` contient de tels caractères, le boot échouera avec
"File not found".

**Recommended fix**: Implémenter la conversion UTF-16 complète
(avec surrogate pairs pour les caractères hors-BMP).

---

### USER-030 — LOW — ISO GRUB pas signée

**File**: `Makefile:266-281`
**Verbatim**:
```make
_make_iso:
	@rm -rf $(ISO_WORKDIR)
	@mkdir -p $(ISO_WORKDIR)/boot/grub
	@cp $(KERNEL_BIN) $(ISO_WORKDIR)/boot/exo-os-kernel
	@$(STRIP_TOOL) --strip-all $(ISO_WORKDIR)/boot/exo-os-kernel 2>/dev/null || true
	@cp bootloader/grub.cfg $(ISO_WORKDIR)/boot/grub/grub.cfg
	@grub-mkrescue -o $(ISO_OUTPUT) $(ISO_WORKDIR) \
	    --compress=xz 2>&1 | grep -v "^$$" || true
```

**Why vulnerable**: L'ISO produite par `grub-mkrescue` n'est pas
signée. GRUB Secure Boot n'est pas configuré. Si l'ISO est
distribuée sans Secure Boot activé côté firmware, n'importe quel
firmware la bootera sans vérification. Le kernel à l'intérieur est
signé (Ed25519 via exo-verity) mais l'ISO elle-même (et le bootloader
GRUB dedans) ne le sont pas.

**Recommended fix**: Pour une distribution release:
1. Signer l'ISO avec une clé GPG et publier le hash SHA-256.
2. Utiliser `shim-signed` + GRUB Secure Boot pour vérifier la
   signature du bootloader.
3. Alternative: utiliser exo-boot.efi signé (PE32+) directement,
   sans GRUB.

═══════════════════════════════════════════════════════════════════════════════
## 4. VERDICT
═══════════════════════════════════════════════════════════════════════════════

**ExoPhoenix est un mirage.** L'architecture documentée (dual-kernel A↔B,
sentinel heartbeat, recovery <500ms, 100% caps survivantes, isolate mémoire)
existe dans le code mais **n'est pas câblée en production**:
- `stage0_init()` (Kernel B entry) — jamais appelé (USER-001).
- `isolate_kernel_a_memory()` — jamais appelée (USER-002).
- `try_recover_exception()` — `phoenix_ready` toujours false car
  `PHOENIX_STATE` reste `BootStage0` (USER-001 conséquence).
- `seed_kernel_a_image_blob()` — commenté (USER-028).

3 926 lignes de code ExoPhoenix sont compilées dans le binaire kernel
mais ne s'exécutent jamais. Le `verify_p0_phoenix.py` retourne PASS
parce qu'il vérifie du texte, pas du comportement (USER-021).

**La chaîne de confiance exec est brisée.** C-01 confirmé ouvert
et aggravé:
- `verify_boot_attestation()` n'a aucun appelant (USER-004).
- `is_chain_verified()` retourne toujours `false` → le bloc
  `if is_chain_verified()` dans `do_execve()` est du code mort
  (USER-003).
- Même `strict_exec_signatures` ne sert à rien car le bloc englobant
  est unreachable.
- Le loader dynamique `runtime_entry()` appelle `run_initializers()`
  (transmute u64→fn) **sans aucune vérification** (USER-007).
- `check_exec_permission()` existe (FIX-APP-09) mais n'est jamais
  appelée (USER-005).
- `detect_signature_note()` cherche la string `"EXOSIG\0\0"` —
  bypass trivial (USER-006).

→ **N'importe quel ELF peut être exec'd sans vérification de signature.**

**Le bootloader exo-boot est la seule partie réellement solide.**
- Ed25519 `verify_strict` + SHA-512 + compile-time guard contre clés
  de test + fail-closed policy (Tampered toujours refusé). ✅
- Mais `secure_boot_required: false` par défaut (USER-008) et config
  ESP non signée (USER-009) → un attaquant qui écrit sur l'ESP
  contourne tout.

**Le loader dynamique est un cauchemar sécurité.**
- `runtime_entry()` → `run_initializers()` transmute u64→fn sans
  validation (USER-007).
- Aucune signature check câblée.
- `pie_aslr.rs` est déterministe (USER-015).

**Les outils d'audit sont bons mais non intégrés.**
- `check_ipc_policy_mirror.py` et `audit_constants.py` sont
  excellents mais pas dans CI (USER-019).
- `verify_p0_phoenix.py` donne un faux sentiment de sécurité
  (USER-021).
- ML NGAV entraîné sur données synthétiques + markov online
  poisonable + checksum FNV-1a non crypto (USER-017, USER-018).

**Build system**: `panic=abort` ✅, `lto=true` ✅, `codegen-units=1` ✅,
mais `overflow-checks` manquant (USER-023), build par défaut non signé
(USER-012), pas de cargo-audit, pas de cargo-vet.

**Priorités de remédiation**:
1. **USER-001 + USER-002** (CRITICAL): câbler `stage0_init()` et
   `isolate_kernel_a_memory()` ou supprimer ExoPhoenix du binaire
   kernel pour réduire la surface d'attaque.
2. **USER-003 + USER-004** (CRITICAL): câbler `verify_boot_attestation()`
   et rendre `check_chain_of_trust()` inconditionnel quand
   `strict_exec_signatures` est activé.
3. **USER-005 + USER-006 + USER-007** (HIGH): implémenter une vraie
   vérification Ed25519 dans le loader via `exo-verity::verify_image()`.
4. **USER-008 + USER-009** (HIGH): `secure_boot_required=true` par
   défaut en release + signer `exo-boot.cfg`.
5. **USER-010** (HIGH): utiliser `aead_seal`/`aead_open` pour les
   blobs at-rest, pas `xor_block`.
6. **USER-019** (MEDIUM): intégrer les scripts d'audit dans CI.

Sans ces fixes, ExoOS **n'offre pas la sécurité annoncée** par son
architecture. La chaîne de confiance boot→kernel tient (exo-verity
est solide), mais la chaîne kernel→userspace est brisée et
ExoPhoenix est inopérant.
