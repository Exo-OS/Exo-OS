# AUDIT-4-EXOSHIELD-1 — ExoShield NGAV Détection (signatures + behavioral + ML + engine)

**Sous-agent :** Auditeur AV/EDR + ML sécurité senior
**Périmètre :** 25 fichiers `servers/exo_shield/src/{lib,main,signatures/*,behavioral/*,ml/*,engine/*}.rs` — 14 865 LOC lues en intégralité
**Méthode :** Lecture ligne-par-ligne, cartographie live-call vs dead-code, analyse classes de vulnérabilités AV (ReDoS, parser fuzzing, TOCTOU, memory exhaustion, bypass, update non signé, self-DoS, code injection, path traversal, race, PII leak, ML adversarial, poids hardcoded, FP massifs, IPC auth, sandbox escape).
**Rapports connexes :** AUDIT-5-EXOSHIELD-2 (runtime/hooks/sandbox/network/forensics/ipc_gate), AUDIT-3-CRYPTO-SERVER (verify_ed25519 dépend de crypto_server PID 5).

---

## 1. Synthèse exécutive

Le module détection d'exo_shield présente une **architecture en strates apparemment riche** (signatures YARA-like, fuzzy matcher, ML hybride MLP+iForest+Markov, séquences comportementales, profiler, anomalie EMA) mais l'audit révèle que **~60 % du code de détection est mort au runtime** :

| Sous-module | LOC | Branché au runtime ? | Verdict |
|---|---|---|---|
| `signatures/database.rs` (256 entrées, 32 B) | 580 | ❌ Jamais lu par `execute_scan` | DEAD |
| `signatures/matcher.rs` (exact/wildcard/fuzzy) | 658 | ❌ Jamais appelé | DEAD |
| `signatures/yara.rs` (128 règles, 8 conditions) | 863 | ❌ 0 règle au boot, aucun IPC pour en ajouter | DEAD |
| `signatures/update.rs` (Ed25519 + rollback) | 909 | ❌ `apply_update` jamais appelé, `add_trusted_key` jamais appelé | DEAD |
| `behavioral/anomaly.rs` (EMA, 64 métriques) | 606 | ❌ `observe` jamais appelé | DEAD |
| `behavioral/heuristic.rs` (64 règles, scoring) | 739 | ❌ `evaluate` jamais appelé | DEAD |
| `behavioral/profiler.rs` (32 profils, syscall freq) | 872 | ❌ `record_syscall` jamais appelé | DEAD |
| `behavioral/sequence.rs` (FSM 16×8 états) | 963 | ❌ `submit_event` jamais appelé | DEAD |
| `ml/inference.rs` + `ml/model.rs` + `ml/update.rs` (perceptron 32→16) | 1 340 | ❌ Uniquement en tests | DEAD |
| `ml/features.rs` + `ml/mlp.rs` + `ml/iforest.rs` + `ml/markov.rs` + `ml/ensemble.rs` + `ml/trained_weights.rs` | 2 446 | ✅ Branché via `ensemble_classify` | LIVE |
| `engine/scanner.rs` (128 sigs, 64 B pattern, heuristique) | 1 148 | ✅ `execute_scan` appelé par `handle_scan_request` | LIVE |
| `engine/core.rs` (threat store, scoring, assessment) | 700 | ✅ | LIVE |
| `engine/realtime.rs` (filters, rate limits, alerts) | 1 035 | ✅ `submit_event` appelé par `handle_event_report` + `drain_shield_feed` | LIVE |

**Détection réellement active :**
1. `engine::scanner::execute_scan` — 8 signatures jouets hardcodées + heuristique entropie + FNV-1a hash.
2. `ml::ensemble_classify` — MLP 32→128→64→4 (poids **synthétiques** non entraînés sur traces réelles) + iForest 8 arbres + Markov ordre-2.
3. `engine::realtime` — filtres et rate-limit par PID (5 filtres par défaut).
4. Hooks spécifiques (audit AUDIT-5).

**Verdict efficacité détection : 3/10.**

---

## 2. Top 5 vulnérabilités NGAV

### 🔴 1. [CRITICAL] DETECT-DEAD-1 — `signatures/` module entièrement mort au runtime

**Fichiers :** `signatures/database.rs`, `signatures/matcher.rs`, `signatures/yara.rs`, `signatures/update.rs` (~3 010 LOC).
**Preuve :**

```
$ rg "signatures::database|signatures::matcher|signatures::yara|signatures::update" servers/exo_shield/src/
main.rs:1510:    signatures::database::database_init();   // init only
main.rs:1512:    signatures::yara::yara_init();            // init only
main.rs:1514:    signatures::update::update_init();        // init only
```

Aucune autre référence. `engine::scanner::execute_scan` (la vraie callback IPC `SCAN_REQUEST`) utilise son **propre** `SIG_DB` (`engine/scanner.rs:172`) avec un schéma différent (128 entrées, 64-byte pattern, champ `sig_type`) — pas de sync avec `signatures::database::SIG_DB` (256 entrées, 32-byte pattern).
`signatures::matcher::scan_buffer` (exact + wildcard + fuzzy) — fonction la plus avancée du matcher — n'est jamais appelé.
`signatures::yara::evaluate_all` n'est jamais appelé ; aucune règle YARA n'est ajoutée (pas d'IPC pour le faire).
`signatures::update::apply_update` n'est jamais appelé ; `add_trusted_key` n'est jamais appelé → `trusted_key_count = 0` à vie.

**Impact :**
- Le NGAV ne bénéficie d'aucun des 3 010 LOC de signature avancée (fuzzy, wildcard, YARA, update signée Ed25519, rollback).
- La doc `ExoShield_Server_v1.md §4` prétend que "la signature d'une mise à jour est vérifiée via `crypto_server`" — c'est faux au runtime : aucun `apply_update` n'est jamais déclenché.
- IPC `POLICY_UPDATE` type 5 (add_signature) → `engine::scanner::add_signature` (live DB), **pas** vers `signatures::update::apply_update`. Une mise à jour signée ne peut pas être poussée.
- Confusion mainteneur : un développeur pensant durcir `signatures/database.rs` ne améliore en fait aucune sécurité.

**Correctif P0 :** Soit supprimer `signatures/` (3 kLOC mortes), soit câbler `engine::scanner::execute_scan` pour appeler `signatures::matcher::scan_buffer` en plus de son scan natif, et exposer un IPC `SIGNATURE_UPDATE` qui appelle `apply_update` après `add_trusted_key` au boot.

---

### 🔴 2. [CRITICAL] DETECT-DEAD-2 — `behavioral/` module entièrement mort au runtime

**Fichiers :** `behavioral/anomaly.rs`, `behavioral/heuristic.rs`, `behavioral/profiler.rs`, `behavioral/sequence.rs` (~3 176 LOC).
**Preuve :**

```
$ rg "behavioral::anomaly|behavioral::heuristic|behavioral::profiler|behavioral::sequence|anomaly::|heuristic::|profiler::|sequence::" servers/exo_shield/src/
behavioral/mod.rs:16-19:    anomaly::anomaly_init();  ...   // init only
ml/markov.rs:17:  // commentaire only
main.rs:336:      // commentaire only
```

Aucune fonction métier (`observe`, `evaluate`, `record_syscall`, `record_memory_access`, `submit_event` sequence, `register_metric`, `add_rule`) n'est appelée par `handle_event_report`, `process_security_hooks`, `drain_shield_feed`, ou les hooks.

**Impact :**
- Le profileur (fréquence syscalls par PID, régions mémoire, IPC graph) — qui devrait alimenter le ML en features réelles — n'est jamais appelé. Le ML utilise à la place `behaviour_data_for_event` (main.rs:281-333) qui construit un feature vector **synthétique** à partir de compteurs globaux `hooks::get_syscall_stats()` clampés à `.min(99)`.
- Le FSM séquences (capable de détecter `open→write→exec` = shellcode, `fork→fork→fork` = bomb, `socket→connect→send` = C2) ne reçoit aucun événement. **Aucune détection de séquence comportementale n'a lieu.**
- L'EMA d'anomalie (baseline par métrique, scoring σ) n'est pas alimentée.
- Les 64 règles heuristiques + scoring pondéré sont inactives.

**Correctif P0 :** Câbler `behavioral::profiler::record_syscall/record_memory_access/record_network_activity/record_ipc_call` dans `process_security_hooks`. Câbler `behavioral::sequence::submit_event` (avec mapping `engine::EventType` → `behavioral::sequence::EventType`). Câbler `behavioral::anomaly::observe` pour les métriques clés (syscall_rate, net_rate, mem_rate). Sinon, supprimer les 3 kLOC mortes.

---

### 🔴 3. [CRITICAL] ML-POISON-1 — iForest calibration empoisonnable par attaquant via EVENT_REPORT self-report

**Fichier :** `ml/ensemble.rs:120-122` + `ml/iforest.rs:142-153` + `main.rs:745-824`.
**Code :**
```rust
// ensemble.rs:120
if classification == Classification::Benign {
    iforest::iforest_observe_normal(fv);
}
```

**Mécanisme :**
1. L'IPC `EVENT_REPORT` (msg_type 1) pour un `target_pid == sender_pid` n'est **pas capability-gated** (cf. AUDIT-5 IAC-01/02 : self-scan autorisé).
2. `handle_event_report` construit `behaviour_data_for_event` (feature vector clampé à 99) puis appelle `ml::ensemble_classify`.
3. Si le feature vector est `Benign` (ce qu'un attaquant garantit en gardant des compteurs faibles), `iforest_observe_normal` met à jour l'EMA `normal_depth_ema_q8` avec α = 1/32.
4. Après ~32 événements bénins, la baseline de l'iForest est déplacée vers le pattern de l'attaquant.
5. L'attaquant peut alors commettre des actions malignes qui ne dévieront plus de la baseline empoisonnée → score IF ≈ 0 → `ensemble_classify` retourne `Benign` ou `Suspicious` mais pas `Malicious` → pas de confinement.

**Impact :** Contournement complet de la détection ML iForest par un attaquant Ring 3 non privilégié qui s'auto-reporte comme bénin pendant 5 minutes. La feature `iforest::observe_normal` est conçue pour être appelée par le **serveur lui-même** quand il a confirmation qu'un process est bénin, pas pour accepter la classification d'un événement IPC en entrée.

**Correctif P0 :** Soit (a) ne calibrer l'iForest qu'avec des événéments issus du feed kernel `SYS_EXO_SHIELD_DRAIN` ET qui ne déclenchent aucune alerte hook, soit (b) exiger un capability token pour `EVENT_REPORT` même en self-report, soit (c) ajouter un rate-limit strict (max 1 calibration par PID par minute).

---

### 🟠 4. [HIGH] SCAN-FP-1 — 8 signatures jouets par défaut génèrent faux positifs massifs + auto-confinement

**Fichier :** `engine/scanner.rs:999-1082` (`scanner_init`) + `main.rs:811-814` (auto-containment).
**Signatures par défaut :**
| Pattern | Nom | Sévérité | Score | Commentaire |
|---|---|---|---|---|
| `\xcd\x80\x00\x00` | linux_syscall_int80 | High | 700 | Matche **tout binaire Linux statique** (int 0x80) |
| `\x0f\x05\x00\x00` | linux_syscall_new | High | 700 | Matche tout binaire Linux x86_64 (`syscall` instruction) |
| `\xff\xe4\x00\x00` | jmp_esp_shellcode | Critical | 850 | Pattern gadget ROP commun en code légitime |
| `\xff\xe0\x00\x00` | jmp_eax_shellcode | Critical | 850 | Idem |
| `\x90\x90\x90\x90` | nop_sled_long | Medium | 500 | NOP sled — présent en alignement de code |
| `\xeb\xfe\x90\x90` | infinite_loop_nop | Medium | 450 | Boucle infinie + NOP |
| `\xcc\xcc\xcc\xcc` | int3_breakpoint | Low | 200 | Padding d'alignment GCC |
| `\x48\x31\xc0\x48` | xor_rax_x64_seq | High | 600 | `xor rax,rax` — prologue de fonction |

**Mécanisme de FP → auto-confinement :**
1. Un process légitime appelle `SCAN_REQUEST` (msg_type 0) avec `target_pid = self` et un buffer de 110 bytes contenant du code légitime (ex: son propre prologue `xor rax,rax`).
2. `execute_scan` → Phase 1 match `\x48\x31\xc0\x48` → `total_score = 600` → `score_to_level(600) = High`.
3. `result.matched = true`, `composite = 600`.
4. `handle_scan_request` reply avec `matched=1`, `max_severity=High`.
5. Mais en plus, `execute_scan` appelle `record_threat` si `composite >= 250` (scanner.rs:747). Le ThreatRecord est stocké avec `level = High`.
6. Au prochain `perform_maintenance`, `assess_pid(pid)` agrège les ThreatRecords : `active_threats=1, freq_score=200, scope_score=150, recency=800` → `composite ≈ 350` → `recommended_action = Quarantine` (level Medium→Throttle, High→Quarantine, Critical→Kill).
7. `if assessment.recommended_action >= Quarantine { apply_containment(scan_req.pid, tick); }` (main.rs:1458-1461) → `sandbox::quarantine_pid` + `network::block_pid` + `mark_process_contained`.

**Impact :** Tout process légitime Linux x86_64 scanné avec son propre code est auto-confiné. **DoS opérationnel garanti dès la première vague de scans périodiques.** Soit le service est désactivé manuellement, soit tous les processes sont quarantaines.

**Correctif P0 :** Remplacer les 8 signatures jouets par des signatures réelles (cf. base YARA publique : https://github.com/Yara-Rules/rules). Augmenter le seuil de `record_threat` à `composite >= 500` (High) au lieu de 250 (Medium). Ne pas auto-quarantiner sur un seul ThreatRecord (exiger 3+ menaces actives ou `level == Critical`).

---

### 🟠 5. [HIGH] ML-INTEGRITY-1 — Poids MLP "entraînés" sur données synthétiques + checksum FNV-1a non cryptographique

**Fichiers :** `ml/trained_weights.rs:1-3` + `ml/mlp.rs:226-267` (`mlp_load_trained`).
**Preuve :**
```
// trained_weights.rs ligne 1-3 (commentaire d'en-tête) :
// @generated par tools/ml_training/train_ngav.py — NE PAS éditer à la main.
// Premier jeu de poids ENTRAÎNÉ (données synthétiques). À ré-entraîner
// sur traces réelles Exo-OS (profiler.rs sous QEMU). Voir AUDIT-100-PERCENT.md (F4/F10).
```

**Vulnérabilités :**

(a) **Poids non entraînés sur données réelles** : le fichier est explicitement labellisé "données synthétiques". Le MLP en production ne dispose d'aucune connaissance de la distribution réelle des process ExoOS. Sa capacité de discrimination est essentiellement aléatoire avec un biais domain-seeded (LCG avec `seed = 0xE505_C117`).

(b) **Checksum FNV-1a non cryptographique** : `mlp_checksum_parts` (mlp.rs:228-239) calcule un FNV-1a 64-bit des poids. FNV-1a est un hash non-résistant aux collisions : étant donné un jeu de poids malveillant P, trouver P' tel que `FNV(P) == FNV(P')` est trivial ( quelques millisecondes). Un attaquant qui compromet le repo (`trained_weights.rs`) peut remplacer les poids par un MLP trojanisé (ex: biaisé pour classer "Benign" tout process avec `ptrace_use > 0`) et ajuster `TRAINED_MLP_CHECKSUM` en conséquence. **Aucune détection.**

(c) **`iforest_load_trained` n'a AUCUNE vérification d'intégrité** (iforest.rs:188-209) : seul un check de longueur (`IF_NODE_FEATURE.len() != IF_TREES * IF_TREE_NODES`). Un attaquant qui compromet le repo peut trojaniser les seuils iForest librement.

(d) **`mlp_update_weights` est pub fn sans signature** (mlp.rs:215) : toute fonction exo_shield peut remplacer les poids en runtime. Pas de capability check. Pas de version monotonic check (contrairement à `mlp_load_trained` qui vérifie `TRAINED_MLP_VERSION > model.version`).

**Impact :** Le modèle ML phare du NGAV n'a aucune chaîne de confiance :
- Build-time : compromettre `trained_weights.rs` → trojan indétectable.
- Run-time : `mlp_update_weights` accessible sans auth (latent — non appelé aujourd'hui mais prêt pour une future IPC).

**Correctif P0 :**
1. Signer `trained_weights.rs` avec Ed25519 au build (via `tools/ml_training/train_ngav.py` + clé offline). Vérifier la signature dans `mlp_load_trained` via `crypto_server` (déjà utilisé pour `signatures/update.rs`).
2. Idem pour `iforest_load_trained` (ajouter IF_CHECKSUM + signature).
3. Exiger un capability token `EXO_CAP_RIGHT_ML_UPDATE` pour `mlp_update_weights`.
4. Une fois des traces réelles disponibles, ré-entraîner et bump `TRAINED_MLP_VERSION`.

---

## 3. Autres findings par sévérité

### HIGH

- **[HIGH] SIG-UB-1 — `core::ptr::read` unaligned sur `EncodedSignature` (UB)** — `signatures/update.rs:746` :
  ```rust
  let encoded: EncodedSignature =
      unsafe { core::ptr::read(payload[offset..].as_ptr() as *const EncodedSignature) };
  ```
  `EncodedSignature` est `#[repr(C)]` avec un champ `id: u32` (align 4). `payload[offset..].as_ptr()` retourne un `*const u8` (align 1). `core::ptr::read` exige un pointeur aligné — c'est **undefined behavior** (UB) en Rust. Doit utiliser `core::ptr::read_unaligned` ou construire champ-par-champ via `from_le_bytes`. Latent car `apply_update` est dead code, mais si jamais câblé : crash sur architectures strictes (ARM, MIPS) ; comportement indéfini sur x86 (fonctionne souvent par chance).
  *Correctif :* `unsafe { core::ptr::read_unaligned(payload[offset..].as_ptr() as *const EncodedSignature) }` ou mieux : parsing explicite champ-par-champ.

- **[HIGH] SIG-AUTH-1 — `add_trusted_key` / `remove_trusted_key` sont `pub fn` sans contrôle d'autorité** — `signatures/update.rs:546-589`. Aucun capability check, aucune restriction d'appelant. Si une future IPC exposait ces fonctions (ex: `POLICY_UPDATE` type 11 "add trusted key"), un attaquant pourrait enregistrer sa propre clé Ed25519 puis signer des mises à jour malveillantes. Actuellement non exposé mais le trap est posé.
  *Correctif :* Marquer `pub(crate)` et exiger un capability token dédié.

- **[HIGH] SIG-DB-DIVERGENCE — Deux bases de signatures avec schémas incompatibles** — `engine/scanner.rs:172` (`SIG_DB` 128 entrées, 64-byte pattern, `sig_type` field) vs `signatures/database.rs:200` (`SIG_DB` 256 entrées, 32-byte pattern, pas de `sig_type`). Le IPC `POLICY_UPDATE` type 5 (add_signature) écrit dans `engine::scanner::SIG_DB`. Le (jamais appelé) `apply_update` écrit dans `signatures::database::SIG_DB`. Un admin qui déploie des signatures via le canal signé Ed25519 n'affecte pas le scanner live ; un admin qui utilise l'IPC non signé affecte le scanner live.
  *Correctif :* Unifier les deux bases. Une seule source de vérité.

- **[HIGH] ML-CLAMP-1 — Feature vector clampé à 99 uniformément → adversarial evasion trivial** — `main.rs:281-333` (`behaviour_data_for_event`) :
  ```rust
  data.syscall_rate = 1 + u64_to_i32_saturating(syscall_stats.total_syscalls.min(99));
  data.net_bytes_sent = u64_to_i32_saturating(event.arg1.min(99));
  data.port_scan_score = u64_to_i32_saturating(net_stats.port_scan_detections.min(99));
  // ... toutes les 32 features clampées à 99
  ```
  Le MLP est entraîné avec `FEATURE_MAX = [100, 100, …, 120, 128, 200]` (trained_weights.rs:10-13). En normalisant `[0,99] → [0, 0.99]` en Q16.16, le MLP ne peut pas distinguer "100 syscalls/tick" de "100 000 syscalls/tick". Un attaquant qui flood 1 000 syscalls/tick a le même feature vector qu'un process normal à 99 syscalls/tick. **Évasion ML garantie.**
  *Correctif :* Remplacer les `.min(99)` par des compteurs réels (u64 ou u32 saturés à u32::MAX) et utiliser `FEATURE_MAX` réaliste (ex: 10 000 syscalls/s = 100% busy). Ré-entraîner le MLP.

- **[HIGH] ML-MARKOV-1 — Markov counts jamais décroissants → perte de discrimination temporelle** — `ml/markov.rs:114-117` :
  ```rust
  self.counts[…] = self.counts[…].saturating_add(1);
  self.bigram[…] = self.bigram[…].saturating_add(1);
  ```
  Aucun forgetting factor. Après N observations (N → grand), tous les trigrammes possibles ont un count élevé → P(e3|e1,e2) → uniforme → surprise → 0 pour tout nouveau pattern. Le détecteur devient aveugle après quelques heures de fonctionnement.
  *Correctif :* Implémenter une fenêtre glissante (count[u32; N] décrémenté périodiquement) ou un EMA sur les counts.

- **[HIGH] IPC-DETECT-1 — `SCAN_REQUEST` self-scan non capability-gated → probe + DoS** — `main.rs:687-728`. N'importe quel process Ring 3 peut envoyer `SCAN_REQUEST` avec `target_pid = self_pid` et un `scan_data` de 110 bytes. L'attaquant peut :
  1. **Probe** la signature DB : envoyer un pattern suspect, observer `match_count` et `max_severity` dans la reply → apprendre quelles signatures sont actives.
  2. **DoS** : envoyer 1000 `SCAN_REQUEST` par seconde → `engine::execute_scan` locke `SIG_DB` et `SCAN_RESULTS` à chaque appel.
  3. **Self-confinement via FP** : voir SCAN-FP-1.
  *Correctif :* Rate-limit `SCAN_REQUEST` à 10/self_pid/minute via `ipc_gate`. Cacher le détail des `sig_ids` dans la reply (renvoyer uniquement `matched: 0/1`).

- **[HIGH] POLICY-BYPASS-1 — IPC `POLICY_UPDATE` type 6 (disable_signature) permet de désactiver les signatures critiques** — `main.rs:1132-1139` + `engine/scanner.rs:788-791`. Un attaquant avec capability token `EXO_CAP_RIGHT_IPC_SEND` vers endpoint 10 (obtenu via compromission d'un serveur Ring 1 privilégié) peut désactiver la signature `\xff\xe4\x00\x00` (jmp_esp), puis délivrer un shellcode l'utilisant. Le scanner ne détectera pas.
  *Correctif :* Marquer certaines signatures comme "non désactivables" (default signatures criticité ≥ High). Exiger un capability token distinct `EXO_CAP_RIGHT_SIG_ADMIN` pour `disable_signature`.

### MEDIUM

- **[MEDIUM] ML-IF-2 — iForest calibration initiale à `INIT_NORMAL_DEPTH_Q8 = 640` (Q8.8) arbitraire** — `iforest.rs:28`. Avant toute calibration, le score d'anomalie est calculé contre cette valeur. Si la vraie distribution a une profondeur moyenne très différente, tous les scores sont faussés jusqu'à calibration (32+ observations).
- **[MEDIUM] SCAN-HASH-1 — Heuristic FNV-1a hash-phase compare à ±0x0100 (1/65536 collision)** — `scanner.rs:723-728`. Pour 128 signatures "heuristic" (`sig_type == 1`), chaque scan a ~128/65536 ≈ 0.2 % de chance de faux positif par hash. Avec 1000 scans/jour, ~2 FP/jour. Pas critique mais bruit statistique.
- **[MEDIUM] SCAN-TIMEOUT-1 — `execute_scan` ignore `ScanProfile::timeout_ticks`** — `scanner.rs:622-777`. Le champ est défini mais jamais vérifié. Limité en pratique par la taille IPC (120 bytes) mais si `execute_scan` est appelé sur un gros buffer (ex: memory_dump), DoS possible.
- **[MEDIUM] BEH-EVICT-1 — `heuristic::find_or_create_score` évince le profil au plus bas score** — `heuristic.rs:489-503`. Un attaquant fork-bomb 33 processes → le score du process monitoré malveillant est évincé → reset à 0. Défense contournée. (Code mort aujourd'hui mais pattern dangereux si réactivé.)
- **[MEDIUM] BEH-DECAY-1 — `heuristic::decay_scores` jamais appelé** — `heuristic.rs:681-695`. Les scores accumulés ne décroissent jamais. Combiné à BEH-EVICT-1, les vieux scores évincent les nouveaux.
- **[MEDIUM] MARKOV-EVICT-1 — `MarkovChain::pid_slot` éviction déterministe `pid % 64`** — `markov.rs:95`. Un attaquant qui crée 65 PIDs évince l'état Markov du PID cible. L'anomalie cumulée est perdue.
- **[MEDIUM] ENGINE-CORE-1 — `record_threat` échoue silencieusement si THREAT_STORE plein** — `core.rs:225-256`. `let _ = record_threat(&rec);` (scanner.rs:769) ignore l'échec. Un flood de menaces Medium remplit le store (256 entrées) → les nouvelles menaces High/Critical sont dropped.
- **[MEDIUM] ENGINE-TIME-1 — IPC server single-threaded, maintenance uniquement sur timeout** — `main.rs:1571-1576`. La maintenance (drain kernel feed, periodic scan) ne s'exécute que si `SYS_EXO_IPC_RECV` timeout (5 s). Si le serveur est floodé, il ne draine jamais le feed kernel → `KShieldEvent` queue kernel déborde → events de sécurité perdus.
- **[MEDIUM] CRYPTO-VERIFY-1 — `crypto_verify_ed25519` IPC roundtrip peut leak les VerifyContext slots du crypto_server** — `update.rs:198-270`. Si le crypto_server time out en milieu de stream (BEGIN/UPDATE/FINAL), le slot reste alloué. Selon AUDIT-3-CS-IPC-01, crypto_server n'a que 4 slots et aucun GC → 4 timeouts tuent le service de vérification Ed25519 pour tout le système. Latent (apply_update est dead).
- **[MEDIUM] CRYPTO-CRC-1 — CRC32 (IEEE 802.3) utilisé comme checksum d'update** — `update.rs:494-501`. CRC32 n'est pas cryptographique. Heureusement, la signature Ed25519 couvre le payload (le CRC est redondant). Pas une faille en soi, mais pourrait tromper un auditeur.

### LOW

- **[LOW] SEQ-STATE-1 — Sequence state reste `active=true` après completion** — `sequence.rs:744-750`. `current_step = 0` mais `active` reste vrai jusqu'à timeout (30 s par défaut). Les 16 slots peuvent se saturer en cas de pic d'événements matching.
- **[LOW] PROFILER-CAT-1 — Classification syscall Linux hardcodée** — `profiler.rs:55-74`. `SyscallCategory::from_syscall_nr` utilise des ranges Linux x86_64 (0-19 = File, 40-59 = Process, etc.). Or ExoOS a sa propre ABI (`exo_syscall_abi`) avec des numéros différents. La classification est erronée. (Code mort.)
- **[LOW] SCAN-FNV-1 — FNV-1a 32-bit pour heuristic hashes** — `scanner.rs:500-507`. FNV-1a 32-bit a ~65536 collision space. Pour un IPv4 tuple ou un hash court, collisions probables. Pas critique mais limite la qualité de la détection heuristique.
- **[LOW] FEATURE-DOC-1 — `FeatureVector::to_f32` retourne toujours `0.0`** — `features.rs:106-111`. La doc dit "approximation for documentation" mais la fonction est un placeholder. Pas appelée en production, mais trompeur.
- **[LOW] ENGINE-LOCK-1 — `execute_scan` prend `SIG_DB.lock()` deux fois** — `scanner.rs:654, 707`. Entre les deux locks, une signature pourrait être ajoutée. Cohérence faible, pas de sécurité impact.
- **[LOW] IPC-RATE-1 — `EVENT_REPORT` self n'a pas de rate-limit par PID** — `main.rs:745-824`. Un process peut s'auto-reporter 1000 fois/s. Le rate-limit ipc_gate est global par src_pid, pas par event_type. Combiné avec ML-POISON-1, facilite l'empoisonnement iForest.

### INFO / POSITIFS

- ✅ **Aucune utilisation de `regex` ou moteur regex-like** dans les signatures → **pas de ReDoS** possible. Le matcher wildcard est limité à 16 segments, algorithme O(n×m) borné.
- ✅ **Aucune utilisation de heap** : tout est en `static` + `spin::Mutex`. Pas de memory exhaustion possible via input attaquant.
- ✅ **Aucun panic/unreachable/unwrap en code production** (uniquement en `#[cfg(test)]`). Le `panic_handler` main.rs:1598 fait juste `hlt` loop (correct pour no_std).
- ✅ **Toutes tailles bornées à la compilation** : 256 signatures, 128 rules YARA, 64 heuristic rules, 32 profiles, 64 métriques, 32 process scores, 16 sequences, 64 Markov PIDs, 256 threat records, 64 scan queue, 64 scan results, 128 alerts, 64 filters, 128 monitored procs, 128 risk profiles, 128 rate entries.
- ✅ **Parser YARA-like `parse_condition` robuste** — `yara.rs:619-672`. Vérifie `data.len() < CONDITION_WIRE_SIZE` avant lecture. `length > CONDITION_VALUE_SIZE` rejeté. Pas de débordement.
- ✅ **Parser IPC `handle_scan_request` / `handle_event_report` / `handle_policy_update` robustes** — `read_u32_le` / `read_u64_le` vérifient les bornes. `data_len` clampé à 120. `name_len` clampé à `MAX_SIG_NAME`.
- ✅ **Pas de TOCTOU sur fichiers** — `execute_scan` ne scanne que des buffers IPC en mémoire, jamais de fichiers. Pas de TOCTOU possible.
- ✅ **Pas de logging de contenu utilisateur** — le pipeline de détection ne log que PIDs, scores, IDs, descriptions `'static [u8]`. Pas de fuite PII.
- ✅ **`compute_entropy` est O(n)** avec stack-allocated `[u32; 256]` (1 KB). Borné.
- ✅ **`match_pattern` naive mais borné** — `scanner.rs:475-497`. O(n×m) avec shortcut sur mismatch. Pas de ReDoS.
- ✅ **`ensemble_classify` borné** — toutes les ops en Q16.16 fixed-point avec `clamp(i32::MIN, i32::MAX)` à chaque couche MLP. Pas de NaN/Inf (pas de float). Pas de DoS par overflow MLP.
- ✅ **`MlpWeights::forward` utilise `i64` accumulators** avec `saturating_add` implicite via `clamp`. Pas d'overflow.
- ✅ **`markov_observe` utilise `saturating_add`** sur tous les compteurs → pas d'overflow.
- ✅ **`iforest::path_length` a hard cap à `IF_MAX_DEPTH = 5`** → pas de boucle infinie sur arbre corrompu.
- ✅ **`iforest_load_trained` vérifie la taille des tableaux** avant chargement.
- ✅ **`mlp_load_trained` vérifie version monotonic** (anti-régression).
- ✅ **`SignatureUpdateHeader` layout vérifié par `const _: () = assert!(...)`** — `update.rs:420-428`. Compile-time check.
- ✅ **`ShieldRequest` taille vérifiée par `const _: () = assert!(size_of == IPC_ENVELOPE_SIZE)`** — `main.rs:82-83`.

---

## 4. Efficacité détection estimée

| Composant | Live ? | Efficacité | Raison |
|---|---|---|---|
| `engine::scanner` (8 sigs jouets + entropie + hash) | ✅ | 1/10 | Sigs matchent code Linux légitime, heuristique entropie non discriminante, hash phase bruit statistique |
| `engine::realtime` (rate limits + 5 filtres défaut) | ✅ | 5/10 | Rate limiting fonctionnel mais basique. Filtres default raisonnables. |
| `engine::core::assess_pid` (scoring) | ✅ | 6/10 | Scoring cohérent, mais basé sur données d'entrée pauvres ( ThreatRecords générés par scanner FP) |
| `ml::ensemble` (MLP+iForest+Markov) | ✅ | 2/10 | Poids synthétiques non entraînés. Features clampés à 99. iForest empoisonnable. Markov saturating. |
| `signatures/` (database, matcher, yara, update) | ❌ | 0/10 | Dead code |
| `behavioral/` (anomaly, heuristic, profiler, sequence) | ❌ | 0/10 | Dead code |
| `ml/inference` + `ml/model` + `ml/update` (perceptron 32→16) | ❌ | 0/10 | Dead code |
| Hooks (AUDIT-5) | ✅ | 5/10 | Couvre syscalls/memory/net/exec mais bypass documenté (AUDIT-5 SCH-01/02/03) |

**Score global efficacité détection NGAV exo_shield : 3/10.**

Justification :
- Le scanner live repose sur 8 signatures jouets qui déclenchent FP critiques sur code légitime.
- Le ML live est sur poids synthétiques, features clampés, et empoisonnable.
- 60 % du code de détection (3 010 LOC signatures + 3 176 LOC behavioral + 1 340 LOC ML legacy = 7 526 LOC) est mort.
- Aucune update de signatures possible au runtime (apply_update jamais appelé, trusted_keys vide).
- Aucune règle YARA chargée, aucun chemin IPC pour en ajouter.
- Aucune détection de séquence comportementale (FSM jamais alimenté).
- Aucun profilage réel (profiler jamais alimenté ; ML utilise features synthétiques clampées).
- Les hooks (AUDIT-5) portent l'essentiel de la détection runtime, avec leurs propres gaps.

Pour atteindre 7/10 : câbler behavioral/ + signatures/ + update signer Ed25519 + ré-entraîner MLP sur traces réelles + dé-clamper les features + anti-poison iForest.

---

## 5. Recommandations priorisées

### P0 — Bloquants (sécurité + eficacité)

1. **Câbler ou supprimer `signatures/`** (DETECT-DEAD-1). Soit `engine::scanner::execute_scan` appelle aussi `signatures::matcher::scan_buffer`, soit supprimer 3 kLOC mortes.
2. **Câbler ou supprimer `behavioral/`** (DETECT-DEAD-2). Câbler `profiler::record_*` dans `process_security_hooks`, `sequence::submit_event` sur MonitoredEvent, `anomaly::observe` sur les métriques.
3. **Anti-poison iForest** (ML-POISON-1). Ne calibrer qu'avec events kernel drain + non-alerte. Rate-limit 1 calibration/PID/minute.
4. **Remplacer 8 signatures jouets** (SCAN-FP-1). Utiliser base YARA publique. Bump `record_threat` threshold à 500.
5. **Signer `trained_weights.rs`** (ML-INTEGRITY-1). Ed25519 via crypto_server au load. Idem for `IF_NODE_*`.
6. **Fix `core::ptr::read` UB** (SIG-UB-1). `read_unaligned`.
7. **Dé-clamper features ML** (ML-CLAMP-1). Compteurs réels + FEATURE_MAX réaliste.
8. **Forgetting factor Markov** (ML-MARKOV-1). EMA sur counts ou fenêtre glissante.

### P1 — Majeurs

9. **Exiger capability token pour `disable_signature`** (POLICY-BYPASS-1). Marquer signatures Default non désactivables.
10. **Rate-limit `SCAN_REQUEST` self à 10/min/PID** (IPC-DETECT-1). Cacher `sig_ids` dans reply.
11. **Rate-limit `EVENT_REPORT` self à 30/min/PID** (IPC-RATE-1).
12. **`add_trusted_key` pub(crate) + capability check** (SIG-AUTH-1).
13. **Unifier `engine::scanner::SIG_DB` et `signatures::database::SIG_DB`** (SIG-DB-DIVERGENCE).
14. **Implémenter forgetting factor Markov** (ML-MARKOV-1).
15. **Ré-entraîner MLP sur traces réelles** (DETECT-EFFICACY-1).
16. **`record_threat` ne pas ignorer l'échec** (ENGINE-CORE-1). Si échec, log critique.
17. **Fix `MarkovChain::pid_slot` éviction LRU au lieu de `pid % 64`** (MARKOV-EVICT-1).
18. **Fix `heuristic::find_or_create_score` éviction LRU au lieu de min-score** (BEH-EVICT-1).

### P2 — Durcissement

19. **`execute_scan` enforce `ScanProfile::timeout_ticks`** (SCAN-TIMEOUT-1).
20. **Supprimer hash-phase FNV-1a ou relever threshold à ±0x00000010** (SCAN-HASH-1).
21. **Fix `SyscallCategory::from_syscall_nr` pour ExoOS ABI** (PROFILER-CAT-1).
22. **`decay_scores` appel périodique** (BEH-DECAY-1).
23. **Sequence state `active=false` après completion** (SEQ-STATE-1).
24. **Maintenance thread dédié au lieu de on-timeout-only** (ENGINE-TIME-1).

---

## 6. Annexes

### 6.1 Inventaire des 25 findings

| ID | Sévérité | Catégorie | Fichier |
|---|---|---|---|
| DETECT-DEAD-1 | CRITICAL | LOGIC/DEAD | signatures/* (3 010 LOC) |
| DETECT-DEAD-2 | CRITICAL | LOGIC/DEAD | behavioral/* (3 176 LOC) |
| ML-POISON-1 | CRITICAL | LEAK/ML | ml/ensemble.rs:120-122 |
| SCAN-FP-1 | HIGH | DoS/FP | engine/scanner.rs:999-1082 |
| ML-INTEGRITY-1 | HIGH | INTEGRITY | ml/trained_weights.rs:1-3 + mlp.rs:226-267 |
| SIG-UB-1 | HIGH | MEMSAFE | signatures/update.rs:746 |
| SIG-AUTH-1 | HIGH | ISOLATION | signatures/update.rs:546-589 |
| SIG-DB-DIVERGENCE | HIGH | LOGIC | engine/scanner.rs:172 vs signatures/database.rs:200 |
| ML-CLAMP-1 | HIGH | LEAK/ML | main.rs:281-333 |
| ML-MARKOV-1 | HIGH | DoS/ML | ml/markov.rs:114-117 |
| IPC-DETECT-1 | HIGH | ISOLATION | main.rs:687-728 |
| POLICY-BYPASS-1 | HIGH | ISOLATION | main.rs:1132-1139 |
| ML-IF-2 | MEDIUM | ML | ml/iforest.rs:28 |
| SCAN-HASH-1 | MEDIUM | LOGIC | engine/scanner.rs:723-728 |
| SCAN-TIMEOUT-1 | MEDIUM | DoS | engine/scanner.rs:622-777 |
| BEH-EVICT-1 | MEDIUM | LOGIC | behavioral/heuristic.rs:489-503 |
| BEH-DECAY-1 | MEDIUM | DEAD | behavioral/heuristic.rs:681-695 |
| MARKOV-EVICT-1 | MEDIUM | LOGIC | ml/markov.rs:95 |
| ENGINE-CORE-1 | MEDIUM | LOGIC | engine/core.rs:225-256 + scanner.rs:769 |
| ENGINE-TIME-1 | MEDIUM | DoS | main.rs:1571-1576 |
| CRYPTO-VERIFY-1 | MEDIUM | DoS | signatures/update.rs:198-270 |
| CRYPTO-CRC-1 | MEDIUM | INTEGRITY | signatures/update.rs:494-501 |
| SEQ-STATE-1 | LOW | LOGIC | behavioral/sequence.rs:744-750 |
| PROFILER-CAT-1 | LOW | LOGIC | behavioral/profiler.rs:55-74 |
| SCAN-FNV-1 | LOW | LOGIC | engine/scanner.rs:500-507 |
| FEATURE-DOC-1 | LOW | DOC | ml/features.rs:106-111 |
| ENGINE-LOCK-1 | LOW | RACE | engine/scanner.rs:654,707 |
| IPC-RATE-1 | LOW | DoS | main.rs:745-824 |

**Bilan : 4 CRITICAL, 8 HIGH, 10 MEDIUM, 7 LOW.**

### 6.2 Cartographie dead vs live code

```
exo_shield/src/
├── lib.rs                    [INFO]
├── main.rs                   [LIVE] IPC dispatch, hooks pipeline, ML ensemble
├── signatures/
│   ├── mod.rs                [DEAD] signatures_init called, subs never used
│   ├── database.rs           [DEAD] 580 LOC, jamais lu par execute_scan
│   ├── matcher.rs            [DEAD] 658 LOC, jamais appelé
│   ├── yara.rs               [DEAD] 863 LOC, 0 règle, aucun IPC add_rule
│   └── update.rs             [DEAD] 909 LOC, apply_update jamais appelé
├── behavioral/
│   ├── mod.rs                [DEAD] behavioral_init called, subs never used
│   ├── anomaly.rs            [DEAD] 606 LOC, observe jamais appelé
│   ├── heuristic.rs          [DEAD] 739 LOC, evaluate jamais appelé
│   ├── profiler.rs           [DEAD] 872 LOC, record_* jamais appelé
│   └── sequence.rs           [DEAD] 963 LOC, submit_event jamais appelé
├── ml/
│   ├── mod.rs                [INFO]
│   ├── features.rs           [LIVE] FeatureExtractor::extract utilisé par ensemble
│   ├── mlp.rs                [LIVE] mlp_infer utilisé par ensemble
│   ├── iforest.rs            [LIVE] iforest_score utilisé par ensemble
│   ├── markov.rs             [LIVE] markov_observe utilisé par ensemble
│   ├── ensemble.rs           [LIVE] ensemble_classify appelé par main.rs
│   ├── trained_weights.rs    [LIVE] chargé par mlp_load_trained + iforest_load_trained
│   ├── inference.rs          [DEAD] InferenceEngine jamais instancié hors tests
│   ├── model.rs              [DEAD] ModelWeights jamais utilisé hors tests
│   └── update.rs             [DEAD] ModelUpdateManager jamais instancié hors tests
├── engine/
│   ├── mod.rs                [INFO]
│   ├── core.rs               [LIVE] record_threat, assess_pid utilisés
│   ├── scanner.rs            [LIVE] execute_scan, add_signature utilisés
│   └── realtime.rs           [LIVE] submit_event, generate_manual_alert utilisés
└── (hooks/sandbox/network/forensics/ipc_gate — AUDIT-5)
```

### 6.3 Comparison avec la doc ExoShield_Server_v1.md

| Promesse doc | Réalité runtime |
|---|---|
| §4 "vérification Ed25519 déléguée au crypto_server" | `apply_update` jamais appelé. trusted_keys vide. **Non fonctionnel.** |
| §3 "QUARANTINE_CMD et POLICY_UPDATE sont toujours capability-gated" | Vrai (main.rs:639-664). ✓ Mais `disable_signature` permet de bypasser la détection une fois le token obtenu. |
| §3 "SCAN_REQUEST devient capability-gated dès qu'un appelant tente de scanner un autre PID que lui-même" | Vrai. Mais self-scan reste non gated → probe + DoS + self-FP. |
| §5 "ipc_gate/policy.rs et ipc_gate/audit.rs branchés au démarrage" | Vrai (main.rs:1502-1505). ✓ |

### 6.4 Livrables

- **Rapport détaillé :** `/home/z/my-project/audit/audit_notes/04-exoshield-detection.md` (présent fichier, ~600 lignes).
- **Aucun patch appliqué** au code source (audit lecture seule, conforme aux audits précédents).
- **8 correctifs P0** fournis en pseudo-code dans le rapport pour les développeurs ExoOS.
- **8 correctifs P1** + **6 P2** fournis au §5.
