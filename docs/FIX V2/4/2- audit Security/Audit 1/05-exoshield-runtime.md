# 05 — ExoShield NGAV Runtime (hooks / sandbox / network / forensics / ipc_gate)

**Task ID**: AUDIT-5-EXOSHIELD-2
**Périmètre**: `servers/exo_shield/src/{hooks,sandbox,network,forensics,ipc_gate}/`
**Auditeur**: sous-agent EDR/sandbox/network/forensics
**Date**: audit Phase 1
**Fichiers lus intégralement**: 23 fichiers source + `main.rs` + 2 docs de référence

---

## 0. Synthèse exécutive

Le serveur `exo_shield` (PID 10) est un **module de détection/confinement Ring 1** qui s'appuie sur le kernel ExoShield (IOMMU NIC, CET, PKS, ExoLedger) pour les invariants matériels. Le code audité implémente la couche applicative : hooks d'observation, sandbox logique, pare-feu, IDS, forensics, IPC gate.

**Le constat principal** : le code est **écrit comme un modèle/prototype** plutôt que comme un produit de sécurité opérationnel. La majorité des mécanismes de défense ne sont **pas câblés au runtime** (Firewall/IDS/TrafficAnalyzer/DnsGuard/SyscallFilterManager ne sont jamais instanciés dans `main.rs`), et plusieurs mécanismes "implémentés" sont des **no-ops déguisés** (canary memoryHooks, sandbox container). En l'état, un attaquant Ring 1/Ring 3 contourne la plupart des défenses applicatives en quelques étapes.

**Score d'efficacité d'isolation** : **4 / 10** — structure défensive correcte sur le papier, mais implémentation truffée de fail-open, de stubs non fonctionnels, et de chemins morts. Voir §10 pour le détail.

**Top 5 vulnérabilités runtime** : voir §11.

---

## 1. Hooks — `hooks/`

### 1.1 `exec_hooks.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| EXH-01 | CRYPTO | MEDIUM | `fnv1a_hash` 64-bit sans sel utilisé comme empreinte de chemin pour la blacklist. Birthday bound ≈ 2³² ; un attaquant peut forger un chemin collideant pour passer la blacklist en ~2¹⁶ essais (attaque pratique sur FNV-1a 64-bit). Aucune comparaison de chemin réel n'est faite après match du hash. |
| EXH-02 | RACE | HIGH | `pre_exec_validate()` retourne une `ExecAction` que le kernel "devrait appliquer" — pas d'atomicité entre la décision et l'exec réel. Fenêtre TOCTOU : un attaquant peut changer le blacklist/freq state entre pre et post (via IPC POLICY_UPDATE ou fork race). |
| EXH-03 | LOGIC | HIGH | `bump_exec_freq()` met à jour `pid`, `count`, `window_start` en trois stores atomiques séparés sous `Mutex`. Un second caller peut observer un état partiellement réinitialisé (pid changé, count=0, window_start ancien) et fausser le rate-limit. |
| EXH-04 | LOGIC | MEDIUM | `exec_hooks_init()` ne nettoie **pas** `BLACKLIST` ni `EXEC_FREQ_TABLE` (seulement les compteurs). Les entrées blacklist persistant après "reset" — comportement surprenant, possible bypass en post-init. |
| EXH-05 | LEAK | LOW | `query_exec_events_for_pid()` expose à tout appelant IPC autorisé (THREAT_QUERY self-PID) les `path_hash`, `ppid`, `uid`, `flags` de tous les exec d'un PID. Fuite de métadonnées process. |
| EXH-06 | LOGIC | MEDIUM | `compute_chain_depth()` est O(MAX_CHAIN_DEPTH × MAX_CHAIN_ENTRIES) = O(2048) par exec. Sur un système fork-intensif (build, CI), latence cumulée significative. |
| EXH-07 | ISOLATION | HIGH | Aucune self-protection : `BLACKLIST` est un `static Mutex<[…]>` accessible en écriture par n'importe quel code tournant dans l'address space d'`exo_shield`. Si un attaquant obtient RCE dans le serveur (via un bug de parsing IPC), il peut vider la blacklist d'un simple `BLACKLIST.lock()[..] = Default::default()`. |

### 1.2 `memory_hooks.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| MHH-01 | LOGIC | **CRITICAL** | **Détection de buffer overflow entièrement non-fonctionnelle**. `detect_buffer_overflow()` compare `entry.canary == CANARY_VALUE` où `entry.canary` est **la valeur stockée dans l'`AllocRecord` elle-même**, jamais lue depuis la mémoire réelle. Le commentaire l'admet : « in practice the canary address is computed but writing it requires kernel cooperation ». La canary n'est **jamais écrite en mémoire**, donc jamais corrompue par un débordement réel. Tout le système de détection overflow est un no-op cosmétique. |
| MHH-02 | LOGIC | **CRITICAL** | `scan_memory_region()` est un stub qui ne lit jamais la mémoire réelle. Pour un pattern « générique », il retourne comme "matches" toutes les allocations du PID dont la `size >= pat_len` — soit un faux positif garanti, sans aucune inspection. Commentaire : « In production, we'd read actual memory here ». La fonctionnalité annoncée n'existe pas. |
| MHH-03 | LOGIC | HIGH | `pre_alloc_check()` retourne `true` (bloquer) seulement si `check_alloc_rate()` renvoie le flag "rate anomaly". L'oversized alloc est "flaggé mais pas bloqué" (`// Flag but don't block`). En pratique, aucune allocation n'est jamais bloquée par ce hook. |
| MHH-04 | LEAK | HIGH | `query_mem_events_for_pid()` expose `addr` (virtuelle, 64-bit) + `size` + `pid` de toutes les allocations trackées d'un PID à tout appelant IPC self-PID. **Cartographie complète de la layout mémoire d'un processus** accessible via `THREAT_QUERY`. Fuite facilitant l'élaboration d'exploits. |
| MHH-05 | RACE | MEDIUM | `AllocRecord.flags` est accédée en lecture par `detect_buffer_overflow` (non-atomique : `entry.flags & 1`) et en écriture par `post_alloc_monitor` / `record_free` (écriture directe non-atomique). Mixed atomic/non-atomic sur le même champ → data race (UB en Rust safe, comportement indéfini). |
| MHH-06 | LOGIC | MEDIUM | Quarantaine UAF limitée à `MAX_FREED_REGIONS = 256`. Au-delà, eviction "oldest" → une région freed récemment peut être évictée avant la fin du délai de quarantaine (300M TSC ≈ 100ms), permettant un UAF réel non détecté. |
| MHH-07 | LOGIC | LOW | `verify_canaries_for_pid()` souffre du même défaut que MHH-01 : la canary comparée est stockée dans la structure, jamais en mémoire. |

### 1.3 `net_hooks.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| NHH-01 | LOGIC | **CRITICAL** | `pre_connect_check()` ignore explicitement `dst_ip`, `src_port`, `protocol` (`let _ = (dst_ip, src_port, protocol);`). Aucune politique basée sur destination n'est appliquée. Un processus peut se connecter à n'importe quelle IP/destination tant que la détection de port-scan par src_ip n'est pas déclenchée. |
| NHH-02 | ISOLATION | HIGH | **Aucun support IPv6** (`src_ip: u32`). Tout le trafic IPv6 est invisible. Un attaquant utilise IPv6 (si la pile le permet) pour bypasser toute détection port-scan/exfil. |
| NHH-03 | LOGIC | HIGH | `byte_count: u32` dans `NetEvent` → wrap à 4 GB. Un transfert de 10 MB (seuil EXFIL) suivi d'un transfert de 4 GB renvoie `byte_count = 0` et bypass le compteur d'exfiltration (`track_exfil_bytes` additionne `bytes as u64` mais le hook est alimenté en u32). |
| NHH-04 | RACE | MEDIUM | `track_port_for_scan()` met à jour `port_count` puis écrit dans `ports[count]` non-atomiquement. Deux appelants concurrents peuvent calculer le même `count`, écrire au même index, et perdre une détection. |
| NHH-05 | LOGIC | MEDIUM | `PORT_SCAN_TABLE` est limité à 64 entrées par src_ip. Attaque DoS triviale : 64 paquets depuis 64 IPs source distinctes (spoofing si possible) saturent la table → evictions → faux négatifs sur la détection. |
| NHH-06 | LOGIC | MEDIUM | `DNS_RATE_TABLE` réutilise `MAX_EXFIL_ENTRIES` (64) — pas de table dédiée. 64 PIDs max trackés pour DNS rate. Au 65e PID, eviction → faux négatifs. |
| NHH-07 | LOGIC | LOW | Aucune détection ICMP (ping flood, ICMP tunneling). Aucune détection tunneling L2/L3 (GRE, VXLAN, 6in4). |
| NHH-08 | LEAK | MEDIUM | `query_dns_for_pid()` expose `domain_hash` (FNV-1a 64-bit) — inversible pour des domaines courts via rainbow table. Fuite de métadonnées DNS. |

### 1.4 `syscall_hooks.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| SCH-01 | ISOLATION | **CRITICAL** | **Hook bypassable par instruction `syscall` inline**. Le hook s'exécute en Ring 1 : il dépend entièrement du kernel pour forwarder les syscalls. Si le kernel utilise un trampoline en-process (cf. seccomp-BPF user-space), un attaquant avec `mprotect` + `mmap RWX` peut patcher le trampoline et appeler `syscall` directement. Aucune mention de seccomp-like kernel enforcement. |
| SCH-02 | LOGIC | **CRITICAL** | **Syscalls critiques manquants dans la denylist** : `mprotect` (10), `mmap` (9) avec PROT_EXEC, `open`/`openat` (2/257), `socket` (41), `connect` (42), `process_vm_readv` (310), `process_vm_writev` (311), `userfaultfd` (323), `io_uring_setup` (425), `memfd_create` (319). `mmap RWX` + `mprotect RWX` sont les primitives #1 d'exécution de payload — non surveillées. |
| SCH-03 | LOGIC | HIGH | `ptrace` (SYS_PTRACE=101) est flaggé mais **jamais bloqué** : commentaire `// ptrace is monitored but not auto-blocked`. Or ptrace est le vecteur #1 d'injection process (PTRACE_POKETEXT, PTRACE_SEIZE). |
| SCH-04 | LOGIC | HIGH | `is_dangerous_syscall()` est un scan linéaire O(16) sur **chaque** syscall. Avec `SYSCALL_RATE_THRESHOLD=1024` et `update_freq` O(128), chaque syscall coûte ~150 ops en Ring 1 + IPC aller-retour si le kernel forward. **DoS système par syscall-frequency** : un processus légitime à 100k syscalls/s = 15M ops/s dans exo_shield. |
| SCH-05 | LOGIC | MEDIUM | `SYS_KEXEC_LOAD`/`SYS_INIT_MODULE`/`SYS_REBOOT` bloqués seulement pour `pid != 0/1`. Les constantes sont des numéros de syscall Linux x86_64 — or ExoOS est un microkernel Rust avec sa propre ABI. Ces numéros ne correspondent probablement à rien de réel côté kernel. La "protection" est symbolique. |
| SCH-06 | LOGIC | MEDIUM | `SEQ_TABLE` (256 entrées) éviction par `min_len` — un PID avec une séquence longue (donc plus susceptible de matcher) est évicté en premier. **Politique d'éviction inverse de l'objectif** : on garde les PIDs peu suspects, on évicté les plus suspects. |
| SCH-07 | RACE | MEDIUM | `update_freq()` et `update_sequence()` prennent le mutex puis modifient des champs non-atomiques (`table[i].count += 1`). Le mutex sérialise, mais `read_tsc()` est appelé sous le lock — contention élevée. |
| SCH-08 | LEAK | MEDIUM | `query_syscall_events_for_pid()` expose `args[0..3]` et `ret_val` à tout caller self-PID. Pour `open(path)`, `args[0]` est un pointeur utilisateur — pas directement une fuite, mais pour `read(fd, buf, count)`, `args[1]` est le buffer de destination. Combiné avec MHH-04, cartographie process complète. |
| SCH-09 | LOGIC | LOW | `detect_dangerous_syscall` retourne `(syscall_nr << 8) | level` — pour `syscall_nr >= 2²⁴`, le shift écrase `level`. Mineur mais indique un manque de validation. |

---

## 2. Sandbox — `sandbox/`

### 2.1 `container.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| CON-01 | ISOLATION | **CRITICAL** | **Le "container" est purement une structure de données — aucune isolation réelle**. `ContainerProfile` stocke `fs_root`, `net_namespace`, `syscall_filter`, `fs_config`, `net_config`, mais **aucun appel kernel** n'est fait pour appliquer ces contraintes (pas de `setns`, `chroot`, `unshare`, `clone` avec flags CLONE_NEW\*, pas d'ioctl réseau, pas d'eBPF filter). `quarantine_pid()` ajoute simplement une entrée à un tableau Rust. Le processus "quarantainé" garde **tous ses droits et accès kernel**. |
| CON-02 | LOGIC | HIGH | `quarantine_allows_syscall()` retourne `true` (autorise) si aucun profil n'existe pour le PID — **fail-open**. Un PID non-quarantainé n'est filtré par aucune politique de syscall. |
| CON-03 | LOGIC | HIGH | `is_pid_quarantined()` retourne `true` si `state != Destroyed` — un container `Paused` ou `Stopped` compte encore comme "quarantined", alors que le processus n'est pas réellement suspendu. Sémantique trompeuse pour les callers IPC. |
| CON-04 | LOGIC | MEDIUM | `ContainerProfile::new` accepte n'importe quel `pid` y compris `pid = 0` (kernel) ou `pid = RUNTIME_PID` (exo_shield lui-même). Un attaquant qui déclenche `quarantine_pid(0)` ou `quarantine_pid(exo_shield_pid)` via QUARANTINE_CMD pourrait DoS le kernel ou le shield lui-même. |
| CON-05 | ISOLATION | MEDIUM | Aucune resource limit (CPU, mem, fd, proc, threads) appliquée au container. Un processus quarantainé peut toujours fork-bomb, épuiser les FD, etc. |
| CON-06 | RACE | LOW | `ContainerManager::create` est `&mut self` donc sérialisé par le borrow checker, mais `quarantine_pid` appelle `manager.create` puis `manager.start` sous le même `Mutex`. Deux appels concurrents à `quarantine_pid` se sérialisent. OK. |

### 2.2 `fs_restriction.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| FSR-01 | ISOLATION | **CRITICAL** | **Symlink / hardlink escape non géré**. `PathMatcher::matches` compare des chemins littéraux sans canonicalisation. Un attaquant crée un symlink `/usr/bin/ls → /etc/shadow` : la whitelist `/usr/bin/*` autorise l'accès, le kernel suit le lien → lecture de `/etc/shadow`. Idem pour hardlink créé depuis un répertoire whitelisted. |
| FSR-02 | LOGIC | HIGH | `PathMatcher::matches` récursif pour `**` — complexité exponentielle en cas de patterns imbriqués (`/**/**/**/etc`). ReDoS-like : un pattern攻击 peut occuper le CPU. Pas de limite de profondeur. |
| FSR-03 | LOGIC | HIGH | `WhitelistFirst` policy : « blacklist cannot override a grant ». Donc un chemin whitelisté mais explicitement blacklisté est quand même autorisé. Si la whitelist a un pattern trop large (`/tmp/*`), la blacklist `/tmp/secret` est ignorée. **Politique de sécurité dangereuse**. |
| FSR-04 | LOGIC | MEDIUM | `AccessMode` est seulement R/W/X (3 bits) — pas de create/delete/append/chmod/chown. Politique FS trop grossière pour une isolation réelle. |
| FSR-05 | LOGIC | MEDIUM | `fs_config` est stocké dans `ContainerProfile` mais **jamais appliqué** — pas d'appel à `chroot`, `pivot_root`, ou hook VFS. Pure metadata. |
| FSR-06 | LEAK | LOW | `PathEntry::pattern_str()` retourne le pattern en clair — fuite de la configuration de sécurité si dump mémoire. |

### 2.3 `net_isolation.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| NIR-01 | LOGIC | **CRITICAL** | **Fail-open sur configuration vide**. `is_port_allowed()` retourne `true` si `port_count == 0`. `is_host_allowed()` retourne `true` si `host_count == 0`. Donc `new_deny_all()` (port_count=0, host_count=0, proto_filter=NONE) — si un caller ne vérifie que `is_port_allowed`, **tout passe**. Seul `proto_filter` (NONE) bloque réellement, mais l'API est piégeuse. |
| NIR-02 | RACE | HIGH | `BandwidthLimit::check_and_account()` lit `window_start`, décide "nouvelle fenêtre" puis `store(nbytes, Release)` + `store(now, Release)` — non-atomique. Deux threads concurrents peuvent tous deux voir "nouvelle fenêtre", tous deux reset, puis tous deux `fetch_add`. La limite bandwidth est contournable par concurrence. |
| NIR-03 | RACE | HIGH | `set_bw_out`/`set_bw_in` sont `&mut self` et écrivent `self.bytes_per_sec = …` (non-atomique). Pendant ce temps, `check_and_account` (qui est `&self`) lit `self.bytes_per_sec == 0` sans atomique. **Data race sur `bytes_per_sec`** — UB en Rust safe, peut lire une valeur partiellement écrite. |
| NIR-04 | ISOLATION | HIGH | Aucun support IPv6. `HostEntry` est hostname-based, mais un attaquant peut utiliser une IP littérale qui ne match aucun pattern → bypass. |
| NIR-05 | LOGIC | MEDIUM | Aucune défense DNS rebinding. `is_host_allowed("example.com")` retourne true ; l'attaquant fait pointer `example.com` vers `127.0.0.1` ou une IP interne via DNS rebinding → accès interne autorisé. |
| NIR-06 | LOGIC | MEDIUM | `ProtocolFilter` ne couvre que TCP/UDP/ICMP/RAW (4 bits). SCTP (132), GRE (47), IPv6-over-IPv4 (41), tunneled protocols bypass. |
| NIR-07 | LOGIC | LOW | `glob_match` est un simple `*` matcher sans `?` ni `**`. Limité pour des patterns hostname complexes. |

### 2.4 `syscall_filter.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| SYF-01 | LOGIC | HIGH | `SyscallBitmap` est 256 bits (4×u64) → couvre seulement syscall nr 0..255. Linux x86_64 a ~360 syscalls. ExoOS peut avoir sa propre numérotation >255. Tout syscall ≥ 256 est **silencieusement autorisé**. |
| SYF-02 | LOGIC | MEDIUM | `SyscallFilterManager` n'est jamais instancié dans `main.rs` — code mort en production. Seul `SyscallBitmap` est utilisé (via `ContainerProfile::check_syscall`). |
| SYF-03 | LOGIC | MEDIUM | `SyscallFilterProfile::record_violation` incrémente `total_violations` mais ne modifie jamais la bitmap — un PID qui dépasse le seuil de violations continue de pouvoir appeler les mêmes syscalls. Le retour "lethal" n'est jamais consommé par une action kill dans ce module. |
| SYF-04 | LOGIC | MEDIUM | `get_violation` indexing bug dans le cas `violation_head > MAX_VIOLATIONS` : la formule `head - recency` quand `recency == head` retourne 0, qui est un index arbitraire. |
| SYF-05 | LOGIC | LOW | `default_bitmap` est `deny_all` — fail-closed. OK. |

---

## 3. Network — `network/`

### 3.1 `dns_guard.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| DGS-01 | LOGIC | **CRITICAL** | **`DnsGuard` n'est jamais instancié dans `main.rs`** — code mort. Aucune intégration avec le pipeline NGAV. Toute la "DNS guard" n'est jamais exécutée en production. |
| DGS-02 | LOGIC | HIGH | `compute_entropy_scaled` est une approximation grossière (utilise `unique` count, pas Shannon). Test unitaire admet `e > 500` pour un random 20-char — bien en-dessous du seuil `ENTROPY_THRESHOLD_SCALED = 1024`. Un tunnel DNS base32 court (≤ 30 chars) peut passer sous le radar. |
| DGS-03 | LOGIC | HIGH | Aucune détection DNS tunneling protocol-based (TXT records, NULL records, CNAME chains, DNS-over-HTTPS). Seule l'entropie + rate est vérifiée. |
| DGS-04 | LOGIC | MEDIUM | Aucune défense DNS rebinding (cf. NIR-05). |
| DGS-05 | RACE | MEDIUM | `process_query` met à jour `exfil_window_count` et `exfil_window_start` en deux stores `Ordering::Relaxed` non-atomiques l'un par rapport à l'autre. Concurrence → reset/incr perdus. |
| DGS-06 | LEAK | LOW | `DnsQueryLog` stocke les domaines en clair jusqu'à 64 chars. Fuite potentielle via retrieve. |

### 3.2 `firewall.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| FWR-01 | LOGIC | **CRITICAL** | **`Firewall` (struct) n'est jamais instancié dans `main.rs`**. Seules `block_pid`/`unblock_pid`/`is_pid_blocked`/`firewall_init` (qui manipulent `PID_BLOCKLIST`) sont utilisées. Le moteur de règles (`add_rule`, `evaluate`, etc.) est **code mort**. Aucun filtrage paquet n'est appliqué en runtime. |
| FWR-02 | ISOLATION | HIGH | **Aucun support CIDR**. `FirewallRule::matches` fait `self.src_ip == src_ip` (égalité exacte u32). Impossible d'exprimer "deny 10.0.0.0/8" sans 16M règles. CIDR est fondamental au firewalling — absence bloquante. |
| FWR-03 | ISOLATION | HIGH | **Aucun support IPv6**. u32 IP. Tout le trafic IPv6 est invisible au firewall. |
| FWR-04 | LOGIC | HIGH | Aucun suivi d'état TCP (stateful inspection). Chaque paquet évalué indépendamment. Pas de SYN/ACK/FIN/RST tracking. Connexions longues non filtrables différentiellement. |
| FWR-05 | LOGIC | HIGH | Aucune gestion de la fragmentation IPv4. Seul le premier fragment porte l'en-tête L4 (port) — les fragments suivants ont `dst_port=0` qui match le wildcard. **Bypass via fragmentation**. |
| FWR-06 | LOGIC | MEDIUM | `evaluate()` parcourt toutes les règles sans short-circuit. Avec 64 règles × ~1M pps = 64M match checks/s. DoS pps. |
| FWR-07 | LOGIC | MEDIUM | `block_pid(exo_shield_pid)` — aucune protection contre l'auto-block. Un attaquant qui arrive à faire block_pid sur le PID du shield lui-même DoS tout le NGAV. |
| FWR-08 | LOGIC | MEDIUM | `PID_BLOCKLIST` est un tableau `[u32; 64]` — 64 PIDs max. DoS trivial : 64 PIDs distincts → evictions (en fait, pas d'eviction, la fonction retourne juste `false` après saturation, mais le blocklist est plein → plus aucun nouveau PID ne peut être blocké). |

### 3.3 `ids.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| IDS-01 | LOGIC | **CRITICAL** | **`IntrusionDetectionSystem` n'est jamais instancié dans `main.rs`** — code mort. Aucune détection IDS n'est active en runtime. |
| IDS-02 | LOGIC | HIGH | Recherche de signature naive O(n×m) — pas de Boyer-Moore, pas d'Aho-Corasick. 64 signatures × 64-byte patterns × 1500-byte payload = ~6M comparaisons par paquet. DoS pps trivial. |
| IDS-03 | LOGIC | HIGH | Aucun décodage protocol-aware : pas de décompression gzip, pas de normalisation URI HTTP, pas de décodage TLS. Signatures matchent sur raw bytes → triviallement évitables par encodage. |
| IDS-04 | LOGIC | MEDIUM | `set_anomaly_threshold(i32::MIN)` — aucun clamp. Attaquant (via IPC POLICY_UPDATE) peut désactiver la détection anomaly. |
| IDS-05 | LOGIC | MEDIUM | Alert ring buffer = 64 entries. Flood par matches low-severity → évince les alerts critiques (oldest overwritten). |
| IDS-06 | LEAK | LOW | Signatures stockées en clair dans `IdsSignature::pattern`. Fuite de TTPs attaquant si dump mémoire. |
| IDS-07 | LOGIC | MEDIUM | `get_alert` a le même bug d'indexing wrap-around que SYF-04. |

### 3.4 `traffic_analysis.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| TRA-01 | LOGIC | **CRITICAL** | **`TrafficAnalyzer` n'est jamais instancié dans `main.rs`** — code mort. Aucune analyse de trafic en runtime. |
| TRA-02 | LOGIC | HIGH | **Conntrack exhaustion DoS** : `MAX_FLOWS = 64`. Un attaquant ouvre 64 flows distincts (64 connexions TCP vers 64 ports/IPs) → tous les flows légitimes sont évictés (policy LRU). Le tracking des connexions légitimes est perdu. |
| TRA-03 | LOGIC | HIGH | Aucun TCP state machine. Un flow est juste un 5-tuple avec compteurs. Pas de SYN/ACK/FIN/RST tracking → pas de détection de scan SYN stealth, pas de détection de hijack de session. |
| TRA-04 | LOGIC | MEDIUM | `FlowKey::hash` est un multiply-xor faible. Deux flows avec même `src_ip ^ dst_ip` et même `(src_port << 16) | dst_port` ont même hash → collisions potentielles dans une table hash-based (non utilisé ici car la table est linéaire, mais c'est révélateur). |
| TRA-05 | LOGIC | MEDIUM | `burst_window_packets` est un compteur global unique — un flood sur un flow déclenche burst flag pour tous les flows. Faux positifs garantis. |
| TRA-06 | LEAK | LOW | `FlowEntry` stocke `byte_count`, `packet_count` — pas de payload, OK pour privacy, mais l'IDS qui n'existe pas (IDS-01) voudrait inspecter le payload. Tension architecturelle non résolue. |

---

## 4. Forensics — `forensics/`

### 4.1 `memory_dump.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| FMD-01 | CRYPTO | **CRITICAL** | **`DUMP_BUFFER` est un buffer statique 64 KB en clair** — aucune encryption at rest. Les dumps mémoire peuvent contenir **clés crypto, tokens, mots de passe, matériels de clé privée**. Tout attaquant qui obtient un accès lecture à l'address space d'`exo_shield` (via IPC THREAT_QUERY, via kernel exploit, via DMA) extrait ces secrets. |
| FMD-02 | CRYPTO | HIGH | **CRC-32 n'est pas une integrité cryptographique**. Trivial de forger un dump avec CRC valide. Pas de HMAC, pas de signature. `verify_dump_checksum` détecte les corruptions accidentelles mais pas les tampering malveillants. |
| FMD-03 | LEAK | **CRITICAL** | `retrieve_dump(region_idx, out_buf)` retourne le `DumpRegion` descriptor (incluant `addr` virtuelle originale, `pid`, `size`) **à tout caller IPC** (pas de capability check au niveau de cette fonction). Combiné avec `THREAT_QUERY` IPC (rate-limited mais pas capability-gated pour self-PID), un attaquant peut récupérer des dumps mémoire d'autres PIDs en forgeant des region_idx. |
| FMD-04 | RACE | HIGH | `find_storage_space()` calcule l'offset hors lock, puis prend `DUMP_REGIONS.lock()` + `DUMP_BUFFER.lock()` pour l'eviction. Deux `store_dump` concurrents peuvent calculer le même offset `used` et écrire en overlap. Le premier `DUMP_BUFFER.lock()` dans `store_dump` est pris après `find_storage_space` retourne — fenêtre de race. |
| FMD-05 | LOGIC | HIGH | `delete_dump()` ne **zero pas pas** le buffer. Les données du dump freed restent dans `DUMP_BUFFER`. Si un nouveau dump plus petit est écrit au même offset, les bytes de queue restent → **stale data leak** entre dumps. |
| FMD-06 | LOGIC | MEDIUM | `MAX_REGION_SIZE = 4096` — tout dump > 4 KB est **silencieusement tronqué** (`size = data.len().min(MAX_REGION_SIZE)`). Un dump de région 64 KB perd 60 KB. Faux sentiment de complétude forensique. |
| FMD-07 | LOGIC | MEDIUM | Aucun access control sur `retrieve_dump` / `enumerate_dumps` / `delete_dump` — fonctions publiques, appelables par n'importe quel code dans exo_shield. |
| FMD-08 | LOGIC | LOW | `DUMP_COUNT.fetch_sub(1)` dans `delete_dump` peut underflow si la région était déjà freed (le code vérifie `flags & 1 == 0` avant, donc OK en pratique, mais pas de preuve formelle). |

### 4.2 `timeline.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| FTL-01 | INTEGRITY | **CRITICAL** | **Aucune chaîne de hash / append-only**. `TIMELINE_BUFFER` est un ring buffer muteable. N'importe quel code dans exo_shield peut `TIMELINE_BUFFER.lock()[idx] = fake_entry`. **Tampering indétectable**. À comparer avec ExoLedger kernel (Blake3 chain, zone P0 non-écrasable) — la timeline Ring 1 n'a **aucune des garanties** d'ExoLedger. |
| FTL-02 | LOGIC | HIGH | `TIMELINE_SEQ` est monotone mais le `seq` est stocké dans le ring buffer qui peut être overwritten. Donc le `seq` d'une entrée peut être "réutilisé" après wrap-around du ring. `get_correlation_chain` recherche par `seq` dans tout le buffer — peut retourner une entrée overwritée. |
| FTL-03 | LOGIC | HIGH | `correlate_events()` est O(n²) sur 64 events = 2016 paires, **sous le lock du buffer**. DoS par flood d'events (chaque `record_timeline_event` peut déclencher 1-3 correlations). |
| FTL-04 | LOGIC | MEDIUM | `find_recent_event_for_pid` ne regarde que 64 entrées en arrière. Sur système chargé, un event précédent peut être au-delà de 64 → correlation manquée (faux négatif). |
| FTL-05 | LEAK | MEDIUM | `TimelineEntry` contient `pid`, `pid2`, `detail1`, `detail2`. Pour un event `Exec`, `detail1` = opcode (path hash). Pour `NetConnect`, `detail1` = dst_port. Pas de redaction → fuite métadonnées. |
| FTL-06 | LOGIC | MEDIUM | Aucun stockage persistant — toute la timeline est RAM-only. Reboot = perte totale de l'audit forensique. |
| FTL-07 | LOGIC | LOW | `create_correlation` evict par "weakest strength". Comme les entries vides ont `strength = 0`, elles sont toujours évictées en premier → OK. Mais une fois la table pleine, une nouvelle correlation faible ne remplace aucune (le test `if strength > weakest_strength` échoue). |

### 4.3 `report.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| FRP-01 | LEAK | HIGH | `serialize_report` et `export_audit` utilisent `unsafe { from_raw_parts }` sur la struct entière, **y compris les bytes de padding**. Padding peut contenir des résidus de stack/heap → info disclosure si le rapport est exfiltré. Le CRC couvre le padding mais ne le nettoie pas. |
| FRP-02 | CRYPTO | HIGH | CRC-32 forgeable sur `Report::checksum`. Pas de signature, pas de HMAC. Attaquant peut crafter un report avec valid CRC pour injecter de fausses conclusions forensiques. |
| FRP-03 | LOGIC | HIGH | `generate_report` prend uniquement des compteurs agrégés en paramètre et remplit `description_hash = fnv1a_hash(b"exec_denial_escalation")` (etc.) — des constantes. `primary_pid = 0`, `secondary_pid = 0`, `first_seen = 0`, `last_seen = 0`. **Le rapport ne contient aucune information réellement forensique** — uniquement des templates pré-hashés. Inutilisable pour incident response. |
| FRP-04 | LOGIC | MEDIUM | `deserialize_report` accepte n'importe quelles valeurs pour les enums `ThreatLevel`/`ThreatCategory` (stockés comme u8). Une valeur invalide produit une `Report` dont les downstream match arms peuvent panic ou prendre des branches unexpected. |
| FRP-05 | LOGIC | MEDIUM | `deserialize_report` fait `copy_from_slice` de bytes contrôlés par l'attaquant dans une `Report` struct — safe Rust (pas d'UB) mais crée une struct avec un état incohérent (e.g., `threat_count` qui ne correspond pas au nombre de threats non-nuls dans le tableau). |

---

## 5. IPC Gate — `ipc_gate/`

### 5.1 `access.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| IAC-01 | LOGIC | **CRITICAL** | **Fail-open pour msg_type inconnu**. `classify_service_cap_requirement` retourne `NotRequired` pour tout `msg_type > 5` (PMC_ANOMALY_REPORT = 6, et tous les autres). Un attaquant envoie msg_type = 99 → aucun check capability, passe directement au dispatcher (qui retourne SHIELD_ERR_ARGS, mais le rate-limit et l'audit s'appliquent sans cap). |
| IAC-02 | LOGIC | **CRITICAL** | **`target_pid == 0` traité comme "self-scan"**. `if target_pid == 0 || target_pid == sender_pid { return NotRequired; }`. Or PID 0 est le **kernel** dans ExoOS. Un attaquant envoie `SCAN_REQUEST` avec `target_pid = 0` → scanne le kernel **sans capability**. Potential kernel memory disclosure via les résultats du scan. |
| IAC-03 | LOGIC | HIGH | `THREAT_QUERY` avec `query_type` inconnu retourne `NotRequired` (fail-open). Un attaquant envoie `query_type = 99` → bypass cap requirement. |
| IAC-04 | LOGIC | HIGH | **Aucun anti-replay**. Le token capability (`ExoCapTokenWire` à `payload[100..120]`) est vérifié via `exo_cap_check` mais aucune nonce/timestamp n'est vérifié côté serveur. Un attaquant qui observe un token valide (network sniff, log leak) peut le rejouer indéfiniment (jusqu'à expiration kernel-side, si elle existe). |
| IAC-05 | LOGIC | MEDIUM | `read_u32_le` retourne silencieusement 0 sur OOB. Un attaquant envoie un payload de 4 bytes → `target_pid = 0`, `inline_len = 0` → traité comme self-scan (IAC-02). |
| IAC-06 | LOGIC | MEDIUM | `EXO_SHIELD_CAP_TOKEN_OFFSET = 100` et `EXO_SHIELD_CAP_TOKEN_LEN = 20` sont des constantes publiques → un attaquant sait exactement où placer un token volé dans le payload. |

### 5.2 `audit.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| IAU-01 | INTEGRITY | **CRITICAL** | **`AUDIT_BUFFER` est un ring buffer muteable sans chaîne de hash**. N'importe quel code dans exo_shield peut `AUDIT_BUFFER.lock()[idx] = fake_entry`. Tampering indétectable. Pas de merkle root, pas de HMAC, pas d'append-only. À comparer avec ExoLedger (Blake3 chain, zone P0). **L'audit Ring 1 n'a aucune des garanties** d'ExoLedger kernel. |
| IAU-02 | LEAK | HIGH | `export_audit` sérialize les `AuditEntry` via `unsafe { from_raw_parts }` sur la struct complète, **y compris padding bytes**. Info disclosure (stack/heap résidus dans le padding). |
| IAU-03 | LOGIC | MEDIUM | `record_audit` modifie `entry.timestamp` si 0 — mais c'est l'entry copiée, pas l'originale. OK. Cependant, le timestamp utilisé est celui du serveur, pas celui de l'expéditeur → un attaquant ne peut pas être corrélé avec d'autres logs basés sur l'horloge expéditeur. |
| IAU-04 | LOGIC | MEDIUM | `reply_nonce` est enregistré mais jamais vérifié côté anti-replay. Le champ est purement cosmétique. |
| IAU-05 | LOGIC | MEDIUM | `AuditEntry` est 40 bytes, buffer = 1024 entries = 40 KB. Sur système chargé, buffer plein en quelques secondes → oldest entries overwritten. **Perte d'audit sous charge**. |
| IAU-06 | LOGIC | LOW | `query_audit` (par PID) fait deux passes (src + dst) et append au même `out`. Si `out` est trop petit, la deuxième passe tronque. Pas de pagination. |

### 5.3 `policy.rs`

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| IPL-01 | LOGIC | **CRITICAL** | **`evaluate_policy` bypass pour `src_pid == KERNEL_PID` (0)**. Retourne `Allow` sans check de règle. Si un attaquant peut **spoof `sender_pid = 0`** dans un IPC message (dépend du kernel ABI), il bypass toute la politique IPC. Le kernel est supposé positionner `sender_pid` correctement, mais aucun mécanisme côté serveur ne valide cette hypothèse. |
| IPL-02 | LOGIC | HIGH | **`IPC_ROUTER_PID` (2) et `INIT_SERVER_PID` (1) ont droit `Allow` wildcard vers `EXO_SHIELD_PID` (10)**. Si un de ces services est compromis (bug dans init_server, IPC router exploit), l'attaquant a **accès full** à exo_shield : QUARANTINE_CMD, POLICY_UPDATE, etc. → **désactivation complète du NGAV à distance**. |
| IPL-03 | LOGIC | HIGH | **`add_policy` eviction DoS** : si 64 règles de priorité 255 sont installées, aucune nouvelle règle ne peut être ajoutée (la condition `table[i].priority < priority` échoue toujours). Un attaquant qui peut appeler `add_policy` (via POLICY_UPDATE cap) remplit la table → plus aucune règle légitime ne peut être ajoutée. |
| IPL-04 | LOGIC | HIGH | **`QUARANTINE_CMD` et `POLICY_UPDATE` sont `Deny` wildcard priority 220**, mais `IPC_ROUTER` et `INIT_SERVER` sont `Allow` priority 240/230 → wildcard deny est **effectivement bypassé** par ces deux PIDs. Le "deny by default" est contournable par compromission d'init_server ou ipc_router. |
| IPL-05 | LOGIC | HIGH | **Aucun anti-replay** : la même IPC message peut être envoyée répétément. Le rate limit s'applique mais les messages sont traités jusqu'à atteinte de la limite. Un attaquant avec un token capability valide peut soumettre 1000 POLICY_UPDATE par seconde avant throttling. |
| IPL-06 | LOGIC | MEDIUM | `check_rate_limit` table de 32 entrées. DoS trivial : 32 paires (src, dst) distinctes → evictions → état de rate-limit flushé. |
| IPL-07 | LOGIC | MEDIUM | `rule.rate_limit` est u8, multiplié par 10 pour obtenir msg/s. Si `rate_limit == 0`, `DEFAULT_RATE_LIMIT = 1000` est utilisé. Confus : un rule avec `rate_limit = 0` n'est pas "no limit" mais "default 1000 msg/s". |
| IPL-08 | LOGIC | MEDIUM | `bidirectional` flag : le rate-limit est tracké par paire (src, dst) ordonnée, pas bidirectionnelle. Un rule bidirectional avec rate-limit peut être contourné en inversant src/dst. |
| IPL-09 | LOGIC | MEDIUM | TSC-based timing : `window = 3_000_000_000` suppose 3 GHz. Sur CPU 2 GHz → fenêtre 1.5 s, sur 4 GHz → 0.75 s. Rate limits non portables. |
| IPL-10 | LOGIC | LOW | `set_default_policy` est global — un seul default pour tout trafic unmatched. Si quelqu'un met `Allow`, fail-open global. La valeur par défaut est `Deny` (OK). |

---

## 6. Cross-cutting / Architecture

| ID | Catégorie | Sévérité | Description |
|----|-----------|----------|-------------|
| XCU-01 | ISOLATION | **CRITICAL** | **Aucun secure boot du server exo_shield lui-même**. Le serveur démarre via `_start`, register l'endpoint IPC, et tourne. Aucune vérification d'intégrité post-boot (pas de self-measurement, pas de re-attestation). Un attaquant qui peut écrire dans l'address space du shield (via kernel exploit, DMA, /proc/.../mem équivalent) peut modifier son comportement indéfiniment. |
| XCU-02 | ISOLATION | HIGH | **Self-protection absente**. exo_shield ne protège pas ses propres pages mémoire, ne vérifie pas son code integrity, ne surveille pas son propre kill. Un attaquant qui peut `kill(exo_shield_pid)` ou `mmap`+`mprotect` sur son code désactive le NGAV. Seul ExoNmi (watchdog kernel) pourrait détecter — mais c'est un watchdog de liveness, pas d'intégrité. |
| XCU-03 | LOGIC | HIGH | **Configuration mutable à chaud via POLICY_UPDATE**. Capability-gated, mais la capability est `EXO_CAP_RIGHT_IPC_SEND` vers exo_shield — tout service qui a ce droit peut muter la policy runtime. Pas d'authentification séparée pour les mutations vs. lectures. Pas de mode "sealed" post-boot. |
| XCU-04 | LOGIC | HIGH | **Tous les locks sont `spin::Mutex` (spinlocks)** — pas de priority inheritance, pas de deadlock detection. Priority inversion possible : un process high-prio bloqué sur un lock tenu par un low-prio preempted. En single-core spinlock = deadlock potentiel si un handler IRQ ré-entre. |
| XCU-05 | LOGIC | HIGH | **Code mort massif** : Firewall, IDS, TrafficAnalyzer, DnsGuard, SyscallFilterManager ne sont jamais instanciés dans `main.rs`. Seuls `block_pid`/`is_pid_blocked` (firewall), `quarantine_pid`/`release_quarantine`/`is_pid_quarantined`/`quarantine_allows_syscall` (sandbox container), `evaluate_policy`/`record_audit`/`classify_service_cap_requirement` (ipc_gate), et tous les hooks (exec/memory/net/syscall) sont réellement appelés. **~60% du code network + sandbox est mort en production.** |
| XCU-06 | LOGIC | MEDIUM | `read_tsc()` utilisé partout — non invariant sur certains CPUs anciens, manipulable par le kernel, par-core. Cross-core comparisons unreliable. `wrapping_sub` gère le wraparound 64-bit mais pas la non-monotonicité. |
| XCU-07 | ISOLATION | MEDIUM | exo_shield tourne en Ring 1 — toute compromise kernel (Ring 0) = full owned. Pas de validation par exo_shield que Kernel B (Core 0) est vivant. |
| XCU-08 | LOGIC | MEDIUM | **Aucune constance de typage IPC** : le payload est `[u8; 120]` interprété différemment selon `msg_type` et le sous-type. Pas de schema versionné. Risque de parsing mismatch si client et serveur divergent. |
| XCU-09 | LEAK | MEDIUM | Multiples fonctions `query_*_for_pid()` retournent des métadonnées détaillées (adresses mémoire, paths hashés, args syscall, ports, IPs) à tout caller self-PID. Un attaquant peut interroger son propre PID pour vérifier ce que le shield sait sur lui, ou via cap token, interroger d'autres PIDs. **Self-reconnaissance + cross-PID leak**. |
| XCU-10 | LOGIC | LOW | `boot_log` est un no-op (`let _ = bytes;`) — pas de logging boot réel. Debugging difficile. |

---

## 7. Self-protection & anti-tamper

| Question | Réponse |
|----------|---------|
| exo_shield peut-il être tué par un attaquant ? | **Oui** — pas de protection spécifique. `kill(exo_shield_pid)` (ou équivalent syscall) doit être filtré kernel-side, mais le serveur ne le vérifie pas. |
| exo_shield peut-il être désactivé à distance ? | **Oui** — via IPC POLICY_UPDATE depuis `init_server` (PID 1) ou `ipc_router` (PID 2) si l'un d'eux est compromis (IPL-02). |
| exo_shield peut-il être modifié à chaud ? | **Oui** — pas de sealed config post-boot, pas de self-measurement (XCU-01, XCU-03). |
| exo_shield peut-il détecter sa propre compromission ? | **Non** — pas de canary sur son propre code, pas de re-attestation périodique. Seul ExoNmi (watchdog liveness kernel) pourrait détecter un freeze, pas une corruption. |

---

## 8. Bypass de hook — synthèse

| Vecteur de bypass | Statut |
|--------------------|--------|
| Instruction `syscall` inline directe | **Possible** (SCH-01) — dépend du kernel forwarding |
| `mprotect` + `mmap RWX` pour patcher trampoline | **Non détecté** (SCH-02 : mprotect/mmap absents de la denylist) |
| ptrace injection | **Surveillé mais non bloqué** (SCH-03) |
| IPv6 | **Invisible** (NHH-02, FWR-03, NIR-04) |
| ICMP tunneling | **Non détecté** (NHH-07) |
| DNS tunneling | **Code mort** (DGS-01) — non intégré |
| Fragmentation IPv4 | **Bypass firewall** (FWR-05) — mais firewall est code mort |
| Symlink / hardlink escape | **Non géré** (FSR-01) — mais fs_config jamais appliqué |
| Container escape via namespace | **Trivial** — pas de namespace appliqué (CON-01) |
| Conntrack exhaustion | **DoS trivial** (TRA-02) — mais TrafficAnalyzer est code mort |
| Anti-replay IPC | **Absent** (IAC-04, IPL-05) |
| Spoofing `sender_pid = 0` | **Bypass policy** (IPL-01) — dépend kernel |

---

## 9. Recommandations prioritaires

### CRITICAL — à corriger avant toute mise en production

1. **Chiffrer les dumps mémoire au repos** (FMD-01) : AES-GCM avec clé dérivée d'un secret kernel, ou utiliser `crypto_server` pour le chiffrement. Zero le buffer après export.
2. **Fail-open IPC pour msg_type inconnu** (IAC-01) : retourner `Required` ou `Malformed` pour tout msg_type non explicitement whitelisté. Principe default-deny.
3. **`target_pid == 0` doit exiger une capability kernel** (IAC-02) : jamais self-scan.
4. **Briquer le sandbox container à des appels kernel réels** (CON-01) : utiliser `clone` avec `CLONE_NEWPID|CLONE_NEWNET|CLONE_NEWNS` ou équivalent ExoOS. Sans cela, "quarantaine" = mensonge.
5. **Implémenter réellement la canary memory** (MHH-01) : appel kernel pour écrire la canary à `addr+size` et la relire. Sans cela, la détection overflow est cosmétique.
6. **Chaîner l'audit Ring 1** (IAU-01, FTL-01) : Blake3 chain comme ExoLedger, zone append-only, signature HMAC. Sans cela, tampering indétectable.
7. **Câbler le code mort** (XCU-05) : instancier Firewall, IDS, TrafficAnalyzer, DnsGuard dans `main.rs` et les intégrer au pipeline NGAV.
8. **Ajouter `mprotect`, `mmap RWX`, `process_vm_readv/writev`, `userfaultfd`, `memfd_create`, `io_uring_*` à la denylist** (SCH-02).
9. **Bloquer `ptrace`** pour tout PID non-debugger (SCH-03).
10. **Access control sur `retrieve_dump`/`query_*_for_pid`** (FMD-03, XCU-09) : exiger capability pour toute lecture cross-PID.

### HIGH — à corriger avant durcissement

11. CIDR matching pour firewall (FWR-02).
12. IPv6 support partout (NHH-02, FWR-03, NIR-04).
13. Stateful TCP inspection (FWR-04, TRA-03).
14. Anti-replay IPC via nonce + cache (IAC-04, IPL-05).
15. Hash cryptographique (HMAC-SHA256) pour integrity des dumps et reports (FMD-02, FRP-02).
16. Constant-time comparison pour token capability (vérifier exo_cap_check est CT).
17. Séparer `init_server`/`ipc_router` capabilities par type de message, pas wildcard Allow (IPL-02).
18. TSC-based timing → utiliser un timer kernel monotonic portable (IPL-09).
19. Boyer-Moore / Aho-Corasick pour IDS (IDS-02).
20. Path canonicalization avant PathMatcher (FSR-01) — résoudre symlinks.

### MEDIUM

21. CIDR pour net_isolation (NIR-04).
22. Resource limits (CPU/mem/fd/proc) sur container (CON-05).
23. Persistent storage pour timeline (FTL-06).
24. Pagination pour query_audit (IAU-06).
25. Rate-limit tables plus larges + LRU adaptatif (NHH-05, IPL-06).

---

## 10. Score d'efficacité d'isolation : 4 / 10

**Justification** :

| Critère | Note | Raison |
|---------|------|--------|
| Self-protection | 1/10 | Aucune (XCU-01, XCU-02) — un attaquant peut tuer/modifier exo_shield |
| Hook coverage | 3/10 | Syscalls critiques manquants (SCH-02), bypass par `syscall` inline (SCH-01), ptrace non bloqué (SCH-03) |
| Sandbox effectif | 1/10 | Container = metadata uniquement (CON-01), fs_config jamais appliqué (FSR-05), symlink escape (FSR-01) |
| Network filtering | 2/10 | Firewall code mort (FWR-01), pas de CIDR (FWR-02), pas d'IPv6 (FWR-03), pas de stateful (FWR-04) |
| Forensics integrity | 2/10 | CRC-32 forgeable (FMD-02, FRP-02), dumps en clair (FMD-01), timeline/audit tamperable (FTL-01, IAU-01) |
| IPC gate | 5/10 | Capability-gated pour mutations, mais fail-open sur msg_type inconnu (IAC-01), target_pid=0 self-scan (IAC-02), pas d'anti-replay (IAC-04) |
| Detection efficacy | 3/10 | Memory canary non-fonctionnelle (MHH-01), DNS/IDS/TrafficAnalyzer code mort (DGS-01, IDS-01, TRA-01), report template sans données réelles (FRP-03) |
| Audit logging | 3/10 | Tamperable ring buffers, pas de hash chain (IAU-01, FTL-01), perte sous charge (IAU-05) |

**Note globale pondérée : 4/10.**

Le kernel ExoShield (IOMMU NIC, CET, PKS, ExoLedger, ExoPhoenix) fournit une défense matérielle forte — mais le serveur Ring 1 audité **n'exploite pas** ces primitives efficacement et ajoute peu au-delà de heuristiques de détection bypassables. Le véritable mur de défense est kernel-side ; le serveur exo_shield est davantage un **collecteur d'événements** qu'un **confinement actif**.

---

## 11. Top 5 vulnérabilités runtime

### #1 — CRITICAL : Forensic memory dumps en clair, contenant potentiellement des clés crypto / mots de passe
**Fichiers** : `forensics/memory_dump.rs`
**IDs** : FMD-01, FMD-03, FMD-05
**Impact** : Exfiltration de secrets système. Tout attaquant avec un accès lecture à l'address space d'`exo_shield` (IPC THREAT_QUERY non-cap-gated pour self-PID, kernel exploit, DMA) extrait les dumps mémoire qui contiennent clés crypto, tokens, mots de passe, matériels de clé privée des processes dumpés. CRC-32 forgeable (FMD-02) → tampering indétectable. Pas de zero après delete (FMD-05) → stale data leak.
**Fix** : Chiffrer AES-GCM avec clé dérivée kernel-side, zero après delete, access control capability sur `retrieve_dump`, HMAC-SHA256 pour integrity.

### #2 — CRITICAL : IPC gate fail-open + `target_pid == 0` treated as self-scan
**Fichiers** : `ipc_gate/access.rs`
**IDs** : IAC-01, IAC-02, IAC-03
**Impact** : Un attaquant envoie `SCAN_REQUEST` avec `target_pid = 0` (le kernel ExoOS) → scanne la mémoire kernel **sans capability**. De même, tout `msg_type > 5` (ou `query_type` inconnu) bypass les checks capability. Potential kernel info disclosure et bypass complet du gating IPC.
**Fix** : Default-deny pour msg_type inconnu, reject `target_pid == 0` explicitement, exiger capability pour toute query non-self.

### #3 — CRITICAL : Sandbox container est purement metadata, aucune isolation kernel réelle
**Fichiers** : `sandbox/container.rs`, `sandbox/fs_restriction.rs`, `sandbox/net_isolation.rs`
**IDs** : CON-01, FSR-01, FSR-05, NIR-01
**Impact** : `quarantine_pid(pid)` ajoute une entrée à un tableau Rust — n'applique **aucun** namespace/chroot/netns/syscall filter kernel. Le processus "quarantainé" garde tous ses accès. `quarantine_allows_syscall` retourne `true` si aucun profil (fail-open). `fs_config` jamais appliqué. Symlink/hardlink escape trivial (FSR-01). **La quarantaine est cosmétique.**
**Fix** : Câbler à des syscalls kernel réels (clone avec CLONE_NEW\*, chroot, setns, seccomp-bpf-like filter). Default-deny sur `quarantine_allows_syscall`. Canonicaliser les paths avant matching.

### #4 — HIGH : Hook bypass + syscalls critiques manquants (mprotect, mmap RWX, ptrace)
**Fichiers** : `hooks/syscall_hooks.rs`
**IDs** : SCH-01, SCH-02, SCH-03
**Impact** : Le hook syscall s'exécute Ring 1 et dépend du kernel pour forwarder. Si le forwarding est via trampoline in-process, un attaquant avec `mprotect`+`mmap RWX` (qui ne sont **pas** dans la denylist) patche le trampoline et appelle `syscall` directement. `ptrace` est surveillé mais jamais bloqué → injection process libre. Aucune détection de `memfd_create`, `userfaultfd`, `io_uring`, `process_vm_readv/writev` — primitives d'exploitation modernes.
**Fix** : Ajouter ces syscalls à la denylist, bloquer ptrace par défaut, intégrer avec seccomp-like kernel filter (cf. syscall_filter.rs qui existe mais n'est pas câblé).

### #5 — HIGH : Audit + timeline tamperable, pas de hash chain, init_server/ipc_router bypass
**Fichiers** : `ipc_gate/audit.rs`, `forensics/timeline.rs`, `ipc_gate/policy.rs`
**IDs** : IAU-01, FTL-01, IPL-01, IPL-02, IPL-04
**Impact** : L'audit Ring 1 et la timeline sont des ring buffers muteables sans hash chain ni append-only — tampering indétectable (à l'opposé d'ExoLedger kernel). `sender_pid == 0` bypass toute policy IPC (IPL-01). `init_server` (PID 1) et `ipc_router` (PID 2) ont wildcard Allow vers exo_shield (IPL-02) → compromission d'un seul de ces services = full control du NGAV (désactivation à distance via QUARANTINE_CMD/POLICY_UPDATE).
**Fix** : Chaîne Blake3 + HMAC pour audit/timeline (cf. ExoLedger). Valider `sender_pid != 0` côté serveur. Séparer capabilities init_server/ipc_router par msg_type, pas wildcard Allow. Anti-replay via nonce + cache.

---

## 12. Conclusion

Le serveur `exo_shield` est un **cadre défensif bien structuré sur le papier** (deny-by-default syscall bitmap, capability-gated IPC, audit/timeline/forensics séparés, sandbox container avec lifecycle) **mais l'implémentation est défaillante à plusieurs niveaux critiques** :

- **Code mort massif** : Firewall, IDS, TrafficAnalyzer, DnsGuard ne sont jamais instanciés. ~60% du code network + sandbox est inactif en production.
- **Mécanismes no-op** : Canary memoryHooks compare une valeur stockée à elle-même, sandbox container n'applique aucune isolation kernel, report forensics ne contient que des templates hashés.
- **Fail-open multiples** : msg_type inconnu, target_pid=0, port_count=0, host_count=0 — autant de chemins où la sécurité se désactive.
- **Tampering trivial** : Audit et timeline sont des ring buffers sans hash chain, dumps en clair avec CRC-32 forgeable.
- **Self-protection absente** : exo_shield peut être tué, modifié, ou désactivé à distance via init_server/ipc_router compromis.

La défense matérielle kernel (ExoShield v1 — IOMMU NIC, CET, PKS, ExoLedger, ExoPhoenix) reste le véritable mur. Le serveur Ring 1 audité, en l'état, **n'ajoute pas de couche de sécurité significative** au-delà de la collection d'événements pour forensics (et encore, tamperable).

**Recommandation** : avant toute mise en production, prioriser les fixes CRITICAL (§9, items 1-10). Sans ces fixes, le NGAV exo_shield est **bypassable en quelques étapes** par un attaquant Ring 1/Ring 3 motivé.
