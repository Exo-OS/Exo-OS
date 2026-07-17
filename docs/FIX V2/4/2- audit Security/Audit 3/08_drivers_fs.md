# ExoOS Audit — Drivers & Filesystems (Task 8)

**Auditeur**: Sub-agent deep security audit (sandboxed vibe coding workspace)
**Périmètre**: `drivers/network/{common,virtio_net,e1000,loopback}`,
`drivers/storage/{fscrypt,ahci,virtio_blk,nvme,partition}`, `drivers/security/verity`,
`drivers/fs/{lib,fat32,ext4}`, `drivers/tty/*`, `drivers/input/ps2/*`,
`drivers/display/vga/*`.
**Méthode**: Lecture intégrale (pas de skimming) de chaque fichier listé.
**Date**: Phase 8.

---

## 1. Inventory (fichiers audités)

### drivers/network/common/src (5)
- `lib.rs` — déclaration de modules.
- `ether.rs` — parsing/écriture EthernetHeader (14 octets).
- `pci_scan.rs` — itérateur pur de BDF PCI.
- `ipv4.rs` — parsing Ipv4Header + checksum.
- `dma_buf.rs` — structure DmaBuffer passive (pas d'allocation).

### drivers/network/virtio_net/src (7)
- `main.rs` — driver userspace, boucle IPC, init hardware, poll RX/TX.
- `pci.rs` — découverte PCI + mapping BAR + parsing capabilities virtio.
- `net.rs` — état du driver (rings locaux, submitted flags).
- `virtqueue.rs` — allocation DMA + ring virtio.
- `mac.rs` — lecture MAC depuis device_cfg.
- `interrupt.rs` — ack ISR + enregistrement IRQ.
- `config.rs` — constantes et structures de messages.

### drivers/network/e1000/src (7)
- `main.rs` — driver userspace E1000.
- `pci.rs` — découverte/mapping BAR0.
- `mac.rs` — lecture RAL/RAH.
- `tx.rs` — TxRing descripteurs.
- `rx.rs` — RxRing descripteurs.
- `interrupt.rs` — enable/disable IMS/ICR.
- `regs.rs` — offsets registres E1000.

### drivers/network/loopback/src (3)
- `main.rs` — driver echo loopback (TX_SUBMIT → TX_COMPLETE).
- `state.rs` — compteurs rx_released/tx_echoed.
- `echo.rs` — swap IPv4 src/dst + checksum.

### drivers/storage/fscrypt/src (1) — **CRITICAL**
- `lib.rs` — AEAD XChaCha20+BLAKE3-MAC, KEK Argon2id, wrap/unwrap volume key, blob cipher.

### drivers/storage/ahci/src (4)
- `lib.rs` — driver AHCI/SATA avec HAL injectée.
- `structures.rs` — CmdHeader/PRDT/FisRegH2D.
- `tests.rs` — mock HBA in-memory.
- `regs.rs` — layout registres AHCI 1.3.1.

### drivers/storage/virtio_blk/src (4)
- `lib.rs` — wrapper autour de la crate `virtio_drivers`.
- `hal.rs` — implémentation Hal avec bounce buffers.
- `virtqueue.rs` — structures et logique pure.
- `legacy_pci.rs` — transport legacy PCI via I/O ports.

### drivers/storage/nvme/src (5)
- `lib.rs` — driver NVMe 1.4 avec HAL injectée.
- `queue.rs` — anneaux SQ/CQ + phase tag (pure).
- `tests.rs` — mock contrôleur NVMe.
- `cmd.rs` — encodage SQE/décodage CQE + PRP (pure).
- `regs.rs` — layout registres contrôleur NVMe.

### drivers/storage/partition/src (5)
- `lib.rs` — orchestrateur `scan()` + types.
- `mbr.rs` — parsing MBR + détection protective GPT.
- `gpt.rs` — parsing header GPT + entrées + CRC.
- `crc32.rs` — CRC-32 IEEE bit-à-bit.
- `guid.rs` — GUID mixed-endian + type-GUIDs ExoOS.

### drivers/security/verity/src (1) — **CRITICAL**
- `lib.rs` — vérification Ed25519+SHA-512 d'un footer EXOSIG01 attaché en fin d'image kernel.

### drivers/fs/src (1 + fat32/* + ext4/*)
- `lib.rs` — déclaration modules + FsDriverError.
- `fat32/{mod,bpb,cluster,dir_entry,fat_table,alloc,compat}.rs` — parsing FAT32.
- `ext4/{mod,superblock,inode,dir,extent,journal,xattr,compat}.rs` — parsing ext4.

### drivers/tty/src (6)
- `lib.rs`, `main.rs` (stub no-op), `console.rs`, `vt100.rs`, `pty.rs`, `line_disc.rs`.

### drivers/input/ps2/src (5)
- `lib.rs`, `main.rs`, `i8042.rs`, `keyboard.rs`, `mouse.rs`.

### drivers/display/vga/src (2)
- `lib.rs`, `main.rs` (stub no-op).

---

## 2. Per-module status

| Module                | Fichiers | LOC | Statut       | Notes |
|-----------------------|----------|-----|--------------|-------|
| network/common        | 5        | ~150 | OK avec 1 mineur | ipv4.rs vérifie total_len, mais pas cohérence ihl+total_len vs fragment offset |
| network/virtio_net    | 7        | ~1700 | **VULN CRITIQUE** | BYPASS_IOMMU explicite ; rx_pool_for_head non borné |
| network/e1000         | 7        | ~1700 | **VULN CRITIQUE** | BYPASS_IOMMU explicite ; len non validé en RX |
| network/loopback      | 3        | ~170 | OK | swap IPv4 borné |
| storage/fscrypt       | 1        | ~400 | **VULN CRITIQUE** | AEAD ≠ Poly1305 (deviation spec) ; pas de zeroization ; pas de filename encryption ; pas de rollback protection |
| storage/ahci          | 4        | ~700 | OK | HAL bornée, PRDT rejet 0/oversize, waits bornés |
| storage/virtio_blk    | 4        | ~620 | OK | délègue à virtio_drivers ; pas de bypass IOMMU explicite |
| storage/nvme          | 5        | ~900 | OK | PRP rejet >2 pages, phase tag, waits bornés |
| storage/partition     | 5        | ~560 | OK | CRC header+entries validés, MAX_GPT_ENTRIES=256, fallback backup |
| security/verity       | 1        | ~330 | **MISMATCH CRITIQUE** | **N'EST PAS dm-verity** : aucune Merkle tree, aucun hash bloc, Ed25519-only sur image kernel |
| fs/fat32              | 7        | ~400 | **VULNÉRABLE** | parse_dir_cluster ne normalise pas les chemins ; pas de protection traversale ../ ; LFN non borné |
| fs/ext4               | 8        | ~700 | **VULNÉRABLE** | extent tree ne parcourt pas les nœuds internes ; journal jamais rejoué (intentionnel mais doc insuffisante) ; xattr value offset non borné |
| tty                   | 6        | ~470 | **STUB INCOMPLET** | pty.rs = ring buffer SANS auth ; vt100.rs = GÉNÉRATION seulement (pas de parser) ; main.rs = spinloop |
| input/ps2             | 5        | ~560 | OK | spin_limit ; touches mappées ; pas de panic sur scancode inconnu |
| display/vga           | 2        | ~180 | OK avec garde | bounds-check à l'init, mais `set_color`/`write_byte` présument cells.len() >= VGA_CELLS |

---

## 3. Findings table

| ID       | Severity   | Module                    | Résumé |
|----------|------------|---------------------------|--------|
| DRV-001  | CRITICAL   | virtio_net/virtqueue.rs   | Driver passe `DMA_MAP_FLAGS_BYPASS_IOMMU` au kernel → IOMMU désactivé pour les rings virtio |
| DRV-002  | CRITICAL   | e1000/main.rs             | Même bypass IOMMU pour rings RX/TX E1000 |
| DRV-003  | CRITICAL   | kernel/dma.rs (effet)     | Le syscall `sys_dma_alloc` honore `BYPASS_IOMMU` utilisateur sans check de privilège → n'importe quel driver Ring1 désactive l'IOMMU |
| DRV-004  | HIGH       | virtio_net/main.rs        | `rx_pool_for_head[head as usize]` — head est lu depuis used ring écrit par le device ; si un device malveillant met `elem.id` ≥ 256, OOB index dans tableau 256 |
| DRV-005  | HIGH       | e1000/rx.rs               | `len = desc.length` est écrit par le device puis forwardé au network_server sans clamp à MTU/PAGE_SIZE → un device malveillant peut annoncer `len = 0xFFFF` |
| DRV-006  | CRITICAL   | fscrypt/lib.rs            | AEAD utilise **BLAKE3 keyed-MAC** (tag 16 o) au lieu de **Poly1305** — dévie du mandate architecture (`XChaCha20-Poly1305 AEAD`) |
| DRV-007  | CRITICAL   | fscrypt/lib.rs            | **Pas de zeroization** des clés : `derive_kek` retourne `[u8;32]` par valeur, `memory: Vec<Block>` Argon2 jamais zeroed ; `kek`/`vk`/`blob_key` non wrappés dans `Zeroizing<>` |
| DRV-008  | CRITICAL   | fscrypt/lib.rs            | **Pas de filename encryption** — fscrypt ne couvre que le contenu (blob), pas les noms |
| DRV-009  | CRITICAL   | fscrypt/lib.rs            | **Pas de rollback protection** : `aead_open` verify-then-decrypt → un ancien (ciphertext,tag) valide est accepté. Aucun compteur, aucune ancre TPM, aucun hash tree metadata |
| DRV-010  | HIGH       | fscrypt/lib.rs            | `block_nonce` est déterministe `blake3(blob_id ‖ offset_le)[..24]` → prédictible mais OK pour XChaCha20 ; toutefois aucune défense contre réutilisation si `disk_offset` est réutilisé (p.ex. snapshot/remap) |
| DRV-011  | MEDIUM     | fscrypt/lib.rs            | `aead_open` laisse le buffer en l'état (ciphertext) en cas d'échec — correct en soi, mais le `expected` tag intermédiaire (16 o sur la stack) n'est pas zeroed |
| DRV-012  | CRITICAL   | verity/lib.rs             | **Le module "verity" n'est PAS dm-verity** : aucune Merkle tree, aucun hash par bloc, aucune racine ancrée. C'est un vérifieur Ed25519 d'image kernel. Aucune protection runtime par bloc |
| DRV-013  | HIGH       | fat32/dir_entry.rs        | `parse_dir_cluster` reconstruit le nom LFN sans aucune vérification de chemin (`..`, `/`, nul bytes) → path traversal possible au niveau appelant |
| DRV-014  | HIGH       | fat32/cluster.rs          | `cluster_is_valid` n'est pas appelé dans `parse_dir_cluster` ni dans `find_free_cluster` ; un BPB corrompu peut annoncer `cluster_count = 0xFFFFFFFF` et causer OOB |
| DRV-015  | HIGH       | fat32/alloc.rs            | `find_free_cluster` itère `0..end.min(fat_entries.len())` mais ne valide pas que `fat_entries[i]` correspond bien au cluster `i+2` côté disque (pas de lecture croisée FAT1/FAT2) |
| DRV-016  | MEDIUM     | fat32/bpb.rs              | `data_sectors` peut underflow → clampé à 0, mais `bytes_per_cluster = bps*spc` n'est pas borné (peut atteindre 16 MiB si `bps=4096, spc=255`) — pas de DoS direct mais allocation grosse |
| DRV-017  | HIGH       | ext4/extent.rs            | `search_level` ne parcourt **pas** les nœuds internes (`depth > 0` → `None`) : un fichier dont l'extent tree a ≥2 niveaux renvoie toujours None → fichier illisible silencieusement, ou pire, l'appelant peut croire le bloc absent et écraser |
| DRV-018  | MEDIUM     | ext4/dir.rs               | `lookup_in_block` ne valide pas `name_len <= rec_len - 8` → un disque malveillant peut faire `rec_len=8, name_len=200` et faire sortir la lecture hors du bloc (clôt par `<= block.len()` mais le `name` lu contient des octets du voisin) |
| DRV-019  | MEDIUM     | ext4/xattr.rs             | `e_value_offs` est lu puis utilisé tel quel (`val_off..val_off+val_size`) — seul check `<= block.len()`, pas de check que `val_off >= 32` (header) ou que la zone ne déborde pas dans une autre xattr |
| DRV-020  | HIGH       | ext4/journal.rs           | `read_journal_state` ne lit QUE 4 octets (s_start) — pas de validation du CRC32c JBD2 superblock, ni de `s_sequence` vs `s_start` → un attaquant peut coller un journal "clean" sur un FS corrompu |
| DRV-021  | MEDIUM     | ext4/superblock.rs        | `block_size = 1024 << s_log_block_size` n'est pas borné : si `s_log_block_size = 0xFFFF_FFFF` (corrompu), déborde ; devrait être clampé à [0,6] (1KiB..64KiB) |
| DRV-022  | HIGH       | tty/pty.rs                | `RingBuffer` est une structure de données seule — **aucune authentification**, aucun notion de master/slave, aucun contrôle d'accès PID. N'importe quel process ayant la référence peut lire/écrire |
| DRV-023  | HIGH       | tty/main.rs               | `_start` est un **stub spinloop** : le driver TTY n'existe pas réellement ; aucun dispatch IPC, aucune isolation console |
| DRV-024  | HIGH       | tty/vt100.rs              | Ne contient QUE des **générateurs** d'escape sequences (`cursor_position`, `CLEAR_SCREEN`). **Aucun parser** d'entrées — un attaquant ne peut pas forcer d'OOB via ce module, mais cela signifie aussi qu'aucune sanitization n'est faite sur les escape sequences reçues du réseau/un process |
| DRV-025  | MEDIUM     | tty/line_disc.rs          | `LINE_MAX=1024` est la seule borne ; pas de support UTF-8 multibyte, pas de protection contre TIOCSTI-like spoofing |
| DRV-026  | MEDIUM     | input/ps2/main.rs         | Le driver PS/2 pousse les événements vers `INPUT_SERVER_ENDPOINT` via `SYS_IPC_SEND` sans authentifier que le récepteur est bien input_server — un endpoint usurpé recevrait toutes les frappes |
| DRV-027  | LOW        | input/ps2/i8042.rs        | `drain_output` boucle sans limite bornée (`while OUTPUT_FULL`) → un device malveillant peut bloquer le driver. `spin_limit` n'est pas appliqué ici |
| DRV-028  | LOW        | input/ps2/mouse.rs        | `packet[0] & 0x08 == 0` (bit always-on) est le seul check de synchronisation ; un device malveillant peut envoyer des packets forgeés (spoofing trivial) — pas de défense possible côté driver PS/2 |
| DRV-029  | MEDIUM     | display/vga/lib.rs        | `VgaTextBuffer::new` assert `cells.len() >= VGA_CELLS` mais `write_byte` calcule `idx = row*VGA_COLS+col` sans re-vérifier — si `cells` est rétréci après construction, OOB |
| DRV-030  | LOW        | network/common/ipv4.rs    | `total_len as usize > packet.len()` est rejeté, mais un packet où `total_len < packet.len()` (padding L2) est accepté sans troncation → l'appelant doit le gérer |
| DRV-031  | LOW        | network/common/dma_buf.rs | `contains_offset` utilise `checked_add` correctement ; aucun vuln, mais aucun accès IOMMU non plus — c'est une structure passive |
| DRV-032  | MEDIUM     | partition/gpt.rs          | `header_size > 512` rejeté (`BadHeaderSize`) — mais `header_size` non borné supérieurement par spec GPT (devrait être == 92 pour rev 1.0). Accepte tout 92 ≤ hs ≤ 512 |
| DRV-033  | MEDIUM     | partition/lib.rs          | `read_gpt_entries` alloue `vec![0u8; blocks * bs]` ; si `num_partition_entries ≤ 256` mais `sizeof_partition_entry` est énorme (corrompu), `total = 256 * huge` peut OOM. Borné par `MAX_GPT_ENTRIES=256` mais pas par `entry_size` |
| DRV-034  | HIGH       | nvme/lib.rs               | `submit_and_poll` : si `c.cid != expected_cid`, retourne `Err(0xFFFF)` sans re-avancer la CQ head → la prochaine complétion sera perdue ; en I/O synchrone OK, mais si le contrôleur envoie une async (par ex. AER), le driver se désynchro |
| DRV-035  | LOW        | nvme/lib.rs               | `alloc_cid` wrap-around non-borné : après 65535 commandes, revient à 1 et peut collisionner avec une commande en vol (théorique, en synchrone pas d'incident) |
| DRV-036  | HIGH       | virtio_blk/hal.rs         | `BOUNCE_TABLE` est global `Mutex<[Option<BounceRecord>; 128]>` — si 128 buffers DMA sont partagés simultanément, le 129e échoue silencieusement (renvoie paddr=0 qui peut être interprété comme un pointeur nul valide côté device) |
| DRV-037  | CRITICAL   | fscrypt/lib.rs            | `unwrap_volume_key` ne vérifie pas `wrapped[5] == VK_SOURCE_PASSPHRASE` (seuls magic+version) → si une future source (TPM, file) est ajoutée, on dérive via passphrase un blob wrap-pour-autre-chose → confusion |
| DRV-038  | HIGH       | virtio_net/main.rs        | `submit_rx_slot` : `addr = rx_base_iova + pool_idx*PAGE_SIZE` ; si `pool_idx ≥ pool_count` (fourni par network_server via IPC, non vérifié), `addr` déborde hors de la région DMA allouée → device écrit hors région |
| DRV-039  | HIGH       | virtio_net/main.rs        | Boucle IPC principale n'authentifie pas l'expéditeur du message `NET_CTRL_TX_SUBMIT` : n'importe quel process connaissant l'endpoint ID 14 peut soumettre des paquets TX (cf. D-01 architecture) |
| DRV-040  | MEDIUM     | e1000/main.rs             | `process_tx_submit` : `idx = msg.pool_idx as usize ; if idx >= TX_RING_SIZE` — correct, mais `self.tx_iova(idx)` n'est pas vérifié contre `pool_count` → un device peut écrire à `tx_base_iova + idx*PAGE_SIZE` pour `idx` jusqu'à 255 même si le pool est plus petit |
| DRV-041  | MEDIUM     | virtio_net/virtqueue.rs   | `recycle_desc` suit `next` lu depuis le descriptor **écrit par le device** (`snapshot.next`) ; si un device malveillant modifie `next` pour pointer vers un autre descriptor en cours d'usage, le driver le libère et le réutilise → double-use |
| DRV-042  | MEDIUM     | e1000/rx.rs               | `poll_one` ne vérifie pas `desc.length <= PAGE_SIZE - hdr_size` avant de le renvoyer → buffer overflow potentiel côté network_server si celui-ci fait `copy_nonoverlapping` de `len` octets depuis la page DMA |
| DRV-043  | LOW        | tty/console.rs            | `write_crlf_normalized` n'a pas de borne de sortie ; si `data` est immense, le sink peut déborder (pas critique, délégué au sink) |
| DRV-044  | LOW        | input/ps2/keyboard.rs     | `hid_to_ascii` ne borne pas `code - 0x04` pour la plage `0x0004..=0x001d` (lettres) — OK car match arm délimite, mais `ctrl + c.is_ascii_alphabetic()` soustrait `b'a'` → pour ctrl+lettre hors a-z mais `is_ascii_alphabetic()` true, le résultat est `(c - b'a') + 1` qui peut déborder |

---

## 4. Findings détaillés

### DRV-001 — CRITICAL — virtio_net demande BYPASS_IOMMU

**Fichier**: `drivers/network/virtio_net/src/virtqueue.rs:11,86-95`

```rust
const DMA_MAP_FLAGS_BYPASS_IOMMU: u64 = 1 << 4;
...
        let iova = unsafe {
            syscall::syscall5(
                syscall::SYS_DMA_ALLOC,
                bytes as u64,
                2,
                &mut virt as *mut u64 as u64,
                DMA_MAP_FLAGS_BYPASS_IOMMU,
                0,
            )
        };
```

**Pourquoi vulnérable**: Le driver demande explicitement au kernel de **bypasser l'IOMMU** pour l'allocation des rings virtio. Côté kernel (`memory/dma/core/mapping.rs:195`), `BYPASS_IOMMU` force `iova = phys.as_u64()` (adresse physique brute). Conséquence : les descripteurs virtio contiennent des adresses physiques kernel, et **le device peut DMA vers n'importe quelle adresse physique** si le firmware/device est malveillant (pas de traduction IOMMU pour restreindre). Le commentaire du code `// VirtIO queue addresses stay physical until translated IOMMU contexts are attached and programmed for Ring1 drivers.` indique que c'est un état transitoire non résolu.

**Fix**: (1) Retirer `DMA_MAP_FLAGS_BYPASS_IOMMU` et laisser le kernel allouer une IOVA traduite. (2) Côté kernel, ignorer `BYPASS_IOMMU` pour les process non privilégiés (cf. DRV-003). (3) Vérifier que le device BDF est bien attaché au domaine IOMMU du driver avant `DRIVER_OK`.

---

### DRV-002 — CRITICAL — e1000 demande BYPASS_IOMMU

**Fichier**: `drivers/network/e1000/src/main.rs:25,550-561`

```rust
const DMA_MAP_FLAGS_BYPASS_IOMMU: u64 = 1 << 4;
...
fn dma_alloc(size: usize) -> Result<DmaRegion, i64> {
    let mut virt = 0u64;
    let iova = unsafe {
        syscall::syscall5(
            syscall::SYS_DMA_ALLOC,
            size as u64,
            DMA_DIR_BIDIR,
            &mut virt as *mut u64 as u64,
            DMA_MAP_FLAGS_BYPASS_IOMMU,
            0,
        )
    };
```

**Pourquoi vulnérable**: Identique à DRV-001. Les rings RX/TX E1000 sont alloués en bypass IOMMU. Un E1000 malveillant (ou un périphérique PCIe hotplug usurpant l'ID 8086:100E) peut écrire dans toute la RAM physique via les descripteurs. Le commentaire `// e1000 descriptors need DMA-visible physical addresses until the kernel programs a translated IOMMU context for this Ring1 driver.` confirme l'état transitoire.

**Fix**: Idem DRV-001. Allouer dans un domaine IOMMU dédié au BDF du E1000.

---

### DRV-003 — CRITICAL — sys_dma_alloc honore BYPASS_IOMMU sans check

**Fichier**: `kernel/src/syscall/table.rs:4624-4674` + `kernel/src/memory/dma/core/mapping.rs:195-205`

```rust
// kernel/src/syscall/table.rs
pub fn sys_dma_alloc(
    size: u64, direction: u64, user_virt_out: u64,
    map_flags: u64,        // ← flag utilisateur non filtré
    domain_hint: u64, _a6: u64,
) -> i64 {
    ...
    match crate::drivers::sys_dma_alloc_for_pid(
        caller_pid, size as usize, direction,
        DmaMapFlags(map_flags as u32),   // ← passé tel quel
        effective_domain,
    ) { ... }
}

// kernel/src/memory/dma/core/mapping.rs:195
let iova = if flags.contains(DmaMapFlags::BYPASS_IOMMU) {
    IovaAddr::new(phys.as_u64())        // ← bypass !
} else { ... };
```

**Pourquoi vulnérable**: N'importe quel process Ring1 peut appeler `SYS_DMA_ALLOC` avec `map_flags = 1<<4` et obtenir un IOVA = adresse physique. Le kernel ne valide pas que l'appelant a le droit de bypass. Le commentaire du code mentionne un usage légitime (`périphérique encore attaché en passthrough`), mais c'est une politique fail-open : la valeur par défaut devrait être IOMMU-on, et le bypass ne devrait être accordé qu'à un process privilégié porteur d'une capability (par ex. `CAP_IOMMU_BYPASS`).

**Fix**: (1) Masquer `BYPASS_IOMMU` dans `sys_dma_alloc` sauf si `caller_pid == 0` ou si le process possède `CAP_IOMMU_ADMIN`. (2) Ajouter un audit log pour tout appel tenté avec `BYPASS_IOMMU`. (3) À terme, supprimer ce flag de l'ABI userspace.

---

### DRV-004 — HIGH — `rx_pool_for_head[head as usize]` non borné

**Fichier**: `drivers/network/virtio_net/src/main.rs:338,394`

```rust
// Ligne 338 (submit_rx_slot) :
self.rx_pool_for_head[head as usize] = pool_idx;

// Ligne 394 (poll_rx) :
let pool_idx = self.rx_pool_for_head[head as usize];
```

**Pourquoi vulnérable**: `head` est retourné par `rx_queue.poll_used()` qui lit `elem.id` depuis la used ring écrite par le device (`virtqueue.rs:201-207`). Le device malveillant peut mettre `elem.id` à n'importe quelle valeur u32, qui est castée en u16 puis indexée dans `rx_pool_for_head: [u16; 256]`. Si `head ≥ 256` (possible puisque le cast est `(elem.id as u16)` et que `elem.id` peut déborder vers `0..=65535`), on accède hors tableau → OOB read/write sur la struct `VirtioHardware`. Le cast en u16 limite à 65535 mais le tableau fait 256.

**Fix**: Vérifier `head < self.rx_queue.queue_size` (et `queue_size ≤ 256`) avant l'indexation. Si out-of-range, drop le descriptor sans traitement.

---

### DRV-005 — HIGH — e1000 RX `len` non clampé

**Fichier**: `drivers/network/e1000/src/rx.rs:90-93` + `main.rs:358-369`

```rust
// rx.rs poll_one :
let len = desc.length;       // ← écrit par le device
desc.status = 0;
self.head = (self.head + 1) & (RX_RING_SIZE - 1);
Some((idx as u16, len))      // ← forwardé tel quel

// main.rs poll_rx :
let Some((pool_idx, len)) = (unsafe { self.rx.poll_one() }) else { break; };
...
ready.entries[ready.count as usize] = RxPacketRef { pool_idx, len };
```

**Pourquoi vulnérable**: `desc.length` est écrit par le device E1000. Si un device malveillant met `length = 0xFFFF`, cette valeur est forwardée au network_server comme `len` du paquet reçu, sans clamp à `PAGE_SIZE - hdr_size` (4096 - 10 = 4086 max attendu). Le network_server peut ensuite faire `copy_nonoverlapping(dma_buf, pkt_buf, len)` et déborder `pkt_buf` si celui-ci fait 4096 octets.

**Fix**: Dans `poll_one`, clamer `len = desc.length.min(PAGE_SIZE as u16 - hdr_size as u16)`. Rejeter `len == 0`.

---

### DRV-006 — CRITICAL — fscrypt AEAD = XChaCha20+BLAKE3-MAC, pas Poly1305

**Fichier**: `drivers/storage/fscrypt/src/lib.rs:31-153`

```rust
const MAC_CONTEXT: &str = "ExoOS-Kernel-XChaCha20-BLAKE3-MAC-v1";
...
fn compute_tag(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8], ct: &[u8]) -> [u8; TAG_LEN] {
    let mut ikm = [0u8; KEY_LEN + NONCE_LEN];
    ikm[..KEY_LEN].copy_from_slice(key);
    ikm[KEY_LEN..].copy_from_slice(nonce);
    let mac_key = blake3::derive_key(MAC_CONTEXT, &ikm);

    let mut hasher = blake3::Hasher::new_keyed(&mac_key);
    hasher.update(&(aad.len() as u64).to_le_bytes());
    hasher.update(aad);
    hasher.update(&(ct.len() as u64).to_le_bytes());
    hasher.update(ct);
    let full = hasher.finalize();
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&full.as_bytes()[..TAG_LEN]);
    tag
}
```

**Pourquoi vulnérable**: L'architecture (`01_architecture.md:15`) mandate **`XChaCha20-Poly1305 AEAD encrypt-then-MAC, AAD length-prefixed`**. Ici, le MAC est **BLAKE3 keyed-MAC** (tag tronqué à 16 octets), pas Poly1305. Conséquences : (1) déviation spec — un auditeur/kernel qui s'attend à Poly1305 ne peut pas interopérer. (2) BLAKE3-MAC avec tag 128-bit a une sécurité différente de Poly1305 (qui est un MAC universel à sécurité prouvée). (3) Le tag est tronqué à 16 octets : la probabilité de forge aléatoire est 2⁻¹²⁸, acceptable mais inférieure au tag 16 octets de Poly1305 (même taille, mais Poly1305 a une preuve de sécurité sous PRF). (4) La dérivation `mac_key = blake3::derive_key(ctx, key‖nonce)` est non standard — l'usage canonique serait `HKDF-Blake3(key, nonce)` comme mentionné dans le mandate.

**Fix**: Soit (a) conformer au mandate et utiliser `XChaCha20-Poly1305` du kernel (`security::crypto::xchacha20_poly1305`), soit (b) mettre à jour le mandate pour documenter ce choix (BLAKE3-MAC) et l'analyser formellement. Recommandé : (a).

---

### DRV-007 — CRITICAL — Pas de zeroization des clés fscrypt

**Fichier**: `drivers/storage/fscrypt/src/lib.rs:202-217,234-278,286-308`

```rust
pub fn derive_kek(passphrase: &[u8], salt: &[u8; 32]) -> Result<[u8; 32], FsCryptError> {
    ...
    let mut out = [0u8; 32];                              // ← stack, jamais zeroed
    let mut memory: Vec<argon2::Block> = Vec::new();     // ← heap, jamais zeroed
    memory.try_reserve(...)...;
    memory.resize(...);
    a2.hash_password_into_with_memory(passphrase, salt, &mut out, memory.as_mut_slice())...;
    Ok(out)                                                // ← retourné par valeur
}

pub fn blob_key(volume_key: &[u8; 32], blob_id: &[u8; 32]) -> [u8; 32] {
    let mut material = [0u8; 64];                          // ← stack, jamais zeroed
    material[..32].copy_from_slice(volume_key);
    material[32..].copy_from_slice(blob_id);
    blake3::derive_key("exofs-atrest-key-v1", &material)  // ← retourné, jamais zeroed
}
```

**Pourquoi vulnérable**: Toutes les clés (KEK, volume key, blob key, mac_key, subkey ChaCha20) sont stockées dans des buffers stack/heap **non zeroés** après usage. Un dump mémoire (cold boot, hibernate, ExoPhoenix memory_dump, exploit kernel) expose les clés. Le mandate crypto (`01_architecture.md:20`) exige **zeroization** des clés. Aucune utilisation de `Zeroizing<>` ou équivalent.

**Fix**: Wrapper toutes les clés dans `zeroize::Zeroizing<[u8; N]>`. Pour `derive_kek`, utiliser `hash_password_into_with_memory` avec un `memory` backed by `Zeroizing<Box<[Block]>>`. Drop trait qui memset.

---

### DRV-008 — CRITICAL — Pas de filename encryption

**Fichier**: `drivers/storage/fscrypt/src/lib.rs` (entier)

Le module expose `xor_block`, `blob_key`, `block_nonce`, `wrap_volume_key`, `unwrap_volume_key`, `aead_seal`, `aead_open` — **aucune fonction pour chiffrer les noms de fichiers**. Les metadata (directory entries, inodes, xattrs) ne sont pas couvertes.

**Pourquoi vulnérable**: Un attaquant qui obtient le disque chiffré voit la structure des répertoires (noms, tailles, timestamps) en clair. Cela fuite : liste d'applications installées, noms de documents sensibles, structure organisationnelle. Le mandate fscrypt (Linux) exige `FNAME_ENCRYPT` pour les noms. Le nom du module (`fscrypt`) suggère cette couverture, mais elle est absente.

**Fix**: Ajouter `encrypt_filename(volume_key, parent_inode, name) -> (ciphertext, nonce)` et `decrypt_filename(...)`. Utiliser une AEAD légère (ou BLAKE3-CTR + MAC) avec `parent_inode` comme AAD pour empêcher le moving de fichiers entre répertoires.

---

### DRV-009 — CRITICAL — Pas de rollback protection

**Fichier**: `drivers/storage/fscrypt/src/lib.rs:169-187`

```rust
pub fn aead_open(
    key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], aad: &[u8],
    buf: &mut [u8], tag: &[u8; TAG_LEN],
) -> bool {
    let expected = compute_tag(key, nonce, aad, buf);
    let mut diff = 0u8;
    for i in 0..TAG_LEN { diff |= expected[i] ^ tag[i]; }
    if diff != 0 { return false; }
    xchacha20_xor(key, nonce, buf);
    true
}
```

**Pourquoi vulnérable**: Aucun mécanisme ne détecte qu'un (ciphertext, tag) a été **réécrit par une version antérieure valide**. Le nonce est déterministe (`block_nonce(blob_id, disk_offset)`) donc un même offset produit toujours le même nonce — si l'attaquant remet l'ancien (ciphertext, tag) à cet offset, le tag re-valide. C'est l'attaque rollback classique. Aucun compteur monotone, aucun hash tree metadata, aucune ancre TPM/kernel-ro.

**Fix**: (1) Stocker un numéro de version par bloc, inclus dans l'AAD. (2) Maintenir un Merkle tree des (version, hash) ancré dans un superblock signé (Ed25519) ou TPM PCRs. (3) Pour le volume key wrap, inclure un compteur dans `wrap_volume_key` et l'incrémenter à chaque rewrap.

---

### DRV-010 — HIGH — Nonce déterministe par (blob, offset)

**Fichier**: `drivers/storage/fscrypt/src/lib.rs:294-302`

```rust
pub fn block_nonce(blob_id: &[u8; 32], disk_offset: u64) -> [u8; 24] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(blob_id);
    material[32..40].copy_from_slice(&disk_offset.to_le_bytes());
    let h = blake3::hash(&material);
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&h.as_bytes()[..24]);
    nonce
}
```

**Pourquoi vulnérable**: Le nonce est déterministe en `disk_offset`. Si le système de stockage réutilise un `disk_offset` pour un autre `blob_id` (par ex. après un snapshot/remap/defrag), le même nonce est réutilisé avec une clé différente (puisque `blob_key` dépend de `blob_id`). Avec XChaCha20 (flux), cela n'est pas immédiatement cassant car la clé change, mais c'est une fragilité. Plus grave : si le même blob est réécrit au même offset avec la même clé, **le même keystream est réutilisé** → XOR des deux ciphertexts = XOR des plaintexts. C'est OK pour fscrypt car le `disk_offset` est censé être unique par écriture, mais c'est fragile.

**Fix**: Inclure un numéro de version dans le nonce, ou utiliser un compteur monotone stocké par bloc.

---

### DRV-011 — MEDIUM — `expected` tag non zeroed après `aead_open`

**Fichier**: `drivers/storage/fscrypt/src/lib.rs:176-184`

```rust
let expected = compute_tag(key, nonce, aad, buf);
let mut diff = 0u8;
for i in 0..TAG_LEN { diff |= expected[i] ^ tag[i]; }
if diff != 0 { return false; }
// expected reste sur la stack
```

**Pourquoi vulnérable**: `expected` est un `[u8; 16]` sur la stack contenant le tag attendu. Bien que ce ne soit pas la clé, c'est un tag intermédiaire qui peut aider une attaque par side-channel. Devrait être zeroed.

**Fix**: `let mut expected = ...; ...; zeroize::zeroize(&mut expected);`

---

### DRV-012 — CRITICAL — "verity" n'est PAS dm-verity

**Fichier**: `drivers/security/verity/src/lib.rs` (entier)

Le module implémente `verify_image(image, pubkey) -> KernelVerdict` — une **vérification Ed25519 d'un footer EXOSIG01** attaché à une image kernel. Il n'y a :
- **Aucune Merkle tree** (pas de `MerkleTree`, `MerkleNode`, `verify_block`, `root_hash`)
- **Aucun hash par bloc** (pas de `block_hash`, `verify_block_at`)
- **Aucune racine ancrée** (le module prend `pubkey` en paramètre ; l'appelant bootloader/kernel est responsable)
- **Aucune protection runtime** : après `verify_image`, le kernel tourne sans aucune revérification des blocs disque lus

**Pourquoi vulnérable**: Le nom du module (`verity`) suggère dm-verity (block-level integrity tree), mais l'implémentation est uniquement **boot-time image signature**. Conséquence : un attaquant qui peut modifier le disque après le boot (par ex. via DMA attack, hot-swap SSD, exploit runtime) **n'est pas détecté**. Les blocs lus par le FS ne sont pas authentifiés. Le mandate architecture mentionne `ExoSeal phase0 (BLAKE3 hash kernel + Ring1)` qui semble être le runtime check, mais ce n'est PAS dans ce module.

**Fix**: Soit (a) renommer le module en `kernel_signature` (clarté), et créer un vrai module `dm_verity` pour le runtime block integrity (Merkle tree BLAKE3, racine ancrée TPM PCR ou kernel-ro), soit (b) si ExoSeal phase0 couvre déjà ce besoin, documenter clairement que ce module n'est que boot-time et que le runtime est ailleurs.

---

### DRV-013 — HIGH — FAT32 `parse_dir_cluster` ne sanitize pas les noms

**Fichier**: `drivers/fs/src/fat32/dir_entry.rs:99-147`

```rust
pub fn parse_dir_cluster(buf: &[u8]) -> Vec<DirEntryParsed> {
    ...
    let name = if !lfns.is_empty() {
        ...
        utf16_to_utf8(&utf16)
    } else { short_name_to_string(&entry.dir_name) };
    ...
    out.push(DirEntryParsed { name, ... });
}
```

**Pourquoi vulnérable**: Le nom reconstruit (LFN ou 8.3) est retourné tel quel sans filtrage des caractères `/`, `\`, `..`, NUL, ou contrôle. Un disque USB malicieusement formaté peut contenir une entrée LFN `"../../etc/passwd"` ou `"\0evil.txt"`. Si l'appelant (VFS) join le nom avec un chemin parent sans sanitization, il y a path traversal. La règle FAT32 n'interdit pas ces caractères dans les LFN (seul `/\:*?"<>|` sont illégaux côté Windows mais pas côté spec FAT32 brute), donc le driver devrait au minimum rejeter `/` et NUL.

**Fix**: Dans `parse_dir_cluster`, rejeter les noms contenant `/`, `\`, NUL, ou `..` exact. Loguer et skip l'entrée.

---

### DRV-014 — HIGH — `cluster_is_valid` jamais appelé dans le parseur

**Fichier**: `drivers/fs/src/fat32/cluster.rs:13-15` + `dir_entry.rs:140-143`

```rust
pub fn cluster_is_valid(cluster: u32, bpb: &ParsedBpb) -> bool {
    cluster >= 2 && cluster < bpb.cluster_count + 2
}
```

**Pourquoi vulnérable**: `parse_dir_cluster` retourne `first_cluster: entry.first_cluster()` sans appeler `cluster_is_valid`. Si un BPB corrompu annonce `cluster_count = 0xFFFFFFFF` ou si une entrée de répertoire a `first_cluster = 0xFFFFFFFE`, l'appelant qui fait `cluster_to_sector(first_cluster, bpb)` va calculer `data_start + (cluster-2)*spc` qui peut déborder u64 ou pointer hors disque. Suivi d'une lecture disque OOB.

**Fix**: Dans `parse_dir_cluster`, appeler `cluster_is_valid` et marquer l'entrée comme invalide (skip) si faux.

---

### DRV-015 — HIGH — Pas de cross-check FAT1 vs FAT2

**Fichier**: `drivers/fs/src/fat32/alloc.rs:22-37` + `fat_table.rs:42-53`

```rust
pub fn find_free_cluster(fat_entries: &[u32], bpb: &ParsedBpb) -> Option<u32> {
    ...
    for i in start..end.min(fat_entries.len()) {
        if is_free(fat_entries[i]) { ... return Some(i as u32); }
    }
    None
}
```

**Pourquoi vulnérable**: La règle `FS-FAT32-05` dit "FAT1 + FAT2 toujours écrites ensemble" et le code de `write_entry_to_buf` documente "appeler deux fois", mais `find_free_cluster` ne lit qu'une seule FAT. Si les deux FATs divergent (corruption, attaque), le driver utilise FAT1 aveuglément. Pas de détection de divergence.

**Fix**: Lire FAT1 et FAT2, comparer, et en cas de divergence : (a) refuser le montage en RW, ou (b) voter majorité (si ≥3 FATs, ce qui n'est pas le cas ici).

---

### DRV-016 — MEDIUM — `bytes_per_cluster` non borné

**Fichier**: `drivers/fs/src/fat32/bpb.rs:108`

```rust
bytes_per_cluster: bps * spc,
```

**Pourquoi vulnérable**: `bps` peut être 4096, `spc` peut être 255 (u8) → `bytes_per_cluster = 1_044_480` (~1 MiB). Pas de DoS direct, mais un disque malveillant peut forcer des allocations grosses (1 MiB par cluster), saturant la mémoire si le driver lit un cluster entier en RAM.

**Fix**: Borner `bytes_per_cluster` à 32 KiB (limite pratique Windows).

---

### DRV-017 — HIGH — Ext4 extent tree ne parcourt pas les nœuds internes

**Fichier**: `drivers/fs/src/ext4/extent.rs:56-78`

```rust
fn search_level(base: *const u8, logical: u32, depth: u16) -> Option<(u64, u16)> {
    let hdr = unsafe { &*(base as *const Ext4ExtentHeader) };
    if hdr.eh_magic != EXT4_EXT_MAGIC { return None; }
    if depth == 0 {
        // Feuille : liste d'Ext4Extent
        ...
    } else {
        // Nœud interne : liste d'Ext4ExtentIdx (on ne parcourt pas le disque ici)
        None     // ← toujours None !
    }
}
```

**Pourquoi vulnérable**: Pour un fichier dont l'extent tree a `depth > 0` (fichiers > ~4 GiB ou fragmentés), `find_extent` retourne toujours `None`. L'appelant peut interpréter ce `None` comme "bloc absent" et potentiellement le traiter comme un zero-block ou pire, l'allouer (si RW). Cela peut corrompre un fichier de >4 GiB silencieusement. Le commentaire dit "on ne parcourt pas le disque ici" — mais il n'y a pas de code ailleurs qui le fait.

**Fix**: Implémenter la descente récursive dans les nœuds internes : lire `ei_leaf_lo | (ei_leaf_hi << 32)`, fetcher le bloc, appeler `search_level` récursivement avec `depth-1`. Borner la profondeur à 5 (limite spec ext4).

---

### DRV-018 — MEDIUM — Ext4 `lookup_in_block` ne valide pas `name_len ≤ rec_len - 8`

**Fichier**: `drivers/fs/src/ext4/dir.rs:26-50`

```rust
let rec_len = entry.rec_len as usize;
if rec_len == 0 || offset + rec_len > block.len() { break; }
if entry.inode != 0 {
    let name_len = entry.name_len as usize;
    let name_start = offset + 8;
    if name_start + name_len <= block.len() {
        let name = &block[name_start..name_start + name_len];
        ...
    }
}
offset += rec_len;
```

**Pourquoi vulnérable**: Le check `name_start + name_len <= block.len()` empêche OOB mais ne vérifie pas `name_len <= rec_len - 8`. Un disque malveillant peut mettre `rec_len = 12, name_len = 100` — le nom lu contient des octets du entry suivant (info leak mineur) ou des données post-entry. Pas de crash mais info leak.

**Fix**: Ajouter `if name_len + 8 > rec_len { break; }`.

---

### DRV-019 — MEDIUM — Ext4 xattr `e_value_offs` non borné inférieurement

**Fichier**: `drivers/fs/src/ext4/xattr.rs:63-69`

```rust
let val_off  = entry.e_value_offs as usize;
let val_size = entry.e_value_size as usize;
let value = if val_off + val_size <= block.len() {
    block[val_off..val_off + val_size].to_vec()
} else {
    alloc::vec![]
};
```

**Pourquoi vulnérable**: `val_off` peut être 0 ou petit — la spec dit `e_value_offs` est relatif au début du bloc xattr et doit pointer après le header (32 o) et après les entries. Si `val_off = 0`, le value lu contient le header lui-même (info leak du magic/checksum). Pas de crash, mais pas de validation spec.

**Fix**: Rejeter `val_off != 0 && val_off < 32` (header size). Rejeter `val_off + val_size > block.len() - 4` ( checksum footer si METADATA_CSUM).

---

### DRV-020 — HIGH — Ext4 journal state sans CRC32c JBD2

**Fichier**: `drivers/fs/src/ext4/journal.rs:20-40`

```rust
pub fn read_journal_state(raw: &[u8]) -> JournalState {
    if raw.len() < 12 { return JournalState::Error; }
    let magic = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);
    if magic != JBD2_MAGIC { return JournalState::Error; }
    if raw.len() < 32 { return JournalState::Error; }
    let s_start = u32::from_be_bytes([raw[28], raw[29], raw[30], raw[31]]);
    if s_start == 0 { JournalState::Clean } else { JournalState::NeedsRecovery }
}
```

**Pourquoi vulnérable**: Aucune validation du CRC32c du superblock JBD2 (`s_checksum` à l'offset 0x3C du superblock JBD2 v2). Un attaquant peut forger un journal avec `magic + s_start=0` (clean) pour masquer un crash et forcer un montage RW alors que des transactions non validées existent. La règle `FS-EXT4-03` dit "JAMAIS rejouer le journal Linux depuis Exo-OS" — correct, mais on devrait au moins valider le CRC pour distinguer un journal vraiment clean d'un journal forgé.

**Fix**: Lire et valider `s_checksum` (CRC32c) du superblock JBD2. Rejeter si invalide.

---

### DRV-021 — MEDIUM — Ext4 `block_size` non borné

**Fichier**: `drivers/fs/src/ext4/superblock.rs:152`

```rust
let block_size = 1024u32 << disk.s_log_block_size;
```

**Pourquoi vulnérable**: Si `s_log_block_size` est corrompu à `0xFFFF_FFFF`, `1024 << 0xFFFF_FFFF` est UB en Rust (shift overflow ; en release mode ça wrappe modulo 32 bits → 0 ou valeur incohérente). La spec ext4 dit `s_log_block_size ∈ [0, 6]` (1 KiB à 64 KiB). Pas de check.

**Fix**: `if disk.s_log_block_size > 6 { return Err(InvalidParameter); }` avant le shift.

---

### DRV-022 — HIGH — tty/pty.rs = RingBuffer SANS auth

**Fichier**: `drivers/tty/src/pty.rs` (entier)

```rust
pub struct RingBuffer {
    buf: [u8; PTY_BUF_SIZE],
    head: usize, tail: usize, len: usize,
}
impl RingBuffer {
    pub fn push(&mut self, byte: u8) -> bool { ... }
    pub fn pop(&mut self) -> Option<u8> { ... }
    pub fn write(&mut self, data: &[u8]) -> usize { ... }
    pub fn read(&mut self, out: &mut [u8]) -> usize { ... }
}
```

**Pourquoi vulnérable**: C'est une structure de données générique sans aucune notion de master/slave, de propriétaire PID, de capability, de contrôle d'accès. N'importe quel process ayant une référence (via shared memory, IPC, ou capacité) peut `push`/`pop` librement. Il n'y a pas de `PtyMaster`/`PtySlave` distincts, pas de `chown` à un UID, pas de `O_NOCTTY`. Le module est **incomplet** pour la sécurité TTY.

**Fix**: Concevoir une `Pty { master: PtyMaster, slave: PtySlave }` où chaque moitié est un handle capability-checked. L'ouverture du slave requiert une cap token `CAP_PTY_OPEN` ou l'appartenance à la session du master.

---

### DRV-023 — HIGH — tty/main.rs est un stub spinloop

**Fichier**: `drivers/tty/src/main.rs:7-13`

```rust
#[cfg(target_os = "none")]
#[no_mangle]
pub extern "C" fn _start() -> ! {
    loop {
        core::hint::spin_loop();
    }
}
```

**Pourquoi vulnérable**: Le "driver TTY" ne fait rien. Pas d'enregistrement IPC, pas de dispatch, pas de gestion des consoles. Cela signifie que toute la sécurité TTY (isolation console, contrôle d'accès pty) est **absente** du système — elle doit être implémentée dans `servers/tty_server/` (hors périmètre de cet audit, mais le module `drivers/tty` est vide). Le code utile est uniquement les bibliothèques `console.rs`, `line_disc.rs`, `pty.rs`, `vt100.rs` qui sont des primitives.

**Fix**: Soit supprimer ce main.rs (le module n'est qu'une bibli), soit implémenter le driver réel.

---

### DRV-024 — HIGH — tty/vt100.rs ne contient que des générateurs

**Fichier**: `drivers/tty/src/vt100.rs` (entier)

```rust
pub const CLEAR_SCREEN: &[u8] = b"\x1b[2J";
pub const CURSOR_HOME: &[u8] = b"\x1b[H";
...
pub fn cursor_position(row: u16, col: u16, out: &mut [u8; 16]) -> &[u8] { ... }
```

**Pourquoi vulnérable**: Le module **génère** des escape sequences mais ne **parse** pas les escape sequences entrantes. Cela signifie que si un process (ou un ttyslave connecté à un programme affichant du contenu réseau non trusted) envoie des escape sequences malicieuses (`\x1b]2;evil\x07` pour setter le titre, `\x1b[6n` pour demander la position curseur qui revient comme input, `\x1b[3;5;...` avec paramètres énormes), il n'y a **aucune sanitization**. Les terminaux modernes (xterm, kitty) ont des dizaines de CVE sur ce sujet.

**Fix**: Implémenter un parser VT100/vt500 strict qui (a) rejette les séquences inconnues, (b) borne les paramètres numériques (max 32767), (c) ignore les DCS/OSC non supportés, (d) ne ré-émet jamais vers le master des réponses automatiques (DSR, CPR) sans sanitize.

---

### DRV-025 — MEDIUM — line_disc.rs pas de protection TIOCSTI-like

**Fichier**: `drivers/tty/src/line_disc.rs:61-107`

```rust
pub fn input_byte(&mut self, byte: u8) -> Option<LineEvent> {
    match byte {
        3 => { ... Signal::Interrupt }
        4 => { ... }
        b'\r' | b'\n' if self.canonical => { ... }
        0x08 | 0x7f if self.canonical => { ... }
        0x0c if self.canonical => Some(LineEvent::ClearScreen),
        byte => {
            if self.len < LINE_MAX {
                self.buf[self.len] = byte;
                self.len += 1;
                ...
            }
        }
    }
}
```

**Pourquoi vulnérable**: Pas de notion de " мастера du terminal" vs "process foreground". N'importe qui peut injecter des bytes dans le line discipline. Sous Linux, `TIOCSTI` permet d'injecter des chars dans le TTY d'un autre process ; ce module n'a aucune défense car il n'a pas de notion d'auteur. Aussi, pas de support UTF-8 multibyte → un byte isolé > 0x7F est stocké tel quel dans `buf[1024]` puis interprété comme char plus tard.

**Fix**: Ajouter un `owner_pid` au LineDiscipline ; n'accepter les input bytes que depuis l'owner. Pour UTF-8, decoder par codepoint.

---

### DRV-026 — MEDIUM — PS/2 driver pousse vers endpoint non authentifié

**Fichier**: `drivers/input/ps2/src/main.rs:204-222`

```rust
fn push_input_event(event: InputEvent) {
    let req = syscall::InputRequest {
        sender_pid: 0,             // ← pas rempli avec le PID réel
        msg_type: syscall::INPUT_MSG_PUSH,
        ...
    };
    let _ = unsafe {
        syscall::syscall6(
            syscall::SYS_IPC_SEND,
            syscall::INPUT_SERVER_ENDPOINT,    // ← endpoint hardcodé
            ...
        )
    };
}
```

**Pourquoi vulnérable**: (1) `sender_pid: 0` — le driver ne s'identifie pas, l'input_server ne peut pas vérifier que l'expéditeur est bien le ps2_driver. (2) `INPUT_SERVER_ENDPOINT` est une constante — si un autre process enregistre cet endpoint (cf. D-01 architecture : `network_server SOCK_RAW sans CAP_NET_RAW`), il reçoit toutes les frappes. (3) Le `_ =` ignore l'erreur d'envoi → si l'input_server est down, les events sont silencieusement droppés (acceptable mais non loggué).

**Fix**: (1) Remplir `sender_pid` via `SYS_GETPID`. (2) L'input_server doit exiger une capability `CAP_INPUT_SOURCE` pour accepter les `INPUT_MSG_PUSH`. (3) Loguer les échecs d'envoi.

---

### DRV-027 — LOW — i8042 `drain_output` non borné

**Fichier**: `drivers/input/ps2/src/i8042.rs:109-113`

```rust
fn drain_output(&mut self) {
    while self.io.read_u8(STATUS_PORT) & STATUS_OUTPUT_FULL != 0 {
        let _ = self.io.read_u8(DATA_PORT);
    }
}
```

**Pourquoi vulnérable**: Boucle `while` sans compteur. Un device malveillant qui maintient `OUTPUT_FULL` à 1 indéfiniment bloque le driver (DoS). `spin_limit` n'est pas utilisé ici.

**Fix**: Ajouter un compteur `for _ in 0..self.spin_limit { ... }`.

---

### DRV-028 — LOW — PS/2 mouse spoofing trivial

**Fichier**: `drivers/input/ps2/src/mouse.rs:23-48`

```rust
pub fn feed(&mut self, byte: u8, out: &mut [Option<InputEvent>; 5]) -> usize {
    if self.len == 0 && byte & 0x08 == 0 { return 0; }
    self.packet[self.len] = byte;
    self.len += 1;
    if self.len < 3 { return 0; }
    self.len = 0;
    let buttons = self.packet[0];
    let dx = sign_extend(self.packet[1], buttons & 0x10 != 0);
    let dy = -sign_extend(self.packet[2], buttons & 0x20 != 0);
    ...
}
```

**Pourquoi vulnérable**: Le seul check de synchro est `byte & 0x08` (bit 3 du premier byte, toujours à 1 en mode standard). Un device malveillant peut forger des packets à volonté (spoofing mouvements/clics). C'est inhérent au PS/2 — aucune authentification côté protocole. La défense doit être au niveau kernel : restreindre qui peut émettre des `INPUT_MSG_PUSH` (cf. DRV-026).

**Fix**: Documenter que la sécurité PS/2 repose entièrement sur l'isolation du port I/O 0x60/0x64 (le kernel ne doit exposer ces ports qu'au ps2_driver). Vérifier que `SYS_IOPORT_READ/WRITE` est restreint par capability.

---

### DRV-029 — MEDIUM — VGA `write_byte` presume cells.len() >= VGA_CELLS

**Fichier**: `drivers/display/vga/src/lib.rs:64-81`

```rust
pub fn write_byte(&mut self, byte: u8) {
    match byte {
        ...
        byte => {
            if self.col >= VGA_COLS { self.newline(); }
            let idx = self.row * VGA_COLS + self.col;
            self.cells[idx] = VgaCell { ... };   // ← idx peut dépasser si cells < VGA_CELLS
            self.col += 1;
        }
    }
}
```

**Pourquoi vulnérable**: `VgaTextBuffer::new` assert `cells.len() >= VGA_CELLS` à la construction, mais `write_byte` ne re-vérifie pas. Si l'appelant rétrécit `cells` après construction (rare mais possible via `split_at_mut` ou `Vec::truncate`), OOB. Aussi : si `self.row` ou `self.col` sont manipulés (via un bug externe), `idx` peut dépasser.

**Fix**: Vérifier `idx < self.cells.len()` avant l'écriture, ou borner `row < VGA_ROWS && col < VGA_COLS` au début de `write_byte`.

---

### DRV-030 — LOW — ipv4.rs accepte les packets avec `total_len < packet.len()`

**Fichier**: `drivers/network/common/src/ipv4.rs:24-27`

```rust
let total_len = u16::from_be_bytes([packet[2], packet[3]]);
if total_len as usize > packet.len() || (total_len as usize) < ihl {
    return None;
}
```

**Pourquoi vulnérable**: Un packet Ethernet de 60 octets contenant un IP `total_len = 20` (header seul) est accepté. L'appelant qui fait `packet[ihl..total_len]` obtient 0 octet de payload, mais si l'appelant utilise `packet[ihl..]` (ignorant `total_len`), il lit 40 octets de padding Ethernet comme payload. Pas de crash mais interprétation erronée.

**Fix**: Tronquer le packet à `total_len` avant de retourner ( retourner un sous-slice).

---

### DRV-031 — LOW — DmaBuffer passive, pas d'allocation

**Fichier**: `drivers/network/common/src/dma_buf.rs:1-27`

La structure est correcte (`contains_offset` utilise `checked_add`), mais c'est uniquement une structure de données — pas d'allocation, pas d'IOMMU. Le commentaire documente que l'allocation réelle est faite via `SYS_DMA_ALLOC` ailleurs. Aucune vulnérabilité ici en soi.

---

### DRV-032 — MEDIUM — partition/gpt.rs accepte tout header_size entre 92 et 512

**Fichier**: `drivers/storage/partition/src/gpt.rs:60-63`

```rust
let header_size = rd_u32(block, 12) as usize;
if header_size < GPT_HEADER_MIN_SIZE || header_size > block.len() {
    return Err(GptError::BadHeaderSize);
}
```

**Pourquoi vulnérable**: La spec GPT rev 1.0 fixe `header_size = 92`. Accepter jusqu'à `block.len()` (512 ou 4096) est permissif. Un attaquant peut annoncer `header_size = 4096` et le CRC est calculé sur 4096 octets, incluant potentiellement des données arbitraires au-delà du header spec. Pas de crash mais interpretation non spec.

**Fix**: Borner `header_size == 92` pour rev 1.0, ou accepter `[92, 512]` max et zero-pad pour le CRC.

---

### DRV-033 — MEDIUM — partition/lib.rs `read_gpt_entries` allocation non bornée sur `entry_size`

**Fichier**: `drivers/storage/partition/src/lib.rs:154-162`

```rust
let entry_size = h.sizeof_partition_entry as usize;
if entry_size < 128 { return Err(PartError::Gpt(GptError::BufferTooSmall)); }
let total = (h.num_partition_entries as usize)
    .checked_mul(entry_size)
    .ok_or(PartError::TooManyEntries)?;
let blocks = total.div_ceil(bs);
let mut table = vec![0u8; blocks * bs];
```

**Pourquoi vulnérable**: `num_partition_entries ≤ 256` (MAX_GPT_ENTRIES), mais `entry_size` n'a pas de borne supérieure. Si `entry_size = 0xFFFFFFFF` (corrompu), `total = 256 * 0xFFFFFFFF` overflow → `checked_mul` retourne None → `TooManyEntries` (OK). Mais si `entry_size = 0x10000000` (268 MiB), `total = 256 * 268M = 64 GiB` → `vec!` tente d'allouer 64 GiB → OOM. Borné par le wrap-around `checked_mul` mais pas par une limite pratique.

**Fix**: Borner `entry_size <= 4096` (ou 16384 max spec).

---

### DRV-034 — HIGH — NVMe `submit_and_poll` perd la CQ en cas de cid mismatch

**Fichier**: `drivers/storage/nvme/src/lib.rs:410-445`

```rust
if cq_ring.entry_is_new(c.phase) {
    let new_head = cq_ring.advance();
    hal.mmio_write32(... cq_head_doorbell ..., new_head as u32);
    if c.cid != expected_cid {
        return Err(0xFFFF);   // ← on a avancé le head, mais on retourne Err
    }
    ...
}
```

**Pourquoi vulnérable**: En cas de `c.cid != expected_cid` (complétion d'une autre commande), le driver a déjà avancé le CQ head et sonné le doorbell — donc cette complétion est "consommée" — mais retourne `Err(0xFFFF)`. L'appelant n'a aucun moyen de récupérer la complétion perdue. En I/O synchrone, cela ne devrait pas arriver, mais si le contrôleur envoie une AER (asynchronous event) sur la admin CQ, le driver se désynchronise et peut丢失 les prochaines complétions légitimes.

**Fix**: Au lieu de `return Err(0xFFFF)`, loguer et continuer à poller jusqu'à obtenir la complétion attendue (en bornant le nombre de polls).

---

### DRV-035 — LOW — NVMe `alloc_cid` wrap-around

**Fichier**: `drivers/storage/nvme/src/lib.rs:181-189`

```rust
fn alloc_cid(&mut self) -> u16 {
    let cid = self.next_cid;
    self.next_cid = self.next_cid.wrapping_add(1);
    if self.next_cid == 0 { self.next_cid = 1; }
    cid
}
```

**Pourquoi vulnérable**: Après 65535 commandes, `next_cid` revient à 1. Si une commande CID=N est encore en vol (théoriquement impossible en synchrone mais possible en cas de timeout non géré), la prochaine commande réutilise CID=N → collision. Le contrôleur peut confondre les deux complétions.

**Fix**: Maintenir un compteur monotonic u32 et n'allouer qu'aux CIDs libres (bitmap). Ou en synchrone strict, c'est OK — documenter.

---

### DRV-036 — HIGH — virtio_blk/hal.rs BOUNCE_TABLE limité à 128

**Fichier**: `drivers/storage/virtio_blk/src/hal.rs:32-66`

```rust
const MAX_BOUNCE_RECORDS: usize = 128;
static BOUNCE_TABLE: Mutex<[Option<BounceRecord>; MAX_BOUNCE_RECORDS]> = ...;
...
fn insert_bounce(record: BounceRecord) -> bool {
    let mut table = BOUNCE_TABLE.lock();
    if table.iter().flatten().any(|existing| existing.paddr == record.paddr) {
        return false;
    }
    let Some(slot) = table.iter_mut().find(|slot| slot.is_none()) else {
        return false;     // ← 129e échoue silencieusement
    };
    *slot = Some(record);
    true
}
...
unsafe fn share(...) -> PhysAddr {
    ...
    if !insert_bounce(record) {
        let _ = unsafe { (ops.dma_dealloc)(paddr, vaddr, pages) };
        return 0;     // ← paddr=0 retourné
    }
    paddr
}
```

**Pourquoi vulnérable**: Si 128 buffers DMA sont partagés simultanément, le 129e `share` échoue silencieusement et retourne `paddr = 0`. Le caller (virtio_drivers) peut interpréter `paddr = 0` comme un pointeur DMA valide vers l'adresse physique 0 — selon l'architecture, cela peut être la RAM basse (IVT, BIOS data) ou une région MMIO. Un device écrivant à l'adresse 0 peut corrompre le boot sector ou les structures UEFI runtime.

**Fix**: (1) Augmenter `MAX_BOUNCE_RECORDS` (par ex. 4096). (2) En cas d'échec, panic ou retour Err explicite (pas 0). (3) Vérifier dans `share` que `paddr != 0` après `dma_alloc`.

---

### DRV-037 — CRITICAL — fscrypt `unwrap_volume_key` ne vérifie pas `VK_SOURCE`

**Fichier**: `drivers/storage/fscrypt/src/lib.rs:257-278`

```rust
pub fn unwrap_volume_key(wrapped: &[u8], passphrase: &[u8]) -> Result<[u8; 32], FsCryptError> {
    if wrapped.len() < WRAPPED_VK_LEN
        || wrapped[0..4] != VK_WRAP_MAGIC
        || wrapped[4] != VK_WRAP_VERSION
    {
        return Err(FsCryptError::BadFormat);
    }
    // ← pas de check wrapped[5] == VK_SOURCE_PASSPHRASE
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&wrapped[6..38]);
    ...
    let kek = derive_kek(passphrase, &salt)?;
    if !aead_open(&kek, &nonce, VK_WRAP_AAD, &mut ct, &tag) {
        return Err(FsCryptError::AuthFailed);
    }
    Ok(ct)
}
```

**Pourquoi vulnérable**: `wrapped[5]` est le champ `source` (0 = passphrase, futur = TPM/file). `unwrap_volume_key` ne valide pas que `source == VK_SOURCE_PASSPHRASE`. Si une future version ajoute `VK_SOURCE_TPM = 1` avec un format de wrap différent (par ex. pas de salt, clé publique RSA-OAEP), `unwrap_volume_key` dériverait quand même une KEK via Argon2id sur le salt stocké et tenterait `aead_open` — qui échouerait (AuthFailed), donc pas de fuite immédiate. Mais cela crée une confusion : un wrap TPM mal interprété comme passphrase echoue silencieusement, masquant une attaque qui swapperait un wrap passphrase contre un wrap TPM (ou inversement).

**Fix**: Ajouter `if wrapped[5] != VK_SOURCE_PASSPHRASE { return Err(FsCryptError::BadFormat); }`.

---

### DRV-038 — HIGH — virtio_net `submit_rx_slot` ne vérifie pas `pool_idx < pool_count`

**Fichier**: `drivers/network/virtio_net/src/main.rs:327-340`

```rust
fn submit_rx_slot(&mut self, pool_idx: u16) -> Result<(), i64> {
    if !self.pool_ready && !self.online { return Err(syscall::ENODEV); }
    let addr = self.rx_base_iova + (pool_idx as usize * PAGE_SIZE) as u64;
    // ← pas de check pool_idx < pool_count
    let bufs = [(addr, PAGE_SIZE as u32, VIRTQ_DESC_F_WRITE)];
    let head = unsafe {
        self.rx_queue.add_chain(&bufs).map_err(|_| syscall::ENOBUFS)?
    };
    self.rx_pool_for_head[head as usize] = pool_idx;
    Ok(())
}
```

**Pourquoi vulnérable**: `pool_idx` vient soit de `apply_driver_init` (boucle `0..pool_count`, OK) soit de `process_rx_releases` qui filtre `(pool_idx as usize) < self.pool_count` (OK), mais aussi de `pop_rx_ready` via `state.handle_rx_used` qui ne re-filtre pas. Si le network_server envoie un `RxReleaseMsg` avec `pool_idx ≥ pool_count`, le filtre de `process_rx_releases` le bloque. Mais si `process_rx_releases` est appelé avec un `msg` forgé (cf. DRV-039), le filtre est contournable via `state.process_rx_releases(msg)` qui lui aussi filtre — donc OK. Mais le `submit_rx_slot` lui-même n'a pas de défense en profondeur : si un bug futur permet d'appeler avec un grand `pool_idx`, `addr` déborde hors de la région DMA allouée par le network_server, et le device écrit hors région.

**Fix**: Ajouter `if (pool_idx as usize) >= self.pool_count { return Err(syscall::EINVAL); }` au début de `submit_rx_slot`. Même chose pour `submit_tx`.

---

### DRV-039 — HIGH — virtio_net n'authentifie pas les messages IPC entrants

**Fichier**: `drivers/network/virtio_net/src/main.rs:491-528`

```rust
loop {
    let rc = recv(&mut request);
    unsafe {
        if rc > 0 {
            match request.msg_type {
                net::NET_CTRL_DRIVER_INIT => { ... VIRTIO_HW.apply_driver_init(...) }
                net::NET_CTRL_RX_RELEASE => { ... VIRTIO_HW.process_rx_releases(...) }
                net::NET_CTRL_MAC_QUERY => VIRTIO_HW.send_mac_reply(),
                NET_CTRL_TX_SUBMIT => {
                    ...
                    let _ = VIRTIO_NET.queue_tx_from_network(msg.pool_idx, msg.len);
                    while let Some(tx) = VIRTIO_NET.pop_tx_pending() {
                        if VIRTIO_HW.submit_tx(tx.pool_idx, tx.len).is_err() { ... }
                    }
                }
                _ => {}
            }
        }
        VIRTIO_HW.poll(&mut VIRTIO_NET);
    }
}
```

**Pourquoi vulnérable**: `recv` ne vérifie pas `request.sender_pid` — n'importe quel process peut envoyer un `NET_CTRL_TX_SUBMIT` à l'endpoint 14 et faire émettre un paquet. C'est la même classe de bug que D-01 (`network_server SOCK_RAW sans CAP_NET_RAW`). Aussi `NET_CTRL_DRIVER_INIT` peut être envoyé par n'importe qui → re-init et potentiellement DoS ou changement d'IOVA.

**Fix**: Le driver doit vérifier `request.sender_pid == NETWORK_SERVER_PID` (résolu via name service signé) ou utiliser une capability token `CAP_NET_DRIVER_CTRL`.

---

### DRV-040 — MEDIUM — e1000 `tx_iova(idx)` non vérifié contre `pool_count`

**Fichier**: `drivers/network/e1000/src/main.rs:313-340`

```rust
fn process_tx_submit(&mut self, msg: TxSubmitMsg) {
    ...
    let idx = msg.pool_idx as usize;
    if !self.online || !self.pool_ready || idx >= TX_RING_SIZE || msg.len == 0 {
        send_single_tx_complete(msg.pool_idx);
        return;
    }
    let addr = self.tx_iova(idx).saturating_add(self.hdr_size as u64);
    // ← idx < TX_RING_SIZE (256) mais pas < pool_count
    unsafe {
        if let Some(desc_idx) = self.tx.prepare(addr, msg.len) { ... }
    }
}
```

**Pourquoi vulnérable**: `idx` est borné à `TX_RING_SIZE = 256` mais pas à `self.pool_count` (qui peut être plus petit, par ex. 64). Si `pool_count = 64` et `idx = 200`, `tx_iova(200) = tx_base_iova + 200*4096` pointe hors de la région DMA allouée par le network_server. Le device E1000 va lire 4096 octets depuis cette adresse — qui peut être une autre région DMA d'un autre device, ou pire, une adresse physique non RAM (MMIO d'un autre device → info leak ou crash).

**Fix**: Remplacer `idx >= TX_RING_SIZE` par `idx >= self.pool_count` (et conserver `idx < TX_RING_SIZE` comme second check).

---

### DRV-041 — MEDIUM — virtio_net `recycle_desc` suit `next` écrit par le device

**Fichier**: `drivers/network/virtio_net/src/virtqueue.rs:210-238`

```rust
pub unsafe fn recycle_desc(&mut self, head: u16) {
    if self.desc.is_null() || head >= self.queue_size { return; }
    let mut idx = head;
    loop {
        let desc = unsafe { self.desc.add(idx as usize) };
        let snapshot = unsafe { core::ptr::read_volatile(desc) };
        let flags = snapshot.flags;
        let next = snapshot.next;            // ← lu depuis le desc device-controlled
        ...
        if flags & VIRTQ_DESC_F_NEXT == 0 || next >= self.queue_size { break; }
        idx = next;
    }
}
```

**Pourquoi vulnérable**: `snapshot.next` est lu depuis la mémoire DMA partagée avec le device. Un device malveillant peut modifier `next` après que le driver a soumis la chaîne, pour pointer vers un descriptor actuellement en cours d'usage pour une autre commande. Le driver libère alors ce descriptor dans la free list, et la prochaine `add_chain` le réutilise → double-use du même descriptor par deux commandes concurrentes → corruption de données / réordonnancement.

**Fix**: Maintenir une copie driver-side du chaînage `next` à la soumission (dans `add_chain`, stocker `next` dans une array driver-only), et utiliser cette copie dans `recycle_desc`. Ne jamais faire confiance au `next` device-side.

---

### DRV-042 — MEDIUM — e1000 `poll_one` ne clamp pas `len`

Voir DRV-005 (même issue). Le `len = desc.length` est forwardé sans clamp à `(PAGE_SIZE - hdr_size)`.

---

### DRV-043 — LOW — tty/console.rs pas de borne de sortie

**Fichier**: `drivers/tty/src/console.rs:11-18`

```rust
pub fn write_crlf_normalized<S: ConsoleSink>(sink: &mut S, data: &[u8]) {
    for &byte in data {
        if byte == b'\n' { sink.write_byte(b'\r'); }
        sink.write_byte(byte);
    }
}
```

**Pourquoi vulnérable**: Si `data` est très grand (par ex. 1 GiB), la fonction boucle sans yield/coop. Pas critique (pas de bounds issue), mais peut bloquer un driver TTY en boucle.

**Fix**: Ajouter un paramètre `max_bytes` ou un callback `should_yield()`.

---

### DRV-044 — LOW — keyboard.rs `hid_to_ascii` ctrl+lettre soustrait `b'a'`

**Fichier**: `drivers/input/ps2/src/keyboard.rs:430-434`

```rust
if ctrl && c.is_ascii_alphabetic() {
    (c.to_ascii_lowercase() - b'a') + 1
} else {
    c
}
```

**Pourquoi vulnérable**: Pour les lettres `a..=z` (`is_ascii_alphabetic()` true), `c.to_ascii_lowercase() - b'a' + 1` est dans `[1..=26]`, OK. Mais pour les lettres accentuées multi-bytes UTF-8, `is_ascii_alphabetic()` retourne false, donc on tombe dans le `else` et retourne `c` tel quel — pas de soustraction. En pratique, le match au-dessus ne produit que des ASCII, donc OK. Mais si une future extension ajoute des codepoints > 0x7F, le `is_ascii_alphabetic()` filterait correctement. Pas de bug actuel.

**Fix**: Aucun (informatif).

---

## 5. Verdict

### Drivers Network

**Status: CRITICAL — ne pas déployer en production**

- **DRV-001, DRV-002, DRV-003**: bypass IOMMU explicite — un device malveillant (PCIe hotplug, firmware compromis) peut lire/écrire toute la RAM via DMA. C'est la vulnérabilité la plus grave de l'audit.
- **DRV-004, DRV-005, DRV-038, DRV-040, DRV-041, DRV-042**: manque de bornes sur les valeurs device-controlled (head, len, pool_idx, next) → OOB ou double-use.
- **DRV-039**: pas d'authentification IPC → n'importe quel process peut injecter des paquets TX ou re-init le driver.
- **Correct**: ipv4.rs, ether.rs ont des bounds checks corrects. loopback est trivial et OK.

### Drivers Storage

**Status: MIXTE**

- **fscrypt (DRV-006 à DRV-011, DRV-037)**: CRITICAL. AEAD non conforme au mandate (BLAKE3-MAC au lieu de Poly1305), pas de zeroization, pas de filename encryption, pas de rollback protection, pas de check `VK_SOURCE`. La crypto elle-même (XChaCha20, Argon2id m=64MiB t=3 p=4 ✓ conforme au mandate) est correcte, mais la couverture de sécurité est incomplète. **Ne pas utiliser pour des données sensibles avant fixes.**
- **verity (DRV-012)**: CRITICAL MISMATCH. Le module n'est pas dm-verity — c'est un vérifieur de signature d'image kernel. Aucune protection runtime par bloc. Le nom est trompeur.
- **ahci, virtio_blk, nvme**: OK avec mineurs. HAL bornée, PRDT/PRP rejets explicites, waits bornés. **DRV-036** (virtio_blk bounce table) et **DRV-034** (nvme cid mismatch) à corriger.
- **partition**: OK avec mineurs. CRC validés, fallback backup GPT, MAX_GPT_ENTRIES. **DRV-033** (entry_size non borné) à corriger.

### Filesystems

**Status: VULNÉRABLE pour des disques non trusted**

- **fat32 (DRV-013 à DRV-016)**: pas de sanitization des noms (path traversal), pas de validation cluster, pas de cross-check FAT1/FAT2. Acceptable pour un usage "clé USB de confiance" mais pas pour un disque arbitraire.
- **ext4 (DRV-017 à DRV-021)**: extent tree incomplet (depth > 0 non géré), journal sans CRC32c, xattr non bornés, block_size non borné. **DRV-017** est le plus grave : un fichier de >4 GiB est silencieusement tronqué.

### TTY

**Status: STUB INCOMPLET**

- **DRV-022, DRV-023, DRV-024**: le driver TTY n'existe pas réellement (main.rs = spinloop). Les modules `pty.rs`, `vt100.rs`, `console.rs`, `line_disc.rs` sont des primitives sans authentification. vt100.rs ne parse pas les escape sequences entrantes. **La sécurité TTY doit être implémentée dans `servers/tty_server/` (hors périmètre).**

### Input PS/2

**Status: OK avec mineurs**

- **DRV-026**: le driver ne s'authentifie pas auprès de l'input_server (sender_pid = 0).
- **DRV-027, DRV-028**: DoS drain_output non borné ; spoofing inhérent au PS/2.
- **Correct**: spin_limit appliqué ailleurs, scancode set1/set2 gérés.

### Display VGA

**Status: OK avec garde**

- **DRV-029**: bounds check à l'init seulement. Pas de re-vérification dans `write_byte`. Si cells est rétréci post-construction, OOB.

---

## 6. Actions prioritaires

### P0 (bloquant production)

1. **DRV-001/002/003**: Retirer `DMA_MAP_FLAGS_BYPASS_IOMMU` des drivers virtio_net et e1000. Côté kernel, filtrer ce flag pour les process non privilégiés.
2. **DRV-006/007/008/009**: Refonte fscrypt — AEAD Poly1305, zeroization systématique, filename encryption, rollback protection (compteur version + Merkle tree metadata).
3. **DRV-012**: Soit renommer `verity` en `kernel_signature`, soit implémenter un vrai dm-verity (Merkle BLAKE3 ancré TPM/kernel-ro).
4. **DRV-017**: Compléter l'extent tree ext4 (descente récursive depth > 0).
5. **DRV-004/005/038/040/041/042**: Ajouter les bornes manquantes sur les valeurs device-controlled.

### P1 (important)

6. **DRV-013**: Sanitization des noms FAT32 (`/`, `\`, NUL, `..`).
7. **DRV-020**: CRC32c JBD2 superblock validation.
8. **DRV-022/023/024**: Implémenter le driver TTY réel avec authentification pty master/slave + parser VT100 strict.
9. **DRV-026**: Authentifier le ps2_driver auprès de l'input_server.
10. **DRV-039**: Authentifier les messages IPC entrants dans virtio_net.
11. **DRV-037**: Vérifier `VK_SOURCE` dans `unwrap_volume_key`.

### P2 (mineur)

12. **DRV-010/011/015/016/018/019/021/027/028/029/030/032/033/034/035/036/043/044**: Voir détails ci-dessus.

---

## 7. Conclusion

L'audit révèle **44 findings** dont **7 CRITICAL**, **18 HIGH**, **13 MEDIUM**, **6 LOW**.

Les trois problèmes systémiques sont :
1. **IOMMU bypassé** par les drivers réseau (DRV-001/002/003) — annule toute la protection ExoShield-IOMMU.
2. **fscrypt incomplet** (DRV-006/007/008/009/037) — la crypto est correcte mais la couverture de sécurité ne répond pas au mandate (filename, rollback, zeroization, Poly1305).
3. **verity mal nommé** (DRV-012) — pas de protection runtime par bloc.

Les drivers AHCI/NVMe/partition sont de bonne qualité (HAL isolée, structures pures testables, waits bornés). Les FS FAT32/ext4 sont acceptables pour des disques trusted mais pas pour des disques arbitraires. Le driver TTY est un stub. Le driver PS/2 est correct.

**Recommandation**: P0 bloquant avant tout déploiement. P1 important pour la robustesse. P2 polish.
