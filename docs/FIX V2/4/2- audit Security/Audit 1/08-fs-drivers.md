# AUDIT-8 — FS / VFS / Drivers — Rapport d'audit profond

**Task ID:** AUDIT-8-FS-DRIVERS
**Auditeur:** kernel senior FS / VFS / drivers
**Périmètre:** `kernel/src/fs/` (308 fichiers, 155k LOC) + `drivers/{storage,network,input,tty,display,audio,fs,security}` + `servers/{vfs_server,network_server,device_server}`
**Méthode:** Audit stratégique — fichiers critiques lus in extenso (syscalls ExoFS 500-520, validation, posix_bridge, mmap, path, symlink, superblock, partition, epoch_commit, captable, e1000, virtio_net, virtio_blk, ahci, nvme, partition, fscrypt, verity, ext4, fat32, tty, ps2, vfs_server, device_server, network_server, dispatch), fichiers bulk (cache, dedup, compress, gc, export, recovery fsck_*) échantillonnés.

---

## 1. Synthèse exécutive

Le module FS d'ExoOS est **massif et architecturalement mature** sur les couches bas niveau (epoch journaling à 3 barrières NVMe, superblock à miroirs avec CRC Blake3, parseur GPT/MBR partagé bootloader/kernel, fscrypt XChaCha20+BLAKE3, verity Ed25519 fail-closed). **En revanche, la couche de sécurité POSIX (permissions, capabilities, ownership) est massivement absente ou explicitement désactivée**, avec des commentaires `FIX-SEC-T0.3/T0.4 : TIER 1 hardening pending` qui avouent l'état permissif.

**Top 5 vulnérabilités:**
1. **CRITICAL** — Capability checks désactivés à l'open (`let _ = cap_rights;`) → tout process peut ouvrir/créer/tronquer n'importe quel fichier
2. **CRITICAL** — VFS layer sans checks de permission Unix (vfs_unlink/vfs_rename/vfs_mkdir/vfs_create ne vérifient ni UID ni mode bits)
3. **CRITICAL** — `owner_matches` true si `caller==0 || entry.owner==0` → bypass d'ownership par défaut (OpenArgs.owner_uid=0) et confusion PID/UID
4. **CRITICAL** — mmap global sans check PID → un process peut `munmap`/`mprotect`/`msync` les mappings d'un autre process
5. **CRITICAL** — IOMMU bypass explicite dans e1000 et virtio_net (`DMA_MAP_FLAGS_BYPASS_IOMMU`) → DMA device peut lire/écrire toute la mémoire kernel

**Score maturité FS/drivers: 4/10** — Socle bas niveau excellent, mais le modèle de sécurité POSIX est non fonctionnel. À ce stade, ExoFS est un FS « single-user » : un process compromis (Ring 3) peut lire, modifier, détruire tous les fichiers et mappings de tous les autres process.

---

## 2. Périmètre couvert

| Module | Fichiers | LOC | Couverture |
|---|---|---|---|
| `kernel/src/fs/exofs/syscall/` | 25 | ~15k | **Totale** (tous les handlers 500-520 lus) |
| `kernel/src/fs/exofs/posix_bridge/` | 5 | ~4k | **Totale** (vfs_compat, mmap, fcntl_lock, inode_emulation) |
| `kernel/src/fs/exofs/path/` | 13 | ~5.6k | Résolver + symlink + canonicalize lus en détail |
| `kernel/src/fs/exofs/epoch/` | 16 | ~5k | epoch_commit + epoch_barriers lus en détail |
| `kernel/src/fs/exofs/storage/` | 22 | ~14k | superblock, partition_scan, virtio_adapter lus en détail |
| `kernel/src/fs/exofs/crypto/` | 14 | ~6k | at_rest, key_storage échantillonnés (cf. audit crypto séparé) |
| `kernel/src/fs/exofs/{cache,dedup,compress,gc,recovery,export,relation,snapshot,quota,objects,io,audit,observability,numa,core}/` | ~210 | ~100k | Échantillonnage stratégique (headers, signatures, entry points) |
| `kernel/src/syscall/{fs_bridge,fs_posix,validation,dispatch}.rs` | 4 | ~7.3k | **Totale** |
| `drivers/storage/{ahci,nvme,virtio_blk,partition,fscrypt}/` | 5 crates | ~3.5k | **Totale** |
| `drivers/network/{e1000,virtio_net,loopback,common}/` | 4 crates | ~2.3k | **Totale** |
| `drivers/input/ps2/`, `drivers/tty/`, `drivers/display/vga/` | 3 crates | ~2k | **Totale** |
| `drivers/fs/{ext4,fat32}/` | 1 crate | ~2k | **Totale** (superblock, journal, bpb, dir_entry, cluster) |
| `drivers/security/verity/` | 1 crate | ~334 | **Totale** |
| `drivers/{display/virtio_gpu,audio/hda,audio/virtio_sound,clock,input/evdev,input/usb_hid,manager,framework}/` | — | — | **Vides** (directories sans `.rs`) — surface inexistante |
| `servers/{vfs_server,network_server,device_server}/` | 3 crates | ~7.7k | **Totale** |

---

## 3. Architecture observée

ExoFS est un **FS content-addressed** (BlobId = Blake3(chemin canonique)) avec une couche de compat POSIX par-dessus (`posix_bridge`). Le journaling se fait par **epochs** (3 slots A/B/C, 3 barrières NVMe par commit). Le montage GPT/MBR est partagé bootloader/kernel via la crate `exo-partition`. Le chiffrement at-rest (fscrypt) utilise XChaCha20 + MAC BLAKE3 keyé, KEK Argon2id.

**Hybride Ring0/Ring1** : ExoFS tourne en Ring0 (syscalls 500-520 directs), `vfs_server` (PID 3) sert de namespace VFS en Ring1 via IPC, `device_server` (PID ?) coordonne les claims PCI/IOMMU, `network_server` (PID 7) gère les sockets.

**Drivers** : virtio-blk/AHCI/NVMe tournent en Ring1 avec un HAL injecté par le kernel. e1000 et virtio_net utilisent `SYS_DMA_ALLOC` avec `DMA_MAP_FLAGS_BYPASS_IOMMU`.

---

## 4. Vulnérabilités détaillées

### V-01 [CRITICAL] — Capability checks désactivés à l'open (permission bypass total)

**Catégorie:** ISOLATION / LOGIC
**Fichiers:** `kernel/src/fs/exofs/syscall/open_by_path.rs:128-131`, `path_resolve.rs:280-281`, `object_open.rs:228-231`, `object_create.rs:321-324`

```rust
// open_by_path.rs
// FIX-SEC-T0.3 : open permissif (durci TIER 1) ; la cap RÉELLE est mintée après
// ouverture (le faux verify_cap conditionnel était bypassable avec cap_rights=0).
let _ = cap_rights;
let _ = cap;
```

L'argument `cap_rights` (a6) passé par le dispatcher est **explicitement ignoré** dans tous les syscalls ExoFS d'ouverture/création. Le commentaire admet l'état "permissif" et promet un durcissement "TIER 1" à venir.

**Conséquence:** N'importe quel process Ring3 peut appeler `sys_exofs_open_by_path("/etc/shadow", O_RDWR|O_CREAT|O_TRUNC, 0, ...)` et obtenir un fd. La "capabilité" est mintée **après** ouverture en fonction des flags demandés (`rights_from_open_flags`), ce qui revient à accorder automatiquement les droits demandés — pas à les vérifier.

**Impact:** Confidentialité + intégrité + disponibilité totales du FS compromise depuis n'importe quel process Ring3.

**Correctif:** Implémenter le TIER 1 : à l'open, vérifier que le process appelant détient (dans sa `cap_table`) une cap `RIGHT_READ`/`RIGHT_WRITE` sur l'objet (ou sur le parent pour CREATE), déléguée par init au boot. Refuser sinon. Ne pas mint les droits depuis les flags de l'open.

---

### V-02 [CRITICAL] — VFS layer sans checks de permission Unix

**Catégorie:** ISOLATION / LOGIC
**Fichiers:** `kernel/src/fs/exofs/posix_bridge/vfs_compat.rs:875-1166` (vfs_lookup, vfs_create, vfs_open, vfs_read, vfs_write, vfs_mkdir, vfs_unlink, vfs_rename, vfs_rmdir, vfs_symlink, vfs_readdir)

Aucune de ces fonctions ne vérifie :
- L'UID du caller vs l'UID propriétaire du parent / de l'objet
- Les bits de mode POSIX (S_IWUSR, S_IRGRP, etc.)
- Le sticky bit sur les répertoires
- La capabilité FS_ROOT pour les opérations privilégiées

Exemple typique :
```rust
pub fn vfs_unlink(parent_ino: ObjectIno, name: &[u8]) -> ExofsResult<()> {
    // ... pas de check_uid, pas de check_sticky, pas de check_write_perm(parent) ...
    let removed = DIRECTORY_REGISTRY.remove(parent_ino, name)
        .ok_or(ExofsError::ObjectNotFound)?;
    // ... free blob, invalidate cache, sub quota ...
}
```

`vfs_open` ne vérifie que le flag `READ_ONLY` sur l'inode, pas les mode bits. `vfs_rename` ne vérifie ni la permission d'écriture sur `old_parent`, ni sur `new_parent`.

**Conséquence:** Tout process qui connaît les `ObjectIno` peut détruire n'importe quelle arborescence. Le `mode` stocké dans `VfsInode` est décoratif.

**Correctif:** Ajouter dans chaque fonction VFS mutante :
1. Récupérer le `current_uid` depuis le TCB
2. Vérifier `parent.mode & S_IWUSR` (ou S_IWGRP/S_IWOTH selon uid)
3. Pour unlink/rename dans un répertoire sticky : vérifier que uid == parent.uid || uid == entry.uid || uid == 0
4. Pour open : vérifier `mode & S_IRUSR`/`S_IWUSR` selon flags

---

### V-03 [CRITICAL] — `owner_matches` true si `caller==0 || entry.owner==0` + confusion PID/UID

**Catégorie:** ISOLATION / LOGIC
**Fichiers:** `kernel/src/fs/exofs/syscall/object_fd.rs:31-33`, `kernel/src/fs/exofs/posix_bridge/vfs_compat.rs:362-364`

```rust
#[inline]
fn owner_matches(entry: ObjectFdEntry, owner_pid: u64) -> bool {
    owner_pid == 0 || entry.owner_uid == 0 || entry.owner_uid == owner_pid
}
```

Trois problèmes :

1. **`owner_pid == 0` → accès total** : `current_owner_pid()` retourne 0 dans tout contexte non-process (kthread, IRQ, early boot, test host). Si un syscall est invoqué depuis un de ces contextes, **toutes** les vérifications d'ownership passent. Risque réel si un chemin syscall peut être atteint sans TCB utilisateur courant.

2. **`entry.owner_uid == 0` → accès total** : `OpenArgs::defaults()` met `owner_uid = 0`. Tous les fichiers ouverts sans args explicites ont `owner_uid=0`, donc sont accessibles à n'importe quel caller.

3. **Confusion PID ↔ UID** : `owner_uid` (qui devrait être un user ID POSIX) est comparé à `current_owner_pid()` (qui est un PID). Ces deux espaces de noms sont disjoints. Si PID 1000 ouvre un fichier, `entry.owner_uid = 1000`. Ensuite, n'importe quel process avec PID 1000 (après recyclage du PID) peut y accéder. Le concept même d'UID POSIX n'existe pas dans ce modèle.

En outre, `OpenArgs.owner_uid` est **fourni par userspace** (`copy_struct_from_user`) sans validation contre le TCB réel — un process peut déclarer `owner_uid = 0` et hériter des accès "root".

**Correctif:**
- Utiliser un vrai UID POSIX séparé du PID, lu depuis le PCB du caller (pas depuis les args userspace)
- Refuser `owner_uid == 0` comme "wildcard" — utiliser un flag explicite `is_privileged`
- Refuser tout syscall ExoFS si `current_pid() == 0` (contexte non-process)

---

### V-04 [CRITICAL] — mmap global sans check PID (cross-process memory manipulation)

**Catégorie:** ISOLATION / RACE
**Fichiers:** `kernel/src/fs/exofs/posix_bridge/mmap.rs:309-416`

`MmapTable` est une table **globale** (`static MMAP_TABLE: MmapTable`), chaque entrée a un champ `pid`, mais :

- `munmap(virt_addr, length)` — ne vérifie pas `e.pid == current_pid()`
- `msync(virt_addr, length)` — ne vérifie pas `e.pid == current_pid()`
- `mprotect(virt_addr, prot)` — ne vérifie pas `e.pid == current_pid()`
- `mark_dirty(virt_addr)` — ne vérifie pas `e.pid == current_pid()`

```rust
pub fn munmap(&self, virt_addr: u64, length: u64) -> ExofsResult<()> {
    // ... pas de check PID ...
    while i < entries.len() {
        let e = &mut entries[i];
        if e.state != MappingState::Removed && e.overlaps_range(virt_addr, length) {
            e.state = MappingState::Removed;  // <-- n'importe qui peut détruire
            // ...
}
```

**Conséquence:** Un process A peut appeler `munmap(addr_de_B, len)` pour détruire les mappings d'un process B (DoS), ou pire, `mprotect(addr_de_B, PROT_WRITE)` pour rendre writable une page read-only d'un autre process, ou `mprotect(addr_de_B, PROT_NONE)` pour crasher un process via SIGSEGV.

**Note positive:** `mprotect` refuse `PROT_WRITE | PROT_EXEC` (W^X enforcement, ligne 399-401) — bonne chose mais ne compense pas l'absence de check PID.

**Correctif:** Ajouter `current_pid()` et vérifier `e.pid == current_pid() || current_pid() == 0` dans toutes les fonctions mutantes. Idéalement, partitionner la table par address space (PCB) plutôt que global.

---

### V-05 [CRITICAL] — IOMMU bypass explicite dans e1000 et virtio_net

**Catégorie:** MEMSAFE / DMA
**Fichiers:** `drivers/network/e1000/src/main.rs:25`, `drivers/network/virtio_net/src/virtqueue.rs:11`

```rust
// e1000/src/main.rs
const DMA_MAP_FLAGS_BYPASS_IOMMU: u64 = 1 << 4;
// ...
let iova = unsafe { syscall::syscall5(SYS_DMA_ALLOC, size, DMA_DIR_BIDIR,
    &mut virt, DMA_MAP_FLAGS_BYPASS_IOMMU, 0) };
```

Les drivers réseau Ring1 demandent explicitement au kernel un mapping DMA **sans traduction IOMMU**. Le `iova` retourné est l'adresse physique brute. Le device peut alors DMA depuis/vers n'importe quelle adresse physique, y compris la mémoire kernel.

Le commentaire du driver admet : *"e1000 descriptors need DMA-visible physical addresses until the kernel programs a translated IOMMU context for this Ring1 driver."* — reconnaissant que c'est un état transitoire non sécurisé.

**Conséquence:**
- Un NIC compromis (firmware malveillant, attaque PCIe furtive, bug e1000) peut lire/écrire toute la RAM
- Pas de cloisonnement entre le NIC et le kernel
- Contourne complètement la séparation Ring0/Ring1

**Atténuation actuelle:** Le virtio_blk utilise des "bounce buffers" (HAL `share`/`unshare`) qui copient les données vers une page DMA dédiée — mais `DMA_MAP_FLAGS_BYPASS_IOMMU` est aussi présent dans virtio_net, donc le bounce buffer seul ne protège que contre les accès hors-zone, pas contre un device malveillant qui écrit hors du buffer alloué.

**Correctif:**
1. Ne jamais passer `BYPASS_IOMMU` en production
2. Le kernel doit attacher un domaine IOMMU par device driver et n'autoriser que les IOVAs traduites
3. Refuser `SYS_DMA_ALLOC` avec `BYPASS_IOMMU` sauf pour le bootloader ou un kernel debug flag

---

### V-06 [HIGH] — VFS server `check_vfs_write_access` whitelist trop large

**Catégorie:** ISOLATION / LOGIC
**Fichiers:** `servers/vfs_server/src/main.rs:758-762, 772-789`

```rust
fn check_vfs_write_access(sender_pid: u32) -> bool {
    const WRITE_ALLOWED: &[u32] = &[1, 3];
    WRITE_ALLOWED.contains(&sender_pid) || sender_pid >= 10
}
```

Tout process avec PID ≥ 10 (n'importe quelle app userspace : exosh, coreutils, services divers) peut écrire via VFS_SERVER à n'importe quel fichier. Le check est binaire (write/no-write), sans notion d'ownership, de chemin, ou de capability.

Le commentaire dit *"PIDs > 10 (exosh, apps) peuvent lire et écrire leurs propres fichiers"* — mais il n'y a aucun mécanisme qui restreint aux "propres fichiers".

**Conséquence:** exosh ou n'importe quelle app peut écrire dans `/etc/passwd` via VFS_OPEN + VFS_WRITE.

**Correctif:** Le VFS server devrait :
1. Maintenir une capability table par PID client
2. À l'open, vérifier la cap sur le path résolu (ou sur le parent pour CREATE)
3. Refuser VFS_MOUNT/VFS_UMOUNT sauf PID 1

---

### V-07 [HIGH] — chmod / chown / rename / link / fsync retournent ENOSYS

**Catégorie:** LOGIC
**Fichiers:** `kernel/src/syscall/handlers/fs_posix.rs:132-357`

```rust
pub fn sys_chmod(path_ptr: u64, mode: u64, ...) -> i64 {
    let path = match read_user_path(path_ptr) { ... };
    let _ = (path, mode);
    ENOSYS
}
pub fn sys_chown(...) -> i64 { ... ENOSYS }
pub fn sys_rename(...) -> i64 { ... ENOSYS }
pub fn sys_link(...) -> i64 { ... ENOSYS }
pub fn sys_fsync(...) -> i64 { ... ENOSYS }
pub fn sys_fdatasync(...) -> i64 { ... ENOSYS }
pub fn sys_access(...) -> i64 { ... ENOSYS }
pub fn sys_chdir(...) -> i64 { ... ENOSYS }
```

Les syscalls POSIX critiques pour la sécurité sont **non implémentés** :
- `chmod`/`chown` : impossible de durcir les permissions après création → le mode est write-once
- `rename` : impossible de déplacer atomiquement (atomicité de mise à jour de fichiers critiques)
- `link` : pas de hardlinks (mais symlink fonctionne)
- `fsync`/`fdatasync` : pas de flush explicite (le writeback epoch sauve le meuble, mais les apps ne peuvent pas forcer)
- `access` : pas de check de permission préalable
- `chdir` : pas de cwd par process (tous les chemins doivent être absolus)

**Conséquence:** Le modèle POSIX est incomplet. Les apps qui comptent sur `rename(tmp, final)` pour l'atomicité (éditeurs, package managers) ne peuvent pas fonctionner. L'absence de `fsync` empêche les DB d'assurer la durabilité.

**Correctif:** Implémenter ces syscalls. `rename` via `vfs_rename` existe déjà dans `vfs_compat.rs:1132`. `chmod`/`chown` devraient mettre à jour `VfsInode.mode`/`uid` avec check de propriété.

---

### V-08 [HIGH] — ExoFS-local `copy_from_user`/`copy_to_user` ne valident pas la plage user

**Catégorie:** MEMSAFE / ISOLATION
**Fichiers:** `kernel/src/fs/exofs/syscall/validation.rs:194-220`

```rust
pub unsafe fn copy_from_user(dst: *mut u8, src: *const u8, len: usize) -> ExofsResult<()> {
    if src.is_null() || dst.is_null() {
        return Err(ExofsError::InvalidArgument);
    }
    if len == 0 { return Ok(()); }
    core::ptr::copy_nonoverlapping(src, dst, len);  // <-- pas de access_ok
    Ok(())
}
```

Contrairement au `syscall/validation.rs:619-661` qui marche la page table utilisateur via `resolve_user_page` et vérifie `entry.is_user()`, l'helper ExoFS-local ne fait que vérifier le pointeur non-nul. Un process peut passer une adresse kernel (ex. `0xFFFF_8000_XXXX_XXXX`) et faire lire/écrire au kernel sa propre mémoire.

Le helper `read_user_path_heap` copie 4096 octets depuis `ptr` vers un buffer kernel, sans valider que `ptr ∈ [0, USER_ADDR_MAX)`.

**Conséquence:** Information disclosure kernel→user (le kernel peut copier des données kernel vers un buffer user qui est en fait une adresse kernel), ou kernel memory corruption (un user peut écrire via `write_user_struct(out_ptr=0xFFFF_..., &kernel_data)`).

**Atténuation observée:** Le dispatcher ExoFS reçoit les args depuis `dispatch_exofs_syscall(ExofsSyscallArgs{a1..a6})` qui sont les registres bruts. Les handlers ExoFS utilisent leurs propres `copy_from_user` sans repasser par le `validate_user_range` du kernel. C'est un contournement du modèle de sécurité.

**Correctif:** Les helpers ExoFS `copy_from_user`/`copy_to_user` doivent déléguer au `crate::syscall::validation::copy_from_user` (qui marche la page table) plutôt que de faire un `ptr::copy_nonoverlapping` direct. Ou ajouter `validate_user_range(ptr, len, 1)` avant toute copie.

---

### V-09 [HIGH] — e1000 RCTL en mode promiscuous + Store Bad Packets

**Catégorie:** DoS / NETWORK
**Fichiers:** `drivers/network/e1000/src/main.rs:245-253`

```rust
unsafe fn program_rx(&self) {
    let rctl = regs::RCTL_EN
        | regs::RCTL_SBP    // Store Bad Packets — accepte même les paquets CRC-incorrects
        | regs::RCTL_UPE    // Unicast Promiscuous Mode — accepte TOUT le trafic unicast
        | regs::RCTL_MPE    // Multicast Promiscuous Mode — accepte tout le multicast
        | regs::RCTL_BAM    // Broadcast Accept Mode
        | regs::RCTL_BSIZE_2048
        | regs::RCTL_SECRC; // Strip Ethernet CRC
    unsafe { write32(self.mmio, regs::RCTL, rctl) };
}
```

Le NIC est configuré pour accepter **tout** le trafic, y compris les paquets corrompus. Cela:
- Déclenche le traitement kernel de chaque paquet sur le réseau, même non destiné à la machine (DoS amplification)
- Force le network stack à parser des paquets malformés (RCTL_SBP)
- Expose la stack à des paquets forgés (ARP spoofing trivial, ICMP redirect)

**Correctif:**
- Désactiver RCTL_SBP par défaut (ne livrer que les paquets CRC-valides)
- Désactiver RCTL_UPE (mode promiscuous doit être opt-in via `ip link set promisc on`)
- RCTL_MPE uniquement si une socket multicast est ouverte

---

### V-10 [HIGH] — virtio_net `recycle_desc` peut boucler à l'infini (DoS par device malveillant)

**Catégorie:** DoS / RACE
**Fichiers:** `drivers/network/virtio_net/src/virtqueue.rs:210-238`

```rust
pub unsafe fn recycle_desc(&mut self, head: u16) {
    let mut idx = head;
    loop {
        let desc = unsafe { self.desc.add(idx as usize) };
        let snapshot = unsafe { core::ptr::read_volatile(desc) };
        let flags = snapshot.flags;
        let next = snapshot.next;
        // ... recycle desc ...
        self.free_head = idx;
        if flags & VIRTQ_DESC_F_NEXT == 0 || next >= self.queue_size {
            break;
        }
        idx = next;  // <-- device-controlled
    }
}
```

Le device (potentiellement malveillant ou bugué) contrôle `next`. Si le device crée une boucle (`desc[i].next = i`), la boucle ne termine jamais → driver bloqué → DoS.

**Mitigation observée:** Le check `next >= self.queue_size` arrête si OOB, mais pas si self-loop.

**Correctif:** Maintenir un bitset "visited" ou un compteur `visited_count ≤ queue_size`. Sortir en erreur si dépassé.

---

### V-11 [HIGH] — `path_resolve` fuite de métadonnées sans check de permission

**Catégorie:** LEAK / ISOLATION
**Fichiers:** `kernel/src/fs/exofs/syscall/path_resolve.rs:254-294`

`sys_exofs_path_resolve(path_ptr, path_len, flags, out_ptr, _, cap_rights)` retourne une `PathResolveResult` contenant `blob_id`, `object_id`, `object_kind`, `size_bytes`, `epoch_id`, `link_count`, `flags` pour n'importe quel chemin — sans vérifier que le caller a le droit de connaître ces infos.

Le check capability est explicitement désactivé (ligne 280-281):
```rust
// FIX-SEC-T0.4 : faux verify_cap retiré ; résolution de chemin, gatée en TIER 1.
let _ = cap_rights;
```

**Conséquence:** N'importe quel process peut stat n'importe quel fichier (info disclosure de tailles, epoch, flags). Présume l'existence de fichiers secrets sans protection.

**Correctif:** Exiger `RIGHT_STAT` sur l'objet résolu (via `captable::check_blob(&blob_id, CapabilityType::ExoFsObjectStat)`). Pour les chemins non existants, retourner ENOENT sans révéler si le parent existe.

---

### V-12 [HIGH] — Bug de résolution `..` dans symlink relatif

**Catégorie:** LOGIC / ISOLATION
**Fichiers:** `kernel/src/fs/exofs/path/resolver.rs:258-291`

Quand un symlink a une cible relative comme `../sibling` :
```rust
let new_root = if raw_target.first() == Some(&b'/') {
    resolver.root_oid()
} else {
    ctx.current_oid.clone()  // <-- répertoire parent du symlink
};
let mut new_remaining: Vec<PathComponent> = Vec::new();
let mut parser = PathParser::new(&target_canonical)?;
while let Some(c) = parser.next_component()? {
    if c.as_bytes() == b".." {
        new_remaining.pop();  // <-- pop sur new_remaining VIDE = no-op
        continue;
    }
    // ...
}
```

Le `..` est traité contre `new_remaining` (vide au début), donc ne fait rien. La résolution cherche ensuite `sibling` dans `ctx.current_oid` (parent du symlink) au lieu du grand-parent.

**Conséquence:** Violation de la sémantique POSIX. Un symlink `/jail/escape -> ../etc/passwd` est résolu comme `/jail/passwd` au lieu de `/etc/passwd`. Un process privilégié qui suppose la résolution POSIX peut être amené à écrire/lire au mauvais endroit. Peut aussi causer des boucles de symlink si la cible est un cycle relatif.

**Correctif:** Pour les symlinks relatifs, préfixer le `..` avec le chemin du répertoire parent du symlink, puis canonicaliser. Ou implémenter `..` via un `pop` sur la pile des OIDs résolus (pas seulement sur `remaining`).

---

### V-13 [MEDIUM] — Race condition dans `handle_mount` du VFS server

**Catégorie:** RACE
**Fichiers:** `servers/vfs_server/src/main.rs:211-257`

```rust
{
    let mut guard = MOUNTS.lock();
    // ... cherche existing entry, capture free_idx ...
}  // <-- lock relâchée ici
let idx = match free_idx { ... };
{
    let mut guard = MOUNTS.lock();  // <-- re-acquise
    let mounts = &mut *guard;
    mounts[idx] = MountEntry { ... };  // <-- idx peut ne plus être libre
}
```

Entre la première libération du lock et la ré-acquisition, un autre thread IPC peut insérer à `free_idx`, causant un overwrite silencieux.

**Correctif:** Maintenir le lock entre la recherche et l'insertion, ou utiliser un slot atomique.

---

### V-14 [MEDIUM] — `captable::check_object_cap` retourne Ok quand `caller_pid()` est None

**Catégorie:** ISOLATION / LOGIC
**Fichiers:** `kernel/src/fs/exofs/syscall/captable.rs:106-121`

```rust
pub fn check_object_cap(object_id: u64, required: u32) -> Result<(), i64> {
    let pid = match caller_pid() {
        Some(p) => p,
        None => return Ok(()), // contexte kernel/test (privilégié) → autorisé
    };
    // ...
}
```

Si `caller_pid()` retourne `None` (TCB null, gs non initialisé, contexte kthread), **toutes** les vérifications de capability passent. Le commentaire dit "privilégié" mais en pratique, c'est fail-open.

`caller_pid()` retourne None dans deux cas :
1. `cfg(test)` — légitime pour les tests
2. `tcb_raw == 0` en production — signifie qu'aucun thread utilisateur n'est courant

Le cas 2 ne devrait jamais arriver pendant un syscall utilisateur (le syscall entry pose le TCB), mais un bug dans le scheduler ou un appel depuis un kthread pourrait déclencher ce chemin.

**Correctif:** En production (`cfg(not(test))`), `caller_pid() == None` devrait être traité comme `Err(EPERM)` (fail-closed), pas `Ok(())` (fail-open).

---

### V-15 [MEDIUM] — FAT32 `cluster_is_valid` est dead code

**Catégorie:** MEMSAFE / LOGIC
**Fichiers:** `drivers/fs/src/fat32/cluster.rs:13-15`

La fonction `cluster_is_valid(cluster, bpb)` existe mais n'est **jamais appelée** dans le driver FAT32. Les numéros de cluster lus depuis la FAT ou les dir entries ne sont pas validés avant `cluster_to_sector`. Si `cluster < 2`, `cluster_to_sector` fait `(cluster - 2) as u64` → underflow u32 → adresse énorme → OOB read/write sur le disque.

**Impact limité:** Le driver FAT32 semble être principalement utilisé pour lire l'ESP (EFI System Partition) au boot, donc le risque est un bootloader compromise par une image FAT32 malveillante sur l'ESP. Faible probabilité d'attaque réseau.

**Correctif:** Appeler `cluster_is_valid(cluster, bpb)` avant tout `cluster_to_sector` dans `fat_table.rs`, `dir_entry.rs`, etc.

---

### V-16 [MEDIUM] — `OpenArgs.owner_uid` et `CreateArgs.owner_uid` fournis par userspace

**Catégorie:** ISOLATION / LOGIC
**Fichiers:** `kernel/src/fs/exofs/syscall/object_open.rs:171-183`, `object_create.rs:309-319`

```rust
fn read_open_args(args_ptr: u64, flags_fallback: u32) -> Result<OpenArgs, i64> {
    if args_ptr == 0 { /* defaults */ }
    unsafe { copy_struct_from_user::<OpenArgs>(args_ptr).map_err(|_| EFAULT) }
    // ^ owner_uid est lu tel quel depuis userspace, non validé contre le TCB
}
```

Un process peut appeler `sys_exofs_object_create` avec `CreateArgs { owner_uid: 0, ... }` et créer un fichier "appartenant à root". Combiné avec V-03 (owner_uid==0 = wildcard), n'importe quel process peut ensuite y accéder.

**Correctif:** Le kernel doit ignorer `OpenArgs.owner_uid` et utiliser `current_uid()` depuis le PCB. `owner_uid` dans OpenArgs ne devrait pas exister (c'est un paramètre privilégié).

---

### V-17 [LOW] — `validate_open_flags` masque `0x0000_07FF` (11 bits)

**Catégorie:** LOGIC
**Fichiers:** `kernel/src/fs/exofs/syscall/validation.rs:481-488`

Seuls les 11 premiers bits sont acceptés. `O_LARGEFILE` (0x8000), `O_CLOEXEC` (0x80000), `O_NOFOLLOW` (0x20000), `O_DIRECTORY` (0x10000) sont rejetés. Impact : compatibilité POSIX incomplète (les apps qui passent `O_CLOEXEC` obtiennent EINVAL).

**Correctif:** Étendre le masque à `0x0040_1FFF` comme fait dans `handlers/fs_posix.rs:16`.

---

### V-18 [LOW] — `validate_path_component` est dead code

**Catégorie:** LOGIC
**Fichiers:** `kernel/src/fs/exofs/syscall/path_resolve.rs:425-438`

La fonction `validate_path_component` (rejette NUL, contrôle chars, backslash) existe mais n'est **pas appelée** par `PathComponents::parse`. La protection NUL repose uniquement sur `read_user_path_heap` qui stoppe au premier NUL. Si un autre chemin d'entrée ne passe pas par cette fonction (ex: `args_ptr` d'open_by_path avec un path_len différent), des NUL embarqués pourraient passer.

**Correctif:** Appeler `validate_path_component` dans `PathComponents::parse` pour chaque composant.

---

## 5. Points positifs observés

### P-01 — Journaling Epoch à 3 barrières NVMe (mature)
`epoch/epoch_commit.rs` : protocole strict avec 3 `nvme_flush()` obligatoires (data → root → record), lock global `EPOCH_COMMIT_LOCK` anti-concurrence, slot A/B/C avec `prev_slot_offset` chainé, statistiques détaillées. Le commentaire `Inverser cet ordre = corruption garantie` montre une compréhension claire du risque.

### P-02 — Superblock à 3 miroirs avec fallback (mature)
`storage/superblock.rs` : 3 copies (primaire LBA 0, secondaire LBA 3, tertiaire fin de disque), sélection du meilleur par `epoch_current` le plus élevé, checksum Blake3 sur les 480 premiers octets, `verify()` checke magic → version → checksum → flags required (FS-10). Testé avec corruption de miroir.

### P-03 — Parseur GPT/MBR robuste (mature)
`drivers/storage/partition/` : signature `EFI PART` + CRC32 header (champ CRC zeroed) + CRC32 table, `MAX_GPT_ENTRIES=256` anti-OOM, fallback header backup, MBR protecteur (`0xEE`) détecté, MBR legacy non réinterprété. 17 tests host.

### P-04 — fscrypt XChaCha20 + BLAKE3 keyed MAC (mature)
`drivers/storage/fscrypt/` : XChaCha20 (RFC 8439, u32 pur pour éviter LLVM split-128), MAC BLAKE3 keyé contexte `ExoOS-Kernel-XChaCha20-BLAKE3-MAC-v1` tag 16o, KEK Argon2id (m=65536, t=3, p=4), nonce de bloc = `blake3::hash(blob_id || offset_le)[..24]` (unique par bloc), comparaison constant-time dans `aead_open`. Source unique kernel/mkfs → pas de divergence.

### P-05 — verity Ed25519 fail-closed (mature)
`drivers/security/verity/` : enum `KernelVerdict` explicite (Verified/Unsigned/Tampered/NoVerifierKey) empêche confusion "non signé" vs "vérifié". `verify_strict` (anti-malléabilité, anti-clé faible). `key_is_usable` refuse clés nulles et vecteurs de test RFC 8032. Recalcul du SHA-512 du corps (pas de confiance au hash stocké).

### P-06 — NVMe/AHCI conservateurs (bons)
`drivers/storage/nvme/` : 1 PRP par transfert (≤ 1 page = 1 bloc ExoFS), `SPIN_LIMIT = 50_000_000` anti-hang, `dma_alloc` fail-closed, bornage `min(CAP.MQES+1, 64)`. AHCI similaire avec 1 PRDT entry ≤ 4 MiB (DBC 22 bits).

### P-07 — Device_server properly privileged
`servers/device_server/main.rs` : `register_device`, `claim`, `release`, `power_set` exigent `sender_pid == 1` (init). `handle_fault` exige `sender_pid == 1 || sender_pid == driver_pid`. `query` et `event_poll` sans check mais infos limitées (XOR de snapshots).

### P-08 — Socket table avec SOCK_RAW privileged
`servers/network_server/socket_table.rs:14-58` : `RAW_SOCKET_ALLOWED_PIDS = [1, 7]` (init + network_server). SOCK_RAW pour tout autre PID → EPERM (équivalent CAP_NET_RAW Linux). Bonne pratique.

### P-09 — W^X enforcement dans mprotect
`posix_bridge/mmap.rs:399-401` : `prot_has_write_exec(prot)` → `PermissionDenied`. Empêche `PROT_WRITE | PROT_EXEC`, réduit la surface d'exploitation ROP/JOP.

### P-10 — Syscall dispatch avec audit + zero-trust hooks
`syscall/dispatch.rs:147-219` : `audit_syscall_entry` (verdicts Allow/DenyEperm/DenyEnosys/Kill), `verify_syscall` (zero-trust context), feed `exo_shield` NGAV. Post-dispatch signal pending check.

### P-11 — copy_from_user kernel-level correct
`syscall/validation.rs:619-661` : `validate_user_range` vérifie non-NULL, `< USER_ADDR_MAX`, `addr+len ≤ USER_ADDR_MAX` (anti-wrap), alignement. `copy_from_user_resolved` marche la page table via `resolve_user_page` qui vérifie `entry.is_user()` et `entry.is_writable()`. **C'est l'helper ExoFS-local qui est bogué (V-08), pas celui-ci.**

---

## 6. Surface d'attaque non implémentée (réduction de risque)

Les répertoires suivants sont **vides** (aucun `.rs`) — surface d'attaque inexistante mais fonctionnalité manquante :
- `drivers/display/virtio_gpu/` — pas de GPU virtio
- `drivers/audio/hda/` — pas de codec HDA
- `drivers/audio/virtio_sound/` — pas de son virtio
- `drivers/clock/` — pas de driver horloge userspace (le kernel gère le TSC/HPET directement)
- `drivers/input/evdev/` — pas de evdev
- `drivers/input/usb_hid/` — pas de parsing HID descriptor (surface hostile évitée)
- `drivers/manager/` — n'existe pas
- `drivers/framework/` — n'existe pas

Note: L'absence d'USB HID est une bonne chose pour la sécurité (parsing de HID descriptor est notoirement vulnérable), mais limite l'utilisabilité.

---

## 7. Recommandations prioritaires

| Priorité | Recommandation | Effort |
|---|---|---|
| P0 | **V-01** Réactiver le check capability à l'open (TIER 1) : `verify_cap(cap_rights, cap)` doit être consulté, et `cap_rights` doit venir de la `cap_table` du PCB, pas d'un registre user-controlled | M (1-2 semaines) |
| P0 | **V-02** Ajouter checks de permission Unix dans vfs_create/open/unlink/rename/mkdir/rmdir (check UID + mode bits + sticky) | M (1 semaine) |
| P0 | **V-03** Séparer UID et PID, refuser `owner_uid==0` comme wildcard, valider `OpenArgs.owner_uid` contre `current_uid()` | S (2-3 jours) |
| P0 | **V-04** Ajouter `current_pid() == e.pid` dans munmap/msync/mprotect/mark_dirty. Idéalement partitionner MmapTable par address space | S (1-2 jours) |
| P0 | **V-05** Supprimer `DMA_MAP_FLAGS_BYPASS_IOMMU` en production, attacher un domaine IOMMU par device | L (1 mois, dépend de l'IOMMU kernel) |
| P1 | **V-06** VFS server : remplacer `check_vfs_write_access` par une capability table par PID client | M (1 semaine) |
| P1 | **V-07** Implémenter chmod/chown/rename/link/fsync/fdatasync/access/chdir | M (1-2 semaines) |
| P1 | **V-08** Les helpers ExoFS `copy_from_user`/`copy_to_user` doivent déléguer à `crate::syscall::validation` (qui marche la page table) | S (1 jour) |
| P1 | **V-09** Désactiver RCTL_SBP, RCTL_UPE, RCTL_MPE par défaut dans e1000 | XS (1 ligne) |
| P1 | **V-10** Ajouter un bitset "visited" dans `recycle_desc` pour casser les cycles | S (1 jour) |
| P1 | **V-11** Exiger `RIGHT_STAT` dans `sys_exofs_path_resolve` | XS (1 ligne) |
| P1 | **V-12** Corriger la résolution `..` des symlinks relatifs (pop sur stack d'OIDs, pas sur remaining) | S (2-3 jours) |
| P2 | **V-13** Maintenir le lock VFS mount entre search et insert | XS |
| P2 | **V-14** `captable::check_object_cap` : `None` → `Err(EPERM)` en production (fail-closed) | XS |
| P2 | **V-15** Appeler `cluster_is_valid` dans le driver FAT32 | S (1 jour) |
| P2 | **V-16** Ignorer `OpenArgs.owner_uid` et `CreateArgs.owner_uid` depuis userspace | XS |
| P3 | **V-17, V-18** Étendre `validate_open_flags`, appeler `validate_path_component` | XS |

---

## 8. Score de maturité

| Dimension | Score /10 | Justification |
|---|---|---|
| **Journaling / crash consistency** | 8 | 3 barrières NVMe, 3 slots A/B/C, lock global, tests. Manque: pas de fsck obligatoire post-crash (conditionnel). |
| **Integrity (CRC, hashes)** | 8 | Blake3 sur superblock + blobs, magic-before-content, backup GPT. Pas de hash tree Merkle pour le data path (verity séparé). |
| **Encryption at rest** | 8 | XChaCha20 + BLAKE3 MAC, Argon2id KEK, nonce unique par bloc. Source unique kernel/mkfs. |
| **Permission model** | 2 | Aucun check Unix à l'open/unlink/rename. Capabilities désactivées à l'open. owner_uid contrôlé par userspace. |
| **Capability system** | 4 | CapTable réelle dans PCB, mécanisme mint/check/revoke réel. Mais bypassed à l'open et fail-open si `caller_pid()==None`. |
| **Path traversal protection** | 6 | `..` rejeté dans path_resolve, canonicalization OK. Bug `..` dans symlink relatif (V-12). |
| **Symlink loop detection** | 7 | `SYMLINK_MAX_DEPTH=40`, `max_iters=8192` dans resolver. Bug V-12 peut causer des cycles inattendus. |
| **Race conditions** | 5 | `OBJECT_LIFECYCLE_LOCK` + `EPOCH_COMMIT_LOCK`. VFS server mount table race (V-13). mmap global sans check PID (V-04). |
| **DoS resistance** | 5 | Quota enforcement, MAX_FDS=4096, MAX_SOCKETS=64, MAX_GPT_ENTRIES=256. e1000 promiscuous + SBP amplifie DoS réseau (V-09). recycle_desc infinite loop (V-10). |
| **DMA / IOMMU safety** | 3 | IOMMU bypass explicite (V-05). Bounce buffers dans virtio_blk mais pas dans e1000/virtio_net. |
| **Userspace pointer validation** | 5 | Kernel-level `validate_user_range` correct, mais helper ExoFS-local bogué (V-08). |
| **POSIX completeness** | 4 | open/read/write/stat/mkdir/symlink OK. chmod/chown/rename/link/fsync/chdir = ENOSYS (V-07). |

**Score global FS/drivers: 4/10**

Le socle bas niveau (journaling, crypto, parsers) est excellent (8/10). La couche de sécurité POSIX (permissions, capabilities, ownership) est non fonctionnelle (2/10). À ce stade, ExoFS ne peut pas être considéré comme multi-utilisateur ou multi-process sécurisé : un process Ring3 compromis a accès total au FS, aux mappings mémoire et (via DMA bypass) à toute la RAM.

---

## 9. Conclusion

ExoFS est un FS **fonctionnellement riche** (155k LOC, snapshots, dedup, compression, quotas, relations, export/import) avec un **socle crypto/journaling mature**, mais dont la **couche de sécurité POSIX est à l'état de prototype**. Les commentaires `FIX-SEC-T0.3/T0.4 : TIER 1 hardening pending` avouent un état permissif délibéré.

**La priorité absolue est d'implémenter le TIER 1** : réactiver les capability checks à l'open, ajouter les checks de permission Unix dans le VFS layer, séparer UID/PID, et supprimer l'IOMMU bypass en production. Sans cela, tout le travail crypto/integrity n'empêche pas un process compromis de lire `master_key` ou `volume_secret` directement depuis le heap kernel via les syscalls ExoFS permissifs.

L'absence de chmod/chown/rename/link/fsync (V-07) limite également la compatibilité POSIX au point que les apps Linux standard ne peuvent pas fonctionner correctement.

Les drivers storage (NVMe/AHCI/virtio_blk) sont de bonne qualité (bornage strict, fail-closed DMA, tests). Les drivers network (e1000/virtio_net) sont fonctionnels mais pratiquent l'IOMMU bypass et activent le mode promiscuous — à durcir avant toute exposition réseau non contrôlée.
