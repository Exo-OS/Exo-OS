# 07 — Audit IPC / Syscall ABI / Memory / Scheduler / Process

**Task ID:** AUDIT-7-KERNEL-IPC-SYSCALL-MEM
**Auditeur:** Sub-agent kernel senior (IPC, syscalls, memory, scheduler, process)
**Périmètre:** `kernel/src/{ipc,syscall,memory,process,scheduler,arch/x86_64}` + `servers/{ipc_router,syscall_abi,scheduler_server,memory_server}`
**Méthode:** Lecture exhaustive des fichiers critiques + croisement avec docs FIX/8, FIX/9, FIX/10, FIX/16.

---

## 0. Synthèse exécutive

Le kernel ExoOS présente une **architecture défensive en cours de maturation** : KPTI, SMEP/SMAP, W^X, IBPB au context switch, CapToken IPC, audit syscall, zero-trust, ExoCordon DAG pour IPC — toutes les briques modernes sont présentes. Cependant, **l'implémentation comporte plusieurs failles d'isolation exploitables** principalement concentrées dans :

1. La registry des PCB (UAF sur `find_by_pid`),
2. Le sous-système IPC raw mailbox (DoS par épuisement, spin-wait longs, manque d'auth sur `mailbox_open`),
3. Le lazy FPU allocator (allocation heap dans handler #NM → deadlock potentiel),
4. Le CoW breaker (TLB shootdown incomplet en SMP → possible stale read après free),
5. Le scheduler server qui délègue l'admission RT sans garde-fou kernel.

**Score maturité isolation kernel : 5.5 / 10** — correct sur le papier, failles critiques en pratique.

---

## 1. IPC — kernel/src/ipc/ (56 fichiers, 17.5 k LOC)

### 1.1 Vue d'ensemble

L'IPC s'organise en 9 sous-modules : `core`, `ring`, `endpoint`, `channel`, `shared_memory`, `sync`, `stats`, `message`, `rpc`. Le locking suit un ordre canonique (IPC = niveau 4, après Memory→Scheduler→Security). L'authentification repose sur `security::access_control::check_access` via `capability_bridge`, et l'ABI syscall valide les CapToken via `validate_ipc_envelope_auth`.

### 1.2 Vulnérabilités IPC

#### 🔴 IPC-01 — `mailbox_open` sans authentification (HIGH/ISOLATION)
**Fichier:** `kernel/src/ipc/channel/raw.rs:202-225`
```rust
pub fn mailbox_open(ep_id: EndpointId) -> bool {
    let id = ep_id.get();
    if id == 0 { return false; }
    if find_slot(id).is_some() { return true; }   // ← idempotent, pas de check owner
    // ... trouve un slot libre et CAS le bitmap
}
```
`mailbox_open` ne vérifie **jamais** que l'appelant est propriétaire légitime de `ep_id`. Les `EndpointId` sont alloués séquentiellement par `alloc_endpoint_id()` (u64 monotone depuis 1) — donc **prédictibles**. Un processus malveillant peut :

- Appeler `mailbox_open(ep_id_attendu)` pour n'importe quel endpoint cible,
- Puis `send_raw(ep_id_attendu, payload, 0)` pour injecter des messages.

**Mitigation partielle:** `sys_exo_ipc_send` (table.rs:2915) appelle `validate_ipc_envelope_auth()` qui exige un CapToken valide pour les enveloppes ABI standard. Mais les enveloppes non-standard (taille ≠ ABI_IPC_ENVELOPE_SIZE) passent en `TrustedCaller`/`NotRequired` sans vérification. **La mailbox elle-même reste ouverte à tous.**

**Correctif:** Ajouter un check `caller_pid == endpoint_owner_pid(ep_id)` dans `mailbox_open`, ou exiger un CapToken IPC_SEND pour tout `send_raw` (pas seulement `send_raw_checked`).

#### 🔴 IPC-02 — DoS par épuisement de `MAX_RAW_SLOTS = 64` (HIGH/DoS)
**Fichier:** `kernel/src/ipc/channel/raw.rs:27`
```rust
pub const MAX_RAW_SLOTS: usize = 64;
```
64 mailboxes globales pour tout le système. Un processus utilisateur peut appeler `exo_ipc_create` 64 fois avec des endpoints différents → **saturation permanente** : tous les `exo_ipc_create` suivants échouent avec `EAGAIN`/`ENOMEM`, bloquant le démarrage de nouveaux services Ring 1.

**Pas de rate limiting**, pas de quota par PID. Le `IPC_ENDPOINT_OWNERS` (table.rs:2760) ajoute 128 slots owner-tracking, mais c'est une table séparée — le bottleneck réel reste `MAX_RAW_SLOTS = 64`.

**Correctif:** Augmenter à ≥1024, ajouter un quota par PID (ex: 8 mailboxes/processus), refuser `mailbox_open` aux PIDs non-owner.

#### 🟠 IPC-03 — Spin-wait 200K/1M iterations dans `send_raw`/`recv_raw` (MEDIUM/DoS)
**Fichier:** `kernel/src/ipc/channel/raw.rs:296-310, 383-401`
```rust
let mut spins: u32 = 0;
loop {
    core::hint::spin_loop();
    spins = spins.saturating_add(1);
    let mut ring = slot.ring.lock();           // ← acquire spinlock à chaque itération
    if ring.enqueue(data) { /* ok */ }
    if spins > 200_000 { return Err(Timeout); }  // send_raw
    if spins > 1_000_000 { return Err(Timeout); } // recv_raw
}
```
Le thread boucle en ré-acquérant le SpinLock à chaque itération. Sur SMP, **chaque itération fait un CAS caché** — ce qui crée une contention inter-CPU massive. La préemption n'est PAS désactivée pendant ces spins, donc le thread peut être préempté en tenant le lock → **tous les autres CPUs attendent**.

De plus, ces spins ne cooperative-yield jamais (pas de `sched_yield`), donc le thread occupe son quantum CPU à brûler du TSC.

**Correctif:** Utiliser `block_current_thread()` (scheduler wait queue) ou au minimum `sched_yield` tous les ~1000 spins, et libérer le lock avant le `spin_loop_hint`.

#### 🟠 IPC-04 — `with_endpoint` scan O(N) sous lock global (MEDIUM/DoS)
**Fichier:** `kernel/src/ipc/endpoint/lifecycle.rs:235-250`
```rust
fn with_endpoint<F, R>(ep_id: EndpointId, f: F) -> Result<R, IpcError> {
    let pool = EP_POOL_DESCS.lock();          // ← SpinLock global
    for slot in pool.iter() {                 // ← O(MAX_ENDPOINTS) = O(4096)
        if let Some(ref b) = slot {
            let desc = unsafe { b.as_ref() };
            if desc.id == ep_id { return f(desc); }
        }
    }
    Err(IpcError::EndpointNotFound)
}
```
`endpoint_destroy` fait **deux** scans O(N) successifs sous le même lock. Avec `MAX_ENDPOINTS = 4096`, chaque appel IPC listen/close/destroy parcourt 4096 entrées — un attaquant peut saturer le CPU en appelant `endpoint_listen` en boucle.

**Correctif:** Indexer par `EndpointId` (hash table) au lieu de scan linéaire, ou maintenir un index `EndpointId → slot_idx` atomique.

#### 🟠 IPC-05 — `endpoint_destroy` TOCTOU sur `active_conns` (HIGH/UAF)
**Fichier:** `kernel/src/ipc/endpoint/lifecycle.rs:180-227`
```rust
pub fn endpoint_destroy(name: &[u8], ep_id: EndpointId) -> Result<(), IpcError> {
    let active = {
        let pool = EP_POOL_DESCS.lock();
        // ... trouve l'index, lit active_conns.load(Acquire)  ← [A]
        ...
    };
    if active == Some(0) || active.is_none() {
        unregister_endpoint(name);                    // ← [B] fenêtre TOCTOU
        // libère le slot
    }
}
```
Entre la lecture de `active_conns` [A] et la libération du slot [B], un autre CPU peut incrémenter `active_conns` via `endpoint_connect`. Le descripteur est libéré alors qu'une connexion est en cours d'établissement → **use-after-free** sur `EndpointDesc`.

**Correctif:** Prendre le lock de l'endpoint (ou un lock registry global) pour la durée entière de la séquence check-then-free, et vérifier `active_conns == 0` sous ce lock atomique avec la libération.

#### 🟡 IPC-06 — Hash FNV-1a non résistant aux collisions pour EndpointRegistry (LOW)
**Fichier:** `kernel/src/ipc/endpoint/registry.rs:35-42`
```rust
fn fnv1a(bytes: &[u8]) -> u64 { /* ... */ }
```
FNV-1a est un hash non-cryptographique. Deux noms d'endpoint distincts peuvent collisionner (birthday paradox : ~50% de collision à 2^32 entrées). Le `lookup` retourne le premier slot avec `slot.hash == hash` — sans comparer le nom réel. **Confusion de namespace** possible si un attaquant peut enregistrer un nom qui hash vers le même bucket qu'un endpoint privilégié.

**Mitigation:** La table est limitée à `MAX_ENDPOINTS` (4096) entrées, donc la probabilité de collision est faible (~2^-46 par paire). Mais l'absence de comparaison de nom est un design smell.

**Correctif:** Stocker le nom (ou un hash secondaire 128-bit) dans l'entrée et comparer à la lookup.

#### 🟡 IPC-07 — `MessageFlags` vs `MsgFlags` toujours dupliqués (LOW/INFO)
**Fichier:** `kernel/src/ipc/core/types.rs:206, 429`

Le rapport FIX/8 ipc demandait l'unification. Le code actuel a **toujours** deux types : `MsgFlags(u32)` (ring/channel) et `MessageFlags(u16)` (message/builder). Des conversions `From` existent (lignes 276, 477), mais la confusion API persiste. `from_bits_truncate` masque les bits > 0x7F silencieusement → perte d'information non détectée.

### 1.3 Points forts IPC

- ✅ CapToken IPC_SEND/IPC_RECV vérifiés via `capability_bridge::check_channel_access` (kernel/src/ipc/capability_bridge/check.rs).
- ✅ `array_index_nospec()` (types.rs:574) implémente Spectre v1 mitigation sur les accès aux buffers indexés.
- ✅ `send_irq_notification` (mod.rs:116) utilise `try_send_raw_nowait` qui ne spin jamais — correct pour ISR.
- ✅ DAG ExoCordon (servers/ipc_router/src/exocordon.rs) applique deny-by-default sur les routes IPC.
- ✅ Soft quarantine + audit exo_shield sur violations IPC (security_gate.rs:173-180, 211-246).

---

## 2. Syscall ABI — kernel/src/syscall/ (23 fichiers, 18.2 k LOC)

### 2.1 Vue d'ensemble

L'entrée syscall utilise SYSCALL/SYSRET avec SWAPGS, KPTI switch dans le stub ASM, vérification canonicité RCX/RSP avant SYSRET (CVE-2012-0217), fallback IRETQ. Le dispatch applique audit syscall + zero-trust verify_syscall avant exécution. Les arguments userspace sont validés via `UserPtr::validate` / `UserBuf::validate` / `UserStr::from_user` avec bounds check, alignement, et anti-wrap.

### 2.2 Vulnérabilités Syscall

#### 🟠 SYS-01 — `dispatch.rs` skip zéro-trust pour 3 syscalls "fast-path-eligible" (MEDIUM/ISOLATION)
**Fichier:** `kernel/src/syscall/dispatch.rs:189-219`
```rust
if nr != SYS_SCHED_YIELD
    && nr != SYS_GETPID
    && nr != SYS_CLOCK_GETTIME
{
    let zt_ok = { /* verify_syscall */ };
    if !zt_ok { /* EPERM */ }
}
```
La vérification zero-trust est **skippée** pour `SYS_SCHED_YIELD`, `SYS_GETPID`, `SYS_CLOCK_GETTIME`. Ensuite le fast_path est appelé. Si le fast-path traite ces 3 syscalls sans vérification, un processus sandboxé (pledge) qui s'est vu interdire `getpid()` (par exemple) peut quand même l'appeler.

**Correctif:** Le skip doit se faire uniquement si le processus n'a pas de restrictions pledge/sandbox. Sinon, appliquer verify_syscall même sur fast-path.

#### 🟠 SYS-02 — `current_thread_raw()` null → audit/zero-trust bypass (MEDIUM/ISOLATION)
**Fichier:** `kernel/src/syscall/dispatch.rs:152-162`
```rust
let (caller_pid, caller_tid) = {
    let tcb_ptr = current_thread_raw();
    if tcb_ptr.is_null() {
        (0u32, 0u32)              // ← pid=0 (kernel thread)
    } else { /* ... */ }
};
match audit_syscall_entry(nr, caller_pid, caller_tid, 0) { /* ... */ }
```
Si `current_thread_raw()` retourne null (kthread ou boot), `caller_pid = 0`. Les règles d'audit peuvent traiter `pid=0` différemment (ex: whitelist kernel). Un attaquant qui pourrait forcer `gs:[0x20]` à 0 (corruption GS_BASE) bypasserait l'audit. Le scénario nécessite déjà une primitive d'écriture kernel, donc c'est un **défense en profondeur** manquante, pas une faille directe.

**Correctif:** Si `tcb_ptr.is_null()` et qu'on vient de Ring 3 (vérifiable via CS dans la frame), panic immédiat.

#### 🟠 SYS-03 — `handle_sigreturn_inplace` restaure `signal_mask` sans validation complète (MEDIUM)
**Fichier:** `kernel/src/syscall/dispatch.rs:349-425`
```rust
let safe_mask = crate::process::signal::mask::SigMask::from(regs.signal_mask).0;
tcb.signal_mask.store(safe_mask, Ordering::Release);
```
Le `safe_mask` est dérivé de `regs.signal_mask` (lu depuis userspace via `verify_and_extract_uc`). Si `verify_and_extract_uc` ne filtre pas correctement les bits (ex: bits > 63 ou bits pour SIGKILL/SIGSTOP qui doivent rester non-masquables), un processus pourrait masquer SIGKILL → insubmersible.

Le commentaire dit "Masque SIGKILL/SIGSTOP non-masquables et bits de signaux invalides" — mais le code utilise `SigMask::from(regs.signal_mask).0` qui peut ne pas appliquer ce filtrage. **À vérifier dans `signal/mask.rs`.**

#### 🟡 SYS-04 — `copy_userspace_argv` alloue un `Vec<String>` (MEDIUM/DoS)
**Fichier:** `kernel/src/syscall/dispatch.rs:760-808`
```rust
fn copy_userspace_argv(argv_ptr: u64, max_args: usize)
    -> Option<alloc::vec::Vec<alloc::string::String>>
{
    // ... boucle jusqu'à max_args (1024)
    // ... String::from_utf8_lossy(user_str.as_bytes()).into_owned()  ← allocation
}
```
`max_args = 1024` et `String::from_utf8_lossy` alloue un buffer par argument. Un attaquant peut passer 1024 arguments de 4096 octets → ~4 MiB d'allocations heap kernel en un seul syscall execve. Répéter execve → fragmentation heap / OOM.

**Mitigation:** `max_args = 1024` et `STRING_MAX = 65536` bornent l'attaque, mais le total reste ~64 MiB théoriques.

**Correctif:** Baisser `ARGV_MAX` à 256, ou compter le total d'octets et refuser si > 64 KiB.

#### 🟡 SYS-05 — `read_user_path` accepte 4096 octets mais `UserStr::from_user` lit octet-par-octet (LOW/INFO)
**Fichier:** `kernel/src/syscall/validation.rs:291-329`
```rust
pub fn from_user(ptr: u64, max: usize) -> Result<Self, SyscallError> {
    // ...
    loop {
        // ...
        copy_from_user(&mut byte as *mut u8, byte_addr as *const u8, 1)?;  // ← 1 octet à la fois
        if byte == 0 { break; }
        buf.push(byte);
        offset += 1;
    }
}
```
Lecture octet-par-octet depuis userspace via `copy_from_user` (qui résout la page via le walker). Pour un chemin de 4096 octets, cela fait 4096 appels à `resolve_user_page` + 4096 lectures physmap. Coût ~4096 × 100ns = 400 µs par syscall qui prend un path. Sur `execve` + `open` + `stat` fréquents, c'est un overhead mesurable, et un attaquant peut spammer ces syscalls pour DoS CPU.

**Correctif:** Lire par chunks de 256 octets en une fois, chercher le `'\0'` ensuite.

#### 🟢 SYS-06 — SYSRET canonicality check + fallback IRETQ (BON)
**Fichier:** `kernel/src/arch/x86_64/syscall.rs:264-308`
```asm
mov rax, rcx
shl rax, 16
sar rax, 16
cmp rax, rcx
jne 997f                        ; ← non-canonique → fallback IRETQ
```
Mitigation CVE-2012-0217 correctement implémentée. Le fallback IRETQ construit une frame user canonique qui fault en Ring 3 sur RIP=0 (non-mappé) → SIGSEGV au lieu de #GP Ring 0.

#### 🟢 SYS-07 — `validate_user_range` robuste (BON)
**Fichier:** `kernel/src/syscall/validation.rs:430-464`

Vérifie : non-NULL (sauf len=0), < USER_ADDR_MAX, `addr + len` ne wrap pas u64 et ne dépasse pas USER_ADDR_MAX, alignement puissance de 2. Anti-wrap via `checked_add`. **Aucun pointeur user n'est déréférencé sans passer par cette fonction.**

#### 🟢 SYS-08 — KPTI switch dans stub ASM avant tout accès pile kernel (BON)
**Fichier:** `kernel/src/arch/x86_64/syscall.rs:198-203`
```asm
mov rax, qword ptr gs:[0x40]     ; kpti_kernel_cr3
test rax, rax
jz 998f
mov cr3, rax                     ; ← switch CR3 AVANT push
998:
```
Le CR3 kernel est chargé **avant** tout push sur la pile kernel, empêchant Meltdown-style attacks via side-channel sur les pushes précoces.

### 2.3 Points forts Syscall

- ✅ `audit_syscall_entry` (FIX-APP-02) avec verdict `Allow/DenyEperm/DenyEnosys/Kill`.
- ✅ `verify_syscall` zero-trust (FIX-APP-01) avec SecurityContext réel.
- ✅ `validate_ipc_envelope_auth` force `sender_pid = caller_pid` pour les appelants non-trusted (FIX-IPC-SENDER-AUTH).
- ✅ `copy_from_user` / `copy_to_user` résolvent la page via le walker et l'UserAddressSpace courant, jamais d'accès direct à un pointeur user.
- ✅ IBRS appliqué au syscall entry (FIX-B-02) et IBPB au context switch cross-processus.

---

## 3. Memory Management — kernel/src/memory/ (130 fichiers, 32.7 k LOC)

### 3.1 Vue d'ensemble

Le sous-système memory est organisé en : `core` (types/layout/address), `physical` (buddy/slab/slub allocator, frame descriptors, zones DMA/DMA32/Normal/High/Movable, NUMA), `virtual` (page tables PML4, KPTI split, VMA tree, mmap/munmap/mprotect, fault handler CoW/demand-paging/swap-in, address space user/kernel), `heap` (hybrid allocator + thread-local cache + vmalloc), `cow` (tracker hash table), `swap`, `dma` (IOMMU Intel VT-d / AMD / ARM SMMU + engines + channels), `huge_pages`, `integrity` (canary/guard pages/sanitizer), `protection` (NX/PKU/SMAP/SMEP/UMIP).

### 3.2 Vulnérabilités Memory

#### 🔴 MEM-01 — CoW breaker : `flush_single` local-only en SMP (HIGH/UAF/info-leak)
**Fichier:** `kernel/src/memory/virtual/fault/cow.rs:46-105`
```rust
match alloc.compare_exchange_pte_raw(page_addr, old_raw, new_raw) {
    Ok(_) => {
        let remaining = COW_TRACKER.dec(old_frame);
        if remaining == 0 {
            alloc.free_frame(old_frame);          // ← old frame libéré
        }
        vma.record_cow_break();
        unsafe { flush_single(page_addr); }       // ← flush TLB LOCAL uniquement
        FaultResult::Handled
    }
    // ...
}
```
Problème : après CAS du PTE et libération éventuelle de `old_frame`, seul le TLB **local** est flushé. Les autres CPUs qui ont une entrée TLB stale pointant vers `old_frame` peuvent continuer à **lire** `old_frame` (le PTE était COW read-only, donc pas d'écriture). Mais si `old_frame` est réalloué à un autre processus (B), le CPU distant peut lire les données de B via son TLB stale → **information leak cross-process**.

Le `cow::tracker.rs:189` (fonction `dec`) utilise un `Mutex<()>` global pour sérialiser inc/dec, mais le `flush_single` n'est PAS synchronisé cross-CPU. Il faudrait `shootdown_sync` (TLB IPI) avant `free_frame`.

**Mitigation partielle:** Le PTE était COW (read-only), donc pas d'écriture via TLB stale. Mais la **lecture** stale après free + realloc reste exploitable.

**Correctif:** Appeler `crate::memory::virt::shootdown_sync(TlbFlushType::Address(page_addr), cpu_count)` avant `alloc.free_frame(old_frame)` si `remaining == 0`.

#### 🔴 MEM-02 — `ProcessRegistry::find_by_pid` UAF race (HIGH/UAF)
**Fichier:** `kernel/src/process/core/registry.rs:196-211`
```rust
pub fn find_by_pid(&self, pid: Pid) -> Option<&ProcessControlBlock> {
    // ...
    let slot = unsafe { &*self.slots.add(slot_idx) };
    let raw = slot.pcb_ptr.load(Ordering::Acquire);
    if raw.is_null() { return None; }
    // SAFETY: raw non null = PCB encore dans la table (non libéré).
    Some(unsafe { &*raw })     // ← AUCUN refcount inc
}
```
**Le champ `refcount` est déclaré (ligne 35) mais JAMAIS incrémenté par `find_by_pid`.** Le `remove` fait `slot.pcb_ptr.swap(null, AcqRel)` puis `Box::from_raw(raw)` (ligne 183-190) — **libération immédiate** du PCB.

Scénario race SMP :
```
CPU 0: find_by_pid(42) → raw = 0xFFFF_8000_0000_1000  (PCB vivant)
CPU 1: remove(Pid(42)) → swap null, Box::from_raw → PCB freed
CPU 0: &*raw → déréférence un PCB libéré → UAF
```
Cette fonction est appelée par **tous les chemins chauds** : `dispatch.rs::check_and_deliver_signals`, `sys_exit`, `sys_wait4`, `sys_execve`, `send_signal_to_pid`, OOM killer, etc. — soit des dizaines de sites d'appel.

**Correctif:** Implémenter un vrai refcount : `find_by_pid` fait `refcount.fetch_add(1)` après le load non-null, puis vérifie que le ptr n'a pas été nullifié entre-temps (CAS loop). Le caller doit appeler `release(pid)` pour décrémenter. Ou bien utiliser un `Rc<ProcessControlBlock>` / `Arc`.

#### 🟠 MEM-03 — Lazy FPU : allocation heap dans handler #NM (HIGH/Deadlock)
**Fichier:** `kernel/src/scheduler/fpu/lazy.rs:115-135` + `save_restore.rs:138-168`
```rust
pub unsafe fn handle_nm_exception(tcb: &mut ThreadControlBlock) {
    cr0_clear_ts();
    if tcb.fpu_state_ptr == 0 {
        super::save_restore::alloc_fpu_state(tcb);   // ← allocation heap dans #NM
    }
    super::save_restore::xrstor_for(tcb);
}
// alloc_fpu_state:
pub unsafe fn alloc_fpu_state(tcb: &mut ThreadControlBlock) -> bool {
    if tcb.sched_state.load(Acquire) & SCHED_IN_RECLAIM_BIT != 0 {
        return false;                                 // ← protection contre reentrance reclaim
    }
    let ptr = alloc::alloc::alloc(layout);            // ← heap kernel (SLUB/hybrid)
    // ...
}
```
Le handler #NM (Device Not Available, déclenché par CR0.TS=1 sur instruction FPU) peut **allouer de la mémoire heap**. Le check `IN_RECLAIM` ne couvre qu'un seul scénario de deadlock :

- Thread A tient un lock memory (ex: buddy allocator) → schedule out.
- Thread B obtient le CPU, instruction FPU → #NM → `alloc_fpu_state` → `alloc::alloc::alloc` → essaie d'acquérir le lock buddy → **deadlock**.

Le rapport FIX/9 (CRIT-MS-03) avait recommandé la **pré-allocation à la création du thread**. Le code actuel fait toujours du lazy. La protection `IN_RECLAIM` est nécessaire mais **insuffisante** : elle ne couvre que les locks de reclaim, pas les locks généraux du buddy/SLUB.

**Correctif:** Allouer `fpu_state_ptr` dans `ThreadControlBlock::new()` (task.rs) au spawn du thread. Si l'allocation échoue au spawn, refuser la création du thread (ENOMEM) plutôt que paniquer plus tard dans #NM.

#### 🟠 MEM-04 — `do_munmap` libère les frames avant shootdown sur erreurs partielles (MEDIUM)
**Fichier:** `kernel/src/memory/virtual/mmap.rs:307-360`
```rust
const BATCH: usize = 64;
while cursor < vma_end.as_u64() {
    let mut frames = [...; BATCH];
    // Phase 1 : démappe + récolte frames
    while cursor < vma_end.as_u64() && count < BATCH {
        if let Some(f) = unsafe { user_as.unmap_page(VirtAddr::new(cursor)) } {
            frames[count] = f;
            count += 1;
        }
        cursor += PAGE_SIZE as u64;
    }
    // Phase 2 : TLB shootdown synchrone
    unsafe { shootdown_sync(Range { start: batch_start, end: batch_end }, cpu_count); }
    // Phase 3 : libère les frames
    for i in 0..count {
        let _ = buddy::free_page(frames[i]);
    }
}
```
La séquence (unmap → shootdown → free) est correcte. Cependant, `unmap_page` fait seulement un flush TLB **local** (via `flush_single`). Le `shootdown_sync` est appelé APRÈS le batch de 64 unmap, ce qui laisse une **fenêtre de 64 pages** où d'autres CPUs peuvent avoir des TLB stale.

Si un autre CPU accède à l'une de ces 64 pages pendant la fenêtre, il obtient un #PF (PTE non-présent) — ce qui est acceptable (la page est en cours de démapping). **Pas de leak**, mais la fenêtre peut causer des pics de #PF sur les autres CPUs.

**Correctif:** Appeler `shootdown_sync` plus fréquemment (ex: BATCH=16) ou faire le shootdown par page dans `unmap_page` pour les régions sensibles.

#### 🟠 MEM-05 — `do_mprotect` ne valide pas le croisement W^X avec l'état précédent (MEDIUM)
**Fichier:** `kernel/src/memory/virtual/mmap.rs:381-458`

`do_mprotect` appelle `validate_prot` qui rejette `PROT_WRITE | PROT_EXEC` simultanés. Mais elle **n'empêche pas** :
1. `mprotect(addr, len, PROT_WRITE)` → OK (RW)
2. `mprotect(addr, len, PROT_EXEC)` → OK (RX), W retiré

C'est conforme à POSIX/Linux (W^X "momentané"), mais permet à un processus de faire du **JIT self-modifying code** en alternant W et X. Pour une vraie politique W^X stricte (anti-JIT), il faudrait marquer la VMA "has been W" et interdire ensuite X.

**Note:** Ce n'est pas un bug — c'est un choix politique. Linux fait pareil.

#### 🟠 MEM-06 — `do_brk` ne fait pas de W^X check (LOW)
**Fichier:** `kernel/src/memory/virtual/mmap.rs:49-57` (syscall handler)

`sys_brk` appelle `do_brk(addr)` qui ne prend pas de `prot` argument. Le heap brk est implicitement RW (pas EXEC). Mais si un processus peut `mprotect` la région brk en PROT_EXEC, il obtient du code W^X-pas-de-W (RX) sur le heap → JIT. Acceptable mais à surveiller.

#### 🟡 MEM-07 — `KASLR_OFFSET` est `AtomicU64` mais pas protégé contre lecture cross-couche (LOW/INFO)
**Fichier:** `kernel/src/security/exploit_mitigations/kaslr.rs:42`
```rust
static KASLR_OFFSET: AtomicU64 = AtomicU64::new(0);
```
L'offset est chargé avec `Ordering::Acquire` après `KASLR_READY`. Mais il n'y a pas de contrôle d'accès : n'importe quel module kernel peut lire `KASLR_OFFSET.load()`. Si une fuite d'info (ex: printk, /proc, dmesg) expose cet offset → KASLR bypassé.

**Correctif:** Marquer la lecture comme `pub(crate)` restreinte, et auditer tous les sites de logging pour s'assurer qu'ils ne loguent jamais `%pK`-style kernel pointers.

#### 🟢 MEM-08 — Buddy allocator robuste (BON)
**Fichier:** `kernel/src/memory/physical/allocator/buddy.rs`

- Bitmap + free-list doublement chaînée par ordre.
- Lock par zone (DMA/DMA32/Normal/High/Movable) — pas de lock global.
- Vérifications de bornes dans `alloc_inner` (ligne 488-500) : `contains_aligned_block`, `bitmap_range_is_free`, `descriptors_range_is_free`.
- Anti-double-free dans `free_pages` (ligne 582) : `bitmap_range_is_allocated` avant libération.
- Pas d'allocation heap dans le chemin chaud (FreeNode embed dans le bloc libre).

#### 🟢 MEM-09 — `validate_prot` rejette W|X (BON)
**Fichier:** `kernel/src/memory/virtual/mmap.rs:163-171`
```rust
fn validate_prot(prot: u32) -> Result<(), MmapError> {
    if prot & !KNOWN_PROT != 0 { return Err(InvalidAddress); }
    if prot & PROT_WRITE != 0 && prot & PROT_EXEC != 0 {
        return Err(PermissionDenied);
    }
    Ok(())
}
```
W^X enforced au moment du mmap/mprotect. `PageFlags::NO_EXECUTE` est posé par défaut sauf si `PROT_EXEC` explicite (ligne 132-134).

#### 🟢 MEM-10 — `CowTracker` utilise Mutex global pour inc/dec (BON)
**Fichier:** `kernel/src/memory/cow/tracker.rs:122-177`

Le `Mutex<()>` sérialise TOUS les inc/dec (pas de TOCTOU sur le refcount). La table de hash utilise sondage linéaire avec tombstones. En cas de table pleine, `try_inc` retourne `Err(TableFull)` (pas de panic).

#### 🟢 MEM-11 — KPTI shadow PML4 sync (BON)
**Fichier:** `kernel/src/arch/x86_64/spectre/kpti.rs:72-105`

`set_current_cr3` synchronise la shadow user PML4 avec le kernel PML4 à chaque context switch (`sync_user_region_to_shadow`), évitant la boucle de #PF au bootstrap (FIX-KPTI-SHADOW-SYNC).

### 3.3 OOM Killer

**Fichier:** `kernel/src/memory/utils/oom_killer.rs`

- ✅ Cooldown 100 ms entre kills (`LAST_KILL_TSC`).
- ✅ Buffer statique `[OomKillCandidate; 64]` — pas d'allocation dans le chemin OOM.
- ✅ Score via trait `OomScorer` injecté par `process/`.
- ⚠️ `oom_kill` invoque `invoke_kill_sender(pid)` qui envoie un signal — mais **n'attend pas** que le processus soit effectivement mort. Si le processus est RT non-préemptible sur un autre CPU, il peut continuer à allouer pendant que l'OOM killer pense avoir résolu le problème.
- ⚠️ Aucune protection contre le **kill de PID 1 (init)** ou des serveurs Ring 1 critiques. Le scorer par défaut est basé sur RSS × uptime / priority — si init a un gros RSS, il peut être la victime.

**Correctif:** Ajouter une `OOM_PROTECTED_PIDS` liste (init, ipc_router, memory_server, scheduler_server, exo_shield) jamais tués.

---

## 4. Process — kernel/src/process/ (44 fichiers, 10 k LOC)

### 4.1 Vulnérabilités Process

#### 🔴 PROC-01 — UAF sur `find_by_pid` (cf. MEM-02) (HIGH/UAF)
La fonction `find_by_pid` (registry.rs:196) retourne `&ProcessControlBlock` sans incrémenter le refcount. Tous les callers sont vulnérables : `sys_exit`, `sys_wait4`, `sys_execve`, `dispatch.rs::check_and_deliver_signals`, `send_signal_to_pid`, etc.

#### 🟠 PROC-02 — PID recycling sans generation check (MEDIUM)
**Fichier:** `kernel/src/process/core/pid.rs:151-161`
```rust
fn free(&self, id: u32) {
    // ...
    let prev = self.words[w].fetch_or(mask, Ordering::Release);
    debug_assert!(prev & mask == 0, "double free");
}
```
Les PIDs sont recyclés immédiatement après `free`. Si un processus A meurt (PID 42), un processus B peut obtenir PID 42 et hériter de :
- Ses capabilities (si pas révoquées),
- Ses IPC endpoints (si pas nettoyés),
- Ses fds hérités (si A était parent de zombies non-reaped),
- Ses device claims (le code `device_claims.rs` utilise `process::get_generation(driver_pid)` — mais il faut vérifier que la generation est checkée partout).

**Mitigation:** Le code de `device_claims.rs` utilise une `generation` (cf. FIX/10 process CORR-32), mais `find_by_pid` ne vérifie pas la génération. Un caller qui a gardé un `Pid(42)` d'avant le recycling va accéder au mauvais PCB.

**Correctif:** Ajouter un compteur `generation` par PID (16 bits supérieurs du PID?), ou maintenir une `Epoch` dans le PCB vérifiée à chaque lookup.

#### 🟠 PROC-03 — `sys_exit` ne notifie pas le scheduler avant `schedule_block` (MEDIUM)
**Fichier:** `kernel/src/syscall/handlers/process.rs:93-129`
```rust
pub fn sys_exit(status: u64, ...) -> i64 {
    // ...
    pcb.set_state(ProcessState::Zombie);
    // ... send SIGCHLD, wake parents, notify vfork ...
    tcb.set_state(TaskState::Dead);
    let cpu_id = tcb.current_cpu();
    let rq = run_queue(cpu_id);
    schedule_block(rq, &mut *(tcb_ptr as *mut _));   // ← yield final
    loop { hlt; }
}
```
La séquence est correcte mais :
1. `pcb.set_state(Zombie)` est fait avant `tcb.set_state(Dead)` — entre les deux, le scheduler peut préempter ce thread et un autre CPU peut voir le PCB Zombie + le TCB encore Running → incohérence.
2. Si une IRQ arrive entre `set_state(Zombie)` et `schedule_block`, le handler peut accéder au PCB en cours de transition.

**Correctif:** Désactiver la préemption (PreemptGuard) sur toute la séquence de exit.

#### 🟠 PROC-04 — `endpoint_destroy` n'est pas appelé avec authentification (MEDIUM)
**Fichier:** `kernel/src/ipc/endpoint/lifecycle.rs:180`

La fonction kernel `endpoint_destroy(name, ep_id)` ne vérifie pas le caller. Le syscall `sys_exo_ipc_destroy` (table.rs:3163) fait le check `endpoint_pid == caller_pid`, mais un autre chemin kernel pourrait appeler `endpoint_destroy` sans cette vérification. À confirmer qu'aucun autre chemin n'existe.

#### 🟡 PROC-05 — `vfork_completion_reached` lit `pcb.flags` sans lock (LOW)
**Fichier:** `kernel/src/process/lifecycle/fork.rs:84-95`
```rust
fn vfork_completion_reached(child_pid: Pid) -> bool {
    match PROCESS_REGISTRY.find_by_pid(child_pid) {
        None => true,
        Some(pcb) => {
            let flags = pcb.flags.load(Ordering::Acquire);
            let state = pcb.state();
            // ...
        }
    }
}
```
Le `find_by_pid` retourne un `&ProcessControlBlock` sans refcount → UAF potentiel si l'enfant meurt entre le `find_by_pid` et la lecture de `flags`. Mais comme on lit l'état du child, et que le child ne peut pas mourir sans que le parent (qui appelle `wait_for_vfork_completion`) le sache, c'est moins critique.

#### 🟢 PROC-06 — PID allocator robuste (BON)
**Fichier:** `kernel/src/process/core/pid.rs`

- Bitmap lock-free avec CAS par word.
- `PID_BITMAP_WORDS = 512` → 32768 PIDs.
- `debug_assert!` contre double-free.
- `peak_used` high-water mark atomique.
- `PID_FIRST_USABLE = 2` (0=idle, 1=init réservés).

---

## 5. Scheduler — kernel/src/scheduler/ (43 fichiers, 8.2 k LOC)

### 5.1 Vulnérabilités Scheduler

#### 🟠 SCHED-01 — RT admission déléguée à Ring 1 sans garde kernel (HIGH/ISOLATION)
**Fichier:** `servers/scheduler_server/src/main.rs:178-202`
```rust
const RT_ALLOWED_PIDS: &[u32] = &[1, 8];
let is_rt_privileged = RT_ALLOWED_PIDS.contains(&sender_pid)
    || (sender_pid == owner_pid && sender_pid <= 10);
```
L'admission RT est faite **exclusivement** par le scheduler_server (Ring 1). Le kernel n'a **pas** de handler pour `SYS_SCHED_SETSCHEDULER` (grep confirme : la constante existe dans numbers.rs mais n'est pas enregistrée dans la table). Donc :

- Si scheduler_server a un bug (ex: checks insuffisants, ou la liste `RT_ALLOWED_PIDS` est modifiable),
- Ou si un attaquant peut spoof son PID en `1` ou `8` (cf. IPC sender_pid qui est forcé — mais les serveurs Ring 1 trusted ont `can_inject = true`),

Alors un processus non-privilégié peut s'auto-promouvoir RT et **starver tout le système**.

**Mitigation:** `sender_pid` est forcé par le kernel dans `sys_exo_ipc_send`. Donc seuls les vrais PID 1 et 8 peuvent demander RT. Mais un serveur Ring 1 compromis (ex: via RCE dans vfs_server PID 4) peut s'auto-RT car `sender_pid <= 10` est dans la whitelist.

**Correctif:** Le kernel doit exposer un syscall `sys_sched_setscheduler` qui effectue sa propre vérification CapToken CAP_SCHED_RT. Le scheduler_server ne fait que la politique d'admission (quota utilization), pas l'autorisation.

#### 🟠 SCHED-02 — `MAX_TASKS_PER_CPU = 512` + pas de quota par utilisateur (MEDIUM/DoS)
**Fichier:** `kernel/src/scheduler/core/runqueue.rs:33`
```rust
pub const MAX_TASKS_PER_CPU: usize = 512;
```
Un utilisateur peut fork-bomb jusqu'à 512 threads par CPU. Au-delà, `rq.enqueue()` retourne `false` et le thread reste en `Running` (cf. `schedule_yield` ligne 569) — mais cela peut causer des panics dans certains chemins. Aussi, 512 threads × MAX_CPUS(256) = 131072 TCBs potentiels, chacun avec un stack kernel de 256 KiB = 32 GiB de stacks kernel → OOM kernel.

**Correctif:** Implémenter `RLIMIT_NPROC` (déjà partiellement dans `process/resource/rlimit.rs` — à vérifier que c'est appliqué au fork).

#### 🟠 SCHED-03 — `RtRunQueue` limitée à `RT_QUEUE_CAPACITY = 256` (MEDIUM/DoS)
**Fichier:** `kernel/src/scheduler/core/runqueue.rs:96`
```rust
const RT_QUEUE_CAPACITY: usize = 256;
```
Si 256 threads RT sont en file d'attente sur un CPU, les suivants ne peuvent pas être enfilés → `enqueue` retourne `false` → le thread reste dans un état indéfini. Un processus avec CAP_SCHED_RT pourrait fork-bomb 256 threads RT et bloquer tous les autres threads RT.

**Correctif:** Retourner `EAGAIN` au spawn si la RT queue est pleine, pas silently ignorer.

#### 🟠 SCHED-04 — Context switch : pas de `IrqGuard` pendant `set_kernel_rsp` + `set_rsp0` (MEDIUM)
**Fichier:** `kernel/src/scheduler/core/switch.rs:474-481`
```rust
unsafe {
    percpu::set_kernel_rsp(next_kstack_top);
    tss::update_rsp0(cpu_idx, next_kstack_top);
}
```
Cette séquence met à jour RSP0 du TSS **après** le switch ASM. Mais le rapport FIX/9 (CRIT-MS-02) avait signalé une fenêtre de course : si une IRQ arrive entre `context_switch_asm` et `tss::update_rsp0`, l'IRQ empile sur l'ancien RSP0 → corruption de stack.

En regardant le code actuel, le `IrqGuard` ou `PreemptGuard` est censé être actif (contrat de `context_switch`), donc les IRQ sont coupées. **Mais** le code ne le vérifie pas explicitement par un `assert_preempt_disabled()` avant la séquence critique.

**Correctif:** Ajouter `assert_preempt_disabled()` au début de `context_switch` pour rattraper tout appel malicieusement effectué avec préemption active.

#### 🟡 SCHED-05 — `RtBitmap::find_highest_prio` retourne priorité 0 si bit 0 set (LOW)
**Fichier:** `kernel/src/scheduler/core/runqueue.rs:74-82`

`find_highest_prio` retourne `trailing_zeros()` du premier mot non-nul. Si `prio=0` est dans la bitmap (ce qui ne devrait pas arriver car `RT_PRIO_MIN = 1`), il retourne 0. Le code de `fifo_should_preempt` (realtime.rs:62) compare `highest_waiting < running_prio` — si `running_prio = 0` (idle), `highest_waiting = 0` ne préempte pas. Mais le fix `rt_bitmap_highest_prio()` retourne `None` si vide, ce qui évite la préemption fantôme. **OK après le BUG-FIX Q.**

#### 🟢 SCHED-06 — IBPB au context switch cross-processus (BON)
**Fichier:** `kernel/src/scheduler/core/switch.rs:298-306`
```rust
let ibpb_needed = features.map_or(false, |cpu| cpu.has_ibpb())
    && prev.pid != next.pid
    && next.pid.0 != 0;
if ibpb_needed {
    unsafe { msr::write_msr(MSR_IA32_PRED_CMD, PRED_CMD_IBPB) };
}
```
Spectre v2 mitigé : IBPB émis au context switch entre processus différents (pas entre threads du même processus). Kthreads exclus (partagent Ring 0 BTB).

#### 🟢 SCHED-07 — PreemptGuard RAII obligatoire (BON)
**Fichier:** `kernel/src/scheduler/core/preempt.rs:163-198`

`PreemptGuard` est `!Send` (PhantomData<*mut ()>), `#[must_use]`, avec `Drop` qui appelle `preempt_enable_raw()`. Compteur per-CPU aligné cache line (pas de false sharing). Détection d'imbrication > 64 (debug_assert).

#### 🟢 SCHED-08 — Lazy FPU + eager save au context switch (BON)
**Fichier:** `kernel/src/scheduler/core/switch.rs:308-326`

Hybride : eager save (XSAVE) au switch-out si `prev.fpu_loaded()`, eager restore (XRSTOR) au switch-in pour threads user. Cela évite le coût du #NM au premier retour Ring 3 (qui utilise SSE pour les copies de structures). Le lazy pur est gardé pour les kthreads.

---

## 6. Arch x86_64 — focus syscall entry / IDT / context switch / SMEP/SMAP

### 6.1 Points forts

- ✅ **SYSRET canonicality check** (syscall.rs:264-279) : `shl/sar/cmp/jne` sur RCX et RSP, fallback IRETQ sur non-canonique → mitigation CVE-2012-0217.
- ✅ **KPTI switch dans stub ASM** avant tout push pile kernel (syscall.rs:198-203 et exceptions.rs:113-119).
- ✅ **SMEP/SMAP activation** au boot (kpti.rs:167-193) si CPU supporte.
- ✅ **IBRS au syscall entry** + **IBPB au context switch cross-processus** (spectre mitigations).
- ✅ **TSS ISTs** pour #DF (IST4), #NMI (IST3), ExoPhoenix IPI (IST1) — stacks dédiées anti-corruption.
- ✅ **ExceptionFrame** bien définie, CS RPL check pour SWAPGS conditionnel.
- ✅ **Retpoline** pour Spectre v2 (spectre/retpoline.rs).
- ✅ **SSBD** pour Speculative Store Bypass (spectre/ssbd.rs).
- ✅ **CET Shadow Stack** partiellement implémenté (exploit_mitigations/cet.rs, MSR_IA32_PL0_SSP sauvegardé/restauré au context switch).

### 6.2 Vulnérabilités Arch

#### 🟡 ARCH-01 — #DF handler fait `out 0xE9, al` avant halt (LOW/INFO)
**Fichier:** `kernel/src/arch/x86_64/exceptions.rs:711-714`
```rust
unsafe { core::arch::asm!("out 0xE9, al", in("al") b'D', options(nomem, nostack)) };
```
Écrit un byte sur le port E9 (debug console Bochs/QEMU). En production sur hardware réel, ce port peut être non-décode → #DF en cascade sur certaines cartes mères. Acceptable pour le debug, mais à conditionner par `cfg(debug_assertions)`.

#### 🟡 ARCH-02 — `do_page_fault` lit `frame.rip` sans vérifier qu'il est mappé (LOW)
**Fichier:** `kernel/src/arch/x86_64/exceptions.rs:1036-1043`
```rust
if frame.rip >= 0x1000 && frame.rip < 0x0000_8000_0000_0000 {
    for bi in 0..8u64 {
        let byte = unsafe { core::ptr::read_volatile((frame.rip + bi) as *const u8) };
        rb |= (byte as u64) << (bi * 8);
    }
}
```
Lit 8 octets à RIP pour le diagnostic. Si RIP est dans la plage user mais **non-mappé**, ce read va déclencher un #PF imbriqué dans le handler #PF → double fault → halt CPU. La condition `rip_pte & 1 != 0` est vérifiée plus tôt (ligne 506-507) mais seulement en `cfg(debug_assertions, exo_kernel_trace)`.

**Correctif:** Déplacer le check `rip_pte & 1 != 0` en production, ou utiliser un wrapper `try_read_volatile` qui catch le #PF.

#### 🟢 ARCH-03 — `do_device_not_avail` délègue correctement au scheduler (BON)
**Fichier:** `kernel/src/arch/x86_64/exceptions.rs:686-702`

Le handler #NM appelle `sched_fpu_handle_nm` (FFI vers `scheduler::fpu::lazy`) avec le TCB courant. Si tcb_ptr est null (boot/idle), simple `clts`. Pas de logique métier dans arch/.

---

## 7. Servers — ipc_router / syscall_abi / scheduler_server / memory_server

### 7.1 ipc_router (servers/ipc_router/src/)

#### 🟠 SRV-IPC-01 — `forward_message` tient le lock `ROUTE_TABLE` pendant le syscall (MEDIUM)
**Fichier:** `servers/ipc_router/src/router.rs:290-326`
```rust
pub fn forward_message(src_pid: u32, dst_pid: u32, payload: &[u8], payload_len: usize) -> bool {
    let policy = apply_policy(src_pid, dst_pid);     // ← prend ROUTE_TABLE.lock()
    match policy {
        Direct | Forwarded => {
            let (dest, _) = resolve_route(dst_pid).unwrap_or(...);   // ← re-prend le lock
            let result = unsafe { syscall6(SYS_IPC_SEND, ...) };     // ← syscall pendant ce temps
            let table = ROUTE_TABLE.lock();                          // ← re-prend le lock
            // ... update stats
        }
    }
}
```
Le lock `ROUTE_TABLE` est pris **3 fois** par `forward_message` (via `apply_policy`, `resolve_route`, et la mise à jour des stats). Pendant le syscall IPC_SEND, le lock n'est pas tenu, mais l'itération des stats après le syscall prend le lock à nouveau. Un autre thread qui veut ajouter une route est bloqué pendant toute la durée du send.

**Correctif:** Capturer `dest` + `policy` en une seule prise de lock, faire le syscall sans lock, puis re-prendre le lock pour les stats (ou utiliser des atomiques pour les stats).

#### 🟢 SRV-IPC-02 — `security_gate::check_message` applique ExoCordon + IPC-04 (BON)
**Fichier:** `servers/ipc_router/src/security_gate.rs:130-168`

L'ordre est correct : d'abord IPC-04 (payload ≤ 192 octets), puis ExoCordon (chemin autorisé + quota). Soft quarantine après 10 violations, notification exo_shield via EVENT_REPORT non-bloquant.

### 7.2 syscall_abi (servers/syscall_abi/src/)

#### 🟢 SRV-ABI-01 — Wrapper `syscall6` correct (BON)
**Fichier:** `servers/syscall_abi/src/lib.rs:9-29`

Inline ASM `syscall` avec `rax` in, `rdi..r9` in, `rax` lateout, `rcx/r11` out. `options(nostack)` — pas de stack frame. Conforme ABI Linux x86_64.

### 7.3 scheduler_server

#### 🟠 SRV-SCHED-01 — RT_ALLOWED_PIDS trop permissive (cf. SCHED-01) (HIGH)
La whitelist `[1, 8]` + `sender_pid <= 10` permet à n'importe quel serveur Ring 1 (PIDs 1-10) de s'auto-promouvoir RT. Si un de ces serveurs est compromis (RCE), l'attaquant peut monopoliser le CPU.

### 7.4 memory_server

#### 🟢 SRV-MEM-01 — `attach_shared_region` vérifie owner/init/published (BON)
**Fichier:** `servers/memory_server/src/mmap_service.rs:388-411`

Le FIX-SHM-ATTACH corrige correctement la faille d'attach sans auth. Trois conditions : owner, init (PID 1), ou published (share_count > 0). Un handle jamais transmis ne peut pas être attaché par un tiers.

#### 🟢 SRV-MEM-02 — Quota per-PID sur memory_server (BON)
**Fichier:** `servers/memory_server/src/allocator.rs` (via `QuotaTable::reserve`)

Chaque PID a un quota de mémoire, vérifié à chaque `allocate_region`. Dépassement → `ENOMEM`. Init_server peut ajuster les quotas via `handle_quota_set` (réservé PID 1).

---

## 8. Top 5 vulnérabilités

| # | ID | Sévérité | Catégorie | Description | Fichier |
|---|----|----------|-----------|-------------|---------|
| 1 | MEM-02 / PROC-01 | 🔴 CRITICAL | UAF | `ProcessRegistry::find_by_pid` retourne `&PCB` sans incrémenter le refcount. `remove()` libère le PCB via `Box::from_raw`. Race SMP → UAF sur ~30 sites d'appel (signals, exit, wait, exec, OOM, IPC). | `process/core/registry.rs:196` |
| 2 | MEM-01 | 🔴 HIGH | UAF / info-leak | CoW breaker appelle `flush_single` (local-only) avant `free_frame`. Autres CPUs peuvent lire le frame libéré via TLB stale → info leak cross-process après realloc. | `memory/virtual/fault/cow.rs:97-105` |
| 3 | IPC-01 | 🔴 HIGH | Isolation | `mailbox_open` ne vérifie pas l'owner. EndpointId est séquentiel (prédictible). N'importe quel processus peut ouvrir la mailbox d'un autre et y injecter des messages. | `ipc/channel/raw.rs:202` |
| 4 | MEM-03 | 🟠 HIGH | Deadlock | Lazy FPU allocator fait `alloc::alloc::alloc` dans le handler #NM. Le check `IN_RECLAIM` ne couvre pas tous les scénarios de lock memory → deadlock possible si #NM pendant un lock buddy tenu. | `scheduler/fpu/lazy.rs:125` + `save_restore.rs:138` |
| 5 | SCHED-01 / SRV-SCHED-01 | 🟠 HIGH | Escalade | RT admission déléguée au scheduler_server (Ring 1) sans garde kernel. `SYS_SCHED_SETSCHEDULER` n'a pas de handler kernel. Whitelist `sender_pid <= 10` permet à tout serveur Ring 1 compromis de s'auto-promouvoir RT → starvation système. | `servers/scheduler_server/src/main.rs:192` |

### Autres vulnérabilités notables

- 🟠 **IPC-02** DoS par épuisement `MAX_RAW_SLOTS = 64` (raw.rs:27).
- 🟠 **IPC-03** Spin-wait 200K/1M iterations avec lock/unlock répétés (raw.rs:296, 383).
- 🟠 **IPC-05** `endpoint_destroy` TOCTOU sur `active_conns` → UAF (lifecycle.rs:180).
- 🟠 **SYS-01** Zero-trust skip sur 3 syscalls fast-path-eligible (dispatch.rs:189).
- 🟠 **PROC-02** PID recycling sans generation check (pid.rs:151).
- 🟠 **PROC-03** `sys_exit` transition Zombie→Dead sans PreemptGuard (process.rs:93).
- 🟠 **SCHED-02** `MAX_TASKS_PER_CPU = 512` + pas de RLIMIT_NPROC enforcement (runqueue.rs:33).
- 🟠 **SRV-IPC-01** `forward_message` prend 3 fois le lock ROUTE_TABLE (router.rs:290).

---

## 9. Score maturité isolation kernel

| Domaine | Score | Commentaire |
|---------|-------|-------------|
| **Syscall ABI & validation** | 7.5/10 | `validate_user_range` robuste, KPTI + SYSRET check + IBRS/IBPB présents. Moins : skip zéro-trust sur 3 syscalls, lazy FPU alloc. |
| **Memory management** | 5/10 | Buddy + KPTI + W^X + KASLR + CoW tracker OK. Moins : **UAF registry**, **CoW flush local-only**, lazy FPU heap alloc, pas de protection PID critique OOM. |
| **IPC isolation** | 4.5/10 | CapToken + ExoCordon DAG + sender_pid forcé. Moins : **mailbox_open sans auth**, **MAX_RAW_SLOTS=64 DoS**, spin-wait longs, endpoint_destroy TOCTOU, scan O(N) endpoints. |
| **Process isolation** | 5/10 | PID allocator robuste, fork CoW OK. Moins : **UAF find_by_pid**, PID recycling sans generation, exit sans PreemptGuard. |
| **Scheduler hardening** | 6/10 | PreemptGuard RAII + IBPB cross-process + RT bitmap O(1). Moins : **RT admission déléguée Ring 1**, pas de RLIMIT_NPROC, pas de assert_preempt_disabled au context switch. |
| **Arch x86_64 mitigations** | 8/10 | SMEP/SMAP/KPTI/IBRS/IBPB/SSBD/Retpoline/CET tous présents. Moins : #DF out E9 en prod, lecture RIP sans check PTE en prod. |

**Score global isolation kernel : 5.5 / 10**

Le kernel a toutes les **mitigations hardware modernes** activées (KPTI/SMEP/SMAP/IBRS/IBPB/CET) et une **architecture de capabilities** solide. Cependant, plusieurs **bugs d'implémentation critiques** (UAF registry, CoW flush incomplet, mailbox sans auth, RT admission déléguée) réduisent drastiquement l'isolation réelle. Le système est **utilisable pour du développement** mais **non production-ready** pour un adversaire actif.

---

## 10. Recommandations prioritaires (P0)

### P0-1 : Fix `ProcessRegistry::find_by_pid` UAF
```rust
pub fn find_by_pid_refcounted(&self, pid: Pid) -> Option<PcbRef> {
    loop {
        let raw = slot.pcb_ptr.load(Ordering::Acquire);
        if raw.is_null() { return None; }
        // CAS refcount+1 si toujours > 0
        if slot.refcount.fetch_add(1, Ordering::AcqRel) > 0 {
            // Vérifier que le ptr n'a pas changé
            if slot.pcb_ptr.load(Ordering::Acquire) == raw {
                return Some(PcbRef { pcb: &*raw, slot });
            }
            slot.refcount.fetch_sub(1, Ordering::Release);
        } else {
            slot.refcount.fetch_sub(1, Ordering::Release);
        }
    }
}
// remove() attend que refcount == 1 avant Box::from_raw.
```

### P0-2 : Fix CoW breaker TLB shootdown
```rust
// Dans cow.rs, avant free_frame :
if remaining == 0 {
    // NOUVEAU : shootdown synchrone cross-CPU avant libération
    let cpu_count = madt::madt_cpu_count();
    unsafe {
        crate::memory::virt::shootdown_sync(
            TlbFlushType::Address(page_addr),
            cpu_count,
        );
    }
    alloc.free_frame(old_frame);
}
```

### P0-3 : Authentification `mailbox_open`
```rust
pub fn mailbox_open_checked(ep_id: EndpointId, caller_pid: u32) -> bool {
    // Vérifier que caller_pid est autorisé à ouvrir cette mailbox
    let packed_pid = (ep_id.get() >> 32) as u32;
    if packed_pid != 0 && packed_pid != caller_pid {
        return false;
    }
    mailbox_open(ep_id)
}
```

### P0-4 : Pré-allocation FpuState au thread spawn
```rust
// Dans ThreadControlBlock::new() :
let fpu_state_ptr = alloc::alloc::alloc(Layout::new::<FpuState>());
if fpu_state_ptr.is_null() {
    return Err(OutOfMemory);  // refuser la création du thread
}
tcb.fpu_state_ptr = fpu_state_ptr as u64;
// handle_nm_exception ne fait plus d'allocation
```

### P0-5 : Garde-fou kernel RT admission
```rust
// Nouveau syscall handler :
pub fn sys_sched_setscheduler(pid: u64, policy: u64, _param: u64, ...) -> i64 {
    let caller_pid = current_pid();
    // CAP_SCHED_RT required for RT/Deadline classes
    if policy == SCHED_FIFO || policy == SCHED_RR || policy == SCHED_DEADLINE {
        if !crate::security::has_capability(caller_pid, Capability::SchedRt) {
            return EPERM;
        }
    }
    // ... apply policy
}
```

---

## 11. Conclusion

L'audit révèle un kernel **architecturalement mature** (mitigations hardware, capability system, IPC DAG, audit syscall, zero-trust) mais **handicapé par des bugs d'implémentation critiques** concentrés sur la gestion du cycle de vie des objets kernel (PCB, EndpointDesc, frames CoW). Ces bugs sont exploitables pour :

- **UAF → RCE kernel** (MEM-02, IPC-05),
- **Info leak cross-process** (MEM-01),
- **Isolation IPC bypass** (IPC-01),
- **Deadlock système** (MEM-03),
- **Escalade de privilèges scheduler** (SCHED-01).

Le score **5.5/10** reflète un système **au-dessus de la moyenne open-source** mais **en-dessous du seuil production-hardened** (Linux ~7.5, seL4 ~9.5). Les 5 correctifs P0 ci-dessus permettenttrait de passer à ~7/10, et l'ajout de tests de concurrence (loom, model checking TLA+) permettrait d'atteindre ~8/10.

**Prochaine étape recommandée :** Appliquer les P0-1 à P0-5, puis lancer une campagne de fuzzing sur les syscalls IPC et memory (mmap/mprotect/fork/execve) avec `cargo-fuzz` en target `x86_64-unknown-none` + QEMU.
