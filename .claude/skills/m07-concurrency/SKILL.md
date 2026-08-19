---
name: m07-concurrency
description: Use when working on threading, shared state or lock design in Rust. Covers Send/Sync bounds, Mutex/RwLock/atomics, channels, deadlock and race analysis. This project is threads-only, with no async runtime anywhere — the device event loop in `device/mod.rs` runs N worker threads over `Arc<Mutex<Peer>>`, a hand-rolled reader/writer `dev_lock`, and per-thread `ThreadData` buffers. Triggers on E0277 Send/Sync, cannot be sent between threads, thread, spawn, channel, mpsc, Mutex, RwLock, parking_lot, Atomic, Ordering, deadlock, race condition, lock contention.
---

# Concurrency

> **Layer 1: Language Mechanics**

## Core Question

**Is this CPU-bound or I/O-bound, and what's the sharing model?**

Before choosing concurrency primitives:
- What's the workload type?
- What data needs to be shared?
- What's the thread safety requirement?

---

## Error → Design Question

| Error | Don't Just Say | Ask Instead |
|-------|----------------|-------------|
| E0277 Send | "Add Send bound" | Should this type cross threads? |
| E0277 Sync | "Wrap in Mutex" | Is shared access really needed? |
| Future not Send | "Use spawn_local" | Is async the right choice? |
| Deadlock | "Reorder locks" | Is the locking design correct? |

---

## Thinking Prompt

Before adding concurrency:

1. **What's the workload?**
   - CPU-bound → threads (std::thread, rayon)
   - I/O-bound → async (tokio, async-std)
   - Mixed → hybrid approach

2. **What's the sharing model?**
   - No sharing → message passing (channels)
   - Immutable sharing → Arc<T>
   - Mutable sharing → Arc<Mutex<T>> or Arc<RwLock<T>>

3. **What are the Send/Sync requirements?**
   - Cross-thread ownership → Send
   - Cross-thread references → Sync
   - Single-thread async → spawn_local

---

## Trace Up ↑

Don't just fix the error. Trace up to the constraint that caused it.

### This project's concurrency model

There is no async runtime here — no tokio, no `.await`, anywhere. `awgtun`
runs a fixed pool of OS threads, each in its own event loop over epoll (Linux)
or kqueue (macOS). Reach for threads, locks and atomics; treat any suggestion to
"just make it async" as out of scope.

| Where | Shape |
|-------|-------|
| `device/mod.rs` | `n_threads` workers, each with its own `ThreadData` buffers and TUN queue |
| `device/dev_lock.rs` | Hand-rolled reader/writer lock; workers hold a read lock, `set=1` takes it writeable |
| `Arc<Mutex<Peer>>` | Every peer, reachable from all workers and from three index maps |
| `AtomicUsize`, `AtomicBool` | Interface MTU, rate-limiter counters |

Two invariants worth knowing before touching a lock here. A worker must not hold
a peer lock across a blocking send. And the peer index maps (`peers`,
`peers_by_idx`, `peers_by_ip`) all point at the *same* `Arc`, so a peer is
mutated in place rather than replaced — see `Device::set_amnezia_config`.

### Generic Trace

```
"Send not satisfied for my type"
    ↑ Ask: Does this type need to cross thread boundaries at all?
    ↑ Ask: Is it reachable from a worker, or owned by one?
```

| Situation | Trace To | Question |
|-----------|----------|----------|
| Raw pointer is not Send | unsafe-checker | Is the `unsafe impl Send` justified? |
| Mutex vs channels | m02-resource | Shared state or message passing? |
| Lock contention on the packet path | m10-performance | Measured, or assumed? |
| Ordering on an atomic | unsafe-checker | What does `Relaxed` actually guarantee here? |

---

## Trace Down ↓

From design to implementation:

```
"Need parallelism for CPU work"
    ↓ Use: std::thread or rayon

"Need concurrency for I/O"
    ↓ Use: async/await with tokio

"Need to share immutable data across threads"
    ↓ Use: Arc<T>

"Need to share mutable data across threads"
    ↓ Use: Arc<Mutex<T>> or Arc<RwLock<T>>
    ↓ Or: channels for message passing

"Need simple atomic operations"
    ↓ Use: AtomicBool, AtomicUsize, etc.
```

---

## Send/Sync Markers

| Marker | Meaning | Example |
|--------|---------|---------|
| `Send` | Can transfer ownership between threads | Most types |
| `Sync` | Can share references between threads | `Arc<T>` |
| `!Send` | Must stay on one thread | `Rc<T>` |
| `!Sync` | No shared refs across threads | `RefCell<T>` |

## Quick Reference

| Pattern | Thread-Safe | Blocking | Use When |
|---------|-------------|----------|----------|
| `std::thread` | Yes | Yes | CPU-bound parallelism |
| `async/await` | Yes | No | I/O-bound concurrency |
| `Mutex<T>` | Yes | Yes | Shared mutable state |
| `RwLock<T>` | Yes | Yes | Read-heavy shared state |
| `mpsc::channel` | Yes | Optional | Message passing |
| `Arc<Mutex<T>>` | Yes | Yes | Shared mutable across threads |

## Decision Flowchart

```
What type of work?
├─ CPU-bound → std::thread or rayon
├─ I/O-bound → async/await
└─ Mixed → hybrid (spawn_blocking)

Need to share data?
├─ No → message passing (channels)
├─ Immutable → Arc<T>
└─ Mutable →
   ├─ Read-heavy → Arc<RwLock<T>>
   └─ Write-heavy → Arc<Mutex<T>>
   └─ Simple counter → AtomicUsize

Async context?
├─ Type is Send → tokio::spawn
├─ Type is !Send → spawn_local
└─ Blocking code → spawn_blocking
```

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| E0277 `Send` not satisfied | Non-Send in async | Use Arc or spawn_local |
| E0277 `Sync` not satisfied | Non-Sync shared | Wrap with Mutex |
| Deadlock | Lock ordering | Consistent lock order |
| `future is not Send` | Non-Send across await | Drop before await |
| `MutexGuard` across await | Guard held during suspend | Scope guard properly |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| Arc<Mutex<T>> everywhere | Contention, complexity | Message passing |
| thread::sleep in async | Blocks executor | tokio::time::sleep |
| Holding locks across await | Blocks other tasks | Scope locks tightly |
| Ignoring deadlock risk | Hard to debug | Lock ordering, try_lock |

---

## Async-Specific Patterns

### Avoid MutexGuard Across Await

```rust
// Bad: guard held across await
let guard = mutex.lock().await;
do_async().await;  // guard still held!

// Good: scope the lock
{
    let guard = mutex.lock().await;
    // use guard
}  // guard dropped
do_async().await;
```

### Non-Send Types in Async

```rust
// Rc is !Send, can't cross await in spawned task
// Option 1: use Arc instead
// Option 2: use spawn_local (single-thread runtime)
// Option 3: ensure Rc is dropped before .await
```

---

## Related Skills

| When | See |
|------|-----|
| Smart pointer choice, interior mutability | m02-resource |
| Performance tuning, lock contention | m10-performance |
| `unsafe impl Send`/`Sync`, atomics ordering | unsafe-checker |
| Borrow errors behind a lock guard | m01-ownership |
