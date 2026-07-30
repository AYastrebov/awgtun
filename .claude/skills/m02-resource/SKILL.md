---
name: m02-resource
description: Use when choosing a smart pointer or deciding who releases a resource. Covers Box/Rc/Arc/Weak, interior mutability, RAII and Drop. This project is multi-threaded, so `Arc<Mutex<_>>` is the norm and `Rc`/`RefCell` are the wrong reach; the resources that actually matter are OS-owned — TUN and UDP file descriptors, epoll/kqueue registrations — and the FFI and JNI handles, which are raw pointers the caller must hand back to `tunnel_free`. Triggers on Box, Rc, Arc, Weak, RefCell, Cell, smart pointer, heap allocation, reference counting, RAII, Drop, leak, file descriptor ownership, Arc vs Rc.
---

# Resource Management

> **Layer 1: Language Mechanics**

## Core Question

**What ownership pattern does this resource need?**

Before choosing a smart pointer, understand:
- Is ownership single or shared?
- Is access single-threaded or multi-threaded?
- Are there potential cycles?

---

## Error → Design Question

| Error | Don't Just Say | Ask Instead |
|-------|----------------|-------------|
| "Need heap allocation" | "Use Box" | Why can't this be on stack? |
| Rc memory leak | "Use Weak" | Is the cycle necessary in design? |
| RefCell panic | "Use try_borrow" | Is runtime check the right approach? |
| Arc overhead complaint | "Accept it" | Is multi-thread access actually needed? |

---

## Thinking Prompt

Before choosing a smart pointer:

1. **What's the ownership model?**
   - Single owner → Box or owned value
   - Shared ownership → Rc/Arc
   - Weak reference → Weak

2. **What's the thread context?**
   - Single-thread → Rc, Cell, RefCell
   - Multi-thread → Arc, Mutex, RwLock

3. **Are there cycles?**
   - Yes → One direction must be Weak
   - No → Regular Rc/Arc is fine

---

## Trace Up ↑

When pointer choice is unclear, trace to design:

```
"Should I use Arc or Rc?"
    ↑ Ask: Is this data shared across threads?
    ↑ Check: m07-concurrency (thread model)
```

| Situation | Trace To | Question |
|-----------|----------|----------|
| Rc vs Arc confusion | m07-concurrency | What's the concurrency model? |
| Lock held too long | m07-concurrency | Should the guard be dropped earlier? |
| A handle leaks across FFI | unsafe-checker | Who calls `tunnel_free`, and when? |

In this repo the answer to "Rc or Arc" is always Arc: every peer lives in an
`Arc<Mutex<Peer>>` reachable from several worker threads at once. `Rc` and
`RefCell` in a `Device` or `Tunn` path are a mistake, not a trade-off.

---

## Trace Down ↓

From design to implementation:

```
"Need single-owner heap data"
    ↓ Use: Box<T>

"Need shared immutable data (single-thread)"
    ↓ Use: Rc<T>

"Need shared immutable data (multi-thread)"
    ↓ Use: Arc<T>

"Need to break reference cycle"
    ↓ Use: Weak<T>

"Need shared mutable data"
    ↓ Single-thread: Rc<RefCell<T>>
    ↓ Multi-thread: Arc<Mutex<T>> or Arc<RwLock<T>>
```

---

## Quick Reference

| Type | Ownership | Thread-Safe | Use When |
|------|-----------|-------------|----------|
| `Box<T>` | Single | Yes | Heap allocation, recursive types |
| `Rc<T>` | Shared | No | Single-thread shared ownership |
| `Arc<T>` | Shared | Yes | Multi-thread shared ownership |
| `Weak<T>` | Weak ref | Same as Rc/Arc | Break reference cycles |
| `Cell<T>` | Single | No | Interior mutability (Copy types) |
| `RefCell<T>` | Single | No | Interior mutability (runtime check) |

## Decision Flowchart

```
Need heap allocation?
├─ Yes → Single owner?
│        ├─ Yes → Box<T>
│        └─ No → Multi-thread?
│                ├─ Yes → Arc<T>
│                └─ No → Rc<T>
└─ No → Stack allocation (default)

Have reference cycles?
├─ Yes → Use Weak for one direction
└─ No → Regular Rc/Arc

Need interior mutability?
├─ Yes → Thread-safe needed?
│        ├─ Yes → Mutex<T> or RwLock<T>
│        └─ No → T: Copy? → Cell<T> : RefCell<T>
└─ No → Use &mut T
```

---

## Common Errors

| Problem | Cause | Fix |
|---------|-------|-----|
| Rc cycle leak | Mutual strong refs | Use Weak for one direction |
| RefCell panic | Borrow conflict at runtime | Use try_borrow or restructure |
| Arc overhead | Atomic ops in hot path | Consider Rc if single-threaded |
| Box unnecessary | Data fits on stack | Remove Box |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| Arc everywhere | Unnecessary atomic overhead | Use Rc for single-thread |
| RefCell everywhere | Runtime panics | Design clear ownership |
| Box for small types | Unnecessary allocation | Stack allocation |
| Ignore Weak for cycles | Memory leaks | Design parent-child with Weak |

---

## Related Skills

| When | See |
|------|-----|
| Ownership errors | m01-ownership |
| Multi-thread context, lock choice | m07-concurrency |
| File descriptors, raw handles, `Drop` across FFI | unsafe-checker |
| Allocation on the packet path | m10-performance |
