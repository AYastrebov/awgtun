---
name: m01-ownership
description: Use when a borrow-checker error needs a design answer rather than a `.clone()`. Treats each error as a question about who should own the data and for how long. Relevant here because the packet path is built on borrowed slices with explicit lifetimes — `TunnResult<'a>` and `Packet<'a>` borrow the caller's buffers, and `PacketClassifier<'a>` borrows the config — so a lifetime error usually means the buffer split is wrong, not that something needs copying. Triggers on E0382, E0597, E0506, E0507, E0515, E0716, E0106, E0499, E0502, value moved, borrowed value does not live long enough, cannot move out of, cannot borrow as mutable, ownership, borrow, lifetime, `'a`, `'static`.
---

# Ownership & Lifetimes

> **Layer 1: Language Mechanics**

## Core Question

**Who should own this data, and for how long?**

Before fixing ownership errors, understand the data's role:
- Is it shared or exclusive?
- Is it short-lived or long-lived?
- Is it transformed or just read?

---

## Error → Design Question

| Error | Don't Just Say | Ask Instead |
|-------|----------------|-------------|
| E0382 | "Clone it" | Who should own this data? |
| E0597 | "Extend lifetime" | Is the scope boundary correct? |
| E0506 | "End borrow first" | Should mutation happen elsewhere? |
| E0507 | "Clone before move" | Why are we moving from a reference? |
| E0515 | "Return owned" | Should caller own the data? |
| E0716 | "Bind to variable" | Why is this temporary? |
| E0106 | "Add 'a" | What is the actual lifetime relationship? |

---

## Thinking Prompt

Before fixing an ownership error, ask:

1. **What is this data's domain role?**
   - Entity (unique identity) → owned
   - Value Object (interchangeable) → clone/copy OK
   - Temporary (computation result) → maybe restructure

2. **Is the ownership design intentional?**
   - By design → work within constraints
   - Accidental → consider redesign

3. **Fix symptom or redesign?**
   - If Strike 3 (3rd attempt) → escalate to Layer 2

---

## Trace Up ↑

When errors persist, trace to design layer:

```
E0382 (moved value)
    ↑ Ask: What design choice led to this ownership pattern?
    ↑ Check: does the protocol require this data to outlive the call?
             (AMNEZIA.md, amneziawg-go)
```

| Persistent Error | Trace To | Question |
|-----------------|----------|----------|
| E0382 repeated | m02-resource | Should use Arc for sharing? |
| E0597 repeated | amnezia-dev | Is the buffer boundary in the right place? |
| E0506/E0507 | m02-resource | Should the owner hold this behind a lock? |

In this repo, "trace up" usually means the wire format: `TunnResult<'a>` borrows
the caller's `dst`, so a lifetime that will not close is often a sign that the
padding prefix and the message body were split at the wrong offset. See
`AMNEZIA.md` and the `amnezia-dev` skill.

---

## Trace Down ↓

From design decisions to implementation:

```
"Data needs to be shared immutably"
    ↓ Use: Arc<T> (multi-thread) or Rc<T> (single-thread)

"Data needs exclusive ownership"
    ↓ Use: move semantics, take ownership

"Data is read-only view"
    ↓ Use: &T (immutable borrow)
```

---

## Quick Reference

| Pattern | Ownership | Cost | Use When |
|---------|-----------|------|----------|
| Move | Transfer | Zero | Caller doesn't need data |
| `&T` | Borrow | Zero | Read-only access |
| `&mut T` | Exclusive borrow | Zero | Need to modify |
| `clone()` | Duplicate | Alloc + copy | Actually need a copy |
| `Rc<T>` | Shared (single) | Ref count | Single-thread sharing |
| `Arc<T>` | Shared (multi) | Atomic ref count | Multi-thread sharing |
| `Cow<T>` | Clone-on-write | Alloc if mutated | Might modify |

## Error Code Reference

| Error | Cause | Quick Fix |
|-------|-------|-----------|
| E0382 | Value moved | Clone, reference, or redesign ownership |
| E0597 | Reference outlives owner | Extend owner scope or restructure |
| E0506 | Assign while borrowed | End borrow before mutation |
| E0507 | Move out of borrowed | Clone or use reference |
| E0515 | Return local reference | Return owned value |
| E0716 | Temporary dropped | Bind to variable |
| E0106 | Missing lifetime | Add `'a` annotation |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| `.clone()` everywhere | Hides design issues | Design ownership properly |
| Fight borrow checker | Increases complexity | Work with the compiler |
| `'static` for everything | Restricts flexibility | Use appropriate lifetimes |
| Leak with `Box::leak` | Memory leak | Proper lifetime design |

---

## Related Skills

| When | See |
|------|-----|
| Need smart pointers or shared ownership | m02-resource |
| Sharing across the device's worker threads | m07-concurrency |
| The lifetime crosses an FFI or JNI boundary | unsafe-checker |
| The buffer layout is protocol-driven | amnezia-dev, `AMNEZIA.md` |
