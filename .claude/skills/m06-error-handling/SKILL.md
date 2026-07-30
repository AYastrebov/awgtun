---
name: m06-error-handling
description: Use when designing or changing how failures are represented in Rust — whether to panic or return Result, how to shape an error enum, and how much context to carry. This is a library, so the library half of the guidance applies: `ConfigError` in `amnezia.rs` and `WireGuardError` in `noise/errors.rs` are `#[non_exhaustive]` enums a caller matches on, and the FFI and JNI surfaces must turn every failure into a null handle or a status rather than unwind across the boundary. Triggers on Result, Option, `?`, unwrap, expect, panic, thiserror, anyhow, custom error, error propagation, when to panic vs return Result.
---

# Error Handling

> **Layer 1: Language Mechanics**

## Core Question

**Is this failure expected or a bug?**

Before choosing error handling strategy:
- Can this fail in normal operation?
- Who should handle this failure?
- What context does the caller need?

---

## Error → Design Question

| Pattern | Don't Just Say | Ask Instead |
|---------|----------------|-------------|
| unwrap panics | "Use ?" | Is None/Err actually possible here? |
| Type mismatch on ? | "Use anyhow" | Are error types designed correctly? |
| Lost error context | "Add .context()" | What does the caller need to know? |
| Too many error variants | "Use Box<dyn Error>" | Is error granularity right? |

---

## Thinking Prompt

Before handling an error:

1. **What kind of failure is this?**
   - Expected → Result<T, E>
   - Absence normal → Option<T>
   - Bug/invariant → panic!
   - Unrecoverable → panic!

2. **Who handles this?**
   - Caller → propagate with ?
   - Current function → match/if-let
   - User → friendly error message
   - Programmer → panic with message

3. **What context is needed?**
   - Type of error → thiserror variants
   - Call chain → anyhow::Context
   - Debug info → anyhow or tracing

---

## Trace Up ↑

When error strategy is unclear:

```
"Should I return Result or Option?"
    ↑ Ask: Is absence/failure normal or exceptional?
    ↑ Check: what does the protocol require? (AMNEZIA.md, amneziawg-go)
```

| Situation | Trace To | Question |
|-----------|----------|----------|
| Too many unwraps | m01-ownership | Is the data model right? |
| Rejecting a config | amnezia-dev | Does the reference implementation reject it too? |
| An error crosses a C or JNI boundary | unsafe-checker | Can this unwind? What does the caller see? |

Two rules this codebase already follows, worth keeping in mind before adding a
variant. A malformed *packet* is not an error to report — it is dropped, because
an attacker chooses its contents. A malformed *configuration* is an error, and
it must be rejected only where amneziawg-go also rejects it; inventing stricter
validation has made real servers unreachable here more than once.

---

## Trace Down ↓

From design to implementation:

```
"Expected failure, library code"
    ↓ Use: thiserror for typed errors

"Expected failure, application code"
    ↓ Use: anyhow for ergonomic errors

"Absence is normal (find, get, lookup)"
    ↓ Use: Option<T>

"Bug or invariant violation"
    ↓ Use: panic!, assert!, unreachable!

"Need to propagate with context"
    ↓ Use: .context("what was happening")
```

---

## Quick Reference

| Pattern | When | Example |
|---------|------|---------|
| `Result<T, E>` | Recoverable error | `fn read() -> Result<String, io::Error>` |
| `Option<T>` | Absence is normal | `fn find() -> Option<&Item>` |
| `?` | Propagate error | `let data = file.read()?;` |
| `unwrap()` | Dev/test only | `config.get("key").unwrap()` |
| `expect()` | Invariant holds | `env.get("HOME").expect("HOME set")` |
| `panic!` | Unrecoverable | `panic!("critical failure")` |

## Library vs Application

| Context | Error Crate | Why |
|---------|-------------|-----|
| Library | `thiserror` | Typed errors for consumers |
| Application | `anyhow` | Ergonomic error handling |
| Mixed | Both | thiserror at boundaries, anyhow internally |

## Decision Flowchart

```
Is failure expected?
├─ Yes → Is absence the only "failure"?
│        ├─ Yes → Option<T>
│        └─ No → Result<T, E>
│                 ├─ Library → thiserror
│                 └─ Application → anyhow
└─ No → Is it a bug?
        ├─ Yes → panic!, assert!
        └─ No → Consider if really unrecoverable

Use ? → Need context?
├─ Yes → .context("message")
└─ No → Plain ?
```

---

## Common Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `unwrap()` panic | Unhandled None/Err | Use `?` or match |
| Type mismatch | Different error types | Use `anyhow` or `From` |
| Lost context | `?` without context | Add `.context()` |
| `cannot use ?` | Missing Result return | Return `Result<(), E>` |

---

## Anti-Patterns

| Anti-Pattern | Why Bad | Better |
|--------------|---------|--------|
| `.unwrap()` everywhere | Panics in production | `.expect("reason")` or `?` |
| Ignore errors silently | Bugs hidden | Handle or propagate |
| `panic!` for expected errors | Bad UX, no recovery | Result |
| Box<dyn Error> everywhere | Lost type info | thiserror |

---

## Related Skills

| When | See |
|------|-----|
| Reporting a failure across the C ABI or JNI | unsafe-checker |
| Which configurations are actually invalid | amnezia-dev, `AMNEZIA.md` |
| Errors from a poisoned or contended lock | m07-concurrency |
| `Result` in a per-packet path | m10-performance |
