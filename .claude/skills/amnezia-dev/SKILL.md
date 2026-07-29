---
name: amnezia-dev
description: >
  AmneziaWG 2.0/3.0 development skill for the boringtun fork. Covers protocol
  implementation, obfuscation parameters, rebase workflow, auditing against
  amneziawg-go, debugging, and extending the codebase. Use this skill whenever
  working on AmneziaWG features, investigating AWG protocol behavior, resolving
  rebase conflicts in AWG-modified files, comparing with the Go reference,
  debugging handshake or padding issues, adding new obfuscation parameters, or
  reviewing AWG-related code. Also trigger on: "sync with upstream", "rebase
  amnezia", "pull master changes", "AWG protocol", "dynamic headers",
  "padding issue", "junk packets", "CPS chains", "I-packets",
  "amneziawg-go comparison", "interop test", "header protection", "content
  padding", "randomized timings", or any mention of H1-H4, S1-S4, Jc, Jmin,
  Jmax, I1-I5 parameters.
---

# AmneziaWG 2.0 / 3.0 Development Guide

This skill provides context for developing, debugging, auditing, and maintaining
the AmneziaWG 2.0 and 3.0 protocol implementation in this boringtun fork.

Start by reading these repo docs for full context:
- `CLAUDE.md` — project structure, build/test commands, integration points
- `AMNEZIA.md` — protocol details, wire format, API reference, Go comparison

## Protocol Quick Reference

AmneziaWG 2.0 adds four obfuscation layers to standard WireGuard. Both peers
must agree on all parameters. When all values are zero/default, standard
WireGuard behavior is preserved.

### Parameters at a Glance

| Group | Params | What they do |
|-------|--------|-------------|
| Headers | H1-H4 (u32 ranges) | Replace WG type constants 1/2/3/4 with random values. Written BEFORE MAC — authenticated. |
| Padding | S1-S4 (u8, bytes) | Random prefix bytes. Added AFTER MAC — not authenticated. Applies to keepalives too. With header protection, all must be >= 12. |
| Junk | Jc/Jmin/Jmax | Random decoy UDP datagrams sent before handshake init. |
| Init | I1-I5 (CPS chains) | Structured camouflage datagrams sent before junk. |
| **3.0** Header protection | 32-byte key | Raw ChaCha20 over the header fields, nonced from the first 12 bytes of the padding prefix. |
| **3.0** Content padding | `content_padding_addition` range | Zero bytes appended inside the AEAD envelope of transport packets. |
| **3.0** Timings | 6 ranges | Randomize rekey/keepalive/reject-after/attempts/persistent-keepalive. Unset = WG constant. |

### Critical Protocol Invariant

```
Outbound:
  1. Build WG message with dynamic header (H1-H4) → header is inside MAC
  2. Compute MAC1/MAC2 over message including dynamic header
  3. Prepend S1-S4 random padding outside MAC
  4. (3.0) ChaCha20-encrypt the header fields, nonce = padding[..12]
  5. Send: [padding][WG message, header-protected]

Inbound:
  1. (3.0) Derive the type mask once from datagram[..12]
  2. determine_padding() — try each type's padding+size+header combo
  3. Strip padding, (3.0) decrypt the protected span
  4. Parse header, verify MAC, process message
```

Getting this order wrong causes silent handshake failures. The Go reference
(`amneziawg-go`) is the authoritative source of truth.

### Send Order for Handshake Initiation

```
I-packets (I1..I5)  →  Junk (Jc packets)  →  Padded Handshake Init
  separate UDPs          separate UDPs          single UDP
```

## Codebase Architecture

```
amnezia.rs          — Config types, validation, CPS parser/generator, junk gen
noise/mod.rs        — Tunn: padding, headers, packet queue, determine_padding()
noise/handshake.rs  — msg_type param for init/response (inside MAC)
noise/session.rs    — msg_type param for transport data
noise/rate_limiter.rs — HeaderConfig for packet classification, cookie headers
noise/timers.rs     — network_outgoing.clear() on reset, 3.0 randomized timings
ffi/mod.rs          — C FFI: amnezia_config/amnezia3_config, new_tunnel_amnezia{,3}
wireguard_ffi.h     — C declarations for both AWG surfaces
jni.rs              — Android: new_tunnel_amnezia3, poll_outgoing_packet, tunnel_free
```

## Task: Rebase on Upstream Master

Read `references/rebase-guide.md` for the step-by-step rebase procedure
including per-file conflict resolution strategies.

Quick version:
```bash
git fetch origin master
git log --oneline amnezia..origin/master  # check what's new
git rebase origin/master                   # rebase
# resolve conflicts per references/rebase-guide.md
cargo test -p boringtun --lib --no-run && ./target/debug/deps/boringtun-* --no-capture
```

## Task: Audit Protocol Correctness

When auditing the implementation against `amneziawg-go`:

1. **Fetch the Go source** for the specific function under audit:
   - `device/send.go` — `SendHandshakeInitiation`, `RoutineSequentialSender`
   - `device/receive.go` — `DeterminePacketTypeAndPadding`, receive routines
   - `device/noise-protocol.go` — `CreateMessageInitiation`, `CreateMessageResponse`
   - `device/cookie.go` — `AddMacs`, `CheckMAC1`
   - `device/device.go` — `Device` struct fields, `NewDevice` defaults

2. **Check these critical behaviors match:**
   - Dynamic header written before MAC (`msg.Type = device.headers.X.Generate()`)
   - Padding prepended after MAC (`buf := make([]byte, padding+len(packet))`)
   - S4 applied to keepalives (`NewOutboundElement` sets `elem.padding`)
   - "Data sent" by wire size (`len(elem.packet) != MessageKeepaliveSize`, 32)
   - Header protection spans and the MACs-before-encryption ordering
   - Timing pick rules in `timers.go` (`Lo`/`Hi`/`PickOne` per arm)
   - I-packets + junk sent on every handshake attempt (including retries)
   - `DeterminePacketTypeAndPadding` logic: exact size for handshake, `>=` for transport
   - Header byte order: little-endian u32

3. **Report format for audit findings:**
   ```
   ## [Function Name]
   Go: [exact behavior with line reference]
   Rust: [our behavior with file:line]
   Match: Yes / No / Partial
   Action: None / Fix needed / Investigate
   ```

## Task: Debug Protocol Issues

Common failure modes and how to diagnose:

### Handshake never completes
1. Check header ranges match between peers (H1-H4 must be identical)
2. Verify dynamic header is written before MAC — check `handshake.rs` msg_type usage
3. Verify padding is stripped before MAC verification — check `decapsulate()` in `mod.rs`
4. Check `determine_padding()` finds the right padding for incoming packets

### Data packets rejected after successful handshake
1. Check H4 transport header range matches
2. Verify S4 padding logic — is it applied/stripped consistently?
3. Check keepalive handling — S4 applies to empty payloads too
4. (3.0) Confirm both peers share the header protection key; a mismatch makes
   every packet unclassifiable and silently dropped

### Pre-handshake packets not sent
1. Verify `queue_pre_handshake_packets()` is called in `format_handshake_initiation()`
2. Check caller drains `poll_outgoing_packet()` before sending init
3. Verify I-packet CPS chains are configured and `active_chains()` yields them

### Buffer too small panics
- `encapsulate()` needs `src.len() + 32 + S4` bytes, plus the content padding
  range's upper bound when it is configured
- `format_handshake_initiation()` needs `148 + S1` bytes
- Cookie reply needs `64 + S3` bytes

## Task: Extend the Implementation

### Adding a new CPS tag
1. Add variant to `CpsTag` enum in `amnezia.rs`
2. Add parsing in `parse_cps_tag()` match arm
3. Add `encoded_len()` calculation
4. Add `generate()` implementation
5. Add tests (parsing + generation with `DetRng`)

### Adding a new obfuscation parameter
1. Add field to the relevant config struct in `amnezia.rs`
2. Add validation in the struct's `validate()` method
3. Wire it through `Tunn` (store in struct, use in send/receive path)
4. Update `Amnezia2Config` and its `Default`/`validate` impls
5. Update FFI `amnezia_config`/`amnezia3_config` and the `new_tunnel_amnezia*`
   entry points, plus the declarations in `wireguard_ffi.h`
6. Update `AMNEZIA.md`, `README.md` and `CLAUDE.md`

### Adding interop tests (Phase 8)
The test should:
1. Start `amneziawg-go` server in a Docker container/netns
2. Configure matching AWG parameters on both sides
3. Create Rust `Tunn` with same config
4. Exchange handshake + data packets via UDP socket
5. Verify: handshake completes, data round-trips, no standard headers on wire

## Testing

```bash
# Build without sudo
cargo test -p boringtun --lib --no-run

# Run all tests (bypass sudo runner)
./target/debug/deps/boringtun-* --no-capture

# Run only AWG tests
./target/debug/deps/boringtun-* amnezia --no-capture

# Build with FFI
cargo build --lib -p boringtun --features ffi-bindings
```

## Go Reference URLs

When you need to check the Go implementation, fetch from:
```
https://raw.githubusercontent.com/amnezia-vpn/amneziawg-go/master/device/{file}
```

Key files: `send.go`, `receive.go`, `device.go`, `noise-protocol.go`,
`cookie.go`, `uapi.go`, `timers.go`, `magic-header.go`, `obf.go`

Companion repos for the 3.0 configuration surface:
```
https://github.com/amnezia-vpn/amneziawg-tools/tree/feat/awg3
https://github.com/amnezia-vpn/amneziawg-linux-kernel-module/tree/feat/awg3
```

UAPI key names for the 3.0 parameters: `header_protection_key`,
`content_padding_addition`, `rekey_after_time`, `rekey_timeout`,
`reject_after_time`, `keepalive_timeout`, `max_handshake_attempts`, and the
now-range-valued per-peer `persistent_keepalive_interval`.

`Amnezia3Config::parse` accepts these same key names in a newline-separated
`key=value` block, which is how the JNI surface is configured. It also accepts
the 2.0 keys and a fork-specific `mtu`; unknown keys route through
`Amnezia2Config::validate_field_name` so AmneziaWG 1.x fields still report as
legacy.
