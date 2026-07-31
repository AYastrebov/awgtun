---
name: amnezia-dev
description: >
  AmneziaWG 2.0/3.0 development skill for the boringtun fork. Covers protocol
  implementation, obfuscation parameters, rebase workflow, auditing against
  amneziawg-go, debugging, testing against a live server, and extending the
  codebase. Use this skill whenever working on AmneziaWG features, investigating
  AWG protocol behavior, resolving rebase conflicts in AWG-modified files,
  comparing with the Go reference, debugging handshake or padding issues, adding
  or validating obfuscation parameters, or reviewing AWG-related code. Also
  trigger on: "sync with upstream", "rebase amnezia", "pull master changes",
  "AWG protocol", "dynamic headers", "padding issue", "junk packets", "CPS
  chains", "I-packets", "amneziawg-go comparison", "interop test", "header
  protection", "content padding", "randomized timings", "config rejected",
  "EINVAL", "awg setconf", "UAPI", or any mention of H1-H4, S1-S4, Jc, Jmin,
  Jmax, I1-I5 parameters.
---

# AmneziaWG 2.0 / 3.0 Development Guide

Context for developing, debugging, auditing and maintaining the AmneziaWG 2.0
and 3.0 implementation in this boringtun fork.

Repo docs worth reading alongside this skill:
- `CLAUDE.md` — structure, build/test commands, integration points
- `AMNEZIA.md` — wire format, API reference, device/UAPI surface, Go comparison

## Ground rule: the reference decides what is invalid

This is the failure mode that has cost this fork the most, twice, and it will
happen again if you are not deliberate about it.

The temptation is to encode Amnezia's *documentation* — its recommended ranges,
its example configs, what "sensible" values look like — as validation. That
feels like hardening. It is not. Every rule stricter than amneziawg-go is a
configuration that a real AmneziaWG server issues and this implementation
refuses to speak to. The failure is invisible in unit tests and total in the
field: `errno=22` and a tunnel that never comes up.

What has already been removed after breaking real servers:

| Invented rule | Reality |
|---|---|
| S1-S4 capped at 64 / 32 | No maximum upstream; a live server's `S2` exceeded it |
| `Jc <= 10`, junk sizes 64-1024 | Upstream bounds none of them |
| Headers may not be 1-4 when any AWG feature is on | Upstream *defaults* H1-H4 to exactly 1,2,3,4 |
| I1-I5 must be contiguous, I1 required | Upstream sends every non-nil chain, gaps included |

The entire device-level validation in amneziawg-go is `mergeWithDevice` in
`device/uapi.go`, and it is two rules:

1. The four header ranges must not overlap.
2. If a header protection key is set, S1-S4 must each be >= 12
   (`HeaderCipherNonceSize`).

That is all. This fork keeps one rule upstream lacks — `Jmin <= Jmax`, because
upstream would underflow computing `Jmax - Jmin` — and that exception is worth
its own justification comment in the code.

So before adding a `ConfigError` variant, go read the reference and find the
check you are mirroring. If it isn't there, the honest options are to accept the
value or to document precisely why this fork must diverge. "The docs say the
range is X" is not a reason.

The same instinct applies in reverse on the receive path: a malformed *packet*
is dropped silently, because an attacker chooses its contents. Only
*configuration* produces errors.

## Protocol Quick Reference

AmneziaWG 2.0 adds four obfuscation layers to standard WireGuard. Both peers
must agree on all parameters. When all values are zero/default, standard
WireGuard behavior is preserved.

| Group | Params | What they do |
|-------|--------|-------------|
| Headers | H1-H4 (u32 ranges) | Replace WG type constants 1/2/3/4 with random values. Written BEFORE MAC — authenticated. |
| Padding | S1-S4 (u8, bytes) | Random prefix bytes. Added AFTER MAC — not authenticated. Applies to keepalives too. With header protection, all must be >= 12. |
| Junk | Jc/Jmin/Jmax | Random decoy UDP datagrams sent before handshake init. Sizes drawn from the half-open range `[Jmin, Jmax)`. |
| Init | I1-I5 (CPS chains) | Structured camouflage datagrams sent before junk. Any subset, gaps allowed. |
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
  2. classify() — try each type's padding+size+header combo
  3. Strip padding, (3.0) decrypt the protected span
  4. Parse header, verify MAC, process message
```

Getting this order wrong causes silent handshake failures — nothing logs, the
peer simply never answers.

### Send Order for Handshake Initiation

```
I-packets (I1..I5)  →  Junk (Jc packets)  →  Padded Handshake Init
  separate UDPs          separate UDPs          single UDP
```

Sent on **every** attempt, retries included.

## Codebase Architecture

```
amnezia.rs          — Config types, validation, CPS parser/generator, junk gen,
                      ChaCha20 header protection, parse()/to_uapi_block()
noise/mod.rs        — Tunn (per-peer), PacketClassifier (peer-independent),
                      padding, headers, packet queue, content padding
noise/handshake.rs  — msg_type param for init/response (inside MAC)
noise/session.rs    — msg_type + content_padding params for transport data
noise/rate_limiter.rs — HeaderConfig for classification, dynamic cookie headers
noise/timers.rs     — network_outgoing.clear() on reset, 3.0 randomized timings
ffi/mod.rs          — C FFI: amnezia_config/amnezia3_config, new_tunnel_amnezia{,3}
wireguard_ffi.h     — C declarations for both AWG surfaces
jni.rs              — Android: new_tunnel_amnezia3, poll_outgoing_packet, tunnel_free
device/mod.rs       — Device-scoped AWG config, classify-before-peer on receive,
                      four junk/I-packet drain sites, set_amnezia_config
device/api.rs       — AWG keys over the UAPI socket (set=1 / get=1)
device/peer.rs      — drain_outgoing, keepalive range, set_tunnel
```

Two structural facts about the `device` path that are easy to get wrong:

**Classification precedes peer lookup.** A padded, header-protected datagram
cannot be attributed to a peer until the prefix is stripped and the header
decrypted, so `PacketClassifier` borrows the *device's* config and runs in the
anonymous UDP handler. This mirrors amneziawg-go, where
`DeterminePacketTypeAndPadding` is a `Device` method. `Tunn::decapsulate`
does the same thing for the connected-socket path, where the peer is known.

**A `Tunn` captures its config at construction.** So changing the device's
AmneziaWG parameters must rebuild every peer (`Device::set_amnezia_config`),
otherwise inbound is classified with the new parameters while peers still send
with the old ones. amneziawg-go has no equivalent step because its peers read
device state live through atomics.

## Task: Audit against amneziawg-go

**Clone the reference, don't fetch files one at a time.** You will want to grep
it — for where a key is parsed, for every caller of a function, for what a
default is — and that is impossible through a raw-file URL:

```bash
git clone --depth 1 https://github.com/amnezia-vpn/amneziawg-go /tmp/awggo
rg -n "handleDeviceLine" -A 40 /tmp/awggo/device/uapi.go
```

Companion repos for the 3.0 configuration surface, when the Go device is not
enough: `amneziawg-tools` and `amneziawg-linux-kernel-module`. AWG 3.0 landed on
`master` in both on 2026-07-30, so `feat/awg3` is no longer where to look; the
live branch to watch now is `feature/awg4`.

Read all three when auditing. They disagree, and the disagreements are where
bugs live — see the reject-after-time note under AmneziaWG 3.0 in `AMNEZIA.md`
for a case where the kernel module and the Go device pick different values for
the same timer.

### Where things live

| Question | Go location |
|---|---|
| How is a UAPI key parsed? | `device/uapi.go` → `handleDeviceLine` |
| What is validated, device-wide? | `device/uapi.go` → `mergeWithDevice` |
| Is the UAPI incremental? | `device/uapi.go` → `fromDevice` seeds from the live device |
| What are H1-H4's defaults? | `device/device.go` → `NewDevice` (1, 2, 3, 4) |
| Send order, MAC/padding/HP ordering | `device/send.go` → `SendHandshakeInitiation` |
| Inbound classification | `device/receive.go` → `DeterminePacketTypeAndPadding` |
| Message construction | `device/noise-protocol.go` → `CreateMessageInitiation` |
| MAC computation | `device/cookie.go` → `AddMacs`, `CheckMAC1` |
| Timing pick rules (Lo/Hi/PickOne) | `device/timers.go` |
| CPS tag implementations | `device/obf*.go` (one file per tag) |

There is no `magic-header.go` on master — header handling lives in `device.go`
and `uapi.go`.

### Behaviors worth checking match

- Dynamic header written before MAC (`msg.Type = device.headers.X.Generate()`)
- Padding prepended after MAC (`buf := make([]byte, padding+len(packet))`)
- Header protection applied last, after MACs
- S4 applied to keepalives (`NewOutboundElement` sets `elem.padding`)
- "Data sent" judged by wire size (`len(elem.packet) != MessageKeepaliveSize`, 32)
- I-packets + junk sent on every attempt, retries included
- `DeterminePacketTypeAndPadding`: exact size for handshake types, `>=` for transport
- Header byte order: little-endian u32

### Report format for audit findings

```
## [Function Name]
Go: [exact behavior, file + function]
Rust: [our behavior with file:line]
Match: Yes / No / Partial
Action: None / Fix needed / Investigate
```

## Task: Debug Protocol Issues

### Before anything else: are the timers even running?

If a device test sends *nothing at all* — no handshake, no junk, silence on the
wire — check how the test binary was built before you touch protocol code:

```bash
cargo test -p boringtun --lib --features device --no-run   # correct
cargo test -p boringtun --lib --all-features --no-run      # clock is frozen
```

`--all-features` enables `mock-instant`, which freezes `Instant::now()`. Every
timer computes an elapsed time of zero forever, so no keepalive fires, no
handshake starts, and every device integration test fails in a way that looks
exactly like a protocol bug. This has burned an entire debugging session. CI is
fine — `cargo test -- --ignored` picks up `device` through `boringtun-cli` and
leaves `mock-instant` off.

### Handshake never completes

1. Check H1-H4 match between peers — both sides must be identical
2. Verify the dynamic header is written before MAC (`handshake.rs` msg_type)
3. Verify padding is stripped before MAC verification (`decapsulate`)
4. Check `PacketClassifier::classify` finds the right padding for inbound

### Data packets rejected after a successful handshake

1. Check the H4 transport range matches
2. Verify S4 is applied and stripped consistently
3. Check keepalives — S4 applies to empty payloads too
4. (3.0) Confirm both peers share the header protection key; a mismatch makes
   every datagram unclassifiable and silently dropped

### Pre-handshake packets not sent

1. Verify `queue_pre_handshake_packets()` runs in `format_handshake_initiation()`
2. Check the caller drains `poll_outgoing_packet()` *before* sending the init
3. Verify the CPS chains are configured and `active_chains()` yields them

On the `device` path there are **four** drain sites, because a handshake
initiation starts from exactly two places, `encapsulate` and `update_timers`:

- `register_timers`, after `update_timers`
- `register_iface_handler`, after `encapsulate`
- the flush loops in `register_udp_handler` and `register_conn_handler`, which
  re-enter `encapsulate` through `send_queued_packet`

Not after `handle_verified_packet` — it only answers inbound messages and never
initiates, so a drain there would be dead code.

### A device test asserts on rx_bytes/tx_bytes and always fails

Those counters track *decapsulated payload* only (`self.tx_bytes += src.len()`).
Handshakes, keepalives and junk do not move them. A test that completes a
handshake without passing tunnel traffic will report `rx_bytes=0` forever —
assert on `last_handshake_time_sec` instead.

### Buffer too small panics

- `encapsulate()` needs `src.len() + 32 + S4`, plus the content padding range's
  upper bound when configured
- `format_handshake_initiation()` needs `148 + S1`
- Cookie reply needs `64 + S3`

## Task: Test against a live AmneziaWG server

A completed handshake and real traffic against a real server is the check no
unit test substitutes for — it is what caught the padding cap. Read
`references/live-server-test.md` for the full procedure: translating a `.conf`
into a UAPI block (the spellings differ), bringing up the tunnel, and doing it
without hijacking the machine's default route.

Treat the server's parameters as secret. `H1`-`H4`, `S1`-`S4` and the junk
profile are exactly what keep its traffic from looking like WireGuard, so a
config pasted into a test, a doc, a commit message or an issue is a detection
signature published for that deployment. Reproduce the *shape* of a real config
when you need a regression test; never its numbers.

## Task: Rebase on Upstream Master

Read `references/rebase-guide.md` for the step-by-step procedure and per-file
conflict strategies.

```bash
git fetch origin master
git log --oneline amnezia..origin/master
git rebase origin/master
```

## Task: Extend the Implementation

### Adding a new CPS tag

1. Add a variant to `CpsTag` in `amnezia.rs`
2. Add the parse arm in `parse_cps_tag()`
3. Add `encoded_len()`
4. Add `generate()`
5. Add tests — parsing plus generation against `DetRng`, so the bytes are pinned

Check `device/obf*.go` for the reference implementation of the tag; each tag has
its own file there.

### Adding a new obfuscation parameter

1. Add the field to the relevant config struct in `amnezia.rs`
2. Validate it *only* as strictly as the reference does — see the ground rule
3. Wire it through `Tunn` (store it, use it in send/receive)
4. Update `Amnezia2Config`/`Amnezia3Config` `Default` and `validate`
5. Extend `parse()` and `to_uapi_block()` — they must round-trip
6. For a device-level parameter, add it to `is_amnezia_interface_key` in
   `device/api.rs`; the routing table and the parser must agree, and there is a
   test that enforces this
7. Update FFI `amnezia_config`/`amnezia3_config`, the `new_tunnel_amnezia*`
   entry points, and `wireguard_ffi.h`
8. Update `AMNEZIA.md`, `README.md`, `CLAUDE.md` and `CHANGELOG.md`

### Adding interop tests

The strongest available test short of a live server is two local devices sharing
a config, driven by a persistent keepalive (see
`device/integration_tests/mod.rs`). Pair every positive test with a negative
control — an AWG device that must *fail* to handshake with a plain WireGuard
peer. Without it, a bug that silently ignores the AWG config still passes, since
two plain WireGuard devices handshake happily.

## Testing

```bash
# Unit tests. The .cargo/config.toml runner is `sudo -E`, so build then run the
# binary directly to avoid the sudo prompt.
cargo test -p boringtun --lib --no-run
./target/debug/deps/boringtun-* --no-capture
./target/debug/deps/boringtun-* amnezia --no-capture   # AWG subset

# Device integration tests: need the `device` feature, root, and --ignored.
# Never --all-features here (see the mock-instant trap above).
cargo test -p boringtun --lib --features device --no-run
sudo -E ./target/debug/deps/boringtun-* --ignored --test-threads 1 awg

# Feature builds
cargo build --lib -p boringtun --features ffi-bindings
cargo build --lib -p boringtun --features jni-bindings
```

Some device integration tests spin up Docker containers; filtering by `awg` or
`test_wireguard` keeps a quick run local.
