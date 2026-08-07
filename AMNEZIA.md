# AmneziaWG Implementation Details

How AmneziaWG 2.0 and 3.0 are implemented in this boringtun fork, how that maps
to the [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) reference, and
where the two differ.

**This is the implementation reference.** For what the parameters mean and how
to configure them, read the [README](README.md) first — it covers each
obfuscation layer, which values both peers must agree on, and a worked `.conf`.
This document assumes that and goes underneath it.

## Start here

If you are about to change something, these are the three things most likely to
bite, and all three fail *silently* — no error, no log, just a peer that stops
answering or a session that misbehaves.

| Invariant | Break it and | Where |
|---|---|---|
| Dynamic header goes in **before** the MAC; padding goes on **after** it; header protection is applied **last** | The peer's MAC check fails and it never replies. Nothing logs, on either side | `format_transport_packet`, `format_handshake_initiation` in `noise/mod.rs` |
| A keepalive is a keepalive regardless of its wire size or padded contents | Idle sessions rekey instead of staying quiet — see [Keepalives](#keepalives) | `encapsulate`, `validate_decapsulated_packet` in `noise/mod.rs` |
| Validation may be no stricter than amneziawg-go's | Real servers become unreachable with `errno=22`. This has happened twice | `Amnezia3Config::validate` in `amnezia.rs` |

### Where things live

Keyed by the question you are likely to be asking. Grep the symbol; the line
numbers move, the names do not.

| Question | Symbol | File |
|---|---|---|
| How is an outbound transport packet built? | `format_transport_packet` | `noise/mod.rs` |
| Where does padding get added and stripped? | `format_transport_packet`, `PacketClassifier::classify` | `noise/mod.rs` |
| How is an inbound datagram identified? | `PacketClassifier::classify` → `Classified` | `noise/mod.rs` |
| Where does the device classify, before it knows the peer? | `register_udp_handler` | `device/mod.rs` |
| Where are junk and I-packets queued, and drained? | `queue_pre_handshake_packets`, `Peer::drain_outgoing` | `noise/mod.rs`, `device/peer.rs` |
| How is header protection applied? | `HeaderProtection::apply`, `keystream` | `amnezia.rs` |
| Where do the randomized timings get picked? | `update_timers`, `roll_handshake_timings` | `noise/timers.rs` |
| What validates a config, and how strictly? | `Amnezia3Config::validate` | `amnezia.rs` |
| How is a UAPI block parsed and emitted? | `Amnezia3Config::parse`, `to_uapi_block` | `amnezia.rs` |
| How do UAPI keys reach the device? | `apply_amnezia_block`, `Device::set_amnezia_config` | `device/api.rs`, `device/mod.rs` |
| Which RNG is used where, and why? | `FastRandom`, `OsRandom` | `amnezia.rs` |
| Where are the CPS tags parsed and generated? | `CpsChain::parse`, `generate_for_init` | `amnezia.rs` |

## Table of Contents

- [Start here](#start-here) — invariants, and where things live
- [Protocol Overview](#protocol-overview)
- [Configuration Parameters](#configuration-parameters)
- [AmneziaWG 3.0](#amneziawg-30)
- [Packet Layout](#packet-layout)
- [Keepalives](#keepalives)
- [Implementation Architecture](#implementation-architecture)
- [File-by-File Changes](#file-by-file-changes)
- [Rust API](#rust-api)
- [C FFI API](#c-ffi-api)
- [JNI API (Android)](#jni-api-android)
- [Device and UAPI (boringtun-cli)](#device-and-uapi-boringtun-cli)
- [Comparison with amneziawg-go](#comparison-with-amneziawg-go)
- [Known Limitations](#known-limitations)

## Protocol Overview

AmneziaWG 2.0 adds four obfuscation layers on top of standard WireGuard:

1. **Dynamic headers (H1-H4):** Replace fixed WireGuard message type constants (1, 2, 3, 4) with random values from configurable ranges.
2. **Packet padding (S1-S4):** Prepend random bytes to each packet type to obscure sizes.
3. **Junk packets (Jc/Jmin/Jmax):** Send random decoy datagrams before handshake initiation.
4. **Init packets (I1-I5):** Send CPS (Custom Packet Signature) datagrams before handshake for protocol camouflage.

All four layers are independent and can be enabled selectively. When all parameters are zero/default, the tunnel behaves as standard WireGuard.

AmneziaWG 3.0 adds three more layers on top, described in [AmneziaWG 3.0](#amneziawg-30): header protection, content padding, and randomized timings. There is no wire-level version negotiation — behavior is entirely config-driven, and a 3.0 tunnel with the 3.0 parameters unset is byte-identical to a 2.0 tunnel.

## Configuration Parameters

| Parameter | Type | Range | Description |
|-----------|------|-------|-------------|
| H1 | u32 range | Any non-overlapping | Handshake initiation header |
| H2 | u32 range | Any non-overlapping | Handshake response header |
| H3 | u32 range | Any non-overlapping | Cookie reply header |
| H4 | u32 range | Any non-overlapping | Transport data header |
| S1 | u8 | 0-255 | Init padding bytes |
| S2 | u8 | 0-255 | Response padding bytes |
| S3 | u8 | 0-255 | Cookie padding bytes |
| S4 | u8 | 0-255 | Transport padding bytes |
| Jc | u8 | 0-255 | Junk packet count (0 = disabled) |
| Jmin | u16 | 0-65535 | Minimum junk size (inclusive) |
| Jmax | u16 | 0-65535 | Maximum junk size (exclusive, as in amneziawg-go) |
| I1-I5 | CPS string | See below | Init packet chain specs |

The ranges above are the field types, not protocol rules — upstream imposes no
maximum on any of them, and treating its *recommended* values as limits is what
once made real servers unreachable from here. See [Validation
Rules](#validation-rules). The one real ceiling is that S1-S4 are `u8` here
against upstream's `uint16`, so a padding value above 255 is rejected; widening
it would break the `amnezia_config` C ABI and Amnezia's tooling stays far below
that.

### CPS Chain Format

Init packets use a tag-based format: `<tag [arg]><tag [arg]>...`

All eight tags the parser accepts are below. The README lists only the five that
do anything in an `I1`-`I5` chain; the other three exist because the tag language
is shared with a data-carrying context, and in an init packet they emit nothing.

| Tag | Description | Example |
|-----|-------------|---------|
| `<b 0xHEX>` | Fixed hex bytes | `<b 0xDEADBEEF>` |
| `<t>` | 4-byte Unix timestamp (big-endian) | `<t>` |
| `<r N>` | N random bytes | `<r 16>` |
| `<rc N>` | N random ASCII letters (a-zA-Z) | `<rc 8>` |
| `<rd N>` | N random ASCII digits (0-9) | `<rd 4>` |
| `<d>` | Pass-through source data | `<d>` |
| `<ds>` | Base64-encoded source data | `<ds>` |
| `<dz N>` | N-byte big-endian data length | `<dz 2>` |

`<d>`, `<ds>` and `<dz>` interpolate source data, and an init packet has none —
so they parse successfully and contribute zero bytes. Putting one in an `I1`
chain is not an error and not useful.

### Validation Rules

- Header ranges must not overlap with each other.
- Jmin must not exceed Jmax.

That is deliberately close to the whole list. amneziawg-go's `mergeWithDevice`
checks only for overlapping headers, plus S1–S4 ≥ 12 when header protection is
on; everything else it accepts. Being stricter here does not harden anything, it
just makes real servers unreachable, so two rules that this fork used to invent
are gone:

- Header values **may** be 1, 2, 3 or 4. Upstream *defaults* H1–H4 to exactly
  those, so junk or padding with the headers left alone is ordinary AmneziaWG.
- Any subset of I1–I5 is valid, gaps included. Upstream sends every configured
  chain in order and never requires I1.

Jmin ≤ Jmax is the one rule kept that upstream lacks: it does not check, and
would underflow computing `Jmax - Jmin`.

## AmneziaWG 3.0

Configure with `Amnezia3Config` and `Tunn::new_with_amnezia3`.

### Upstream release of record

This implementation is aligned with, and was audited against, these three
releases. All three are the current `master` and the newest tag of their repo.

| Repo | Release | Commit | Date |
|---|---|---|---|
| [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) | `v3.0.20260805` | `08d68cd` | 2026-08-05 |
| [amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) | `v3.0.20260805` | `9f70177` | 2026-08-05 |
| [amneziawg-linux-kernel-module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module) | `v3.0.20260805` | `ce16310` | 2026-08-04 |

To check for drift, clone each and `git log <commit>..HEAD` from the row above;
an empty result on all three means there is nothing to do. Read all three when
auditing rather than only the Go device — they disagree in places, and those
disagreements are where the bugs are (see [Where the three implementations
disagree](#where-the-three-implementations-disagree)).

`feature/awg4` exists in all three repos but predates the 3.0 work (2025-10-15
to 2025-11-04), so it is a stale experiment rather than the next release.

### Header protection

Raw, unauthenticated ChaCha20 (32-byte key, 12-byte nonce, block counter 0) over the low-entropy header fields of every datagram. The nonce is the **first 12 bytes of the random padding prefix**, which is why enabling header protection requires S1-S4 to all be at least 12.

The AmneziaWG README used to say 8 while the code enforced 12; upstream settled
on 12 in `ce7cf10`/`7860d60`, which is what this implements. The kernel module
reaches the same rule from the other direction in `7304fbf`/`ff0aa32`: it now
refuses a header protection key outright when any of S1-S4 is below 12, rather
than accepting the config and producing unclassifiable packets.

| Message | Encrypted span |
|---------|----------------|
| Handshake initiation | 148 bytes (whole message) |
| Handshake response | 92 bytes (whole message) |
| Cookie reply | 64 bytes (whole message) |
| Transport | first 16 bytes (type, receiver index, counter) — the AEAD ciphertext is untouched |

Ordering matters: MAC1/MAC2 are computed over the plaintext message, then the message including its MACs is encrypted. On the wire the MACs are not recognizable to a DPI system. The receiver reverses this before any MAC check, so the Noise core is unchanged.

I1-I5 signature packets and Jc junk packets are never header-protected.

On receive, the 4-byte type field of each candidate message type is decrypted and tested against the corresponding H range. All candidates share one nonce, so the mask is derived once per datagram (`typeHash` in the Go reference).

An all-zero key means "disabled", matching `HeaderProtectionCipher`'s `key.IsZero()` check. The Rust API models this as `Option<[u8; 32]>` and the FFI accepts either NULL or an all-zero key.

### Content padding (`content_padding_addition`)

A random number of zero bytes, picked per packet from the configured range, appended to the transport content **inside** the AEAD envelope. Because the padding is authenticated, no length field is needed: the receiver trims it using the IP total-length field and needs no configuration of its own.

The addition is clamped to the space left in the last MTU segment: `add = min(add, mtu - packet_size % mtu)`. `Tunn` has no MTU concept of its own, so the MTU used for clamping is an `Amnezia3Config` field (default 1420, matching the Go device default).

Keepalives are content-padded too, which is one of the two ways a padded
keepalive can stop looking like a keepalive. See [Keepalives](#keepalives).

### Randomized timings

The WireGuard timing constants become inclusive ranges; an unset (all-zero) range falls back to the classic constant, so a default `TimingRanges` preserves stock behavior exactly.

| WireGuard constant | Range | Pick rule |
|---|---|---|
| `REKEY_TIMEOUT` (5 s), retransmit | `rekey_timeout` | fresh pick per initiation, retries included |
| `KEEPALIVE_TIMEOUT` (10 s) | `keepalive_timeout` | fresh pick per check |
| `KEEPALIVE_TIMEOUT + REKEY_TIMEOUT`, new-handshake | keepalive + rekey | `Hi`(keepalive) + pick(rekey) |
| `REKEY_AFTER_TIME` (120 s), initiator rekey | `rekey_after_time` | fresh pick per check |
| `REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT`, receiver rekey | reject / keepalive / rekey | pick(reject) - `Lo`(keepalive) - `Lo`(rekey) |
| `REJECT_AFTER_TIME` (180 s), keypair expiry | `reject_after_time` | `Hi` |
| `MaxTimerHandshakes` (18) | `max_handshake_attempts` | pick per new handshake |
| Persistent keepalive | `persistent_keepalive` | fresh pick on every fire |

amneziawg-go gives up on a handshake after a **count** of attempts; boringtun bounds retries by time (`REKEY_ATTEMPT_TIME`). The two are expressed here as `rekey_timeout * max_handshake_attempts`, which for default ranges is exactly the classic 90 s.

Go also uses `Lo(rekey_timeout)` as the minimum spacing between initiations (`rekeyMinTimeout`), and the kernel module agrees since `51f3bb1` fixed an inverted ternary that had been reading the range only when it was *unset*. boringtun has no equivalent gate, and does not need one: it suppresses duplicate initiations structurally via `is_in_progress()`, and its retransmit interval is a fresh pick from `[Lo, Hi]`, which is never below the floor the other two enforce.

#### Where the three implementations disagree

Keypair expiry (`zeroKeyMaterial`, armed at `reject_after_time * 3`) is the one arm where the reference implementations do not agree, so it is worth stating which one this follows and why.

| | Value used |
|---|---|
| amneziawg-go (`keychainExpireTime`) | `Hi(reject_after_time)` |
| kernel module (`wg_timers_session_derived`) | `PickOne(reject_after_time)` |
| this fork | `Hi`, following Go |

`Hi` is the safe reading. Sessions expire at a value drawn from the range, so key material has to outlive the longest session that could still be in flight; a fresh pick can land below a live session's own draw and zero the keys while it is still in use. Go's choice is also the conservative one, so following it costs nothing.

The kernel module has a second, clearer slip in the same area: `wg_expired_retransmit_handshake` arms `timer_zero_key_material` from `rekey_after_time` rather than `reject_after_time` (`timers.c`, still present at `c78a89e`). Both are upstream bugs to watch rather than behavior to copy — which is the reason to read all three implementations when auditing, not just the Go one.

### Randomness: which source, and why

AmneziaWG draws a lot of random values per packet, and they are not all the same
kind of secret. This implementation splits them, as amneziawg-go does.

| Drawn per | Values | Source |
|---|---|---|
| Packet | `S1`-`S4` prefix bytes | `FastRandom` |
| Packet | message type within its `H` range, content padding length | `FastRandom` |
| Timer tick | every timing range pick | `FastRandom` |
| Handshake | junk contents, CPS `<r>`/`<rc>`/`<rd>` bytes | `FastRandom` |
| Once | Noise ephemeral keys, cookie and MAC keys | `OsRandom` |

`OsRandom` is `getrandom`, which costs a syscall — around 160 ns here. That is
the right price for a long-lived secret drawn once and far too high for a value
drawn three times per packet. `FastRandom` is a buffered ChaCha20 keystream
seeded from the OS and kept per thread, at roughly 5-9 ns per draw. Go's
`crypto/rand` is the same design, which is why `rand.Read` costs 36 ns there
rather than a syscall.

Upstream draws the line further out still: `UintRange.PickOne` uses `fastrandn`,
`runtime.fastrand`, which is not cryptographic at all. Using a real CSPRNG for
those is the more conservative half of the same split.

A CSPRNG is sufficient for the padding prefix even though its first 12 bytes are
the header protection nonce. With either source the nonces are uniform over 96
bits, so a collision is a birthday event near 2^48 packets; a CSPRNG's output is
computationally indistinguishable from uniform, so the bound is the same up to a
negligible term.

What genuinely differs is state duplication. `fork` copies the buffer, so parent
and child would emit identical bytes — for an `S1`-`S4` prefix that is keystream
reuse under one key, and it is not hypothetical, since `boringtun-cli` forks to
daemonize and any FFI or JNI embedder may fork for its own reasons. A
`pthread_atfork` child handler bumps a generation counter, and every thread
discards its buffer when the value moves. The check runs per draw rather than
per refill, so bytes inherited but not yet consumed are dropped too.
`fork_does_not_duplicate_the_keystream` covers it, and fails without the guard.

### Constant-time comparison

MAC verification and the decrypted static-key check compare against
attacker-supplied bytes, where an early return leaks how much of the value the
attacker guessed correctly. These use `subtle::ConstantTimeEq`. They previously
used `ring::constant_time::verify_slices_are_equal`, which ring has deprecated
with the note that it makes "no promises regarding side channels" — the promise
being the only reason to call it.

## Packet Layout

### Send Order for Handshake Initiation

```
1. I-packets (I1, I2, ... I5)     — separate UDP datagrams
2. Junk packets (Jc random packets) — separate UDP datagrams
3. Handshake initiation             — single UDP datagram
```

### Wire Format

Each packet type on the wire:

```
Handshake Init:     [S1 random bytes][Type(H1)][Sender][Ephemeral][Static][Timestamp][MAC1][MAC2]
Handshake Response: [S2 random bytes][Type(H2)][Sender][Receiver][Ephemeral][Empty][MAC1][MAC2]
Cookie Reply:       [S3 random bytes][Type(H3)][Receiver][Nonce][Cookie]
Transport Data:     [S4 random bytes][Type(H4)][Receiver][Counter][Encrypted Content]
Transport Keepalive:[Type(H4)][Receiver][Counter][Encrypted Empty]  (no S4 padding)
```

### Critical Protocol Detail: Header vs. Padding Ordering

**Dynamic headers** are written INTO the message struct **before** MAC computation. The MAC covers the obfuscated header value, not the original WireGuard type constant. Both peers must agree on header ranges for MAC verification to succeed.

**Padding** is prepended **after** MAC computation. It is NOT authenticated. The receiver knows the padding size from its configuration and strips it before processing.

This two-phase approach is critical for interoperability. Getting the order wrong causes silent handshake failures.

## Keepalives

A keepalive is an authenticated transport packet with no payload. Its job is to
tell the peer "still here" so an idle session is not torn down, and to keep a
NAT mapping open. It has to be distinguishable from data, because the two feed
different timers.

Padding makes that distinguishing harder, and getting it wrong inverts what the
mechanism does. This is worth its own section because both this fork and
amneziawg-go got it wrong in the same way, and the failure is silent.

### Why the classification matters

`update_timers` decides to start a new handshake on this condition:

```rust
if data_packet_sent > aut_packet_received
    && now - aut_packet_received >= Hi(keepalive_timeout) + pick(rekey_timeout)
    && mem::replace(&mut self.timers.want_handshake, false)
{
    handshake_initiation_required = true;
}
```

In words: if we have sent *data* more recently than we have received anything
authenticated, and that has been true for a keepalive interval plus a rekey
timeout, assume the session is broken and handshake again. That is correct — it
is how a peer notices a dead path.

`data_packet_sent` only advances for data. A keepalive must not touch it, or
the condition reads "we have been talking and hearing nothing back" every time
an idle link sends its scheduled keepalive. The peer is under no obligation to
answer a keepalive, so `aut_packet_received` stays put, the deadline passes, and
the session rekeys. Then it does it again. Keepalives stop keeping the session
quiet and start driving it.

### What went wrong

Both sides of the classification used a test that padding invalidates.

**Outbound.** Whether a packet was a keepalive was inferred from its wire size,
compared against the unpadded 32 bytes (`MessageKeepaliveSize`). An `S4` prefix
or a content-padding addition changes that size, so every keepalive on a padded
configuration registered as data and armed the timer above.

**Inbound.** A keepalive was recognised by an empty payload. With content
padding the payload is not empty — it decrypts to zeros — so the check missed
it and the peer's keepalives counted as data received.

This fork inherited the outbound rule deliberately, with a comment citing
amneziawg-go's `len(elem.packet) != MessageKeepaliveSize` and two tests pinning
it in place. It was a faithful copy of a real bug.

### The fix

Upstream fixed both in amneziawg-go `08d68cd` and kernel module `ce16310`, both
titled "keepalives are ignored", and this follows.

**Outbound**, being a keepalive is a property of the call, not of the bytes. Only
a caller with nothing to send passes an empty payload, so `src.is_empty()` in
`encapsulate` is the fact itself rather than a proxy for it. Upstream reaches
the same place with an explicit `isKeepalive` flag set in `SendKeepalive`.

Nothing else can reach `encapsulate` with an empty payload by accident. The
device reads from the TUN and calls `Tunn::dst_address` first, which rejects
anything it cannot parse as IPv4 or IPv6, so a zero-length read never gets that
far. A library or FFI caller passing an empty buffer is asking to send nothing,
which is a keepalive by definition.

**Inbound**, a first byte of zero marks a keepalive. That is safe because no IP
packet can begin with a zero byte — the high nibble is the version, 4 or 6 — so
the test cannot collide with real traffic. Upstream checks `elem.packet[0] == 0`
and the kernel module `*p == 0` for the same reason.

A payload that is neither a keepalive nor routable is still dropped and still
counts as data received, and a test pins that so widening the keepalive test
cannot quietly swallow it.

### Which configurations were affected

Anything with a non-zero `S4`, on AmneziaWG 2.0 or 3.0, or with
`ContentPaddingAddition` set on 3.0. Plain WireGuard and an AmneziaWG
configuration with `S4 = 0` and no content padding were never affected, because
their keepalives are exactly 32 bytes and decrypt to nothing.

### Measured

Against a live AmneziaWG server with `PersistentKeepalive = 25`, left idle for
70 seconds, reading the handshake's age from `get=1`:

| | age before idle | age after |
|---|---:|---:|
| before the fix | 2 s | **7 s** — a new handshake replaced it mid-idle |
| after the fix | 2 s | **72 s** — one handshake throughout |

The 7 is the tell: the handshake being reported is younger than the idle period,
so it is not the one the session started with.

## Implementation Architecture

The implementation follows a layered approach that minimizes changes to boringtun's core Noise state machine:

```
┌─────────────────────────────────────────────┐
│              Tunn (noise/mod.rs)             │
│  - Owns the Amnezia3Config fields           │
│  - Generates dynamic headers from ranges    │
│  - Prepends/strips padding                  │
│  - Queues I-packets and junk                │
│  - Classifies inbound datagrams             │
├─────────────────────────────────────────────┤
│      PacketClassifier (noise/mod.rs)        │
│  - Strips padding, decrypts the header      │
│  - Borrows config, needs no Tunn, so the    │
│    device can classify before it knows      │
│    which peer a datagram belongs to         │
├─────────────────────────────────────────────┤
│     Handshake / Session / RateLimiter       │
│  - Accept msg_type: u32 parameter           │
│  - Write msg_type into packet BEFORE MAC    │
│  - No knowledge of ranges or padding        │
├─────────────────────────────────────────────┤
│            amnezia.rs module                │
│  - Config types + validation                │
│  - RandomSource: OsRandom and FastRandom    │
│  - ChaCha20 header protection primitive     │
│  - CPS parser and generator                 │
│  - Junk packet generator                    │
│  - HeaderRange::generate()                  │
└─────────────────────────────────────────────┘
```

The Noise handshake code (`handshake.rs`, `session.rs`) only gained a `msg_type: u32` parameter — it has no knowledge of AmneziaWG configuration. All range-based header selection, padding, and packet queuing lives in the `Tunn` layer.

## File-by-File Changes

### New Files

| File | Lines | Purpose |
|------|-------|---------|
| `amnezia.rs` | ~2730 | Every AWG 2.0 and 3.0 config type, validation, the CPS parser and generator, junk generation, the ChaCha20 header protection primitive, `parse`/`to_uapi_block`, and the `RandomSource` implementations |
| `jni.rs` | ~370 | Android bindings: `new_tunnel_amnezia3`, `wireguard_poll_outgoing_packet`, `tunnel_free` |
| `benches/crypto_benches/amnezia_benching.rs` | ~245 | Criterion benchmarks for encapsulate, decapsulate, handshake initiation and `update_timers` |

### Modified Files

| File | Change Summary |
|------|---------------|
| `noise/mod.rs` | `Tunn` gains the AWG config fields and the `network_outgoing` queue; `new_with_amnezia`/`new_with_amnezia3` constructors; `PacketClassifier` and `Classified` for peer-independent inbound classification; padding and header protection in `encapsulate`/`decapsulate`; content padding; `format_handshake_initiation` queues I-packets and junk; `constant_time_eq` |
| `noise/handshake.rs` | `format_handshake_initiation`, `format_handshake_response` and `receive_handshake_initialization` take `msg_type: u32`, written before the MAC |
| `noise/session.rs` | `format_packet_data` takes `msg_type` and `content_padding` |
| `noise/rate_limiter.rs` | `verify_packet` takes `&HeaderConfig`; `format_cookie_reply` takes `msg_type`; dynamic cookie headers |
| `noise/timers.rs` | `clear_all` clears `network_outgoing`; the AWG 3.0 `TimingRanges`, `roll_handshake_timings`, and the per-arm range rules in `update_timers` |
| `device/mod.rs` | Device-scoped `Amnezia3Config`; classify-before-peer on receive; padded and protected cookie replies; junk and I-packets drained at the four sites that can start a handshake; `set_amnezia_config` rebuilds peers when the configuration changes |
| `device/api.rs` | AmneziaWG keys merged incrementally over the current config on `set=1`, emitted by `to_uapi_block` on `get=1`; per-peer `persistent_keepalive_interval` accepts a range |
| `device/peer.rs` | `drain_outgoing`, `set_tunnel`, and the configured keepalive range kept for `get=1` |
| `device/integration_tests/mod.rs` | The `test_awg*` device tests: a two-device handshake, its plain-WireGuard negative control, UAPI round-trip, incremental update, and padding without custom headers |
| `ffi/mod.rs` | `amnezia_config` and `amnezia3_config` structs, `new_tunnel_amnezia`, `new_tunnel_amnezia3`, `wireguard_poll_outgoing_packet` |
| `wireguard_ffi.h` | C declarations for both AmneziaWG surfaces |
| `lib.rs` | `pub mod amnezia;`, and `serialization` gated on the `device`/`ffi-bindings` features |

## Rust API

### Creating a Tunnel

```rust
use boringtun::noise::Tunn;
use boringtun::amnezia::*;

// Standard WireGuard (unchanged API)
let tunnel = Tunn::new(private_key, peer_public, None, None, index, None);

// AmneziaWG 2.0
let config = Amnezia2Config {
    headers: HeaderConfig::new(
        HeaderRange::new(100, 200)?,  // H1
        HeaderRange::new(201, 300)?,  // H2
        HeaderRange::new(301, 400)?,  // H3
        HeaderRange::new(401, 500)?,  // H4
    )?,
    paddings: PaddingConfig::new(16, 16, 16, 8)?,
    junk: JunkConfig::new(3, 64, 256)?,
    init_packets: InitPacketConfig::default(),
};

let tunnel = Tunn::new_with_amnezia(
    private_key, peer_public, None, Some(25), index, None, config,
)?; // Returns Result<Tunn, ConfigError>

// AmneziaWG 3.0: the 2.0 blocks plus header protection, content padding
// and randomized timings.
let mut config = Amnezia3Config::from_amnezia2(config);
config.header_protection_key = Some(header_key); // requires S1-S4 >= 12
config.content_padding_addition = Some(U32Range::new(1, 64)?);
config.timing_ranges = TimingRanges {
    rekey_timeout: U32Range::new(3, 9)?,
    keepalive_timeout: U32Range::new(8, 15)?,
    ..TimingRanges::default()   // unset ranges keep the WireGuard constants
};
config.mtu = 1420;              // used only to clamp content padding

let tunnel = Tunn::new_with_amnezia3(
    private_key, peer_public, None, Some(25), index, None, config,
)?;
```

### Sending Pre-Handshake Packets

Before sending the handshake initiation, drain the pre-handshake queue:

```rust
// After encapsulate() or format_handshake_initiation() triggers a handshake:
while let Some(packet) = tunnel.poll_outgoing_packet() {
    socket.send_to(&packet, peer_addr)?;
}
// Then send the handshake init (returned by encapsulate/format_handshake_initiation)
```

### Buffer Sizing

With AmneziaWG padding active, output buffers must be larger:

- Handshake initiation: `148 + S1` bytes
- Handshake response: `92 + S2` bytes
- Transport data: `payload.len() + 32 + S4` bytes
- `update_timers()` / `wireguard_tick()`: the larger of a handshake initiation (`148 + S1`) and an unpadded keepalive (`32 + S4`)

Content padding does not raise these floors. amneziawg-go writes into pooled 64 KiB buffers (`MaxMessageSize = (1 << 16) - 1`), so its MTU clamp is enough to keep a padded packet in bounds; `Tunn` writes into a buffer the caller owns, so the space left in `dst` is applied as a third term in the same clamp. A tight buffer therefore yields less padding rather than a panic.

To get the full configured range, add the range's upper bound on top of the sizes above. Under-sizing is silent: the packet is still valid and still round-trips, it just carries less padding than configured, which weakens the size obfuscation.

## C FFI API

### Configuration

```c
typedef struct {
    uint32_t h1_start, h1_end;  // H1 range
    uint32_t h2_start, h2_end;  // H2 range
    uint32_t h3_start, h3_end;  // H3 range
    uint32_t h4_start, h4_end;  // H4 range
    uint8_t  s1, s2, s3, s4;    // Padding sizes
    uint8_t  jc;                // Junk count
    uint16_t jmin, jmax;        // Junk size range
    const char *i1, *i2, *i3, *i4, *i5;  // CPS chains (NULL to skip)
} amnezia_config;

typedef struct {
    amnezia_config base;                 // all 2.0 parameters
    const uint8_t *header_protection_key; // 32 bytes; NULL or all-zero = off
    uint32_t content_padding_min, content_padding_max;
    uint32_t rekey_after_time_min, rekey_after_time_max;            // seconds
    uint32_t rekey_timeout_min, rekey_timeout_max;                  // seconds
    uint32_t reject_after_time_min, reject_after_time_max;          // seconds
    uint32_t keepalive_timeout_min, keepalive_timeout_max;          // seconds
    uint32_t max_handshake_attempts_min, max_handshake_attempts_max; // count
    uint32_t persistent_keepalive_min, persistent_keepalive_max;    // seconds
    uint32_t mtu;                        // 0 selects the default (1420)
} amnezia3_config;
```

Every `*_min`/`*_max` pair is inclusive; a pair of zeros means "unset" and falls back to the WireGuard default. Zeroing the whole struct yields standard WireGuard behavior. The declarations live in `boringtun/src/wireguard_ffi.h`.

### Functions

```c
// Create tunnel with AWG 2.0 config (NULL config = standard WireGuard)
void* new_tunnel_amnezia(
    const char *private_key, const char *public_key,
    const char *preshared_key, uint16_t keep_alive,
    uint32_t index, const amnezia_config *config);

// Create tunnel with AWG 3.0 config (NULL config = standard WireGuard)
void* new_tunnel_amnezia3(
    const char *private_key, const char *public_key,
    const char *preshared_key, uint16_t keep_alive,
    uint32_t index, const amnezia3_config *config);

// Drain pre-handshake packets (call in loop until returns 0)
size_t wireguard_poll_outgoing_packet(
    void *tunnel, uint8_t *dst, uint32_t dst_size);
```

## JNI API (Android)

The `jni-bindings` feature exposes the tunnel to Android's `VpnService` through
`io.github.ayastrebov.boringtun.BoringTunJNI`. AmneziaWG is configured with a
single UAPI-style `key=value` block rather than a long scalar signature:

```kotlin
val config = """
    jc=4
    jmin=64
    jmax=256
    s1=16
    s2=16
    s3=16
    s4=16
    h1=100-199
    h2=200-299
    h3=300-399
    h4=400-499
    header_protection_key=$hexKey
    content_padding_addition=1-64
    rekey_timeout=3-9
    persistent_keepalive_interval=20-30
""".trimIndent()

val handle = BoringTunJNI.new_tunnel_amnezia3(
    secretKeyBase64, publicKeyBase64, presharedKeyBase64, keepAlive, index, config,
)
require(handle != 0L) { "invalid AmneziaWG configuration" }
```

Blank lines, indentation and `#` comments are ignored; unset keys keep their
WireGuard defaults, so an empty string yields a standard WireGuard tunnel. All
keys are listed under [Configuration Parameters](#configuration-parameters) and
[AmneziaWG 3.0](#amneziawg-30); `mtu` is a fork extension standing in for the
device MTU, and an all-zero `header_protection_key` means "disabled".

**This is the UAPI spelling, not the `.conf` one.** An AmneziaWG `.conf` names
the 3.0 fields in CamelCase and encodes keys in base64
(`HeaderProtectionKey = vIOc…`, `ContentPaddingAddition = 0-64`); the parser
wants snake_case and hex. Case is folded, so the 2.0 names survive untouched
(`Jc` → `jc`), but the 3.0 ones do not. Translate a `.conf` the way
`awg setconf` does before passing it in.

### The drain contract

This is the easiest thing to get wrong. Junk packets and the I1-I5 signature
packets are queued, not returned inline, so after creating a tunnel and after
**every** `wireguard_write` and `wireguard_tick`, drain the queue and send those
datagrams *before* the handshake initiation the call produced:

```kotlin
fun drainPreHandshake(handle: Long, socket: DatagramChannel, buf: ByteBuffer) {
    while (true) {
        buf.clear()
        val size = BoringTunJNI.wireguard_poll_outgoing_packet(handle, buf, buf.capacity())
        if (size == 0) break
        buf.limit(size)
        socket.write(buf)
    }
}
```

Skipping this does not break the tunnel — the handshake still completes — but
`Jc` and `I1`-`I5` silently have no effect on the wire.

### Lifecycle

`BoringTunJNI.tunnel_free(handle)` releases the tunnel. The handle must not be
used afterwards; passing 0 is a no-op.

> **Note:** every JNI export is bound to a literal class name via
> `#[export_name]`, so the Kotlin class must be declared at exactly
> `io.github.ayastrebov.boringtun.BoringTunJNI` or the runtime will not resolve
> the natives. A consumer shipping its own package has to patch the export
> prefix in `boringtun/src/jni.rs` and rebuild.
>
> This used to be `com.cloudflare.app.boringtun.BoringTunJNI`, inherited from
> upstream. That names Cloudflare's own Android application package, which is
> wrong for a fork they do not publish, so it was changed. Any consumer built
> against the old prefix must update its class declaration.

## Device and UAPI (boringtun-cli)

With the `device` feature, `boringtun-cli` is a full AmneziaWG endpoint. It is
configured over the usual WireGuard UAPI socket at
`/var/run/wireguard/<iface>.sock`, so the amneziawg-tools `awg` binary drives it
directly.

### Configuration

The AmneziaWG parameters are **interface-level**, listed in the `[Interface]`
section alongside `PrivateKey` and `ListenPort`:

```ini
[Interface]
PrivateKey = <base64>
ListenPort = 51820
Jc = 3
Jmin = 64
Jmax = 256
S1 = 16
S2 = 16
S3 = 16
S4 = 16
H1 = 1000-1099
H2 = 2000-2099
H3 = 3000-3099
H4 = 4000-4099
I1 = <b 0xc0ffee><r 32>
HeaderProtectionKey = <64 hex characters>
ContentPaddingAddition = 1-32
RekeyTimeout = 3-6
KeepaliveTimeout = 8-12

[Peer]
PublicKey = <base64>
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

`awg setconf` translates these to the snake_case `key=value` names that
`Amnezia3Config::parse` accepts (`ContentPaddingAddition` →
`content_padding_addition`), with keys in hex rather than base64 — the same
format the JNI surface takes. See [JNI API (Android)](#jni-api-android) for the
full key list.

### Bringing up a tunnel

```bash
# Start the device (creates /var/run/wireguard/awg0.sock)
sudo boringtun-cli awg0

# Push the configuration
sudo awg setconf awg0 /etc/amnezia/awg0.conf

# Address and route as usual
sudo ip addr add 10.0.0.2/24 dev awg0
sudo ip link set up dev awg0

# Confirm the handshake
sudo awg show awg0
```

A completed handshake with a real AmneziaWG server, and traffic flowing over it,
is the check that no unit test can stand in for.

### How `set=1` handles the AmneziaWG keys

**Incremental, like the rest of the UAPI.** A key absent from a `set=1` keeps
its current value, so `awg set awg0 jc 5` changes the junk count and nothing
else. This mirrors amneziawg-go's `ipcSetDevice`, which seeds itself from the
live device, overlays the keys present in the operation, and merges the result
back.

The keys collected from an interface section are still parsed and validated as
one block — the current configuration is re-serialized and the new lines
appended — so the cross-field rules (overlapping header ranges, S1–S4 ≥ 12 under
header protection) are enforced atomically and a rejected configuration leaves
the device untouched.

**Changing the configuration rebuilds the peers.** A `Tunn` captures its
AmneziaWG parameters at construction, so a device-level change is pushed into
every existing peer; otherwise inbound datagrams would be classified with the
new parameters while the peers still sent with the old ones. Sessions reset and
the peers re-handshake, which is no loss: the parameters that changed define the
wire format. amneziawg-go needs no equivalent step because its peers read the
device configuration live.

**`mtu` is not a key on this path.** It exists only because `Tunn` has no
concept of an MTU, which matters for the FFI and JNI surfaces. A device knows
its interface MTU and that value is authoritative, so content padding is clamped
against the live one and `mtu=` over the socket is rejected like any other
unknown key.

### Verified interoperability

This fork has completed handshakes and passed ICMP traffic against two
independent AmneziaWG server implementations:

| Server | Configuration | Client path |
|---|---|---|
| amneziawg-go | AmneziaWG 2.0 — `H1`–`H4`, `S1`–`S4`, junk, `I1`–`I5` | `boringtun-cli` over the UAPI socket, exactly as `awg setconf` drives it |
| amneziawg kernel module | AmneziaWG 3.0 — the 2.0 layers plus header protection, content padding and randomized timings | `Tunn` driven directly over a UDP socket |

The 3.0 run is what puts header protection and content padding on the wire
against something other than ourselves. Header protection in particular gives a
binary result: the type field is ChaCha20-encrypted under a shared 32-byte key
with the nonce taken from the padding prefix, so a keystream or nonce derivation
that disagreed with the reference by a single byte would make every datagram
unclassifiable and nothing would handshake at all. Both sides handshook in
roughly 25 ms.

Packet captures of those runs confirmed, against each server's own parameters:

- **Send order** — each configured `I1`–`I5` datagram first, one UDP datagram
  per chain and byte-exact against it, then `Jc` junk datagrams, then the
  handshake initiation. Nothing was reordered or coalesced.
- **Junk sizing** — every junk datagram fell in the half-open range
  `[Jmin, Jmax)`, never reaching `Jmax` itself.
- **Padding arithmetic** — the initiation measured exactly `148 + S1` bytes and
  the response `92 + S2`, so `S1`/`S2` reached the wire outside the MAC.
- **Content padding** — transport packets carrying a 56-byte ping landed inside
  the `84 + 32 + S4 + [content_padding_addition]` window in both directions, and
  the receiver trimmed the server's padding back to the original packet using
  the IP total-length field.
- **Round trip** — `get=1` reported every AmneziaWG key back, and ICMP flowed at
  0% loss with `rx_bytes`/`tx_bytes` advancing on both sides.

> The server's actual parameter values are deliberately not recorded here. A
> deployment's `H1`–`H4`, `S1`–`S4` and junk profile are precisely what stop its
> traffic looking like WireGuard; publishing them hands a censor an exact
> signature for that server — match the type field against `H1`–`H4`, then the
> `148 + S1` initiation. Treat a real config the way you would treat its private
> key. `references/live-server-test.md` in the `amnezia-dev` skill describes how
> to run this check against your own server.

What these runs established that no unit test had:

- One server's `S2` sat above the 64-byte maximum this implementation used to
  enforce. That limit came from Amnezia's documentation rather than the protocol
  — amneziawg-go applies no maximum to S1–S4 — and it made interop with that
  server impossible. See the note on validation strictness below.
- The CPS generator and the junk size distribution match what a real server
  expects, not merely what our own tests assert.
- Header protection, content padding and the 3.0 timing ranges are accepted by
  an implementation that shares no code with this one, so they are not merely
  self-consistent.

#### Rekeying and sustained traffic

A later pair of runs against the kernel module held one session open for 51
minutes and another for 12, rather than exiting once the first echo came back.
Together they completed **30 rekeys** and pushed roughly 190,000 packets —
about 144 MB in each direction — through the established session.

- **Rekey timing.** Every undisturbed session was replaced inside the
  configured `RekeyAfterTime` window, never before its `Lo` and never past its
  `Hi`. This is the initiator-side `keyRefreshTimeoutSending` check in
  `update_timers` (`noise/timers.rs`, the `rekey_after_time` arm), which re-picks from the range on every timer tick
  rather than drawing once per session; over a run of that length the observed
  intervals clustered near the low end of the window, which is what repeated
  sampling against a rising session age predicts.
- **Continuity.** Traffic crossed every rekey without a stall or a dropped
  packet, including rekeys that fired in the middle of a bulk transfer. The
  peer accepted our initiations and we accepted its responses with header
  protection and content padding active on both the expiring and the new
  session.
- **Volume.** Content padding and header protection held up over sustained
  load, not just the single ping the earlier runs sent. Nothing degraded as the
  nonce counter advanced.

Two observations from those runs are worth recording because they look like
faults and are not:

- **Sessions that end early after heavy traffic.** Some sessions were replaced
  well short of the `RekeyAfterTime` window, always following a burst. That is the `data_packet_sent > aut_packet_received` arm of `update_timers`
  (`noise/timers.rs`) — having sent data and received no *authenticated*
  packet for `Hi(keepalive) + pick(rekey_timeout)`, we initiate. Bursts lost a
  small fraction of echo replies; when the losses happened to land on
  consecutive keepalive-interval probes afterwards, that threshold tripped. It
  is stock WireGuard behavior detecting a peer that has gone quiet, and it is
  also what recovers the session: an earlier run stalled for ~90 s and resumed
  exactly when this rule rebuilt the tunnel.
- **Throughput figures from this harness are a floor, not a measurement.** A
  userspace probe echoing through the tunnel topped out near 1,500 packets/s
  each way. Doubling the in-flight window barely moved it, and packets 2.6×
  apart in size gave nearly the same bit rate — so the ceiling is the probe's
  single-threaded per-packet cost, not the tunnel or the link. The per-packet
  crypto cost is ~1.2 µs, orders of magnitude below what that rate implies. A
  real throughput number needs `iperf3` over an actual TUN interface.

Still unverified: the loss those bursts showed (~1-2% under load) has not been
attributed. It is equally consistent with the server, the container hosting it,
or the path, and nothing points at this implementation — but it has not been
run down.

To reproduce this without a TUN device or root, drive a `Tunn` straight over a
`UdpSocket`: parse the server's parameters into an `Amnezia3Config`, build the
tunnel with `Tunn::new_with_amnezia3`, then per attempt call `encapsulate` with
a hand-built ICMP echo, drain `poll_outgoing_packet()` and send the queue
*before* the returned initiation, and feed replies to `decapsulate`. That covers
the whole protocol path; only the `device` module and UAPI socket are skipped.
Note the two spelling differences between a `.conf` and the UAPI — the 3.0 keys
are CamelCase in a file and snake_case over the socket, and
`HeaderProtectionKey` is base64 in a file but 64 hex characters over the socket.

### Validation is as permissive as the reference

amneziawg-go bounds almost nothing: S1–S4 have no maximum (only a minimum of 12
when header protection is on), and `Jc`/`Jmin`/`Jmax` have no range check at all.
Encoding Amnezia's *recommended* ranges as hard limits rejected real
configurations, so those limits are gone.

What is still enforced: header ranges must not overlap, S1–S4 must be ≥ 12 when a
header protection key is set, and `Jmin` must not exceed `Jmax` — the last one
being stricter than upstream, which would underflow computing `Jmax - Jmin`.

One divergence remains: S1–S4 are `u8` here and `uint16` upstream, so a padding
value above 255 is accepted by amneziawg-go and rejected here. Widening it would
break the `amnezia_config` C ABI, and Amnezia's own tooling stays far below that.

### Endpoint hostnames are not resolved

The UAPI `endpoint` key is parsed as a `SocketAddr`, so it needs a literal
`ip:port`. `wg-quick` resolves the hostname in an `Endpoint =` line before
talking to the UAPI; there is no equivalent here, so a configuration naming a
host must be resolved before it is pushed.

### Changing parameters on a live interface

The AmneziaWG parameters can be changed on a running device: `set=1` merges the
new keys over the current configuration, and `Device::set_amnezia_config`
rebuilds every peer's `Tunn` from the result. Sessions reset and the peers
re-handshake, which is not a loss — the parameters that changed *are* the wire
format, so any session in flight was already unusable by the peer that prompted
the change. `test_awg3_config_updates_are_incremental` covers it end to end.

What is still unsupported is modifying an existing *peer*: `update_peer` panics
rather than merging into a live one, which is a pre-existing boringtun
limitation unrelated to AmneziaWG. Remove the peer and add it back.

A bare `Tunn` has no equivalent — it captures its configuration at construction,
so a library caller changing parameters must build a new one.

## Comparison with amneziawg-go

### Protocol Fidelity

| Aspect | amneziawg-go | This implementation | Match |
|--------|-------------|---------------------|-------|
| Dynamic header before MAC | Yes | Yes | Exact |
| Padding after MAC | Always prepended | Always prepended | Exact |
| Send order (I→Junk→Init) | Atomic `SendBuffers` | Separate queue + drain | Functionally equivalent |
| S4 on keepalive | Applied (`elem.padding` set for every element) | Applied | Exact |
| "Data sent" classification | explicit `isKeepalive` flag, set in `SendKeepalive` | `src.is_empty()` in `encapsulate` | Exact |
| I-packets/junk on retry | Every attempt | Every attempt | Exact |
| Junk size distribution | `min + fastrandn(max - min)`, half-open | Half-open `[Jmin, Jmax)` | Exact |
| Header byte order | Little-endian u32 | Little-endian u32 | Exact |
| Packet classification | `DeterminePacketTypeAndPadding` (a `Device` method) | `PacketClassifier::classify` (peer-independent, as upstream's is) | Equivalent; ours also returns the keystream it derived |
| CPS tags | b, t, r, rc, rd, d, ds, dz | Same set | Exact |
| Transport header for keepalive | Same as data (H4) | Same as data (H4) | Exact |
| Header protection primitive | Raw ChaCha20, nonce = prefix[..12] | Same | Exact |
| Header protection spans | 148 / 92 / 64 / 16 | Same | Exact |
| MACs before encryption | Yes | Yes | Exact |
| All-zero header key = off | Yes | Yes (`Option`/NULL/all-zero) | Exact |
| Content padding inside AEAD | Yes, clamped to MTU segment | Same, plus a clamp to the caller's buffer | Exact when `dst` has room |
| All-zero payload on receive | Keepalive: `elem.packet[0] == 0` | `packet[0] == 0` | Exact |
| Other non-IP payload on receive | Dropped, counted as data received | Same | Exact |
| Timing range pick rules | Per-arm (see table above) | Same | Exact |
| Content padded to multiple of 16 | Yes, when CPA is unset | **No** (never has been) | **Differs** |
| Handshake give-up bound | Attempt count | Time (`timeout * attempts`) | Equivalent for default ranges |
| Retransmit timer jitter | 0-334 ms (`RekeyTimeoutJitterMaxMs`) | None | **Differs** |
| Persistent keepalive re-arm | Every authenticated packet traversal | On fire only | **Differs** |
| IP total-length lower bound | Rejects `< 20` (IPv4 header) | Only an upper bound is checked | **Differs** |
| Minimum spacing between initiations | `Lo(rekey_timeout)` | Structural (`is_in_progress`) | Functionally equivalent |

### Measured cost

`benches/crypto_benches/amnezia_benching.rs` covers the four AmneziaWG paths.
Numbers below are 1280-byte payloads on one machine, so treat the ratios rather
than the absolutes as the message. Plain WireGuard is the control: it runs the
same code with every parameter unset, so the gap between the rows is the price
of the obfuscation.

| | WireGuard | AWG 2.0 | AWG 3.0 |
|---|---:|---:|---:|
| `encapsulate` | 500 ns | 514 ns | 616 ns |
| `decapsulate` | 635 ns | 635 ns | 732 ns |
| handshake initiation | 38.7 µs | 38.8 µs | 39.0 µs |
| handshake with `Jc=8` | — | — | 39.8 µs |

`update_timers` is the one path whose cost scales with peer count rather than
packet rate — the device calls it for every peer every 250 ms, and it usually
has nothing to do. An idle peer draws two values from the timing ranges and an
established initiator four, so it is 42 ns for a WireGuard peer and 60 ns for an
AWG 3.0 one.

Those AWG 3.0 figures are roughly half what they were before the randomness
split above: `encapsulate` was 1077 ns, `decapsulate` 796 ns, and an established
peer's timer tick 680 ns, almost all of it `getrandom` syscalls.

### Architectural Differences

| | amneziawg-go | This implementation |
|---|---|---|
| **Header injection** | Sets `msg.Type` field in message struct, serialized with `binary.Write` | Passes `msg_type: u32` to formatting functions, written via `to_le_bytes()` |
| **Padding** | `make([]byte, padding+len); copy(buf[padding:], packet)` | Writes WG packet at `dst[padding..]`, fills `dst[..padding]` with random |
| **Padding stripping** | `copy(packet, packet[padding:])` (in-place shift) | `&datagram[padding..]` (zero-copy slice) |
| **Pre-handshake packets** | All sent atomically via `SendBuffers` | Queued in `VecDeque`, caller drains via `poll_outgoing_packet()` |
| **Config storage** | Fields on `Device` struct | Fields on `Tunn` struct (split from `Amnezia2Config`) |
| **Randomness** | `crypto/rand` | `RandomSource` trait (injectable for testing), `OsRandom` in production |
| **Config validation** | Implicit (Go type system + UAPI parsing) | Explicit `validate()` returning `Result<(), ConfigError>` |

### Key Difference: Send Atomicity

The Go implementation sends I-packets, junk, and the handshake init in a single `SendBuffers` call, ensuring they arrive as a burst. Our implementation queues them separately and relies on the caller to drain and send them in order before sending the init. This is by design — boringtun's API is "give me a buffer, I'll fill it" rather than "I'll send packets for you." The caller must follow this protocol:

```rust
// 1. Trigger handshake (returns the init packet)
let result = tunnel.encapsulate(ip_packet, &mut dst);
// 2. FIRST drain pre-handshake packets
while let Some(pkt) = tunnel.poll_outgoing_packet() {
    socket.send(&pkt);
}
// 3. THEN send the init from step 1
if let TunnResult::WriteToNetwork(init) = result {
    socket.send(init);
}
```

### Receive-Side Optimization

The Go implementation strips padding by copying data in-place (`copy(packet, packet[padding:])`). Our implementation uses a zero-copy slice (`&datagram[padding..]`), which is more efficient.

With header protection enabled the incoming datagram cannot be decrypted in place, since `decapsulate` takes `&[u8]`. Neither path allocates: handshake, response and cookie messages have a fixed size bounded by 148 bytes and decrypt into a stack buffer, while a transport packet's 16-byte header decrypts into a stack array and `PacketData` is assembled from it plus the untouched ciphertext slice.

Classification and decryption share one cipher. Everything decrypted in a
datagram uses that datagram's nonce, so `PacketClassifier::classify` derives 16
keystream bytes once and returns them in [`Classified::header_mask`]. A
transport header is exactly those 16 bytes, so the receive path XORs the mask in
rather than building a second ChaCha20 over the same key and nonce to recompute
bytes it already had. Handshake messages are protected past 16 bytes and still
call `apply`; that runs once per handshake rather than once per packet, so the
second setup does not matter there.

`classified_header_mask_matches_a_second_apply` pins the two against each other.
If they ever diverged, every AWG 3.0 data packet would decrypt to garbage while
handshakes kept working, which is a miserable symptom to debug backwards.

### What amneziawg-go Has That We Don't

- **Batched I/O**: amneziawg-go inherits wireguard-go's `IdealBatchSize = 128`
  reads and writes plus GSO on Linux (`conn/gso_linux.go`), so it amortizes one
  syscall over up to 128 packets. The `device` here does one `recv_from` per
  datagram. At high packet rates this dominates everything else on this page.
- **Ordering**: Go runs `RoutineSequentialSender`/`RoutineSequentialReceiver` to
  keep a peer's packets in order across its worker pool. Each thread here runs an
  independent event loop, so datagrams can be reordered between threads.
  WireGuard tolerates it — that is what the replay window is for — but it is a
  deliberate difference, inherited from upstream boringtun.
- **Live reconfiguration**: covered below.
- **Runtime config changes**: The Go version's peers read the device
  configuration live, so a UAPI update takes effect on the next packet. A `Tunn`
  captures its configuration at construction, so a `Device` implements the same
  thing by rebuilding its peers — the sessions reset where Go's would survive.
  A bare `Tunn` has to be recreated by its caller.

UAPI configuration is no longer on this list — see
[Device and UAPI](#device-and-uapi-boringtun-cli).

## Known Limitations

1. **No batched I/O**: amneziawg-go reads and writes up to 128 packets per syscall and uses GSO on Linux; this does one `recv_from` per datagram. At high packet rates that difference outweighs everything else on this page. (This entry used to read "client-only". That was wrong: `handle_handshake_init` answers an initiation with an H2 type, an S2 prefix and header protection, and `test_awg3_handshake_between_two_devices` has a working responder.)

2. **Interop is verified manually, not automatically**: this fork has completed handshakes and passed traffic against both amneziawg-go and the amneziawg kernel module, the latter with the full 3.0 feature set (see [Verified interoperability](#verified-interoperability)) — but those were manual runs. Automated coverage is still unit tests, a differential test against an independent reimplementation of the Go keystream, and integration tests between two boringtun devices — none of which would catch a misreading of the Go source shared by our implementation and our tests. A Docker-based test against amneziawg-go is not yet written, so interop can regress silently.

3. **Buffer size responsibility**: With padding active, callers must allocate larger output buffers than standard WireGuard. The `encapsulate()` and `format_handshake_initiation()` docs specify the required sizes.

4. **Runtime config changes cost the sessions**: a `Device` accepts new AmneziaWG parameters over the UAPI socket, but implements them by rebuilding each peer's `Tunn`, so established sessions drop and re-handshake. amneziawg-go's peers read device state live and keep their sessions. A bare `Tunn` cannot be reconfigured at all and must be rebuilt by its caller.

5. **Legacy fields rejected**: AmneziaWG 1.0/1.5 fields (`j1`, `j2`, `j3`, `itime`) are explicitly rejected.

6. **No 16-byte content alignment**: boringtun has never padded transport content to a multiple of 16, and AWG 3.0 does not change that. amneziawg-go does so whenever content padding is unset, so wire sizes differ from the Go implementation in that configuration — an observable fingerprint difference, though not an interop failure. With content padding configured, upstream skips the alignment too and the implementations agree.

7. **Timing randomization is per-tunnel**: amneziawg-go stores timing ranges on the device and the persistent-keepalive range on the peer. Here everything lives on `Tunn`, so each tunnel picks independently.

8. **No retransmit jitter**: amneziawg-go adds a random 0-334 ms (`RekeyTimeoutJitterMaxMs`) to the handshake retransmit and new-handshake timers, as stock wireguard-go does. boringtun has never added this jitter and AWG 3.0 does not change that. The `rekey_timeout` range supplies coarser randomization at second granularity, so retransmit timing is still randomized — just quantized to whole seconds rather than milliseconds.

9. **No lower bound on the decapsulated IP total-length field**: amneziawg-go drops a packet whose declared length is below the IP header size (`int(length) < ipv4.HeaderLen`); `validate_decapsulated_packet` checks only that the declared length does not exceed the buffer. A peer that declares a total length under 20 therefore yields a truncated slice to the caller rather than being dropped. Reaching this requires an already-authenticated peer — the payload has passed AEAD verification — so it is a hostile-peer concern, not a network-attacker one. It predates the AWG work and is inherited from upstream boringtun.

10. **Persistent keepalive re-arms on fire, not on traffic**: in amneziawg-go, `timersAnyAuthenticatedPacketTraversal` re-arms the persistent-keepalive timer with a fresh range pick after *every* authenticated packet sent or received, so a new interval is drawn constantly and keepalives only fire when the link is idle. boringtun's timer is not reset by other traffic — it fires on a fixed cadence from the last keepalive — so a new interval is drawn only when one fires. This follows from pre-existing boringtun timer behavior rather than the AWG 3.0 work; aligning it would change standard WireGuard behavior too.
