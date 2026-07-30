# AmneziaWG Implementation Details

This document describes the AmneziaWG 2.0 and 3.0 protocol implementation in this boringtun fork, how it maps to the [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) reference, and where the two implementations differ.

## Table of Contents

- [Protocol Overview](#protocol-overview)
- [Configuration Parameters](#configuration-parameters)
- [AmneziaWG 3.0](#amneziawg-30)
- [Packet Layout](#packet-layout)
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
| S1 | u8 | 0-64 | Init padding bytes |
| S2 | u8 | 0-64 | Response padding bytes |
| S3 | u8 | 0-64 | Cookie padding bytes |
| S4 | u8 | 0-32 | Transport padding bytes |
| Jc | u8 | 0-10 | Junk packet count (0 = disabled) |
| Jmin | u16 | 64-1024 | Minimum junk size (inclusive) |
| Jmax | u16 | 64-1024 | Maximum junk size (exclusive, as in amneziawg-go) |
| I1-I5 | CPS string | See below | Init packet chain specs |

### CPS Chain Format

Init packets use a tag-based format: `<tag [arg]><tag [arg]>...`

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

For I1-I5 init packets, source data is always empty (`<d>`, `<ds>`, `<dz>` produce zero/empty output).

### Validation Rules

- Header ranges must not overlap with each other.
- When any AWG feature is active, header values must not be 1, 2, 3, or 4 (standard WireGuard types).
- If I1 is absent, I2-I5 must also be absent. No gaps allowed (I1, I3 without I2 is invalid).
- Jmin must not exceed Jmax.

## AmneziaWG 3.0

Reference: amneziawg-go @ `d57d98d`. Configure with `Amnezia3Config` and `Tunn::new_with_amnezia3`.

### Header protection

Raw, unauthenticated ChaCha20 (32-byte key, 12-byte nonce, block counter 0) over the low-entropy header fields of every datagram. The nonce is the **first 12 bytes of the random padding prefix**, which is why enabling header protection requires S1-S4 to all be at least 12.

Note that the AmneziaWG README says the minimum is 8; the code (`uapi.go`, `HeaderCipherNonceSize`) enforces 12. We follow the code.

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

Keepalives are padded too. Since amneziawg-go classifies an outbound packet as "data sent" by comparing its wire size against the unpadded 32-byte keepalive, a padded keepalive counts as data and arms the new-handshake timer. This fork replicates that, and it applies to a non-zero S4 as well as to content padding.

A padded keepalive decrypts to all zeros, which is neither IPv4 nor IPv6. Such payloads are dropped silently and counted as data received, as in the Go sequential receiver.

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

Go also uses `Lo(rekey_timeout)` as the minimum spacing between initiations (`rekeyMinTimeout`). boringtun has no equivalent — it suppresses duplicate initiations structurally, via `is_in_progress()`.

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

## Implementation Architecture

The implementation follows a layered approach that minimizes changes to boringtun's core Noise state machine:

```
┌─────────────────────────────────────────────┐
│              Tunn (noise/mod.rs)             │
│  - Owns Amnezia2Config fields               │
│  - Generates dynamic headers from ranges    │
│  - Prepends/strips padding                  │
│  - Queues I-packets and junk                │
│  - Calls determine_padding() on receive     │
├─────────────────────────────────────────────┤
│     Handshake / Session / RateLimiter       │
│  - Accept msg_type: u32 parameter           │
│  - Write msg_type into packet BEFORE MAC    │
│  - No knowledge of ranges or padding        │
├─────────────────────────────────────────────┤
│            amnezia.rs module                │
│  - Config types + validation                │
│  - RandomSource trait + OsRandom            │
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
| `amnezia.rs` | ~1155 | All AWG config types, validation, CPS parser/generator, junk generation, `RandomSource` trait |

### Modified Files

| File | Change Summary |
|------|---------------|
| `noise/mod.rs` | `Tunn` struct gains AWG config fields + `network_outgoing` queue. `new_with_amnezia()` constructor. `parse_incoming_packet_config()` classifies by header ranges. `encapsulate()`/`decapsulate()` apply/strip padding. `format_handshake_initiation()` queues I-packets + junk. `determine_padding()` replicates Go's `DeterminePacketTypeAndPadding`. |
| `noise/handshake.rs` | `format_handshake_initiation()`, `format_handshake_response()`, `receive_handshake_initialization()` accept `msg_type: u32` parameter. Dynamic header written before MAC. |
| `noise/session.rs` | `format_packet_data()` accepts `msg_type: u32`. Dynamic transport header. |
| `noise/rate_limiter.rs` | `verify_packet()` accepts `&HeaderConfig`. `format_cookie_reply()` accepts `msg_type: u32`. Dynamic cookie header generation. |
| `noise/timers.rs` | `clear_all()` also clears `network_outgoing` queue. |
| `device/mod.rs` | Device-scoped `Amnezia3Config`. Peers built with `new_with_amnezia3()`. Inbound datagrams stripped and header-decrypted before `verify_packet()`. Cookie replies padded and protected. Junk/I-packets drained at the four sites that can start a handshake. |
| `device/api.rs` | AmneziaWG interface keys collected into a block for `Amnezia3Config::parse` on `set=1`; `to_uapi_block()` emitted on `get=1`. Per-peer `persistent_keepalive_interval` accepts an AWG 3.0 range. |
| `device/peer.rs` | `drain_outgoing()` helper; keeps the configured keepalive range for `get=1`. |
| `ffi/mod.rs` | `amnezia_config` C struct, `new_tunnel_amnezia()`, `wireguard_poll_outgoing_packet()`. |
| `lib.rs` | `pub mod amnezia;` |

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
`com.cloudflare.app.boringtun.BoringTunJNI`. AmneziaWG is configured with a
single UAPI-style `key=value` block rather than a long scalar signature — the
same text an AmneziaWG `.conf` file carries:

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

> **Note:** every JNI export is bound to the literal class name
> `com.cloudflare.app.boringtun.BoringTunJNI` via `#[export_name]`. A consumer
> shipping its own package must either keep that class name or patch the export
> prefix in `boringtun/src/jni.rs`.

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

Over the UAPI wire these become the lowercase `key=value` names that
`Amnezia3Config::parse` accepts — the same format the JNI surface takes. See
[JNI API (Android)](#jni-api-android) for the full key list.

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

### Two divergences from WireGuard's UAPI

**AmneziaWG parameters are replace-all per `set=1`.** WireGuard's UAPI is
incremental — each key patches current state. The AmneziaWG keys in an interface
section are instead collected and parsed as one block, so a key absent from a
non-empty block returns to its default. This is what lets the cross-field rules
(overlapping header ranges, S1–S4 ≥ 12 under header protection) be validated
atomically, and it means a rejected configuration leaves the device untouched. A
`set=1` carrying *no* AmneziaWG keys leaves the existing configuration alone, so
peer-only updates are safe.

**`mtu` is ignored on this path.** The key exists only because `Tunn` has no
concept of an MTU, which matters for the FFI and JNI surfaces. A device does
know its interface MTU, and it is authoritative, so content padding is clamped
against the live value.

### Changing parameters on a live interface

Not supported. `update_peer` refuses to modify an existing peer — a pre-existing
boringtun limitation, unrelated to AmneziaWG — and the parameters are baked into
each peer's `Tunn` at construction. Take the interface down and bring it back up.

## Comparison with amneziawg-go

### Protocol Fidelity

| Aspect | amneziawg-go | This implementation | Match |
|--------|-------------|---------------------|-------|
| Dynamic header before MAC | Yes | Yes | Exact |
| Padding after MAC | Always prepended | Always prepended | Exact |
| Send order (I→Junk→Init) | Atomic `SendBuffers` | Separate queue + drain | Functionally equivalent |
| S4 on keepalive | Applied (`elem.padding` set for every element) | Applied | Exact |
| "Data sent" classification | `len(packet) != MessageKeepaliveSize` | `packet.len() != 32` | Exact |
| I-packets/junk on retry | Every attempt | Every attempt | Exact |
| Junk size distribution | `min + fastrandn(max - min)`, half-open | Half-open `[Jmin, Jmax)` | Exact |
| Header byte order | Little-endian u32 | Little-endian u32 | Exact |
| Packet classification | `DeterminePacketTypeAndPadding` | `determine_padding()` | Functionally equivalent |
| CPS tags | b, t, r, rc, rd, d, ds, dz | Same set | Exact |
| Transport header for keepalive | Same as data (H4) | Same as data (H4) | Exact |
| Header protection primitive | Raw ChaCha20, nonce = prefix[..12] | Same | Exact |
| Header protection spans | 148 / 92 / 64 / 16 | Same | Exact |
| MACs before encryption | Yes | Yes | Exact |
| All-zero header key = off | Yes | Yes (`Option`/NULL/all-zero) | Exact |
| Content padding inside AEAD | Yes, clamped to MTU segment | Same, plus a clamp to the caller's buffer | Exact when `dst` has room |
| Non-IP payload on receive | Dropped, counted as data received | Same | Exact |
| Timing range pick rules | Per-arm (see table above) | Same | Exact |
| Content padded to multiple of 16 | Yes, when CPA is unset | **No** (never has been) | **Differs** |
| Handshake give-up bound | Attempt count | Time (`timeout * attempts`) | Equivalent for default ranges |
| Retransmit timer jitter | 0-334 ms (`RekeyTimeoutJitterMaxMs`) | None | **Differs** |
| Persistent keepalive re-arm | Every authenticated packet traversal | On fire only | **Differs** |
| IP total-length lower bound | Rejects `< 20` (IPv4 header) | Only an upper bound is checked | **Differs** |
| Minimum spacing between initiations | `Lo(rekey_timeout)` | Structural (`is_in_progress`) | Functionally equivalent |

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

### What amneziawg-go Has That We Don't

- **Server/responder mode**: We only implement client-side AWG. The Go version supports both.
- **Runtime config changes**: The Go version can update AWG parameters via UAPI at runtime. Ours are fixed when the tunnel is constructed, so changing them means recreating it.

UAPI configuration is no longer on this list — see
[Device and UAPI](#device-and-uapi-boringtun-cli).

## Known Limitations

1. **Client-only**: This fork supports outbound AmneziaWG connections only. Server/inbound mode is not implemented.

2. **No cross-implementation interop test**: protocol correctness is verified by unit tests, a differential test against an independent reimplementation of the Go keystream sequence, and integration tests between two boringtun devices. Nothing here has yet exchanged a packet with amneziawg-go itself, so a shared misreading of the Go source would not be caught. The manual recipe in [Device and UAPI](#device-and-uapi-boringtun-cli) is the way to close that gap today; an automated Docker-based test against the Go implementation is not yet written.

3. **Buffer size responsibility**: With padding active, callers must allocate larger output buffers than standard WireGuard. The `encapsulate()` and `format_handshake_initiation()` docs specify the required sizes.

4. **No runtime config changes**: AWG parameters are fixed at tunnel creation. Changing them requires creating a new tunnel.

5. **Legacy fields rejected**: AmneziaWG 1.0/1.5 fields (`j1`, `j2`, `j3`, `itime`) are explicitly rejected.

6. **No 16-byte content alignment**: boringtun has never padded transport content to a multiple of 16, and AWG 3.0 does not change that. amneziawg-go does so whenever content padding is unset, so wire sizes differ from the Go implementation in that configuration — an observable fingerprint difference, though not an interop failure. With content padding configured, upstream skips the alignment too and the implementations agree.

7. **Timing randomization is per-tunnel**: amneziawg-go stores timing ranges on the device and the persistent-keepalive range on the peer. Here everything lives on `Tunn`, so each tunnel picks independently.

8. **No retransmit jitter**: amneziawg-go adds a random 0-334 ms (`RekeyTimeoutJitterMaxMs`) to the handshake retransmit and new-handshake timers, as stock wireguard-go does. boringtun has never added this jitter and AWG 3.0 does not change that. The `rekey_timeout` range supplies coarser randomization at second granularity, so retransmit timing is still randomized — just quantized to whole seconds rather than milliseconds.

9. **No lower bound on the decapsulated IP total-length field**: amneziawg-go drops a packet whose declared length is below the IP header size (`int(length) < ipv4.HeaderLen`); `validate_decapsulated_packet` checks only that the declared length does not exceed the buffer. A peer that declares a total length under 20 therefore yields a truncated slice to the caller rather than being dropped. Reaching this requires an already-authenticated peer — the payload has passed AEAD verification — so it is a hostile-peer concern, not a network-attacker one. It predates the AWG work and is inherited from upstream boringtun.

10. **Persistent keepalive re-arms on fire, not on traffic**: in amneziawg-go, `timersAnyAuthenticatedPacketTraversal` re-arms the persistent-keepalive timer with a fresh range pick after *every* authenticated packet sent or received, so a new interval is drawn constantly and keepalives only fire when the link is idle. boringtun's timer is not reset by other traffic — it fires on a fixed cadence from the last keepalive — so a new interval is drawn only when one fires. This follows from pre-existing boringtun timer behavior rather than the AWG 3.0 work; aligning it would change standard WireGuard behavior too.
