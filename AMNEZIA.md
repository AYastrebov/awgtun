# AmneziaWG 2.0 Implementation Details

This document describes the AmneziaWG 2.0 protocol implementation in this boringtun fork, how it maps to the [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) reference, and where the two implementations differ.

## Table of Contents

- [Protocol Overview](#protocol-overview)
- [Configuration Parameters](#configuration-parameters)
- [Packet Layout](#packet-layout)
- [Implementation Architecture](#implementation-architecture)
- [File-by-File Changes](#file-by-file-changes)
- [Rust API](#rust-api)
- [C FFI API](#c-ffi-api)
- [Comparison with amneziawg-go](#comparison-with-amneziawg-go)
- [Known Limitations](#known-limitations)

## Protocol Overview

AmneziaWG 2.0 adds four obfuscation layers on top of standard WireGuard:

1. **Dynamic headers (H1-H4):** Replace fixed WireGuard message type constants (1, 2, 3, 4) with random values from configurable ranges.
2. **Packet padding (S1-S4):** Prepend random bytes to each packet type to obscure sizes.
3. **Junk packets (Jc/Jmin/Jmax):** Send random decoy datagrams before handshake initiation.
4. **Init packets (I1-I5):** Send CPS (Custom Packet Signature) datagrams before handshake for protocol camouflage.

All four layers are independent and can be enabled selectively. When all parameters are zero/default, the tunnel behaves as standard WireGuard.

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
| Jmin | u16 | 64-1024 | Minimum junk size |
| Jmax | u16 | 64-1024 | Maximum junk size |
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
| `device/mod.rs` | Passes `&HeaderConfig::default()` to `verify_packet()`. |
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
```

### Functions

```c
// Create tunnel with AWG config (NULL config = standard WireGuard)
void* new_tunnel_amnezia(
    const char *private_key, const char *public_key,
    const char *preshared_key, uint16_t keep_alive,
    uint32_t index, const amnezia_config *config);

// Drain pre-handshake packets (call in loop until returns 0)
size_t wireguard_poll_outgoing_packet(
    void *tunnel, uint8_t *dst, uint32_t dst_size);
```

## Comparison with amneziawg-go

### Protocol Fidelity

| Aspect | amneziawg-go | This implementation | Match |
|--------|-------------|---------------------|-------|
| Dynamic header before MAC | Yes | Yes | Exact |
| Padding after MAC | Always prepended | Always prepended | Exact |
| Send order (I→Junk→Init) | Atomic `SendBuffers` | Separate queue + drain | Functionally equivalent |
| S4 skip for keepalive | `len != keepaliveSize` | `src.is_empty()` | Equivalent |
| I-packets/junk on retry | Every attempt | Every attempt | Exact |
| Header byte order | Little-endian u32 | Little-endian u32 | Exact |
| Packet classification | `DeterminePacketTypeAndPadding` | `determine_padding()` | Functionally equivalent |
| CPS tags | b, t, r, rc, rd, d, ds, dz | Same set | Exact |
| Transport header for keepalive | Same as data (H4) | Same as data (H4) | Exact |

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

### What amneziawg-go Has That We Don't

- **Server/responder mode**: We only implement client-side AWG. The Go version supports both.
- **UAPI configuration**: The Go version accepts AWG parameters via the WireGuard UAPI interface. We use typed Rust constructors.
- **Runtime config changes**: The Go version can update AWG parameters via UAPI at runtime. Our config is set at tunnel creation.

## Known Limitations

1. **Client-only**: This fork supports outbound AmneziaWG connections only. Server/inbound mode is not implemented.

2. **No interop test suite yet**: Protocol correctness is verified by unit tests and code review against amneziawg-go. Automated interop tests against the Go server (Phase 8 of the implementation plan) are not yet implemented.

3. **Buffer size responsibility**: With padding active, callers must allocate larger output buffers than standard WireGuard. The `encapsulate()` and `format_handshake_initiation()` docs specify the required sizes.

4. **No runtime config changes**: AWG parameters are fixed at tunnel creation. Changing them requires creating a new tunnel.

5. **AmneziaWG 2.0 only**: Legacy AmneziaWG 1.0/1.5 fields (`j1`, `j2`, `j3`, `itime`) are explicitly rejected.
