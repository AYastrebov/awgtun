# Plan: Fork BoringTun and Implement AmneziaWG 2.0 Client Core

## Objective

Build a Rust-native AmneziaWG 2.0 protocol core by forking BoringTun and adding only the protocol behavior needed for a `shoes` outbound client. The result should let `shoes` establish a WireGuard-style encrypted tunnel to existing AmneziaWG 2.0 servers without running `amneziawg-go` as a subprocess and without depending on a kernel AmneziaWG module.

The fork is intentionally client-focused. It must be able to initiate a tunnel, maintain handshakes, send encrypted IP packets, receive encrypted IP packets, process server responses, process cookie replies, and keep the session alive. It does not need to accept AmneziaWG clients as a server.

## Reference Projects

- BoringTun: <https://github.com/cloudflare/boringtun>
  BoringTun is the Rust WireGuard userspace implementation to fork. It already provides the WireGuard Noise state machine, timers, packet queueing, session handling, and packet encapsulation/decapsulation API.

- AmneziaWG Go implementation: <https://github.com/amnezia-vpn/amneziawg-go>
  This is the behavioral reference. Its UAPI exposes the Amnezia-specific configuration fields (`jc`, `jmin`, `jmax`, `s1-s4`, `h1-h4`, `i1-i5`) and its packet path shows where these fields are applied.

- AmneziaWG protocol documentation: <https://docs.amnezia.org/documentation/amnezia-wg/>
  This defines AmneziaWG 2.0 as dynamic headers for all WireGuard packet types, randomized packet sizes, pre-handshake signature packets, and junk packets while keeping WireGuard cryptography.

- Xray WireGuard outbound approach: <https://github.com/XTLS/Xray-core/tree/main/proxy/wireguard>
  Xray is useful as an architecture reference, not as code to port directly. It treats WireGuard as an L3 tunnel with a virtual network interface and exposes TCP/UDP dialing through that tunnel. `shoes` should follow that model conceptually.

## Scope

In scope:

- Fork BoringTun into a crate that can be consumed by `shoes`.
- Implement AmneziaWG 2.0 packet behavior.
- Support client/outbound operation only.
- Support one AmneziaWG server peer for the first production milestone.
- Support IPv4 and IPv6 inner tunnel packets when the later `shoes` integration can feed them.
- Keep the public core API independent of OS TUN devices.
- Provide deterministic test hooks for random header, padding, CPS, and junk generation.
- Provide interop tests against official `amneziawg-go`.

Out of scope:

- AmneziaWG server/inbound mode.
- Kernel TUN, kernel module management, `wg-quick`, or platform network interface setup.
- WireGuard config file parsing as a primary API.
- Full AmneziaWG 1.0/1.5 compatibility.
- GUI client export/import support.
- Routing policy inside the protocol core.

Compatibility expectation:

- If all Amnezia-specific values are disabled or zeroed, the fork should continue to behave like ordinary WireGuard where practical. This is useful as a regression baseline, but the supported product target is AmneziaWG 2.0.

## Why Fork BoringTun First

BoringTun already has the highest-risk WireGuard internals:

- Noise_IK handshake flow.
- X25519 key agreement.
- ChaCha20-Poly1305 encryption.
- Blake2s hashing and MAC handling.
- Cookie replies and rate-limiter behavior.
- Session rotation and replay protection.
- Persistent keepalive and handshake timers.
- A library API where the caller provides network and tunnel packet I/O.

Reimplementing those parts directly in `shoes` would create unnecessary cryptographic and protocol risk. The fork should preserve BoringTun's state machine as much as possible and concentrate changes around packet encoding, packet classification, and Amnezia-specific pre-handshake traffic.

## High-Level Architecture

Create a fork with a crate name that makes the protocol scope explicit, for example:

- Repository: `boringtun-awg` or `amneziawg-boringtun`.
- Library crate: `amneziawg_tunnel` or `boringtun_awg`.
- Optional CLI crate only for manual interop debugging, not required by `shoes`.

The fork should preserve the core BoringTun abstraction:

```rust
pub struct Tunn { ... }

impl Tunn {
    pub fn encapsulate<'a>(&mut self, ip_packet: &[u8], out: &'a mut [u8]) -> TunnResult<'a>;
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        out: &'a mut [u8],
    ) -> TunnResult<'a>;
}
```

Then add AmneziaWG 2.0 configuration and packet codec behavior:

```rust
pub struct Amnezia2Config {
    pub junk: JunkConfig,
    pub paddings: PaddingConfig,
    pub headers: HeaderConfig,
    pub init_packets: InitPacketConfig,
}

pub struct HeaderRange {
    pub start: u32,
    pub end: u32,
}

pub struct PaddingConfig {
    pub s1: u8,
    pub s2: u8,
    pub s3: u8,
    pub s4: u8,
}

pub struct JunkConfig {
    pub count: u8,
    pub min_size: u16,
    pub max_size: u16,
}

pub struct InitPacketConfig {
    pub i1: Option<CpsChain>,
    pub i2: Option<CpsChain>,
    pub i3: Option<CpsChain>,
    pub i4: Option<CpsChain>,
    pub i5: Option<CpsChain>,
}
```

The preferred internal shape is a packet codec abstraction:

```rust
trait PacketCodec {
    fn encode_handshake_initiation(...);
    fn encode_handshake_response(...);
    fn encode_cookie_reply(...);
    fn encode_transport(...);
    fn classify_incoming(&self, packet: &[u8]) -> Result<LogicalPacket, PacketError>;
}
```

The standard WireGuard codec can remain close to BoringTun's current constants. The AmneziaWG 2.0 codec can own dynamic headers, padding, packet-prefix handling, CPS packets, and junk generation. If a full trait split is too invasive, start with a smaller `PacketLayout` helper, but keep the same separation in mind.

## Xray-Core Lessons To Reuse

Xray's WireGuard code is useful because it models WireGuard as a network tunnel, not as a stream protocol:

- `DeviceConfig` stores keys, local tunnel addresses, peers, MTU, worker count, and domain strategy.
- `createIPCRequest` serializes the device and peer configuration into the WireGuard device.
- `Tunnel` exposes `BuildDevice`, `DialContextTCPAddrPort`, `DialUDPAddrPort`, and `Close`.
- The outbound handler keeps a long-lived tunnel and dials TCP/UDP through it for each proxied request.
- The network bind layer controls how WireGuard UDP packets reach the peer.

For Rust and `shoes`, do not copy the Go structure literally. Use the lesson:

- The protocol core should not know about `shoes` routing.
- The protocol core should accept IP packets and produce UDP datagrams.
- The integration layer should own the UDP socket and the virtual network stack.
- The integration layer should expose TCP/UDP dialing through the tunnel.

## Detailed Implementation Plan

### Phase 0: Fork Hygiene And Upstream Baseline

1. Fork BoringTun at a pinned upstream commit.
2. Add an `upstream-main` remote branch or tag policy so future security fixes can be compared.
3. Rename only what is necessary in Cargo metadata. Avoid large cosmetic rewrites.
4. Run BoringTun's existing unit tests and record the baseline.
5. Add CI for:
   - `cargo fmt --check`
   - `cargo clippy`
   - `cargo test`
   - Linux x86_64
   - Linux aarch64 if available
   - macOS if the crate needs to build for local development
   - Android/iOS targets later, once `shoes` mobile integration starts

Deliverable:

- A fork that behaves like BoringTun before Amnezia-specific changes.

### Phase 1: Public Configuration Types

Add typed AmneziaWG 2.0 configuration before changing packet behavior.

Validation rules:

- `H1-H4` must each be either a single `u32` value or a closed `start..=end` range.
- Header ranges must not overlap.
- Header values must not accidentally classify as ordinary WireGuard standard headers unless the config explicitly allows zero/standard compatibility.
- `S1-S3` should follow AmneziaWG 2.0 documented limits. Treat out-of-range values as config errors.
- `S4` should follow the stricter transport padding limit from AmneziaWG 2.0 docs.
- `Jc`, `Jmin`, and `Jmax` must be validated together:
  - `Jc == 0` disables junk train.
  - If `Jc > 0`, `Jmin <= Jmax`.
  - Reject values that would exceed the effective outer MTU when combined with UDP/IP overhead, or at least return a warning/error path to the caller.
- `I1-I5` must parse as CPS chains.
- If `I1` is absent, skip the whole `I1-I5` signature chain. This matches the documented AmneziaWG behavior.
- Reject unsupported 1.0/1.5-only aliases. This fork supports 2.0 only.

Parsing should not be YAML-specific. The crate should expose typed constructors and parsers for individual fields:

```rust
impl HeaderRange {
    pub fn parse(input: &str) -> Result<Self, ConfigError>;
}

impl CpsChain {
    pub fn parse(input: &str) -> Result<Self, ConfigError>;
}
```

Deliverable:

- Config structs with strict validation.
- Unit tests for all validation edges.

### Phase 2: CPS Parser And Generator

Implement CPS packet generation for `I1-I5`.

AmneziaWG 2.0 tag set to support:

- `<b 0x...>` static bytes.
- `<r N>` cryptographically random bytes.
- `<rd N>` random ASCII decimal digits.
- `<rc N>` random ASCII alphanumeric or alphabetic characters according to the official 2.0 behavior. Confirm exact character set from `amneziawg-go`.
- `<t>` 32-bit Unix timestamp in network byte order if that is what the reference uses.
- `<c>` packet counter if supported by the 2.0 reference implementation.

Important implementation detail:

- Make random generation injectable for tests:

```rust
pub trait RandomSource {
    fn fill_bytes(&mut self, out: &mut [u8]);
    fn gen_range_u32(&mut self, start: u32, end: u32) -> u32;
}
```

Production can use `rand_core::OsRng` or the project's existing randomness choice. Tests can use a deterministic RNG.

Generation behavior:

- Before every handshake initiation, generate each configured `I` packet in order.
- Skip missing packets after `I1` according to confirmed reference behavior.
- Emit each generated packet as an extra UDP datagram before the real handshake initiation.
- Keep CPS generation outside the Noise state transition itself. The CPS packets are transport camouflage, not WireGuard packets.

Deliverable:

- CPS parser.
- CPS generator.
- Golden tests for deterministic generation.
- Size limit tests.

### Phase 3: Junk Train Generation

Implement `Jc`, `Jmin`, `Jmax`.

Behavior:

- When a handshake initiation is about to be sent, emit:
  1. `I1-I5` signature datagrams, if configured.
  2. `Jc` random junk datagrams.
  3. The AmneziaWG handshake initiation datagram.

Each junk datagram:

- Has random length in `[Jmin, Jmax]`.
- Contains cryptographically random bytes.
- Is not fed into the WireGuard state machine.

Testing:

- Deterministic RNG verifies count and sizes.
- MTU guard verifies oversized junk is rejected or reported.
- Interop test verifies official `amneziawg-go` server ignores these datagrams and completes handshake.

Deliverable:

- A queued network-output API that can return multiple datagrams for one tunnel event.

### Phase 4: Packet Header Ranges

BoringTun currently classifies packets by exact standard WireGuard message type and size:

- `1`: handshake initiation.
- `2`: handshake response.
- `3`: cookie reply.
- `4`: transport data.

AmneziaWG 2.0 replaces these fixed headers with configured `H1-H4` values or ranges.

Required changes:

- Outbound:
  - For each packet type, choose a random header value from the configured range.
  - Write that value in the exact byte order used by `amneziawg-go`.
  - Ensure the value participates in authentication/MAC calculations at the same stage as the reference implementation.

- Inbound:
  - Classify the packet by matching the first four bytes against `H1-H4`.
  - Map the matched value back to a logical WireGuard packet type.
  - Normalize only internally. Do not mutate caller buffers unless explicitly documented.
  - Reject packets whose header does not match any configured range.

Reference detail to verify in `amneziawg-go`:

- Whether the logical type is ever restored before MAC verification.
- Whether the dynamic header is included directly in MAC1/MAC2 input.
- Whether the value is little-endian or big-endian on the wire.
- Whether any reserved/type bits are interpreted beyond the full `u32`.

Implementation recommendation:

- Add `LogicalMessageType`:

```rust
enum LogicalMessageType {
    HandshakeInit,
    HandshakeResponse,
    CookieReply,
    Transport,
}
```

- Add `HeaderCodec`:

```rust
struct HeaderCodec {
    init: HeaderRange,
    response: HeaderRange,
    cookie: HeaderRange,
    transport: HeaderRange,
}
```

- Keep packet parsing based on logical message type after classification.

Deliverable:

- Dynamic header send/receive.
- Non-overlap enforcement.
- Unit tests for all boundary values.
- Fuzz tests for random unknown headers.

### Phase 5: S1-S4 Padding And Packet Layout

AmneziaWG 2.0 adds randomized padding/prefix bytes to all packet classes:

- `S1`: handshake initiation.
- `S2`: handshake response.
- `S3`: cookie reply.
- `S4`: transport data.

This is the most protocol-sensitive phase. It must mirror `amneziawg-go` exactly.

Tasks:

1. Identify the reference layout in `amneziawg-go`:
   - Is padding before the logical WireGuard fields or after the fixed header?
   - Is padding length fixed to the configured value or random in `0..=Sx`?
   - Is padding authenticated?
   - Are MAC offsets shifted by the padding length?
   - How does the receiver infer padding length?

2. Implement packet builders per logical packet type:
   - Build the message body using BoringTun's existing state machine.
   - Insert Amnezia padding at the same stage as reference.
   - Compute or verify authentication over the same bytes as reference.
   - Return the fully obfuscated UDP datagram.

3. Implement packet parsers:
   - Classify by `H1-H4`.
   - Determine and strip or account for padding.
   - Feed the logical WireGuard fields to BoringTun's existing handshake/session code.

4. Add careful size accounting:
   - Output buffer sizing must account for standard WireGuard overhead plus max padding.
   - Transport packets must leave enough room for outer UDP/IP overhead.
   - The API should expose `max_outbound_datagram_size(inner_packet_len)`.

Testing:

- Fixed RNG tests for each packet type.
- Round-trip encode/decode tests.
- Interop with `amneziawg-go`.
- Capture-based tests asserting packet sizes vary according to config.

Deliverable:

- AmneziaWG 2.0 packet layout support for all four packet types.

### Phase 6: Multi-Datagram Output API

BoringTun's classic API returns one `WriteToNetwork` packet for a given operation. AmneziaWG handshake initiation may need to emit several datagrams: `I1-I5`, junk packets, then the real handshake initiation.

Add a client-friendly output API:

```rust
pub enum TunnelOutput<'a> {
    Done,
    WriteNetwork(&'a [u8]),
    WriteTunnelV4(&'a [u8], Ipv4Addr),
    WriteTunnelV6(&'a [u8], Ipv6Addr),
    Error(TunnelError),
}

pub struct OutputQueue { ... }
```

Possible designs:

- Keep BoringTun's `TunnResult` for compatibility and add `drain_network_outputs()`.
- Or return a small iterator/batch from `encapsulate`.

Recommended for `shoes`:

- Let `encapsulate` enqueue all network datagrams internally.
- The integration layer repeatedly calls `poll_next_network_datagram` until empty.
- This avoids forcing every caller to understand CPS and junk sequencing.

Deliverable:

- A stable API that `shoes` can drive without protocol-specific special cases.

### Phase 7: Timer And Keepalive Behavior

Client operation needs handshake retry, persistent keepalive, and session refresh.

Tasks:

- Preserve BoringTun timer behavior.
- Ensure AmneziaWG CPS/junk packets are emitted before each new handshake initiation, including retries.
- Ensure persistent keepalive transport packets use `H4` and `S4`.
- Ensure cookie replies are parsed with `H3` and `S3`.
- Expose timer deadlines to the integration layer:

```rust
pub fn next_timer_deadline(&self) -> Option<Instant>;
pub fn update_timers(&mut self, now: Instant, out: &mut OutputQueue);
```

Deliverable:

- A tunnel core that can be driven by a Tokio task without busy polling.

### Phase 8: Interop Test Harness

Create an interop harness before declaring protocol support complete.

Test topology:

- Start official `amneziawg-go` or AmneziaWG kernel module in a network namespace/container.
- Configure an AmneziaWG 2.0 server with known keys and obfuscation params.
- Run the Rust fork as client.
- Send ICMP, UDP, and TCP inner packets through the tunnel.
- Capture outer UDP packets with `tcpdump`.

Interop cases:

- Minimal 2.0 config with only `H1-H4` and `S1-S4`.
- Full config with `I1-I5`, `Jc`, `Jmin`, `Jmax`, `H1-H4`, `S1-S4`.
- IPv4 only.
- IPv6 only.
- Dual stack.
- Persistent keepalive.
- Handshake retry after dropped first response.
- Cookie reply path if practical.
- MTU edge cases.

Assertions:

- Handshake completes.
- Server sees client inner address.
- Client can receive response data.
- Captured packets do not use standard WireGuard headers `1`, `2`, `3`, `4` when Amnezia headers are configured.
- Packet sizes vary according to S/J settings.
- No packet exceeds configured effective MTU.

Deliverable:

- Automated Linux interop tests.
- Manual test instructions for macOS if needed.

### Phase 9: Public API For Shoes

The fork should expose a narrow API for `shoes`:

```rust
pub struct ClientTunnelConfig {
    pub private_key: StaticSecret,
    pub peer_public_key: PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<Duration>,
    pub amnezia: Amnezia2Config,
    pub mtu: usize,
}

pub struct ClientTunnel { ... }

impl ClientTunnel {
    pub fn new(config: ClientTunnelConfig) -> Result<Self, Error>;
    pub fn encapsulate_ip_packet(&mut self, ip_packet: &[u8], out: &mut OutputQueue) -> Result<()>;
    pub fn decapsulate_udp_datagram(
        &mut self,
        source: Option<IpAddr>,
        datagram: &[u8],
        out: &mut OutputQueue,
    ) -> Result<()>;
    pub fn update_timers(&mut self, now: Instant, out: &mut OutputQueue) -> Result<()>;
}
```

The core must not:

- Open sockets.
- Resolve DNS.
- Create OS TUN devices.
- Know about `shoes` routing rules.
- Spawn tasks internally unless there is a strong reason.

Deliverable:

- A library API suitable for embedding.

## Risk Areas

### Packet Layout And Authentication

The largest risk is assuming Amnezia padding/header changes can be applied after ordinary WireGuard packet creation. `amneziawg-go` sets dynamic message type values inside the handshake message construction, so authentication details may depend on those bytes. The fork must mirror the reference implementation, not just transform bytes at the end.

Mitigation:

- Read `amneziawg-go` send, receive, cookie, MAC, and UAPI code before modifying BoringTun.
- Add interop tests early.
- Use packet captures.

### Randomized Headers And Padding

Random behavior can make tests flaky.

Mitigation:

- Use injectable RNG and clock.
- Keep production randomness behind a small interface.

### BoringTun Upstream Drift

Forking creates maintenance cost.

Mitigation:

- Keep patches isolated.
- Avoid reformatting upstream files.
- Document every modified upstream file.
- Add an `UPSTREAM.md` file in the fork describing base commit and rebase policy.

### Mobile Builds

`shoes` supports Android and iOS FFI. The fork must build for those targets.

Mitigation:

- Avoid platform-specific code in protocol core.
- Use portable crypto/random crates.
- Keep OS socket/TUN work in `shoes`, not the fork.

## Suggested Milestones

Milestone 1: Fork baseline

- BoringTun fork builds and tests pass.
- Public AmneziaWG config types compile.

Milestone 2: Config and CPS

- Header/padding/junk/CPS config validation.
- CPS and junk generation with deterministic tests.

Milestone 3: Dynamic headers

- `H1-H4` send/receive support.
- Standard WireGuard regression tests still pass where applicable.

Milestone 4: Full packet layout

- `S1-S4` support for handshake, cookie, and transport packets.
- Output queue supports multiple datagrams.

Milestone 5: Interop

- Rust client connects to official AmneziaWG 2.0 server.
- TCP and UDP inner traffic work.

Milestone 6: Release candidate for `shoes`

- Stable crate API.
- Minimal docs.
- Version pinned in `shoes`.

## Acceptance Criteria

- Rust client can connect to an official AmneziaWG 2.0 server.
- Full 2.0 obfuscation parameters are supported.
- No server/inbound code is required.
- The crate exposes IP-packet in, UDP-datagram out and UDP-datagram in, IP-packet out.
- The crate has deterministic unit tests and Linux interop tests.
- The crate can be embedded by `shoes` without spawning a subprocess or creating an OS TUN device.
