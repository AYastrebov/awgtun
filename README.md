![boringtun logo banner](./banner.png)

# BoringTun + AmneziaWG 2.0 / 3.0

A fork of [cloudflare/boringtun](https://github.com/cloudflare/boringtun) that speaks [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) 2.0 and 3.0. WireGuard itself is untouched: leave the AmneziaWG parameters at their defaults and the tunnel is byte-for-byte standard WireGuard.

Both directions work. A tunnel here can initiate a handshake or answer one, so it runs as a client against an AmneziaWG server or as an endpoint two peers connect through.

Two crates:

* **`boringtun`** — the library. WireGuard and AmneziaWG with no network or tunnel stack; you supply the I/O. This is what the FFI and JNI bindings wrap.
* **`boringtun-cli`** — a [userspace tunnel](https://www.wireguard.com/xplatform/) for Linux and macOS, with AmneziaWG support built in. It listens on the usual WireGuard UAPI socket, so amneziawg-tools' `awg` drives it directly.

Validated against [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go), amneziawg-tools and the AmneziaWG kernel module (see [the release of record](AMNEZIA.md#upstream-release-of-record)), and against a live AmneziaWG server.

## Quick start

```bash
# Build the CLI
cargo build --bin boringtun-cli --release

# Bring up an interface and hand it an AmneziaWG config
sudo ./target/release/boringtun-cli awg0
sudo awg setconf awg0 /etc/amnezia/awg0.conf
sudo ip addr add 10.0.0.2/32 dev awg0
sudo ip link set up dev awg0
sudo awg show awg0
```

Building the library instead: `cargo build --lib -p boringtun --release`, adding `--features ffi-bindings` or `--features jni-bindings` for the C and Android surfaces.

Tests: the runner uses `sudo` for TUN device tests, so build first and run the binary directly to skip the prompt.

```bash
cargo test -p boringtun --lib --no-run
./target/debug/deps/boringtun-* --no-capture
```

## What AmneziaWG does

WireGuard is easy to fingerprint. Every packet opens with a fixed 4-byte message type of 1, 2, 3 or 4; handshake messages are always exactly 148 and 92 bytes; and a new session announces itself with a recognisable burst. None of that is a cryptographic weakness, but it makes the protocol trivial to classify and block.

AmneziaWG reshapes what a censor sees while leaving the cryptography alone. The Noise handshake, the ChaCha20-Poly1305 session, and the key schedule are all stock WireGuard. What changes is the framing around them:

```
standard WireGuard                AmneziaWG
┌──────────────────┐              ┌───────────┬──────────────────┐
│ type │ body      │              │ S-padding │ type │ body      │
│ 1..4 │           │              │  random   │ H1..4│           │
└──────────────────┘              └───────────┴──────────────────┘
                                   └─ 3.0: type field encrypted ─┘
```

and, before a handshake even starts, the initiator emits decoy traffic:

```
I1..I5 signature packets  →  Jc junk packets  →  the real handshake
  separate datagrams          separate datagrams    one datagram
```

Both ends must agree on the parameters that define the framing. Get one wrong and nothing announces the problem. The peer just never answers, because it cannot recognise the packets as WireGuard at all.

## Parameters

### Conventions

**Must match** means both peers need the identical value, because it defines how a packet is parsed. **Local** means the parameter only shapes what this peer sends, so the two ends may differ or one may omit it entirely.

A **range** is written `lo-hi` (inclusive) or as a single number, which is the same as `lo-hi` with both equal. A value drawn from a range is re-drawn each time it is used. Unset, or all-zero, means the feature is off and the standard WireGuard behaviour applies.

Parameters live in the `[Interface]` section of a `.conf`, except `PersistentKeepalive`, which stays per-peer as it is in WireGuard.

### Message headers — H1-H4

The `uint32` message type that opens every WireGuard packet, replaced by a value drawn from a range you choose. The value is written before the MAC is computed, so it is authenticated rather than merely cosmetic.

| Parameter | Type | Match | Replaces |
|---|---|---|---|
| `H1` | u32 range | both ends | handshake initiation (WireGuard's `1`) |
| `H2` | u32 range | both ends | handshake response (`2`) |
| `H3` | u32 range | both ends | cookie reply (`3`) |
| `H4` | u32 range | both ends | transport data (`4`) |

The four ranges must not overlap, or a receiver could not tell which message type it has. They may legitimately include 1-4, which is what upstream defaults to, so leaving the headers alone while using the other layers is a valid configuration.

### Message padding — S1-S4

Random bytes prepended to each message type, changing packet sizes on the wire. Added after the MAC, so they are outside the authenticated span; the receiver strips exactly `Sn` bytes based on which message type it is looking for.

| Parameter | Type | Match | Applies to |
|---|---|---|---|
| `S1` | u8 | both ends | handshake initiation → `148 + S1` bytes |
| `S2` | u8 | both ends | handshake response → `92 + S2` bytes |
| `S3` | u8 | both ends | cookie reply → `64 + S3` bytes |
| `S4` | u8 | both ends | transport data, keepalives included |

Under AmneziaWG 3.0 the first 12 bytes of this prefix double as the header protection nonce, which is why enabling that feature requires every one of S1-S4 to be at least 12.

> This implementation stores S1-S4 as `u8`, so 255 is the ceiling; upstream parses them as `uint16`. Amnezia's own tooling stays far below either limit.

### Junk packets — Jc, Jmin, Jmax

`Jc` datagrams of random content, each sized from the half-open range `[Jmin, Jmax)`, sent immediately before every handshake initiation, retries included. They carry nothing; the peer fails to classify them and drops them.

| Parameter | Type | Match | Description |
|---|---|---|---|
| `Jc` | u8 | sender only | how many junk datagrams; `0` disables |
| `Jmin` | u16 | sender only | minimum size, inclusive |
| `Jmax` | u16 | sender only | maximum size, exclusive |

Because the receiver discards them either way, junk is worth configuring on the client alone. Four to twelve is the usual range.

> Keep `Jmax` below the system MTU. A junk packet large enough to fragment produces an IP fragment pair, which is itself a distinctive signature, the opposite of what you wanted.

### Signature packets — I1-I5

Datagrams built from a tag language, sent ahead of the junk, in order, skipping any that are unset. They exist to make the opening of a connection resemble some other protocol; a common use is an I1 that looks like a TLS ClientHello.

`I1` through `I5` each hold a tag string and produce one datagram, sent in numerical order. All five are sender-only, and any subset works, gaps included: `I1` and `I3` without `I2` is valid.

| Tag | Emits |
|---|---|
| `<b 0xHEX>` | the hex bytes verbatim, two hex digits per byte |
| `<r N>` | `N` random bytes |
| `<rc N>` | `N` random ASCII letters, `a-zA-Z` |
| `<rd N>` | `N` random ASCII digits, `0-9` |
| `<t>` | the current Unix time, 4 bytes big-endian |

So `I1 = <b 0x160301><r 32><t>` sends a three-byte TLS record header, 32 random bytes and a timestamp. As with junk, the client side alone is enough, and the same MTU warning applies.

### Header protection — AmneziaWG 3.0

Raw ChaCha20 over the low-entropy header fields, so the message type does not appear in the clear even as a random-looking constant. The nonce is the first 12 bytes of the S-padding prefix, which differs per packet.

`HeaderProtectionKey` is a 32-byte key, written base64 in a `.conf` and hex over the UAPI socket. Both ends need the same one.

Handshake, response and cookie messages are encrypted in full, MACs included. Transport packets have only their 16-byte header encrypted, since the AEAD ciphertext already looks like random noise and needs no help. Junk and signature packets are never protected.

Generate a key with `awg genkey`. An all-zero key means disabled. Every one of S1-S4 must be at least 12, since they supply the nonce.

### Content padding — AmneziaWG 3.0

Zero bytes appended to transport content *inside* the AEAD envelope, so the padding is authenticated. No length field is needed: the receiver recovers the real length from the IP total-length field.

`ContentPaddingAddition` is a u32 range of bytes added to each transport packet. Because the receiver needs no configuration to undo it, this one really is sender-only, though setting it at both ends obscures both directions.

The addition is clamped to what remains in the MTU segment, so it never causes fragmentation.

### Timings — AmneziaWG 3.0

WireGuard's fixed timing constants become ranges, re-drawn at each use, so a session's rhythm stops being a fingerprint. Any range left unset keeps the standard constant exactly.

All of these are sender-only; they govern this peer's own clock.

| Parameter | Default | Meaning |
|---|---|---|
| `RekeyAfterTime` | 120 s | session age at which the initiator rekeys |
| `RekeyTimeout` | 5 s | wait before retrying an unanswered handshake |
| `RejectAfterTime` | 180 s | session age after which traffic is refused |
| `KeepaliveTimeout` | 10 s | idle time before an empty keepalive |
| `MaxHandshakeAttempts` | 18 | retries before giving up |
| `PersistentKeepalive` | off | per-peer; keepalive interval, re-drawn each time |

### Random trailers and cookie suppression — AmneziaWG 3.1

`RandomTrailers = on` puts a random number of bytes on the end of each datagram, so a message with a fixed size stops having one. Initiations, responses and cookie replies carry them outside the MAC, and the receiver trims them by the message's known size. Transport packets instead widen their content padding inside the AEAD, and only when `ContentPaddingAddition` is unset — that one wins if both are set.

**Both ends must set it.** Unlike content padding, a receiver only tolerates a trailing byte when trailers are enabled; otherwise the exact-size test that recognises a handshake message rejects the datagram.

Trailer length is bounded by a sliding window that tracks the largest datagram the tunnel has carried, so packets grow to resemble traffic the peer already sends rather than to a fixed size. The window resets when a peer's endpoint changes.

`DisableCookies = on` stops this end from answering with cookie replies when it is under load. It does not change when a cookie is deemed necessary, only whether one is sent, so a flooding peer gets silence rather than a retry hint. Sender-only.

| Parameter | Default | Both ends? |
|---|---|---|
| `RandomTrailers` | off | **yes** |
| `DisableCookies` | off | no |

### A complete configuration

```ini
[Interface]
PrivateKey = <base64>
Address = 10.0.0.2/32
MTU = 1420

# 2.0 framing. H and S must match the server.
Jc = 8
Jmin = 75
Jmax = 123
S1 = 40
S2 = 97
S3 = 20
S4 = 16
H1 = 1000000-1000999
H2 = 2000000-2000999
H3 = 3000000-3000999
H4 = 4000000-4000999
I1 = <b 0x160301><r 32>
I2 = <r 28>

# 3.0. The key must match; the rest are local.
HeaderProtectionKey = <base64>
ContentPaddingAddition = 0-64
RekeyAfterTime = 121-155
RekeyTimeout = 5
RejectAfterTime = 185-201
KeepaliveTimeout = 12-26
MaxHandshakeAttempts = 18

# 3.1. RandomTrailers must match; DisableCookies is local.
RandomTrailers = on
DisableCookies = off

[Peer]
PublicKey = <base64>
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
```

> A deployment's parameters are as sensitive as its keys. `H1`-`H4` and `S1`-`S4` are precisely what stop its traffic from resembling WireGuard, so publishing them hands a censor a signature for that server: match the type field, then look for a `148 + S1` byte initiation. Treat a `.conf` accordingly.

Only three rules are enforced, matching upstream: the header ranges must not overlap, S1-S4 must reach 12 when header protection is on, and `Jmin` must not exceed `Jmax`. Everything else Amnezia documents is a recommendation, not a limit.

## Using the library

### Rust

```rust
use boringtun::amnezia::*;
use boringtun::noise::Tunn;

let config = Amnezia2Config {
    headers: HeaderConfig::new(
        HeaderRange::new(100, 200)?,  // H1: handshake init
        HeaderRange::new(201, 300)?,  // H2: handshake response
        HeaderRange::new(301, 400)?,  // H3: cookie reply
        HeaderRange::new(401, 500)?,  // H4: transport data
    )?,
    paddings: PaddingConfig::new(16, 16, 16, 8)?,
    junk: JunkConfig::new(3, 64, 256)?,
    init_packets: InitPacketConfig::default(),
};

let mut tunnel = Tunn::new_with_amnezia(
    private_key, peer_public_key, None, Some(25), index, None, config,
)?;
```

For 3.0, lift the config and add the newer parameters:

```rust
let mut config = Amnezia3Config::from_amnezia2(config);
config.header_protection_key = Some(header_key);
config.content_padding_addition = Some(U32Range::new(1, 64)?);
config.timing_ranges = TimingRanges {
    rekey_timeout: U32Range::new(3, 9)?,
    ..TimingRanges::default()   // unset ranges keep the WireGuard constants
};

let mut tunnel = Tunn::new_with_amnezia3(
    private_key, peer_public_key, None, Some(25), index, None, config,
)?;
```

One thing to get right: junk and signature packets are queued rather than returned inline. After creating a tunnel, and after every call that can start a handshake, drain the queue and send what it gives you *before* the handshake packet.

```rust
while let Some(packet) = tunnel.poll_outgoing_packet() {
    udp_socket.send_to(&packet, peer_addr)?;
}
```

Skip it and the tunnel still comes up, which is what makes this so easy to get wrong: `Jc` and `I1`-`I5` just quietly never reach the wire.

### C FFI

`amnezia_config` and `amnezia3_config` structs with `new_tunnel_amnezia`, `new_tunnel_amnezia3` and `wireguard_poll_outgoing_packet`, declared in `boringtun/src/wireguard_ffi.h`. Full reference in [`AMNEZIA.md`](AMNEZIA.md#c-ffi-api).

### JNI (Android)

The `jni-bindings` feature exposes the same surface to `VpnService`, through the class `io.github.ayastrebov.boringtun.BoringTunJNI` — the exports are bound to that literal name, so the Kotlin declaration has to match it. Parameters arrive as one UAPI-style block rather than a long argument list:

```kotlin
val handle = BoringTunJNI.new_tunnel_amnezia3(
    secretKey, publicKey, presharedKey, keepAlive, index,
    "s1=16\ns2=16\ns3=16\ns4=16\nh1=100-199\nh2=200-299\nh3=300-399\nh4=400-499\n",
)
```

That block uses the UAPI spelling (snake_case names, hex keys), not the CamelCase and base64 a `.conf` carries. Drain `wireguard_poll_outgoing_packet` after every write and tick, and release with `tunnel_free`. See [`AMNEZIA.md`](AMNEZIA.md#jni-api-android).

### Further reading

- [`AMNEZIA.md`](AMNEZIA.md) — wire format, packet layouts, the UAPI surface, and where this fork differs from the three upstream implementations
- [AmneziaWG protocol documentation](https://docs.amnezia.org/documentation/amnezia-wg/)

The AmneziaWG behaviour here was written against Amnezia's own implementations,
which are the authority whenever this fork and they disagree:

- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) — the reference
  implementation, and the one this fork follows most closely
- [amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) — `awg` and
  `awg-quick`, which define the `.conf` and UAPI spellings
- [amneziawg-linux-kernel-module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module)
  — the in-kernel implementation

[`AMNEZIA.md`](AMNEZIA.md#upstream-release-of-record) records the exact release
of each that this was last audited against.

## Supported platforms

Target triple                 |Binary|Library|
------------------------------|:----:|------|
x86_64-unknown-linux-gnu      |  ✓   | ✓    |
aarch64-unknown-linux-gnu     |  ✓   | ✓    |
armv7-unknown-linux-gnueabihf |  ✓   | ✓    |
x86_64-apple-darwin           |  ✓   | ✓    |
x86_64-pc-windows-msvc        |      | ✓    |
aarch64-apple-ios             |      | ✓    |
armv7-apple-ios               |      | ✓    |
armv7s-apple-ios              |      | ✓    |
aarch64-linux-android         |      | ✓    |
arm-linux-androideabi         |      | ✓    |

#### Linux

`x86-64`, `aarch64` and `armv7` architectures are supported. The behaviour should be identical to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/), with the following difference:

`boringtun` will drop privileges when started. When privileges are dropped it is not possible to set `fwmark`. If `fwmark` is required, such as when using `wg-quick`, run with `--disable-drop-privileges` or set the environment variable `WG_SUDO=1`.

You will need to give the executable the `CAP_NET_ADMIN` capability using: `sudo setcap cap_net_admin+epi boringtun`. sudo is not needed.

#### macOS

The behaviour is similar to that of [wireguard-go](https://git.zx2c4.com/wireguard-go/about/). Specifically the interface name must be `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select the lowest available. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

---

#### FFI bindings

The library exposes C ABI bindings defined in the `wireguard_ffi.h` header file. These work with C/C++, Swift (bridging header), or C# ([DLLImport](https://docs.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.dllimportattribute?view=netcore-2.2) with `CallingConvention.Cdecl`).

#### JNI bindings

Java Native Interface bindings are defined in `src/jni.rs`.

## License

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause), inherited from boringtun, whose copyright notice is retained in [`LICENSE`](LICENSE).

The AmneziaWG support is an independent reimplementation in Rust, written by
reading [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) (MIT) and
comparing behaviour against it. No code was taken from
[amneziawg-tools](https://github.com/amnezia-vpn/amneziawg-tools) or the
[kernel module](https://github.com/amnezia-vpn/amneziawg-linux-kernel-module),
both of which are GPL-2.0 and were consulted only to check what this
implementation should do on the wire.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the 3-Clause BSD License, shall be licensed as above, without any additional terms or conditions.

If you want to contribute to this project, please read our [`CONTRIBUTING.md`].

[`CONTRIBUTING.md`]: https://github.com/cloudflare/.github/blob/master/CONTRIBUTING.md

---

**This project is not affiliated with, endorsed by, or supported by Amnezia.**
It is an independent implementation of the AmneziaWG protocol. Please do not
report problems with it to the Amnezia projects; open an issue here instead.

<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. BoringTun is not sponsored or endorsed by Jason A. Donenfeld. AmneziaWG and Amnezia are projects of the Amnezia team; this fork is not affiliated with them.</sub></sub></sub></sub>
