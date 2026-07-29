![boringtun logo banner](./banner.png)

# BoringTun + AmneziaWG 2.0 / 3.0

This is a fork of [cloudflare/boringtun](https://github.com/cloudflare/boringtun) that adds [AmneziaWG](https://docs.amnezia.org/documentation/amnezia-wg/) 2.0 and 3.0 protocol support. The upstream WireGuard implementation is preserved — when AmneziaWG parameters are left at their defaults, the tunnel behaves exactly like standard WireGuard.

The fork is client-focused. It can initiate tunnels, maintain handshakes, encrypt and decrypt IP packets, and keep sessions alive against AmneziaWG 2.0 and 3.0 servers. It does not implement server/inbound mode.

The project consists of two parts:

* The library `boringtun` — a portable WireGuard + AmneziaWG implementation without network or tunnel stacks. Callers provide their own I/O.
* The executable `boringtun-cli` — a [userspace WireGuard](https://www.wireguard.com/xplatform/) tunnel for Linux and macOS (does not include AWG support).

### Building

- Library only: `cargo build --lib -p boringtun --release`
- With FFI bindings: `cargo build --lib -p boringtun --features ffi-bindings --release`
- CLI executable: `cargo build --bin boringtun-cli --release`

### Testing

The test runner is configured to use `sudo` for TUN device tests. To run unit tests without sudo, build first, then run the binary directly:

```bash
cargo test -p boringtun --lib --no-run
./target/debug/deps/boringtun-* --no-capture
```

## AmneziaWG support

AmneziaWG makes WireGuard traffic harder to identify through deep packet inspection. It does this by randomizing packet headers, sizes, and timing patterns while keeping WireGuard's cryptography untouched.

### 2.0

Four obfuscation mechanisms, each independently configurable:

- **Dynamic headers (H1-H4)** — WireGuard normally uses fixed message type values (1, 2, 3, 4) in the first four bytes of every packet. AmneziaWG replaces these with random values drawn from configurable ranges. The randomized header is written into the packet before MAC computation, so it's covered by authentication.
- **Packet padding (S1-S4)** — random bytes prepended to each packet type after MAC computation. This changes packet sizes without breaking authentication. S4 (transport padding) applies to keepalives too, matching the Go reference.
- **Junk packets (Jc/Jmin/Jmax)** — random-sized decoy datagrams sent before handshake initiation. The server silently discards them.
- **Init packets (I1-I5)** — structured camouflage datagrams (CPS chains) sent before junk. These use a tag-based format (`<b 0xFF><r 16><t>`) to generate protocol-mimicking byte sequences.

### 3.0

Three further mechanisms, layered on the 2.0 parameters:

- **Header protection** — raw ChaCha20 over the low-entropy header fields, keyed by a shared 32-byte key and nonced from the random padding prefix. Handshake messages are encrypted in full, including their MACs; transport packets have their 16-byte header encrypted. Requires S1-S4 to all be at least 12.
- **Content padding** — a random number of zero bytes appended to transport content inside the AEAD envelope, so the padding is authenticated and the receiver needs no configuration.
- **Randomized timings** — the WireGuard timing constants (rekey, keepalive, reject-after, handshake attempts, persistent keepalive) become configurable ranges, picked afresh at each use.

### Rust API

```rust
use boringtun::noise::Tunn;
use boringtun::amnezia::*;

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

// Before sending the handshake init, drain pre-handshake datagrams
while let Some(packet) = tunnel.poll_outgoing_packet() {
    udp_socket.send_to(&packet, peer_addr)?;
}
```

For AmneziaWG 3.0, lift the config and set the 3.0 parameters:

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

### C FFI

The library also exposes AmneziaWG through C bindings (`amnezia_config` and `amnezia3_config` structs, `new_tunnel_amnezia`, `new_tunnel_amnezia3`, `wireguard_poll_outgoing_packet`), declared in `boringtun/src/wireguard_ffi.h`. See [`AMNEZIA.md`](AMNEZIA.md) for the full C API reference.

### Further reading

- [`AMNEZIA.md`](AMNEZIA.md) — wire format, implementation details, and comparison with amneziawg-go
- [AmneziaWG protocol docs](https://docs.amnezia.org/documentation/amnezia-wg/)
- [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go) — the Go reference implementation this fork was validated against

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

The project is licensed under the [3-Clause BSD License](https://opensource.org/licenses/BSD-3-Clause).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the 3-Clause BSD License, shall be licensed as above, without any additional terms or conditions.

If you want to contribute to this project, please read our [`CONTRIBUTING.md`].

[`CONTRIBUTING.md`]: https://github.com/cloudflare/.github/blob/master/CONTRIBUTING.md

---
<sub><sub><sub><sub>WireGuard is a registered trademark of Jason A. Donenfeld. BoringTun is not sponsored or endorsed by Jason A. Donenfeld.</sub></sub></sub></sub>
