# CLAUDE.md

## Project Overview

This is a fork of [cloudflare/boringtun](https://github.com/cloudflare/boringtun) with **AmneziaWG 2.0** protocol support. The fork adds packet obfuscation capabilities while preserving full standard WireGuard compatibility when AmneziaWG features are disabled.

## Repository Structure

```
boringtun/              # Main library crate
  src/
    amnezia.rs          # AmneziaWG 2.0 config, CPS generator, junk generation
    noise/
      mod.rs            # Tunn struct, encapsulate/decapsulate, packet parsing
      handshake.rs      # Noise_IK handshake state machine
      session.rs        # ChaCha20-Poly1305 session encryption
      rate_limiter.rs   # MAC verification, cookie replies
      timers.rs         # Rekey, keepalive, handshake retry timers
    device/             # Optional TUN device integration (feature-gated)
    ffi/                # C FFI bindings
    lib.rs
boringtun-cli/          # Optional CLI binary
```

## Branch Strategy

- `master` — tracks upstream cloudflare/boringtun
- `amnezia` — AmneziaWG 2.0 integration (primary development branch)

## Building

```bash
cargo build --lib -p boringtun --release
```

## Testing

The `.cargo/config.toml` sets `runner = 'sudo -E'` for TUN device tests. To run unit tests without sudo, build then run the binary directly:

```bash
cargo test -p boringtun --lib --no-run
./target/debug/deps/boringtun-* --no-capture
```

To run only AmneziaWG tests:
```bash
./target/debug/deps/boringtun-* amnezia --no-capture
```

## AmneziaWG Integration Points

Files modified from upstream boringtun (keep these in mind during rebases):

| File | Changes |
|------|---------|
| `amnezia.rs` | New file — all AWG config types, CPS generator, junk generation |
| `noise/mod.rs` | HeaderConfig, PaddingConfig, padding send/receive, multi-datagram output |
| `noise/handshake.rs` | `msg_type` parameter for dynamic headers |
| `noise/session.rs` | `msg_type` parameter for transport packets |
| `noise/rate_limiter.rs` | HeaderConfig param, dynamic cookie headers |
| `noise/timers.rs` | Clear network_outgoing queue on reset |
| `device/mod.rs` | Pass default HeaderConfig to verify_packet |

## Key API

```rust
// Standard WireGuard (unchanged)
Tunn::new(private_key, peer_public, psk, keepalive, index, rate_limiter)

// AmneziaWG 2.0
Tunn::new_with_amnezia(private_key, peer_public, psk, keepalive, index, rate_limiter, amnezia_config)

// Before sending handshake init, drain pre-handshake packets:
while let Some(packet) = tunn.poll_outgoing_packet() {
    socket.send(&packet);
}
```

## Protocol Reference

- AmneziaWG docs: https://docs.amnezia.org/documentation/amnezia-wg/
- Go reference: https://github.com/amnezia-vpn/amneziawg-go
- Dynamic headers are written BEFORE MAC computation (inside Noise handshake)
- Padding is prepended AFTER MAC computation (transport layer)
- Send order: I-packets -> Junk -> Padded handshake init
