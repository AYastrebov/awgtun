# CLAUDE.md

## Project Overview

This is a fork of [cloudflare/boringtun](https://github.com/cloudflare/boringtun) with **AmneziaWG 2.0 and 3.0** protocol support. The fork adds packet obfuscation capabilities while preserving full standard WireGuard compatibility when AmneziaWG features are disabled.

## Repository Structure

```
boringtun/              # Main library crate
  src/
    amnezia.rs          # AmneziaWG 2.0/3.0 config, CPS generator, junk generation,
                        # header protection primitive
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

## A real server's parameters are secret

Never commit a live AmneziaWG deployment's `H1`-`H4`, `S1`-`S4`, `Jc`/`Jmin`/`Jmax`
or `I1`-`I5` values — not in tests, docs, commit messages or issues. Those
parameters are what stop the server's traffic from looking like WireGuard, so
publishing them hands a censor an exact signature for that deployment: match the
type field against `H1`-`H4`, then look for a `148 + S1` byte initiation. Treat a
`.conf` the way you would treat its private key.

Regression tests should reproduce the *shape* of a real configuration — every key
populated, `S2` above 64, single-value timing ranges — with synthetic numbers.

## Skills

`.claude/skills/` holds the skills that apply to this codebase. Invoke them by
name with the Skill tool.

| Skill | Use for |
|-------|---------|
| `amnezia-dev` | AmneziaWG protocol work, auditing against amneziawg-go, rebases, wire-format debugging |
| `unsafe-checker` | The C FFI, JNI, TUN and epoll/kqueue syscalls, `MaybeUninit` buffers — 47 soundness rules |
| `m07-concurrency` | The threaded device event loop, `Arc<Mutex<Peer>>`, `dev_lock`, atomics. No async anywhere in this project |
| `m06-error-handling` | `ConfigError`/`WireGuardError` design, panic-vs-Result, failures crossing a foreign boundary |
| `m10-performance` | The per-packet path and the criterion crypto benches |
| `m01-ownership` | Lifetime errors on the borrowed packet buffers (`TunnResult<'a>`, `Packet<'a>`) |
| `m02-resource` | Smart-pointer choice, file descriptors, FFI handle lifetime |

## Branch Strategy

- `master` — tracks upstream cloudflare/boringtun
- `amnezia` — AmneziaWG 2.0/3.0 integration (primary development branch)

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

The device integration tests are `#[ignore]`d and need root and a TUN device:

```bash
cargo test -p boringtun --lib --features device --no-run
sudo -E ./target/debug/deps/boringtun-* --ignored --test-threads 1 awg
```

**Never build them with `--all-features`.** That turns on `mock-instant`, which
freezes the clock, so no timer ever fires, nothing is ever sent, and every
device integration test fails in a way that looks like a protocol bug. CI's
`cargo test -- --ignored` is fine — it picks up `device` through
`boringtun-cli`'s dependency and leaves `mock-instant` off.

## AmneziaWG Integration Points

Files modified from upstream boringtun (keep these in mind during rebases):

| File | Changes |
|------|---------|
| `amnezia.rs` | New file — all AWG config types, CPS generator, junk generation, ChaCha20 header protection |
| `noise/mod.rs` | HeaderConfig, PaddingConfig, padding send/receive, multi-datagram output, header protection, content padding |
| `noise/handshake.rs` | `msg_type` parameter for dynamic headers |
| `noise/session.rs` | `msg_type` and `content_padding` parameters for transport packets |
| `noise/rate_limiter.rs` | HeaderConfig param, dynamic cookie headers |
| `noise/timers.rs` | Clear network_outgoing queue on reset, AWG 3.0 randomized timings |
| `ffi/mod.rs` | `amnezia_config`/`amnezia3_config`, `new_tunnel_amnezia`/`new_tunnel_amnezia3` |
| `wireguard_ffi.h` | AWG 2.0 and 3.0 declarations |
| `device/mod.rs` | Device-scoped AWG config, AWG-aware receive, junk/I-packet drain sites |
| `device/api.rs` | AWG keys over the UAPI socket (`set=1`/`get=1`) |
| `device/peer.rs` | `drain_outgoing`, per-peer keepalive range |

## Key API

```rust
// Standard WireGuard (unchanged)
Tunn::new(private_key, peer_public, psk, keepalive, index, rate_limiter)

// AmneziaWG 2.0
Tunn::new_with_amnezia(private_key, peer_public, psk, keepalive, index, rate_limiter, amnezia_config)

// AmneziaWG 3.0 (header protection, content padding, randomized timings)
Tunn::new_with_amnezia3(private_key, peer_public, psk, keepalive, index, rate_limiter, amnezia3_config)

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
- AWG 3.0 header protection is applied LAST on send, and FIRST on receive; the nonce is the first 12 bytes of the S1-S4 prefix, so those must be >= 12
- AWG 3.0 content padding goes INSIDE the AEAD envelope; the receiver trims it via the IP total-length field
