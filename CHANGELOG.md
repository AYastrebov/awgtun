# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- AmneziaWG 3.0: ChaCha20 header protection, content padding inside the AEAD envelope, and randomized WireGuard timings, at parity with amneziawg-go `d57d98d`
- `Amnezia3Config` and `Tunn::new_with_amnezia3`; `Tunn::new` and `Tunn::new_with_amnezia` are unchanged and now delegate to it
- C FFI: `amnezia3_config` and `new_tunnel_amnezia3`
- `Amnezia3Config::parse` reads a UAPI-style `key=value` configuration block, covering the AmneziaWG 2.0 and 3.0 keys under their upstream names
- JNI: `new_tunnel_amnezia3` (configured from that block), `wireguard_poll_outgoing_packet` and `tunnel_free`, so Android consumers can run AmneziaWG without binding the C FFI directly
- `wireguard_ffi.h`: declarations for the AmneziaWG 2.0 surface (`amnezia_config`, `new_tunnel_amnezia`, `wireguard_poll_outgoing_packet`), which were missing entirely, alongside the new 3.0 ones

### Changed
- Keepalives now carry the S4 padding prefix, matching amneziawg-go. This changes the wire size of keepalives for existing AmneziaWG 2.0 configurations with a non-zero S4.
- An outbound packet counts as "data sent" when its wire size differs from the unpadded 32-byte keepalive, rather than when its payload is non-empty — again matching amneziawg-go. A non-zero S4 therefore arms the new-handshake timer on keepalives.
- Transport payloads that are neither IPv4 nor IPv6 are dropped silently and counted as data received instead of returning `InvalidPacket`

### Fixed
- JNI: tunnels created through the bindings could not be released — there was no `tunnel_free` binding, so every tunnel leaked
- C FFI: a zeroed `amnezia_config` was rejected instead of yielding standard WireGuard behavior, because the all-zero H1-H4 fields were read as four overlapping ranges
- Range generation no longer overflows for a range covering the whole `u32` space
- Junk packet sizes are drawn from the half-open range `[Jmin, Jmax)`, matching amneziawg-go's `min + fastrandn(max - min)`. Previously `Jmax` itself could be produced.
- `Amnezia3Config::validate` now rejects inverted content-padding and timing ranges, which a public struct literal could construct while bypassing `U32Range::new`
- `Tunn::persistent_keepalive` reports the interval armed from an AWG 3.0 `persistent_keepalive` range instead of returning `None` while keepalives were being sent
- Content padding is clamped to the space left in the caller's `dst` buffer, so enabling it no longer raises the buffer requirement of `encapsulate`/`update_timers` and cannot panic an existing caller. amneziawg-go gets this for free from its pooled 64 KiB buffers; a tight `dst` now yields less padding instead.

## [0.7.1] - 2026-05-01

### Security
- use a 64-bit nonce counter on 32-bit platforms to avoid the possibility of nonce re-use with large REKEY_AFTER_TIME
- CLI only: remove vulnerable dependency: `atty`

### Fixed
- use portable-atomic to support targets without native 64-bit atomics

## [0.7.0] - 2026-01-09

### Changes

- Breaking: make `noise::Tunn::new` infallible
- Upgrade vulnerable dependencies: ring, x25519-dalek
- Fix a compilation error on freebsd
- Fix incorrect socket type in `device::Peer::connect_endpoint`