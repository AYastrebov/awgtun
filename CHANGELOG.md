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
- `device`: AmneziaWG support, making `boringtun-cli` a full AmneziaWG endpoint. Parameters are set with `set=1` and reported by `get=1`, so amneziawg-tools' `awg setconf`/`showconf` drive it directly.
- `Amnezia3Config::to_uapi_block`, the inverse of `parse`, emitting only non-default fields
- `PacketClassifier`, which strips the padding prefix and decrypts the protected header without a `Tunn`. A device has to classify a datagram before it knows which peer it belongs to, as amneziawg-go does on its own `Device`.
- Verified interoperability with the AmneziaWG **kernel module** over a full 3.0 configuration — header protection, content padding and randomized timings — alongside the existing amneziawg-go result. Sessions held open for the better part of an hour completed 30 rekeys inside the configured `RekeyAfterTime` window and carried ~144 MB each way without a stall, so rekeying and sustained load are no longer unverified against a real peer. See `AMNEZIA.md`.

### Removed
- `AWG2_MAX_HANDSHAKE_PADDING`, `AWG2_MAX_TRANSPORT_PADDING`, `AWG2_MAX_JUNK_COUNT`, `AWG2_MIN_JUNK_SIZE`, `AWG2_MAX_JUNK_SIZE`, and the `ConfigError` variants `PaddingOutOfRange`, `JunkCountOutOfRange` and `JunkSizeOutOfRange`. The limits they expressed are not part of the protocol.
- `HeaderConfig::validate_wireguard_compatible` and the `ConfigError` variants `StandardHeaderValue`, `InitPacketRequiresI1` and `InitPacketGap`. The rules they expressed are not part of the protocol either; `HeaderConfig::validate` now checks only for overlap, which is all amneziawg-go checks.

### Changed
- Keepalives now carry the S4 padding prefix, matching amneziawg-go. This changes the wire size of keepalives for existing AmneziaWG 2.0 configurations with a non-zero S4.
- An outbound packet counts as "data sent" when its wire size differs from the unpadded 32-byte keepalive, rather than when its payload is non-empty — again matching amneziawg-go. A non-zero S4 therefore arms the new-handshake timer on keepalives.
- Transport payloads that are neither IPv4 nor IPv6 are dropped silently and counted as data received instead of returning `InvalidPacket`

### Fixed
- Configurations from real AmneziaWG servers were rejected. S1-S4 were capped at 64 (32 for S4), `Jc` at 10 and junk sizes to 64-1024 — ranges taken from Amnezia's documentation rather than the protocol. amneziawg-go enforces no maximum on any of them, and a live server whose `S2` exceeded 64 was unreachable as a result. Only the checks upstream also makes are kept, plus `Jmin <= Jmax`, which upstream omits and would underflow on.
- JNI: tunnels created through the bindings could not be released — there was no `tunnel_free` binding, so every tunnel leaked
- `device`: `set=1` split each line on every `=` rather than the first, rejecting any value containing one
- C FFI: a zeroed `amnezia_config` was rejected instead of yielding standard WireGuard behavior, because the all-zero H1-H4 fields were read as four overlapping ranges
- Range generation no longer overflows for a range covering the whole `u32` space
- Junk packet sizes are drawn from the half-open range `[Jmin, Jmax)`, matching amneziawg-go's `min + fastrandn(max - min)`. Previously `Jmax` itself could be produced.
- `Amnezia3Config::validate` now rejects inverted content-padding and timing ranges, which a public struct literal could construct while bypassing `U32Range::new`
- `Tunn::persistent_keepalive` reports the interval armed from an AWG 3.0 `persistent_keepalive` range instead of returning `None` while keepalives were being sent
- Content padding is clamped to the space left in the caller's `dst` buffer, so enabling it no longer raises the buffer requirement of `encapsulate`/`update_timers` and cannot panic an existing caller. amneziawg-go gets this for free from its pooled 64 KiB buffers; a tight `dst` now yields less padding instead.
- Configurations that enable junk, padding or I-packets while leaving H1-H4 at the WireGuard defaults were rejected. amneziawg-go defaults H1-H4 to the standard types 1-4 and never refuses them, so `s1=16 s2=16 s3=16 s4=16` — a valid obfuscation profile — was unconfigurable.
- I1-I5 no longer have to be contiguous. amneziawg-go stores each chain independently and sends every configured one, so `i1` plus `i3` is valid there; requiring I1 and refusing gaps rejected it. `InitPacketConfig::active_chains` now yields every configured chain rather than stopping at the first gap, which would otherwise have dropped I-packets a peer expects.
- `device`: AmneziaWG keys in `set=1` are now incremental, as they are in amneziawg-go and as the rest of the UAPI is. Setting one key replaced the whole AmneziaWG configuration, so `awg set <if> jc 5` wiped S1-S4, H1-H4 and the header protection key.
- `device`: changing the AmneziaWG configuration rebuilds the peers' tunnels. A `Tunn` captures its parameters at construction, so inbound datagrams were classified with the new configuration while peers still sent with the old one.
- `device`: `mtu` is no longer accepted over the UAPI socket. A device knows its interface MTU and uses it, so the key was reported by `get=1` without being honored.

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