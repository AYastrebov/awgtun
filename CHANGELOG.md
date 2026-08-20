# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-08-20

The C and JNI bindings move out of the library into a new `awgtun-ffi` crate.
Requested by shoes, whose report is at `git show 9e6e777:INTEGRATION.md`.

### Changed

- **The library is a plain rlib again.** `awgtun` declared `crate-type = ["staticlib", "cdylib", "rlib"]`, and Cargo cannot feature-gate `crate-type`, so every Rust consumer built and linked a staticlib and a cdylib it never used. On Android it was worse than wasteful: `cargo-ndk` copies every cdylib in the graph into the consumer's AAR, and ours arrived under a hashed filename that `System.loadLibrary` cannot load — downstream carried a delete step and a CI guard to undo what this crate produced.
- **Migration.** The `ffi-bindings` and `jni-bindings` features are gone from `awgtun`; build `-p awgtun-ffi` instead, with `--features jni-bindings` for the JNI exports. The C header moves to `awgtun-ffi/wireguard_ffi.h` with its contents unchanged. The Android shared library is now `libawgtun_ffi.so`, so `System.loadLibrary("awgtun")` becomes `System.loadLibrary("awgtun_ffi")`. The JNI class name is unchanged.
- `serialization` is now a public module and `KeyBytes` a public type. The FFI crate parses keys with it from outside the library, and turning a hex or base64 key into 32 bytes is something most consumers need anyway.

## [0.8.0] - 2026-08-20

The project is now **awgtun**, published from
[AYastrebov/awgtun](https://github.com/AYastrebov/awgtun). It was called
boringtun, which is Cloudflare's crate name and was never available to this
fork. See the rename entry under Changed for what that breaks.

### Added
- AmneziaWG 3.1: `random_trailers` and `disable_cookies`, at parity with amneziawg-go `1b86b2a`. Random trailers append a random number of bytes to each initiation, response and cookie reply — outside the MAC, trimmed by the receiver using the message's fixed size — and widen transport content padding inside the AEAD when `content_padding_addition` is unset. Their length is bounded by a per-peer sliding UDP window that tracks the largest datagram the tunnel has carried and resets when the endpoint changes. `disable_cookies` withholds cookie replies without changing the rate limiter's decision. Both default to off, and both peers must agree on `random_trailers`: a receiver only tolerates a trailing byte when it is enabled. Configurable through `Amnezia3Config`, the UAPI socket, and the C FFI (`random_trailers`/`disable_cookies` appended to `amnezia3_config`, so existing field offsets are unchanged).
- AmneziaWG 3.0: ChaCha20 header protection, content padding inside the AEAD envelope, and randomized WireGuard timings, at parity with amneziawg-go `d57d98d`
- `Amnezia3Config` and `Tunn::new_with_amnezia3`; `Tunn::new` and `Tunn::new_with_amnezia` are unchanged and now delegate to it
- C FFI: `amnezia3_config` and `new_tunnel_amnezia3`
- `Amnezia3Config::parse` reads a UAPI-style `key=value` configuration block, covering the AmneziaWG 2.0 and 3.0 keys under their upstream names
- JNI: `new_tunnel_amnezia3` (configured from that block), `wireguard_poll_outgoing_packet` and `tunnel_free`, so Android consumers can run AmneziaWG without binding the C FFI directly
- `wireguard_ffi.h`: declarations for the AmneziaWG 2.0 surface (`amnezia_config`, `new_tunnel_amnezia`, `wireguard_poll_outgoing_packet`), which were missing entirely, alongside the new 3.0 ones
- `device`: AmneziaWG support, making `awgtun-cli` a full AmneziaWG endpoint. Parameters are set with `set=1` and reported by `get=1`, so amneziawg-tools' `awg setconf`/`showconf` drive it directly.
- `Amnezia3Config::to_uapi_block`, the inverse of `parse`, emitting only non-default fields
- `PacketClassifier`, which strips the padding prefix and decrypts the protected header without a `Tunn`. A device has to classify a datagram before it knows which peer it belongs to, as amneziawg-go does on its own `Device`.
- Verified interoperability with the AmneziaWG **kernel module** over a full 3.0 configuration — header protection, content padding and randomized timings — alongside the existing amneziawg-go result. Sessions held open for the better part of an hour completed 30 rekeys inside the configured `RekeyAfterTime` window and carried ~144 MB each way without a stall, so rekeying and sustained load are no longer unverified against a real peer. See `AMNEZIA.md`.

### Removed
- `AWG2_MAX_HANDSHAKE_PADDING`, `AWG2_MAX_TRANSPORT_PADDING`, `AWG2_MAX_JUNK_COUNT`, `AWG2_MIN_JUNK_SIZE`, `AWG2_MAX_JUNK_SIZE`, and the `ConfigError` variants `PaddingOutOfRange`, `JunkCountOutOfRange` and `JunkSizeOutOfRange`. The limits they expressed are not part of the protocol.
- `HeaderConfig::validate_wireguard_compatible` and the `ConfigError` variants `StandardHeaderValue`, `InitPacketRequiresI1` and `InitPacketGap`. The rules they expressed are not part of the protocol either; `HeaderConfig::validate` now checks only for overlap, which is all amneziawg-go checks.

### Changed
- **Renamed from `boringtun` to `awgtun`.** The library crate is `awgtun` and the binary is `awgtun-cli`; `use boringtun::` becomes `use awgtun::`. The JNI class moves to `io.github.ayastrebov.awgtun.AwgTunJNI`, which breaks the ABI for anything already built against the old exports. `repository` and `documentation` pointed at cloudflare/boringtun and docs.rs/boringtun and now point here; `keywords` and `categories` are set so the crate is findable under "amneziawg" despite the name. BSD-3-Clause requires no name to be kept, and `LICENSE.md` retains Cloudflare's copyright notice as clauses 1 and 2 require.
- Version restarts at 0.8.0. The inherited 0.7.1 collided with a real, unrelated crates.io release of the same number.
- Supported platforms table corrected. It advertised `armv7-apple-ios`, a target Rust no longer has, and omitted `aarch64-apple-darwin`, which is every Mac since 2020. It now lists exactly what the release workflow builds.
- Minimum supported Rust version raised from 1.78 to 1.85. 1.78 was never a compatibility promise — it was the floor implied by `Cargo.lock` being format v4 — and holding it meant pinning transitive crates that had already moved past it. `awgtun-cli` has required 1.88 throughout.
- Dependencies refreshed to their latest semver-compatible releases. `chacha20poly1305` and `aead` no longer name pre-release versions (`0.10.0-pre.1`, `0.5.0-pre.2`) in their requirements, which had left `cargo update` free to pull an unreleased AEAD into the packet path.
- Keepalives now carry the S4 padding prefix, matching amneziawg-go. This changes the wire size of keepalives for existing AmneziaWG 2.0 configurations with a non-zero S4.
- Transport payloads that are neither IPv4 nor IPv6 are dropped silently and counted as data received instead of returning `InvalidPacket`

### Fixed
- Keepalives were treated as data whenever `S4` or content padding was configured, so they armed the new-handshake timer instead of keeping the session quiet — the mechanism provoked rekeys rather than preventing them. Outbound, whether a packet is a keepalive is now a property of the call rather than of its wire size; inbound, a payload whose first byte is zero is recognised as one, since a content-padded keepalive decrypts to zeros rather than to nothing. Matches amneziawg-go `08d68cd` and kernel module `ce16310`, which fixed the same bug in both implementations.
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