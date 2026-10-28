# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Match kernel WireGuard and wireguard-go's handshake timestamp epoch (+10,
  not +37). Switching the same peer identity from awgtun to a kernel client
  no longer introduces a 27-second anti-replay window. A server which has
  already accepted a timestamp from an older +37 build may still require that
  window to expire once on upgrade. Add stamper regression tests and an opt-in
  same-key switch test against actual kernel WireGuard; see
  [the test instructions](docs/kernel-timestamp-test.md).
- JNI: `wireguard_write`, `wireguard_read`, `wireguard_tick` and
  `wireguard_poll_outgoing_packet` trusted their size arguments. A `dst_size`
  larger than the direct buffer let native code write past it, and a `src_size`
  larger than the `byte[]` read past the copy. Sizes are now checked against
  the buffer's capacity and the array's length, a negative size or
  overlapping `dst` and `op` buffers are refused before the tunnel runs, and a
  refused call writes nothing. See
  [Buffers and errors](AMNEZIA.md#buffers-and-errors).
- JNI: `wireguard_write` and `wireguard_read` called `unwrap()` on the array
  copy, so a JNI failure panicked across the FFI boundary.
- JNI: `x25519_key_to_hex` and `x25519_key_to_base64` leaked the native string
  on every call, and `new_tunnel` and `new_tunnel_amnezia3` never released the
  UTF chars of their key arguments.

### Changed

- Minimum supported Rust version raised from 1.85 to 1.97 for `awgtun` and
  `awgtun-ffi`, and from 1.88 to 1.97 for `awgtun-cli`, so all three crates
  declare the same version. CI's MSRV job now checks the FFI crate and the CLI
  as well as the library.
- RustCrypto stack moved up a generation: `blake2` 0.11, `hmac` 0.13,
  `chacha20poly1305` 0.11, `aead` 0.6 and `chacha20` 0.10, which replace
  `generic-array` with `hybrid-array`. `x25519-dalek` 3.0 moves to
  `curve25519-dalek` 5 and `rand_core` 0.10, which no longer has `OsRng`. Keys
  now come from `StaticSecret::random()`, and other OS randomness comes from
  `getrandom`, the crate x25519-dalek uses for its own key generation. No
  change on the wire.
- `parking_lot` 0.13, `base64` 0.23, `socket2` 0.6, and for tests
  `mock_instant` 0.6 (its per-thread clock, as 0.3 had without `sync`) and
  `etherparse` 0.21.
- `jni` 0.22. Every Android export now runs inside `EnvUnowned::with_env`, so a
  Rust panic is caught and logged instead of crashing the app, and failures
  still return 0 or `null`. Two things made that possible: the JNI
  constructors no longer install the C API's SIGSEGV panic hook, and the JNI
  exports drive the tunnel directly rather than through the `extern "C"`
  `wireguard_*` functions, where a panic aborts. The exports are
  `extern "system"`, the JNI calling convention, which matches `extern "C"` on
  every Android ABI.

## [0.11.0] - 2026-10-20

Configurations that real AmneziaWG servers issue but this fork refused. S1-S4
and `Jc` were 8-bit here and 16-bit in all three reference implementations, so
a server with `S2` above 255 could not be configured at all. Handshake retries
also gain the jitter the reference applies.

Minor rather than patch because the `amnezia_config` C struct changed layout and
several public Rust types widened. Under 0.x that is where a breaking change goes.

### Fixed

- **Handshake retransmits had no jitter.** wireguard-go and amneziawg-go arm the retransmit and new-handshake timers for their timeout plus a random 0-334 ms (`RekeyTimeoutJitterMaxMs`); this fork only said so in a comment, so every retry fired on a whole second. Both timers now carry the jitter, drawn per initiation as the reference does.
- **S1-S4 and `Jc` above 255 were rejected.** They were stored as `u8`, while amneziawg-go, the kernel module and amneziawg-tools all parse them as 16-bit. A real server issuing `S2` above 255 could not be configured at all: `InvalidFieldValue { field: "s2" }`, or `errno=22` over the UAPI. They are now `u16` (#1, reported by @szonov). Nothing on the wire changes; every packet path already took them as `usize`. A prefix too large for the output buffer, which the wider type now allows, gets `DestinationBufferTooSmall` at each padded write site instead of a panic, and the device drops such a cookie reply.

### Changed

- **Breaking: `amnezia_config` C layout.** `s1`-`s4` and `jc` are `uint16_t` rather than `uint8_t`, so a C caller must rebuild against the new `wireguard_ffi.h`; one compiled against the old header passes a mismatched struct. JNI is unaffected, since it takes the UAPI text form.
- **Breaking (Rust):** `PaddingConfig`'s fields and `new`, `JunkConfig::count` and `new`, `HEADER_PROTECTION_MIN_PADDING`, and `ConfigError::HeaderProtectionPaddingTooSmall`'s `value`/`min` are `u16`.

## [0.10.0] - 2026-09-07

AmneziaWG 3.1 interoperability. Everything here came out of running against a
live 3.1 server and against the three upstream implementations; several of these
bugs made a 3.1 link either impossible or quietly lossy, and none of them
produced a log line at either end.

### Fixed

- **Transport packets were classified after handshakes, losing ~3.5% of them.** AWG 3.1 relaxes the three handshake size tests from `==` to `>=`, so a full-size data packet passes all three on size alone and only the type-range test stands between it and a misparse. That field is read over ciphertext, so it is uniformly random: with the 50-million-wide ranges Amnezia's own generator emits, each range steals ~1.16% of data packets and all three were tried first. Measured against a live server, throughput went from ~4.2 MB/s to ~14.5 MB/s once transport is classified first, and the loss was unstable across runs rather than a flat slowdown.
- **The same collision on the send side.** Fixing our own classifier only protects what we receive; a peer running an unpatched classifier still drops what we send. Outbound loss measured 5.0-5.2% against a live server while inbound was 0.0%, with uploads at 0.17 MB/s against downloads at 14.5 MB/s. Transport packets that would collide with a handshake range are no longer emitted. This has no removal criterion: there is no version negotiation, so a sender cannot tell which classifier a peer runs.
- **The device never trimmed the 3.1 random trailer.** `Tunn::decapsulate` did; the device's UDP receive path passed message-plus-trailer to the rate limiter, where the `==` size tests rejected it and `Err(_) => continue` dropped it silently. A device could not complete a handshake with a trailered peer in either role.
- **CPS random lengths were capped at an invented 1000 bytes.** `newRandObf` in amneziawg-go applies no range check, and production `I1` chains pad an initiation to the size of a TLS record with a random-bytes tag well past that. A live 3.1 server's configuration was rejected outright with `errno=22`. The only real bound is the datagram.
- **`DisableCookies` suppressed the reply instead of the whole under-load path.** The rate limiter still demanded a valid MAC2 while the peer never received the cookie needed to build one, so every handshake against a busy device died in silence — worse than not having the switch. Matches amneziawg-go `b5928ef` and kernel module `3c38e16`.
- **The device read the interface MTU once and kept it.** `wg-quick` sets the MTU after handing over the interface, so the value was routinely wrong — 1500 on a macOS utun whose tunnel is really 1420 — and content padding sized against it would fragment. The MTU is now polled and pushed into each peer through the new `Tunn::set_mtu`.
- `conf_to_uapi.py` dropped `RandomTrailers` and `DisableCookies` silently, and forwarded `I2 =` as an empty `i2=`, which the device rejects.

### Changed

- **`RateLimiter::verify_packet` takes a `disable_cookies` argument.** This is the breaking change in this release. It gates entry to the under-load path, which is what `DisableCookies` has to do.
- **AWG 3.0 content padding is bounded by the sliding UDP window, not the MTU**, following amneziawg-go `da11c9f` and kernel module `7fc0145`. A packet now grows towards the sizes the tunnel has actually carried rather than towards the link size, and the size compared against is the whole datagram rather than the payload. The MTU is kept as a second bound, which upstream drops: it costs nothing while the window stays under the MTU, and prevents fragmentation when the MTU shrinks after the window has widened.
- The UDP window is now widened unconditionally rather than only when `random_trailers` is on. That was harmless while the window sized nothing but trailers; once content padding is measured against it, a tunnel with trailers off would have kept its starting window forever.

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