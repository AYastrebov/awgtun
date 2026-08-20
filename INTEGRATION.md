# Integration requests from downstream

Feedback from consumers of this library, addressed to whoever works on this
repository next. Each entry says who is asking, what they verified, and what
they want. Remove an entry when it is done or rejected — this file is an inbox,
not a history.

## From shoes (AYastrebov/shoes, branch `mobile`) — 2026-08-20

shoes consumes awgtun as a git dependency pinned to `tag = "v0.8.0"`, drives
`Tunn` directly rather than through the device layer, and builds
`Amnezia3Config` field by field from its own YAML config. Everything below was
verified against both trees on 2026-08-20.

### Done in 0.9.0: C/JNI exports moved out of the library crate

Built as proposed. `awgtun-ffi` owns the export surface with
`crate-type = ["staticlib", "cdylib"]`, and `awgtun` is a plain rlib. Verified
in a clean target directory: building the library alone now produces only
`libawgtun-*.rlib` and `.rmeta` — no `.a`, no `.so`.

What downstream has to change:

- Build `-p awgtun-ffi` where you built `awgtun` with `--features ffi-bindings`;
  `--features jni-bindings` still selects the JNI exports, now on that crate.
- The Android library is `libawgtun_ffi.so`, so `System.loadLibrary("awgtun")`
  becomes `System.loadLibrary("awgtun_ffi")`. The JNI class name is unchanged.
- The header is at `awgtun-ffi/wireguard_ffi.h`, contents unchanged.

shoes' delete step and CI guard can go once it moves to 0.9.0, since nothing
foreign lands in the AAR any more.

One thing the split surfaced: `Amnezia2Config` is `#[non_exhaustive]`, so the
FFI crate can no longer build it with a struct literal and starts from
`Amnezia2Config::wireguard_compatible()` instead. That is the attribute working
as intended rather than a problem, but it is worth knowing if you construct
that type yourself. `KeyBytes` is now public for the same reason.

### Suggested, no urgency: publish to crates.io

Impossible under the old name — `boringtun` on crates.io is Cloudflare's —
but the crate's own name is publishable. A crates.io release would let
downstream replace the git pin with a version requirement and bring
`cargo audit` / dependabot coverage. The tag pin works fine meanwhile.

### No change needed — recorded so it stays that way

The AmneziaWG 3.1 surface is already right for a direct-`Tunn` consumer:

- Both `random_trailers` and `disable_cookies` live in `Amnezia3Config`, not
  behind the device layer, so a consumer building that struct directly can
  expose them without any change here.
- `Tunn::reset_udp_window` is `pub`, which is exactly what a direct-`Tunn`
  consumer needs: it does not get `Peer::set_endpoint`'s automatic reset, so it
  must call it itself when its endpoint rebinds. shoes will do that from its
  network-change path when it exposes 3.1.

Also fine as-is: the `x25519` re-export, empty default features, and the module
layout surviving the rename unchanged.

*The requested doc polish is done: `Amnezia3Config::random_trailers` now points
at `Tunn::reset_udp_window`, and that method's own docs say plainly that a
direct-`Tunn` caller owns the reset. Its previous wording said the `Device`
layer calls it, which read as "not your problem" to exactly the audience whose
problem it is.*
