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

### Requested: move the C/JNI exports out of the library crate

`awgtun/Cargo.toml` declares `crate-type = ["staticlib", "cdylib", "rlib"]` on
the library crate, and Cargo cannot feature-gate `crate-type`, so every
downstream build pays for all three:

- A plain desktop `cargo build` of shoes produces `libawgtun-*.a`, `.rlib`
  **and** `.so` in `target/debug/deps` — only the rlib is ever used. That is
  extra link work on every build of every Rust consumer, on every target.
- On Android, `cargo-ndk` copies every cdylib in the graph into the consumer's
  AAR. shoes ships three ABIs, so ~330 KB × 3 of `libawgtun-*.so` land where
  nothing can load them (the hashed filename is not a valid `System.loadLibrary`
  name). shoes defends itself with a delete step in its build script *and* a CI
  loop that fails if a foreign `.so` appears in the AAR — two mechanisms
  compensating for the dependency's crate layout.

Proposed shape: a workspace member (say `awgtun-ffi`) with
`crate-type = ["staticlib", "cdylib"]` owning the `ffi-bindings` /
`jni-bindings` export surface, and `awgtun` itself as a plain rlib. Release
artifacts stay as they are — the release workflow builds the FFI crate instead
of the library with a feature. Rust consumers stop building artifacts they
discard, and the AAR pollution disappears at the source.

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
