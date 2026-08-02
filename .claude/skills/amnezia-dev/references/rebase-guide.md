# Pulling upstream boringtun into this fork

This fork carries the AmneziaWG work on `master` and has diverged far enough
that upstream is a source to pull *from* rather than a base to sit on. There is
no separate integration branch any more, and there was never an `upstream`
remote — `origin` is the fork.

Merge rather than rebase. `master` is published and other people may have it;
rebasing it would rewrite history they already hold. Rebasing was the right call
when the AmneziaWG work lived on a private branch, and is the wrong one now.

## Pre-flight

```bash
git status                    # must be clean
git branch --show-current     # must be on master

# One-time, if not already configured.
git remote add upstream https://github.com/cloudflare/boringtun

git fetch upstream master
git log --oneline master..upstream/master | head -20
```

If no new commits, stop — nothing to pull.

## Preview conflicts

```bash
git diff --name-only $(git merge-base master upstream/master)..upstream/master
```

Cross-reference with the table below. Anything outside it should merge cleanly.

## Merge

```bash
git merge upstream/master
```

## Conflict resolution by file

The shape of nearly every conflict is the same: our changes *add* to upstream
functions rather than replacing them — an extra parameter, an extra branch, an
extra field. So the strategy is almost always "take upstream's version, then
re-apply our additions on top", not "pick a side".

| File | Our changes | Strategy |
|------|------------|----------|
| `amnezia.rs` | Entirely new file | Always keep ours — no upstream counterpart |
| `lib.rs` | `pub mod amnezia;` | Keep both sides; just ensure our line survives |
| `noise/mod.rs` | `Tunn` AWG fields, `new_with_amnezia{,3}`, `PacketClassifier`, padding in `encapsulate`/`decapsulate`, header protection, content padding, `poll_outgoing_packet`, `queue_pre_handshake_packets` | Largest conflict surface. Accept upstream structure, re-apply our additions |
| `noise/handshake.rs` | `msg_type: u32` on `format_handshake_initiation`, `format_handshake_response`, `receive_handshake_initialization` | Mechanical — re-add the parameter |
| `noise/session.rs` | `msg_type` and `content_padding` on `format_packet_data` | Mechanical — re-add both |
| `noise/rate_limiter.rs` | `HeaderConfig` param on `verify_packet`, `msg_type` on `format_cookie_reply` | Re-apply the parameter additions |
| `noise/timers.rs` | `network_outgoing.clear()` in `clear_all`, AWG 3.0 randomized timings (`TimingRanges`, `roll_handshake_timings`, the range arms in `update_timers`) | The timing work is substantial; re-apply carefully and rerun the timer tests |
| `device/mod.rs` | Device-scoped `amnezia` field, classify-before-peer in `register_udp_handler`, four drain sites, `set_amnezia_config`, `peer_amnezia_config` | Upstream rarely touches the event loop; if it does, re-apply each drain site individually |
| `device/api.rs` | `is_amnezia_interface_key`, `apply_amnezia_block`, AWG block in `api_get`, keepalive range in `api_set_peer`, `splitn(2, '=')` | Re-apply; the `splitn` fix is easy to lose |
| `device/peer.rs` | `drain_outgoing`, `keepalive_range`, `set_tunnel` | Additive methods; re-add |
| `device/integration_tests/mod.rs` | The `test_awg*` tests and their helpers | Ours are appended at the end of the module; usually conflict-free |
| `ffi/mod.rs` | `amnezia_config`/`amnezia3_config`, `new_tunnel_amnezia{,3}`, `wireguard_poll_outgoing_packet` | Accept upstream, re-apply our additions |
| `wireguard_ffi.h` | AWG 2.0 and 3.0 declarations | Additive |
| `jni.rs` | `new_tunnel_amnezia3`, `poll_outgoing_packet`, `tunnel_free` | Additive |
| `Cargo.toml` | base64, rand_core (already upstream deps) | Accept upstream dependency changes |

## After resolving each file

```bash
git add <file>
git merge --continue
```

## Verify

Do not skip the device tests — the `device` module is where a silent upstream
change is most likely to break AmneziaWG, because classification and the drain
sites live inside functions upstream owns.

```bash
# Unit tests
cargo test -p boringtun --lib --no-run
./target/debug/deps/boringtun-* --no-capture

# Device tests. Never --all-features: it enables mock-instant, which freezes the
# clock so no timer fires and every device test fails looking like a protocol bug.
cargo test -p boringtun --lib --features device --no-run
sudo -E ./target/debug/deps/boringtun-* --ignored --test-threads 1 awg

# Feature builds
cargo build --lib -p boringtun --features ffi-bindings
cargo build --lib -p boringtun --features jni-bindings
```

All tests must pass — 97 unit tests and 5 AWG device tests as of this writing.
If the count dropped, a test was lost in a conflict rather than fixed.

A green suite still is not proof of interop. If the merge touched
`noise/mod.rs`, `noise/session.rs` or the `device` receive path, run the live
server check in `live-server-test.md` before considering the merge done.

## Abort if needed

```bash
git merge --abort
```

## Notes

- Never force-push. `master` is published, which is also why this merges rather
  than rebases.
- If upstream renamed or restructured a file we modify, flag it rather than guessing
- `.cargo/config.toml` sets `runner = 'sudo -E'`; run test binaries directly to
  avoid the sudo prompt on unit tests
