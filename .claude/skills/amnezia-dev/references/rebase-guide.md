# Rebase Guide: amnezia branch onto upstream master

## Pre-flight

```bash
git status                    # must be clean
git branch --show-current     # must be on amnezia
git fetch origin master
git log --oneline amnezia..origin/master | head -20
```

If no new commits, stop — nothing to rebase.

## Preview Conflicts

```bash
git diff --name-only $(git merge-base amnezia origin/master)..origin/master
```

Cross-reference with AWG-modified files below.

## Rebase

```bash
git rebase origin/master
```

## Conflict Resolution by File

| File | Our changes | Strategy |
|------|------------|----------|
| `amnezia.rs` | Entirely new file | Always keep ours (no upstream counterpart) |
| `lib.rs` | Added `pub mod amnezia;` | Keep both sides — just ensure our line is present |
| `noise/mod.rs` | Tunn fields, new_with_amnezia, parse_incoming_packet_config, encapsulate/decapsulate padding, determine_padding, poll_outgoing_packet, queue_pre_handshake_packets | Accept upstream structural changes, re-apply our additions. Our changes ADD to functions rather than replacing them. |
| `noise/handshake.rs` | `msg_type: u32` param on format_handshake_initiation, format_handshake_response, receive_handshake_initialization | Accept upstream, re-add the msg_type parameter. The change is mechanical. |
| `noise/session.rs` | `msg_type: u32` param on format_packet_data | Accept upstream, re-add parameter |
| `noise/rate_limiter.rs` | HeaderConfig import, header_config param on verify_packet, msg_type on format_cookie_reply, dynamic cookie header | Accept upstream, re-apply parameter additions |
| `noise/timers.rs` | `self.network_outgoing.clear()` in clear_all | Trivial — add after `self.packet_queue.clear()` |
| `device/mod.rs` | `&HeaderConfig::default()` arg to verify_packet | Re-apply the extra argument |
| `ffi/mod.rs` | amnezia imports, amnezia_config struct, new_tunnel_amnezia, wireguard_poll_outgoing_packet | Accept upstream, re-apply our additions |
| `Cargo.toml` | We use base64, rand_core (already upstream deps) | Accept upstream dependency changes |

## After Resolving Each File

```bash
git add <file>
git rebase --continue
```

## Verify

```bash
cargo test -p boringtun --lib --no-run
./target/debug/deps/boringtun-* --no-capture
cargo clippy -p boringtun 2>&1 | grep -E "error|warning" | head -20
cargo build --lib -p boringtun --features ffi-bindings
```

All 38+ tests must pass.

## Abort if Needed

```bash
git rebase --abort
```

## Important Notes

- Never force-push without explicit user confirmation
- If upstream renamed/restructured files we modify, flag it to the user
- `.cargo/config.toml` has `runner = 'sudo -E'` — run test binaries directly
