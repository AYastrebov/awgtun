# Same-key userspace → kernel timestamp regression

Kernel WireGuard (`drivers/net/wireguard/noise.c::tai64n_now`) and wireguard-go
use Unix seconds + `0x400000000000000a`. The inherited BoringTun stamper added
37 instead of 10. A kernel initiation following a userspace initiation with the
same identity therefore appears older for approximately 27 seconds.

The unit tests exercise the actual stamper against the kernel clock convention
and verify that switching to a kernel timestamp one second later goes forwards.
The opt-in integration test uses actual **standard kernel WireGuard**, not the
AmneziaWG module or another awgtun instance. It completes an awgtun handshake,
then replaces only the client with a kernel peer using the same private key.
The server and its replay state remain alive. The kernel client must complete
its own handshake within eight seconds (allowing one normal ~5s retry, but not
allowing the 27s offset to expire). Obfuscation is disabled throughout.

CI runs it on every pull request: the `integration-tests` job runs all
ignored tests as root on `ubuntu-latest`, whose kernel ships the `wireguard`
module, and installs `wireguard-tools` for `wg`. To run it locally, build on
Linux, then run only this ignored test as root:

```sh
cargo test -p awgtun --test kernel_timestamp --locked --no-run
sudo ./target/debug/deps/kernel_timestamp-<hash> --ignored --nocapture
```

Requires `ip`, `wg`, Linux network namespace support and the `wireguard` module.
A missing prerequisite is a failure, not a silent pass. Only ephemeral random
keys are used. Interfaces are created in the original namespace so their UDP
sockets remain there, then moved to dedicated namespaces; no host addresses,
routes or firewall rules are changed. Cleanup deletes only test namespaces and
interfaces. Do not run simultaneously with another copy with the same process ID.

Changing back from an already-running +37 build to the fixed build can itself
cause one final replay window, because the server has remembered the old future
timestamp. The patch prevents that offset from being introduced by future
handshakes; it does not clear or weaken the server's anti-replay state.
