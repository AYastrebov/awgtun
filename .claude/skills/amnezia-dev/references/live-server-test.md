# Testing against a live AmneziaWG server

Two awgtun devices talking to each other prove the code is self-consistent.
Only a real server proves it speaks AmneziaWG. This is the test that caught a
padding cap that made a production server unreachable, and it takes about a
minute to run.

You need: an AmneziaWG `.conf` from a working server, root, and `socat`.

## Step 1: translate the `.conf` into a UAPI block

A `.conf` and the UAPI socket are **not** the same format, and this trips people
up. `awg setconf` translates between them; if you drive the socket directly, you
translate.

| `.conf` | UAPI | Note |
|---|---|---|
| `Jc`, `S1`, `H1` … | `jc`, `s1`, `h1` … | Case-folded, so 2.0 keys survive as-is |
| `ContentPaddingAddition` | `content_padding_addition` | CamelCase → snake_case |
| `RekeyAfterTime`, `MaxHandshakeAttempts` | `rekey_after_time`, `max_handshake_attempts` | same |
| `HeaderProtectionKey = <base64>` | `header_protection_key=<64 hex chars>` | **base64 → hex** |
| `PrivateKey`, `PublicKey`, `PresharedKey` | same names, lowercased | **base64 → hex** |
| `Endpoint = host:port` | `endpoint=<ip>:port` | The parser wants a `SocketAddr`; resolve DNS yourself |
| `MTU` | *(nothing)* | Not a UAPI key — a device knows its own MTU. Sending `mtu=` gets `errno=22` |
| `Address`, `DNS` | *(nothing)* | Applied with `ip addr` / resolver config, not the socket |

The interface keys come first, then `replace_peers=true`, then the peer section.
The device applies the AmneziaWG block when it sees `public_key`, so a peer must
never precede the interface keys.

`scripts/conf_to_uapi.py` does this translation. It prints the block on stdout
and the address/endpoint it found on stderr:

```bash
python3 .claude/skills/amnezia-dev/scripts/conf_to_uapi.py ~/server.conf "192.0.2.0/24" > /tmp/uapi.txt
```

The second argument overrides `AllowedIPs` — see the warning in step 3.

## Step 2: bring up the tunnel

```bash
IF=awgtest0
SOCK=/var/run/wireguard/$IF.sock

sudo WG_SUDO=1 ./target/release/awgtun-cli --disable-drop-privileges \
    -v debug -l /tmp/awgtun.log "$IF"
sleep 1

printf 'set=1\n%s\n\n' "$(cat /tmp/uapi.txt)" | sudo socat - UNIX-CONNECT:"$SOCK"
# expect: errno=0
```

`errno=22` is `EINVAL` — the AmneziaWG block was rejected. `errno=71` is
`EPROTO`, a malformed line. Check `/tmp/awgtun.log` for the specific
`ConfigError`; the device logs it before returning the number.

Then address and route:

```bash
sudo ip addr add 192.0.2.2/32 dev "$IF"
sudo ip link set mtu 1420 up dev "$IF"
sudo ip route add 192.0.2.0/24 dev "$IF"
```

## Step 3: don't hijack the default route

A real `.conf` almost always says `AllowedIPs = 0.0.0.0/0, ::/0`. Honoring that
sends *all* of the machine's traffic through the tunnel, which is a rude thing
to do to someone's workstation in the middle of a test and awkward to unwind if
the tunnel then misbehaves.

Route only the tunnel subnet and ping the server's tunnel address. That
exercises the identical code path — handshake, classification, header
protection, content padding, encapsulation, decapsulation — with none of the
blast radius.

## Step 4: verify

```bash
ping -c 4 192.0.2.1
printf 'get=1\n\n' | sudo socat - UNIX-CONNECT:"$SOCK"
```

What a healthy result looks like:

- `ping` at 0% loss. The handshake, both directions of the data path, and the
  peer's own padding and header protection all had to work for a single reply.
- `last_handshake_time_sec` present.
- `rx_bytes` and `tx_bytes` both non-zero — these count decapsulated payload, so
  they move only once real traffic flows. They stay at 0 through a
  handshake-only test, which is not a failure.
- The `get=1` block echoes back every AmneziaWG key you set, which is
  `awg showconf` round-tripping.

Tear down with `sudo ip link del awgtest0`.

## Step 5: clean up the key material

The UAPI block contains the private key and preshared key in hex, in a
world-readable temp file. Delete it when you are done, and never paste the block
into a commit, an issue, or a transcript. Redact when quoting output:

```bash
sed -E 's/^(private_key|public_key|preshared_key|header_protection_key)=.*/\1=<redacted>/'
```

## Reading the wire

To confirm what actually left the machine — the I-packet/junk/init order, the
sizes — capture before starting the device:

```bash
sudo tcpdump -i any -n "udp and host <server-ip>" -w /tmp/awg.pcap
```

Expect, in order: each configured I-packet as its own datagram at the size its
CPS chain implies, then `Jc` junk datagrams with sizes in `[Jmin, Jmax)`, then
one datagram of `148 + S1` bytes. The response is `92 + S2`. If the initiation
is exactly 148 bytes, S1 never got applied; if the I-packets are missing, the
caller is not draining `poll_outgoing_packet()`.
