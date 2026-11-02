# Phobos obfuscation: wire format

This document specifies the UDP obfuscation layer used by
[Phobos](https://github.com/Ground-Zerro/Phobos), so that `awgtun::phobos` can
interoperate with a Phobos server without depending on, or being derived from,
its source code. It describes behaviour observable on the wire and in the
reference's configuration surface.

## Reference of record

| Repository | Commit | Date |
|---|---|---|
| Ground-Zerro/Phobos | `22aedefda053062dc58c036072d2da6e216d5a34` | 2026-10-12 |

The protocol has no versioned specification upstream. Behaviour is defined by
the server's obfuscator (`src/phobos-obfuscator`) and its client ports. To
check for drift, diff `src/phobos-obfuscator/{obfuscation.h,masking*.c,config.c}`
and `windows/phobos/golden_vectors_test.go` from the commit above to the
current head. The conformance vectors in `awgtun/src/phobos.rs` are taken
from that test file.

Licensing: the Phobos repository is AGPL-3.0 and its obfuscator directory is
GPL-3.0, while awgtun is BSD-3-Clause. `awgtun::phobos` is written from this
document. Do not copy code from the Phobos tree into this repository.

## Where it sits

```
client WireGuard ─► [ Phobos encode → mask ] ─UDP─► [ unmask → decode ] ─► server WireGuard
```

A Phobos server terminates the obfuscation and forwards **standard
WireGuard** to a kernel interface. The client must therefore send plain
WireGuard messages under Phobos: no AmneziaWG headers, padding, header
protection or junk. The decoder also relies on bytes 1–3 of a WireGuard
message being zero (see below), which every AmneziaWG feature breaks.

The two layers are independent:

1. **Encoding** transforms one WireGuard message into one opaque payload
   (header rewrite, optional random tail, XOR keystream).
2. **Masking** wraps that payload in a cover-protocol frame (none, a STUN Data
   Indication, or an RTP header) and adds STUN Binding control traffic.

## Configuration

Key spellings are the reference's client and server configuration keys.

| Key | Type | Accepted | Default | Meaning |
|---|---|---|---|---|
| `key` | bytes | 1–255 bytes, after trimming whitespace | — (required) | Shared XOR key, used as raw bytes (not base64-decoded) |
| `masking` | enum | `none`, `stun`, `media`, `auto`, `tls` (case-insensitive) | `auto` | Cover protocol. See below |
| `max-dummy` | integer | 0–1024 | 4 | Upper bound (exclusive) on random tail bytes for cookie and transport messages |
| `obfuscate-bytes` | integer | 0–2³¹−1 | 0, or 16 under `media` | XOR only the first N bytes; 0 means the whole payload |
| `media-pt` | integer | 0–127 | 0 | RTP payload type; 0 picks a preset at random |
| `media-ssrc` | u32 | decimal, `0x` hex or leading-`0` octal | 0 | RTP SSRC; 0 picks one at random per stream |
| `media-clock` | integer, fps | 0–1000 | 0 | RTP timestamp step is `90000 / fps`; 0 picks a preset |

Notes on `masking`:

- `auto` is a **server** mode: the server identifies each client's masking
  from its first packet. A client configured `auto` has no cover protocol, so
  it behaves exactly like `none`.
- `tls` exists only for the reference's SOCKS5/TCP presets. On UDP it
  installs no cover protocol, so it also behaves like `none`.
- When `masking` is `media` and `obfuscate-bytes` is 0 or absent, the
  effective value is 16.

Both peers must agree on `key`, `masking` (unless the server is `auto`) and
`obfuscate-bytes`. `max-dummy` and the `media-*` values are sender-side only,
except that a configured `media-pt` or `media-ssrc` is also enforced on
receive.

## Encoding

### WireGuard message types

The first four bytes of a WireGuard message, read little-endian, are its type:
1 = initiation, 2 = response, 3 = cookie reply, 4 = transport data. In plain
WireGuard, bytes 1–3 are always zero.

A buffer of at least 4 bytes **looks plain** when `b[0]` is in 1..=4 and
`b[1]`, `b[2]` and `b[3]` are all zero. Anything else **looks obfuscated**.

### Keystream

The keystream depends only on the key `K` (length `k`) and the length `n` of
the region being masked:

```
table  = CRC-8, reflected, polynomial 0x8C, init 0; table[i] = crc8 of the single byte i
base   = (n + k) mod 256
adj[j] = (K[j] + base) mod 256              for j in 0..k
c      = 0
for i in 0..n:
    c          = table[c XOR adj[i mod k]]
    stream[i]  = c
```

The mask is `stream[0..n]`, and masking is `buf[i] ^= stream[i]`. Applying
it twice restores the input. Two regions of the same length under the same
key get the same mask.

### Encode (sender)

Input is one WireGuard message `M` of length `L >= 4`. `R` is the configured
`obfuscate-bytes` value, after the `media` default above is applied.

1. `partial = R > 0 and R < L`.
2. `t = LE32(M[0..4])` (the original type, read before rewriting).
3. Choose `r` uniformly in 1..=255. Set `M[0] ^= r` and `M[1] = r`.
4. Tail length `d`:
   - `d = 0` if `partial` or `L >= 1024`.
   - Otherwise let `room = 1024 - L`. If `R > 0`, set
     `room = min(room, R - L + 1)`. Then:
     - `t` is 1 or 2: `d` uniform in `[0, min(room, 512))`.
     - `t` is 3 or 4 and `max-dummy > 0`: `d` uniform in
       `[0, min(room, max-dummy))`.
     - Otherwise, `d = 0`.
5. Write `d` as little-endian u16 into `M[2..4]`, and append `d` random bytes.
   The new length is `L' = L + d`.
6. Mask the first `partial ? R : L'` bytes with the keystream for that length.

Since `r != 0`, an encoded message never looks plain once unmasked. The
`R - L + 1` cap keeps `L' <= R`, so a receiver that sees `L'` reaches the same
`partial` decision.

### Decode (receiver)

Input is a payload `P` of length `N >= 4`.

1. `partial = R > 0 and R < N`. Unmask the first `partial ? R : N` bytes with
   the keystream for that length.
2. If `P` now looks plain, it was never encoded: deliver it as is, length `N`.
3. Otherwise, `P[0] ^= P[1]`, `d = LE16(P[2..4])`, and set `P[1..4] = 0`.
   The message is `P[0 .. N - d]`.
4. Drop the payload if `N - d < 4` or `N - d > N`.

## Masking

All multi-byte fields in this section are big-endian. The STUN magic cookie is
`21 12 A4 42`.

### `none`

The payload is the datagram. No control traffic.

### `stun`

**Data frame, both directions.** A 24-byte header, then the payload:

```
off  len  value
 0    2   0x0115              (Data Indication)
 2    2   0x0000              (message length — the reference leaves it zero)
 4    4   magic cookie
 8   12   transaction ID, random per frame
20    2   0x0013              (DATA attribute)
22    2   payload length
24    …   payload
```

**Binding Request.** 28 bytes:

```
 0    2   0x0001
 2    2   0x0008              (message length: the fingerprint attribute)
 4    4   magic cookie
 8   12   transaction ID, random
20    2   0x8028              (FINGERPRINT)
22    2   0x0004
24    4   CRC-32/IEEE(bytes 0..20, length field zeroed) XOR 0x5354554E
```

**FINGERPRINT quirk.** The reference computes the CRC while the
message-length field (bytes 2–3) is still zero, and only then writes the
length. RFC 5389 includes the final length, so these fingerprints don't
validate under a strict STUN parser. Match the reference anyway: its test
vectors pin this order. The same rule applies to the Binding Success
Response below.

**Binding Success Response**, sent in reply to a peer's Binding Request.
40 bytes:

```
 0    2   0x0101
 2    2   0x0014              (20: XOR-MAPPED-ADDRESS + FINGERPRINT)
 4    4   magic cookie
 8   12   the request's transaction ID
20    2   0x0020              (XOR-MAPPED-ADDRESS)
22    2   0x0008
24    1   0x00
25    1   0x01                (IPv4)
26    2   source port XOR 0x2112
28    4   source IPv4 address XOR magic cookie
32    2   0x8028
34    2   0x0004
36    4   CRC-32/IEEE(bytes 0..32, length field zeroed) XOR 0x5354554E
```

The source is the address the request came from. If it is IPv6 and not
IPv4-mapped, no reply is sent.

**Client behaviour:**

- Before sending each plain WireGuard handshake initiation (type 1), send a
  Binding Request.
- Every 10 seconds, send a Binding Request. This only adds realism: the
  server does not count it as activity, and its idle timeout is driven by
  WireGuard traffic alone.
- On receive, classify the datagram:
  - Fewer than 8 bytes, or no magic cookie at offset 4: drop.
  - `0x0001` Binding Request: reply with a Binding Success Response; nothing
    is delivered. A request shorter than 20 bytes has no complete transaction
    ID and is dropped.
  - `0x0101` Binding Success: drop.
  - `0x0115` Data Indication: valid when `N >= 24`, the message-length field
    plus 20 is at most `N`, the attribute type is `0x0013`, and the DATA
    length plus 24 is at most `N`. The payload is `DATA length` bytes at
    offset 24. Any other Data Indication is dropped.
  - Any other type: drop.

### `media`

**Data frame.** A 12-byte RTP header, then the payload:

```
 0    1   0x80                       (version 2, no padding/extension/CSRC)
 1    1   0x80 | payload type        (marker bit set)
 2    2   sequence number
 4    4   timestamp
 8    4   SSRC
12    …   payload
```

Each direction is its own stream. On its first frame a stream picks a random
starting sequence and timestamp. Its SSRC is `media-ssrc`, or a random
non-zero value. Its payload type and timestamp step come from `media-pt` and
`media-clock`, and each unset value is filled from one preset drawn uniformly
from this table of `(payload type, timestamp step)` pairs:

```
(96,3000) (96,3600) (96,3750) (96,1500) (96,6000) (97,3000) (97,3600)
(97,4500) (97,9000) (97,18000) (98,3000) (98,3600) (98,3750) (98,1500)
(98,6000) (99,3000) (99,3600) (100,3000) (100,1500) (100,3750) (102,3000)
(102,1500) (102,3600) (104,3000) (104,1500) (106,3000) (106,3750) (108,3000)
(108,1500) (110,3000) (112,3000) (112,3600) (114,3000) (114,1500) (116,3000)
(118,3000) (119,3000) (120,3000) (122,3000) (123,3000) (124,3000) (125,3000)
(125,1500) (126,3000) (127,3000) (127,1500) (127,3750) (96,1502) (96,3003)
(97,3753)
```

Each frame uses the current sequence number and timestamp, then increments
the sequence by 1 and the timestamp by the step, both wrapping.

**Control traffic** is the same STUN Binding exchange as `stun`, on a 5-second
timer.

**Receive:**

- A datagram carrying the magic cookie at offset 4 is handled as STUN
  control/data, exactly as under `stun`.
- Otherwise it is RTP. Drop it if `N < 16`, or `b[0] & 0xC0 != 0x80`, or a
  configured `media-pt` differs from `b[1] & 0x7F`, or a configured
  `media-ssrc` differs from `b[8..12]`. The payload starts at offset 12.

## Receive order

For each datagram from the server:

1. Fewer than 4 bytes: drop.
2. If the raw datagram looks plain, drop it. The reference client classifies
   such a datagram as unobfuscated and *encodes* it on its way to the local
   WireGuard, so it never arrives intact; dropping is the same outcome without
   the wasted work. A Phobos server never sends one.
3. Unmask with the configured cover protocol. If that produced a reply,
   send it. If it produced no payload, stop.
4. Payload under 4 bytes: drop.
5. Decode. Deliver the result to WireGuard.

Malformed datagrams are dropped silently. Only configuration produces errors.

## Server state that constrains the client

The server keys clients by source address. It accepts a handshake initiation
from any address, but drops every other message from an address whose
handshake has not completed through it. Its idle timeout defaults to 300 s.

A client whose source address changes (rebind, network switch) must
therefore send a **handshake initiation**, not a keepalive, before data flows
again. awgtun leaves this to the caller, because the codec owns no socket.

## Size overhead

| Masking | Fixed overhead | Random tail |
|---|---|---|
| `none` | 0 | Up to 511 bytes on handshakes; under `max-dummy` on cookie/transport; none at or above 1024 bytes, or when `obfuscate-bytes` is partial |
| `stun` | 24 bytes | same |
| `media` | 12 bytes | same |

Transport messages of 1024 bytes or more never get a tail, so a full-size
tunnel packet grows only by the fixed overhead. Lower the tunnel MTU by that
amount.
