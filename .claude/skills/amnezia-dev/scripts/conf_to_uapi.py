#!/usr/bin/env python3
"""Translate an AmneziaWG .conf into an awgtun UAPI `set=1` block.

A .conf and the UAPI socket are different formats: .conf names the 3.0 fields in
CamelCase and encodes keys in base64, UAPI uses snake_case and hex. `awg setconf`
does this translation; this script does it when you drive the socket directly.

Usage:
    conf_to_uapi.py <path/to/server.conf> [allowed-ips-override]

Prints the block on stdout, and the interface address plus the resolved endpoint
on stderr so they can be read without capturing the block (which holds private
key material).

The second argument replaces the peer's AllowedIPs. Pass the tunnel subnet, e.g.
"192.0.2.0/24" — a real config almost always says 0.0.0.0/0, and honoring that
routes the whole machine through the tunnel.
"""

import base64
import socket
import sys

# .conf name (lowercased) -> UAPI name. 2.0 keys are identical once folded.
INTERFACE_KEYS = {
    "jc": "jc",
    "jmin": "jmin",
    "jmax": "jmax",
    "s1": "s1",
    "s2": "s2",
    "s3": "s3",
    "s4": "s4",
    "h1": "h1",
    "h2": "h2",
    "h3": "h3",
    "h4": "h4",
    "i1": "i1",
    "i2": "i2",
    "i3": "i3",
    "i4": "i4",
    "i5": "i5",
    "contentpaddingaddition": "content_padding_addition",
    "rekeyaftertime": "rekey_after_time",
    "rekeytimeout": "rekey_timeout",
    "rejectaftertime": "reject_after_time",
    "keepalivetimeout": "keepalive_timeout",
    "maxhandshakeattempts": "max_handshake_attempts",
    "headerprotectionkey": "header_protection_key",
    # Deliberately absent: MTU. It is not a UAPI key in wg or amneziawg-go — the
    # device uses its interface MTU — and sending it earns EINVAL. Set it with
    # `ip link set mtu`, as wg-quick does.
}

# Values that are base64 in .conf and hex over the socket.
KEY_FIELDS = {"privatekey", "publickey", "presharedkey", "headerprotectionkey"}


def to_hex(value, field):
    try:
        raw = base64.b64decode(value, validate=True)
    except Exception:
        # Already hex, or the user pre-translated it.
        return value
    if len(raw) != 32:
        sys.exit(f"{field}: expected a 32-byte key, got {len(raw)} bytes")
    return raw.hex()


def main():
    if not 2 <= len(sys.argv) <= 3:
        sys.exit(__doc__)
    conf_path = sys.argv[1]
    allowed_override = sys.argv[2] if len(sys.argv) > 2 else None

    interface, peer = [], []
    section = None
    address = endpoint = None

    with open(conf_path) as handle:
        for raw_line in handle:
            line = raw_line.split("#")[0].strip()
            if not line:
                continue
            if line.startswith("["):
                section = line.strip("[]").lower()
                continue

            key, _, value = line.partition("=")
            key = key.strip().lower()
            value = value.strip()

            if section == "interface":
                if key == "privatekey":
                    interface.append("private_key=" + to_hex(value, key))
                elif key == "address":
                    address = value
                elif key in INTERFACE_KEYS:
                    if key in KEY_FIELDS:
                        value = to_hex(value, key)
                    interface.append(f"{INTERFACE_KEYS[key]}={value}")
            elif section == "peer":
                if key == "publickey":
                    peer.append("public_key=" + to_hex(value, key))
                elif key == "presharedkey":
                    peer.append("preshared_key=" + to_hex(value, key))
                elif key == "endpoint":
                    host, _, port = value.rpartition(":")
                    endpoint = f"{socket.gethostbyname(host)}:{port}"
                    peer.append("endpoint=" + endpoint)
                elif key == "allowedips":
                    for cidr in (allowed_override or value).split(","):
                        peer.append("allowed_ip=" + cidr.strip())
                elif key == "persistentkeepalive":
                    peer.append("persistent_keepalive_interval=" + value)

    if not peer:
        sys.exit("no [Peer] section found")

    print(f"address={address}", file=sys.stderr)
    print(f"endpoint={endpoint}", file=sys.stderr)
    if allowed_override:
        print(f"allowed_ip overridden to {allowed_override}", file=sys.stderr)

    # The device applies the AmneziaWG block when it reaches `public_key`, so the
    # interface keys have to come first.
    print("\n".join(interface + ["replace_peers=true"] + peer))


if __name__ == "__main__":
    main()
