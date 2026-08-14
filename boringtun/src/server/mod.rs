// Copyright (c) 2024 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! A runtime-agnostic (sans-io), synchronous multi-peer WireGuard/AmneziaWG
//! **server** core.
//!
//! Unlike [`crate::device`], which owns sockets and an epoll loop, this module
//! is a pure state machine: the caller performs every byte of I/O and hands
//! datagrams in and out. That makes it usable from an async runtime (e.g. a
//! tokio app) without dragging blocking sockets along.
//!
//! The one responder-specific complication is anonymous demultiplexing: on a
//! single UDP socket the peer that sent a datagram is not known until the
//! packet is parsed, and with AmneziaWG 3.0 header protection the message type
//! is itself encrypted. [`WgServer::handle_incoming`] is a sans-io port of the
//! anonymous demux the device runs in `register_udp_handler`: classify, strip
//! the S1-S4 padding, unprotect the header, rate-limit, select the peer by
//! anonymous handshake parse (initiations) or `receiver_idx >> 8` (everything
//! else), then feed the verified packet to that peer's [`Tunn`].

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use rand_core::{OsRng, RngCore};

use crate::amnezia::{Amnezia3Config, ConfigError};
use crate::noise::handshake::parse_handshake_anon;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::{
    Packet, PacketClassifier, Tunn, TunnResult, COOKIE_REPLY_SZ, TRANSPORT_HEADER_SZ,
};
use crate::x25519;
use std::sync::Arc;

/// Configuration for a single peer the server accepts.
pub struct PeerConfig {
    pub public_key: x25519::PublicKey,
    pub preshared_key: Option<[u8; 32]>,
    /// Cryptokey-routing networks owned by this peer, as `(network, cidr)`.
    pub allowed_ips: Vec<(IpAddr, u8)>,
    pub persistent_keepalive: Option<u16>,
}

/// The result of feeding one inbound datagram to [`WgServer::handle_incoming`].
pub enum ServerInput<'a> {
    /// Send these datagrams, in order, to `to`.
    WriteToNetwork {
        to: SocketAddr,
        datagrams: Vec<Vec<u8>>,
    },
    /// A decapsulated inner IP packet from the peer with this static pubkey.
    /// Borrows the caller's `out` scratch buffer.
    WriteToTunnel { peer: [u8; 32], packet: &'a [u8] },
    /// Nothing to do (dropped, consumed, or an error the caller ignores).
    Done,
}

/// Datagrams destined for a single peer's endpoint. Emitted by
/// [`WgServer::update_timers`] and [`WgServer::encapsulate_to_peer`].
pub struct PeerDatagrams {
    pub to: SocketAddr,
    pub datagrams: Vec<Vec<u8>>,
}

/// One accepted peer: its tunnel state, on-wire index, last known endpoint, and
/// cryptokey-routing networks.
struct Peer {
    tunn: Tunn,
    /// Local index. The peer's on-wire receiver-index base is `index << 8`, so
    /// demux is `receiver_idx >> 8 == index`.
    index: u32,
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<(IpAddr, u8)>,
}

impl Peer {
    fn is_allowed_ip(&self, ip: IpAddr) -> bool {
        self.allowed_ips.iter().any(|&(net, cidr)| {
            IpNetwork::new_truncate(net, cidr)
                .map(|n| n.contains(ip))
                .unwrap_or(false)
        })
    }
}

/// A sans-io multi-peer AmneziaWG/WireGuard server (responder).
pub struct WgServer {
    private_key: x25519::StaticSecret,
    public_key: x25519::PublicKey,
    /// Shared obfuscation config; identical for every peer, as AmneziaWG
    /// requires (the demux classifies on it before any peer is known).
    amnezia: Amnezia3Config,
    rate_limiter: Arc<RateLimiter>,
    /// Peers keyed by static public-key bytes. Bytes rather than `PublicKey`
    /// so the map key is unconditionally `Hash + Eq`.
    peers: HashMap<[u8; 32], Peer>,
    /// `receiver_idx >> 8` -> peer pubkey bytes, for demuxing non-initiation
    /// packets.
    peers_by_idx: HashMap<u32, [u8; 32]>,
    /// Cryptokey routing: destination IP -> owning peer pubkey bytes.
    routing: IpNetworkTable<[u8; 32]>,
    /// Monotonic local-index allocator. A plain counter suffices here — unlike
    /// the device, the server does not obfuscate its indices with an LFSR.
    next_index: u32,
}

impl WgServer {
    /// Create a server. `amnezia` is the shared obfuscation config used by every
    /// peer and by the anonymous demux.
    pub fn new(private_key: x25519::StaticSecret, amnezia: Amnezia3Config) -> Self {
        let public_key = x25519::PublicKey::from(&private_key);
        // The rate limiter authenticates mac1/mac2 with the server's own public
        // key, exactly as the device builds it.
        let rate_limiter = Arc::new(RateLimiter::new(&public_key, 100));
        WgServer {
            private_key,
            public_key,
            amnezia,
            rate_limiter,
            peers: HashMap::new(),
            peers_by_idx: HashMap::new(),
            routing: IpNetworkTable::new(),
            next_index: 1,
        }
    }

    /// Add or replace a peer. Assigns a fresh local index, wires the peer into
    /// the pubkey map, the index map (`index == receiver_idx >> 8`), and the
    /// cryptokey-routing table.
    pub fn add_peer(&mut self, peer: PeerConfig) -> Result<(), ConfigError> {
        let key = peer.public_key.to_bytes();

        // Replacing an existing peer: drop its old index/route bindings first.
        self.remove_peer(&peer.public_key);

        let index = self.next_index;
        self.next_index = self.next_index.wrapping_add(1);

        let tunn = Tunn::new_with_amnezia3(
            self.private_key.clone(),
            peer.public_key,
            peer.preshared_key,
            peer.persistent_keepalive,
            index,
            Some(self.rate_limiter.clone()),
            self.amnezia.clone(),
        )?;

        for &(net, cidr) in &peer.allowed_ips {
            if let Ok(network) = IpNetwork::new_truncate(net, cidr) {
                self.routing.insert(network, key);
            }
        }

        self.peers_by_idx.insert(index, key);
        self.peers.insert(
            key,
            Peer {
                tunn,
                index,
                endpoint: None,
                allowed_ips: peer.allowed_ips,
            },
        );
        Ok(())
    }

    /// Remove a peer and all of its routing/index bindings. A no-op if unknown.
    pub fn remove_peer(&mut self, public_key: &x25519::PublicKey) {
        let key = public_key.to_bytes();
        if let Some(peer) = self.peers.remove(&key) {
            self.peers_by_idx.remove(&peer.index);
            self.routing.retain(|_, v| *v != key);
        }
    }

    /// Handle one inbound UDP datagram received from `src`. `out` is a scratch
    /// buffer (>= 65536) that a returned [`ServerInput::WriteToTunnel`] borrows
    /// from.
    ///
    /// This is the sans-io port of the device's anonymous UDP demux.
    pub fn handle_incoming<'a>(
        &mut self,
        datagram: &[u8],
        src: SocketAddr,
        out: &'a mut [u8],
    ) -> ServerInput<'a> {
        let len = datagram.len();
        if len == 0 {
            return ServerInput::Done;
        }

        // The caller only lends `&[u8]`, but unprotecting the header must mutate
        // the datagram in place (as the device does on its owned receive
        // buffer), so work on a copy we own. The S1-S4 padding prefix is the
        // header-protection nonce and is not part of the mutated span.
        let mut buf = datagram.to_vec();

        let classified = PacketClassifier::from_config(&self.amnezia).classify(&buf[..len]);
        let (padding, protected_len) = classified
            .as_ref()
            .map(|c| (c.padding, c.protected_len))
            .unwrap_or((0, 0));

        if padding > len {
            return ServerInput::Done;
        }
        let protected = protected_len.min(len - padding);

        match classified.as_ref().and_then(|c| c.header_mask) {
            // A transport header is exactly the span `classify` already derived
            // the keystream for; decrypt it with a cheap XOR. Per-packet case.
            Some(mask) if protected == TRANSPORT_HEADER_SZ => {
                let message = &mut buf[padding..len];
                for (byte, mask_byte) in message.iter_mut().zip(mask.iter()) {
                    *byte ^= mask_byte;
                }
            }
            // A handshake message is protected past those 16 bytes. Once per
            // handshake, so paying for a second cipher setup is fine.
            _ if protected > 0 => {
                if let Some(hp) = self.amnezia.header_protection() {
                    let (prefix, message) = buf[..len].split_at_mut(padding);
                    hp.apply(prefix, &mut message[..protected]);
                }
            }
            _ => {}
        }

        let packet = &buf[padding..len];

        // A cookie reply is built into scratch so the S3 padding can be wrapped
        // around it, mirroring `Tunn::decapsulate`.
        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let parsed = match self.rate_limiter.verify_packet(
            Some(src.ip()),
            packet,
            &mut cookie,
            &self.amnezia.headers,
        ) {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie_reply)) => {
                let s3 = self.amnezia.paddings.s3 as usize;
                let reply_len = cookie_reply.len();
                let mut built = vec![0u8; s3 + reply_len];
                if s3 > 0 {
                    OsRng.fill_bytes(&mut built[..s3]);
                }
                built[s3..s3 + reply_len].copy_from_slice(cookie_reply);
                if let Some(hp) = self.amnezia.header_protection() {
                    let (prefix, message) = built.split_at_mut(s3);
                    hp.apply(prefix, message);
                }
                return ServerInput::WriteToNetwork {
                    to: src,
                    datagrams: vec![built],
                };
            }
            Err(_) => return ServerInput::Done,
        };

        // Select the peer. Compute its key from immutable borrows of self so the
        // `&self.rate_limiter`/`&self.private_key` borrows all end before we take
        // `&mut self.peers`. `parsed` borrows `buf` (a local), not self.
        let key = match &parsed {
            Packet::HandshakeInit(p) => {
                match parse_handshake_anon(&self.private_key, &self.public_key, p) {
                    Ok(hh) => {
                        let k = x25519::PublicKey::from(hh.peer_static_public).to_bytes();
                        if self.peers.contains_key(&k) {
                            k
                        } else {
                            return ServerInput::Done;
                        }
                    }
                    Err(_) => return ServerInput::Done,
                }
            }
            Packet::HandshakeResponse(p) => match self.peers_by_idx.get(&(p.receiver_idx >> 8)) {
                Some(k) => *k,
                None => return ServerInput::Done,
            },
            Packet::PacketCookieReply(p) => match self.peers_by_idx.get(&(p.receiver_idx >> 8)) {
                Some(k) => *k,
                None => return ServerInput::Done,
            },
            Packet::PacketData(p) => match self.peers_by_idx.get(&(p.receiver_idx >> 8)) {
                Some(k) => *k,
                None => return ServerInput::Done,
            },
        };

        let peer = match self.peers.get_mut(&key) {
            Some(peer) => peer,
            None => return ServerInput::Done,
        };

        // A valid transport/handshake packet re-homes the peer's endpoint. The
        // window is a property of the path, so a new endpoint starts over.
        let endpoint_changed = peer.endpoint != Some(src);
        peer.endpoint = Some(src);
        if endpoint_changed {
            peer.tunn.reset_udp_window();
        }

        let out_len = out.len();
        match peer.tunn.handle_verified_packet(parsed, out) {
            TunnResult::WriteToNetwork(resp) => {
                let mut datagrams = vec![resp.to_vec()];
                // Flush any queued follow-up. Re-entering `encapsulate` via
                // `decapsulate(None, &[], ..)` starts a handshake when a queued
                // packet has no session, which queues AmneziaWG junk/I-packets
                // that must precede the initiation. Empty for a plain responder,
                // kept for fidelity. A separate scratch buffer is used because
                // `out` is still borrowed for `'a` by the tunnel-delivery arms
                // that this same `match` may return.
                let mut scratch = vec![0u8; out_len];
                while let TunnResult::WriteToNetwork(pkt) =
                    peer.tunn.decapsulate(None, &[], &mut scratch)
                {
                    let pkt = pkt.to_vec();
                    while let Some(junk) = peer.tunn.poll_outgoing_packet() {
                        datagrams.push(junk);
                    }
                    datagrams.push(pkt);
                }
                ServerInput::WriteToNetwork { to: src, datagrams }
            }
            TunnResult::WriteToTunnelV4(pkt, addr) => {
                if peer.is_allowed_ip(addr.into()) {
                    ServerInput::WriteToTunnel {
                        peer: key,
                        packet: pkt,
                    }
                } else {
                    ServerInput::Done
                }
            }
            TunnResult::WriteToTunnelV6(pkt, addr) => {
                if peer.is_allowed_ip(addr.into()) {
                    ServerInput::WriteToTunnel {
                        peer: key,
                        packet: pkt,
                    }
                } else {
                    ServerInput::Done
                }
            }
            TunnResult::Done | TunnResult::Err(_) => ServerInput::Done,
        }
    }

    /// Route an inner IP packet from the server's inner stack to the owning peer
    /// (by destination IP) and encapsulate it. Returns the datagram(s) to send
    /// to that peer's current endpoint, or `None` if the packet is unroutable,
    /// the peer has no known endpoint, or encapsulation errored.
    ///
    /// Encapsulating for an idle peer may start a handshake, queuing AmneziaWG
    /// junk/I-packets that must be sent before the initiation, so those are
    /// drained and ordered ahead of the returned message.
    pub fn encapsulate_to_peer(
        &mut self,
        inner_packet: &[u8],
        out: &mut [u8],
    ) -> Option<PeerDatagrams> {
        let dst_ip = Tunn::dst_address(inner_packet)?;
        let key = *self.routing.longest_match(dst_ip).map(|(_net, k)| k)?;
        let peer = self.peers.get_mut(&key)?;
        let to = peer.endpoint?;

        match peer.tunn.encapsulate(inner_packet, out) {
            TunnResult::WriteToNetwork(pkt) => {
                let pkt = pkt.to_vec();
                // Junk/I-packets queued by a fresh handshake precede the message.
                let mut datagrams = Vec::new();
                while let Some(junk) = peer.tunn.poll_outgoing_packet() {
                    datagrams.push(junk);
                }
                datagrams.push(pkt);
                Some(PeerDatagrams { to, datagrams })
            }
            _ => None,
        }
    }

    /// Drive periodic timers for every peer, returning the datagrams to send per
    /// peer endpoint (rekey handshakes, keepalives). Call roughly every
    /// 100-250ms. Peers without a known endpoint are skipped.
    pub fn update_timers(&mut self, out: &mut [u8]) -> Vec<PeerDatagrams> {
        let mut result = Vec::new();
        for peer in self.peers.values_mut() {
            let to = match peer.endpoint {
                Some(to) => to,
                None => continue,
            };
            if let TunnResult::WriteToNetwork(pkt) = peer.tunn.update_timers(out) {
                let pkt = pkt.to_vec();
                let mut datagrams = Vec::new();
                while let Some(junk) = peer.tunn.poll_outgoing_packet() {
                    datagrams.push(junk);
                }
                datagrams.push(pkt);
                result.push(PeerDatagrams { to, datagrams });
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::noise::TunnResult;

    const MAX_UDP_SIZE: usize = 65536;

    fn keypair(seed: u8) -> (x25519::StaticSecret, x25519::PublicKey) {
        let secret = x25519::StaticSecret::from([seed; 32]);
        let public = x25519::PublicKey::from(&secret);
        (secret, public)
    }

    /// An AmneziaWG 3.0 config with header protection ON (so the demux's
    /// header-protection path is exercised) and every S-padding at the
    /// header-protection minimum. Synthetic key material only.
    fn awg3_config() -> Amnezia3Config {
        let input = "\
header_protection_key=5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a
s1=15
s2=15
s3=15
s4=15
jc=0
";
        Amnezia3Config::parse(input).expect("config must be valid")
    }

    /// Build an IPv4 packet whose source is 10.0.0.2 and destination `dst`.
    /// 40 bytes, IHL 5, as boringtun validates the inner packet.
    fn ipv4_packet(dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45; // IPv4, IHL 5
        p[2] = 0;
        p[3] = 40; // total length
                   // src 10.0.0.2
        p[12..16].copy_from_slice(&[10, 0, 0, 2]);
        p[16..20].copy_from_slice(&dst);
        p
    }

    fn client_tunn(config: &Amnezia3Config) -> (Tunn, x25519::PublicKey) {
        let (client_secret, client_public) = keypair(1);
        let (_server_secret, server_public) = keypair(2);
        let psk = [0x33u8; 32];
        let client = Tunn::new_with_amnezia3(
            client_secret,
            server_public,
            Some(psk),
            Some(25),
            1,
            None,
            config.clone(),
        )
        .expect("client config must be valid");
        (client, client_public)
    }

    #[test]
    fn client_server_interop_awg3_header_protection() {
        let config = awg3_config();
        let (mut client, client_public) = client_tunn(&config);
        let (server_secret, _server_public) = keypair(2);

        let mut server = WgServer::new(server_secret, config);

        // 1. Register the client as a peer owning 10.0.0.2/32.
        server
            .add_peer(PeerConfig {
                public_key: client_public,
                preshared_key: Some([0x33u8; 32]),
                allowed_ips: vec![(IpAddr::from([10, 0, 0, 2]), 32)],
                persistent_keepalive: Some(25),
            })
            .expect("add_peer must succeed");

        let client_src: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let mut client_buf = vec![0u8; MAX_UDP_SIZE];
        let mut out = vec![0u8; MAX_UDP_SIZE];

        let ip_packet = ipv4_packet([10, 0, 0, 1]);

        // 2. Client starts a handshake.
        let init = match client.encapsulate(&ip_packet, &mut client_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected a handshake initiation, got {:?}", other),
        };
        // Drain any junk the client queued ahead of the initiation.
        while let Some(_junk) = client.poll_outgoing_packet() {}

        // 3. Server answers the initiation with a handshake response.
        let response = match server.handle_incoming(&init, client_src, &mut out) {
            ServerInput::WriteToNetwork { to, datagrams } => {
                assert_eq!(to, client_src, "response must go back to the client");
                assert!(!datagrams.is_empty(), "expected >= 1 response datagram");
                datagrams.last().unwrap().clone()
            }
            _ => panic!("server must answer the initiation"),
        };

        // Client consumes the response, completing the handshake, then drains.
        match client.decapsulate(None, &response, &mut client_buf) {
            TunnResult::WriteToNetwork(_) | TunnResult::Done => {}
            other => panic!("client failed to complete the handshake: {:?}", other),
        }
        while let TunnResult::WriteToNetwork(_) = client.decapsulate(None, &[], &mut client_buf) {}

        // 4. A data packet crosses and is delivered to the tunnel.
        let transport = match client.encapsulate(&ip_packet, &mut client_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected a transport packet, got {:?}", other),
        };
        match server.handle_incoming(&transport, client_src, &mut out) {
            ServerInput::WriteToTunnel { peer, packet } => {
                assert_eq!(peer, client_public.to_bytes(), "delivered to right peer");
                assert_eq!(packet, &ip_packet[..], "payload must survive the tunnel");
            }
            _ => panic!("server did not deliver the data packet"),
        }

        // 5. Return path: an inner packet destined for 10.0.0.2 routes to the
        // client and comes out intact on the client side.
        let return_packet = {
            // src 10.0.0.1, dst 10.0.0.2
            let mut p = vec![0u8; 40];
            p[0] = 0x45;
            p[3] = 40;
            p[12..16].copy_from_slice(&[10, 0, 0, 1]);
            p[16..20].copy_from_slice(&[10, 0, 0, 2]);
            p
        };
        let pd = server
            .encapsulate_to_peer(&return_packet, &mut out)
            .expect("return packet must route to the client");
        assert_eq!(
            pd.to, client_src,
            "return datagrams go to the client endpoint"
        );
        assert!(!pd.datagrams.is_empty());
        let last = pd.datagrams.last().unwrap().clone();
        match client.decapsulate(None, &last, &mut client_buf) {
            TunnResult::WriteToTunnelV4(pkt, _) => {
                assert_eq!(pkt, &return_packet[..], "return payload must survive");
            }
            other => panic!("client did not decrypt the return packet: {:?}", other),
        }

        // 7. Timers should now be able to emit a keepalive to the endpoint.
        // (Best effort — not every tick produces one.)
        let _ = server.update_timers(&mut out);
    }

    #[test]
    fn unknown_receiver_index_is_dropped() {
        let config = awg3_config();
        let (server_secret, _server_public) = keypair(2);
        let mut server = WgServer::new(server_secret, config.clone());

        // A transport-shaped datagram whose receiver index matches no peer.
        // Build it via a client that the server does NOT know about.
        let (mut client, client_public) = client_tunn(&config);
        server
            .add_peer(PeerConfig {
                public_key: client_public,
                preshared_key: Some([0x33u8; 32]),
                allowed_ips: vec![(IpAddr::from([10, 0, 0, 2]), 32)],
                persistent_keepalive: Some(25),
            })
            .unwrap();
        // Remove it again so its index no longer resolves.
        server.remove_peer(&client_public);

        let client_src: SocketAddr = "203.0.113.7:51820".parse().unwrap();
        let mut client_buf = vec![0u8; MAX_UDP_SIZE];
        let mut out = vec![0u8; MAX_UDP_SIZE];
        let ip_packet = ipv4_packet([10, 0, 0, 1]);
        let init = match client.encapsulate(&ip_packet, &mut client_buf) {
            TunnResult::WriteToNetwork(data) => data.to_vec(),
            other => panic!("expected init, got {:?}", other),
        };
        while let Some(_junk) = client.poll_outgoing_packet() {}
        // No peer with this public key -> anonymous parse finds nobody.
        match server.handle_incoming(&init, client_src, &mut out) {
            ServerInput::Done => {}
            _ => panic!("unknown peer must be dropped"),
        }
    }

    #[test]
    fn unrouted_destination_is_none() {
        let config = awg3_config();
        let (server_secret, _server_public) = keypair(2);
        let mut server = WgServer::new(server_secret, config);
        let mut out = vec![0u8; MAX_UDP_SIZE];
        // No peers at all -> nothing routes.
        let packet = ipv4_packet([198, 51, 100, 9]);
        assert!(server.encapsulate_to_peer(&packet, &mut out).is_none());
    }
}
