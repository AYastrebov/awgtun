// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use parking_lot::RwLock;
use socket2::{Domain, Protocol, Type};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

use crate::amnezia::U32Range;
use crate::device::{AllowedIps, Error};
use crate::noise::{Tunn, TunnResult};

#[derive(Default, Debug)]
pub struct Endpoint {
    pub addr: Option<SocketAddr>,
    pub conn: Option<socket2::Socket>,
}

pub struct Peer {
    /// The associated tunnel struct
    pub(crate) tunnel: Tunn,
    /// The index the tunnel uses
    index: u32,
    endpoint: RwLock<Endpoint>,
    allowed_ips: AllowedIps<()>,
    preshared_key: Option<[u8; 32]>,
    /// AWG 3.0 `persistent_keepalive_interval` range, when configured as one.
    /// Kept so `get=1` reports the configured range rather than the single
    /// interval that happens to be armed right now.
    keepalive_range: Option<U32Range>,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct AllowedIP {
    pub addr: IpAddr,
    pub cidr: u8,
}

impl FromStr for AllowedIP {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ip: Vec<&str> = s.split('/').collect();
        if ip.len() != 2 {
            return Err("Invalid IP format".to_owned());
        }

        let (addr, cidr) = (ip[0].parse::<IpAddr>(), ip[1].parse::<u8>());
        match (addr, cidr) {
            (Ok(addr @ IpAddr::V4(_)), Ok(cidr)) if cidr <= 32 => Ok(AllowedIP { addr, cidr }),
            (Ok(addr @ IpAddr::V6(_)), Ok(cidr)) if cidr <= 128 => Ok(AllowedIP { addr, cidr }),
            _ => Err("Invalid IP format".to_owned()),
        }
    }
}

impl Peer {
    pub fn new(
        tunnel: Tunn,
        index: u32,
        endpoint: Option<SocketAddr>,
        allowed_ips: &[AllowedIP],
        preshared_key: Option<[u8; 32]>,
        keepalive_range: Option<U32Range>,
    ) -> Peer {
        Peer {
            tunnel,
            index,
            endpoint: RwLock::new(Endpoint {
                addr: endpoint,
                conn: None,
            }),
            allowed_ips: allowed_ips.iter().map(|ip| (ip, ())).collect(),
            preshared_key,
            keepalive_range,
        }
    }

    pub fn update_timers<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        self.tunnel.update_timers(dst)
    }

    /// Take the AmneziaWG datagrams queued ahead of a handshake initiation:
    /// the I1-I5 init packets followed by `Jc` junk packets.
    ///
    /// These must be sent *before* the handshake initiation that queued them,
    /// so callers drain this after any call that can start a handshake and
    /// send the result first. Returns an empty vector for a standard WireGuard
    /// peer, which is the common case.
    pub fn drain_outgoing(&mut self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        while let Some(packet) = self.tunnel.poll_outgoing_packet() {
            packets.push(packet);
        }
        packets
    }

    pub fn endpoint(&self) -> parking_lot::RwLockReadGuard<'_, Endpoint> {
        self.endpoint.read()
    }

    pub(crate) fn endpoint_mut(&self) -> parking_lot::RwLockWriteGuard<'_, Endpoint> {
        self.endpoint.write()
    }

    pub fn shutdown_endpoint(&self) {
        if let Some(conn) = self.endpoint.write().conn.take() {
            tracing::info!("Disconnecting from endpoint");
            conn.shutdown(Shutdown::Both).unwrap();
        }
    }

    /// Point this peer at `addr`, returning whether that was a change.
    ///
    /// The caller uses the return value to reset the AWG 3.1 UDP window, which
    /// lives on the tunnel: a window learned from one path should not size the
    /// trailers sent down the next one. That cannot happen here because the
    /// tunnel is behind the peer's own lock and this takes `&self`.
    pub fn set_endpoint(&self, addr: SocketAddr) -> bool {
        let mut endpoint = self.endpoint.write();
        if endpoint.addr != Some(addr) {
            // We only need to update the endpoint if it differs from the current one
            if let Some(conn) = endpoint.conn.take() {
                conn.shutdown(Shutdown::Both).unwrap();
            }

            endpoint.addr = Some(addr);
            return true;
        }
        false
    }

    pub fn connect_endpoint(
        &self,
        port: u16,
        fwmark: Option<u32>,
    ) -> Result<socket2::Socket, Error> {
        let mut endpoint = self.endpoint.write();

        if endpoint.conn.is_some() {
            return Err(Error::Connect("Connected".to_owned()));
        }

        let addr = endpoint
            .addr
            .expect("Attempt to connect to undefined endpoint");

        let udp_conn =
            socket2::Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
        udp_conn.set_reuse_address(true)?;
        let bind_addr = if addr.is_ipv4() {
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port).into()
        } else {
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0).into()
        };
        udp_conn.bind(&bind_addr)?;
        udp_conn.connect(&addr.into())?;
        udp_conn.set_nonblocking(true)?;

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        if let Some(fwmark) = fwmark {
            udp_conn.set_mark(fwmark)?;
        }
        // `SO_MARK` is a Linux-family option. Elsewhere the argument is accepted
        // and ignored, so callers need no `cfg` of their own.
        #[cfg(not(any(target_os = "android", target_os = "fuchsia", target_os = "linux")))]
        let _ = fwmark;

        tracing::info!(
            message="Connected endpoint",
            port=port,
            endpoint=?endpoint.addr.unwrap()
        );

        endpoint.conn = Some(udp_conn.try_clone().unwrap());

        Ok(udp_conn)
    }

    pub fn is_allowed_ip<I: Into<IpAddr>>(&self, addr: I) -> bool {
        self.allowed_ips.find(addr.into()).is_some()
    }

    pub fn allowed_ips(&self) -> impl Iterator<Item = (IpAddr, u8)> + '_ {
        self.allowed_ips.iter().map(|(_, ip, cidr)| (ip, cidr))
    }

    pub fn time_since_last_handshake(&self) -> Option<std::time::Duration> {
        self.tunnel.time_since_last_handshake()
    }

    pub fn persistent_keepalive(&self) -> Option<u16> {
        self.tunnel.persistent_keepalive()
    }

    /// The configured AWG 3.0 keepalive range, if the interval was set as one.
    pub fn keepalive_range(&self) -> Option<U32Range> {
        self.keepalive_range
    }

    pub fn preshared_key(&self) -> Option<&[u8; 32]> {
        self.preshared_key.as_ref()
    }

    /// Replace this peer's tunnel, adopting the new receiving index.
    ///
    /// Used when the device's AmneziaWG configuration changes: a `Tunn`
    /// captures that configuration at construction, so the peers have to be
    /// rebuilt from it. The caller owns `peers_by_idx` and must re-key this
    /// peer there, reading [`Peer::index`] before the swap.
    pub fn set_tunnel(&mut self, tunnel: Tunn, index: u32) {
        self.tunnel = tunnel;
        self.index = index;
    }

    pub fn index(&self) -> u32 {
        self.index
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amnezia::{Amnezia3Config, CpsChain, HeaderRange, JunkConfig, PaddingConfig};
    use crate::x25519;
    use rand_core::OsRng;

    fn tunn(config: Amnezia3Config, index: u32) -> Tunn {
        let secret = x25519::StaticSecret::random_from_rng(OsRng);
        let peer = x25519::PublicKey::from(&x25519::StaticSecret::random_from_rng(OsRng));
        Tunn::new_with_amnezia3(secret, peer, None, None, index, None, config)
            .expect("valid tunnel config")
    }

    fn peer(tunnel: Tunn, index: u32) -> Peer {
        Peer::new(tunnel, index, None, &[], None, None)
    }

    /// An AmneziaWG config with everything that queues a pre-handshake
    /// datagram: two I-packets and three junk packets.
    fn awg_with_pre_handshake_traffic() -> Amnezia3Config {
        let mut config = Amnezia3Config::wireguard_compatible();
        config.paddings = PaddingConfig::new(16, 16, 16, 16).unwrap();
        config.headers = crate::amnezia::HeaderConfig::new(
            HeaderRange::new(1000, 1099).unwrap(),
            HeaderRange::new(2000, 2099).unwrap(),
            HeaderRange::new(3000, 3099).unwrap(),
            HeaderRange::new(4000, 4099).unwrap(),
        )
        .unwrap();
        config.junk = JunkConfig::new(3, 64, 128).unwrap();
        config.init_packets.i1 = Some(CpsChain::parse("<b 0xc0ffee>").unwrap());
        config.init_packets.i2 = Some(CpsChain::parse("<r 20>").unwrap());
        config
    }

    /// A plain WireGuard peer queues nothing, so the drain the device performs
    /// on every outbound packet has to be free of surprises — it runs on the
    /// hot path whether or not AmneziaWG is configured.
    #[test]
    fn drain_is_empty_for_a_wireguard_peer() {
        let mut p = peer(tunn(Amnezia3Config::wireguard_compatible(), 1), 1);
        let mut dst = vec![0u8; 2048];

        assert!(p.drain_outgoing().is_empty(), "nothing queued before use");
        assert!(matches!(
            p.tunnel.format_handshake_initiation(&mut dst, true),
            TunnResult::WriteToNetwork(_)
        ));
        assert!(
            p.drain_outgoing().is_empty(),
            "a WireGuard handshake queues no side traffic"
        );
    }

    /// I-packets first, then junk — the order the peer expects on the wire. The
    /// device sends the drained vector in order, ahead of the initiation, so a
    /// reordering here is a reordering on the wire.
    #[test]
    fn drain_yields_i_packets_then_junk_in_order() {
        let config = awg_with_pre_handshake_traffic();
        let mut p = peer(tunn(config, 1), 1);
        let mut dst = vec![0u8; 2048];

        assert!(matches!(
            p.tunnel.format_handshake_initiation(&mut dst, true),
            TunnResult::WriteToNetwork(_)
        ));

        let queued = p.drain_outgoing();
        assert_eq!(queued.len(), 5, "two I-packets plus three junk packets");

        // I1 is a fixed 3-byte chain, I2 is 20 random bytes; both are exact.
        assert_eq!(queued[0], vec![0xc0, 0xff, 0xee], "I1 is byte-exact");
        assert_eq!(queued[1].len(), 20, "I2 is <r 20>");
        // The junk that follows is drawn from [Jmin, Jmax).
        for junk in &queued[2..] {
            assert!(
                (64..128).contains(&junk.len()),
                "junk size {} outside [64, 128)",
                junk.len()
            );
        }
    }

    /// Draining is destructive: the device calls it once per initiation and
    /// sends what it gets. If a second call returned the same datagrams they
    /// would go out twice, and if the queue were never emptied it would grow
    /// for the lifetime of the peer.
    #[test]
    fn drain_empties_the_queue() {
        let config = awg_with_pre_handshake_traffic();
        let mut p = peer(tunn(config, 1), 1);
        let mut dst = vec![0u8; 2048];

        p.tunnel.format_handshake_initiation(&mut dst, true);
        assert_eq!(p.drain_outgoing().len(), 5);
        assert!(
            p.drain_outgoing().is_empty(),
            "the second drain must come back empty"
        );

        // A retry queues a fresh batch, because every attempt carries its own
        // I-packets and junk.
        p.tunnel.format_handshake_initiation(&mut dst, true);
        assert_eq!(p.drain_outgoing().len(), 5, "a retry re-queues");
    }

    /// `set_tunnel` is how a device-wide AmneziaWG change reaches a live peer.
    /// It has to swap both the tunnel and the index, because the device re-keys
    /// `peers_by_idx` from `index()` around the call.
    #[test]
    fn set_tunnel_adopts_the_new_index() {
        let mut p = peer(tunn(Amnezia3Config::wireguard_compatible(), 7), 7);
        assert_eq!(p.index(), 7);

        let config = awg_with_pre_handshake_traffic();
        p.set_tunnel(tunn(config, 9), 9);
        assert_eq!(p.index(), 9, "the index moves with the tunnel");

        // The replacement really is the new configuration: it queues the
        // pre-handshake traffic the old one did not.
        let mut dst = vec![0u8; 2048];
        p.tunnel.format_handshake_initiation(&mut dst, true);
        assert_eq!(p.drain_outgoing().len(), 5);
    }

    /// `get=1` reports the configured range rather than the interval that
    /// happens to be armed, so the peer has to keep it.
    #[test]
    fn keepalive_range_round_trips() {
        let range = U32Range::new(20, 30).unwrap();
        let p = Peer::new(
            tunn(Amnezia3Config::wireguard_compatible(), 1),
            1,
            None,
            &[],
            None,
            Some(range),
        );
        assert_eq!(p.keepalive_range(), Some(range));

        let p = peer(tunn(Amnezia3Config::wireguard_compatible(), 2), 2);
        assert_eq!(p.keepalive_range(), None);
    }
}
