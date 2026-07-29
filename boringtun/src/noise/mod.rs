// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod errors;
pub mod handshake;
pub mod rate_limiter;

mod session;
mod timers;

use crate::amnezia::{
    Amnezia2Config, Amnezia3Config, ConfigError, HeaderConfig, HeaderProtection, InitPacketConfig,
    JunkConfig, OsRandom, PaddingConfig, U32Range,
};
use crate::amnezia::RandomSource as _;
use crate::noise::errors::WireGuardError;
use crate::noise::handshake::Handshake;
use crate::noise::rate_limiter::RateLimiter;
use crate::noise::timers::{TimerName, Timers};
use crate::x25519;

use std::collections::VecDeque;
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

/// The default value to use for rate limiting, when no other rate limiter is defined
const PEER_HANDSHAKE_RATE_LIMIT: u64 = 10;

const IPV4_MIN_HEADER_SIZE: usize = 20;
const IPV4_LEN_OFF: usize = 2;
const IPV4_SRC_IP_OFF: usize = 12;
const IPV4_DST_IP_OFF: usize = 16;
const IPV4_IP_SZ: usize = 4;

const IPV6_MIN_HEADER_SIZE: usize = 40;
const IPV6_LEN_OFF: usize = 4;
const IPV6_SRC_IP_OFF: usize = 8;
const IPV6_DST_IP_OFF: usize = 24;
const IPV6_IP_SZ: usize = 16;

const IP_LEN_SZ: usize = 2;

const MAX_QUEUE_DEPTH: usize = 256;
/// number of sessions in the ring, better keep a PoT
const N_SESSIONS: usize = 8;

#[derive(Debug)]
pub enum TunnResult<'a> {
    Done,
    Err(WireGuardError),
    WriteToNetwork(&'a mut [u8]),
    WriteToTunnelV4(&'a mut [u8], Ipv4Addr),
    WriteToTunnelV6(&'a mut [u8], Ipv6Addr),
}

impl<'a> From<WireGuardError> for TunnResult<'a> {
    fn from(err: WireGuardError) -> TunnResult<'a> {
        TunnResult::Err(err)
    }
}

/// Tunnel represents a point-to-point WireGuard connection
pub struct Tunn {
    /// The handshake currently in progress
    handshake: handshake::Handshake,
    /// The N_SESSIONS most recent sessions, index is session id modulo N_SESSIONS
    sessions: [Option<session::Session>; N_SESSIONS],
    /// Index of most recently used session
    current: usize,
    /// Queue to store blocked packets
    packet_queue: VecDeque<Vec<u8>>,
    /// Keeps tabs on the expiring timers
    timers: timers::Timers,
    tx_bytes: usize,
    rx_bytes: usize,
    rate_limiter: Arc<RateLimiter>,
    /// AmneziaWG dynamic header configuration
    header_config: HeaderConfig,
    /// AmneziaWG padding configuration
    padding_config: PaddingConfig,
    /// AmneziaWG junk configuration
    junk_config: JunkConfig,
    /// AmneziaWG init packet (CPS) configuration
    init_packet_config: InitPacketConfig,
    /// AWG 3.0 header protection (ChaCha20 over the WG message header)
    header_protection: Option<HeaderProtection>,
    /// AWG 3.0 content padding addition range for transport packets
    content_padding: Option<U32Range>,
    /// Outer MTU used to clamp content padding
    mtu: u32,
    /// Queue for pre-handshake datagrams (I-packets, junk) that need to be
    /// sent before the actual handshake initiation.
    network_outgoing: VecDeque<Vec<u8>>,
}

type MessageType = u32;
const HANDSHAKE_INIT: MessageType = 1;
const HANDSHAKE_RESP: MessageType = 2;
const COOKIE_REPLY: MessageType = 3;
const DATA: MessageType = 4;

const HANDSHAKE_INIT_SZ: usize = 148;
const HANDSHAKE_RESP_SZ: usize = 92;
const COOKIE_REPLY_SZ: usize = 64;
const DATA_OVERHEAD_SZ: usize = 32;
const TRANSPORT_HEADER_SZ: usize = 16; // type(4) + receiver(4) + counter(8)
/// Wire size of an unpadded keepalive: transport header + AEAD tag.
/// Matches amneziawg-go's `MessageKeepaliveSize`.
const KEEPALIVE_SZ: usize = DATA_OVERHEAD_SZ;

#[derive(Debug)]
pub struct HandshakeInit<'a> {
    sender_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_static: &'a [u8],
    encrypted_timestamp: &'a [u8],
}

#[derive(Debug)]
pub struct HandshakeResponse<'a> {
    sender_idx: u32,
    pub receiver_idx: u32,
    unencrypted_ephemeral: &'a [u8; 32],
    encrypted_nothing: &'a [u8],
}

#[derive(Debug)]
pub struct PacketCookieReply<'a> {
    pub receiver_idx: u32,
    nonce: &'a [u8],
    encrypted_cookie: &'a [u8],
}

#[derive(Debug)]
pub struct PacketData<'a> {
    pub receiver_idx: u32,
    counter: u64,
    encrypted_encapsulated_packet: &'a [u8],
}

/// Describes a packet from network
#[derive(Debug)]
pub enum Packet<'a> {
    HandshakeInit(HandshakeInit<'a>),
    HandshakeResponse(HandshakeResponse<'a>),
    PacketCookieReply(PacketCookieReply<'a>),
    PacketData(PacketData<'a>),
}

impl Tunn {
    #[inline(always)]
    pub fn parse_incoming_packet(src: &[u8]) -> Result<Packet, WireGuardError> {
        Self::parse_incoming_packet_config(src, &HeaderConfig::default())
    }

    #[inline(always)]
    pub fn parse_incoming_packet_config<'a>(
        src: &'a [u8],
        header_config: &HeaderConfig,
    ) -> Result<Packet<'a>, WireGuardError> {
        if src.len() < 4 {
            return Err(WireGuardError::InvalidPacket);
        }

        // Read the type field — may be a dynamic AmneziaWG header value
        let packet_type = u32::from_le_bytes(src[0..4].try_into().unwrap());

        // Classify by checking against configured header ranges
        if header_config.init.contains(packet_type) && src.len() == HANDSHAKE_INIT_SZ {
            Ok(Packet::HandshakeInit(HandshakeInit {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[8..40])
                    .expect("length already checked above"),
                encrypted_static: &src[40..88],
                encrypted_timestamp: &src[88..116],
            }))
        } else if header_config.response.contains(packet_type) && src.len() == HANDSHAKE_RESP_SZ {
            Ok(Packet::HandshakeResponse(HandshakeResponse {
                sender_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                receiver_idx: u32::from_le_bytes(src[8..12].try_into().unwrap()),
                unencrypted_ephemeral: <&[u8; 32] as TryFrom<&[u8]>>::try_from(&src[12..44])
                    .expect("length already checked above"),
                encrypted_nothing: &src[44..60],
            }))
        } else if header_config.cookie.contains(packet_type) && src.len() == COOKIE_REPLY_SZ {
            Ok(Packet::PacketCookieReply(PacketCookieReply {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                nonce: &src[8..32],
                encrypted_cookie: &src[32..64],
            }))
        } else if header_config.transport.contains(packet_type) && src.len() >= DATA_OVERHEAD_SZ {
            Ok(Packet::PacketData(PacketData {
                receiver_idx: u32::from_le_bytes(src[4..8].try_into().unwrap()),
                counter: u64::from_le_bytes(src[8..16].try_into().unwrap()),
                encrypted_encapsulated_packet: &src[16..],
            }))
        } else {
            Err(WireGuardError::InvalidPacket)
        }
    }

    pub fn is_expired(&self) -> bool {
        self.handshake.is_expired()
    }

    pub fn dst_address(packet: &[u8]) -> Option<IpAddr> {
        if packet.is_empty() {
            return None;
        }

        match packet[0] >> 4 {
            4 if packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_DST_IP_OFF..IPV4_DST_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            6 if packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_DST_IP_OFF..IPV6_DST_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                Some(IpAddr::from(addr_bytes))
            }
            _ => None,
        }
    }

    /// Create a new tunnel using own private key and the peer public key
    pub fn new(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) -> Self {
        Self::new_with_amnezia(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            rate_limiter,
            Amnezia2Config::default(),
        )
        .expect("default Amnezia2Config is always valid")
    }

    /// Create a new tunnel with AmneziaWG 2.0 configuration.
    ///
    /// Returns `Err(ConfigError)` if the AmneziaWG config is invalid
    /// (e.g. overlapping header ranges, padding out of bounds).
    pub fn new_with_amnezia(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        amnezia: Amnezia2Config,
    ) -> Result<Self, ConfigError> {
        Self::new_with_amnezia3(
            static_private,
            peer_static_public,
            preshared_key,
            persistent_keepalive,
            index,
            rate_limiter,
            Amnezia3Config::from_amnezia2(amnezia),
        )
    }

    /// Create a new tunnel with AmneziaWG 3.0 configuration.
    ///
    /// Returns `Err(ConfigError)` if the AmneziaWG config is invalid
    /// (e.g. overlapping header ranges, padding out of bounds, header
    /// protection enabled with S1-S4 < 12).
    pub fn new_with_amnezia3(
        static_private: x25519::StaticSecret,
        peer_static_public: x25519::PublicKey,
        preshared_key: Option<[u8; 32]>,
        persistent_keepalive: Option<u16>,
        index: u32,
        rate_limiter: Option<Arc<RateLimiter>>,
        amnezia: Amnezia3Config,
    ) -> Result<Self, ConfigError> {
        amnezia.validate()?;
        let static_public = x25519::PublicKey::from(&static_private);
        // Computed before the struct literal because `init_packets` is not Copy
        let header_protection = amnezia.header_protection();

        Ok(Tunn {
            handshake: Handshake::new(
                static_private,
                static_public,
                peer_static_public,
                index << 8,
                preshared_key,
            ),
            sessions: Default::default(),
            current: Default::default(),
            tx_bytes: Default::default(),
            rx_bytes: Default::default(),

            packet_queue: VecDeque::new(),
            timers: Timers::new(
                persistent_keepalive,
                rate_limiter.is_none(),
                amnezia.timing_ranges,
            ),

            rate_limiter: rate_limiter.unwrap_or_else(|| {
                Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
            }),
            header_config: amnezia.headers,
            padding_config: amnezia.paddings,
            junk_config: amnezia.junk,
            init_packet_config: amnezia.init_packets,
            header_protection,
            content_padding: amnezia.content_padding_addition,
            mtu: amnezia.mtu,
            network_outgoing: VecDeque::new(),
        })
    }

    /// Update the private key and clear existing sessions
    pub fn set_static_private(
        &mut self,
        static_private: x25519::StaticSecret,
        static_public: x25519::PublicKey,
        rate_limiter: Option<Arc<RateLimiter>>,
    ) {
        self.timers.should_reset_rr = rate_limiter.is_none();
        self.rate_limiter = rate_limiter.unwrap_or_else(|| {
            Arc::new(RateLimiter::new(&static_public, PEER_HANDSHAKE_RATE_LIMIT))
        });
        self.handshake
            .set_static_private(static_private, static_public);
        for s in &mut self.sessions {
            *s = None;
        }
    }

    /// Encapsulate a single packet from the tunnel interface.
    /// Returns TunnResult.
    ///
    /// # Panics
    /// Panics if dst buffer is too small.
    /// Size of dst should be at least `src.len() + 32 + S4` for data packets,
    /// and no less than `148 + S1` bytes (to hold a padded handshake initiation).
    /// Keepalive packets also occupy `S4` bytes of padding (amneziawg-go
    /// f4f4c99). With AWG 3.0 header protection enabled, the first 16 bytes
    /// after the padding prefix are ChaCha20-encrypted. With AWG 3.0 content
    /// padding configured, dst must additionally hold up to the range's upper
    /// bound in appended zero bytes.
    /// When AmneziaWG is disabled (default config), S1 and S4 are both 0.
    pub fn encapsulate<'a>(&mut self, src: &[u8], dst: &'a mut [u8]) -> TunnResult<'a> {
        let current = self.current;
        if let Some(ref session) = self.sessions[current % N_SESSIONS] {
            // Send the packet using an established session
            let content_padding = self.content_padding_addition(src.len());
            let packet = self.format_transport_packet(session, src, content_padding, dst);
            // amneziawg-go classifies an outbound packet as "data sent" by wire
            // size (`len(elem.packet) != MessageKeepaliveSize`), so an S4 prefix
            // makes even an empty packet count as data. Match that rule rather
            // than testing the payload.
            let is_keepalive = packet.len() == KEEPALIVE_SZ;
            self.timer_tick(TimerName::TimeLastPacketSent);
            if !is_keepalive {
                self.timer_tick(TimerName::TimeLastDataPacketSent);
            }
            self.tx_bytes += src.len();
            return TunnResult::WriteToNetwork(packet);
        }

        // If there is no session, queue the packet for future retry
        self.queue_packet(src);
        // Initiate a new handshake if none is in progress
        self.format_handshake_initiation(dst, false)
    }

    /// AWG 3.0 content padding addition: a random pick from the configured
    /// range, clamped to the space left in the last MTU segment. Mirrors
    /// amneziawg-go's `randomPaddingAddition`; boringtun never pads content to a
    /// multiple of 16, so the addition applies as-is.
    fn content_padding_addition(&self, packet_size: usize) -> usize {
        let range = match self.content_padding {
            Some(range) => range,
            None => return 0,
        };
        let mut add = range.generate(&mut OsRandom) as usize;
        let mtu = self.mtu as usize;
        if mtu != 0 {
            let last_unit = if packet_size > mtu {
                packet_size % mtu
            } else {
                packet_size
            };
            add = add.min(mtu - last_unit);
        }
        add
    }

    /// Format a transport (data or keepalive) packet: dynamic H4 header,
    /// S4 random prefix (applied to keepalives as well, matching
    /// amneziawg-go f4f4c99), AWG 3.0 content padding inside the AEAD envelope,
    /// and AWG 3.0 header protection over the 16-byte transport header when
    /// enabled.
    fn format_transport_packet<'a>(
        &self,
        session: &session::Session,
        src: &[u8],
        content_padding: usize,
        dst: &'a mut [u8],
    ) -> &'a mut [u8] {
        let transport_type = self.header_config.transport.generate(&mut OsRandom);
        let s4 = self.padding_config.s4 as usize;

        // Write WG packet at offset s4, then fill the prefix with random padding
        let packet =
            session.format_packet_data(src, &mut dst[s4..], transport_type, content_padding);
        let packet_len = packet.len();
        if s4 > 0 {
            OsRandom.fill_bytes(&mut dst[..s4]);
        }
        if let Some(hp) = self.header_protection {
            let (prefix, message) = dst.split_at_mut(s4);
            hp.apply(prefix, &mut message[..TRANSPORT_HEADER_SZ]);
        }
        &mut dst[..s4 + packet_len]
    }

    /// Receives a UDP datagram from the network and parses it.
    /// Returns TunnResult.
    ///
    /// If the result is of type TunnResult::WriteToNetwork, should repeat the call with empty datagram,
    /// until TunnResult::Done is returned. If batch processing packets, it is OK to defer until last
    /// packet is processed.
    pub fn decapsulate<'a>(
        &mut self,
        src_addr: Option<IpAddr>,
        datagram: &[u8],
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        if datagram.is_empty() {
            // Indicates a repeated call
            return self.send_queued_packet(dst);
        }

        // Strip AmneziaWG padding before parsing; with AWG 3.0 header
        // protection, decrypt the protected region first.
        let (padding, protected_len) = self.determine_padding(datagram).unwrap_or((0, 0));
        let payload = &datagram[padding..];

        // Transport packets protect only the 16-byte header, so the message is
        // never contiguous after decryption. Decrypt the header on the stack and
        // assemble the packet directly — `verify_packet` neither MACs nor rate
        // limits transport packets, and `determine_padding` already matched the
        // type against H4 and checked the minimum size.
        if let Some(hp) = self.header_protection {
            if protected_len == TRANSPORT_HEADER_SZ {
                let mut header = [0u8; TRANSPORT_HEADER_SZ];
                header.copy_from_slice(&payload[..TRANSPORT_HEADER_SZ]);
                hp.apply(&datagram[..padding], &mut header);
                let packet = Packet::PacketData(PacketData {
                    receiver_idx: u32::from_le_bytes(
                        header[4..8].try_into().expect("fixed 16-byte header"),
                    ),
                    counter: u64::from_le_bytes(
                        header[8..16].try_into().expect("fixed 16-byte header"),
                    ),
                    encrypted_encapsulated_packet: &payload[TRANSPORT_HEADER_SZ..],
                });
                return self.handle_verified_packet(packet, dst);
            }
        }

        // Handshake, response and cookie messages are protected in full and have
        // a fixed size bounded by `HANDSHAKE_INIT_SZ`, so a stack buffer holds
        // the decrypted message without allocating.
        let mut decrypted = [0u8; HANDSHAKE_INIT_SZ];
        let stripped: &[u8] = match self.header_protection {
            Some(hp) if protected_len > 0 => {
                let protected = protected_len.min(payload.len());
                decrypted[..protected].copy_from_slice(&payload[..protected]);
                hp.apply(&datagram[..padding], &mut decrypted[..protected]);
                &decrypted[..protected]
            }
            _ => payload,
        };

        let mut cookie = [0u8; COOKIE_REPLY_SZ];
        let packet = match self
            .rate_limiter
            .verify_packet(src_addr, stripped, &mut cookie, &self.header_config)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(cookie)) => {
                // Add S3 padding to cookie reply
                let s3 = self.padding_config.s3 as usize;
                if s3 > 0 {
                    OsRandom.fill_bytes(&mut dst[..s3]);
                }
                dst[s3..s3 + cookie.len()].copy_from_slice(cookie);
                if let Some(hp) = self.header_protection {
                    let (prefix, message) = dst.split_at_mut(s3);
                    hp.apply(prefix, &mut message[..cookie.len()]);
                }
                return TunnResult::WriteToNetwork(&mut dst[..s3 + cookie.len()]);
            }
            Err(TunnResult::Err(e)) => return TunnResult::Err(e),
            _ => unreachable!(),
        };

        self.handle_verified_packet(packet, dst)
    }

    pub(crate) fn handle_verified_packet<'a>(
        &mut self,
        packet: Packet,
        dst: &'a mut [u8],
    ) -> TunnResult<'a> {
        match packet {
            Packet::HandshakeInit(p) => self.handle_handshake_init(p, dst),
            Packet::HandshakeResponse(p) => self.handle_handshake_response(p, dst),
            Packet::PacketCookieReply(p) => self.handle_cookie_reply(p),
            Packet::PacketData(p) => self.handle_data(p, dst),
        }
        .unwrap_or_else(TunnResult::from)
    }

    fn handle_handshake_init<'a>(
        &mut self,
        p: HandshakeInit,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_initiation",
            remote_idx = p.sender_idx
        );

        let resp_type = self.header_config.response.generate(&mut OsRandom);
        let s2 = self.padding_config.s2 as usize;
        let (packet, session) =
            self.handshake
                .receive_handshake_initialization(p, &mut dst[s2..], resp_type)?;

        // Store new session in ring buffer
        let index = session.local_index();
        self.sessions[index % N_SESSIONS] = Some(session);

        let packet_len = packet.len();
        if s2 > 0 {
            OsRandom.fill_bytes(&mut dst[..s2]);
        }
        if let Some(hp) = self.header_protection {
            let (prefix, message) = dst.split_at_mut(s2);
            hp.apply(prefix, &mut message[..packet_len]);
        }

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeLastPacketSent);
        self.timer_tick_session_established(false, index); // New session established, we are not the initiator

        tracing::debug!(message = "Sending handshake_response", local_idx = index);

        Ok(TunnResult::WriteToNetwork(&mut dst[..s2 + packet_len]))
    }

    fn handle_handshake_response<'a>(
        &mut self,
        p: HandshakeResponse,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received handshake_response",
            local_idx = p.receiver_idx,
            remote_idx = p.sender_idx
        );

        let session = self.handshake.receive_handshake_response(p)?;

        let content_padding = self.content_padding_addition(0);
        let keepalive_packet = self.format_transport_packet(&session, &[], content_padding, dst);
        // Store new session in ring buffer
        let l_idx = session.local_index();
        let index = l_idx % N_SESSIONS;
        self.sessions[index] = Some(session);

        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick_session_established(true, index); // New session established, we are the initiator
        self.set_current_session(l_idx);

        tracing::debug!("Sending keepalive");

        Ok(TunnResult::WriteToNetwork(keepalive_packet)) // Send a keepalive as a response
    }

    fn handle_cookie_reply<'a>(
        &mut self,
        p: PacketCookieReply,
    ) -> Result<TunnResult<'a>, WireGuardError> {
        tracing::debug!(
            message = "Received cookie_reply",
            local_idx = p.receiver_idx
        );

        self.handshake.receive_cookie_reply(p)?;
        self.timer_tick(TimerName::TimeLastPacketReceived);
        self.timer_tick(TimerName::TimeCookieReceived);

        tracing::debug!("Did set cookie");

        Ok(TunnResult::Done)
    }

    /// Update the index of the currently used session, if needed
    fn set_current_session(&mut self, new_idx: usize) {
        let cur_idx = self.current;
        if cur_idx == new_idx {
            // There is nothing to do, already using this session, this is the common case
            return;
        }
        if self.sessions[cur_idx % N_SESSIONS].is_none()
            || self.timers.session_timers[new_idx % N_SESSIONS]
                >= self.timers.session_timers[cur_idx % N_SESSIONS]
        {
            self.current = new_idx;
            tracing::debug!(message = "New session", session = new_idx);
        }
    }

    /// Decrypts a data packet, and stores the decapsulated packet in dst.
    fn handle_data<'a>(
        &mut self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<TunnResult<'a>, WireGuardError> {
        let r_idx = packet.receiver_idx as usize;
        let idx = r_idx % N_SESSIONS;

        // Get the (probably) right session
        let decapsulated_packet = {
            let session = self.sessions[idx].as_ref();
            let session = session.ok_or_else(|| {
                tracing::trace!(message = "No current session available", remote_idx = r_idx);
                WireGuardError::NoCurrentSession
            })?;
            session.receive_packet_data(packet, dst)?
        };

        self.set_current_session(r_idx);

        self.timer_tick(TimerName::TimeLastPacketReceived);

        Ok(self.validate_decapsulated_packet(decapsulated_packet))
    }

    /// Returns the next queued pre-handshake datagram (I-packet or junk), if any.
    /// The caller should send these datagrams to the network before the handshake
    /// initiation packet. Call repeatedly until `None` is returned.
    pub fn poll_outgoing_packet(&mut self) -> Option<Vec<u8>> {
        self.network_outgoing.pop_front()
    }

    /// Returns true if there are queued pre-handshake datagrams.
    pub fn has_outgoing_packets(&self) -> bool {
        !self.network_outgoing.is_empty()
    }

    /// Formats a new handshake initiation message and store it in dst. If force_resend is true will send
    /// a new handshake, even if a handshake is already in progress (for example when a handshake times out).
    ///
    /// Before sending the returned packet, the caller must drain `poll_outgoing_packet()` and
    /// send those datagrams first (I-packets and junk).
    ///
    /// dst must be at least `148 + S1` bytes (handshake init size + padding).
    pub fn format_handshake_initiation<'a>(
        &mut self,
        dst: &'a mut [u8],
        force_resend: bool,
    ) -> TunnResult<'a> {
        if self.handshake.is_in_progress() && !force_resend {
            return TunnResult::Done;
        }

        if self.handshake.is_expired() {
            self.timers.clear();
        }

        let starting_new_handshake = !self.handshake.is_in_progress();
        self.timers
            .roll_handshake_timings(&mut OsRandom, starting_new_handshake);

        // Queue I-packets and junk before the handshake initiation
        // (sent as separate UDP datagrams before the real init)
        self.queue_pre_handshake_packets();

        let init_type = self.header_config.init.generate(&mut OsRandom);
        let s1 = self.padding_config.s1 as usize;

        match self.handshake.format_handshake_initiation(&mut dst[s1..], init_type) {
            Ok(packet) => {
                tracing::debug!("Sending handshake_initiation");

                let packet_len = packet.len();
                if s1 > 0 {
                    OsRandom.fill_bytes(&mut dst[..s1]);
                }
                if let Some(hp) = self.header_protection {
                    let (prefix, message) = dst.split_at_mut(s1);
                    hp.apply(prefix, &mut message[..packet_len]);
                }

                if starting_new_handshake {
                    self.timer_tick(TimerName::TimeLastHandshakeStarted);
                }
                self.timer_tick(TimerName::TimeLastPacketSent);
                TunnResult::WriteToNetwork(&mut dst[..s1 + packet_len])
            }
            Err(e) => TunnResult::Err(e),
        }
    }

    /// Generate and queue I-packets (CPS chains) and junk packets.
    /// These are sent as separate UDP datagrams before the handshake initiation.
    fn queue_pre_handshake_packets(&mut self) {
        // I-packets first
        for chain in self.init_packet_config.active_chains() {
            let packet = chain.generate_for_init(&mut OsRandom);
            if !packet.is_empty() {
                self.network_outgoing.push_back(packet);
            }
        }

        // Then junk packets
        let junk_packets = self.junk_config.generate_junk_packets(&mut OsRandom);
        for junk in junk_packets {
            self.network_outgoing.push_back(junk);
        }
    }

    /// Check if an IP packet is v4 or v6, truncate to the length indicated by the length field
    /// Returns the truncated packet and the source IP as TunnResult
    fn validate_decapsulated_packet<'a>(&mut self, packet: &'a mut [u8]) -> TunnResult<'a> {
        let (computed_len, src_ip_address) = match packet.len() {
            0 => return TunnResult::Done, // This is keepalive, and not an error
            _ if packet[0] >> 4 == 4 && packet.len() >= IPV4_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV4_LEN_OFF..IPV4_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV4_IP_SZ] = packet
                    [IPV4_SRC_IP_OFF..IPV4_SRC_IP_OFF + IPV4_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize,
                    IpAddr::from(addr_bytes),
                )
            }
            _ if packet[0] >> 4 == 6 && packet.len() >= IPV6_MIN_HEADER_SIZE => {
                let len_bytes: [u8; IP_LEN_SZ] = packet[IPV6_LEN_OFF..IPV6_LEN_OFF + IP_LEN_SZ]
                    .try_into()
                    .unwrap();
                let addr_bytes: [u8; IPV6_IP_SZ] = packet
                    [IPV6_SRC_IP_OFF..IPV6_SRC_IP_OFF + IPV6_IP_SZ]
                    .try_into()
                    .unwrap();
                (
                    u16::from_be_bytes(len_bytes) as usize + IPV6_MIN_HEADER_SIZE,
                    IpAddr::from(addr_bytes),
                )
            }
            _ => {
                // amneziawg-go drops payloads that are neither IPv4 nor IPv6 —
                // content-padded keepalives decrypt to all zeros — but still
                // counts them as data received.
                self.timer_tick(TimerName::TimeLastDataPacketReceived);
                return TunnResult::Done;
            }
        };

        if computed_len > packet.len() {
            return TunnResult::Err(WireGuardError::InvalidPacket);
        }

        self.timer_tick(TimerName::TimeLastDataPacketReceived);
        self.rx_bytes += computed_len;

        match src_ip_address {
            IpAddr::V4(addr) => TunnResult::WriteToTunnelV4(&mut packet[..computed_len], addr),
            IpAddr::V6(addr) => TunnResult::WriteToTunnelV6(&mut packet[..computed_len], addr),
        }
    }

    /// Get a packet from the queue, and try to encapsulate it
    fn send_queued_packet<'a>(&mut self, dst: &'a mut [u8]) -> TunnResult<'a> {
        if let Some(packet) = self.dequeue_packet() {
            match self.encapsulate(&packet, dst) {
                TunnResult::Err(_) => {
                    // On error, return packet to the queue
                    self.requeue_packet(packet);
                }
                r => return r,
            }
        }
        TunnResult::Done
    }

    /// Push packet to the back of the queue
    fn queue_packet(&mut self, packet: &[u8]) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_back(packet.to_vec());
        }
    }

    /// Push packet to the front of the queue
    fn requeue_packet(&mut self, packet: Vec<u8>) {
        if self.packet_queue.len() < MAX_QUEUE_DEPTH {
            // Drop if too many are already in queue
            self.packet_queue.push_front(packet);
        }
    }

    fn dequeue_packet(&mut self) -> Option<Vec<u8>> {
        self.packet_queue.pop_front()
    }

    /// Determine the padding length for an incoming packet by trying each
    /// message type's padding + expected size, then validating the header at
    /// the padding offset. With AWG 3.0 header protection enabled, the
    /// 4 type bytes are decrypted before the range check.
    ///
    /// Returns `Some((padding, protected_len))` where `protected_len` is the
    /// number of bytes after the padding covered by header protection (the
    /// full message for handshake types, the 16-byte header for transport),
    /// or `None` if no match.
    fn determine_padding(&self, src: &[u8]) -> Option<(usize, usize)> {
        let checks: [(usize, &crate::amnezia::HeaderRange, usize, bool); 4] = [
            (
                self.padding_config.s1 as usize,
                &self.header_config.init,
                HANDSHAKE_INIT_SZ,
                true,
            ),
            (
                self.padding_config.s2 as usize,
                &self.header_config.response,
                HANDSHAKE_RESP_SZ,
                true,
            ),
            (
                self.padding_config.s3 as usize,
                &self.header_config.cookie,
                COOKIE_REPLY_SZ,
                true,
            ),
            (
                self.padding_config.s4 as usize,
                &self.header_config.transport,
                DATA_OVERHEAD_SZ,
                false,
            ),
        ];

        // Every candidate shares the same nonce — the first 12 bytes of the
        // datagram — so the type keystream is derived once, as in
        // amneziawg-go's `typeHash`.
        let type_mask = match self.header_protection {
            Some(hp) if src.len() >= crate::amnezia::HEADER_PROTECTION_NONCE_SIZE => {
                Some(hp.type_mask(src))
            }
            _ => None,
        };

        for &(padding, header_range, expected_size, exact) in &checks {
            let size_ok = if exact {
                src.len() == padding + expected_size
            } else {
                src.len() >= padding + expected_size
            };

            if size_ok && padding + 4 <= src.len() {
                let mut type_bytes: [u8; 4] = src[padding..padding + 4]
                    .try_into()
                    .expect("bounds checked: padding + 4 <= src.len()");
                if let Some(mask) = type_mask {
                    for (byte, mask_byte) in type_bytes.iter_mut().zip(mask.iter()) {
                        *byte ^= mask_byte;
                    }
                }
                let header = u32::from_le_bytes(type_bytes);
                if header_range.contains(header) {
                    let protected_len = if exact {
                        expected_size
                    } else {
                        TRANSPORT_HEADER_SZ
                    };
                    return Some((padding, protected_len));
                }
            }
        }
        None
    }

    fn estimate_loss(&self) -> f32 {
        let session_idx = self.current;

        let mut weight = 9.0;
        let mut cur_avg = 0.0;
        let mut total_weight = 0.0;

        for i in 0..N_SESSIONS {
            if let Some(ref session) = self.sessions[(session_idx.wrapping_sub(i)) % N_SESSIONS] {
                let (expected, received) = session.current_packet_cnt();

                let loss = if expected == 0 {
                    0.0
                } else {
                    1.0 - received as f32 / expected as f32
                };

                cur_avg += loss * weight;
                total_weight += weight;
                weight /= 3.0;
            }
        }

        if total_weight == 0.0 {
            0.0
        } else {
            cur_avg / total_weight
        }
    }

    /// Return stats from the tunnel:
    /// * Time since last handshake in seconds
    /// * Data bytes sent
    /// * Data bytes received
    pub fn stats(&self) -> (Option<Duration>, usize, usize, f32, Option<u32>) {
        let time = self.time_since_last_handshake();
        let tx_bytes = self.tx_bytes;
        let rx_bytes = self.rx_bytes;
        let loss = self.estimate_loss();
        let rtt = self.handshake.last_rtt;

        (time, tx_bytes, rx_bytes, loss, rtt)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "mock-instant")]
    use crate::noise::timers::{REKEY_AFTER_TIME, REKEY_TIMEOUT};

    use super::*;
    use crate::amnezia::HeaderRange;
    use rand_core::{OsRng, RngCore};

    fn create_two_tuns() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let my_idx = OsRng.next_u32();

        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let their_idx = OsRng.next_u32();

        let my_tun = Tunn::new(my_secret_key, their_public_key, None, None, my_idx, None);

        let their_tun = Tunn::new(their_secret_key, my_public_key, None, None, their_idx, None);

        (my_tun, their_tun)
    }

    fn create_handshake_init(tun: &mut Tunn) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_init = tun.format_handshake_initiation(&mut dst, false);
        assert!(matches!(handshake_init, TunnResult::WriteToNetwork(_)));
        let handshake_init = if let TunnResult::WriteToNetwork(sent) = handshake_init {
            sent
        } else {
            unreachable!();
        };

        handshake_init.into()
    }

    fn create_handshake_response(tun: &mut Tunn, handshake_init: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let handshake_resp = tun.decapsulate(None, handshake_init, &mut dst);
        assert!(matches!(handshake_resp, TunnResult::WriteToNetwork(_)));

        let handshake_resp = if let TunnResult::WriteToNetwork(sent) = handshake_resp {
            sent
        } else {
            unreachable!();
        };

        handshake_resp.into()
    }

    fn parse_handshake_resp(tun: &mut Tunn, handshake_resp: &[u8]) -> Vec<u8> {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, handshake_resp, &mut dst);
        assert!(matches!(keepalive, TunnResult::WriteToNetwork(_)));

        let keepalive = if let TunnResult::WriteToNetwork(sent) = keepalive {
            sent
        } else {
            unreachable!();
        };

        keepalive.into()
    }

    fn parse_keepalive(tun: &mut Tunn, keepalive: &[u8]) {
        let mut dst = vec![0u8; 2048];
        let keepalive = tun.decapsulate(None, keepalive, &mut dst);
        assert!(matches!(keepalive, TunnResult::Done));
    }

    fn create_two_tuns_and_handshake() -> (Tunn, Tunn) {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        parse_keepalive(&mut their_tun, &keepalive);

        (my_tun, their_tun)
    }

    fn create_ipv4_udp_packet() -> Vec<u8> {
        let header =
            etherparse::PacketBuilder::ipv4([192, 168, 1, 2], [192, 168, 1, 3], 5).udp(5678, 23);
        let payload = [0, 1, 2, 3];
        let mut packet = Vec::<u8>::with_capacity(header.size(payload.len()));
        header.write(&mut packet, &payload).unwrap();
        packet
    }

    #[cfg(feature = "mock-instant")]
    fn update_timer_results_in_handshake(tun: &mut Tunn) {
        let mut dst = vec![0u8; 2048];
        let result = tun.update_timers(&mut dst);
        assert!(matches!(result, TunnResult::WriteToNetwork(_)));
        let packet_data = if let TunnResult::WriteToNetwork(data) = result {
            data
        } else {
            unreachable!();
        };
        let packet = Tunn::parse_incoming_packet(packet_data).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn create_two_tunnels_linked_to_eachother() {
        let (_my_tun, _their_tun) = create_two_tuns();
    }

    #[test]
    fn handshake_init() {
        let (mut my_tun, _their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));
    }

    #[test]
    fn handshake_init_and_response() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let packet = Tunn::parse_incoming_packet(&resp).unwrap();
        assert!(matches!(packet, Packet::HandshakeResponse(_)));
    }

    #[test]
    fn full_handshake() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        let packet = Tunn::parse_incoming_packet(&keepalive).unwrap();
        assert!(matches!(packet, Packet::PacketData(_)));
    }

    #[test]
    fn full_handshake_plus_timers() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        // Time has not yet advanced so their is nothing to do
        assert!(matches!(my_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn new_handshake_after_two_mins() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];

        // Advance time 1 second and "send" 1 packet so that we send a handshake
        // after the timeout
        mock_instant::MockClock::advance(Duration::from_secs(1));
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        assert!(matches!(
            my_tun.update_timers(&mut my_dst),
            TunnResult::Done
        ));
        let sent_packet_buf = create_ipv4_udp_packet();
        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));

        //Advance to timeout
        mock_instant::MockClock::advance(REKEY_AFTER_TIME);
        assert!(matches!(their_tun.update_timers(&mut []), TunnResult::Done));
        update_timer_results_in_handshake(&mut my_tun);
    }

    #[test]
    #[cfg(feature = "mock-instant")]
    fn handshake_no_resp_rekey_timeout() {
        let (mut my_tun, _their_tun) = create_two_tuns();

        let init = create_handshake_init(&mut my_tun);
        let packet = Tunn::parse_incoming_packet(&init).unwrap();
        assert!(matches!(packet, Packet::HandshakeInit(_)));

        mock_instant::MockClock::advance(REKEY_TIMEOUT);
        update_timer_results_in_handshake(&mut my_tun)
    }

    #[test]
    fn one_ip_packet() {
        let (mut my_tun, mut their_tun) = create_two_tuns_and_handshake();
        let mut my_dst = [0u8; 1024];
        let mut their_dst = [0u8; 1024];

        let sent_packet_buf = create_ipv4_udp_packet();

        let data = my_tun.encapsulate(&sent_packet_buf, &mut my_dst);
        assert!(matches!(data, TunnResult::WriteToNetwork(_)));
        let data = if let TunnResult::WriteToNetwork(sent) = data {
            sent
        } else {
            unreachable!();
        };

        let data = their_tun.decapsulate(None, data, &mut their_dst);
        assert!(matches!(data, TunnResult::WriteToTunnelV4(..)));
        let recv_packet_buf = if let TunnResult::WriteToTunnelV4(recv, _addr) = data {
            recv
        } else {
            unreachable!();
        };
        assert_eq!(sent_packet_buf, recv_packet_buf);
    }

    fn awg3_test_config(key: [u8; 32]) -> crate::amnezia::Amnezia3Config {
        crate::amnezia::Amnezia3Config {
            junk: JunkConfig::disabled(),
            paddings: PaddingConfig::new(16, 16, 16, 16).expect("valid paddings"),
            headers: HeaderConfig::new(
                HeaderRange::new(100, 199).expect("valid range"),
                HeaderRange::new(200, 299).expect("valid range"),
                HeaderRange::new(300, 399).expect("valid range"),
                HeaderRange::new(400, 499).expect("valid range"),
            )
            .expect("valid headers"),
            init_packets: InitPacketConfig::default(),
            header_protection_key: Some(key),
            content_padding_addition: None,
            timing_ranges: Default::default(),
            mtu: crate::amnezia::AWG3_DEFAULT_MTU,
        }
    }

    #[test]
    fn new_with_amnezia3_constructs() {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let config = awg3_test_config([0x42; 32]);
        let tun = Tunn::new_with_amnezia3(
            my_secret_key,
            their_public_key,
            None,
            None,
            1,
            None,
            config,
        );
        assert!(tun.is_ok());
        // silence unused warning for their_secret_key's counterpart in later tasks
        let _ = (my_public_key, their_secret_key);
    }

    fn create_two_tuns_awg3() -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let key = [0x42; 32];

        let my_tun = Tunn::new_with_amnezia3(
            my_secret_key,
            their_public_key,
            None,
            None,
            1,
            None,
            awg3_test_config(key),
        )
        .expect("valid awg3 config");
        let their_tun = Tunn::new_with_amnezia3(
            their_secret_key,
            my_public_key,
            None,
            None,
            2,
            None,
            awg3_test_config(key),
        )
        .expect("valid awg3 config");
        (my_tun, their_tun)
    }

    #[test]
    fn awg3_handshake_init_is_header_protected() {
        let (mut my_tun, _) = create_two_tuns_awg3();
        let init = create_handshake_init(&mut my_tun);
        // S1 = 16 padding + 148 init message
        assert_eq!(init.len(), 16 + 148);

        // Decrypting with the configured key yields a valid initiation.
        let hp = crate::amnezia::HeaderProtection::new([0x42; 32]);
        let mut decrypted = init[16..].to_vec();
        hp.apply(&init[..16], &mut decrypted);
        let packet = Tunn::parse_incoming_packet_config(
            &decrypted,
            &HeaderConfig::new(
                HeaderRange::new(100, 199).unwrap(),
                HeaderRange::new(200, 299).unwrap(),
                HeaderRange::new(300, 399).unwrap(),
                HeaderRange::new(400, 499).unwrap(),
            )
            .unwrap(),
        );
        assert!(matches!(packet, Ok(Packet::HandshakeInit(_))));
    }

    #[test]
    fn awg3_keepalive_has_s4_prefix() {
        let (mut my_tun, mut their_tun) = create_two_tuns_awg3();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        // Response: S2 (16) + 92
        assert_eq!(resp.len(), 16 + 92);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);
        // Keepalive transport packet: S4 (16) + 16 header + 16 tag.
        // (Previously keepalives skipped S4; amneziawg-go f4f4c99 applies it.)
        assert_eq!(keepalive.len(), 16 + 32);
    }

    fn ipv4_packet() -> Vec<u8> {
        // Minimal 24-byte IPv4 packet: 20-byte header + 4 payload bytes
        let mut p = vec![0u8; 24];
        p[0] = 0x45; // version 4, IHL 5
        p[2..4].copy_from_slice(&24u16.to_be_bytes()); // total length
        p[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        p[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst
        p
    }

    #[test]
    fn awg3_full_handshake_and_data_round_trip() {
        let (mut my_tun, mut their_tun) = create_two_tuns_awg3();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let keepalive = parse_handshake_resp(&mut my_tun, &resp);

        // Responder consumes the keepalive (header-protected transport).
        let mut dst = vec![0u8; 2048];
        let result = their_tun.decapsulate(None, &keepalive, &mut dst);
        assert!(matches!(result, TunnResult::Done));

        // Data packet my -> their, through S4 + header protection.
        let ip = ipv4_packet();
        let mut enc_buf = vec![0u8; 2048];
        let encapsulated = match my_tun.encapsulate(&ip, &mut enc_buf) {
            TunnResult::WriteToNetwork(packet) => packet.len(),
            other => panic!("expected WriteToNetwork, got {:?}", other),
        };
        let wire = enc_buf[..encapsulated].to_vec();
        assert_eq!(wire.len(), 16 + 16 + ip.len() + 16); // S4 + header + content + tag

        let mut dec_buf = vec![0u8; 2048];
        match their_tun.decapsulate(None, &wire, &mut dec_buf) {
            TunnResult::WriteToTunnelV4(packet, addr) => {
                assert_eq!(packet, &ip[..]);
                assert_eq!(addr, std::net::IpAddr::from([10, 0, 0, 1]));
            }
            other => panic!("expected WriteToTunnelV4, got {:?}", other),
        }
    }

    fn create_two_tuns_awg3_cpa(cpa_lo: u32, cpa_hi: u32) -> (Tunn, Tunn) {
        let my_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(&my_secret_key);
        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let their_public_key = x25519_dalek::PublicKey::from(&their_secret_key);
        let key = [0x42; 32];

        let mut config = awg3_test_config(key);
        config.content_padding_addition = Some(U32Range::new(cpa_lo, cpa_hi).expect("valid range"));

        let my_tun =
            Tunn::new_with_amnezia3(my_secret_key, their_public_key, None, None, 1, None, config)
                .expect("valid awg3 config");
        let their_tun = Tunn::new_with_amnezia3(
            their_secret_key,
            my_public_key,
            None,
            None,
            2,
            None,
            // The receiver does not need the CPA range: padding is inside AEAD.
            awg3_test_config(key),
        )
        .expect("valid awg3 config");
        (my_tun, their_tun)
    }

    fn complete_awg3_handshake(my_tun: &mut Tunn, their_tun: &mut Tunn) {
        let init = create_handshake_init(my_tun);
        let resp = create_handshake_response(their_tun, &init);
        let keepalive = parse_handshake_resp(my_tun, &resp);
        let mut dst = vec![0u8; 2048];
        let _ = their_tun.decapsulate(None, &keepalive, &mut dst);
    }

    #[test]
    fn awg3_content_padding_sizes_and_round_trip() {
        let (mut my_tun, mut their_tun) = create_two_tuns_awg3_cpa(16, 16);
        complete_awg3_handshake(&mut my_tun, &mut their_tun);

        let ip = ipv4_packet();
        let mut enc_buf = vec![0u8; 2048];
        let wire_len = match my_tun.encapsulate(&ip, &mut enc_buf) {
            TunnResult::WriteToNetwork(packet) => packet.len(),
            other => panic!("expected WriteToNetwork, got {:?}", other),
        };
        // S4 (16) + header (16) + content (24 + 16 CPA zeros) + tag (16)
        assert_eq!(wire_len, 16 + 16 + 24 + 16 + 16);

        // Receiver trims the CPA zeros via the IP total-length field.
        let mut dec_buf = vec![0u8; 2048];
        match their_tun.decapsulate(None, &enc_buf[..wire_len], &mut dec_buf) {
            TunnResult::WriteToTunnelV4(packet, _) => assert_eq!(packet, &ip[..]),
            other => panic!("expected WriteToTunnelV4, got {:?}", other),
        }
    }

    #[test]
    fn awg3_content_padding_varies_within_range() {
        let (mut my_tun, mut their_tun) = create_two_tuns_awg3_cpa(1, 64);
        complete_awg3_handshake(&mut my_tun, &mut their_tun);

        let ip = ipv4_packet();
        let base = 16 + 16 + ip.len() + 16;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..32 {
            let mut enc_buf = vec![0u8; 2048];
            match my_tun.encapsulate(&ip, &mut enc_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    let add = packet.len() - base;
                    assert!((1..=64).contains(&add), "addition {} out of range", add);
                    seen.insert(add);
                }
                other => panic!("expected WriteToNetwork, got {:?}", other),
            }
        }
        assert!(seen.len() > 1, "content padding should vary across packets");
    }

    #[test]
    fn awg3_content_padding_is_clamped_to_mtu() {
        let (mut my_tun, mut their_tun) = create_two_tuns_awg3_cpa(200, 200);
        complete_awg3_handshake(&mut my_tun, &mut their_tun);

        // An IP packet 100 bytes short of the MTU leaves room for only 100
        // padding bytes, so the 200-byte addition is clamped.
        let mtu = crate::amnezia::AWG3_DEFAULT_MTU as usize;
        let mut ip = ipv4_packet();
        ip.resize(mtu - 100, 0);
        let len = ip.len() as u16;
        ip[2..4].copy_from_slice(&len.to_be_bytes());

        let mut enc_buf = vec![0u8; 4096];
        let wire_len = match my_tun.encapsulate(&ip, &mut enc_buf) {
            TunnResult::WriteToNetwork(packet) => packet.len(),
            other => panic!("expected WriteToNetwork, got {:?}", other),
        };
        assert_eq!(wire_len, 16 + 16 + ip.len() + 100 + 16);
    }

    #[test]
    fn awg3_content_padded_keepalive_is_dropped_as_data() {
        let (mut my_tun, mut their_tun) = create_two_tuns_awg3_cpa(8, 8);
        complete_awg3_handshake(&mut my_tun, &mut their_tun);

        // CPA-padded keepalive: content is 8 zero bytes inside AEAD.
        let mut enc_buf = vec![0u8; 2048];
        let wire_len = match my_tun.encapsulate(&[], &mut enc_buf) {
            TunnResult::WriteToNetwork(packet) => packet.len(),
            other => panic!("expected WriteToNetwork, got {:?}", other),
        };
        // S4 (16) + header (16) + content (8 zeros) + tag (16)
        assert_eq!(wire_len, 16 + 16 + 8 + 16);

        // amneziawg-go drops payloads that are neither IPv4 nor IPv6, but still
        // counts them as data received.
        let mut dec_buf = vec![0u8; 2048];
        let _ = their_tun.update_timers(&mut vec![0u8; 2048]);
        their_tun.timers[TimerName::TimeLastDataPacketReceived] = Duration::ZERO;
        let result = their_tun.decapsulate(None, &enc_buf[..wire_len], &mut dec_buf);
        assert!(matches!(result, TunnResult::Done));
        assert_eq!(
            their_tun.timers[TimerName::TimeLastDataPacketReceived],
            their_tun.timers[TimerName::TimeCurrent]
        );
    }

    #[test]
    fn padded_keepalive_counts_as_data_sent() {
        // With an S4 prefix the wire size differs from MessageKeepaliveSize, so
        // amneziawg-go arms the data-sent timer even for an empty payload.
        let (mut my_tun, mut their_tun) = create_two_tuns_awg3();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let _ = parse_handshake_resp(&mut my_tun, &resp);

        let mut buf = vec![0u8; 2048];
        let _ = my_tun.update_timers(&mut buf);
        assert!(my_tun.timers[TimerName::TimeCurrent] > Duration::ZERO);

        my_tun.timers[TimerName::TimeLastDataPacketSent] = Duration::ZERO;
        match my_tun.encapsulate(&[], &mut buf) {
            TunnResult::WriteToNetwork(_) => {}
            other => panic!("expected WriteToNetwork, got {:?}", other),
        }
        assert_eq!(
            my_tun.timers[TimerName::TimeLastDataPacketSent],
            my_tun.timers[TimerName::TimeCurrent]
        );
    }

    #[test]
    fn unpadded_keepalive_is_not_data_sent() {
        let (mut my_tun, mut their_tun) = create_two_tuns();
        let init = create_handshake_init(&mut my_tun);
        let resp = create_handshake_response(&mut their_tun, &init);
        let _ = parse_handshake_resp(&mut my_tun, &resp);

        let mut buf = vec![0u8; 2048];
        let _ = my_tun.update_timers(&mut buf);
        my_tun.timers[TimerName::TimeLastDataPacketSent] = Duration::ZERO;
        match my_tun.encapsulate(&[], &mut buf) {
            TunnResult::WriteToNetwork(packet) => assert_eq!(packet.len(), KEEPALIVE_SZ),
            other => panic!("expected WriteToNetwork, got {:?}", other),
        }
        assert_eq!(
            my_tun.timers[TimerName::TimeLastDataPacketSent],
            Duration::ZERO
        );
    }

    #[test]
    fn awg3_mismatched_header_protection_key_drops() {
        let (mut my_tun, _) = create_two_tuns_awg3();
        let their_secret_key = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let my_public_key = x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::random_from_rng(OsRng),
        );
        let mut wrong_key_tun = Tunn::new_with_amnezia3(
            their_secret_key,
            my_public_key,
            None,
            None,
            2,
            None,
            awg3_test_config([0x99; 32]), // different header protection key
        )
        .expect("valid awg3 config");

        let init = create_handshake_init(&mut my_tun);
        let mut dst = vec![0u8; 2048];
        let result = wrong_key_tun.decapsulate(None, &init, &mut dst);
        assert!(matches!(result, TunnResult::Err(WireGuardError::InvalidPacket)));
    }
}
