use super::handshake::{b2s_hash, b2s_keyed_mac_16, b2s_keyed_mac_16_2, b2s_mac_24};
use crate::amnezia::{FastRandom, HeaderConfig};
use crate::noise::handshake::{LABEL_COOKIE, LABEL_MAC1};
use crate::noise::{HandshakeInit, HandshakeResponse, Packet, Tunn, TunnResult, WireGuardError};

#[cfg(feature = "mock-instant")]
use mock_instant::Instant;
use portable_atomic::{AtomicU64, Ordering};
use std::net::IpAddr;

#[cfg(not(feature = "mock-instant"))]
use crate::sleepyinstant::Instant;

use aead::generic_array::GenericArray;
use aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305};
use parking_lot::Mutex;
use rand_core::{OsRng, RngCore};

const COOKIE_REFRESH: u64 = 128; // Use 128 and not 120 so the compiler can optimize out the division
const COOKIE_SIZE: usize = 16;
const COOKIE_NONCE_SIZE: usize = 24;

/// How often should reset count in seconds
const RESET_PERIOD: u64 = 1;

type Cookie = [u8; COOKIE_SIZE];

/// There are two places where WireGuard requires "randomness" for cookies:
///
/// * The 24 byte nonce in the cookie message — here the only goal is to avoid
///   nonce reuse.
/// * A secret value that changes every two minutes.
///
/// Because the main goal of the cookie is simply for a party to prove ownership
/// of an IP address we can relax the randomness definition a bit, in order to
/// avoid locking, because using less resources is the main goal of any DoS
/// prevention mechanism. In order to avoid locking and calls to rand we derive
/// pseudo random values using the AEAD and some counters.
pub struct RateLimiter {
    /// The key we use to derive the nonce
    nonce_key: [u8; 32],
    /// The key we use to derive the cookie
    secret_key: [u8; 16],
    start_time: Instant,
    /// A single 64 bit counter (should suffice for many years)
    nonce_ctr: AtomicU64,
    mac1_key: [u8; 32],
    cookie_key: Key,
    limit: u64,
    /// The counter since last reset
    count: AtomicU64,
    /// The time last reset was performed on this rate limiter
    last_reset: Mutex<Instant>,
}

impl RateLimiter {
    pub fn new(public_key: &crate::x25519::PublicKey, limit: u64) -> Self {
        let mut secret_key = [0u8; 16];
        OsRng.fill_bytes(&mut secret_key);
        RateLimiter {
            nonce_key: Self::rand_bytes(),
            secret_key,
            start_time: Instant::now(),
            nonce_ctr: AtomicU64::new(0),
            mac1_key: b2s_hash(LABEL_MAC1, public_key.as_bytes()),
            cookie_key: b2s_hash(LABEL_COOKIE, public_key.as_bytes()).into(),
            limit,
            count: AtomicU64::new(0),
            last_reset: Mutex::new(Instant::now()),
        }
    }

    fn rand_bytes() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Reset packet count (ideally should be called with a period of 1 second)
    pub fn reset_count(&self) {
        // The rate limiter is not very accurate, but at the scale we care about it doesn't matter much
        let current_time = Instant::now();
        let mut last_reset_time = self.last_reset.lock();
        if current_time.duration_since(*last_reset_time).as_secs() >= RESET_PERIOD {
            self.count.store(0, Ordering::SeqCst);
            *last_reset_time = current_time;
        }
    }

    /// Compute the correct cookie value based on the current secret value and the source IP
    fn current_cookie(&self, addr: IpAddr) -> Cookie {
        let mut addr_bytes = [0u8; 16];

        match addr {
            IpAddr::V4(a) => addr_bytes[..4].copy_from_slice(&a.octets()[..]),
            IpAddr::V6(a) => addr_bytes[..].copy_from_slice(&a.octets()[..]),
        }

        // The current cookie for a given IP is the MAC(responder.changing_secret_every_two_minutes, initiator.ip_address)
        // First we derive the secret from the current time, the value of cur_counter would change with time.
        let cur_counter = Instant::now().duration_since(self.start_time).as_secs() / COOKIE_REFRESH;

        // Next we derive the cookie
        b2s_keyed_mac_16_2(&self.secret_key, &cur_counter.to_le_bytes(), &addr_bytes)
    }

    fn nonce(&self) -> [u8; COOKIE_NONCE_SIZE] {
        let ctr = self.nonce_ctr.fetch_add(1, Ordering::Relaxed);

        b2s_mac_24(&self.nonce_key, &ctr.to_le_bytes())
    }

    fn is_under_load(&self) -> bool {
        self.count.fetch_add(1, Ordering::SeqCst) >= self.limit
    }

    pub(crate) fn format_cookie_reply<'a>(
        &self,
        idx: u32,
        cookie: Cookie,
        mac1: &[u8],
        dst: &'a mut [u8],
        msg_type: u32,
    ) -> Result<&'a mut [u8], WireGuardError> {
        if dst.len() < super::COOKIE_REPLY_SZ {
            return Err(WireGuardError::DestinationBufferTooSmall);
        }

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (nonce, rest) = rest.split_at_mut(24);
        let (encrypted_cookie, _) = rest.split_at_mut(16 + 16);

        // msg.message_type = dynamic AmneziaWG header (or standard WG type 3)
        message_type.copy_from_slice(&msg_type.to_le_bytes());
        // msg.receiver_index = little_endian(initiator.sender_index)
        receiver_index.copy_from_slice(&idx.to_le_bytes());
        nonce.copy_from_slice(&self.nonce()[..]);

        let cipher = XChaCha20Poly1305::new(&self.cookie_key);

        let iv = GenericArray::from_slice(nonce);

        encrypted_cookie[..16].copy_from_slice(&cookie);
        let tag = cipher
            .encrypt_in_place_detached(iv, mac1, &mut encrypted_cookie[..16])
            .map_err(|_| WireGuardError::DestinationBufferTooSmall)?;

        encrypted_cookie[16..].copy_from_slice(&tag);

        Ok(&mut dst[..super::COOKIE_REPLY_SZ])
    }

    /// Verify the MAC fields on the datagram, and apply rate limiting if needed
    pub fn verify_packet<'a, 'b>(
        &self,
        src_addr: Option<IpAddr>,
        src: &'a [u8],
        dst: &'b mut [u8],
        header_config: &HeaderConfig,
    ) -> Result<Packet<'a>, TunnResult<'b>> {
        let packet = Tunn::parse_incoming_packet_config(src, header_config)?;

        // Verify and rate limit handshake messages only
        if let Packet::HandshakeInit(HandshakeInit { sender_idx, .. })
        | Packet::HandshakeResponse(HandshakeResponse { sender_idx, .. }) = packet
        {
            let (msg, macs) = src.split_at(src.len() - 32);
            let (mac1, mac2) = macs.split_at(16);

            let computed_mac1 = b2s_keyed_mac_16(&self.mac1_key, msg);
            if !super::constant_time_eq(&computed_mac1[..16], mac1) {
                return Err(TunnResult::Err(WireGuardError::InvalidMac));
            }

            if self.is_under_load() {
                let addr = match src_addr {
                    None => return Err(TunnResult::Err(WireGuardError::UnderLoad)),
                    Some(addr) => addr,
                };

                // Only given an address can we validate mac2
                let cookie = self.current_cookie(addr);
                let computed_mac2 = b2s_keyed_mac_16_2(&cookie, msg, mac1);

                if !super::constant_time_eq(&computed_mac2[..16], mac2) {
                    let cookie_msg_type = header_config.cookie.generate(&mut FastRandom);
                    let cookie_packet = self
                        .format_cookie_reply(sender_idx, cookie, mac1, dst, cookie_msg_type)
                        .map_err(TunnResult::Err)?;
                    return Err(TunnResult::WriteToNetwork(cookie_packet));
                }
            }
        }

        Ok(packet)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amnezia::{Amnezia3Config, HeaderRange, PaddingConfig};
    use crate::noise::{Packet, Tunn};
    use rand_core::OsRng;
    use std::convert::TryInto as _;

    /// H3 is what a cookie reply's type is drawn from, so give each range a
    /// distinct, easily recognised band.
    fn awg_headers() -> HeaderConfig {
        HeaderConfig::new(
            HeaderRange::new(1000, 1099).unwrap(),
            HeaderRange::new(2000, 2099).unwrap(),
            HeaderRange::new(3000, 3099).unwrap(),
            HeaderRange::new(4000, 4099).unwrap(),
        )
        .unwrap()
    }

    /// A tunnel plus the responder's public key, and a genuine handshake
    /// initiation from it — MACs included, which is what makes it a usable
    /// input for `verify_packet`.
    fn initiation(headers: HeaderConfig) -> (crate::x25519::PublicKey, Vec<u8>) {
        let initiator_secret = crate::x25519::StaticSecret::random_from_rng(OsRng);
        let responder_secret = crate::x25519::StaticSecret::random_from_rng(OsRng);
        let responder_public = crate::x25519::PublicKey::from(&responder_secret);

        let mut config = Amnezia3Config::wireguard_compatible();
        config.headers = headers;
        // No padding: `verify_packet` is given an already-stripped message.
        config.paddings = PaddingConfig::default();

        let mut initiator = Tunn::new_with_amnezia3(
            initiator_secret,
            responder_public,
            None,
            None,
            1,
            None,
            config,
        )
        .unwrap();

        let mut buf = vec![0u8; 2048];
        let packet = match initiator.format_handshake_initiation(&mut buf, false) {
            TunnResult::WriteToNetwork(packet) => packet.to_vec(),
            other => panic!("expected an initiation, got {:?}", other),
        };
        (responder_public, packet)
    }

    /// The happy path: a genuine initiation carries a mac1 the responder can
    /// recompute, so it verifies. Nothing else in the suite covers mac1 at all.
    #[test]
    fn accepts_a_genuine_initiation() {
        let (responder_public, packet) = initiation(HeaderConfig::wireguard_compatible());
        let limiter = RateLimiter::new(&responder_public, 100);
        let mut dst = [0u8; super::super::COOKIE_REPLY_SZ];

        let parsed = limiter
            .verify_packet(
                None,
                &packet,
                &mut dst,
                &HeaderConfig::wireguard_compatible(),
            )
            .expect("a genuine initiation must verify");
        assert!(matches!(parsed, Packet::HandshakeInit(_)));
    }

    /// mac1 is what stops an attacker from spending our CPU on Noise
    /// operations for packets it cannot have authored. Flipping a single bit
    /// anywhere in the MAC has to be rejected — which is also the behaviour the
    /// constant-time comparison exists to protect.
    #[test]
    fn rejects_a_forged_mac1() {
        let (responder_public, packet) = initiation(HeaderConfig::wireguard_compatible());
        let limiter = RateLimiter::new(&responder_public, 100);
        let mut dst = [0u8; super::super::COOKIE_REPLY_SZ];

        // mac1 occupies the 16 bytes preceding the 16 mac2 bytes.
        let mac1_start = packet.len() - 32;
        for bit in [0usize, 7, 63, 127] {
            let mut forged = packet.clone();
            forged[mac1_start + bit / 8] ^= 1 << (bit % 8);
            let result = limiter.verify_packet(
                None,
                &forged,
                &mut dst,
                &HeaderConfig::wireguard_compatible(),
            );
            assert!(
                matches!(result, Err(TunnResult::Err(WireGuardError::InvalidMac))),
                "flipping mac1 bit {} must be rejected",
                bit
            );
        }
    }

    /// A rate limiter with a limit of zero is always under load, which is how
    /// the cookie path is reached deterministically. Without a valid mac2 the
    /// responder answers with a cookie reply rather than doing Noise work.
    #[test]
    fn issues_a_cookie_reply_when_under_load() {
        let (responder_public, packet) = initiation(HeaderConfig::wireguard_compatible());
        let limiter = RateLimiter::new(&responder_public, 0);
        let mut dst = [0u8; super::super::COOKIE_REPLY_SZ];

        let addr: IpAddr = "192.0.2.10".parse().unwrap();
        match limiter.verify_packet(
            Some(addr),
            &packet,
            &mut dst,
            &HeaderConfig::wireguard_compatible(),
        ) {
            Err(TunnResult::WriteToNetwork(reply)) => {
                assert_eq!(reply.len(), super::super::COOKIE_REPLY_SZ);
                assert_eq!(
                    u32::from_le_bytes(reply[..4].try_into().unwrap()),
                    3,
                    "a plain WireGuard cookie reply is type 3"
                );
            }
            other => panic!("expected a cookie reply, got {:?}", other),
        }
    }

    /// The AmneziaWG variant of the same path: the cookie reply's type must be
    /// drawn from H3, not the standard 3, or a peer expecting obfuscated
    /// headers cannot classify it and the cookie is lost.
    #[test]
    fn cookie_reply_uses_the_configured_h3_range() {
        let headers = awg_headers();
        let (responder_public, packet) = initiation(headers);
        let limiter = RateLimiter::new(&responder_public, 0);
        let addr: IpAddr = "192.0.2.10".parse().unwrap();

        // Several draws, since the type is random within the range.
        for _ in 0..16 {
            let mut dst = [0u8; super::super::COOKIE_REPLY_SZ];
            match limiter.verify_packet(Some(addr), &packet, &mut dst, &headers) {
                Err(TunnResult::WriteToNetwork(reply)) => {
                    let msg_type = u32::from_le_bytes(reply[..4].try_into().unwrap());
                    assert!(
                        headers.cookie.contains(msg_type),
                        "cookie reply type {} is outside H3",
                        msg_type
                    );
                }
                other => panic!("expected a cookie reply, got {:?}", other),
            }
        }
    }

    /// Without a source address there is no cookie to bind to, so an
    /// under-load responder drops the packet instead of answering.
    #[test]
    fn refuses_to_answer_under_load_without_a_source_address() {
        let (responder_public, packet) = initiation(HeaderConfig::wireguard_compatible());
        let limiter = RateLimiter::new(&responder_public, 0);
        let mut dst = [0u8; super::super::COOKIE_REPLY_SZ];

        let result = limiter.verify_packet(
            None,
            &packet,
            &mut dst,
            &HeaderConfig::wireguard_compatible(),
        );
        assert!(matches!(
            result,
            Err(TunnResult::Err(WireGuardError::UnderLoad))
        ));
    }

    /// A short destination buffer must be reported, not written past.
    #[test]
    fn rejects_a_cookie_buffer_that_is_too_small() {
        let (responder_public, packet) = initiation(HeaderConfig::wireguard_compatible());
        let limiter = RateLimiter::new(&responder_public, 0);
        let mut dst = [0u8; super::super::COOKIE_REPLY_SZ - 1];

        let addr: IpAddr = "192.0.2.10".parse().unwrap();
        let result = limiter.verify_packet(
            Some(addr),
            &packet,
            &mut dst,
            &HeaderConfig::wireguard_compatible(),
        );
        assert!(matches!(
            result,
            Err(TunnResult::Err(WireGuardError::DestinationBufferTooSmall))
        ));
    }
}
