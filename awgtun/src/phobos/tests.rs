use super::test_vectors::{BINDING_SUCCESS, DECODE, MASK};
use super::*;
use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

/// Deterministic xorshift32, so a failing case reproduces.
struct XorShift(u32);

impl RandomSource for XorShift {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        for b in out {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.0 = x;
            *b = x as u8;
        }
    }
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(ring::digest::digest(&ring::digest::SHA256, data))
}

fn server() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), 51822))
}

/// Synthetic WireGuard-shaped message: a real type field, then filler.
fn wg_message(msg_type: u8, len: usize) -> Vec<u8> {
    let mut m = vec![msg_type, 0, 0, 0];
    m.extend((4..len).map(|i| (i * 31 + 7) as u8));
    m
}

fn config(masking: Masking) -> PhobosConfig {
    let mut c = PhobosConfig::new(b"synthetic-test-key".to_vec()).unwrap();
    c.masking = masking;
    c
}

fn codec(c: PhobosConfig, seed: u32) -> PhobosCodec<XorShift> {
    PhobosCodec::with_rng(c, XorShift(seed)).unwrap()
}

// --- Conformance vectors ---------------------------------------------------

#[test]
fn keystream_matches_reference_vectors() {
    for &(key, len, digest) in MASK {
        let mut buf = vec![0u8; len];
        apply_keystream(&mut buf, key.as_bytes());
        assert_eq!(sha256_hex(&buf), digest, "key {key:?} length {len}");
    }
}

#[test]
fn decode_matches_reference_vectors() {
    for &(key, ob, encoded, decoded) in DECODE {
        let mut buf = hex::decode(encoded).unwrap();
        let want = hex::decode(decoded).unwrap();
        let n = decode(&mut buf, key.as_bytes(), ob).expect("vector decodes");
        assert_eq!(&buf[..n], &want[..], "key {key:?} obfuscate-bytes {ob}");
    }
}

#[test]
fn binding_success_matches_reference_vectors() {
    for &(txid, addr, want) in BINDING_SUCCESS {
        let txid: [u8; 12] = hex::decode(txid).unwrap().try_into().unwrap();
        let got = build_binding_success(&txid, addr.parse().unwrap()).unwrap();
        assert_eq!(hex::encode(got), want, "{addr}");
    }
}

// --- Encoding ----------------------------------------------------------------

#[test]
fn encode_round_trips_the_reference_payloads() {
    for (seed, &(key, ob, _, decoded)) in DECODE.iter().enumerate() {
        let msg = hex::decode(decoded).unwrap();
        let mut rng = XorShift(seed as u32 + 1);
        let mut buf = msg.clone();
        encode(&mut buf, 0, key.as_bytes(), DEFAULT_MAX_DUMMY, ob, &mut rng);
        let n = decode(&mut buf, key.as_bytes(), ob).unwrap();
        assert_eq!(&buf[..n], &msg[..]);
    }
}

#[test]
fn encoded_messages_never_look_plain() {
    let key = b"k";
    let mut rng = XorShift(9);
    for t in 1..=4u8 {
        for _ in 0..200 {
            let mut buf = wg_message(t, 148);
            encode(&mut buf, 0, key, DEFAULT_MAX_DUMMY, 0, &mut rng);
            let mut unmasked = buf.clone();
            apply_keystream(&mut unmasked, key);
            assert!(!looks_plain(&unmasked));
            assert_ne!(unmasked[1], 0, "the random byte is never zero");
        }
    }
}

#[test]
fn tail_stays_within_its_bounds() {
    let key = b"k";
    let mut rng = XorShift(3);
    let mut max_seen = [0usize; 5];
    for _ in 0..4000 {
        for t in 1..=4u8 {
            let msg = wg_message(t, 64);
            let mut buf = msg.clone();
            encode(&mut buf, 0, key, 10, 0, &mut rng);
            let tail = buf.len() - msg.len();
            max_seen[usize::from(t)] = max_seen[usize::from(t)].max(tail);
        }
    }
    // Handshakes: [0, 512). Cookie and transport: [0, max-dummy).
    assert_eq!(max_seen[1], 511);
    assert_eq!(max_seen[2], 511);
    assert_eq!(max_seen[3], 9);
    assert_eq!(max_seen[4], 9);
}

#[test]
fn no_tail_at_the_size_limit_or_when_disabled() {
    let key = b"k";
    let mut rng = XorShift(5);
    for _ in 0..200 {
        let mut big = wg_message(1, usize::from(DUMMY_LIMIT));
        encode(&mut big, 0, key, DEFAULT_MAX_DUMMY, 0, &mut rng);
        assert_eq!(big.len(), usize::from(DUMMY_LIMIT));

        let mut data = wg_message(4, 100);
        encode(&mut data, 0, key, 0, 0, &mut rng);
        assert_eq!(data.len(), 100, "max-dummy 0 disables the transport tail");
    }
}

#[test]
fn partial_obfuscation_masks_only_the_prefix_and_adds_no_tail() {
    let key = b"k";
    let mut rng = XorShift(11);
    let msg = wg_message(4, 200);
    let mut buf = msg.clone();
    encode(&mut buf, 0, key, DEFAULT_MAX_DUMMY, 16, &mut rng);
    assert_eq!(buf.len(), msg.len());
    assert_eq!(
        &buf[16..],
        &msg[16..],
        "bytes past obfuscate-bytes are untouched"
    );
    let n = decode(&mut buf, key, 16).unwrap();
    assert_eq!(&buf[..n], &msg[..]);
}

#[test]
fn a_short_message_under_obfuscate_bytes_stays_unpartial_after_its_tail() {
    // L = 40 < R = 48: the whole thing is masked, and the tail is capped so
    // the encoded length never crosses R. Otherwise the receiver would take
    // it for a partial message and fail to decode.
    let key = b"k";
    let mut rng = XorShift(13);
    for _ in 0..500 {
        let msg = wg_message(1, 40);
        let mut buf = msg.clone();
        encode(&mut buf, 0, key, DEFAULT_MAX_DUMMY, 48, &mut rng);
        assert!(buf.len() <= 48);
        let n = decode(&mut buf, key, 48).unwrap();
        assert_eq!(&buf[..n], &msg[..]);
    }
}

#[test]
fn decode_rejects_a_tail_longer_than_the_payload() {
    let key = b"k";
    let mut buf = vec![0x04 ^ 0x55, 0x55, 0xFF, 0xFF, 1, 2, 3, 4];
    apply_keystream(&mut buf, key);
    assert_eq!(decode(&mut buf, key, 0), None);
    assert_eq!(decode(&mut [1, 2, 3], key, 0), None);
}

// --- STUN ------------------------------------------------------------------

#[test]
fn binding_request_has_a_valid_fingerprint() {
    let mut c = codec(config(Masking::Stun), 1);
    let req = c.binding_request();
    assert_eq!(&req[0..4], &[0x00, 0x01, 0x00, 0x08]);
    assert_eq!(&req[4..8], &STUN_COOKIE);
    assert_eq!(&req[20..24], &[0x80, 0x28, 0x00, 0x04]);
    // Over the header as it stood before the length was filled in.
    let mut header = [0u8; 20];
    header.copy_from_slice(&req[..20]);
    header[2..4].fill(0);
    let fp = u32::from_be_bytes(req[24..28].try_into().unwrap());
    assert_eq!(fp, crc32(&header) ^ STUN_FINGERPRINT_XOR);
    assert_ne!(
        c.binding_request()[8..20],
        req[8..20],
        "fresh transaction ID"
    );
}

#[test]
fn crc32_is_ieee() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
}

#[test]
fn a_binding_request_from_the_server_is_answered() {
    let mut c = codec(config(Masking::Stun), 1);
    let mut server_side = codec(config(Masking::Stun), 2);
    let mut req = server_side.binding_request();
    match c.unwrap(&mut req, server()) {
        Unwrapped::Reply(reply) => {
            assert_eq!(&reply[0..2], &[0x01, 0x01]);
            assert_eq!(&reply[8..20], &req[8..20], "echoes the transaction ID");
        }
        other => panic!("expected a reply, got {:?}", other),
    }
}

#[test]
fn an_ipv6_source_gets_no_reply_but_a_mapped_one_does() {
    let mut c = codec(config(Masking::Stun), 1);
    let mut req = c.binding_request();
    let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 0));
    assert!(matches!(c.unwrap(&mut req.clone(), v6), Unwrapped::Drop));
    let mapped = SocketAddr::V6(SocketAddrV6::new(
        Ipv4Addr::new(10, 0, 0, 7).to_ipv6_mapped(),
        1,
        0,
        0,
    ));
    let reply = match c.unwrap(&mut req, mapped) {
        Unwrapped::Reply(r) => r,
        other => panic!("expected a reply, got {:?}", other),
    };
    // Same bytes as for the plain IPv4 source.
    let v4 = build_binding_success(
        &req[8..20].try_into().unwrap(),
        "10.0.0.7:1".parse().unwrap(),
    );
    assert_eq!(Some(reply), v4);
}

#[test]
fn stun_control_and_malformed_datagrams_are_dropped() {
    let mut c = codec(config(Masking::Stun), 1);
    let mut success = build_binding_success(&[7; 12], server()).unwrap();
    assert!(matches!(c.unwrap(&mut success, server()), Unwrapped::Drop));

    let mut no_cookie = vec![0x01, 0x15, 0, 0, 9, 9, 9, 9, 0, 0, 0, 0];
    assert!(matches!(
        c.unwrap(&mut no_cookie, server()),
        Unwrapped::Drop
    ));

    // A Data Indication claiming more data than the datagram holds.
    let mut out = Vec::new();
    c.wrap(&wg_message(4, 64), &mut out).unwrap();
    out[22..24].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(matches!(c.unwrap(&mut out, server()), Unwrapped::Drop));

    assert!(matches!(
        c.unwrap(&mut [0, 1, 2], server()),
        Unwrapped::Drop
    ));
}

#[test]
fn plain_wireguard_from_the_network_is_dropped() {
    for masking in [Masking::None, Masking::Stun, Masking::Media] {
        let mut c = codec(config(masking), 1);
        let mut plain = wg_message(2, 92);
        assert!(matches!(c.unwrap(&mut plain, server()), Unwrapped::Drop));
    }
}

// --- Codec -------------------------------------------------------------------

#[test]
fn every_masking_round_trips_every_message_type() {
    for masking in [Masking::None, Masking::Stun, Masking::Media] {
        let mut tx = codec(config(masking), 21);
        let mut rx = codec(config(masking), 22);
        for (t, len) in [(1u8, 148), (2, 92), (3, 64), (4, 32), (4, 1420)] {
            let msg = wg_message(t, len);
            let mut out = Vec::new();
            tx.wrap(&msg, &mut out).unwrap();
            match rx.unwrap(&mut out, server()) {
                Unwrapped::WireGuard(got) => assert_eq!(got, &msg[..], "{masking:?} type {t}"),
                other => panic!("{:?} type {}: {:?}", masking, t, other),
            }
        }
    }
}

#[test]
fn stun_frame_layout() {
    let mut c = codec(config(Masking::Stun), 4);
    let mut out = Vec::new();
    c.wrap(&wg_message(4, 100), &mut out).unwrap();
    assert_eq!(&out[0..4], &[0x01, 0x15, 0x00, 0x00]);
    assert_eq!(&out[4..8], &STUN_COOKIE);
    assert_eq!(&out[20..22], &[0x00, 0x13]);
    let data_len = usize::from(u16::from_be_bytes([out[22], out[23]]));
    assert_eq!(data_len, out.len() - STUN_DATA_HEADER_LEN);
}

#[test]
fn only_an_initiation_under_stun_or_media_brings_a_binding_request() {
    for masking in [Masking::None, Masking::Stun, Masking::Media] {
        let mut c = codec(config(masking), 1);
        let mut out = Vec::new();
        for t in 1..=4u8 {
            let pre = c.wrap(&wg_message(t, 148), &mut out).unwrap();
            let expected = t == 1 && masking != Masking::None;
            assert_eq!(pre.is_some(), expected, "{masking:?} type {t}");
        }
    }
}

#[test]
fn rtp_sequence_and_timestamp_advance_with_a_stable_ssrc() {
    let mut c = config(Masking::Media);
    c.media = MediaParams {
        payload_type: 96,
        ssrc: 0xDEAD_BEEF,
        timestamp_step: 3000,
    };
    let mut codec = codec(c, 1);
    let (mut a, mut b) = (Vec::new(), Vec::new());
    codec.wrap(&wg_message(4, 64), &mut a).unwrap();
    codec.wrap(&wg_message(4, 64), &mut b).unwrap();
    assert_eq!(&a[0..2], &[0x80, 0x80 | 96]);
    let seq = |p: &[u8]| u16::from_be_bytes([p[2], p[3]]);
    let ts = |p: &[u8]| u32::from_be_bytes(p[4..8].try_into().unwrap());
    assert_eq!(seq(&b), seq(&a).wrapping_add(1));
    assert_eq!(ts(&b), ts(&a).wrapping_add(3000));
    assert_eq!(&a[8..12], &0xDEAD_BEEFu32.to_be_bytes());
    assert_eq!(&a[8..12], &b[8..12]);
}

#[test]
fn unset_media_params_come_from_one_preset() {
    for seed in 1..50 {
        let mut c = codec(config(Masking::Media), seed);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        c.wrap(&wg_message(4, 64), &mut a).unwrap();
        c.wrap(&wg_message(4, 64), &mut b).unwrap();
        let pt = a[1] & 0x7F;
        let step = u32::from_be_bytes(b[4..8].try_into().unwrap())
            .wrapping_sub(u32::from_be_bytes(a[4..8].try_into().unwrap()));
        assert!(
            MEDIA_PRESETS.contains(&(pt, step as u16)),
            "pt {} step {}",
            pt,
            step
        );
        assert_ne!(&a[8..12], &[0, 0, 0, 0], "random SSRC is non-zero");
    }
}

#[test]
fn media_enforces_a_configured_payload_type_and_ssrc() {
    let mut sender_cfg = config(Masking::Media);
    sender_cfg.media.payload_type = 100;
    sender_cfg.media.ssrc = 42;
    let mut tx = codec(sender_cfg.clone(), 1);
    let mut out = Vec::new();
    tx.wrap(&wg_message(4, 64), &mut out).unwrap();

    let mut wrong_pt = sender_cfg.clone();
    wrong_pt.media.payload_type = 101;
    assert!(matches!(
        codec(wrong_pt, 2).unwrap(&mut out.clone(), server()),
        Unwrapped::Drop
    ));

    let mut wrong_ssrc = sender_cfg.clone();
    wrong_ssrc.media.ssrc = 43;
    assert!(matches!(
        codec(wrong_ssrc, 2).unwrap(&mut out.clone(), server()),
        Unwrapped::Drop
    ));

    // Unset on the receiver: anything goes.
    assert!(matches!(
        codec(config(Masking::Media), 2).unwrap(&mut out, server()),
        Unwrapped::WireGuard(_)
    ));
}

#[test]
fn media_also_accepts_stun_framed_data() {
    // A server in `auto` answers in whatever it detected; the reference's
    // MEDIA receiver handles STUN-carrying datagrams too.
    let mut stun = config(Masking::Stun);
    stun.obfuscate_bytes = MEDIA_DEFAULT_OBFUSCATE_BYTES;
    let mut tx = codec(stun, 1);
    let msg = wg_message(2, 92);
    let mut out = Vec::new();
    tx.wrap(&msg, &mut out).unwrap();
    match codec(config(Masking::Media), 2).unwrap(&mut out, server()) {
        Unwrapped::WireGuard(got) => assert_eq!(got, &msg[..]),
        other => panic!("{:?}", other),
    }
}

#[test]
fn media_defaults_obfuscate_bytes_to_16() {
    let c = config(Masking::Media);
    assert_eq!(c.effective_obfuscate_bytes(), 16);
    let mut explicit = config(Masking::Media);
    explicit.obfuscate_bytes = 64;
    assert_eq!(explicit.effective_obfuscate_bytes(), 64);
    assert_eq!(config(Masking::Stun).effective_obfuscate_bytes(), 0);
}

#[test]
fn wrap_rejects_what_cannot_be_framed() {
    let mut c = codec(config(Masking::Stun), 1);
    let mut out = Vec::new();
    assert_eq!(c.wrap(&[1, 0, 0], &mut out), Err(WrapError::TooShort));
    assert_eq!(
        c.wrap(&wg_message(4, 65_536), &mut out),
        Err(WrapError::TooLong)
    );
}

/// The largest transport message STUN can carry is 65535 bytes: past 1024
/// it gets no tail, so its DATA length is its own length. The check used to
/// reserve 511 bytes of tail for every message and refused this one.
#[test]
fn stun_carries_a_transport_message_up_to_its_16_bit_length() {
    let mut tx = codec(config(Masking::Stun), 1);
    let mut rx = codec(config(Masking::Stun), 2);
    for len in [65_104, 65_535] {
        let msg = wg_message(4, len);
        let mut out = Vec::new();
        tx.wrap(&msg, &mut out).unwrap();
        assert_eq!(out.len(), STUN_DATA_HEADER_LEN + len);
        match rx.unwrap(&mut out, server()) {
            Unwrapped::WireGuard(got) => assert_eq!(got, &msg[..], "length {len}"),
            other => panic!("length {}: {:?}", len, other),
        }
    }
    assert_eq!(Masking::Stun.max_message_len(), Some(65_535));
    assert_eq!(Masking::Media.max_message_len(), None);
}

// --- Configuration -----------------------------------------------------------

#[test]
fn set_accepts_the_reference_spellings_and_ranges() {
    let mut c = PhobosConfig::new(b"x".to_vec()).unwrap();
    assert!(c.set("key", "  spaced key \n").unwrap());
    assert_eq!(c.key(), b"spaced key");
    assert!(c.set("masking", "STUN").unwrap());
    assert_eq!(c.masking, Masking::Stun);
    assert!(c.set("max-dummy", "1024").unwrap());
    assert!(c.set("max-dummy", "1025").is_err());
    assert!(c.set("obfuscate-bytes", "2147483647").unwrap());
    assert!(c.set("obfuscate-bytes", "-1").is_err());
    assert!(c.set("media-pt", "127").unwrap());
    assert!(c.set("media-pt", "128").is_err());
    assert!(c.set("media-clock", "30").unwrap());
    assert_eq!(c.media.timestamp_step, 3000);
    assert!(c.set("media-clock", "0").unwrap());
    assert_eq!(c.media.timestamp_step, 0);
    assert!(c.set("media-clock", "1001").is_err());
    assert!(c.set("max-dummy", "4x").is_err());
    // Belongs to the caller, not the codec.
    assert!(!c.set("target", "203.0.113.9:51822").unwrap());
    assert!(!c.set("source-lport", "13255").unwrap());
}

#[test]
fn auto_and_tls_mask_nothing_on_udp() {
    for v in ["auto", "AUTO", "tls", "none", " None "] {
        assert_eq!(Masking::parse(v).unwrap(), Masking::None, "{v}");
    }
    assert_eq!(Masking::parse("media").unwrap(), Masking::Media);
    assert!(Masking::parse("quic").is_err());
}

#[test]
fn ssrc_parses_like_strtoul_base_zero() {
    assert_eq!(parse_ssrc("3735928559").unwrap(), 0xDEAD_BEEF);
    assert_eq!(parse_ssrc("0xDEADBEEF").unwrap(), 0xDEAD_BEEF);
    assert_eq!(parse_ssrc("010").unwrap(), 8);
    assert_eq!(parse_ssrc("0").unwrap(), 0);
    assert!(parse_ssrc("4294967296").is_err());
    assert!(parse_ssrc("12ab").is_err());
}

#[test]
fn keys_are_bounded_and_kept_as_text() {
    assert!(PhobosConfig::new(Vec::new()).is_err());
    assert!(PhobosConfig::new(vec![b'a'; MAX_KEY_LEN]).is_ok());
    assert!(PhobosConfig::new(vec![b'a'; MAX_KEY_LEN + 1]).is_err());
    // Base64-looking keys are not decoded.
    let c = PhobosConfig::new(b"QUJD".to_vec()).unwrap();
    assert_eq!(c.key(), b"QUJD");
}

#[test]
fn debug_output_redacts_the_key() {
    let c = PhobosConfig::new(b"very-secret".to_vec()).unwrap();
    let shown = format!("{c:?} {:?}", PhobosCodec::new(c.clone()).unwrap());
    assert!(!shown.contains("very-secret"), "{}", shown);
}

#[test]
fn a_directly_edited_config_is_validated_by_the_codec() {
    let mut c = config(Masking::None);
    c.max_dummy = 2000;
    assert!(PhobosCodec::new(c).is_err());
}
