//! Phobos UDP obfuscation, client side.
//!
//! [Phobos](https://github.com/Ground-Zerro/Phobos) puts an obfuscating proxy
//! in front of a standard WireGuard server. Each WireGuard message is XORed
//! with a key-derived keystream, gets a random tail, and is framed as a STUN
//! Data Indication or an RTP packet. This module is that transformation for a
//! client. It owns no socket and no timer, and it has no tie to [`Tunn`]: the
//! caller runs every outgoing datagram through [`PhobosCodec::wrap`] and every
//! incoming one through [`PhobosCodec::unwrap`].
//!
//! The wire format is specified in `docs/phobos.md`, and this module is
//! written from that document. Don't port code from the Phobos tree: it is
//! (A)GPL-licensed and awgtun is BSD-3-Clause.
//!
//! # Not combinable with AmneziaWG
//!
//! A Phobos server forwards to plain kernel WireGuard, and its decoder relies
//! on bytes 1–3 of every WireGuard message being zero. Use Phobos with a
//! [`Tunn`] built by [`Tunn::new`], never `new_with_amnezia*`.
//!
//! # What the caller must do
//!
//! - Send the Binding Request that [`PhobosCodec::wrap`] returns *before* the
//!   wrapped datagram.
//! - Send [`Unwrapped::Reply`] back to the peer.
//! - Every [`PhobosCodec::control_interval`], send
//!   [`PhobosCodec::binding_request`].
//! - After the local address changes, start a new handshake rather than
//!   sending a keepalive. The server drops non-handshake traffic from an
//!   address it has not seen complete a handshake.
//! - Lower the tunnel MTU by [`Masking::overhead`].
//!
//! [`Tunn`]: crate::noise::Tunn
//! [`Tunn::new`]: crate::noise::Tunn::new

use std::convert::TryInto;
use std::fmt;
use std::net::SocketAddr;
use std::time::Duration;

use crate::amnezia::{ConfigError, FastRandom, RandomSource};

#[cfg(test)]
mod test_vectors;

/// Longest key the reference accepts. Its key buffer is 256 bytes including
/// the terminating NUL.
pub const MAX_KEY_LEN: usize = 255;
/// `max-dummy` when unset.
pub const DEFAULT_MAX_DUMMY: u16 = 4;
/// Largest `max-dummy` the reference accepts, and the size from which no
/// message gets a random tail.
pub const DUMMY_LIMIT: u16 = 1024;
/// Exclusive upper bound on a handshake message's random tail.
const HANDSHAKE_DUMMY_LIMIT: u16 = 512;
/// Effective `obfuscate-bytes` under [`Masking::Media`] when it is left at 0.
pub const MEDIA_DEFAULT_OBFUSCATE_BYTES: u32 = 16;

/// Length of a STUN Binding Request, as [`PhobosCodec::binding_request`]
/// builds it.
pub const BINDING_REQUEST_LEN: usize = 28;
/// Length of a STUN Binding Success Response, as [`Unwrapped::Reply`]
/// carries it.
pub const BINDING_SUCCESS_LEN: usize = 40;

const STUN_HEADER_LEN: usize = 20;
const STUN_DATA_HEADER_LEN: usize = 24;
const RTP_HEADER_LEN: usize = 12;
const STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_SUCCESS: u16 = 0x0101;
const STUN_DATA_INDICATION: u16 = 0x0115;
const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const STUN_ATTR_FINGERPRINT: u16 = 0x8028;
const STUN_ATTR_DATA: u16 = 0x0013;
const STUN_FINGERPRINT_XOR: u32 = 0x5354_554E;

/// WireGuard handshake initiation, as a little-endian `u32` type field.
const WG_HANDSHAKE_INITIATION: u32 = 1;

/// `(payload type, timestamp step)` pairs a [`Masking::Media`] stream draws
/// from for whichever of `media-pt` / `media-clock` is unset.
const MEDIA_PRESETS: [(u8, u16); 50] = [
    (96, 3000),
    (96, 3600),
    (96, 3750),
    (96, 1500),
    (96, 6000),
    (97, 3000),
    (97, 3600),
    (97, 4500),
    (97, 9000),
    (97, 18000),
    (98, 3000),
    (98, 3600),
    (98, 3750),
    (98, 1500),
    (98, 6000),
    (99, 3000),
    (99, 3600),
    (100, 3000),
    (100, 1500),
    (100, 3750),
    (102, 3000),
    (102, 1500),
    (102, 3600),
    (104, 3000),
    (104, 1500),
    (106, 3000),
    (106, 3750),
    (108, 3000),
    (108, 1500),
    (110, 3000),
    (112, 3000),
    (112, 3600),
    (114, 3000),
    (114, 1500),
    (116, 3000),
    (118, 3000),
    (119, 3000),
    (120, 3000),
    (122, 3000),
    (123, 3000),
    (124, 3000),
    (125, 3000),
    (125, 1500),
    (126, 3000),
    (127, 3000),
    (127, 1500),
    (127, 3750),
    (96, 1502),
    (96, 3003),
    (97, 3753),
];

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// The cover protocol a datagram is framed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Masking {
    /// No frame and no control traffic.
    #[default]
    None,
    /// STUN Data Indication framing, with a Binding exchange every 10 s.
    Stun,
    /// RTP framing, with a STUN Binding exchange every 5 s.
    Media,
}

impl Masking {
    /// Parse a `masking` value, the way the reference does.
    ///
    /// `auto` and `tls` are accepted and mean [`Masking::None`]. `auto` is the
    /// server identifying each client's masking: a client set to `auto` frames
    /// nothing. `tls` only applies to the reference's SOCKS5/TCP presets, and
    /// on UDP it frames nothing either.
    pub fn parse(value: &str) -> Result<Self, ConfigError> {
        match value.trim().to_ascii_lowercase().as_str() {
            "none" | "auto" | "tls" => Ok(Masking::None),
            "stun" => Ok(Masking::Stun),
            "media" => Ok(Masking::Media),
            _ => Err(ConfigError::InvalidFieldValue {
                field: "masking".into(),
                reason: "expected none, stun, media, auto or tls",
            }),
        }
    }

    /// Bytes the frame adds in front of every payload. The tunnel MTU
    /// must be lowered by this much.
    pub fn overhead(self) -> usize {
        match self {
            Masking::None => 0,
            Masking::Stun => STUN_DATA_HEADER_LEN,
            Masking::Media => RTP_HEADER_LEN,
        }
    }

    /// How often to send a STUN Binding Request, if at all.
    pub fn control_interval(self) -> Option<Duration> {
        match self {
            Masking::None => None,
            Masking::Stun => Some(Duration::from_secs(10)),
            Masking::Media => Some(Duration::from_secs(5)),
        }
    }

    /// The longest WireGuard message this masking can carry, if it has a
    /// limit of its own. A caller sizing its MTU against it must count the
    /// whole message: tunnel MTU plus WireGuard's 32 bytes of overhead.
    ///
    /// Only STUN has one: its DATA length is 16 bits. Encoding never pushes
    /// a message over it, because a message gets a random tail only while
    /// it is under 1024 bytes ([`DUMMY_LIMIT`]), so the encoded payload is
    /// either under 1024 bytes or exactly the message's length.
    pub fn max_message_len(self) -> Option<usize> {
        match self {
            Masking::Stun => Some(usize::from(u16::MAX)),
            Masking::None | Masking::Media => None,
        }
    }
}

/// RTP stream parameters for [`Masking::Media`]. Zero means "pick at random".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MediaParams {
    /// RTP payload type, 0–127. Enforced on receive when non-zero.
    pub payload_type: u8,
    /// RTP SSRC. Enforced on receive when non-zero.
    pub ssrc: u32,
    /// RTP timestamp increment per frame, `90000 / media-clock`.
    pub timestamp_step: u16,
}

/// A Phobos client configuration, for one server preset.
///
/// `Debug` redacts the key: like an AmneziaWG parameter set, it identifies a
/// deployment.
#[derive(Clone, PartialEq, Eq)]
pub struct PhobosConfig {
    key: Vec<u8>,
    /// Cover protocol.
    pub masking: Masking,
    /// Exclusive upper bound on the random tail of cookie and transport
    /// messages. 0 disables it for those. At most [`DUMMY_LIMIT`].
    pub max_dummy: u16,
    /// XOR only the first this-many bytes of each payload. 0 means all of it,
    /// or [`MEDIA_DEFAULT_OBFUSCATE_BYTES`] under [`Masking::Media`]. Kept
    /// at most `i32::MAX`, as the reference parses it.
    pub obfuscate_bytes: u32,
    /// RTP parameters, used under [`Masking::Media`] only.
    pub media: MediaParams,
}

impl fmt::Debug for PhobosConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhobosConfig")
            .field("key", &format_args!("<{} bytes redacted>", self.key.len()))
            .field("masking", &self.masking)
            .field("max_dummy", &self.max_dummy)
            .field("obfuscate_bytes", &self.obfuscate_bytes)
            .field("media", &self.media)
            .finish()
    }
}

impl PhobosConfig {
    /// A configuration with the reference's defaults and the given key.
    ///
    /// The key is used as raw bytes. A Phobos key that looks like base64 is
    /// still used as the base64 *text*, not decoded.
    pub fn new(key: impl Into<Vec<u8>>) -> Result<Self, ConfigError> {
        let key = key.into();
        validate_key(&key)?;
        Ok(PhobosConfig {
            key,
            masking: Masking::None,
            max_dummy: DEFAULT_MAX_DUMMY,
            obfuscate_bytes: 0,
            media: MediaParams::default(),
        })
    }

    /// The shared key.
    pub fn key(&self) -> &[u8] {
        &self.key
    }

    /// Replace the shared key.
    pub fn set_key(&mut self, key: impl Into<Vec<u8>>) -> Result<(), ConfigError> {
        let key = key.into();
        validate_key(&key)?;
        self.key = key;
        Ok(())
    }

    /// Apply one `name = value` line from a Phobos configuration section,
    /// using the reference's key spellings and accepted ranges.
    ///
    /// Returns `Ok(false)` for a name the codec does not use (`target`,
    /// `source-lport`, `idle-timeout` and the like). Those belong to the
    /// caller, so a whole section can be fed through here.
    pub fn set(&mut self, name: &str, value: &str) -> Result<bool, ConfigError> {
        let value = value.trim();
        match name.trim() {
            "key" => self.set_key(value.as_bytes())?,
            "masking" => self.masking = Masking::parse(value)?,
            "max-dummy" => {
                self.max_dummy = parse_int(name, value, 0, i64::from(DUMMY_LIMIT))? as u16
            }
            "obfuscate-bytes" => {
                self.obfuscate_bytes = parse_int(name, value, 0, i64::from(i32::MAX))? as u32
            }
            "media-pt" => self.media.payload_type = parse_int(name, value, 0, 127)? as u8,
            "media-ssrc" => self.media.ssrc = parse_ssrc(value)?,
            "media-clock" => {
                let fps = parse_int(name, value, 0, 1000)?;
                self.media.timestamp_step = if fps == 0 { 0 } else { (90_000 / fps) as u16 };
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Check the fields a caller may have set directly.
    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_key(&self.key)?;
        if self.max_dummy > DUMMY_LIMIT {
            return Err(ConfigError::InvalidFieldValue {
                field: "max-dummy".into(),
                reason: "must be between 0 and 1024",
            });
        }
        if self.obfuscate_bytes > i32::MAX as u32 {
            return Err(ConfigError::InvalidFieldValue {
                field: "obfuscate-bytes".into(),
                reason: "must be between 0 and 2147483647",
            });
        }
        if self.media.payload_type > 127 {
            return Err(ConfigError::InvalidFieldValue {
                field: "media-pt".into(),
                reason: "must be between 0 and 127",
            });
        }
        Ok(())
    }

    /// The `obfuscate-bytes` value actually applied, after the
    /// [`Masking::Media`] default.
    pub fn effective_obfuscate_bytes(&self) -> u32 {
        if self.obfuscate_bytes == 0 && self.masking == Masking::Media {
            MEDIA_DEFAULT_OBFUSCATE_BYTES
        } else {
            self.obfuscate_bytes
        }
    }
}

fn validate_key(key: &[u8]) -> Result<(), ConfigError> {
    if key.is_empty() {
        return Err(ConfigError::InvalidFieldValue {
            field: "key".into(),
            reason: "must not be empty",
        });
    }
    if key.len() > MAX_KEY_LEN {
        return Err(ConfigError::InvalidFieldValue {
            field: "key".into(),
            reason: "must be at most 255 bytes",
        });
    }
    Ok(())
}

fn parse_int(name: &str, value: &str, min: i64, max: i64) -> Result<i64, ConfigError> {
    match value.parse::<i64>() {
        Ok(v) if (min..=max).contains(&v) => Ok(v),
        Ok(_) => Err(ConfigError::InvalidFieldValue {
            field: name.trim().into(),
            reason: "out of range",
        }),
        Err(_) => Err(ConfigError::InvalidFieldValue {
            field: name.trim().into(),
            reason: "must be an integer",
        }),
    }
}

/// `media-ssrc` takes a C-style integer: `0x` hex, leading-`0` octal, or
/// decimal.
///
/// The reference stores it in a `uint32_t` and silently truncates a larger
/// value. This rejects one instead, since it can only be a typo.
fn parse_ssrc(value: &str) -> Result<u32, ConfigError> {
    let parsed = if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        u32::from_str_radix(hex, 16)
    } else if value.len() > 1 && value.starts_with('0') {
        u32::from_str_radix(&value[1..], 8)
    } else {
        value.parse::<u32>()
    };
    parsed.map_err(|_| ConfigError::InvalidFieldValue {
        field: "media-ssrc".into(),
        reason: "must be a 32-bit unsigned integer",
    })
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// CRC-8, reflected polynomial 0x8C, one entry per input byte.
const CRC8: [u8; 256] = {
    let mut table = [0u8; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = 0u8;
        let mut byte = i as u8;
        let mut bit = 0;
        while bit < 8 {
            let mix = (crc ^ byte) & 1;
            crc >>= 1;
            if mix != 0 {
                crc ^= 0x8C;
            }
            byte >>= 1;
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

/// CRC-32/IEEE (reflected 0xEDB88320), for the STUN FINGERPRINT attribute.
const CRC32: [u32; 256] = {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
};

fn crc32(data: &[u8]) -> u32 {
    !data.iter().fold(!0u32, |crc, &b| {
        CRC32[((crc ^ u32::from(b)) & 0xFF) as usize] ^ (crc >> 8)
    })
}

/// XOR `buf` with the keystream for a region of `buf.len()` bytes.
///
/// The keystream depends on the region's length as well as the key, so
/// applying it to a prefix is not the same as applying it to the whole buffer
/// and truncating.
///
/// # Panics
/// If `key` is empty or longer than [`MAX_KEY_LEN`]. A [`PhobosConfig`]
/// never holds such a key.
pub fn apply_keystream(buf: &mut [u8], key: &[u8]) {
    assert!(!key.is_empty() && key.len() <= MAX_KEY_LEN);
    // Truncating casts are the specification: `(n + k) mod 256`.
    let base = buf.len().wrapping_add(key.len()) as u8;
    let mut adjusted = [0u8; MAX_KEY_LEN];
    let adjusted = &mut adjusted[..key.len()];
    for (a, &k) in adjusted.iter_mut().zip(key) {
        *a = k.wrapping_add(base);
    }
    let mut crc = 0u8;
    for (byte, &a) in buf.iter_mut().zip(adjusted.iter().cycle()) {
        crc = CRC8[usize::from(crc ^ a)];
        *byte ^= crc;
    }
}

/// Whether the first four bytes are a plain WireGuard type field: 1–4
/// little-endian, with bytes 1–3 zero.
fn looks_plain(buf: &[u8]) -> bool {
    buf.len() >= 4 && (1..=4).contains(&buf[0]) && buf[1] == 0 && buf[2] == 0 && buf[3] == 0
}

/// Encode the WireGuard message at `buf[start..]` in place, appending its
/// random tail. `buf.len() - start` must be at least 4.
fn encode(
    buf: &mut Vec<u8>,
    start: usize,
    key: &[u8],
    max_dummy: u16,
    obfuscate_bytes: u32,
    rng: &mut impl RandomSource,
) {
    let len = buf.len() - start;
    debug_assert!(len >= 4);
    let ob = obfuscate_bytes as usize;
    let partial = ob > 0 && ob < len;
    let msg_type = u32::from_le_bytes([buf[start], buf[start + 1], buf[start + 2], buf[start + 3]]);

    let r = rng.gen_range_u32(1, 255) as u8;
    buf[start] ^= r;
    buf[start + 1] = r;

    let mut dummy = 0u16;
    if !partial && len < usize::from(DUMMY_LIMIT) {
        let mut room = DUMMY_LIMIT - len as u16;
        if ob > 0 {
            // Not partial, so `ob >= len` and this is at least 1. Keeps the
            // encoded length at most `ob`, so the receiver also sees a
            // non-partial message.
            let partial_room = ob - len + 1;
            if partial_room < usize::from(room) {
                room = partial_room as u16;
            }
        }
        let bound = match msg_type {
            1 | 2 => room.min(HANDSHAKE_DUMMY_LIMIT),
            3 | 4 if max_dummy > 0 => room.min(max_dummy),
            _ => 0,
        };
        if bound > 0 {
            dummy = rng.gen_range_u16(0, bound - 1);
        }
    }
    buf[start + 2..start + 4].copy_from_slice(&dummy.to_le_bytes());
    if dummy > 0 {
        let old = buf.len();
        buf.resize(old + usize::from(dummy), 0);
        rng.fill_bytes(&mut buf[old..]);
    }

    let payload = &mut buf[start..];
    let masked = if partial { ob } else { payload.len() };
    apply_keystream(&mut payload[..masked], key);
}

/// Decode a payload in place. Returns the WireGuard message's length, or
/// `None` if the payload is malformed.
///
/// A payload that unmasks to something already plain is returned whole: the
/// sender never encoded it. This mirrors the reference.
pub fn decode(payload: &mut [u8], key: &[u8], obfuscate_bytes: u32) -> Option<usize> {
    let len = payload.len();
    if len < 4 {
        return None;
    }
    let ob = obfuscate_bytes as usize;
    let masked = if ob > 0 && ob < len { ob } else { len };
    apply_keystream(&mut payload[..masked], key);
    if looks_plain(payload) {
        return Some(len);
    }
    payload[0] ^= payload[1];
    let dummy = usize::from(u16::from_le_bytes([payload[2], payload[3]]));
    payload[1..4].fill(0);
    len.checked_sub(dummy).filter(|&n| n >= 4)
}

// ---------------------------------------------------------------------------
// STUN
// ---------------------------------------------------------------------------

fn write_stun_header(out: &mut [u8], msg_type: u16, msg_len: u16, txid: &[u8; 12]) {
    out[0..2].copy_from_slice(&msg_type.to_be_bytes());
    out[2..4].copy_from_slice(&msg_len.to_be_bytes());
    out[4..8].copy_from_slice(&STUN_COOKIE);
    out[8..20].copy_from_slice(txid);
}

/// Append a FINGERPRINT attribute at `packet[at..at + 8]`, then set the
/// header's message length to cover everything after the header.
///
/// The CRC is taken over `packet[..at]` while the message-length field is
/// still **zero**: the reference writes the length afterwards. RFC 5389
/// computes it with the final length, so a strict STUN parser would reject
/// these fingerprints, but the reference's vectors pin this order.
fn finish_with_fingerprint(packet: &mut [u8], at: usize) {
    packet[2..4].fill(0);
    let fp = crc32(&packet[..at]) ^ STUN_FINGERPRINT_XOR;
    packet[at..at + 2].copy_from_slice(&STUN_ATTR_FINGERPRINT.to_be_bytes());
    packet[at + 2..at + 4].copy_from_slice(&4u16.to_be_bytes());
    packet[at + 4..at + 8].copy_from_slice(&fp.to_be_bytes());
    let msg_len = (at + 8 - STUN_HEADER_LEN) as u16;
    packet[2..4].copy_from_slice(&msg_len.to_be_bytes());
}

fn build_binding_request(txid: &[u8; 12]) -> [u8; BINDING_REQUEST_LEN] {
    let mut out = [0u8; BINDING_REQUEST_LEN];
    write_stun_header(&mut out, STUN_BINDING_REQUEST, 0, txid);
    finish_with_fingerprint(&mut out, STUN_HEADER_LEN);
    out
}

/// The reply to a Binding Request from `source`, or `None` for an IPv6
/// source, which the reference does not answer.
fn build_binding_success(txid: &[u8; 12], source: SocketAddr) -> Option<[u8; BINDING_SUCCESS_LEN]> {
    let ip = match source {
        SocketAddr::V4(v4) => *v4.ip(),
        SocketAddr::V6(v6) => v6.ip().to_ipv4_mapped()?,
    };
    let mut out = [0u8; BINDING_SUCCESS_LEN];
    write_stun_header(&mut out, STUN_BINDING_SUCCESS, 0, txid);
    out[20..22].copy_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    out[22..24].copy_from_slice(&8u16.to_be_bytes());
    out[24] = 0;
    out[25] = 0x01;
    let port = source.port().to_be_bytes();
    out[26] = port[0] ^ STUN_COOKIE[0];
    out[27] = port[1] ^ STUN_COOKIE[1];
    for (i, b) in ip.octets().iter().enumerate() {
        out[28 + i] = b ^ STUN_COOKIE[i];
    }
    finish_with_fingerprint(&mut out, 32);
    Some(out)
}

enum StunOutcome {
    /// The payload is `datagram[24..24 + len]`.
    Data(usize),
    Reply([u8; BINDING_SUCCESS_LEN]),
    Drop,
}

/// Handle a datagram that carries the STUN magic cookie.
fn handle_stun(datagram: &[u8], source: SocketAddr) -> StunOutcome {
    let n = datagram.len();
    match u16::from_be_bytes([datagram[0], datagram[1]]) {
        STUN_BINDING_REQUEST => {
            if n < STUN_HEADER_LEN {
                return StunOutcome::Drop;
            }
            let txid: [u8; 12] = datagram[8..20].try_into().expect("12-byte slice");
            match build_binding_success(&txid, source) {
                Some(reply) => StunOutcome::Reply(reply),
                None => StunOutcome::Drop,
            }
        }
        STUN_DATA_INDICATION => {
            if n < STUN_DATA_HEADER_LEN {
                return StunOutcome::Drop;
            }
            let msg_len = usize::from(u16::from_be_bytes([datagram[2], datagram[3]]));
            let attr = u16::from_be_bytes([datagram[20], datagram[21]]);
            let data_len = usize::from(u16::from_be_bytes([datagram[22], datagram[23]]));
            if msg_len + STUN_HEADER_LEN > n
                || attr != STUN_ATTR_DATA
                || data_len + STUN_DATA_HEADER_LEN > n
            {
                return StunOutcome::Drop;
            }
            StunOutcome::Data(data_len)
        }
        // Binding Success and anything else carry nothing for WireGuard.
        _ => StunOutcome::Drop,
    }
}

fn has_stun_cookie(datagram: &[u8]) -> bool {
    datagram.len() >= 8 && datagram[4..8] == STUN_COOKIE
}

// ---------------------------------------------------------------------------
// RTP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
struct RtpStream {
    sequence: u16,
    timestamp: u32,
    ssrc: u32,
    timestamp_step: u16,
    payload_type: u8,
}

impl RtpStream {
    fn new(params: MediaParams, rng: &mut impl RandomSource) -> Self {
        let sequence = rng.gen_range_u16(0, u16::MAX);
        let timestamp = rng.gen_range_u32(0, u32::MAX);
        let ssrc = if params.ssrc != 0 {
            params.ssrc
        } else {
            rng.gen_range_u32(1, u32::MAX)
        };
        let (preset_pt, preset_step) =
            MEDIA_PRESETS[rng.gen_range_u32(0, MEDIA_PRESETS.len() as u32 - 1) as usize];
        RtpStream {
            sequence,
            timestamp,
            ssrc,
            timestamp_step: if params.timestamp_step != 0 {
                params.timestamp_step
            } else {
                preset_step
            },
            payload_type: if params.payload_type != 0 {
                params.payload_type
            } else {
                preset_pt
            },
        }
    }

    fn write_header(&mut self, out: &mut [u8]) {
        out[0] = 0x80;
        out[1] = 0x80 | (self.payload_type & 0x7F);
        out[2..4].copy_from_slice(&self.sequence.to_be_bytes());
        out[4..8].copy_from_slice(&self.timestamp.to_be_bytes());
        out[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
        self.sequence = self.sequence.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(u32::from(self.timestamp_step));
    }
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/// Why [`PhobosCodec::wrap`] refused a datagram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WrapError {
    /// Shorter than a WireGuard type field (4 bytes).
    TooShort,
    /// Too long for a STUN DATA attribute's 16-bit length.
    TooLong,
}

impl fmt::Display for WrapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WrapError::TooShort => f.write_str("datagram shorter than a WireGuard header"),
            WrapError::TooLong => f.write_str("datagram too long for a STUN DATA attribute"),
        }
    }
}

impl std::error::Error for WrapError {}

/// What [`PhobosCodec::unwrap`] found in a datagram.
#[derive(Debug)]
pub enum Unwrapped<'a> {
    /// A WireGuard message, decoded in place inside the datagram buffer.
    /// Pass it to `Tunn::decapsulate`.
    WireGuard(&'a mut [u8]),
    /// A STUN Binding Success Response to send back to the peer. Nothing is
    /// delivered to WireGuard.
    Reply([u8; BINDING_SUCCESS_LEN]),
    /// Control traffic needing no answer, or a malformed datagram.
    Drop,
}

/// The Phobos transformation for one tunnel, client side.
///
/// Holds the configuration, a random source and, under [`Masking::Media`],
/// the outgoing RTP stream's counters. It is `Send` but not shared: keep one
/// per tunnel, behind the same lock as whatever sends on its socket, so RTP
/// sequence numbers go out in order.
pub struct PhobosCodec<R = FastRandom> {
    config: PhobosConfig,
    obfuscate_bytes: u32,
    rng: R,
    rtp: Option<RtpStream>,
}

impl<R> fmt::Debug for PhobosCodec<R> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhobosCodec")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl PhobosCodec<FastRandom> {
    /// A codec drawing randomness from awgtun's per-thread ChaCha20 stream.
    pub fn new(config: PhobosConfig) -> Result<Self, ConfigError> {
        Self::with_rng(config, FastRandom)
    }
}

impl<R: RandomSource> PhobosCodec<R> {
    /// A codec with an injected random source, for deterministic tests.
    pub fn with_rng(config: PhobosConfig, rng: R) -> Result<Self, ConfigError> {
        config.validate()?;
        Ok(PhobosCodec {
            obfuscate_bytes: config.effective_obfuscate_bytes(),
            config,
            rng,
            rtp: None,
        })
    }

    /// The configuration this codec was built with.
    pub fn config(&self) -> &PhobosConfig {
        &self.config
    }

    /// How often to send [`binding_request`](Self::binding_request), if at all.
    pub fn control_interval(&self) -> Option<Duration> {
        self.config.masking.control_interval()
    }

    /// Wrap one outgoing WireGuard datagram into `out`, replacing its
    /// contents.
    ///
    /// Returns a STUN Binding Request when `datagram` is a handshake
    /// initiation and the masking has control traffic. Send it *before*
    /// `out`, as the reference does.
    pub fn wrap(
        &mut self,
        datagram: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<Option<[u8; BINDING_REQUEST_LEN]>, WrapError> {
        if datagram.len() < 4 {
            return Err(WrapError::TooShort);
        }
        let masking = self.config.masking;
        let header = masking.overhead();
        // Checked before doing any work. See `max_message_len` for why the
        // input's own length is the bound, tail included.
        if masking
            .max_message_len()
            .is_some_and(|max| datagram.len() > max)
        {
            return Err(WrapError::TooLong);
        }

        let is_initiation =
            u32::from_le_bytes([datagram[0], datagram[1], datagram[2], datagram[3]])
                == WG_HANDSHAKE_INITIATION;
        let preamble = if is_initiation && masking.control_interval().is_some() {
            Some(self.binding_request())
        } else {
            None
        };

        out.clear();
        out.reserve(header + datagram.len() + usize::from(HANDSHAKE_DUMMY_LIMIT));
        out.resize(header, 0);
        out.extend_from_slice(datagram);
        encode(
            out,
            header,
            &self.config.key,
            self.config.max_dummy,
            self.obfuscate_bytes,
            &mut self.rng,
        );
        let payload_len = out.len() - header;

        match masking {
            Masking::None => {}
            Masking::Stun => {
                let mut txid = [0u8; 12];
                self.rng.fill_bytes(&mut txid);
                // The message-length field stays 0, as the reference sends it.
                write_stun_header(out, STUN_DATA_INDICATION, 0, &txid);
                out[20..22].copy_from_slice(&STUN_ATTR_DATA.to_be_bytes());
                out[22..24].copy_from_slice(&(payload_len as u16).to_be_bytes());
            }
            Masking::Media => {
                let params = self.config.media;
                let rng = &mut self.rng;
                self.rtp
                    .get_or_insert_with(|| RtpStream::new(params, rng))
                    .write_header(out);
            }
        }
        Ok(preamble)
    }

    /// Unwrap one incoming datagram from `source`, in place.
    ///
    /// Malformed datagrams come back as [`Unwrapped::Drop`]: their contents
    /// are chosen by whoever sent them, so nothing here is an error.
    pub fn unwrap<'a>(&mut self, datagram: &'a mut [u8], source: SocketAddr) -> Unwrapped<'a> {
        let n = datagram.len();
        // A plain-looking datagram was never encoded, and the reference never
        // delivers one intact. See "Receive order" in docs/phobos.md.
        if n < 4 || looks_plain(datagram) {
            return Unwrapped::Drop;
        }
        let (offset, len) = match self.config.masking {
            Masking::None => (0, n),
            Masking::Stun => {
                if !has_stun_cookie(datagram) {
                    return Unwrapped::Drop;
                }
                match handle_stun(datagram, source) {
                    StunOutcome::Data(len) => (STUN_DATA_HEADER_LEN, len),
                    StunOutcome::Reply(reply) => return Unwrapped::Reply(reply),
                    StunOutcome::Drop => return Unwrapped::Drop,
                }
            }
            Masking::Media => {
                if has_stun_cookie(datagram) {
                    match handle_stun(datagram, source) {
                        StunOutcome::Data(len) => (STUN_DATA_HEADER_LEN, len),
                        StunOutcome::Reply(reply) => return Unwrapped::Reply(reply),
                        StunOutcome::Drop => return Unwrapped::Drop,
                    }
                } else {
                    let media = self.config.media;
                    if n < RTP_HEADER_LEN + 4
                        || datagram[0] & 0xC0 != 0x80
                        || (media.payload_type != 0 && datagram[1] & 0x7F != media.payload_type)
                        || (media.ssrc != 0 && datagram[8..12] != media.ssrc.to_be_bytes())
                    {
                        return Unwrapped::Drop;
                    }
                    (RTP_HEADER_LEN, n - RTP_HEADER_LEN)
                }
            }
        };
        if len < 4 {
            return Unwrapped::Drop;
        }
        let payload = &mut datagram[offset..offset + len];
        match decode(payload, &self.config.key, self.obfuscate_bytes) {
            Some(m) => Unwrapped::WireGuard(&mut payload[..m]),
            None => Unwrapped::Drop,
        }
    }

    /// A STUN Binding Request with a fresh transaction ID, for the periodic
    /// control traffic.
    pub fn binding_request(&mut self) -> [u8; BINDING_REQUEST_LEN] {
        let mut txid = [0u8; 12];
        self.rng.fill_bytes(&mut txid);
        build_binding_request(&txid)
    }
}

#[cfg(test)]
mod tests;
