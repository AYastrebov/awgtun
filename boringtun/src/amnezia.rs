// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! AmneziaWG 2.0 configuration and packet generation.
//!
//! This module intentionally models only the AmneziaWG 2.0 fields. Legacy
//! 1.0/1.5-only aliases are rejected by name.

use std::fmt;
use std::num::ParseIntError;
use std::time::{SystemTime, UNIX_EPOCH};

pub const AWG2_MAX_HANDSHAKE_PADDING: u8 = 64;
pub const AWG2_MAX_TRANSPORT_PADDING: u8 = 32;
pub const AWG2_MAX_JUNK_COUNT: u8 = 10;
pub const AWG2_MIN_JUNK_SIZE: u16 = 64;
pub const AWG2_MAX_JUNK_SIZE: u16 = 1024;
pub const AWG2_MAX_CPS_RANDOM_LEN: usize = 1000;

const STANDARD_WIREGUARD_HEADERS: [u32; 4] = [1, 2, 3, 4];

// ---------------------------------------------------------------------------
// RandomSource — injectable RNG for deterministic testing
// ---------------------------------------------------------------------------

/// Trait for injectable randomness. Production uses `OsRandom`; tests use a
/// deterministic implementation.
pub trait RandomSource {
    fn fill_bytes(&mut self, out: &mut [u8]);

    /// Generate a random `u32` in `[start, end]` (inclusive).
    fn gen_range_u32(&mut self, start: u32, end: u32) -> u32 {
        if start == end {
            return start;
        }
        let range = end - start + 1;
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        let raw = u32::from_le_bytes(buf);
        start + (raw % range)
    }

    /// Generate a random `u16` in `[start, end]` (inclusive).
    fn gen_range_u16(&mut self, start: u16, end: u16) -> u16 {
        self.gen_range_u32(u32::from(start), u32::from(end)) as u16
    }
}

/// Production random source backed by the OS CSPRNG.
#[derive(Debug, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(out);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConfigError {
    InvalidHeaderRange {
        value: String,
        reason: &'static str,
    },
    HeaderRangesOverlap {
        first: HeaderKind,
        second: HeaderKind,
    },
    StandardHeaderValue {
        header: HeaderKind,
        value: u32,
    },
    PaddingOutOfRange {
        field: PaddingKind,
        value: u8,
        max: u8,
    },
    JunkCountOutOfRange {
        value: u8,
        max: u8,
    },
    JunkSizeOutOfRange {
        field: JunkSizeKind,
        value: u16,
        min: u16,
        max: u16,
    },
    JunkMinExceedsMax {
        min: u16,
        max: u16,
    },
    JunkExceedsMtu {
        max_size: u16,
        mtu: usize,
    },
    InvalidCps {
        reason: String,
    },
    UnsupportedCpsTag {
        tag: String,
    },
    CpsValueOutOfRange {
        tag: &'static str,
        value: usize,
        max: usize,
    },
    InitPacketRequiresI1 {
        field: InitPacketKind,
    },
    InitPacketGap {
        missing: InitPacketKind,
        present: InitPacketKind,
    },
    UnsupportedLegacyField {
        field: String,
    },
    InvalidRange {
        value: String,
        reason: &'static str,
    },
    HeaderProtectionPaddingTooSmall {
        field: PaddingKind,
        value: u8,
        min: u8,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::InvalidHeaderRange { value, reason } => {
                write!(f, "invalid header range `{}`: {}", value, reason)
            }
            ConfigError::HeaderRangesOverlap { first, second } => {
                write!(f, "{} and {} header ranges overlap", first, second)
            }
            ConfigError::StandardHeaderValue { header, value } => write!(
                f,
                "{} header range includes standard WireGuard type {}",
                header, value
            ),
            ConfigError::PaddingOutOfRange { field, value, max } => {
                write!(f, "{} padding {} exceeds max {}", field, value, max)
            }
            ConfigError::JunkCountOutOfRange { value, max } => {
                write!(f, "junk count {} exceeds max {}", value, max)
            }
            ConfigError::JunkSizeOutOfRange {
                field,
                value,
                min,
                max,
            } => write!(
                f,
                "{} junk size {} is outside {}..={}",
                field, value, min, max
            ),
            ConfigError::JunkMinExceedsMax { min, max } => {
                write!(f, "junk min {} exceeds junk max {}", min, max)
            }
            ConfigError::JunkExceedsMtu { max_size, mtu } => {
                write!(
                    f,
                    "junk max size {} exceeds effective MTU {}",
                    max_size, mtu
                )
            }
            ConfigError::InvalidCps { reason } => write!(f, "invalid CPS chain: {}", reason),
            ConfigError::UnsupportedCpsTag { tag } => {
                write!(f, "unsupported AmneziaWG 2.0 CPS tag `{}`", tag)
            }
            ConfigError::CpsValueOutOfRange { tag, value, max } => {
                write!(f, "<{}> length {} exceeds max {}", tag, value, max)
            }
            ConfigError::InitPacketRequiresI1 { field } => {
                write!(f, "{} is set but I1 is absent", field)
            }
            ConfigError::InitPacketGap { missing, present } => {
                write!(f, "{} is set after missing {}", present, missing)
            }
            ConfigError::UnsupportedLegacyField { field } => {
                write!(f, "`{}` is not an AmneziaWG 2.0 field", field)
            }
            ConfigError::InvalidRange { value, reason } => {
                write!(f, "invalid range `{}`: {}", value, reason)
            }
            ConfigError::HeaderProtectionPaddingTooSmall { field, value, min } => write!(
                f,
                "{} padding {} is below the header-protection minimum {}",
                field, value, min
            ),
        }
    }
}

impl std::error::Error for ConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderKind {
    Init,
    Response,
    Cookie,
    Transport,
}

impl fmt::Display for HeaderKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            HeaderKind::Init => "H1",
            HeaderKind::Response => "H2",
            HeaderKind::Cookie => "H3",
            HeaderKind::Transport => "H4",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingKind {
    Init,
    Response,
    Cookie,
    Transport,
}

impl fmt::Display for PaddingKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            PaddingKind::Init => "S1",
            PaddingKind::Response => "S2",
            PaddingKind::Cookie => "S3",
            PaddingKind::Transport => "S4",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JunkSizeKind {
    Min,
    Max,
}

impl fmt::Display for JunkSizeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            JunkSizeKind::Min => "Jmin",
            JunkSizeKind::Max => "Jmax",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitPacketKind {
    I1,
    I2,
    I3,
    I4,
    I5,
}

impl InitPacketKind {
    fn from_index(index: usize) -> Self {
        match index {
            0 => InitPacketKind::I1,
            1 => InitPacketKind::I2,
            2 => InitPacketKind::I3,
            3 => InitPacketKind::I4,
            4 => InitPacketKind::I5,
            _ => unreachable!("only five AmneziaWG init packet slots exist"),
        }
    }
}

impl fmt::Display for InitPacketKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            InitPacketKind::I1 => "I1",
            InitPacketKind::I2 => "I2",
            InitPacketKind::I3 => "I3",
            InitPacketKind::I4 => "I4",
            InitPacketKind::I5 => "I5",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderRange {
    pub start: u32,
    pub end: u32,
}

impl HeaderRange {
    pub const fn single(value: u32) -> Self {
        HeaderRange {
            start: value,
            end: value,
        }
    }

    pub fn new(start: u32, end: u32) -> Result<Self, ConfigError> {
        if end < start {
            return Err(ConfigError::InvalidHeaderRange {
                value: format!("{}-{}", start, end),
                reason: "range end is smaller than start",
            });
        }

        Ok(HeaderRange { start, end })
    }

    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ConfigError::InvalidHeaderRange {
                value: input.to_owned(),
                reason: "empty value",
            });
        }

        let mut parts = input.split('-');
        let start = parse_u32_part(input, parts.next())?;
        let end = match parts.next() {
            Some(part) => parse_u32_part(input, Some(part))?,
            None => start,
        };
        if parts.next().is_some() {
            return Err(ConfigError::InvalidHeaderRange {
                value: input.to_owned(),
                reason: "expected `value` or `start-end`",
            });
        }

        HeaderRange::new(start, end).map_err(|_| ConfigError::InvalidHeaderRange {
            value: input.to_owned(),
            reason: "range end is smaller than start",
        })
    }

    pub fn contains(self, value: u32) -> bool {
        self.start <= value && value <= self.end
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Pick a random value from this range.
    pub fn generate(&self, rng: &mut dyn RandomSource) -> u32 {
        rng.gen_range_u32(self.start, self.end)
    }
}

fn parse_u32_part(input: &str, part: Option<&str>) -> Result<u32, ConfigError> {
    let part = part.unwrap_or_default().trim();
    if part.is_empty() {
        return Err(ConfigError::InvalidHeaderRange {
            value: input.to_owned(),
            reason: "empty range bound",
        });
    }

    part.parse::<u32>()
        .map_err(|err| header_parse_error(input, err))
}

fn header_parse_error(input: &str, err: ParseIntError) -> ConfigError {
    let reason = match err.kind() {
        std::num::IntErrorKind::PosOverflow => "value exceeds u32",
        std::num::IntErrorKind::NegOverflow => "negative value is not allowed",
        std::num::IntErrorKind::InvalidDigit => "expected decimal digits",
        std::num::IntErrorKind::Empty => "empty range bound",
        _ => "could not parse integer",
    };
    ConfigError::InvalidHeaderRange {
        value: input.to_owned(),
        reason,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderConfig {
    pub init: HeaderRange,
    pub response: HeaderRange,
    pub cookie: HeaderRange,
    pub transport: HeaderRange,
}

impl HeaderConfig {
    pub const fn wireguard_compatible() -> Self {
        HeaderConfig {
            init: HeaderRange::single(1),
            response: HeaderRange::single(2),
            cookie: HeaderRange::single(3),
            transport: HeaderRange::single(4),
        }
    }

    pub fn new(
        init: HeaderRange,
        response: HeaderRange,
        cookie: HeaderRange,
        transport: HeaderRange,
    ) -> Result<Self, ConfigError> {
        let config = HeaderConfig {
            init,
            response,
            cookie,
            transport,
        };
        config.validate_no_overlap()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.validate_no_overlap()?;
        self.validate_no_standard_headers()
    }

    pub fn validate_wireguard_compatible(&self) -> Result<(), ConfigError> {
        self.validate_no_overlap()
    }

    fn entries(&self) -> [(HeaderKind, HeaderRange); 4] {
        [
            (HeaderKind::Init, self.init),
            (HeaderKind::Response, self.response),
            (HeaderKind::Cookie, self.cookie),
            (HeaderKind::Transport, self.transport),
        ]
    }

    fn validate_no_overlap(&self) -> Result<(), ConfigError> {
        let entries = self.entries();
        for left in 0..entries.len() {
            for right in left + 1..entries.len() {
                if entries[left].1.overlaps(entries[right].1) {
                    return Err(ConfigError::HeaderRangesOverlap {
                        first: entries[left].0,
                        second: entries[right].0,
                    });
                }
            }
        }
        Ok(())
    }

    fn validate_no_standard_headers(&self) -> Result<(), ConfigError> {
        for (kind, range) in self.entries() {
            for value in STANDARD_WIREGUARD_HEADERS {
                if range.contains(value) {
                    return Err(ConfigError::StandardHeaderValue {
                        header: kind,
                        value,
                    });
                }
            }
        }
        Ok(())
    }
}

impl Default for HeaderConfig {
    fn default() -> Self {
        HeaderConfig::wireguard_compatible()
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PaddingConfig {
    pub s1: u8,
    pub s2: u8,
    pub s3: u8,
    pub s4: u8,
}

impl PaddingConfig {
    pub fn new(s1: u8, s2: u8, s3: u8, s4: u8) -> Result<Self, ConfigError> {
        let config = PaddingConfig { s1, s2, s3, s4 };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_padding(PaddingKind::Init, self.s1, AWG2_MAX_HANDSHAKE_PADDING)?;
        validate_padding(PaddingKind::Response, self.s2, AWG2_MAX_HANDSHAKE_PADDING)?;
        validate_padding(PaddingKind::Cookie, self.s3, AWG2_MAX_HANDSHAKE_PADDING)?;
        validate_padding(PaddingKind::Transport, self.s4, AWG2_MAX_TRANSPORT_PADDING)
    }
}

fn validate_padding(field: PaddingKind, value: u8, max: u8) -> Result<(), ConfigError> {
    if value > max {
        return Err(ConfigError::PaddingOutOfRange { field, value, max });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JunkConfig {
    pub count: u8,
    pub min_size: u16,
    pub max_size: u16,
}

impl JunkConfig {
    pub const fn disabled() -> Self {
        JunkConfig {
            count: 0,
            min_size: 0,
            max_size: 0,
        }
    }

    pub fn new(count: u8, min_size: u16, max_size: u16) -> Result<Self, ConfigError> {
        let config = JunkConfig {
            count,
            min_size,
            max_size,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.count == 0 {
            return Ok(());
        }
        if self.count > AWG2_MAX_JUNK_COUNT {
            return Err(ConfigError::JunkCountOutOfRange {
                value: self.count,
                max: AWG2_MAX_JUNK_COUNT,
            });
        }
        validate_junk_size(JunkSizeKind::Min, self.min_size)?;
        validate_junk_size(JunkSizeKind::Max, self.max_size)?;
        if self.min_size > self.max_size {
            return Err(ConfigError::JunkMinExceedsMax {
                min: self.min_size,
                max: self.max_size,
            });
        }
        Ok(())
    }

    pub fn validate_for_mtu(&self, effective_outer_mtu: usize) -> Result<(), ConfigError> {
        self.validate()?;
        if self.count > 0 && usize::from(self.max_size) > effective_outer_mtu {
            return Err(ConfigError::JunkExceedsMtu {
                max_size: self.max_size,
                mtu: effective_outer_mtu,
            });
        }
        Ok(())
    }

    /// Generate junk packets as a `Vec` of random byte buffers.
    /// Returns an empty vec if junk is disabled.
    pub fn generate_junk_packets(&self, rng: &mut dyn RandomSource) -> Vec<Vec<u8>> {
        if self.count == 0 {
            return Vec::new();
        }
        let mut packets = Vec::with_capacity(self.count as usize);
        for _ in 0..self.count {
            let size = rng.gen_range_u16(self.min_size, self.max_size) as usize;
            let mut buf = vec![0u8; size];
            rng.fill_bytes(&mut buf);
            packets.push(buf);
        }
        packets
    }
}

fn validate_junk_size(field: JunkSizeKind, value: u16) -> Result<(), ConfigError> {
    if !(AWG2_MIN_JUNK_SIZE..=AWG2_MAX_JUNK_SIZE).contains(&value) {
        return Err(ConfigError::JunkSizeOutOfRange {
            field,
            value,
            min: AWG2_MIN_JUNK_SIZE,
            max: AWG2_MAX_JUNK_SIZE,
        });
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpsChain {
    tags: Vec<CpsTag>,
}

impl CpsChain {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let mut parser = CpsParser::new(input);
        parser.parse()
    }

    pub fn tags(&self) -> &[CpsTag] {
        &self.tags
    }

    /// Returns the total encoded byte length of this chain.
    ///
    /// `data_len` is the byte length of the source data fed to the chain.
    /// For I1-I5 init packets this is always 0.
    pub fn encoded_len(&self, data_len: usize) -> usize {
        self.tags.iter().map(|t| t.encoded_len(data_len)).sum()
    }

    /// Convenience: encoded length assuming no source data (I1-I5 init packets).
    pub fn encoded_len_for_init(&self) -> usize {
        self.encoded_len(0)
    }

    /// Generate the full chain bytes into a new `Vec<u8>`.
    pub fn generate(&self, rng: &mut dyn RandomSource, data: &[u8]) -> Vec<u8> {
        let total = self.encoded_len(data.len());
        let mut out = vec![0u8; total];
        let mut offset = 0;
        for tag in &self.tags {
            offset += tag.generate(rng, data, &mut out, offset);
        }
        debug_assert_eq!(offset, total);
        out
    }

    /// Convenience: generate with no source data (I1-I5 init packets).
    pub fn generate_for_init(&self, rng: &mut dyn RandomSource) -> Vec<u8> {
        self.generate(rng, &[])
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CpsTag {
    Bytes(Vec<u8>),
    Timestamp,
    RandomBytes { len: usize },
    RandomChars { len: usize },
    RandomDigits { len: usize },
    /// Pass-through copy of source data (`<d>`).
    /// For I1-I5 init packets (no source data), produces zero bytes.
    Data,
    /// Base64 encoding of source data (`<ds>`).
    /// For I1-I5 init packets (no source data), produces zero bytes.
    DataString,
    /// N-byte big-endian length of source data (`<dz N>`).
    DataSize { len: usize },
}

impl CpsTag {
    /// Returns the encoded byte length of this tag.
    ///
    /// `data_len` is the byte length of the source data fed to the chain.
    /// For I1-I5 init packets this is always 0.
    fn encoded_len(&self, data_len: usize) -> usize {
        match self {
            CpsTag::Bytes(bytes) => bytes.len(),
            CpsTag::Timestamp => 4,
            CpsTag::RandomBytes { len }
            | CpsTag::RandomChars { len }
            | CpsTag::RandomDigits { len } => *len,
            CpsTag::Data => data_len,
            CpsTag::DataString => {
                if data_len == 0 {
                    0
                } else {
                    // Standard base64 output length (with padding)
                    ((data_len + 2) / 3) * 4
                }
            }
            CpsTag::DataSize { len } => *len,
        }
    }

    /// Write this tag's bytes into `out` starting at `offset`. Returns the
    /// number of bytes written.
    fn generate(
        &self,
        rng: &mut dyn RandomSource,
        data: &[u8],
        out: &mut [u8],
        offset: usize,
    ) -> usize {
        match self {
            CpsTag::Bytes(bytes) => {
                out[offset..offset + bytes.len()].copy_from_slice(bytes);
                bytes.len()
            }
            CpsTag::Timestamp => {
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as u32;
                out[offset..offset + 4].copy_from_slice(&ts.to_be_bytes());
                4
            }
            CpsTag::RandomBytes { len } => {
                rng.fill_bytes(&mut out[offset..offset + len]);
                *len
            }
            CpsTag::RandomChars { len } => {
                const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
                for i in 0..*len {
                    let idx = rng.gen_range_u32(0, (ALPHA.len() - 1) as u32) as usize;
                    out[offset + i] = ALPHA[idx];
                }
                *len
            }
            CpsTag::RandomDigits { len } => {
                for i in 0..*len {
                    out[offset + i] = b'0' + rng.gen_range_u32(0, 9) as u8;
                }
                *len
            }
            CpsTag::Data => {
                out[offset..offset + data.len()].copy_from_slice(data);
                data.len()
            }
            CpsTag::DataString => {
                if data.is_empty() {
                    0
                } else {
                    use base64::Engine;
                    let encoded = base64::engine::general_purpose::STANDARD.encode(data);
                    let bytes = encoded.as_bytes();
                    out[offset..offset + bytes.len()].copy_from_slice(bytes);
                    bytes.len()
                }
            }
            CpsTag::DataSize { len } => {
                let size = data.len() as u64;
                let be = size.to_be_bytes();
                // Write the last `len` bytes of the big-endian representation
                let start = 8 - len;
                out[offset..offset + len].copy_from_slice(&be[start..]);
                *len
            }
        }
    }
}

struct CpsParser<'a> {
    input: &'a str,
    offset: usize,
}

impl<'a> CpsParser<'a> {
    fn new(input: &'a str) -> Self {
        CpsParser { input, offset: 0 }
    }

    fn parse(&mut self) -> Result<CpsChain, ConfigError> {
        let mut tags = Vec::new();

        while self.skip_whitespace() {
            self.consume_byte(b'<')?;
            let tag_start = self.offset;
            let tag_end =
                self.input[self.offset..]
                    .find('>')
                    .ok_or_else(|| ConfigError::InvalidCps {
                        reason: "missing closing `>`".to_owned(),
                    })?
                    + self.offset;

            let tag = self.input[tag_start..tag_end].trim();
            self.offset = tag_end + 1;
            tags.push(parse_cps_tag(tag)?);
        }

        if tags.is_empty() {
            return Err(ConfigError::InvalidCps {
                reason: "empty chain".to_owned(),
            });
        }

        Ok(CpsChain { tags })
    }

    fn skip_whitespace(&mut self) -> bool {
        while let Some(byte) = self.input.as_bytes().get(self.offset) {
            if !byte.is_ascii_whitespace() {
                break;
            }
            self.offset += 1;
        }
        self.offset < self.input.len()
    }

    fn consume_byte(&mut self, expected: u8) -> Result<(), ConfigError> {
        match self.input.as_bytes().get(self.offset) {
            Some(actual) if *actual == expected => {
                self.offset += 1;
                Ok(())
            }
            _ => Err(ConfigError::InvalidCps {
                reason: format!("expected `{}` at byte {}", expected as char, self.offset),
            }),
        }
    }
}

fn reject_arg(tag: &str, arg: Option<&str>) -> Result<(), ConfigError> {
    if arg.is_some() {
        return Err(ConfigError::InvalidCps {
            reason: format!("<{}> does not take an argument", tag),
        });
    }
    Ok(())
}

fn parse_cps_tag(tag: &str) -> Result<CpsTag, ConfigError> {
    let mut parts = tag.split_whitespace();
    let name = parts.next().ok_or_else(|| ConfigError::InvalidCps {
        reason: "empty tag".to_owned(),
    })?;
    let arg = parts.next();
    if parts.next().is_some() {
        return Err(ConfigError::InvalidCps {
            reason: format!("<{}> has too many arguments", name),
        });
    }

    match name {
        "b" => parse_bytes_tag(arg),
        "t" => {
            reject_arg("t", arg)?;
            Ok(CpsTag::Timestamp)
        }
        "r" => parse_len_tag("r", arg).map(|len| CpsTag::RandomBytes { len }),
        "rc" => parse_len_tag("rc", arg).map(|len| CpsTag::RandomChars { len }),
        "rd" => parse_len_tag("rd", arg).map(|len| CpsTag::RandomDigits { len }),
        "d" => {
            reject_arg("d", arg)?;
            Ok(CpsTag::Data)
        }
        "ds" => {
            reject_arg("ds", arg)?;
            Ok(CpsTag::DataString)
        }
        "dz" => parse_len_tag("dz", arg).map(|len| CpsTag::DataSize { len }),
        _ => Err(ConfigError::UnsupportedCpsTag {
            tag: name.to_owned(),
        }),
    }
}

fn parse_bytes_tag(arg: Option<&str>) -> Result<CpsTag, ConfigError> {
    let arg = arg.ok_or_else(|| ConfigError::InvalidCps {
        reason: "<b> requires a 0x-prefixed hex argument".to_owned(),
    })?;
    let hex = arg
        .strip_prefix("0x")
        .ok_or_else(|| ConfigError::InvalidCps {
            reason: "<b> requires a 0x-prefixed hex argument".to_owned(),
        })?;
    if hex.is_empty() {
        return Err(ConfigError::InvalidCps {
            reason: "<b> hex data is empty".to_owned(),
        });
    }
    if hex.len() % 2 != 0 {
        return Err(ConfigError::InvalidCps {
            reason: "<b> hex data must contain full bytes".to_owned(),
        });
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for idx in (0..hex.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&hex[idx..idx + 2], 16).map_err(|_| ConfigError::InvalidCps {
                reason: "<b> contains non-hex data".to_owned(),
            })?;
        bytes.push(byte);
    }

    Ok(CpsTag::Bytes(bytes))
}

fn parse_len_tag(tag: &'static str, arg: Option<&str>) -> Result<usize, ConfigError> {
    let arg = arg.ok_or_else(|| ConfigError::InvalidCps {
        reason: format!("<{}> requires a length argument", tag),
    })?;
    let len = arg.parse::<usize>().map_err(|_| ConfigError::InvalidCps {
        reason: format!("<{}> length must be a non-negative integer", tag),
    })?;
    if len > AWG2_MAX_CPS_RANDOM_LEN {
        return Err(ConfigError::CpsValueOutOfRange {
            tag,
            value: len,
            max: AWG2_MAX_CPS_RANDOM_LEN,
        });
    }
    Ok(len)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InitPacketConfig {
    pub i1: Option<CpsChain>,
    pub i2: Option<CpsChain>,
    pub i3: Option<CpsChain>,
    pub i4: Option<CpsChain>,
    pub i5: Option<CpsChain>,
}

impl InitPacketConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        let chains = self.chains();
        if chains[0].is_none() {
            for (index, chain) in chains.iter().enumerate().skip(1) {
                if chain.is_some() {
                    return Err(ConfigError::InitPacketRequiresI1 {
                        field: InitPacketKind::from_index(index),
                    });
                }
            }
            return Ok(());
        }

        let mut seen_gap = None;
        for (index, chain) in chains.iter().enumerate() {
            match (seen_gap, chain.is_some()) {
                (None, false) => seen_gap = Some(InitPacketKind::from_index(index)),
                (Some(missing), true) => {
                    return Err(ConfigError::InitPacketGap {
                        missing,
                        present: InitPacketKind::from_index(index),
                    })
                }
                _ => {}
            }
        }

        Ok(())
    }

    pub fn active_chains(&self) -> impl Iterator<Item = &CpsChain> {
        IntoIterator::into_iter(self.chains())
            .take_while(|chain| chain.is_some())
            .flatten()
    }

    fn chains(&self) -> [Option<&CpsChain>; 5] {
        [
            self.i1.as_ref(),
            self.i2.as_ref(),
            self.i3.as_ref(),
            self.i4.as_ref(),
            self.i5.as_ref(),
        ]
    }
}

// ---------------------------------------------------------------------------
// AWG 3.0 — generic ranges and timing configuration
// ---------------------------------------------------------------------------

/// Default outer MTU used for content-padding clamping (matches amneziawg-go's
/// default device MTU).
pub const AWG3_DEFAULT_MTU: u32 = 1420;

/// Minimum S1-S4 padding when header protection is enabled: the ChaCha20
/// nonce is read from the first 12 bytes of the random padding prefix.
pub const HEADER_PROTECTION_MIN_PADDING: u8 = 12;

/// Inclusive `u32` range used by AWG 3.0 content padding and timing
/// parameters. A fully-zero range means "unset" (fall back to the WireGuard
/// default), matching amneziawg-go's `UintRange`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct U32Range {
    pub lo: u32,
    pub hi: u32,
}

impl U32Range {
    pub const fn zero() -> Self {
        U32Range { lo: 0, hi: 0 }
    }

    pub const fn single(value: u32) -> Self {
        U32Range {
            lo: value,
            hi: value,
        }
    }

    pub fn new(lo: u32, hi: u32) -> Result<Self, ConfigError> {
        if hi < lo {
            return Err(ConfigError::InvalidRange {
                value: format!("{}-{}", lo, hi),
                reason: "range end is smaller than start",
            });
        }
        Ok(U32Range { lo, hi })
    }

    /// Parse `"a"` or `"a-b"` (decimal, inclusive).
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ConfigError::InvalidRange {
                value: input.to_owned(),
                reason: "empty value",
            });
        }

        let mut parts = input.split('-');
        let lo = parse_range_part(input, parts.next())?;
        let hi = match parts.next() {
            Some(part) => parse_range_part(input, Some(part))?,
            None => lo,
        };
        if parts.next().is_some() {
            return Err(ConfigError::InvalidRange {
                value: input.to_owned(),
                reason: "expected `value` or `start-end`",
            });
        }

        U32Range::new(lo, hi)
    }

    /// A fully-zero range means "unset" — callers fall back to defaults.
    pub fn is_zero(&self) -> bool {
        self.lo == 0 && self.hi == 0
    }

    /// Pick a random value from `[lo, hi]` (inclusive).
    pub fn generate(&self, rng: &mut dyn RandomSource) -> u32 {
        rng.gen_range_u32(self.lo, self.hi)
    }

    /// Random pick, or `default` when the range is unset.
    pub fn pick_or(&self, rng: &mut dyn RandomSource, default: u32) -> u32 {
        if self.is_zero() {
            default
        } else {
            self.generate(rng)
        }
    }

    /// Range lower bound, or `default` when unset.
    pub fn lo_or(&self, default: u32) -> u32 {
        if self.is_zero() {
            default
        } else {
            self.lo
        }
    }

    /// Range upper bound, or `default` when unset.
    pub fn hi_or(&self, default: u32) -> u32 {
        if self.is_zero() {
            default
        } else {
            self.hi
        }
    }
}

fn parse_range_part(input: &str, part: Option<&str>) -> Result<u32, ConfigError> {
    let part = part.unwrap_or_default().trim();
    if part.is_empty() {
        return Err(ConfigError::InvalidRange {
            value: input.to_owned(),
            reason: "empty range bound",
        });
    }
    part.parse::<u32>().map_err(|_| ConfigError::InvalidRange {
        value: input.to_owned(),
        reason: "expected decimal digits",
    })
}

/// AWG 3.0 randomized timing parameters (all ranges, seconds except
/// `max_handshake_attempts` which is a count). Unset (zero) ranges fall back
/// to the classic WireGuard constants, preserving standard behavior.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimingRanges {
    pub rekey_after_time: U32Range,
    pub rekey_timeout: U32Range,
    pub reject_after_time: U32Range,
    pub keepalive_timeout: U32Range,
    pub max_handshake_attempts: U32Range,
    pub persistent_keepalive: U32Range,
}

impl TimingRanges {
    pub fn is_zero(&self) -> bool {
        self.rekey_after_time.is_zero()
            && self.rekey_timeout.is_zero()
            && self.reject_after_time.is_zero()
            && self.keepalive_timeout.is_zero()
            && self.max_handshake_attempts.is_zero()
            && self.persistent_keepalive.is_zero()
    }
}

// ---------------------------------------------------------------------------
// AWG 3.0 — header protection (ChaCha20 over low-entropy header fields)
// ---------------------------------------------------------------------------

pub const HEADER_PROTECTION_KEY_SIZE: usize = 32;
pub const HEADER_PROTECTION_NONCE_SIZE: usize = 12;

/// AWG 3.0 header protection key. Applies raw (unauthenticated) ChaCha20 to
/// the WireGuard message that follows the random padding prefix; the first
/// 12 bytes of that prefix are the nonce. Mirrors amneziawg-go's
/// `Device.HeaderProtectionCipher`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderProtection {
    key: [u8; HEADER_PROTECTION_KEY_SIZE],
}

impl HeaderProtection {
    pub fn new(key: [u8; HEADER_PROTECTION_KEY_SIZE]) -> Self {
        HeaderProtection { key }
    }

    /// XOR `message` in place with the ChaCha20 keystream (block counter 0).
    /// `prefix` is the random crypto padding preceding the message; its first
    /// 12 bytes are the nonce.
    ///
    /// # Panics
    /// Panics if `prefix` is shorter than the nonce size. Config validation
    /// (S1-S4 >= 12) guarantees this cannot happen for real packets.
    pub fn apply(&self, prefix: &[u8], message: &mut [u8]) {
        use chacha20::cipher::{KeyIvInit, StreamCipher};
        use std::convert::TryInto;

        let nonce: &[u8; HEADER_PROTECTION_NONCE_SIZE] = prefix[..HEADER_PROTECTION_NONCE_SIZE]
            .try_into()
            .expect("header protection requires at least 12 bytes of padding prefix");
        let mut cipher = chacha20::ChaCha20::new((&self.key).into(), nonce.into());
        cipher.apply_keystream(message);
    }

    /// Decrypt a 4-byte message-type candidate (keystream bytes 0..4).
    pub fn peek_type(&self, prefix: &[u8], type_bytes: [u8; 4]) -> u32 {
        let mut buf = type_bytes;
        self.apply(prefix, &mut buf);
        u32::from_le_bytes(buf)
    }
}

// ---------------------------------------------------------------------------
// AWG 3.0 — aggregate configuration
// ---------------------------------------------------------------------------

/// AmneziaWG 3.0 configuration: all AWG 2.0 obfuscation parameters plus
/// header protection, content padding, and randomized timings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Amnezia3Config {
    pub junk: JunkConfig,
    pub paddings: PaddingConfig,
    pub headers: HeaderConfig,
    pub init_packets: InitPacketConfig,
    /// Header protection key. `None` disables header protection.
    /// When set, all of S1-S4 must be >= [`HEADER_PROTECTION_MIN_PADDING`].
    pub header_protection_key: Option<[u8; HEADER_PROTECTION_KEY_SIZE]>,
    /// Random extra content padding for transport packets (inside AEAD).
    pub content_padding_addition: Option<U32Range>,
    /// Randomized WireGuard timing parameters.
    pub timing_ranges: TimingRanges,
    /// Outer MTU used to clamp content padding (amneziawg-go uses the device
    /// MTU; boringtun's `Tunn` has no MTU concept, so it is configured here).
    pub mtu: u32,
}

impl Amnezia3Config {
    pub fn wireguard_compatible() -> Self {
        Amnezia3Config::default()
    }

    /// Lift an AWG 2.0 config into 3.0 with all 3.0 features disabled.
    pub fn from_amnezia2(config: Amnezia2Config) -> Self {
        Amnezia3Config {
            junk: config.junk,
            paddings: config.paddings,
            headers: config.headers,
            init_packets: config.init_packets,
            header_protection_key: None,
            content_padding_addition: None,
            timing_ranges: TimingRanges::default(),
            mtu: AWG3_DEFAULT_MTU,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.junk.validate()?;
        self.paddings.validate()?;
        self.init_packets.validate()?;

        if self.junk == JunkConfig::disabled()
            && self.paddings == PaddingConfig::default()
            && self.headers == HeaderConfig::wireguard_compatible()
            && self.init_packets == InitPacketConfig::default()
        {
            self.headers.validate_wireguard_compatible()?;
        } else {
            self.headers.validate()?;
        }

        if self.header_protection_key.is_some() {
            for (field, value) in [
                (PaddingKind::Init, self.paddings.s1),
                (PaddingKind::Response, self.paddings.s2),
                (PaddingKind::Cookie, self.paddings.s3),
                (PaddingKind::Transport, self.paddings.s4),
            ] {
                if value < HEADER_PROTECTION_MIN_PADDING {
                    return Err(ConfigError::HeaderProtectionPaddingTooSmall {
                        field,
                        value,
                        min: HEADER_PROTECTION_MIN_PADDING,
                    });
                }
            }
        }

        Ok(())
    }

    pub fn header_protection(&self) -> Option<HeaderProtection> {
        self.header_protection_key.map(HeaderProtection::new)
    }
}

impl Default for Amnezia3Config {
    fn default() -> Self {
        Amnezia3Config {
            junk: JunkConfig::disabled(),
            paddings: PaddingConfig::default(),
            headers: HeaderConfig::wireguard_compatible(),
            init_packets: InitPacketConfig::default(),
            header_protection_key: None,
            content_padding_addition: None,
            timing_ranges: TimingRanges::default(),
            mtu: AWG3_DEFAULT_MTU,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Amnezia2Config {
    pub junk: JunkConfig,
    pub paddings: PaddingConfig,
    pub headers: HeaderConfig,
    pub init_packets: InitPacketConfig,
}

impl Amnezia2Config {
    pub fn wireguard_compatible() -> Self {
        Amnezia2Config::default()
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.junk.validate()?;
        self.paddings.validate()?;
        self.init_packets.validate()?;

        if self.is_wireguard_compatible() {
            self.headers.validate_wireguard_compatible()
        } else {
            self.headers.validate()
        }
    }

    pub fn validate_for_mtu(&self, effective_outer_mtu: usize) -> Result<(), ConfigError> {
        self.validate()?;
        self.junk.validate_for_mtu(effective_outer_mtu)
    }

    pub fn is_wireguard_compatible(&self) -> bool {
        self.junk == JunkConfig::disabled()
            && self.paddings == PaddingConfig::default()
            && self.headers == HeaderConfig::wireguard_compatible()
            && self.init_packets == InitPacketConfig::default()
    }

    pub fn validate_field_name(field: &str) -> Result<(), ConfigError> {
        match field.to_ascii_lowercase().as_str() {
            "jc" | "jmin" | "jmax" | "s1" | "s2" | "s3" | "s4" | "h1" | "h2" | "h3" | "h4"
            | "i1" | "i2" | "i3" | "i4" | "i5" => Ok(()),
            "j1" | "j2" | "j3" | "itime" => Err(ConfigError::UnsupportedLegacyField {
                field: field.to_owned(),
            }),
            _ => Err(ConfigError::UnsupportedLegacyField {
                field: field.to_owned(),
            }),
        }
    }
}

impl Default for Amnezia2Config {
    fn default() -> Self {
        Amnezia2Config {
            junk: JunkConfig::disabled(),
            paddings: PaddingConfig::default(),
            headers: HeaderConfig::wireguard_compatible(),
            init_packets: InitPacketConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic RNG that produces a repeating counter byte sequence.
    /// Useful for golden tests where exact output must be reproducible.
    struct DetRng {
        counter: u8,
    }

    impl DetRng {
        fn new(seed: u8) -> Self {
            DetRng { counter: seed }
        }
    }

    impl RandomSource for DetRng {
        fn fill_bytes(&mut self, out: &mut [u8]) {
            for byte in out.iter_mut() {
                *byte = self.counter;
                self.counter = self.counter.wrapping_add(1);
            }
        }
    }

    fn chain(input: &str) -> CpsChain {
        CpsChain::parse(input).unwrap()
    }

    #[test]
    fn parses_header_single_value() {
        assert_eq!(
            HeaderRange::parse("1234").unwrap(),
            HeaderRange::single(1234)
        );
    }

    #[test]
    fn parses_header_range() {
        assert_eq!(
            HeaderRange::parse("123-456").unwrap(),
            HeaderRange {
                start: 123,
                end: 456
            }
        );
    }

    #[test]
    fn rejects_bad_header_ranges() {
        assert!(HeaderRange::parse("").is_err());
        assert!(HeaderRange::parse("456-123").is_err());
        assert!(HeaderRange::parse("1-2-3").is_err());
        assert!(HeaderRange::parse("abc").is_err());
        assert!(HeaderRange::parse("4294967296").is_err());
    }

    #[test]
    fn rejects_overlapping_header_ranges() {
        let err = HeaderConfig::new(
            HeaderRange::new(100, 200).unwrap(),
            HeaderRange::new(201, 300).unwrap(),
            HeaderRange::new(300, 400).unwrap(),
            HeaderRange::new(500, 600).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ConfigError::HeaderRangesOverlap {
                first: HeaderKind::Response,
                second: HeaderKind::Cookie
            }
        ));
    }

    #[test]
    fn rejects_standard_headers_for_active_awg_config() {
        let mut config = Amnezia2Config::default();
        config.paddings.s1 = 1;
        let err = config.validate().unwrap_err();
        assert!(matches!(
            err,
            ConfigError::StandardHeaderValue {
                header: HeaderKind::Init,
                value: 1
            }
        ));
    }

    #[test]
    fn allows_standard_headers_for_wireguard_compatible_config() {
        let config = Amnezia2Config::default();
        assert!(config.is_wireguard_compatible());
        config.validate().unwrap();
    }

    #[test]
    fn validates_padding_limits() {
        PaddingConfig::new(64, 64, 64, 32).unwrap();
        assert!(matches!(
            PaddingConfig::new(65, 0, 0, 0),
            Err(ConfigError::PaddingOutOfRange {
                field: PaddingKind::Init,
                value: 65,
                max: AWG2_MAX_HANDSHAKE_PADDING
            })
        ));
        assert!(matches!(
            PaddingConfig::new(0, 0, 0, 33),
            Err(ConfigError::PaddingOutOfRange {
                field: PaddingKind::Transport,
                value: 33,
                max: AWG2_MAX_TRANSPORT_PADDING
            })
        ));
    }

    #[test]
    fn validates_junk_config() {
        JunkConfig::disabled().validate().unwrap();
        JunkConfig::new(10, 64, 1024).unwrap();
        assert!(matches!(
            JunkConfig::new(11, 64, 1024),
            Err(ConfigError::JunkCountOutOfRange { value: 11, .. })
        ));
        assert!(matches!(
            JunkConfig::new(1, 63, 1024),
            Err(ConfigError::JunkSizeOutOfRange {
                field: JunkSizeKind::Min,
                value: 63,
                ..
            })
        ));
        assert!(matches!(
            JunkConfig::new(1, 128, 64),
            Err(ConfigError::JunkMinExceedsMax { min: 128, max: 64 })
        ));
    }

    #[test]
    fn validates_junk_against_mtu() {
        let config = JunkConfig::new(1, 64, 512).unwrap();
        assert!(config.validate_for_mtu(512).is_ok());
        assert!(matches!(
            config.validate_for_mtu(511),
            Err(ConfigError::JunkExceedsMtu {
                max_size: 512,
                mtu: 511
            })
        ));
    }

    #[test]
    fn parses_cps_chain() {
        let parsed = CpsChain::parse("<b 0x0102><rc 4><rd 3><r 2><t>").unwrap();
        assert_eq!(
            parsed.tags(),
            &[
                CpsTag::Bytes(vec![1, 2]),
                CpsTag::RandomChars { len: 4 },
                CpsTag::RandomDigits { len: 3 },
                CpsTag::RandomBytes { len: 2 },
                CpsTag::Timestamp,
            ]
        );
        assert_eq!(parsed.encoded_len(0), 15);
    }

    #[test]
    fn parses_cps_data_tags() {
        let parsed = CpsChain::parse("<d><ds><dz 4>").unwrap();
        assert_eq!(
            parsed.tags(),
            &[CpsTag::Data, CpsTag::DataString, CpsTag::DataSize { len: 4 },]
        );
        // With no source data (init packets), Data and DataString produce 0 bytes
        assert_eq!(parsed.encoded_len(0), 4);
        // With 10 bytes of source data
        assert_eq!(parsed.encoded_len(10), 10 + 16 + 4); // data + base64(10)=16 + dz(4)
    }

    #[test]
    fn rejects_invalid_cps_tags() {
        assert!(CpsChain::parse("").is_err());
        assert!(CpsChain::parse("<b 0102>").is_err());
        assert!(CpsChain::parse("<b 0x123>").is_err());
        assert!(CpsChain::parse("<r 1001>").is_err());
        assert!(CpsChain::parse("<c>").is_err());
        assert!(CpsChain::parse("prefix <r 1>").is_err());
        assert!(CpsChain::parse("<t 1>").is_err());
        assert!(CpsChain::parse("<d 1>").is_err());
        assert!(CpsChain::parse("<ds 1>").is_err());
    }

    #[test]
    fn validates_init_packet_chain_presence() {
        let config = InitPacketConfig {
            i1: None,
            i2: Some(chain("<r 1>")),
            i3: None,
            i4: None,
            i5: None,
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InitPacketRequiresI1 {
                field: InitPacketKind::I2
            })
        ));
    }

    #[test]
    fn validates_init_packet_chain_gaps() {
        let config = InitPacketConfig {
            i1: Some(chain("<r 1>")),
            i2: None,
            i3: Some(chain("<r 1>")),
            i4: None,
            i5: None,
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InitPacketGap {
                missing: InitPacketKind::I2,
                present: InitPacketKind::I3
            })
        ));
    }

    #[test]
    fn iterates_active_init_packet_chain_until_first_gap() {
        let config = InitPacketConfig {
            i1: Some(chain("<r 1>")),
            i2: Some(chain("<r 2>")),
            i3: None,
            i4: None,
            i5: None,
        };
        let lengths = config
            .active_chains()
            .map(|c| c.encoded_len_for_init())
            .collect::<Vec<_>>();
        assert_eq!(lengths, vec![1, 2]);
    }

    #[test]
    fn rejects_legacy_field_names() {
        Amnezia2Config::validate_field_name("h1").unwrap();
        assert!(matches!(
            Amnezia2Config::validate_field_name("j1"),
            Err(ConfigError::UnsupportedLegacyField { .. })
        ));
        assert!(matches!(
            Amnezia2Config::validate_field_name("itime"),
            Err(ConfigError::UnsupportedLegacyField { .. })
        ));
    }

    // -- Phase 2: CPS generation tests --

    #[test]
    fn generates_static_bytes() {
        let c = chain("<b 0xDEAD>");
        let mut rng = DetRng::new(0);
        let out = c.generate_for_init(&mut rng);
        assert_eq!(out, vec![0xDE, 0xAD]);
    }

    #[test]
    fn generates_random_bytes() {
        let c = chain("<r 5>");
        let mut rng = DetRng::new(10);
        let out = c.generate_for_init(&mut rng);
        assert_eq!(out, vec![10, 11, 12, 13, 14]);
    }

    #[test]
    fn generates_random_chars() {
        let c = chain("<rc 4>");
        let mut rng = DetRng::new(0);
        let out = c.generate_for_init(&mut rng);
        // All bytes must be ASCII letters
        assert_eq!(out.len(), 4);
        for &b in &out {
            assert!(b.is_ascii_alphabetic(), "byte {} is not alphabetic", b);
        }
    }

    #[test]
    fn generates_random_digits() {
        let c = chain("<rd 3>");
        let mut rng = DetRng::new(0);
        let out = c.generate_for_init(&mut rng);
        assert_eq!(out.len(), 3);
        for &b in &out {
            assert!(b >= b'0' && b <= b'9', "byte {} is not a digit", b);
        }
    }

    #[test]
    fn generates_compound_chain() {
        let c = chain("<b 0xFF><r 2><rd 1>");
        let mut rng = DetRng::new(0);
        let out = c.generate_for_init(&mut rng);
        assert_eq!(out.len(), 4);
        assert_eq!(out[0], 0xFF); // static byte
        assert_eq!(out[1], 0); // first random byte (DetRng seed=0)
        assert_eq!(out[2], 1); // second random byte
        assert!(out[3] >= b'0' && out[3] <= b'9'); // random digit
    }

    #[test]
    fn generates_data_tags_with_source() {
        let c = chain("<d><dz 2>");
        let mut rng = DetRng::new(0);
        let out = c.generate(&mut rng, b"hello");
        // <d> produces "hello" (5 bytes), <dz 2> produces big-endian len=5 in 2 bytes
        assert_eq!(&out[..5], b"hello");
        assert_eq!(&out[5..], &[0, 5]);
    }

    #[test]
    fn generates_data_string_tag() {
        let c = chain("<ds>");
        let mut rng = DetRng::new(0);
        let out = c.generate(&mut rng, b"Hi");
        // base64("Hi") = "SGk="
        assert_eq!(&out, b"SGk=");
    }

    #[test]
    fn generates_data_tags_empty_for_init() {
        let c = chain("<d><ds><dz 4>");
        let mut rng = DetRng::new(0);
        let out = c.generate_for_init(&mut rng);
        // <d> and <ds> produce 0 bytes; <dz 4> produces 4 zero bytes (len=0)
        assert_eq!(out, vec![0, 0, 0, 0]);
    }

    #[test]
    fn header_range_generate() {
        let range = HeaderRange::new(100, 200).unwrap();
        let mut rng = DetRng::new(0);
        for _ in 0..50 {
            let v = range.generate(&mut rng);
            assert!(v >= 100 && v <= 200, "value {} out of range", v);
        }

        let single = HeaderRange::single(42);
        assert_eq!(single.generate(&mut rng), 42);
    }

    // -- Phase 3: Junk generation tests --

    #[test]
    fn junk_disabled_produces_nothing() {
        let config = JunkConfig::disabled();
        let mut rng = DetRng::new(0);
        assert!(config.generate_junk_packets(&mut rng).is_empty());
    }

    #[test]
    fn junk_generates_correct_count_and_sizes() {
        let config = JunkConfig::new(3, 64, 128).unwrap();
        let mut rng = DetRng::new(0);
        let packets = config.generate_junk_packets(&mut rng);
        assert_eq!(packets.len(), 3);
        for pkt in &packets {
            assert!(pkt.len() >= 64 && pkt.len() <= 128, "size {} out of range", pkt.len());
        }
    }

    #[test]
    fn junk_fixed_size_when_min_equals_max() {
        let config = JunkConfig::new(2, 100, 100).unwrap();
        let mut rng = DetRng::new(0);
        let packets = config.generate_junk_packets(&mut rng);
        assert_eq!(packets.len(), 2);
        for pkt in &packets {
            assert_eq!(pkt.len(), 100);
        }
    }

    #[test]
    fn u32_range_parse_and_generate() {
        let single = U32Range::parse("25").expect("single value parses");
        assert_eq!(single, U32Range::single(25));

        let range = U32Range::parse("120-240").expect("range parses");
        assert_eq!(range, U32Range { lo: 120, hi: 240 });

        assert!(U32Range::parse("240-120").is_err());
        assert!(U32Range::parse("1-2-3").is_err());
        assert!(U32Range::parse("").is_err());
        assert!(U32Range::parse("abc").is_err());

        let mut rng = DetRng::new(0xAA);
        for _ in 0..32 {
            let v = range.generate(&mut rng);
            assert!((120..=240).contains(&v));
        }
        assert_eq!(U32Range::single(7).generate(&mut rng), 7);
    }

    #[test]
    fn u32_range_defaults() {
        let zero = U32Range::zero();
        assert!(zero.is_zero());
        let mut rng = DetRng::new(0xFF);
        assert_eq!(zero.pick_or(&mut rng, 120), 120);
        assert_eq!(zero.lo_or(10), 10);
        assert_eq!(zero.hi_or(180), 180);
        let range = U32Range::single(30);
        assert_eq!(range.pick_or(&mut rng, 120), 30);
        assert_eq!(range.lo_or(10), 30);
        assert_eq!(range.hi_or(180), 30);
    }

    #[test]
    fn timing_ranges_default_is_zero() {
        let ranges = TimingRanges::default();
        assert!(ranges.is_zero());
        let ranges = TimingRanges {
            rekey_timeout: U32Range::single(5),
            ..TimingRanges::default()
        };
        assert!(!ranges.is_zero());
    }

    #[test]
    fn header_protection_chacha20_known_answer() {
        // RFC 8439 A.1 test vector #1: zero key, zero nonce, counter 0.
        let hp = HeaderProtection::new([0u8; HEADER_PROTECTION_KEY_SIZE]);
        let prefix = [0u8; HEADER_PROTECTION_NONCE_SIZE];
        let mut message = [0u8; 64];
        hp.apply(&prefix, &mut message);
        let expected: [u8; 64] = [
            0x76, 0xb8, 0xe0, 0xad, 0xa0, 0xf1, 0x3d, 0x90, 0x40, 0x5d, 0x6a, 0xe5, 0x53, 0x86,
            0xbd, 0x28, 0xbd, 0xd2, 0x19, 0xb8, 0xa0, 0x8d, 0xed, 0x1a, 0xa8, 0x36, 0xef, 0xcc,
            0x8b, 0x77, 0x0d, 0xc7, 0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d, 0x77, 0x24,
            0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37, 0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
            0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86,
        ];
        assert_eq!(message, expected);
    }

    #[test]
    fn header_protection_round_trip_and_peek() {
        let hp = HeaderProtection::new([0x42; HEADER_PROTECTION_KEY_SIZE]);
        let mut prefix = [0u8; 16];
        DetRng::new(7).fill_bytes(&mut prefix);

        let plaintext: [u8; 32] = [0x11; 32];
        let mut message = plaintext;
        hp.apply(&prefix, &mut message);
        assert_ne!(message, plaintext);

        // decrypt restores the plaintext (XOR is its own inverse)
        hp.apply(&prefix, &mut message);
        assert_eq!(message, plaintext);

        // peek_type decrypts exactly the first 4 keystream bytes
        let mut type_bytes = [0u8; 4];
        type_bytes.copy_from_slice(&plaintext[..4]);
        hp.apply(&prefix, &mut type_bytes);
        assert_eq!(
            hp.peek_type(&prefix, type_bytes),
            u32::from_le_bytes([0x11; 4])
        );
    }

    fn awg3_base_config() -> Amnezia3Config {
        Amnezia3Config {
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
            header_protection_key: Some([0x42; HEADER_PROTECTION_KEY_SIZE]),
            content_padding_addition: Some(U32Range::single(16)),
            timing_ranges: TimingRanges::default(),
            mtu: AWG3_DEFAULT_MTU,
        }
    }

    #[test]
    fn amnezia3_valid_config_passes() {
        assert!(awg3_base_config().validate().is_ok());
    }

    #[test]
    fn amnezia3_header_protection_requires_padding_12() {
        for (s1, s2, s3, s4) in [
            (11, 16, 16, 16),
            (16, 11, 16, 16),
            (16, 16, 11, 16),
            (16, 16, 16, 11),
        ] {
            let mut config = awg3_base_config();
            config.paddings = PaddingConfig::new(s1, s2, s3, s4).expect("valid paddings");
            let err = config.validate().expect_err("padding < 12 must fail");
            assert!(matches!(
                err,
                ConfigError::HeaderProtectionPaddingTooSmall {
                    min: HEADER_PROTECTION_MIN_PADDING,
                    ..
                }
            ));
        }

        // Without a key, small paddings are fine.
        let mut config = awg3_base_config();
        config.header_protection_key = None;
        config.paddings = PaddingConfig::new(0, 0, 0, 0).expect("valid paddings");
        // zero paddings + awg headers → not wireguard-compatible, still valid
        assert!(config.validate().is_ok());
    }

    #[test]
    fn amnezia3_from_amnezia2_preserves_fields() {
        let v2 = Amnezia2Config {
            junk: JunkConfig::disabled(),
            paddings: PaddingConfig::new(1, 2, 3, 4).expect("valid paddings"),
            headers: HeaderConfig::new(
                HeaderRange::single(100),
                HeaderRange::single(200),
                HeaderRange::single(300),
                HeaderRange::single(400),
            )
            .expect("valid headers"),
            init_packets: InitPacketConfig::default(),
        };
        let v3 = Amnezia3Config::from_amnezia2(v2.clone());
        assert_eq!(v3.junk, v2.junk);
        assert_eq!(v3.paddings, v2.paddings);
        assert_eq!(v3.headers, v2.headers);
        assert_eq!(v3.init_packets, v2.init_packets);
        assert_eq!(v3.header_protection_key, None);
        assert_eq!(v3.content_padding_addition, None);
        assert!(v3.timing_ranges.is_zero());
        assert_eq!(v3.mtu, AWG3_DEFAULT_MTU);
    }
}
