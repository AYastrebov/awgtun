// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! AmneziaWG 2.0 configuration and packet generation.
//!
//! This module intentionally models only the AmneziaWG 2.0 fields. Legacy
//! 1.0/1.5-only aliases are rejected by name.

use std::fmt;
use std::num::ParseIntError;
use std::time::{SystemTime, UNIX_EPOCH};

pub const AWG2_MAX_CPS_RANDOM_LEN: usize = 1000;

// ---------------------------------------------------------------------------
// RandomSource — injectable RNG for deterministic testing
// ---------------------------------------------------------------------------

/// Trait for injectable randomness. Production uses `OsRandom`; tests use a
/// deterministic implementation.
pub trait RandomSource {
    fn fill_bytes(&mut self, out: &mut [u8]);

    /// Generate a random `u32` in `[start, end]` (inclusive). An inverted
    /// range (`start > end`) yields `start`.
    fn gen_range_u32(&mut self, start: u32, end: u32) -> u32 {
        if start >= end {
            return start;
        }
        let mut buf = [0u8; 4];
        self.fill_bytes(&mut buf);
        let raw = u32::from_le_bytes(buf);
        match (end - start).checked_add(1) {
            Some(range) => start + (raw % range),
            // Full `u32` span: every value is already in range.
            None => raw,
        }
    }

    /// Generate a random `u16` in `[start, end]` (inclusive).
    fn gen_range_u16(&mut self, start: u16, end: u16) -> u16 {
        self.gen_range_u32(u32::from(start), u32::from(end)) as u16
    }
}

/// Production random source backed by the OS CSPRNG.
///
/// Every draw is a `getrandom` syscall, which costs on the order of 190 ns.
/// That is the right price for bytes that go on the wire as ciphertext-grade
/// filler, and too high for a value drawn on every packet — see [`FastRandom`].
#[derive(Debug, Clone, Copy)]
pub struct OsRandom;

impl RandomSource for OsRandom {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(out);
    }
}

/// Buffered ChaCha20 keystream, seeded from the OS and kept per thread.
///
/// About eighteen times cheaper per draw than [`OsRandom`], because it
/// amortizes one `getrandom` syscall over a buffer instead of making one per
/// value. This is the same design as Go's `crypto/rand`, which is why
/// amneziawg-go's `rand.Read` costs 36 ns where a raw syscall costs ~160.
///
/// # When to use which
///
/// Use this for everything that goes on the wire as random-looking material:
/// the S1-S4 padding prefix, junk packet contents, CPS `<r>` bytes, the message
/// type inside its H1-H4 range, content padding lengths, timer jitter.
///
/// Keep [`OsRandom`] for long-lived secrets — cookie and MAC keys, anything a
/// peer's security depends on beyond a single packet. There is no throughput
/// argument for those (they are drawn once), so the conservative choice is free.
///
/// # Why a CSPRNG is enough for the padding prefix
///
/// The first 12 bytes of the prefix are the header protection nonce, so a
/// repeat would reuse a ChaCha20 keystream and leak the XOR of two headers.
/// That is a real hazard, and it is *not* one the OS RNG protects against any
/// better: with either source the nonces are uniform over 96 bits, so a
/// collision is a birthday event around 2^48 packets. A CSPRNG's output is
/// computationally indistinguishable from uniform, so the bound is the same up
/// to a negligible term.
///
/// What genuinely differs is state duplication, which the OS RNG cannot suffer
/// and a userspace buffer can — see the fork handling below.
#[derive(Debug, Clone, Copy)]
pub struct FastRandom;

/// Incremented by a `pthread_atfork` child handler.
///
/// A buffered userspace RNG has one failure mode a `getrandom` syscall does
/// not: `fork` copies the buffer, so parent and child hand out identical bytes
/// from it. For padding that is keystream reuse, and it is not hypothetical
/// here — `boringtun-cli` forks to daemonize, and any FFI or JNI embedder may
/// fork for its own reasons.
///
/// Each thread records the generation it seeded at and throws its buffer away
/// when the value moves, so a child never repeats a byte its parent might also
/// emit. The check is one relaxed atomic load per draw; the handler itself only
/// touches an atomic, which keeps it async-signal-safe as `pthread_atfork`
/// requires.
static FORK_GENERATION: portable_atomic::AtomicUsize = portable_atomic::AtomicUsize::new(0);

#[cfg(unix)]
extern "C" fn note_fork() {
    FORK_GENERATION.fetch_add(1, portable_atomic::Ordering::Relaxed);
}

/// Keystream drawn per refill. Large enough to amortize the ChaCha20 setup over
/// many draws, small enough to stay off the hot part of the cache.
const FAST_RNG_BUFFER_SIZE: usize = 256;

/// Reseed from the OS after this many bytes. ChaCha20 could safely emit vastly
/// more from one key, so this is hygiene rather than necessity: it bounds how
/// much output a leaked thread-local state could explain, at a cost of one
/// syscall per megabyte.
const FAST_RNG_RESEED_INTERVAL: usize = 1 << 20;

struct FastRngState {
    key: [u8; 32],
    /// Nonce counter. ChaCha20 with a 12-byte nonce addresses 256 GiB per key,
    /// far beyond the reseed interval, so this cannot wrap between reseeds.
    block: u64,
    buffer: [u8; FAST_RNG_BUFFER_SIZE],
    /// Bytes of `buffer` already handed out.
    used: usize,
    since_reseed: usize,
    /// Value of [`FORK_GENERATION`] this state was seeded at.
    generation: usize,
}

impl FastRngState {
    fn new() -> Self {
        // Registered once per process. The handler must survive for the life of
        // the process, so there is nothing to unregister.
        #[cfg(unix)]
        {
            static REGISTER: std::sync::Once = std::sync::Once::new();
            REGISTER.call_once(|| {
                // Safety: `note_fork` only performs a relaxed atomic increment,
                // which is async-signal-safe, as `pthread_atfork` child
                // handlers must be.
                unsafe {
                    libc::pthread_atfork(None, None, Some(note_fork));
                }
            });
        }

        let mut state = FastRngState {
            key: [0u8; 32],
            block: 0,
            buffer: [0u8; FAST_RNG_BUFFER_SIZE],
            used: FAST_RNG_BUFFER_SIZE,
            since_reseed: FAST_RNG_RESEED_INTERVAL,
            generation: 0,
        };
        state.reseed();
        state
    }

    fn reseed(&mut self) {
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut self.key);
        self.block = 0;
        self.since_reseed = 0;
        self.generation = FORK_GENERATION.load(portable_atomic::Ordering::Relaxed);
        // Anything still buffered predates the new key, so drop it.
        self.used = FAST_RNG_BUFFER_SIZE;
    }

    fn refill(&mut self) {
        use chacha20::cipher::{KeyIvInit, StreamCipher};

        if self.since_reseed >= FAST_RNG_RESEED_INTERVAL {
            self.reseed();
        }

        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.block.to_le_bytes());
        self.block += 1;

        self.buffer = [0u8; FAST_RNG_BUFFER_SIZE];
        let mut cipher = chacha20::ChaCha20::new((&self.key).into(), (&nonce).into());
        cipher.apply_keystream(&mut self.buffer);

        self.used = 0;
        self.since_reseed += FAST_RNG_BUFFER_SIZE;
    }

    fn fill(&mut self, out: &mut [u8]) {
        // Checked per draw rather than per refill: a fork copies whatever is
        // still unconsumed in the buffer, so a child that only reseeded when the
        // buffer ran dry would first hand out bytes its parent can also emit.
        if self.generation != FORK_GENERATION.load(portable_atomic::Ordering::Relaxed) {
            self.reseed();
        }

        let mut written = 0;
        while written < out.len() {
            if self.used == FAST_RNG_BUFFER_SIZE {
                self.refill();
            }
            let take = (out.len() - written).min(FAST_RNG_BUFFER_SIZE - self.used);
            out[written..written + take].copy_from_slice(&self.buffer[self.used..self.used + take]);
            self.used += take;
            written += take;
        }
    }
}

thread_local! {
    static FAST_RNG: std::cell::RefCell<FastRngState> =
        std::cell::RefCell::new(FastRngState::new());
}

impl RandomSource for FastRandom {
    fn fill_bytes(&mut self, out: &mut [u8]) {
        FAST_RNG.with(|state| state.borrow_mut().fill(out));
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
    UnsupportedLegacyField {
        field: String,
    },
    InvalidRange {
        value: String,
        reason: &'static str,
    },
    InvalidConfigLine {
        line: String,
        reason: &'static str,
    },
    InvalidFieldValue {
        field: String,
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
            ConfigError::UnsupportedLegacyField { field } => {
                write!(f, "`{}` is not an AmneziaWG 2.0 field", field)
            }
            ConfigError::InvalidRange { value, reason } => {
                write!(f, "invalid range `{}`: {}", value, reason)
            }
            ConfigError::InvalidConfigLine { line, reason } => {
                write!(f, "invalid config line `{}`: {}", line, reason)
            }
            ConfigError::InvalidFieldValue { field, reason } => {
                write!(f, "invalid value for `{}`: {}", field, reason)
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

    /// Non-overlapping ranges are the only rule, matching amneziawg-go's
    /// `mergeWithDevice`, which checks exactly that and nothing else.
    ///
    /// In particular a range may include the standard WireGuard types 1-4:
    /// upstream *defaults* H1-H4 to them (`NewDevice`), so a configuration that
    /// turns on junk, padding or I-packets while leaving the headers alone is
    /// ordinary AmneziaWG and must be accepted.
    pub fn validate(&self) -> Result<(), ConfigError> {
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
}

impl Default for HeaderConfig {
    fn default() -> Self {
        HeaderConfig::wireguard_compatible()
    }
}

/// Inverse of [`HeaderRange::parse`].
impl fmt::Display for HeaderRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.start == self.end {
            write!(f, "{}", self.start)
        } else {
            write!(f, "{}-{}", self.start, self.end)
        }
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

    /// No upper bound is enforced, matching amneziawg-go, which parses S1-S4
    /// and applies no maximum. The only constraint upstream has is a minimum of
    /// [`HEADER_PROTECTION_MIN_PADDING`] when header protection is enabled,
    /// which [`Amnezia3Config::validate`] checks.
    ///
    /// The field type caps these at 255. amneziawg-go parses them as `uint16`,
    /// so a configuration using S1-S4 above 255 is accepted there and rejected
    /// here. Amnezia's own tooling stays well below that.
    pub fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }
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

    /// amneziawg-go bounds none of these — `jc`, `jmin` and `jmax` are parsed
    /// and stored with no range check at all — so neither do we, beyond the
    /// field types. Enforcing the ranges from Amnezia's documentation rejected
    /// configurations that real AmneziaWG servers issue.
    ///
    /// `min_size > max_size` is still refused. Upstream does not check it and
    /// would underflow computing `max - min`; our junk generator clamps instead,
    /// but the configuration is malformed either way and silently producing
    /// fixed-size junk would defeat the point of the parameter.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.count == 0 {
            return Ok(());
        }
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
    ///
    /// Sizes are drawn from `[min_size, max_size)` — half-open, matching
    /// amneziawg-go's `min + fastrandn(max - min)`. When `min_size` equals
    /// `max_size` every packet is exactly that size, as in Go where
    /// `fastrandn(0)` yields 0.
    pub fn generate_junk_packets(&self, rng: &mut dyn RandomSource) -> Vec<Vec<u8>> {
        if self.count == 0 {
            return Vec::new();
        }
        let mut packets = Vec::with_capacity(self.count as usize);
        for _ in 0..self.count {
            let size = if self.max_size <= self.min_size {
                self.min_size
            } else {
                rng.gen_range_u16(self.min_size, self.max_size - 1)
            } as usize;
            let mut buf = vec![0u8; size];
            rng.fill_bytes(&mut buf);
            packets.push(buf);
        }
        packets
    }
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
    RandomBytes {
        len: usize,
    },
    RandomChars {
        len: usize,
    },
    RandomDigits {
        len: usize,
    },
    /// Pass-through copy of source data (`<d>`).
    /// For I1-I5 init packets (no source data), produces zero bytes.
    Data,
    /// Base64 encoding of source data (`<ds>`).
    /// For I1-I5 init packets (no source data), produces zero bytes.
    DataString,
    /// N-byte big-endian length of source data (`<dz N>`).
    DataSize {
        len: usize,
    },
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
                    data_len.div_ceil(3) * 4
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

/// Inverse of [`parse_cps_tag`].
impl fmt::Display for CpsTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CpsTag::Bytes(bytes) => {
                write!(f, "<b 0x")?;
                for byte in bytes {
                    write!(f, "{:02x}", byte)?;
                }
                write!(f, ">")
            }
            CpsTag::Timestamp => write!(f, "<t>"),
            CpsTag::RandomBytes { len } => write!(f, "<r {}>", len),
            CpsTag::RandomChars { len } => write!(f, "<rc {}>", len),
            CpsTag::RandomDigits { len } => write!(f, "<rd {}>", len),
            CpsTag::Data => write!(f, "<d>"),
            CpsTag::DataString => write!(f, "<ds>"),
            CpsTag::DataSize { len } => write!(f, "<dz {}>", len),
        }
    }
}

/// Inverse of [`CpsChain::parse`].
impl fmt::Display for CpsChain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for tag in &self.tags {
            write!(f, "{}", tag)?;
        }
        Ok(())
    }
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
    /// Nothing to check: any subset of I1-I5 is a valid configuration.
    ///
    /// amneziawg-go stores each chain independently and its send path walks all
    /// five slots, emitting every non-nil one (`SendHandshakeInitiation`), so
    /// `i1` plus `i3` with no `i2` is legal there. This used to reject gaps,
    /// which no protocol rule requires.
    pub fn validate(&self) -> Result<(), ConfigError> {
        Ok(())
    }

    /// The configured chains in I1-I5 order, skipping unset slots — the same
    /// order and the same "every non-nil one" rule as amneziawg-go.
    pub fn active_chains(&self) -> impl Iterator<Item = &CpsChain> {
        IntoIterator::into_iter(self.chains()).flatten()
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

    /// Check the invariant `hi >= lo`. The constructors enforce it, but the
    /// fields are public, so aggregate configs re-check before use.
    pub fn validate(&self, field: &'static str) -> Result<(), ConfigError> {
        if self.hi < self.lo {
            return Err(ConfigError::InvalidRange {
                value: format!("{}={}-{}", field, self.lo, self.hi),
                reason: "range end is smaller than start",
            });
        }
        Ok(())
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

/// Inverse of [`U32Range::parse`].
impl fmt::Display for U32Range {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
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
    pub fn validate(&self) -> Result<(), ConfigError> {
        self.rekey_after_time.validate("rekey_after_time")?;
        self.rekey_timeout.validate("rekey_timeout")?;
        self.reject_after_time.validate("reject_after_time")?;
        self.keepalive_timeout.validate("keepalive_timeout")?;
        self.max_handshake_attempts
            .validate("max_handshake_attempts")?;
        self.persistent_keepalive.validate("persistent_keepalive")?;
        Ok(())
    }

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

    /// The first `N` keystream bytes for `prefix`.
    ///
    /// Everything a receiver decrypts in one datagram shares that datagram's
    /// nonce, so the keystream is derived once and XORed wherever it is needed
    /// rather than rebuilding the cipher per use. Drawing 16 bytes covers both
    /// the 4-byte type check and the whole transport header, which is what lets
    /// the receive path classify and decrypt with a single ChaCha20 setup;
    /// amneziawg-go's `typeHash` is the 4-byte case of this.
    pub fn keystream<const N: usize>(&self, prefix: &[u8]) -> [u8; N] {
        let mut mask = [0u8; N];
        self.apply(prefix, &mut mask);
        mask
    }

    /// Keystream bytes `0..4`, the mask over a message type field.
    pub fn type_mask(&self, prefix: &[u8]) -> [u8; 4] {
        self.keystream::<4>(prefix)
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
        self.headers.validate()?;

        if let Some(range) = self.content_padding_addition {
            range.validate("content_padding_addition")?;
        }
        self.timing_ranges.validate()?;

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

    /// Parse a newline-separated `key=value` configuration block in the *UAPI*
    /// spelling — the one amneziawg-tools writes to the socket, not the one an
    /// AmneziaWG `.conf` file carries.
    ///
    /// The two differ, and a `.conf` will not parse as-is: it names fields in
    /// CamelCase (`ContentPaddingAddition`, `HeaderProtectionKey`) and encodes
    /// keys in base64, where UAPI uses snake_case and hex. Case is folded here,
    /// so the AmneziaWG 2.0 names happen to survive (`Jc` -> `jc`), but the 3.0
    /// names do not. Translate a `.conf` the way `awg setconf` does before
    /// feeding it here.
    ///
    /// Recognized keys are the AmneziaWG 2.0 set (`jc`, `jmin`, `jmax`,
    /// `s1`-`s4`, `h1`-`h4`, `i1`-`i5`) plus the 3.0 set
    /// (`header_protection_key` as 64 hex characters,
    /// `content_padding_addition`, `rekey_after_time`, `rekey_timeout`,
    /// `reject_after_time`, `keepalive_timeout`, `max_handshake_attempts`,
    /// `persistent_keepalive_interval`) and the fork-specific `mtu`.
    ///
    /// Blank lines and `#` comments are ignored. Unset keys keep their
    /// defaults, so an empty input yields a standard WireGuard configuration.
    /// Repeated keys take the last value, which is what makes an incremental
    /// overlay possible: serialize a config, append the changed lines, reparse.
    ///
    /// # Errors
    /// Returns [`ConfigError`] for a malformed line, an unknown or legacy key,
    /// an unparseable value, or a combination that fails [`Self::validate`].
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let mut config = Amnezia3Config::default();
        // Header ranges are validated as a set, so collect them before building.
        let mut headers = HeaderConfig::wireguard_compatible();
        let mut saw_header = false;

        for raw_line in input.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (key, value) =
                line.split_once('=')
                    .ok_or_else(|| ConfigError::InvalidConfigLine {
                        line: line.to_owned(),
                        reason: "expected `key=value`",
                    })?;
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();

            match key.as_str() {
                "jc" => config.junk.count = parse_field_u8(&key, value)?,
                "jmin" => config.junk.min_size = parse_field_u16(&key, value)?,
                "jmax" => config.junk.max_size = parse_field_u16(&key, value)?,
                "s1" => config.paddings.s1 = parse_field_u8(&key, value)?,
                "s2" => config.paddings.s2 = parse_field_u8(&key, value)?,
                "s3" => config.paddings.s3 = parse_field_u8(&key, value)?,
                "s4" => config.paddings.s4 = parse_field_u8(&key, value)?,
                "h1" => {
                    headers.init = HeaderRange::parse(value)?;
                    saw_header = true;
                }
                "h2" => {
                    headers.response = HeaderRange::parse(value)?;
                    saw_header = true;
                }
                "h3" => {
                    headers.cookie = HeaderRange::parse(value)?;
                    saw_header = true;
                }
                "h4" => {
                    headers.transport = HeaderRange::parse(value)?;
                    saw_header = true;
                }
                "i1" => config.init_packets.i1 = Some(CpsChain::parse(value)?),
                "i2" => config.init_packets.i2 = Some(CpsChain::parse(value)?),
                "i3" => config.init_packets.i3 = Some(CpsChain::parse(value)?),
                "i4" => config.init_packets.i4 = Some(CpsChain::parse(value)?),
                "i5" => config.init_packets.i5 = Some(CpsChain::parse(value)?),
                "header_protection_key" => {
                    let key = parse_header_protection_key(value)?;
                    // An all-zero key means "disabled" upstream.
                    config.header_protection_key = if key.iter().all(|byte| *byte == 0) {
                        None
                    } else {
                        Some(key)
                    };
                }
                "content_padding_addition" => {
                    let range = U32Range::parse(value)?;
                    config.content_padding_addition =
                        if range.is_zero() { None } else { Some(range) };
                }
                "rekey_after_time" => {
                    config.timing_ranges.rekey_after_time = U32Range::parse(value)?
                }
                "rekey_timeout" => config.timing_ranges.rekey_timeout = U32Range::parse(value)?,
                "reject_after_time" => {
                    config.timing_ranges.reject_after_time = U32Range::parse(value)?
                }
                "keepalive_timeout" => {
                    config.timing_ranges.keepalive_timeout = U32Range::parse(value)?
                }
                "max_handshake_attempts" => {
                    config.timing_ranges.max_handshake_attempts = U32Range::parse(value)?
                }
                // Per-peer upstream; `Tunn` is already per-peer, so it lands in
                // the timing ranges alongside the device-scoped ones.
                "persistent_keepalive_interval" => {
                    config.timing_ranges.persistent_keepalive = U32Range::parse(value)?
                }
                // Not an upstream UAPI key: amneziawg-go clamps content padding
                // against the device MTU, which `Tunn` has no concept of.
                "mtu" => config.mtu = parse_field_u32(&key, value)?,
                _ => {
                    // Reuse the 2.0 key table so the AmneziaWG 1.x fields keep
                    // reporting as legacy rather than merely unknown. Every key
                    // it accepts is handled above, so this always errors.
                    Amnezia2Config::validate_field_name(&key)?;
                    return Err(ConfigError::UnsupportedLegacyField { field: key });
                }
            }
        }

        if saw_header {
            config.headers = HeaderConfig::new(
                headers.init,
                headers.response,
                headers.cookie,
                headers.transport,
            )?;
        }

        config.validate()?;
        Ok(config)
    }

    /// Serialize back to the `key=value` block [`Self::parse`] accepts.
    ///
    /// Only fields that differ from the default are emitted, so a standard
    /// WireGuard configuration produces an empty string and `get=1` stays
    /// byte-identical to upstream boringtun for non-AmneziaWG devices.
    ///
    /// Every emitted line round-trips: `parse(&cfg.to_uapi_block()) == cfg`.
    pub fn to_uapi_block(&self) -> String {
        use std::fmt::Write as _;

        let default = Amnezia3Config::default();
        let mut out = String::new();

        if self.junk != default.junk {
            let _ = writeln!(out, "jc={}", self.junk.count);
            let _ = writeln!(out, "jmin={}", self.junk.min_size);
            let _ = writeln!(out, "jmax={}", self.junk.max_size);
        }

        for (key, value, fallback) in [
            ("s1", self.paddings.s1, default.paddings.s1),
            ("s2", self.paddings.s2, default.paddings.s2),
            ("s3", self.paddings.s3, default.paddings.s3),
            ("s4", self.paddings.s4, default.paddings.s4),
        ] {
            if value != fallback {
                let _ = writeln!(out, "{}={}", key, value);
            }
        }

        // Header ranges are a set: emit all four if any one differs, so the
        // parser rebuilds them through `HeaderConfig::new` and re-checks for
        // overlap.
        if self.headers != default.headers {
            let _ = writeln!(out, "h1={}", self.headers.init);
            let _ = writeln!(out, "h2={}", self.headers.response);
            let _ = writeln!(out, "h3={}", self.headers.cookie);
            let _ = writeln!(out, "h4={}", self.headers.transport);
        }

        for (key, chain) in [
            ("i1", &self.init_packets.i1),
            ("i2", &self.init_packets.i2),
            ("i3", &self.init_packets.i3),
            ("i4", &self.init_packets.i4),
            ("i5", &self.init_packets.i5),
        ] {
            if let Some(chain) = chain {
                let _ = writeln!(out, "{}={}", key, chain);
            }
        }

        if let Some(key) = self.header_protection_key {
            let _ = write!(out, "header_protection_key=");
            for byte in key {
                let _ = write!(out, "{:02x}", byte);
            }
            let _ = writeln!(out);
        }

        if let Some(range) = self.content_padding_addition {
            let _ = writeln!(out, "content_padding_addition={}", range);
        }

        for (key, range) in [
            ("rekey_after_time", self.timing_ranges.rekey_after_time),
            ("rekey_timeout", self.timing_ranges.rekey_timeout),
            ("reject_after_time", self.timing_ranges.reject_after_time),
            ("keepalive_timeout", self.timing_ranges.keepalive_timeout),
            (
                "max_handshake_attempts",
                self.timing_ranges.max_handshake_attempts,
            ),
            (
                "persistent_keepalive_interval",
                self.timing_ranges.persistent_keepalive,
            ),
        ] {
            if !range.is_zero() {
                let _ = writeln!(out, "{}={}", key, range);
            }
        }

        if self.mtu != default.mtu {
            let _ = writeln!(out, "mtu={}", self.mtu);
        }

        out
    }
}

fn parse_field_u8(field: &str, value: &str) -> Result<u8, ConfigError> {
    value
        .parse::<u8>()
        .map_err(|_| ConfigError::InvalidFieldValue {
            field: field.to_owned(),
            reason: "expected a decimal value in 0-255",
        })
}

fn parse_field_u16(field: &str, value: &str) -> Result<u16, ConfigError> {
    value
        .parse::<u16>()
        .map_err(|_| ConfigError::InvalidFieldValue {
            field: field.to_owned(),
            reason: "expected a decimal value in 0-65535",
        })
}

fn parse_field_u32(field: &str, value: &str) -> Result<u32, ConfigError> {
    value
        .parse::<u32>()
        .map_err(|_| ConfigError::InvalidFieldValue {
            field: field.to_owned(),
            reason: "expected a decimal value",
        })
}

/// Decode the 32-byte header protection key from hex, as amneziawg-go's UAPI
/// does. An all-zero key means "disabled", matching `HeaderCipherKey::IsZero`.
fn parse_header_protection_key(
    value: &str,
) -> Result<[u8; HEADER_PROTECTION_KEY_SIZE], ConfigError> {
    use std::convert::TryInto;

    let bytes = hex::decode(value).map_err(|_| ConfigError::InvalidFieldValue {
        field: "header_protection_key".to_owned(),
        reason: "expected hex characters",
    })?;
    let key: [u8; HEADER_PROTECTION_KEY_SIZE] =
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| ConfigError::InvalidFieldValue {
                field: "header_protection_key".to_owned(),
                reason: "expected exactly 32 bytes (64 hex characters)",
            })?;
    Ok(key)
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
        self.headers.validate()
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

    /// Accept the AmneziaWG 2.0 configuration keys, rejecting the AmneziaWG
    /// 1.x fields (`j1`, `j2`, `j3`, `itime`) explicitly.
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

    /// amneziawg-go defaults H1-H4 to the standard WireGuard types 1-4 and
    /// never refuses them, so a configuration that turns on junk, padding or
    /// I-packets while leaving the headers alone is ordinary AmneziaWG. This
    /// used to reject exactly that, which made `s1=16 s2=16 s3=16 s4=16` — a
    /// perfectly valid obfuscation profile — unconfigurable.
    /// The buffered RNG must produce fresh output, not a repeating buffer.
    #[test]
    fn fast_random_does_not_repeat_within_a_thread() {
        // More than one buffer's worth, so the refill path is exercised.
        let mut first = vec![0u8; FAST_RNG_BUFFER_SIZE * 3];
        let mut second = vec![0u8; FAST_RNG_BUFFER_SIZE * 3];
        FastRandom.fill_bytes(&mut first);
        FastRandom.fill_bytes(&mut second);
        assert_ne!(first, second, "consecutive draws must differ");

        // No buffer-sized block should repeat within a single draw either,
        // which is what a counter that failed to advance would look like.
        let block = &first[..FAST_RNG_BUFFER_SIZE];
        assert_ne!(
            block,
            &first[FAST_RNG_BUFFER_SIZE..FAST_RNG_BUFFER_SIZE * 2]
        );
        assert_ne!(block, &first[FAST_RNG_BUFFER_SIZE * 2..]);
    }

    /// A buffered userspace RNG's one failure mode the OS RNG does not have:
    /// `fork` copies the buffer, so without the generation check the child
    /// replays bytes the parent will also emit. For the S1-S4 prefix those
    /// bytes are the header protection nonce, and a repeat is keystream reuse.
    ///
    /// This is not hypothetical — `boringtun-cli` forks to daemonize.
    #[cfg(unix)]
    #[test]
    fn fork_does_not_duplicate_the_keystream() {
        const N: usize = 64;

        // Prime the buffer so the child inherits unconsumed bytes. Without the
        // per-draw generation check it would hand those out verbatim.
        let mut primer = [0u8; 16];
        FastRandom.fill_bytes(&mut primer);

        let mut fds = [0i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
        let (read_fd, write_fd) = (fds[0], fds[1]);

        let pid = unsafe { libc::fork() };
        assert!(pid >= 0, "fork failed");

        if pid == 0 {
            // Child. Only async-signal-safe work: the draw touches a
            // thread-local and may call getrandom, and the write is a syscall.
            let mut child_bytes = [0u8; N];
            FastRandom.fill_bytes(&mut child_bytes);
            unsafe {
                libc::write(write_fd, child_bytes.as_ptr() as *const libc::c_void, N);
                libc::_exit(0);
            }
        }

        let mut parent_bytes = [0u8; N];
        FastRandom.fill_bytes(&mut parent_bytes);

        unsafe { libc::close(write_fd) };
        let mut child_bytes = [0u8; N];
        let mut read_total = 0;
        while read_total < N {
            let n = unsafe {
                libc::read(
                    read_fd,
                    child_bytes.as_mut_ptr().add(read_total) as *mut libc::c_void,
                    N - read_total,
                )
            };
            assert!(n > 0, "short read from child");
            read_total += n as usize;
        }
        unsafe {
            libc::close(read_fd);
            libc::waitpid(pid, std::ptr::null_mut(), 0);
        }

        assert_ne!(
            parent_bytes.as_slice(),
            child_bytes.as_slice(),
            "parent and child emitted identical bytes after fork — the buffered \
             state was inherited, which for an S1-S4 prefix is nonce reuse"
        );
    }

    #[test]
    fn accepts_standard_headers_alongside_other_awg_features() {
        let mut config = Amnezia2Config::default();
        config.paddings.s1 = 1;
        config
            .validate()
            .expect("padding with default headers is valid");

        let config = Amnezia2Config {
            paddings: PaddingConfig::new(16, 16, 16, 16).unwrap(),
            junk: JunkConfig::new(3, 64, 256).unwrap(),
            ..Amnezia2Config::default()
        };
        config
            .validate()
            .expect("junk with default headers is valid");

        let config = Amnezia3Config {
            paddings: PaddingConfig::new(16, 16, 16, 16).unwrap(),
            ..Amnezia3Config::default()
        };
        config
            .validate()
            .expect("AWG 3.0 padding with default headers is valid");
    }

    #[test]
    fn allows_standard_headers_for_wireguard_compatible_config() {
        let config = Amnezia2Config::default();
        assert!(config.is_wireguard_compatible());
        config.validate().unwrap();
    }

    /// amneziawg-go applies no maximum to S1-S4, so neither do we. This used to
    /// cap handshake padding at 64 and transport padding at 32, values taken
    /// from Amnezia's documentation rather than the protocol, which rejected
    /// configurations that real AmneziaWG servers issue.
    #[test]
    fn accepts_padding_the_reference_implementation_accepts() {
        PaddingConfig::new(64, 64, 64, 32).unwrap();
        // The shape that a live server handed us and this used to refuse.
        PaddingConfig::new(53, 65, 17, 16).unwrap();
        // Bounded only by the field type.
        PaddingConfig::new(255, 255, 255, 255).unwrap();
    }

    #[test]
    fn validates_junk_config() {
        JunkConfig::disabled().validate().unwrap();
        JunkConfig::new(10, 64, 1024).unwrap();
        // Values outside Amnezia's documented ranges are still valid protocol,
        // and upstream bounds none of them.
        JunkConfig::new(11, 64, 1024).unwrap();
        JunkConfig::new(1, 63, 1024).unwrap();
        JunkConfig::new(128, 8, 40000).unwrap();
        // A real server config.
        JunkConfig::new(8, 75, 123).unwrap();

        // Still refused: the generator cannot draw from an inverted range.
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
            &[
                CpsTag::Data,
                CpsTag::DataString,
                CpsTag::DataSize { len: 4 },
            ]
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

    /// amneziawg-go stores I1-I5 independently and sends every non-nil chain,
    /// so any subset is valid and a gap is not an error. This used to require
    /// I1 and refuse gaps.
    #[test]
    fn accepts_any_subset_of_init_packet_chains() {
        let config = InitPacketConfig {
            i1: None,
            i2: Some(chain("<r 1>")),
            i3: None,
            i4: None,
            i5: None,
        };
        config.validate().expect("I2 without I1 is valid");

        let config = InitPacketConfig {
            i1: Some(chain("<r 1>")),
            i2: None,
            i3: Some(chain("<r 1>")),
            i4: None,
            i5: None,
        };
        config.validate().expect("a gap at I2 is valid");
    }

    /// Every configured chain is emitted, in I1-I5 order, gaps included — the
    /// same rule as amneziawg-go's send path. Truncating at the first gap would
    /// silently drop I-packets a peer expects on the wire.
    #[test]
    fn iterates_every_configured_init_packet_chain() {
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

        let config = InitPacketConfig {
            i1: Some(chain("<r 1>")),
            i2: None,
            i3: Some(chain("<r 3>")),
            i4: None,
            i5: Some(chain("<r 5>")),
        };
        let lengths = config
            .active_chains()
            .map(|c| c.encoded_len_for_init())
            .collect::<Vec<_>>();
        assert_eq!(lengths, vec![1, 3, 5]);
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
            assert!(b.is_ascii_digit(), "byte {} is not a digit", b);
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
            assert!((100..=200).contains(&v), "value {} out of range", v);
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
            // Half-open [64, 128), matching amneziawg-go's JunkPackets.
            assert!(
                pkt.len() >= 64 && pkt.len() < 128,
                "size {} out of range",
                pkt.len()
            );
        }
    }

    #[test]
    fn junk_size_upper_bound_is_exclusive() {
        // amneziawg-go draws `min + fastrandn(max - min)`, so `max` itself is
        // never produced. With a two-value span every packet must be `min`
        // or `min + 1`, and over many draws both must appear.
        let config = JunkConfig::new(10, 64, 66).unwrap();
        let mut sizes = std::collections::HashSet::new();
        for seed in 0..32u8 {
            let mut rng = DetRng::new(seed);
            for pkt in config.generate_junk_packets(&mut rng) {
                assert!(pkt.len() == 64 || pkt.len() == 65, "size {}", pkt.len());
                sizes.insert(pkt.len());
            }
        }
        assert_eq!(sizes.len(), 2, "both sizes in [64, 66) should occur");
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
    fn gen_range_u32_handles_full_and_inverted_spans() {
        let mut rng = DetRng::new(0x11);
        // A full-width span must not overflow the `end - start + 1` count.
        for _ in 0..8 {
            let _ = rng.gen_range_u32(0, u32::MAX);
        }
        assert!(rng.gen_range_u32(u32::MAX - 1, u32::MAX) >= u32::MAX - 1);
        // An inverted span degenerates to its start.
        assert_eq!(rng.gen_range_u32(50, 10), 50);
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
    fn amnezia3_parses_a_full_config_block() {
        let config = Amnezia3Config::parse(
            "\n\
             # AmneziaWG 3.0\n\
             jc=4\n\
             jmin=64\n\
             jmax=256\n\
             s1=16\n\
             s2=17\n\
             s3=18\n\
             s4=19\n\
             h1=100-199\n\
             h2=200-299\n\
             h3=300-399\n\
             h4=400-499\n\
             i1=<b 0xff><r 16>\n\
             header_protection_key=\
             4242424242424242424242424242424242424242424242424242424242424242\n\
             content_padding_addition=1-64\n\
             rekey_after_time=100-140\n\
             rekey_timeout=3-9\n\
             reject_after_time=170-200\n\
             keepalive_timeout=8-15\n\
             max_handshake_attempts=10-20\n\
             persistent_keepalive_interval=20-30\n\
             mtu=1400\n",
        )
        .expect("valid config block");

        assert_eq!(
            config.junk,
            JunkConfig::new(4, 64, 256).expect("valid junk")
        );
        assert_eq!(
            config.paddings,
            PaddingConfig::new(16, 17, 18, 19).expect("valid paddings")
        );
        assert_eq!(config.headers.init, HeaderRange::new(100, 199).unwrap());
        assert_eq!(
            config.headers.transport,
            HeaderRange::new(400, 499).unwrap()
        );
        assert!(config.init_packets.i1.is_some());
        assert!(config.init_packets.i2.is_none());
        assert_eq!(config.header_protection_key, Some([0x42; 32]));
        assert_eq!(
            config.content_padding_addition,
            Some(U32Range { lo: 1, hi: 64 })
        );
        assert_eq!(
            config.timing_ranges.rekey_timeout,
            U32Range { lo: 3, hi: 9 }
        );
        assert_eq!(
            config.timing_ranges.persistent_keepalive,
            U32Range { lo: 20, hi: 30 }
        );
        assert_eq!(config.mtu, 1400);
    }

    /// `to_uapi_block` is what `get=1` returns, so it has to feed straight back
    /// into `parse` — that is the property `awg showconf` depends on.
    #[test]
    fn amnezia3_uapi_block_round_trips() {
        let block = "jc=4\n\
                     jmin=64\n\
                     jmax=256\n\
                     s1=16\n\
                     s2=17\n\
                     s3=18\n\
                     s4=19\n\
                     h1=100-199\n\
                     h2=200-299\n\
                     h3=300-399\n\
                     h4=400-499\n\
                     i1=<b 0xff><r 16>\n\
                     i2=<t><rc 8><rd 4><dz 2>\n\
                     header_protection_key=\
                     4242424242424242424242424242424242424242424242424242424242424242\n\
                     content_padding_addition=1-64\n\
                     rekey_after_time=100-140\n\
                     rekey_timeout=3-9\n\
                     reject_after_time=170-200\n\
                     keepalive_timeout=8-15\n\
                     max_handshake_attempts=10-20\n\
                     persistent_keepalive_interval=20-30\n\
                     mtu=1400\n";

        let config = Amnezia3Config::parse(block).expect("valid config block");
        let emitted = config.to_uapi_block();

        // Every key survives the round trip...
        assert_eq!(
            Amnezia3Config::parse(&emitted).expect("emitted block re-parses"),
            config
        );
        // ...and the emitted text matches the input, since the input is already
        // in canonical form. This catches silently dropped keys, which an
        // equality-only check would miss if `parse` also ignored them.
        assert_eq!(emitted, block);
    }

    /// A configuration in the shape a real Amnezia server issues: every AWG 3.0
    /// key set at once, `S2` above 64, single-value timing ranges, and a
    /// content-padding range starting at zero. This shape was rejected before
    /// the padding and junk limits were relaxed to match amneziawg-go, because
    /// `s2 > 64` tripped a cap taken from Amnezia's documentation rather than
    /// from the protocol.
    ///
    /// The values here are synthetic on purpose. A deployment's H1-H4, S1-S4
    /// and junk profile are what make its traffic *not* look like WireGuard, so
    /// publishing a real server's set hands a censor an exact signature for it —
    /// the type field matches H1-H4, the initiation is `148 + S1` bytes, the
    /// response `92 + S2`. Reproduce a real config's *shape* when adding a
    /// regression test; never its numbers.
    #[test]
    fn amnezia3_parses_a_fully_populated_server_config() {
        let config = Amnezia3Config::parse(
            "jc=8\n\
             jmin=75\n\
             jmax=123\n\
             s1=40\n\
             s2=97\n\
             s3=20\n\
             s4=16\n\
             h1=1000000-1000999\n\
             h2=2000000-2000999\n\
             h3=3000000-3000999\n\
             h4=4000000-4000999\n\
             content_padding_addition=0-64\n\
             rekey_after_time=121-155\n\
             rekey_timeout=5\n\
             reject_after_time=185-201\n\
             keepalive_timeout=12-26\n\
             max_handshake_attempts=18\n\
             i1=<b 0x160301><r 8>\n\
             i2=<r 28>\n\
             i3=<r 17><t>\n\
             i4=<r 62>\n\
             i5=<t><r 14>\n\
             mtu=1420\n",
        )
        .expect("a fully populated server configuration must be accepted");

        assert_eq!(config.paddings.s2, 97, "S2 above 64 must survive");
        assert_eq!(config.junk.count, 8);
        // Single values are ranges of one, not an error.
        assert_eq!(config.timing_ranges.rekey_timeout, U32Range::single(5));
        assert_eq!(
            config.timing_ranges.max_handshake_attempts,
            U32Range::single(18)
        );
        // A range starting at zero is still enabled; only an all-zero range is
        // "unset".
        assert_eq!(
            config.content_padding_addition,
            Some(U32Range { lo: 0, hi: 64 })
        );
        assert!(config.header_protection_key.is_none());
        assert!(config.init_packets.i5.is_some());
    }

    /// A plain WireGuard device must not grow AmneziaWG lines in `get=1`.
    #[test]
    fn amnezia3_uapi_block_is_empty_for_wireguard_defaults() {
        assert_eq!(Amnezia3Config::default().to_uapi_block(), "");
        assert_eq!(Amnezia3Config::wireguard_compatible().to_uapi_block(), "");
    }

    /// A 2.0-only config must not acquire 3.0 keys on the way out.
    #[test]
    fn amnezia3_uapi_block_round_trips_a_two_zero_config() {
        let config = Amnezia3Config::parse(
            "jc=2\njmin=64\njmax=128\ns1=8\ns2=8\nh1=100\nh2=200\nh3=300\nh4=400\n",
        )
        .expect("valid 2.0 block");

        let emitted = config.to_uapi_block();
        assert!(!emitted.contains("header_protection_key"));
        assert!(!emitted.contains("content_padding_addition"));
        assert!(!emitted.contains("rekey_timeout"));
        assert!(!emitted.contains("mtu="));
        // Single-value ranges emit without a redundant `a-a` form.
        assert!(emitted.contains("h1=100\n"), "emitted: {}", emitted);
        assert_eq!(
            Amnezia3Config::parse(&emitted).expect("emitted block re-parses"),
            config
        );
    }

    #[test]
    fn amnezia3_parses_empty_and_two_zero_configs() {
        // Nothing configured is standard WireGuard.
        let config = Amnezia3Config::parse("").expect("empty input is valid");
        assert_eq!(config, Amnezia3Config::default());

        // A 2.0-only block leaves every 3.0 feature off.
        let config = Amnezia3Config::parse(
            "jc=2\njmin=64\njmax=128\ns1=8\ns2=8\nh1=100\nh2=200\nh3=300\nh4=400\n",
        )
        .expect("valid 2.0 block");
        assert_eq!(config.header_protection_key, None);
        assert_eq!(config.content_padding_addition, None);
        assert!(config.timing_ranges.is_zero());
        assert_eq!(config.mtu, AWG3_DEFAULT_MTU);
    }

    #[test]
    fn amnezia3_parse_treats_zero_valued_keys_as_unset() {
        let config = Amnezia3Config::parse(
            "header_protection_key=\
             0000000000000000000000000000000000000000000000000000000000000000\n\
             content_padding_addition=0\n",
        )
        .expect("zero values disable the features");
        assert_eq!(config.header_protection_key, None);
        assert_eq!(config.content_padding_addition, None);
    }

    #[test]
    fn amnezia3_parse_rejects_bad_input() {
        // Malformed line
        assert!(matches!(
            Amnezia3Config::parse("jc"),
            Err(ConfigError::InvalidConfigLine { .. })
        ));
        // AmneziaWG 1.x fields still report as legacy
        assert!(matches!(
            Amnezia3Config::parse("itime=30"),
            Err(ConfigError::UnsupportedLegacyField { .. })
        ));
        assert!(matches!(
            Amnezia3Config::parse("j1=whatever"),
            Err(ConfigError::UnsupportedLegacyField { .. })
        ));
        // Unknown key
        assert!(Amnezia3Config::parse("not_a_key=1").is_err());
        // Non-numeric scalar
        assert!(matches!(
            Amnezia3Config::parse("s1=big"),
            Err(ConfigError::InvalidFieldValue { .. })
        ));
        // Bad header protection keys
        assert!(matches!(
            Amnezia3Config::parse("header_protection_key=zz"),
            Err(ConfigError::InvalidFieldValue { .. })
        ));
        assert!(matches!(
            Amnezia3Config::parse("header_protection_key=4242"),
            Err(ConfigError::InvalidFieldValue { .. })
        ));
        // Inverted range
        assert!(Amnezia3Config::parse("rekey_timeout=9-3").is_err());
        // Overlapping headers are caught by HeaderConfig::new
        assert!(Amnezia3Config::parse("h1=100-200\nh2=150-250\nh3=300\nh4=400").is_err());
    }

    #[test]
    fn amnezia3_parse_enforces_header_protection_padding() {
        // S1-S4 >= 12 is enforced through the shared validate().
        let config = "h1=100\nh2=200\nh3=300\nh4=400\n\
                      s1=11\ns2=16\ns3=16\ns4=16\n\
                      header_protection_key=\
                      4242424242424242424242424242424242424242424242424242424242424242\n";
        assert!(matches!(
            Amnezia3Config::parse(config),
            Err(ConfigError::HeaderProtectionPaddingTooSmall { .. })
        ));
    }

    #[test]
    fn amnezia3_rejects_inverted_ranges() {
        // U32Range's fields are public, so a struct literal can bypass `new`.
        let mut config = awg3_base_config();
        config.content_padding_addition = Some(U32Range { lo: 64, hi: 8 });
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRange { .. })
        ));

        let mut config = awg3_base_config();
        config.timing_ranges = TimingRanges {
            keepalive_timeout: U32Range { lo: 30, hi: 10 },
            ..TimingRanges::default()
        };
        assert!(matches!(
            config.validate(),
            Err(ConfigError::InvalidRange { .. })
        ));
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
