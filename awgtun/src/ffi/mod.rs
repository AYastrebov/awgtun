// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Requiring explicit per-fn "Safety" docs not worth it. Just pass in valid
// pointers and buffers/lengths to these, ok?
#![allow(clippy::missing_safety_doc)]

//! C bindings for the awgtun library
use super::noise::{Tunn, TunnResult};
use crate::amnezia::{
    Amnezia2Config, Amnezia3Config, CpsChain, HeaderConfig, HeaderRange, InitPacketConfig,
    JunkConfig, PaddingConfig, TimingRanges, U32Range, HEADER_PROTECTION_KEY_SIZE,
};
use crate::x25519::{PublicKey, StaticSecret};
use base64::Engine as _;
use hex::encode as encode_hex;
use libc::{raise, SIGSEGV};
use parking_lot::Mutex;
use rand_core::OsRng;
use tracing;
use tracing_subscriber::fmt;

use crate::serialization::KeyBytes;
use std::ffi::{CStr, CString};
use std::io::{Error, Write};
use std::os::raw::c_char;
use std::panic;
use std::ptr;
use std::ptr::null_mut;
use std::slice;
use std::sync::Once;

static PANIC_HOOK: Once = Once::new();

#[allow(non_camel_case_types)]
#[repr(C)]
/// Indicates the operation required from the caller
pub enum result_type {
    /// No operation is required.
    WIREGUARD_DONE = 0,
    /// Write dst buffer to network. Size indicates the number of bytes to write.
    WRITE_TO_NETWORK = 1,
    /// Some error occurred, no operation is required. Size indicates error code.
    WIREGUARD_ERROR = 2,
    /// Write dst buffer to the interface as an ipv4 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV4 = 4,
    /// Write dst buffer to the interface as an ipv6 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV6 = 6,
}

/// The return type of WireGuard functions
#[repr(C)]
pub struct wireguard_result {
    /// The operation to be performed by the caller
    pub op: result_type,
    /// Additional information, required to perform the operation
    pub size: usize,
}

#[repr(C)]
pub struct stats {
    pub time_since_last_handshake: i64,
    pub tx_bytes: usize,
    pub rx_bytes: usize,
    pub estimated_loss: f32,
    pub estimated_rtt: i32,
    reserved: [u8; 56], // Make sure to add new fields in this space, keeping total size constant
}

impl<'a> From<TunnResult<'a>> for wireguard_result {
    fn from(res: TunnResult<'a>) -> wireguard_result {
        match res {
            TunnResult::Done => wireguard_result {
                op: result_type::WIREGUARD_DONE,
                size: 0,
            },
            TunnResult::Err(e) => wireguard_result {
                op: result_type::WIREGUARD_ERROR,
                size: e as _,
            },
            TunnResult::WriteToNetwork(b) => wireguard_result {
                op: result_type::WRITE_TO_NETWORK,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV4(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV4,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV6(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV6,
                size: b.len(),
            },
        }
    }
}

#[repr(C)]
pub struct x25519_key {
    pub key: [u8; 32],
}

/// Generates a new x25519 secret key.
#[no_mangle]
pub extern "C" fn x25519_secret_key() -> x25519_key {
    x25519_key {
        key: StaticSecret::random_from_rng(OsRng).to_bytes(),
    }
}

/// Computes a public x25519 key from a secret key.
#[no_mangle]
pub extern "C" fn x25519_public_key(private_key: x25519_key) -> x25519_key {
    let private = StaticSecret::from(private_key.key);
    let public = PublicKey::from(&private);
    x25519_key {
        key: public.to_bytes(),
    }
}

/// Returns the base64 encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[no_mangle]
pub extern "C" fn x25519_key_to_base64(key: x25519_key) -> *const c_char {
    let encoded_key = base64::engine::general_purpose::STANDARD.encode(key.key);
    CString::into_raw(CString::new(encoded_key).unwrap())
}

/// Returns the hex encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[no_mangle]
pub extern "C" fn x25519_key_to_hex(key: x25519_key) -> *const c_char {
    let encoded_key = encode_hex(key.key);
    CString::into_raw(CString::new(encoded_key).unwrap())
}

/// Frees memory of the string given by `x25519_key_to_hex` or `x25519_key_to_base64`
#[no_mangle]
pub unsafe extern "C" fn x25519_key_to_str_free(stringified_key: *mut c_char) {
    drop(CString::from_raw(stringified_key));
}

/// Check if the input C-string represents a valid base64 encoded x25519 key.
/// Return 1 if valid 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn check_base64_encoded_x25519_key(key: *const c_char) -> i32 {
    let c_str = CStr::from_ptr(key);
    let utf8_key = match c_str.to_str() {
        Err(_) => return 0,
        Ok(string) => string,
    };

    if let Ok(key) = base64::engine::general_purpose::STANDARD.decode(utf8_key) {
        let len = key.len();
        let mut zero = 0u8;
        for b in key {
            zero |= b
        }
        if len == 32 && zero != 0 {
            1
        } else {
            0
        }
    } else {
        0
    }
}

/// Custom tracing_subscriber writer to an external function pointer
struct FFIFunctionPointerWriter {
    log_func: unsafe extern "C" fn(*const c_char),
}

/// Implements Write trait for use with tracing_subscriber
impl Write for FFIFunctionPointerWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        let out_str = String::from_utf8_lossy(buf).to_string();
        if let Ok(c_string) = CString::new(out_str) {
            unsafe { (self.log_func)(c_string.as_ptr()) }
            Ok(buf.len())
        } else {
            Err(Error::other("Failed to create CString from buffer."))
        }
    }

    fn flush(&mut self) -> Result<(), std::io::Error> {
        // no-op
        Ok(())
    }
}

/// Sets the default tracing_subscriber to write to `log_func`.
///
/// Uses Compact format without level, target, thread ids, thread names, or ansi control characters.
/// Subscribes to TRACE level events.
///
/// This function should only be called once as setting the default tracing_subscriber
/// more than once will result in an error.
///
/// Returns false on failure.
///
/// # Safety
///
/// `c_char` will be freed by the library after calling `log_func`. If the value needs
/// to be stored then `log_func` needs to create a copy, e.g. `strcpy`.
#[no_mangle]
pub unsafe extern "C" fn set_logging_function(
    log_func: unsafe extern "C" fn(*const c_char),
) -> bool {
    let result = std::panic::catch_unwind(|| -> bool {
        let writer = FFIFunctionPointerWriter { log_func };
        let format = fmt::format()
            // don't include levels in formatted output
            .with_level(false)
            // don't include targets
            .with_target(false)
            // don't 'include the thread ID of the current thread
            .with_thread_ids(false)
            // don't 'include the name of the current thread
            .with_thread_names(false)
            // use the `Compact` formatting style.
            .compact()
            // disable terminal escape codes
            .with_ansi(false);

        fmt()
            .event_format(format)
            .with_writer(std::sync::Mutex::new(writer))
            .with_max_level(tracing::Level::TRACE)
            .with_ansi(false)
            .try_init()
            .is_ok()
    });
    result.unwrap_or_default()
}

/// Allocate a new tunnel, return NULL on failure.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
) -> *mut Mutex<Tunn> {
    let c_str = CStr::from_ptr(static_private);
    let static_private = match c_str.to_str() {
        Err(_) => return ptr::null_mut(),
        Ok(string) => string,
    };

    let c_str = CStr::from_ptr(server_static_public);
    let server_static_public = match c_str.to_str() {
        Err(_) => return ptr::null_mut(),
        Ok(string) => string,
    };

    let preshared_key = if preshared_key.is_null() {
        None
    } else {
        let c_str = CStr::from_ptr(preshared_key);

        if let Ok(string) = c_str.to_str() {
            if let Ok(key) = string.parse::<KeyBytes>() {
                Some(key.0)
            } else {
                return null_mut();
            }
        } else {
            return null_mut();
        }
    };

    let private_key = match static_private.parse::<KeyBytes>() {
        Err(_) => return ptr::null_mut(),
        Ok(key) => StaticSecret::from(key.0),
    };

    let public_key = match server_static_public.parse::<KeyBytes>() {
        Err(_) => return ptr::null_mut(),
        Ok(key) => PublicKey::from(key.0),
    };

    let keep_alive = if keep_alive == 0 {
        None
    } else {
        Some(keep_alive)
    };

    let tunnel = Box::new(Mutex::new(Tunn::new(
        private_key,
        public_key,
        preshared_key,
        keep_alive,
        index,
        None,
    )));

    PANIC_HOOK.call_once(|| {
        // FFI won't properly unwind on panic, but it will if we cause a segmentation fault
        panic::set_hook(Box::new(move |_| {
            raise(SIGSEGV);
        }));
    });

    Box::into_raw(tunnel)
}

/// AmneziaWG 2.0 configuration for the C FFI.
///
/// Set all fields to zero for standard WireGuard behavior.
/// I1-I5 are optional CPS chain strings (UTF-8, null-terminated). Pass NULL to disable.
#[repr(C)]
pub struct amnezia_config {
    /// Dynamic header ranges (H1-H4). Each pair is (start, end) inclusive.
    /// Use start == end for a single fixed value.
    pub h1_start: u32,
    pub h1_end: u32,
    pub h2_start: u32,
    pub h2_end: u32,
    pub h3_start: u32,
    pub h3_end: u32,
    pub h4_start: u32,
    pub h4_end: u32,
    /// Padding sizes (S1-S4)
    pub s1: u8,
    pub s2: u8,
    pub s3: u8,
    pub s4: u8,
    /// Junk packet config
    pub jc: u8,
    pub jmin: u16,
    pub jmax: u16,
    /// CPS init packet chain strings (null-terminated UTF-8, or NULL to skip).
    pub i1: *const c_char,
    pub i2: *const c_char,
    pub i3: *const c_char,
    pub i4: *const c_char,
    pub i5: *const c_char,
}

/// Parse an optional CPS chain from a C string pointer. Returns Ok(None) for NULL.
unsafe fn parse_optional_cps(ptr: *const c_char) -> Result<Option<CpsChain>, ()> {
    if ptr.is_null() {
        return Ok(None);
    }
    let s = CStr::from_ptr(ptr).to_str().map_err(|_| ())?;
    if s.is_empty() {
        return Ok(None);
    }
    CpsChain::parse(s).map(Some).map_err(|_| ())
}

/// Build an [`Amnezia2Config`] from the C representation.
///
/// # Safety
/// `cfg.i1`-`cfg.i5` must each be NULL or a valid null-terminated C string.
unsafe fn amnezia2_from_c(cfg: &amnezia_config) -> Result<Amnezia2Config, ()> {
    let header_bounds = [
        cfg.h1_start,
        cfg.h1_end,
        cfg.h2_start,
        cfg.h2_end,
        cfg.h3_start,
        cfg.h3_end,
        cfg.h4_start,
        cfg.h4_end,
    ];
    // Leaving every H field zero means "standard WireGuard headers"; taking the
    // values literally would produce four identical, overlapping ranges.
    let headers = if header_bounds.iter().all(|bound| *bound == 0) {
        HeaderConfig::wireguard_compatible()
    } else {
        HeaderConfig::new(
            HeaderRange {
                start: cfg.h1_start,
                end: cfg.h1_end,
            },
            HeaderRange {
                start: cfg.h2_start,
                end: cfg.h2_end,
            },
            HeaderRange {
                start: cfg.h3_start,
                end: cfg.h3_end,
            },
            HeaderRange {
                start: cfg.h4_start,
                end: cfg.h4_end,
            },
        )
        .map_err(|_| ())?
    };

    let paddings = PaddingConfig::new(cfg.s1, cfg.s2, cfg.s3, cfg.s4).map_err(|_| ())?;

    let junk = if cfg.jc == 0 {
        JunkConfig::disabled()
    } else {
        JunkConfig::new(cfg.jc, cfg.jmin, cfg.jmax).map_err(|_| ())?
    };

    Ok(Amnezia2Config {
        headers,
        paddings,
        junk,
        init_packets: InitPacketConfig {
            i1: parse_optional_cps(cfg.i1)?,
            i2: parse_optional_cps(cfg.i2)?,
            i3: parse_optional_cps(cfg.i3)?,
            i4: parse_optional_cps(cfg.i4)?,
            i5: parse_optional_cps(cfg.i5)?,
        },
    })
}

/// The keys and keepalive shared by every `new_tunnel*` entry point.
pub(crate) struct TunnelIdentity {
    private_key: StaticSecret,
    public_key: PublicKey,
    preshared_key: Option<[u8; 32]>,
    keep_alive: Option<u16>,
}

/// Parse the base64 key arguments common to all constructors.
///
/// # Safety
/// `static_private` and `server_static_public` must be valid null-terminated C
/// strings; `preshared_key` must be NULL or one.
pub(crate) unsafe fn parse_tunnel_identity(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
) -> Result<TunnelIdentity, ()> {
    if static_private.is_null() || server_static_public.is_null() {
        return Err(());
    }

    let private_key = CStr::from_ptr(static_private)
        .to_str()
        .map_err(|_| ())?
        .parse::<KeyBytes>()
        .map(|key| StaticSecret::from(key.0))
        .map_err(|_| ())?;

    let public_key = CStr::from_ptr(server_static_public)
        .to_str()
        .map_err(|_| ())?
        .parse::<KeyBytes>()
        .map(|key| PublicKey::from(key.0))
        .map_err(|_| ())?;

    let preshared_key = if preshared_key.is_null() {
        None
    } else {
        Some(
            CStr::from_ptr(preshared_key)
                .to_str()
                .map_err(|_| ())?
                .parse::<KeyBytes>()
                .map(|key| key.0)
                .map_err(|_| ())?,
        )
    };

    Ok(TunnelIdentity {
        private_key,
        public_key,
        preshared_key,
        keep_alive: if keep_alive == 0 {
            None
        } else {
            Some(keep_alive)
        },
    })
}

/// Install the FFI panic hook: unwinding across the boundary is UB, so turn a
/// panic into a segfault instead.
pub(crate) fn install_panic_hook() {
    PANIC_HOOK.call_once(|| {
        panic::set_hook(Box::new(move |_| {
            // SAFETY: raising SIGSEGV is the intended way to abort here — it is
            // always sound to call and never returns to Rust code.
            unsafe { raise(SIGSEGV) };
        }));
    });
}

/// Build a boxed tunnel from an already-parsed identity and AmneziaWG 3.0
/// configuration, installing the FFI panic hook. Shared by the C and JNI entry
/// points; returns NULL if the configuration is invalid.
pub(crate) fn build_amnezia3_tunnel(
    identity: TunnelIdentity,
    index: u32,
    amnezia: Amnezia3Config,
) -> *mut Mutex<Tunn> {
    let tunnel = match Tunn::new_with_amnezia3(
        identity.private_key,
        identity.public_key,
        identity.preshared_key,
        identity.keep_alive,
        index,
        None,
        amnezia,
    ) {
        Ok(tunnel) => tunnel,
        Err(_) => return null_mut(),
    };

    install_panic_hook();

    Box::into_raw(Box::new(Mutex::new(tunnel)))
}

/// Allocate a new tunnel with AmneziaWG 2.0 configuration.
/// Returns NULL on failure (invalid keys or invalid amnezia config).
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_amnezia(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    config: *const amnezia_config,
) -> *mut Mutex<Tunn> {
    if config.is_null() {
        return new_tunnel(
            static_private,
            server_static_public,
            preshared_key,
            keep_alive,
            index,
        );
    }

    let amnezia = match amnezia2_from_c(&*config) {
        Ok(amnezia) => amnezia,
        Err(()) => return null_mut(),
    };

    let identity = match parse_tunnel_identity(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
    ) {
        Ok(identity) => identity,
        Err(()) => return null_mut(),
    };

    let tunnel = match Tunn::new_with_amnezia(
        identity.private_key,
        identity.public_key,
        identity.preshared_key,
        identity.keep_alive,
        index,
        None,
        amnezia,
    ) {
        Ok(t) => t,
        Err(_) => return null_mut(),
    };

    install_panic_hook();

    Box::into_raw(Box::new(Mutex::new(tunnel)))
}

/// AmneziaWG 3.0 configuration for the C FFI.
///
/// Extends [`amnezia_config`] with header protection, content padding and
/// randomized timings. Zeroing the whole struct yields standard WireGuard
/// behavior.
///
/// Every `*_min`/`*_max` pair is an inclusive range; a pair of zeros means
/// "unset" and falls back to the WireGuard default for that parameter.
#[repr(C)]
pub struct amnezia3_config {
    /// All AmneziaWG 2.0 parameters (H1-H4, S1-S4, Jc/Jmin/Jmax, I1-I5).
    pub base: amnezia_config,
    /// Pointer to a 32-byte header protection key, or NULL to disable header
    /// protection. An all-zero key also disables it, matching amneziawg-go.
    /// When enabled, S1-S4 must all be at least 12.
    pub header_protection_key: *const u8,
    /// Extra zero bytes appended to transport content inside the AEAD envelope.
    pub content_padding_min: u32,
    pub content_padding_max: u32,
    /// Randomized timing ranges, in seconds (attempts is a count).
    pub rekey_after_time_min: u32,
    pub rekey_after_time_max: u32,
    pub rekey_timeout_min: u32,
    pub rekey_timeout_max: u32,
    pub reject_after_time_min: u32,
    pub reject_after_time_max: u32,
    pub keepalive_timeout_min: u32,
    pub keepalive_timeout_max: u32,
    pub max_handshake_attempts_min: u32,
    pub max_handshake_attempts_max: u32,
    /// Persistent keepalive range. When set, it takes precedence over the
    /// `keep_alive` argument passed to `new_tunnel_amnezia3`, and a fresh
    /// interval is drawn from it every time a keepalive fires.
    pub persistent_keepalive_min: u32,
    pub persistent_keepalive_max: u32,
    /// Outer MTU used to clamp content padding. 0 selects the default (1420).
    pub mtu: u32,
    /// AmneziaWG 3.1. Appended after `mtu` so every field above keeps its
    /// offset; a caller that zeroes the struct gets 3.0 behaviour unchanged.
    ///
    /// Non-zero enables random trailers: a random number of bytes on the end of
    /// each handshake, response and cookie datagram, and wider content padding
    /// on transport packets when `content_padding_*` is unset. Both peers must
    /// set it — a receiver only tolerates a trailer when it is on.
    pub random_trailers: u8,
    /// Non-zero suppresses cookie replies entirely.
    pub disable_cookies: u8,
}

/// Build an inclusive range from a C min/max pair. A zero pair means "unset".
fn range_from_c(min: u32, max: u32) -> Result<U32Range, ()> {
    U32Range::new(min, max).map_err(|_| ())
}

/// Read an optional 32-byte header protection key. NULL or all-zero disables
/// header protection, matching amneziawg-go's `HeaderProtectionCipher`.
///
/// # Safety
/// `ptr` must be NULL or point to at least 32 readable bytes.
unsafe fn header_protection_key_from_c(ptr: *const u8) -> Option<[u8; HEADER_PROTECTION_KEY_SIZE]> {
    if ptr.is_null() {
        return None;
    }
    let mut key = [0u8; HEADER_PROTECTION_KEY_SIZE];
    key.copy_from_slice(slice::from_raw_parts(ptr, HEADER_PROTECTION_KEY_SIZE));
    if key.iter().all(|byte| *byte == 0) {
        return None;
    }
    Some(key)
}

/// Allocate a new tunnel with AmneziaWG 3.0 configuration.
/// Returns NULL on failure (invalid keys or invalid amnezia config).
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel_amnezia3(
    static_private: *const c_char,
    server_static_public: *const c_char,
    preshared_key: *const c_char,
    keep_alive: u16,
    index: u32,
    config: *const amnezia3_config,
) -> *mut Mutex<Tunn> {
    if config.is_null() {
        return new_tunnel(
            static_private,
            server_static_public,
            preshared_key,
            keep_alive,
            index,
        );
    }
    let cfg = &*config;

    let base = match amnezia2_from_c(&cfg.base) {
        Ok(base) => base,
        Err(()) => return null_mut(),
    };

    let content_padding = match range_from_c(cfg.content_padding_min, cfg.content_padding_max) {
        Ok(range) if range.is_zero() => None,
        Ok(range) => Some(range),
        Err(()) => return null_mut(),
    };

    let timing_ranges = match (|| {
        Ok(TimingRanges {
            rekey_after_time: range_from_c(cfg.rekey_after_time_min, cfg.rekey_after_time_max)?,
            rekey_timeout: range_from_c(cfg.rekey_timeout_min, cfg.rekey_timeout_max)?,
            reject_after_time: range_from_c(cfg.reject_after_time_min, cfg.reject_after_time_max)?,
            keepalive_timeout: range_from_c(cfg.keepalive_timeout_min, cfg.keepalive_timeout_max)?,
            max_handshake_attempts: range_from_c(
                cfg.max_handshake_attempts_min,
                cfg.max_handshake_attempts_max,
            )?,
            persistent_keepalive: range_from_c(
                cfg.persistent_keepalive_min,
                cfg.persistent_keepalive_max,
            )?,
        })
    })() {
        Ok(ranges) => ranges,
        Err(()) => return null_mut(),
    };

    let mut amnezia = Amnezia3Config::from_amnezia2(base);
    amnezia.header_protection_key = header_protection_key_from_c(cfg.header_protection_key);
    amnezia.content_padding_addition = content_padding;
    amnezia.timing_ranges = timing_ranges;
    amnezia.random_trailers = cfg.random_trailers != 0;
    amnezia.disable_cookies = cfg.disable_cookies != 0;
    if cfg.mtu != 0 {
        amnezia.mtu = cfg.mtu;
    }

    let identity = match parse_tunnel_identity(
        static_private,
        server_static_public,
        preshared_key,
        keep_alive,
    ) {
        Ok(identity) => identity,
        Err(()) => return null_mut(),
    };

    build_amnezia3_tunnel(identity, index, amnezia)
}

/// Returns the next pre-handshake packet (I-packet or junk) that should be sent
/// before the handshake initiation. Writes the packet to dst and returns the size.
/// Returns 0 when there are no more packets to drain.
///
/// Call this in a loop after `new_tunnel_amnezia`, `wireguard_write`, `wireguard_tick`,
/// or `wireguard_force_handshake` until it returns 0, sending each packet to the network.
#[no_mangle]
pub unsafe extern "C" fn wireguard_poll_outgoing_packet(
    tunnel: *const Mutex<Tunn>,
    dst: *mut u8,
    dst_size: u32,
) -> usize {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    match tunnel.poll_outgoing_packet() {
        Some(packet) => {
            let len = packet.len();
            if len > dst_size as usize {
                return 0;
            }
            let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
            dst[..len].copy_from_slice(&packet);
            len
        }
        None => 0,
    }
}

/// Drops the Tunn object
#[no_mangle]
pub unsafe extern "C" fn tunnel_free(tunnel: *mut Mutex<Tunn>) {
    drop(Box::from_raw(tunnel));
}

/// Write an IP packet from the tunnel interface.
/// For more details check noise::tunnel_to_network functions.
#[no_mangle]
pub unsafe extern "C" fn wireguard_write(
    tunnel: *const Mutex<Tunn>,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let src = slice::from_raw_parts(src, src_size as usize);
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.encapsulate(src, dst))
}

/// Read a UDP packet from the server.
/// For more details check noise::network_to_tunnel functions.
#[no_mangle]
pub unsafe extern "C" fn wireguard_read(
    tunnel: *const Mutex<Tunn>,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let src = slice::from_raw_parts(src, src_size as usize);
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.decapsulate(None, src, dst))
}

/// This is a state keeping function, that need to be called periodically.
/// Recommended interval: 100ms.
///
/// `dst` must hold whichever is larger: a handshake initiation (`148 + s1`
/// bytes) or an unpadded keepalive (`32 + s4` bytes). A smaller buffer aborts
/// the process via the FFI panic hook.
///
/// Content padding does not raise that floor — the addition is clamped to the
/// room left in `dst` — but to get the full configured range, allow
/// `content_padding_max` on top of the keepalive size.
#[no_mangle]
pub unsafe extern "C" fn wireguard_tick(
    tunnel: *const Mutex<Tunn>,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.update_timers(dst))
}

/// Force the tunnel to initiate a new handshake, dst buffer must be at least 148 + S1 bytes long.
/// After this call, drain `wireguard_poll_outgoing_packet` before sending the handshake init.
#[no_mangle]
pub unsafe extern "C" fn wireguard_force_handshake(
    tunnel: *const Mutex<Tunn>,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let mut tunnel = tunnel.as_ref().unwrap().lock();
    // Slices are not owned, and therefore will not be freed by Rust
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.format_handshake_initiation(dst, true))
}

/// Returns stats from the tunnel:
/// Time of last handshake in seconds (or -1 if no handshake occurred)
/// Number of data bytes encapsulated
/// Number of data bytes decapsulated
#[no_mangle]
pub unsafe extern "C" fn wireguard_stats(tunnel: *const Mutex<Tunn>) -> stats {
    let tunnel = tunnel.as_ref().unwrap().lock();
    let (time, tx_bytes, rx_bytes, estimated_loss, estimated_rtt) = tunnel.stats();
    stats {
        time_since_last_handshake: time.map(|t| t.as_secs() as i64).unwrap_or(-1),
        tx_bytes,
        rx_bytes,
        estimated_loss,
        estimated_rtt: estimated_rtt.map(|r| r as i32).unwrap_or(-1),
        reserved: [0u8; 56],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn keypair() -> (CString, CString) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (
            CString::new(base64::engine::general_purpose::STANDARD.encode(secret.to_bytes()))
                .expect("no interior nul"),
            CString::new(base64::engine::general_purpose::STANDARD.encode(public.as_bytes()))
                .expect("no interior nul"),
        )
    }

    fn zeroed_config() -> amnezia3_config {
        amnezia3_config {
            base: amnezia_config {
                h1_start: 0,
                h1_end: 0,
                h2_start: 0,
                h2_end: 0,
                h3_start: 0,
                h3_end: 0,
                h4_start: 0,
                h4_end: 0,
                s1: 0,
                s2: 0,
                s3: 0,
                s4: 0,
                jc: 0,
                jmin: 0,
                jmax: 0,
                i1: ptr::null(),
                i2: ptr::null(),
                i3: ptr::null(),
                i4: ptr::null(),
                i5: ptr::null(),
            },
            header_protection_key: ptr::null(),
            content_padding_min: 0,
            content_padding_max: 0,
            rekey_after_time_min: 0,
            rekey_after_time_max: 0,
            rekey_timeout_min: 0,
            rekey_timeout_max: 0,
            reject_after_time_min: 0,
            reject_after_time_max: 0,
            keepalive_timeout_min: 0,
            keepalive_timeout_max: 0,
            max_handshake_attempts_min: 0,
            max_handshake_attempts_max: 0,
            persistent_keepalive_min: 0,
            persistent_keepalive_max: 0,
            mtu: 0,
            random_trailers: 0,
            disable_cookies: 0,
        }
    }

    unsafe fn build(config: &amnezia3_config) -> *mut Mutex<Tunn> {
        let (my_secret, _) = keypair();
        let (_, their_public) = keypair();
        new_tunnel_amnezia3(
            my_secret.as_ptr(),
            their_public.as_ptr(),
            ptr::null(),
            0,
            1,
            config,
        )
    }

    #[test]
    fn amnezia3_zeroed_config_builds_a_wireguard_tunnel() {
        unsafe {
            let tunnel = build(&zeroed_config());
            assert!(!tunnel.is_null());
            tunnel_free(tunnel);
        }
    }

    #[test]
    fn amnezia3_full_config_builds() {
        let key = [0x42u8; HEADER_PROTECTION_KEY_SIZE];
        let mut config = zeroed_config();
        config.base.h1_start = 100;
        config.base.h1_end = 199;
        config.base.h2_start = 200;
        config.base.h2_end = 299;
        config.base.h3_start = 300;
        config.base.h3_end = 399;
        config.base.h4_start = 400;
        config.base.h4_end = 499;
        config.base.s1 = 16;
        config.base.s2 = 16;
        config.base.s3 = 16;
        config.base.s4 = 16;
        config.header_protection_key = key.as_ptr();
        config.content_padding_min = 1;
        config.content_padding_max = 32;
        config.rekey_timeout_min = 3;
        config.rekey_timeout_max = 9;
        config.mtu = 1400;

        unsafe {
            let tunnel = build(&config);
            assert!(!tunnel.is_null());
            tunnel_free(tunnel);
        }
    }

    #[test]
    fn amnezia3_all_zero_key_disables_header_protection() {
        // An all-zero key means "off" in amneziawg-go, so the S1-S4 >= 12 rule
        // must not apply — this config would otherwise be rejected.
        let key = [0u8; HEADER_PROTECTION_KEY_SIZE];
        let mut config = zeroed_config();
        config.header_protection_key = key.as_ptr();
        config.base.h1_start = 100;
        config.base.h1_end = 199;
        config.base.h2_start = 200;
        config.base.h2_end = 299;
        config.base.h3_start = 300;
        config.base.h3_end = 399;
        config.base.h4_start = 400;
        config.base.h4_end = 499;
        config.base.s4 = 1;

        unsafe {
            let tunnel = build(&config);
            assert!(!tunnel.is_null());
            tunnel_free(tunnel);
        }
    }

    #[test]
    fn amnezia3_rejects_short_padding_with_header_protection() {
        let key = [0x42u8; HEADER_PROTECTION_KEY_SIZE];
        let mut config = zeroed_config();
        config.header_protection_key = key.as_ptr();
        config.base.s1 = 11;
        config.base.s2 = 16;
        config.base.s3 = 16;
        config.base.s4 = 16;

        unsafe {
            assert!(build(&config).is_null());
        }
    }

    #[test]
    fn amnezia3_null_config_falls_back_to_wireguard() {
        let (my_secret, _) = keypair();
        let (_, their_public) = keypair();
        unsafe {
            let tunnel = new_tunnel_amnezia3(
                my_secret.as_ptr(),
                their_public.as_ptr(),
                ptr::null(),
                0,
                1,
                ptr::null(),
            );
            assert!(!tunnel.is_null());
            tunnel_free(tunnel);
        }
    }

    #[test]
    fn amnezia3_rejects_invalid_keys_and_null_pointers() {
        let config = zeroed_config();
        let (my_secret, _) = keypair();
        let (_, their_public) = keypair();
        let garbage = CString::new("not-a-base64-key").expect("no interior nul");

        unsafe {
            // NULL key pointers are rejected rather than dereferenced.
            assert!(new_tunnel_amnezia3(
                ptr::null(),
                their_public.as_ptr(),
                ptr::null(),
                0,
                1,
                &config
            )
            .is_null());
            assert!(new_tunnel_amnezia3(
                my_secret.as_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                1,
                &config
            )
            .is_null());
            // Unparseable keys are rejected.
            assert!(new_tunnel_amnezia3(
                garbage.as_ptr(),
                their_public.as_ptr(),
                ptr::null(),
                0,
                1,
                &config
            )
            .is_null());
            // An unparseable preshared key is rejected too.
            assert!(new_tunnel_amnezia3(
                my_secret.as_ptr(),
                their_public.as_ptr(),
                garbage.as_ptr(),
                0,
                1,
                &config
            )
            .is_null());
        }
    }

    #[test]
    fn amnezia3_tunnel_emits_awg3_shaped_packets() {
        // The other FFI tests only prove construction; this one drives the
        // tunnel and checks the wire format actually reflects the config.
        let key = [0x42u8; HEADER_PROTECTION_KEY_SIZE];
        let mut config = zeroed_config();
        config.base.h1_start = 100;
        config.base.h1_end = 199;
        config.base.h2_start = 200;
        config.base.h2_end = 299;
        config.base.h3_start = 300;
        config.base.h3_end = 399;
        config.base.h4_start = 400;
        config.base.h4_end = 499;
        config.base.s1 = 16;
        config.base.s2 = 16;
        config.base.s3 = 16;
        config.base.s4 = 16;
        config.header_protection_key = key.as_ptr();

        let (my_secret, _) = keypair();
        let (_, their_public) = keypair();

        unsafe {
            let tunnel = new_tunnel_amnezia3(
                my_secret.as_ptr(),
                their_public.as_ptr(),
                ptr::null(),
                0,
                1,
                &config,
            );
            assert!(!tunnel.is_null());

            let mut dst = vec![0u8; 2048];
            let result = wireguard_force_handshake(tunnel, dst.as_mut_ptr(), dst.len() as u32);
            assert!(matches!(result.op, result_type::WRITE_TO_NETWORK));
            // S1 prefix plus the 148-byte initiation.
            assert_eq!(result.size, 16 + 148);

            // The type field on the wire is header-protected, so it must not
            // fall in the configured H1 range as-is.
            let mut type_bytes = [0u8; 4];
            type_bytes.copy_from_slice(&dst[16..20]);
            let wire_type = u32::from_le_bytes(type_bytes);
            assert!(
                !(100..=199).contains(&wire_type),
                "type {} leaked in plaintext",
                wire_type
            );

            tunnel_free(tunnel);
        }
    }

    #[test]
    fn amnezia3_rejects_inverted_ranges() {
        let mut config = zeroed_config();
        config.rekey_timeout_min = 9;
        config.rekey_timeout_max = 3;

        unsafe {
            assert!(build(&config).is_null());
        }
    }
}
