// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// Requiring explicit per-fn "Safety" docs not worth it. Just pass in valid
// pointers and buffers/lengths to these, ok?
#![allow(clippy::missing_safety_doc)]

//! C bindings for the BoringTun library
use super::noise::{Tunn, TunnResult};
use crate::amnezia::{
    Amnezia2Config, CpsChain, HeaderConfig, HeaderRange, InitPacketConfig, JunkConfig,
    PaddingConfig,
};
use crate::x25519::{PublicKey, StaticSecret};
use base64::{decode, encode};
use hex::encode as encode_hex;
use libc::{raise, SIGSEGV};
use parking_lot::Mutex;
use rand_core::OsRng;
use tracing;
use tracing_subscriber::fmt;

use crate::serialization::KeyBytes;
use std::ffi::{CStr, CString};
use std::io::{Error, ErrorKind, Write};
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
    let encoded_key = encode(key.key);
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

    if let Ok(key) = decode(utf8_key) {
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
            Err(Error::new(
                ErrorKind::Other,
                "Failed to create CString from buffer.",
            ))
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
    if let Ok(value) = result {
        value
    } else {
        false
    }
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
        return new_tunnel(static_private, server_static_public, preshared_key, keep_alive, index);
    }
    let cfg = &*config;

    // Parse header ranges
    let headers = match HeaderConfig::new(
        HeaderRange { start: cfg.h1_start, end: cfg.h1_end },
        HeaderRange { start: cfg.h2_start, end: cfg.h2_end },
        HeaderRange { start: cfg.h3_start, end: cfg.h3_end },
        HeaderRange { start: cfg.h4_start, end: cfg.h4_end },
    ) {
        Ok(h) => h,
        Err(_) => return null_mut(),
    };

    let paddings = match PaddingConfig::new(cfg.s1, cfg.s2, cfg.s3, cfg.s4) {
        Ok(p) => p,
        Err(_) => return null_mut(),
    };

    let junk = if cfg.jc == 0 {
        JunkConfig::disabled()
    } else {
        match JunkConfig::new(cfg.jc, cfg.jmin, cfg.jmax) {
            Ok(j) => j,
            Err(_) => return null_mut(),
        }
    };

    let i1 = match parse_optional_cps(cfg.i1) { Ok(v) => v, Err(_) => return null_mut() };
    let i2 = match parse_optional_cps(cfg.i2) { Ok(v) => v, Err(_) => return null_mut() };
    let i3 = match parse_optional_cps(cfg.i3) { Ok(v) => v, Err(_) => return null_mut() };
    let i4 = match parse_optional_cps(cfg.i4) { Ok(v) => v, Err(_) => return null_mut() };
    let i5 = match parse_optional_cps(cfg.i5) { Ok(v) => v, Err(_) => return null_mut() };

    let amnezia = Amnezia2Config {
        headers,
        paddings,
        junk,
        init_packets: InitPacketConfig { i1, i2, i3, i4, i5 },
    };

    // Parse keys (same as new_tunnel)
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

    let keep_alive = if keep_alive == 0 { None } else { Some(keep_alive) };

    let tunnel = match Tunn::new_with_amnezia(
        private_key, public_key, preshared_key, keep_alive, index, None, amnezia,
    ) {
        Ok(t) => t,
        Err(_) => return null_mut(),
    };

    PANIC_HOOK.call_once(|| {
        panic::set_hook(Box::new(move |_| {
            raise(SIGSEGV);
        }));
    });

    Box::into_raw(Box::new(Mutex::new(tunnel)))
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
