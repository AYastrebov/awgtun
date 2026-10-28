// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// temporary, we need to do some verification around these bindings later
#![allow(clippy::missing_safety_doc)]

//! JNI bindings for the awgtun library.
//!
//! Every export upgrades its `EnvUnowned` with `with_env`, which also catches
//! panics so none unwinds into the JVM, and resolves the outcome with
//! `LogErrorAndDefault`: a failure is logged and the method returns 0 or
//! `null`, which is what these bindings have always returned on error.
//!
//! For that catch to work, a panic has to reach `with_env` as an unwind. So
//! the tunnel is driven through plain Rust calls here, not the `extern "C"`
//! `wireguard_*` functions, which abort when a panic hits their boundary.
//! The JNI constructors also skip the C ABI's process-wide SIGSEGV panic hook,
//! which fires before any unwinding can start.

use std::convert::TryFrom;
use std::fmt;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

use jni::errors::LogErrorAndDefault;
use jni::objects::{JByteArray, JByteBuffer, JClass, JString};
use jni::strings::JNIStr;
use jni::sys::{jint, jlong, jshort};
use jni::{Env, EnvUnowned};
use parking_lot::Mutex;

use crate::build_amnezia3_tunnel;
use crate::new_tunnel_unhooked;
use crate::parse_tunnel_identity;
use crate::tunnel_free;
use crate::wireguard_result;
use crate::x25519_key;
use crate::x25519_key_to_base64;
use crate::x25519_key_to_hex;
use crate::x25519_key_to_str_free;
use crate::x25519_public_key;
use crate::x25519_secret_key;

use awgtun::amnezia::Amnezia3Config;
use awgtun::noise::{Tunn, TunnResult};

pub extern "C" fn log_print(_log_string: *const c_char) {
    /*
    XXX:
    Define callback function in app.
    */
}

/// Why an export gave up. Only ever logged; the caller sees 0 or `null`.
#[derive(Debug)]
enum BindingError {
    Jni(jni::errors::Error),
    /// A size argument was negative.
    NegativeSize,
    /// A size argument was larger than the direct buffer it describes.
    /// Trusting it would let native code write past the buffer.
    BufferTooSmall,
    /// `dst` and `op` overlap, so they cannot both be written as slices.
    OverlappingBuffers,
    /// The tunnel handle was 0.
    NullTunnel,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingError::Jni(err) => write!(f, "{err}"),
            BindingError::NegativeSize => f.write_str("negative size"),
            BindingError::BufferTooSmall => f.write_str("size exceeds the direct buffer capacity"),
            BindingError::OverlappingBuffers => f.write_str("dst and op buffers overlap"),
            BindingError::NullTunnel => f.write_str("null tunnel handle"),
        }
    }
}

impl std::error::Error for BindingError {}

impl From<jni::errors::Error> for BindingError {
    fn from(err: jni::errors::Error) -> Self {
        BindingError::Jni(err)
    }
}

/// Copies a 32-byte key out of a Java `byte[]`.
fn read_key(env: &Env, array: &JByteArray) -> Result<x25519_key, BindingError> {
    let mut key = [0i8; 32];
    array.get_region(env, 0, &mut key)?;
    Ok(x25519_key {
        key: key.map(|b| b as u8),
    })
}

fn size(len: jint) -> Result<usize, BindingError> {
    usize::try_from(len).map_err(|_| BindingError::NegativeSize)
}

/// The first `len` bytes of a direct `ByteBuffer`, checked to be within its
/// capacity. A raw region rather than a slice, so that two of them can be
/// checked for overlap before either becomes a `&mut [u8]`.
struct Region {
    ptr: *mut u8,
    len: usize,
}

impl Region {
    fn new(env: &Env, buf: &JByteBuffer, len: jint) -> Result<Region, BindingError> {
        let len = size(len)?;
        if env.get_direct_buffer_capacity(buf)? < len {
            return Err(BindingError::BufferTooSmall);
        }
        Ok(Region {
            ptr: env.get_direct_buffer_address(buf)?,
            len,
        })
    }

    fn overlaps(&self, other: &Region) -> bool {
        let (a, b) = (self.ptr as usize, other.ptr as usize);
        a < b + other.len && b < a + self.len
    }

    /// # Safety
    ///
    /// The buffer the region came from must stay referenced for `'buf`, and no
    /// other live slice may overlap it.
    unsafe fn slice<'buf>(self) -> &'buf mut [u8] {
        if self.len == 0 {
            return &mut [];
        }
        // SAFETY: the JVM guarantees a direct buffer's address is valid for its
        // capacity, which `new` checked covers `len`; aliasing and lifetime are
        // the caller's contract.
        unsafe { slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

/// `dst` and the one-byte `op` buffer, as slices that are known not to alias.
/// The buffers are taken by `&mut` so the borrow checker stops a second call
/// from handing out another pair; two Java references to the same memory are
/// caught by the overlap check.
fn dst_and_op<'buf>(
    env: &Env,
    dst: &'buf mut JByteBuffer,
    dst_size: jint,
    op: &'buf mut JByteBuffer,
) -> Result<(&'buf mut [u8], &'buf mut [u8]), BindingError> {
    let dst = Region::new(env, dst, dst_size)?;
    let op = Region::new(env, op, 1)?;
    if dst.overlaps(&op) {
        return Err(BindingError::OverlappingBuffers);
    }
    // SAFETY: both buffers are exclusively borrowed for `'buf`, and the
    // regions were just checked to be disjoint.
    Ok(unsafe { (dst.slice(), op.slice()) })
}

/// The tunnel behind a handle from `new_tunnel` or `new_tunnel_amnezia3`.
///
/// # Safety
///
/// A non-zero `handle` must be a live tunnel that `tunnel_free` has not freed.
unsafe fn tunnel<'a>(handle: jlong) -> Result<&'a Mutex<Tunn>, BindingError> {
    // SAFETY: per the caller contract, a non-null handle points to a live
    // `Mutex<Tunn>` from `Box::into_raw`.
    unsafe { (handle as *const Mutex<Tunn>).as_ref() }.ok_or(BindingError::NullTunnel)
}

/// Turns a C string from `x25519_key_to_hex`/`_base64` into a Java string and
/// frees it, which the 0.19 bindings never did.
fn take_key_string<'local>(
    env: &mut Env<'local>,
    encoded: *const c_char,
) -> Result<JString<'local>, BindingError> {
    if encoded.is_null() {
        return Ok(JString::default());
    }
    // SAFETY: `encoded` is a non-null, NUL-terminated string just returned by
    // `x25519_key_to_hex`/`x25519_key_to_base64`, and it is freed only below,
    // after the last use of the borrow.
    let result = env.new_string(unsafe { JNIStr::from_ptr(encoded) }.to_str());
    // SAFETY: `encoded` came from `CString::into_raw` in those functions and
    // has not been freed.
    unsafe { x25519_key_to_str_free(encoded as *mut c_char) };
    Ok(result?)
}

/// Generates new x25519 secret key and converts into java byte array.
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_x25519_1secret_1key"]
pub extern "system" fn generate_secret_key<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
) -> JByteArray<'local> {
    env.with_env(|env| -> Result<_, BindingError> {
        Ok(env.byte_array_from_slice(&x25519_secret_key().key)?)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Computes public x25519 key from secret key and converts into java byte array.
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_x25519_1public_1key"]
pub extern "system" fn generate_public_key1<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    arg_secret_key: JByteArray<'local>,
) -> JByteArray<'local> {
    env.with_env(|env| -> Result<_, BindingError> {
        let secret_key = read_key(env, &arg_secret_key)?;
        Ok(env.byte_array_from_slice(&x25519_public_key(secret_key).key)?)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Converts x25519 key to hex string.
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_x25519_1key_1to_1hex"]
pub extern "system" fn convert_x25519_key_to_hex<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    arg_key: JByteArray<'local>,
) -> JString<'local> {
    env.with_env(|env| -> Result<_, BindingError> {
        let key = read_key(env, &arg_key)?;
        take_key_string(env, x25519_key_to_hex(key))
    })
    .resolve::<LogErrorAndDefault>()
}

/// Converts x25519 key to base64 string.
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_x25519_1key_1to_1base64"]
pub extern "system" fn convert_x25519_key_to_base64<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    arg_key: JByteArray<'local>,
) -> JString<'local> {
    env.with_env(|env| -> Result<_, BindingError> {
        let key = read_key(env, &arg_key)?;
        take_key_string(env, x25519_key_to_base64(key))
    })
    .resolve::<LogErrorAndDefault>()
}

/// Creates new tunnel
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_new_1tunnel"]
pub extern "system" fn create_new_tunnel<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    arg_secret_key: JString<'local>,
    arg_public_key: JString<'local>,
    arg_preshared_key: JString<'local>,
    keep_alive: jshort,
    index: jint,
) -> jlong {
    env.with_env(|env| -> Result<_, BindingError> {
        // Held until the tunnel is built: the pointers below borrow them, and
        // dropping them releases the JVM's copy of each string.
        let secret_key = arg_secret_key.mutf8_chars(env)?;
        let public_key = arg_public_key.mutf8_chars(env)?;
        let preshared_key = if arg_preshared_key.is_null() {
            None
        } else {
            Some(arg_preshared_key.mutf8_chars(env)?)
        };

        // SAFETY: each pointer is NUL-terminated and stays valid while the
        // `MUTF8Chars` above are alive; `new_tunnel` copies what it keeps.
        let tunnel = unsafe {
            new_tunnel_unhooked(
                secret_key.as_ptr(),
                public_key.as_ptr(),
                preshared_key.as_ref().map_or(ptr::null(), |k| k.as_ptr()),
                keep_alive as u16,
                index as u32,
            )
        };
        Ok(tunnel as jlong)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Creates a new tunnel with AmneziaWG 2.0/3.0 configuration.
///
/// `arg_config` is a newline-separated `key=value` block in the AmneziaWG UAPI
/// format — see [`crate::amnezia::Amnezia3Config::parse`] for the accepted keys.
/// An empty string yields a standard WireGuard tunnel.
///
/// Returns 0 on failure, matching `new_tunnel`.
///
/// After this call, and after every `wireguard_write` and `wireguard_tick`, the
/// caller must drain `wireguard_poll_outgoing_packet` until it returns 0 and
/// send each datagram before the handshake initiation. Junk packets and the
/// I1-I5 signature packets are delivered only through that queue.
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_new_1tunnel_1amnezia3"]
pub extern "system" fn create_new_amnezia3_tunnel<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    arg_secret_key: JString<'local>,
    arg_public_key: JString<'local>,
    arg_preshared_key: JString<'local>,
    keep_alive: jshort,
    index: jint,
    arg_config: JString<'local>,
) -> jlong {
    env.with_env(|env| -> Result<_, BindingError> {
        let secret_key = arg_secret_key.mutf8_chars(env)?;
        let public_key = arg_public_key.mutf8_chars(env)?;
        let preshared_key = if arg_preshared_key.is_null() {
            None
        } else {
            Some(arg_preshared_key.mutf8_chars(env)?)
        };

        let config = if arg_config.is_null() {
            String::new()
        } else {
            arg_config.try_to_string(env)?
        };

        let amnezia = match Amnezia3Config::parse(&config) {
            Ok(amnezia) => amnezia,
            Err(_) => return Ok(0),
        };

        // SAFETY: as in `create_new_tunnel`, the pointers are NUL-terminated
        // and outlive the call, and `parse_tunnel_identity` copies the keys.
        let identity = unsafe {
            parse_tunnel_identity(
                secret_key.as_ptr(),
                public_key.as_ptr(),
                preshared_key.as_ref().map_or(ptr::null(), |k| k.as_ptr()),
                keep_alive as u16,
            )
        };
        let identity = match identity {
            Ok(identity) => identity,
            Err(()) => return Ok(0),
        };

        Ok(build_amnezia3_tunnel(identity, index as u32, amnezia) as jlong)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Drains the next pre-handshake datagram (I-packet or junk) into `dst`,
/// returning its size, or 0 when the queue is empty.
///
/// Call in a loop until it returns 0 after creating a tunnel and after every
/// `wireguard_write` / `wireguard_tick`, sending each datagram to the network
/// before the handshake initiation those calls produced.
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_wireguard_1poll_1outgoing_1packet"]
pub unsafe extern "system" fn poll_outgoing_packet<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    dst: JByteBuffer<'local>,
    dst_size: jint,
) -> jint {
    env.with_env(|env| -> Result<_, BindingError> {
        // SAFETY: `dst` stays referenced for the whole call, and this is the
        // only slice made from it.
        let dst = unsafe { Region::new(env, &dst, dst_size)?.slice() };
        // SAFETY: the caller passes a live handle (see `tunnel`).
        let tunnel = unsafe { tunnel(handle) }?;
        Ok(match tunnel.lock().poll_outgoing_packet() {
            // Same as the C ABI: a datagram that does not fit is dropped.
            Some(packet) if packet.len() <= dst.len() => {
                dst[..packet.len()].copy_from_slice(&packet);
                packet.len() as jint
            }
            _ => 0,
        })
    })
    .resolve::<LogErrorAndDefault>()
}

/// Frees a tunnel created by `new_tunnel` or `new_tunnel_amnezia3`.
///
/// The handle must not be used afterwards. Passing 0 is a no-op.
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_tunnel_1free"]
pub unsafe extern "system" fn free_tunnel<'local>(
    _env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
) {
    if tunnel == 0 {
        return;
    }
    tunnel_free(tunnel as *mut Mutex<Tunn>);
}

/// Which way `transform_packet` runs a packet through the tunnel.
#[derive(Clone, Copy)]
enum Direction {
    Encapsulate,
    Decapsulate,
}

/// Shared body of `wireguard_write` and `wireguard_read`: both take a Java
/// `byte[]` source, a direct destination buffer and a one-byte `op` buffer.
#[allow(clippy::too_many_arguments)]
unsafe fn transform_packet<'local>(
    env: &mut EnvUnowned<'local>,
    handle: jlong,
    src: JByteArray<'local>,
    src_size: jint,
    mut dst: JByteBuffer<'local>,
    dst_size: jint,
    mut op: JByteBuffer<'local>,
    direction: Direction,
) -> jint {
    env.with_env(|env| -> Result<_, BindingError> {
        // Every argument is validated before the tunnel sees anything, so a
        // rejected call has no side effects.
        let src_len = size(src_size)?;
        let (dst, op) = dst_and_op(env, &mut dst, dst_size, &mut op)?;
        let src = env.convert_byte_array(&src)?;
        // `src_size` is the caller's claim; the copy is what was really passed.
        let src = &src[..src_len.min(src.len())];
        // SAFETY: the caller passes a live handle (see `tunnel`).
        let tunnel = unsafe { tunnel(handle) }?;

        let mut tunnel = tunnel.lock();
        let result: TunnResult = match direction {
            Direction::Encapsulate => tunnel.encapsulate(src, dst),
            Direction::Decapsulate => tunnel.decapsulate(None, src, dst),
        };
        let output = wireguard_result::from(result);
        op[0] = output.op as u8;
        Ok(output.size as jint)
    })
    .resolve::<LogErrorAndDefault>()
}

/// Encrypts raw IP packets into WG formatted packets.
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_wireguard_1write"]
pub unsafe extern "system" fn encrypt_raw_packet<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    src: JByteArray<'local>,
    src_size: jint,
    dst: JByteBuffer<'local>,
    dst_size: jint,
    op: JByteBuffer<'local>,
) -> jint {
    transform_packet(
        &mut env,
        tunnel,
        src,
        src_size,
        dst,
        dst_size,
        op,
        Direction::Encapsulate,
    )
}

/// Decrypts WG formatted packets into raw IP packets.
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_wireguard_1read"]
pub unsafe extern "system" fn decrypt_to_raw_packet<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    src: JByteArray<'local>,
    src_size: jint,
    dst: JByteBuffer<'local>,
    dst_size: jint,
    op: JByteBuffer<'local>,
) -> jint {
    transform_packet(
        &mut env,
        tunnel,
        src,
        src_size,
        dst,
        dst_size,
        op,
        Direction::Decapsulate,
    )
}

/// Periodic function that writes WG formatted packets into destination buffer
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_wireguard_1tick"]
pub unsafe extern "system" fn run_periodic_task<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    handle: jlong,
    mut dst: JByteBuffer<'local>,
    dst_size: jint,
    mut op: JByteBuffer<'local>,
) -> jint {
    env.with_env(|env| -> Result<_, BindingError> {
        let (dst, op) = dst_and_op(env, &mut dst, dst_size, &mut op)?;
        // SAFETY: the caller passes a live handle (see `tunnel`).
        let tunnel = unsafe { tunnel(handle) }?;
        let output = wireguard_result::from(tunnel.lock().update_timers(dst));
        op[0] = output.op as u8;
        Ok(output.size as jint)
    })
    .resolve::<LogErrorAndDefault>()
}
