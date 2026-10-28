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

use std::convert::TryFrom;
use std::fmt;
use std::os::raw::c_char;
use std::ptr;

use jni::errors::LogErrorAndDefault;
use jni::objects::{JByteArray, JByteBuffer, JClass, JString};
use jni::strings::JNIStr;
use jni::sys::{jint, jlong, jshort};
use jni::{Env, EnvUnowned};
use parking_lot::Mutex;

use crate::build_amnezia3_tunnel;
use crate::new_tunnel;
use crate::parse_tunnel_identity;
use crate::tunnel_free;
use crate::wireguard_poll_outgoing_packet;
use crate::wireguard_read;
use crate::wireguard_result;
use crate::wireguard_tick;
use crate::wireguard_write;
use crate::x25519_key;
use crate::x25519_key_to_base64;
use crate::x25519_key_to_hex;
use crate::x25519_key_to_str_free;
use crate::x25519_public_key;
use crate::x25519_secret_key;

use awgtun::amnezia::Amnezia3Config;
use awgtun::noise::Tunn;

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
    /// A size argument was negative or larger than the direct buffer it
    /// describes. Trusting it would let native code write past the buffer.
    BufferTooSmall,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BindingError::Jni(err) => write!(f, "{err}"),
            BindingError::BufferTooSmall => f.write_str("size exceeds the direct buffer capacity"),
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

/// The address of a direct `ByteBuffer`, checked to hold at least `len` bytes.
fn direct_buffer(env: &Env, buf: &JByteBuffer, len: jint) -> Result<*mut u8, BindingError> {
    let len = usize::try_from(len).map_err(|_| BindingError::BufferTooSmall)?;
    if env.get_direct_buffer_capacity(buf)? < len {
        return Err(BindingError::BufferTooSmall);
    }
    Ok(env.get_direct_buffer_address(buf)?)
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
            new_tunnel(
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
    tunnel: jlong,
    dst: JByteBuffer<'local>,
    dst_size: jint,
) -> jint {
    env.with_env(|env| -> Result<_, BindingError> {
        let dst_ptr = direct_buffer(env, &dst, dst_size)?;
        // SAFETY: the caller passes a handle from `new_tunnel*` that has not
        // been freed, and `dst_ptr` holds `dst_size` bytes (checked above).
        let len = unsafe {
            wireguard_poll_outgoing_packet(tunnel as *const Mutex<Tunn>, dst_ptr, dst_size as u32)
        };
        Ok(len as jint)
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

/// Shared body of `wireguard_write` and `wireguard_read`: both take a Java
/// `byte[]` source, a direct destination buffer and a one-byte `op` buffer.
#[allow(clippy::too_many_arguments)]
unsafe fn transform_packet<'local>(
    env: &mut EnvUnowned<'local>,
    tunnel: jlong,
    src: JByteArray<'local>,
    src_size: jint,
    dst: JByteBuffer<'local>,
    dst_size: jint,
    op: JByteBuffer<'local>,
    f: unsafe extern "C" fn(*const Mutex<Tunn>, *const u8, u32, *mut u8, u32) -> wireguard_result,
) -> jint {
    env.with_env(|env| -> Result<_, BindingError> {
        let dst_ptr = direct_buffer(env, &dst, dst_size)?;
        let op_ptr = direct_buffer(env, &op, 1)?;
        let src = env.convert_byte_array(&src)?;
        // `src_size` is the caller's claim; the copy is what was really passed.
        let src_len = usize::try_from(src_size).unwrap_or(0).min(src.len());

        // SAFETY: the tunnel handle is live (caller contract), `src` holds
        // `src_len` bytes, and both direct buffers were checked above.
        let output = unsafe {
            f(
                tunnel as *const Mutex<Tunn>,
                src.as_ptr(),
                src_len as u32,
                dst_ptr,
                dst_size as u32,
            )
        };
        // SAFETY: `op_ptr` points into a direct buffer of at least one byte.
        unsafe { *op_ptr = output.op as u8 };
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
        wireguard_write,
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
        wireguard_read,
    )
}

/// Periodic function that writes WG formatted packets into destination buffer
#[export_name = "Java_io_github_ayastrebov_awgtun_AwgTunJNI_wireguard_1tick"]
pub unsafe extern "system" fn run_periodic_task<'local>(
    mut env: EnvUnowned<'local>,
    _class: JClass<'local>,
    tunnel: jlong,
    dst: JByteBuffer<'local>,
    dst_size: jint,
    op: JByteBuffer<'local>,
) -> jint {
    env.with_env(|env| -> Result<_, BindingError> {
        let dst_ptr = direct_buffer(env, &dst, dst_size)?;
        let op_ptr = direct_buffer(env, &op, 1)?;
        // SAFETY: the tunnel handle is live (caller contract) and both direct
        // buffers were checked above.
        let output =
            unsafe { wireguard_tick(tunnel as *const Mutex<Tunn>, dst_ptr, dst_size as u32) };
        // SAFETY: `op_ptr` points into a direct buffer of at least one byte.
        unsafe { *op_ptr = output.op as u8 };
        Ok(output.size as jint)
    })
    .resolve::<LogErrorAndDefault>()
}
