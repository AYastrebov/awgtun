// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// temporary, we need to do some verification around these bindings later
#![allow(clippy::missing_safety_doc)]

/// JNI bindings for BoringTun library
use std::os::raw::c_char;
use std::ptr;

use jni::objects::{JByteBuffer, JClass, JString};
use jni::strings::JNIStr;
use jni::sys::{jbyteArray, jint, jlong, jshort, jstring};
use jni::JNIEnv;
use parking_lot::Mutex;

use crate::amnezia::Amnezia3Config;
use crate::ffi::build_amnezia3_tunnel;
use crate::ffi::new_tunnel;
use crate::ffi::parse_tunnel_identity;
use crate::ffi::tunnel_free;
use crate::ffi::wireguard_poll_outgoing_packet;
use crate::ffi::wireguard_read;
use crate::ffi::wireguard_result;
use crate::ffi::wireguard_tick;
use crate::ffi::wireguard_write;
use crate::ffi::x25519_key;
use crate::ffi::x25519_key_to_base64;
use crate::ffi::x25519_key_to_hex;
use crate::ffi::x25519_public_key;
use crate::ffi::x25519_secret_key;

use crate::noise::Tunn;

pub extern "C" fn log_print(_log_string: *const c_char) {
    /*
    XXX:
    Define callback function in app.
    */
}

/// Generates new x25519 secret key and converts into java byte array.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1secret_1key"]
pub extern "C" fn generate_secret_key(env: JNIEnv, _class: JClass) -> jbyteArray {
    match env.byte_array_from_slice(&x25519_secret_key().key) {
        Ok(v) => v,
        Err(_) => ptr::null_mut(),
    }
}

/// Computes public x25519 key from secret key and converts into java byte array.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1public_1key"]
pub unsafe extern "C" fn generate_public_key1(
    env: JNIEnv,
    _class: JClass,
    arg_secret_key: jbyteArray,
) -> jbyteArray {
    let mut key_inner = [0; 32];

    if env
        .get_byte_array_region(arg_secret_key, 0, &mut key_inner)
        .is_err()
    {
        return ptr::null_mut();
    }

    let secret_key = x25519_key {
        key: std::mem::transmute::<[i8; 32], [u8; 32]>(key_inner),
    };

    match env.byte_array_from_slice(&x25519_public_key(secret_key).key) {
        Ok(v) => v,
        Err(_) => ptr::null_mut(),
    }
}

/// Converts x25519 key to hex string.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1key_1to_1hex"]
pub unsafe extern "C" fn convert_x25519_key_to_hex(
    env: JNIEnv,
    _class: JClass,
    arg_key: jbyteArray,
) -> jstring {
    let mut key = [0; 32];

    if env.get_byte_array_region(arg_key, 0, &mut key).is_err() {
        return ptr::null_mut();
    }

    let x25519_key = x25519_key {
        key: std::mem::transmute::<[i8; 32], [u8; 32]>(key),
    };

    let output = match env.new_string(JNIStr::from_ptr(x25519_key_to_hex(x25519_key)).to_owned()) {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };

    output.into_inner()
}

/// Converts x25519 key to base64 string.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_x25519_1key_1to_1base64"]
pub unsafe extern "C" fn convert_x25519_key_to_base64(
    env: JNIEnv,
    _class: JClass,
    arg_key: jbyteArray,
) -> jstring {
    let mut key = [0; 32];

    if env.get_byte_array_region(arg_key, 0, &mut key).is_err() {
        return ptr::null_mut();
    }

    let x25519_key = x25519_key {
        key: std::mem::transmute::<[i8; 32], [u8; 32]>(key),
    };

    let output = match env.new_string(JNIStr::from_ptr(x25519_key_to_base64(x25519_key)).to_owned())
    {
        Ok(v) => v,
        Err(_) => return ptr::null_mut(),
    };

    output.into_inner()
}

/// Creates new tunnel
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_new_1tunnel"]
pub unsafe extern "C" fn create_new_tunnel(
    env: JNIEnv,
    _class: JClass,
    arg_secret_key: JString,
    arg_public_key: JString,
    arg_preshared_key: JString,
    keep_alive: jshort,
    index: jint,
) -> jlong {
    let secret_key = match env.get_string_utf_chars(arg_secret_key) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let public_key = match env.get_string_utf_chars(arg_public_key) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let preshared_key = if arg_preshared_key.is_null() {
        ptr::null_mut()
    } else {
        match env.get_string_utf_chars(arg_preshared_key) {
            Ok(v) => v,
            Err(_) => return 0,
        }
    };

    let tunnel = new_tunnel(
        secret_key,
        public_key,
        preshared_key,
        keep_alive as u16,
        index as u32,
    );

    if tunnel.is_null() {
        return 0;
    }

    tunnel as jlong
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
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_new_1tunnel_1amnezia3"]
pub unsafe extern "C" fn create_new_amnezia3_tunnel(
    env: JNIEnv,
    _class: JClass,
    arg_secret_key: JString,
    arg_public_key: JString,
    arg_preshared_key: JString,
    keep_alive: jshort,
    index: jint,
    arg_config: JString,
) -> jlong {
    let secret_key = match env.get_string_utf_chars(arg_secret_key) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let public_key = match env.get_string_utf_chars(arg_public_key) {
        Ok(v) => v,
        Err(_) => return 0,
    };

    let preshared_key = if arg_preshared_key.is_null() {
        ptr::null_mut()
    } else {
        match env.get_string_utf_chars(arg_preshared_key) {
            Ok(v) => v,
            Err(_) => return 0,
        }
    };

    let config = if arg_config.is_null() {
        String::new()
    } else {
        match env.get_string(arg_config) {
            Ok(v) => v.into(),
            Err(_) => return 0,
        }
    };

    let amnezia = match Amnezia3Config::parse(&config) {
        Ok(amnezia) => amnezia,
        Err(_) => return 0,
    };

    let identity =
        match parse_tunnel_identity(secret_key, public_key, preshared_key, keep_alive as u16) {
            Ok(identity) => identity,
            Err(()) => return 0,
        };

    let tunnel = build_amnezia3_tunnel(identity, index as u32, amnezia);
    if tunnel.is_null() {
        return 0;
    }

    tunnel as jlong
}

/// Drains the next pre-handshake datagram (I-packet or junk) into `dst`,
/// returning its size, or 0 when the queue is empty.
///
/// Call in a loop until it returns 0 after creating a tunnel and after every
/// `wireguard_write` / `wireguard_tick`, sending each datagram to the network
/// before the handshake initiation those calls produced.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1poll_1outgoing_1packet"]
pub unsafe extern "C" fn poll_outgoing_packet(
    env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
    dst: JByteBuffer,
    dst_size: jint,
) -> jint {
    let dst_ptr: *mut u8 = match env.get_direct_buffer_address(dst) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    wireguard_poll_outgoing_packet(tunnel as *const Mutex<Tunn>, dst_ptr, dst_size as u32) as jint
}

/// Frees a tunnel created by `new_tunnel` or `new_tunnel_amnezia3`.
///
/// The handle must not be used afterwards. Passing 0 is a no-op.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_tunnel_1free"]
pub unsafe extern "C" fn free_tunnel(_env: JNIEnv, _class: JClass, tunnel: jlong) {
    if tunnel == 0 {
        return;
    }
    tunnel_free(tunnel as *mut Mutex<Tunn>);
}

/// Encrypts raw IP packets into WG formatted packets.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1write"]
pub unsafe extern "C" fn encrypt_raw_packet(
    env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
    src: jbyteArray,
    src_size: jint,
    dst: JByteBuffer,
    dst_size: jint,
    op: JByteBuffer,
) -> jint {
    let dst_ptr: *mut u8 = match env.get_direct_buffer_address(dst) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let op_ptr: *mut u8 = match env.get_direct_buffer_address(op) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let output: wireguard_result = wireguard_write(
        tunnel as *const Mutex<Tunn>,
        env.convert_byte_array(src).unwrap().as_mut_ptr(),
        src_size as u32,
        dst_ptr,
        dst_size as u32,
    );
    *op_ptr = output.op as u8;

    output.size as i32
}

/// Decrypts WG formatted packets into raw IP packets.
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1read"]
pub unsafe extern "C" fn decrypt_to_raw_packet(
    env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
    src: jbyteArray,
    src_size: jint,
    dst: JByteBuffer,
    dst_size: jint,
    op: JByteBuffer,
) -> jint {
    let dst_ptr: *mut u8 = match env.get_direct_buffer_address(dst) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let op_ptr: *mut u8 = match env.get_direct_buffer_address(op) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let output: wireguard_result = wireguard_read(
        tunnel as *const Mutex<Tunn>,
        env.convert_byte_array(src).unwrap().as_mut_ptr(),
        src_size as u32,
        dst_ptr,
        dst_size as u32,
    );

    *op_ptr = output.op as u8;

    output.size as i32
}

/// Periodic function that writes WG formatted packets into destination buffer
#[export_name = "Java_com_cloudflare_app_boringtun_BoringTunJNI_wireguard_1tick"]
pub unsafe extern "C" fn run_periodic_task(
    env: JNIEnv,
    _class: JClass,
    tunnel: jlong,
    dst: JByteBuffer,
    dst_size: jint,
    op: JByteBuffer,
) -> jint {
    let dst_ptr: *mut u8 = match env.get_direct_buffer_address(dst) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let op_ptr: *mut u8 = match env.get_direct_buffer_address(op) {
        Ok(v) => v.as_mut_ptr(),
        Err(_) => return 0,
    };

    let output: wireguard_result =
        wireguard_tick(tunnel as *const Mutex<Tunn>, dst_ptr, dst_size as u32);

    *op_ptr = output.op as u8;

    output.size as i32
}
