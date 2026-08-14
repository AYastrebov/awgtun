// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! An implementation of the WireGuard protocol, plus AmneziaWG 2.0 and 3.0
//! obfuscation, with no network or tunnel stack of its own.
//!
//! ```text
//! git clone https://github.com/cloudflare/boringtun.git
//! ```

#[cfg(feature = "device")]
pub mod device;

#[cfg(feature = "server")]
pub mod server;

pub mod amnezia;
#[cfg(feature = "ffi-bindings")]
pub mod ffi;
#[cfg(feature = "jni-bindings")]
pub mod jni;
pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

// Only the `device` UAPI parser and the C FFI parse keys from strings; with
// neither feature on, the whole module is dead code.
#[cfg(any(feature = "device", feature = "ffi-bindings"))]
pub(crate) mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
