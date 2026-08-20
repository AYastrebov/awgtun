// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! An implementation of the WireGuard protocol, plus AmneziaWG 2.0 and 3.0
//! obfuscation, with no network or tunnel stack of its own.
//!
//! ```text
//! git clone https://github.com/AYastrebov/awgtun.git
//! ```

#[cfg(feature = "device")]
pub mod device;

pub mod amnezia;
pub mod noise;

#[cfg(not(feature = "mock-instant"))]
pub(crate) mod sleepyinstant;

// Public, and no longer feature-gated: the FFI crate parses keys with it from
// outside, and turning a hex or base64 key into bytes is something most
// consumers of this library end up needing anyway.
pub mod serialization;

/// Re-export of the x25519 types
pub mod x25519 {
    pub use x25519_dalek::{
        EphemeralSecret, PublicKey, ReusableSecret, SharedSecret, StaticSecret,
    };
}
