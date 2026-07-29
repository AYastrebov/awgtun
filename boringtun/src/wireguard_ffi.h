// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

struct wireguard_tunnel; // This corresponds to the Rust type

enum
{
    MAX_WIREGUARD_PACKET_SIZE = 65536 + 64,
};

enum result_type
{
    WIREGUARD_DONE = 0,
    WRITE_TO_NETWORK = 1,
    WIREGUARD_ERROR = 2,
    WRITE_TO_TUNNEL_IPV4 = 4,
    WRITE_TO_TUNNEL_IPV6 = 6,
};

struct wireguard_result
{
    enum result_type op;
    size_t size;
};

struct stats
{
    int64_t time_since_last_handshake;
    size_t tx_bytes;
    size_t rx_bytes;
    float estimated_loss;
    int32_t estimated_rtt; // rtt estimated on time it took to complete latest initiated handshake in ms
    uint8_t reserved[56];  // decrement appropriately when adding new fields
};

struct x25519_key
{
    uint8_t key[32];
};

// Generates a fresh x25519 secret key
struct x25519_key x25519_secret_key();
// Computes an x25519 public key from a secret key
struct x25519_key x25519_public_key(struct x25519_key private_key);
// Encodes a public or private x25519 key to base64. Must be freed with x25519_key_to_str_free.
const char *x25519_key_to_base64(struct x25519_key key);
// Encodes a public or private x25519 key to hex. Must be freed with x25519_key_to_str_free.
const char *x25519_key_to_hex(struct x25519_key key);
// Free string pointer obtained from either x25519_key_to_base64 or x25519_key_to_hex
void x25519_key_to_str_free(const char *key_str);
// Check if a null terminated string represents a valid x25519 key
// Returns 0 if not
int check_base64_encoded_x25519_key(const char *key);

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
bool set_logging_function(void (*log_func)(const char *));

// Allocate a new tunnel
struct wireguard_tunnel *new_tunnel(const char *static_private,
                                    const char *server_static_public,
                                    const char *preshared_key,
                                    uint16_t keep_alive, // Keep alive interval in seconds
                                    uint32_t index);      // The 24bit index prefix to be used for session indexes

// AmneziaWG 2.0 configuration.
// Zero every field for standard WireGuard behavior.
// H1-H4 are inclusive (start, end) ranges; use start == end for a fixed value.
// I1-I5 are optional CPS chain strings (UTF-8, null-terminated); pass NULL to skip.
struct amnezia_config {
    uint32_t h1_start;
    uint32_t h1_end;
    uint32_t h2_start;
    uint32_t h2_end;
    uint32_t h3_start;
    uint32_t h3_end;
    uint32_t h4_start;
    uint32_t h4_end;
    uint8_t s1;
    uint8_t s2;
    uint8_t s3;
    uint8_t s4;
    uint8_t jc;
    uint16_t jmin;
    uint16_t jmax;
    const char *i1;
    const char *i2;
    const char *i3;
    const char *i4;
    const char *i5;
};

// AmneziaWG 3.0 configuration: the 2.0 parameters plus header protection,
// content padding and randomized timings.
// Every *_min/*_max pair is an inclusive range; a pair of zeros means "unset"
// and falls back to the WireGuard default for that parameter.
struct amnezia3_config {
    struct amnezia_config base;
    // 32-byte header protection key, or NULL to disable. An all-zero key also
    // disables it. When enabled, s1-s4 must all be at least 12.
    const uint8_t *header_protection_key;
    uint32_t content_padding_min;
    uint32_t content_padding_max;
    uint32_t rekey_after_time_min;      // seconds
    uint32_t rekey_after_time_max;
    uint32_t rekey_timeout_min;         // seconds
    uint32_t rekey_timeout_max;
    uint32_t reject_after_time_min;     // seconds
    uint32_t reject_after_time_max;
    uint32_t keepalive_timeout_min;     // seconds
    uint32_t keepalive_timeout_max;
    uint32_t max_handshake_attempts_min; // count
    uint32_t max_handshake_attempts_max;
    // Persistent keepalive range, in seconds. When set it takes precedence
    // over the keep_alive argument of new_tunnel_amnezia3, and a fresh
    // interval is drawn from it every time a keepalive fires.
    uint32_t persistent_keepalive_min;
    uint32_t persistent_keepalive_max;
    uint32_t mtu;                       // 0 selects the default (1420)
};

// Allocate a new tunnel with AmneziaWG 2.0 configuration.
// Returns NULL on failure. A NULL config falls back to new_tunnel.
struct wireguard_tunnel *new_tunnel_amnezia(const char *static_private,
                                            const char *server_static_public,
                                            const char *preshared_key,
                                            uint16_t keep_alive,
                                            uint32_t index,
                                            const struct amnezia_config *config);

// Allocate a new tunnel with AmneziaWG 3.0 configuration.
// Returns NULL on failure. A NULL config falls back to new_tunnel.
struct wireguard_tunnel *new_tunnel_amnezia3(const char *static_private,
                                             const char *server_static_public,
                                             const char *preshared_key,
                                             uint16_t keep_alive,
                                             uint32_t index,
                                             const struct amnezia3_config *config);

// Returns the next pre-handshake datagram (I-packet or junk) to send before the
// handshake initiation, writing it to dst and returning its size. Returns 0 when
// the queue is empty.
//
// Call in a loop after new_tunnel_amnezia, new_tunnel_amnezia3, wireguard_write,
// wireguard_tick or wireguard_force_handshake until it returns 0, sending each
// datagram to the network.
size_t wireguard_poll_outgoing_packet(const struct wireguard_tunnel *tunnel,
                                      uint8_t *dst,
                                      uint32_t dst_size);

// Deallocate the tunnel
void tunnel_free(struct wireguard_tunnel *);

struct wireguard_result wireguard_write(const struct wireguard_tunnel *tunnel,
                                        const uint8_t *src,
                                        uint32_t src_size,
                                        uint8_t *dst,
                                        uint32_t dst_size);

struct wireguard_result wireguard_read(const struct wireguard_tunnel *tunnel,
                                       const uint8_t *src,
                                       uint32_t src_size,
                                       uint8_t *dst,
                                       uint32_t dst_size);

// dst must hold whichever is larger: a handshake initiation (148 + s1 bytes)
// or a keepalive (32 + s4 bytes plus content_padding_max when content padding
// is configured). With content padding enabled the keepalive case dominates.
struct wireguard_result wireguard_tick(const struct wireguard_tunnel *tunnel,
                                       uint8_t *dst,
                                       uint32_t dst_size);

struct wireguard_result wireguard_force_handshake(const struct wireguard_tunnel *tunnel,
                                                  uint8_t *dst,
                                                  uint32_t dst_size);

struct stats wireguard_stats(const struct wireguard_tunnel *tunnel);
