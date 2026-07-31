use amnezia_benching::{
    bench_amnezia_decapsulate, bench_amnezia_encapsulate, bench_amnezia_handshake_init,
    bench_amnezia_update_timers,
};
use blake2s_benching::{bench_blake2s_hash, bench_blake2s_hmac, bench_blake2s_keyed};
use chacha20poly1305_benching::bench_chacha20poly1305;
use x25519_public_key_benching::bench_x25519_public_key;
use x25519_shared_key_benching::bench_x25519_shared_key;

mod amnezia_benching;
mod blake2s_benching;
mod chacha20poly1305_benching;
mod x25519_public_key_benching;
mod x25519_shared_key_benching;

criterion::criterion_group!(
    crypto_benches,
    bench_chacha20poly1305,
    bench_blake2s_hash,
    bench_blake2s_hmac,
    bench_blake2s_keyed,
    bench_x25519_shared_key,
    bench_x25519_public_key,
    bench_amnezia_encapsulate,
    bench_amnezia_decapsulate,
    bench_amnezia_handshake_init,
    bench_amnezia_update_timers
);
criterion::criterion_main!(crypto_benches);
