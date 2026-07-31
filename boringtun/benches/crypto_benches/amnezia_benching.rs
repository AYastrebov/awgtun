use boringtun::amnezia::{
    Amnezia2Config, Amnezia3Config, HeaderConfig, HeaderRange, JunkConfig, PaddingConfig,
    TimingRanges, U32Range,
};
use boringtun::noise::{Tunn, TunnResult};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput};
use rand_core::OsRng;

/// A 1280-byte IPv4 payload: a realistic full-MTU tunnelled packet, big enough
/// that per-packet fixed costs are not lost in the AEAD but small enough to stay
/// inside one segment.
const PAYLOAD: usize = 1280;

fn ipv4_packet(len: usize) -> Vec<u8> {
    let mut packet = vec![0u8; len];
    packet[0] = 0x45; // IPv4, IHL 5
    packet[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    packet
}

fn headers() -> HeaderConfig {
    HeaderConfig::new(
        HeaderRange::new(1000, 1099).unwrap(),
        HeaderRange::new(2000, 2099).unwrap(),
        HeaderRange::new(3000, 3099).unwrap(),
        HeaderRange::new(4000, 4099).unwrap(),
    )
    .unwrap()
}

/// The three configurations worth separating: stock WireGuard as the control,
/// AWG 2.0 (dynamic headers plus padding), and AWG 3.0 (adds header protection
/// and content padding, the two per-packet costs unique to 3.0).
fn configs() -> Vec<(&'static str, Amnezia3Config)> {
    let wireguard = Amnezia3Config::wireguard_compatible();

    let mut awg2_inner = Amnezia2Config::wireguard_compatible();
    awg2_inner.paddings = PaddingConfig::new(16, 16, 16, 16).unwrap();
    awg2_inner.headers = headers();
    awg2_inner.validate().expect("valid AWG 2.0 bench config");
    let awg2 = Amnezia3Config::from_amnezia2(awg2_inner);

    let mut awg3 = awg2.clone();
    awg3.header_protection_key = Some([0x42; 32]);
    awg3.content_padding_addition = Some(U32Range::new(1, 32).unwrap());

    vec![("wireguard", wireguard), ("awg2", awg2), ("awg3", awg3)]
}

/// Build a pair of tunnels that have completed a handshake, so the benchmarks
/// measure the transport path rather than the Noise handshake.
fn established_pair(config: &Amnezia3Config) -> (Tunn, Tunn) {
    let secret_a = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let secret_b = x25519_dalek::StaticSecret::random_from_rng(OsRng);
    let public_a = x25519_dalek::PublicKey::from(&secret_a);
    let public_b = x25519_dalek::PublicKey::from(&secret_b);

    let mut a =
        Tunn::new_with_amnezia3(secret_a, public_b, None, None, 1, None, config.clone()).unwrap();
    let mut b =
        Tunn::new_with_amnezia3(secret_b, public_a, None, None, 2, None, config.clone()).unwrap();

    let mut buf = vec![0u8; 4096];
    // init -> response -> keepalive, which is what establishes both directions.
    let init = match a.format_handshake_initiation(&mut buf, false) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("expected an initiation, got {:?}", other),
    };
    let mut resp_buf = vec![0u8; 4096];
    let resp = match b.decapsulate(None, &init, &mut resp_buf) {
        TunnResult::WriteToNetwork(packet) => packet.to_vec(),
        other => panic!("expected a response, got {:?}", other),
    };
    let mut keepalive_buf = vec![0u8; 4096];
    match a.decapsulate(None, &resp, &mut keepalive_buf) {
        TunnResult::WriteToNetwork(packet) => {
            let mut sink = vec![0u8; 4096];
            b.decapsulate(None, packet, &mut sink);
        }
        other => panic!("expected a keepalive, got {:?}", other),
    }

    (a, b)
}

/// Outbound transport path: dynamic H4 header, S4 prefix, AEAD, and for 3.0 the
/// content padding pick plus header protection.
pub fn bench_amnezia_encapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("amnezia_encapsulate");
    group.throughput(Throughput::Bytes(PAYLOAD as u64));

    for (name, config) in configs() {
        let (mut sender, _receiver) = established_pair(&config);
        let payload = ipv4_packet(PAYLOAD);
        let mut dst = vec![0u8; 4096];

        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| match sender.encapsulate(&payload, &mut dst) {
                TunnResult::WriteToNetwork(packet) => packet.len(),
                other => panic!("expected a packet, got {:?}", other),
            })
        });
    }
    group.finish();
}

/// Inbound transport path: classification (which for 3.0 derives the header
/// protection type mask), padding strip, header decrypt, AEAD open.
pub fn bench_amnezia_decapsulate(c: &mut Criterion) {
    let mut group = c.benchmark_group("amnezia_decapsulate");
    group.throughput(Throughput::Bytes(PAYLOAD as u64));

    for (name, config) in configs() {
        let (mut sender, mut receiver) = established_pair(&config);
        let payload = ipv4_packet(PAYLOAD);
        let mut dst = vec![0u8; 4096];

        // Each datagram can only be decapsulated once — the anti-replay counter
        // rejects a repeat — so pre-generate a batch and consume one per
        // iteration.
        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter_batched(
                || match sender.encapsulate(&payload, &mut dst) {
                    TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                    other => panic!("expected a packet, got {:?}", other),
                },
                |datagram| {
                    let mut out = vec![0u8; 4096];
                    match receiver.decapsulate(None, &datagram, &mut out) {
                        TunnResult::WriteToTunnelV4(packet, _) => packet.len(),
                        other => panic!("expected a tunnel packet, got {:?}", other),
                    }
                },
                BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

/// The handshake initiation path, which is where junk and I-packet generation
/// land. Amortized per handshake rather than per packet, but it is the one place
/// a large `Jc` shows up.
pub fn bench_amnezia_handshake_init(c: &mut Criterion) {
    let mut group = c.benchmark_group("amnezia_handshake_init");

    let mut with_junk = configs()
        .into_iter()
        .find(|(name, _)| *name == "awg3")
        .map(|(_, config)| config)
        .unwrap();
    with_junk.junk = JunkConfig::new(8, 64, 256).unwrap();

    let mut cases = configs();
    cases.push(("awg3_junk8", with_junk));

    for (name, config) in cases {
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let peer =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::random_from_rng(OsRng));
        let mut tunn = Tunn::new_with_amnezia3(secret, peer, None, None, 1, None, config).unwrap();
        let mut dst = vec![0u8; 4096];

        group.bench_function(BenchmarkId::from_parameter(name), |b| {
            b.iter(|| {
                let len = match tunn.format_handshake_initiation(&mut dst, true) {
                    TunnResult::WriteToNetwork(packet) => packet.len(),
                    other => panic!("expected an initiation, got {:?}", other),
                };
                // Drain the queued junk and I-packets so they are counted and
                // the queue does not grow without bound across iterations.
                let mut queued = 0;
                while let Some(packet) = tunn.poll_outgoing_packet() {
                    queued += packet.len();
                }
                len + queued
            })
        });
    }
    group.finish();
}

/// `update_timers` is the one AmneziaWG path whose cost scales with peer count
/// rather than packet rate: the device calls it for every peer every 250 ms,
/// and it almost always has nothing to do. On that steady-state path an
/// established initiator draws four values from the AWG 3.0 timing ranges —
/// the new-handshake timeout, the keepalive timeout, and two rekey deadlines —
/// so this is where a syscall-per-draw RNG would be paid 4x per peer per tick.
pub fn bench_amnezia_update_timers(c: &mut Criterion) {
    let mut group = c.benchmark_group("amnezia_update_timers");

    // Every timing range populated, so all four picks are live. Values are far
    // enough out that nothing actually fires during a benchmark run and the
    // measurement stays on the "nothing to do" path the device really sees.
    let mut awg3_timed = configs()
        .into_iter()
        .find(|(name, _)| *name == "awg3")
        .map(|(_, config)| config)
        .unwrap();
    awg3_timed.timing_ranges = TimingRanges {
        rekey_after_time: U32Range::new(120, 180).unwrap(),
        rekey_timeout: U32Range::new(5, 9).unwrap(),
        reject_after_time: U32Range::new(180, 220).unwrap(),
        keepalive_timeout: U32Range::new(10, 20).unwrap(),
        max_handshake_attempts: U32Range::new(10, 20).unwrap(),
        persistent_keepalive: U32Range::default(),
    };

    let cases = vec![
        ("wireguard", Amnezia3Config::wireguard_compatible()),
        ("awg3_timing_ranges", awg3_timed),
    ];

    for (name, config) in cases {
        // Idle: no session yet. This is most peers most of the time.
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let peer =
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::random_from_rng(OsRng));
        let mut idle =
            Tunn::new_with_amnezia3(secret, peer, None, None, 1, None, config.clone()).unwrap();
        let mut dst = vec![0u8; 2048];

        group.bench_function(BenchmarkId::from_parameter(format!("{}_idle", name)), |b| {
            b.iter(|| match idle.update_timers(&mut dst) {
                TunnResult::Done => 0usize,
                other => panic!("expected an idle tick, got {:?}", other),
            })
        });

        // Established: the initiator arms two extra rekey deadlines, so this is
        // the four-pick case.
        let (mut sender, _receiver) = established_pair(&config);
        group.bench_function(
            BenchmarkId::from_parameter(format!("{}_established", name)),
            |b| {
                b.iter(|| match sender.update_timers(&mut dst) {
                    TunnResult::Done => 0usize,
                    TunnResult::WriteToNetwork(packet) => packet.len(),
                    other => panic!("unexpected tick result {:?}", other),
                })
            },
        );
    }
    group.finish();
}
