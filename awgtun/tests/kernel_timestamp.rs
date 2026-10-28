//! Opt-in Linux regression against real kernel WireGuard, not a second awgtun.
//! Requires root, iproute2, wireguard-tools and the wireguard kernel module.
#![cfg(target_os = "linux")]

use awgtun::{
    noise::{Tunn, TunnResult},
    x25519,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::{
    io::Write,
    net::UdpSocket,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

fn run(program: &str, args: &[&str], input: Option<&str>) -> String {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start kernel test tool");
    if let Some(input) = input {
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{program} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

struct Network {
    server: String,
    client: String,
    server_link: String,
    client_link: String,
}
impl Drop for Network {
    fn drop(&mut self) {
        // Each name belongs only to this test; never flush host routes/rules.
        for ns in [&self.client, &self.server] {
            let _ = Command::new("ip").args(["netns", "del", ns]).output();
        }
        for link in [&self.client_link, &self.server_link] {
            let _ = Command::new("ip").args(["link", "del", link]).output();
        }
    }
}
impl Network {
    fn wg(&self, server: bool, args: &[&str], input: Option<&str>) -> String {
        let ns = if server { &self.server } else { &self.client };
        let mut all = vec!["netns", "exec", ns.as_str(), "wg"];
        all.extend_from_slice(args);
        run("ip", &all, input)
    }
}

#[test]
#[ignore = "requires root, ip, wg and kernel WireGuard; creates isolated namespaces"]
fn userspace_to_kernel_same_key_without_replay_pause() {
    let id = std::process::id();
    let net = Network {
        server: format!("awgtun-ts-s-{id}"),
        client: format!("awgtun-ts-c-{id}"),
        server_link: format!("ats{id}"),
        client_link: format!("atc{id}"),
    };
    let client_secret = x25519::StaticSecret::random();
    let server_secret = x25519::StaticSecret::random();
    let client_public = x25519::PublicKey::from(&client_secret);
    let server_public = x25519::PublicKey::from(&server_secret);
    for (ns, link) in [
        (&net.server, &net.server_link),
        (&net.client, &net.client_link),
    ] {
        run("ip", &["netns", "add", ns], None);
        // Create in the original namespace, then move the interface. WireGuard's
        // UDP socket stays in its birth namespace, so only loopback is needed.
        run("ip", &["link", "add", link, "type", "wireguard"], None);
        run("ip", &["link", "set", link, "netns", ns], None);
        run("ip", &["-n", ns, "link", "set", link, "up"], None);
    }
    net.wg(
        true,
        &[
            "set",
            &net.server_link,
            "private-key",
            "/dev/stdin",
            "listen-port",
            "0",
            "peer",
            &STANDARD.encode(client_public.as_bytes()),
            "allowed-ips",
            "10.203.0.1/32",
        ],
        Some(&STANDARD.encode(server_secret.to_bytes())),
    );
    let port: u16 = net
        .wg(true, &["show", &net.server_link, "listen-port"], None)
        .trim()
        .parse()
        .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.connect(("127.0.0.1", port)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut tunnel = Tunn::new(client_secret.clone(), server_public, None, None, 1, None);
    let mut outgoing = [0u8; 2048];
    match tunnel.format_handshake_initiation(&mut outgoing, false) {
        TunnResult::WriteToNetwork(packet) => {
            socket.send(packet).unwrap();
        }
        other => panic!("expected initiation, got {:?}", other),
    }
    let mut incoming = [0u8; 2048];
    let n = socket
        .recv(&mut incoming)
        .expect("kernel must answer userspace handshake");
    match tunnel.decapsulate(None, &incoming[..n], &mut outgoing) {
        TunnResult::WriteToNetwork(packet) => {
            socket.send(packet).unwrap();
        }
        other => panic!("expected key-confirmation packet, got {:?}", other),
    }
    // Keep the server and its latest_timestamp untouched across the switch.
    drop(tunnel);
    drop(socket);
    let endpoint = format!("127.0.0.1:{port}");
    let start = Instant::now();
    net.wg(
        false,
        &[
            "set",
            &net.client_link,
            "private-key",
            "/dev/stdin",
            "peer",
            &STANDARD.encode(server_public.as_bytes()),
            "endpoint",
            &endpoint,
            "allowed-ips",
            "10.203.0.2/32",
            "persistent-keepalive",
            "1",
        ],
        Some(&STANDARD.encode(client_secret.to_bytes())),
    );
    loop {
        let result = net.wg(
            false,
            &["show", &net.client_link, "latest-handshakes"],
            None,
        );
        if result
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u64>()
            .unwrap()
            != 0
        {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(8),
            "kernel handshake rejected after userspace with the same key (timestamp replay)"
        );
        thread::sleep(Duration::from_millis(25));
    }
}
