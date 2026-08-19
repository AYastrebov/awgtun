// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

// This module contains some integration tests for awgtun
// Those tests require docker and sudo privileges to run
#[cfg(all(test, not(target_os = "macos")))]
mod tests {
    use crate::device::{DeviceConfig, DeviceHandle};
    use crate::x25519::{PublicKey, StaticSecret};
    use base64::Engine as _;
    use hex::encode;
    use rand_core::OsRng;
    use ring::rand::{SecureRandom, SystemRandom};
    use std::fmt::Write as _;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;

    static NEXT_IFACE_IDX: AtomicUsize = AtomicUsize::new(100); // utun 100+ should be vacant during testing on CI
    static NEXT_PORT: AtomicUsize = AtomicUsize::new(61111); // Use ports starting with 61111, hoping we don't run into a taken port 🤷
    static NEXT_IP: AtomicUsize = AtomicUsize::new(0xc0000200); // Use 192.0.2.0/24 for those tests, we might use more than 256 addresses though, usize must be >=32 bits on all supported platforms
    static NEXT_IP_V6: AtomicUsize = AtomicUsize::new(0); // Use the 2001:db8:: address space, append this atomic counter for bottom 32 bits

    fn next_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(
            NEXT_IP.fetch_add(1, Ordering::Relaxed) as u32
        ))
    }

    fn next_ip_v6() -> IpAddr {
        let addr = 0x2001_0db8_0000_0000_0000_0000_0000_0000_u128
            + u128::from(NEXT_IP_V6.fetch_add(1, Ordering::Relaxed) as u32);

        IpAddr::V6(Ipv6Addr::from(addr))
    }

    fn next_port() -> u16 {
        NEXT_PORT.fetch_add(1, Ordering::Relaxed) as u16
    }

    /// Represents an allowed IP and cidr for a peer
    struct AllowedIp {
        ip: IpAddr,
        cidr: u8,
    }

    /// Represents a single peer running in a container
    struct Peer {
        key: StaticSecret,
        endpoint: SocketAddr,
        allowed_ips: Vec<AllowedIp>,
        container_name: Option<String>,
    }

    /// Represents a single WireGuard interface on local machine
    struct WGHandle {
        _device: DeviceHandle,
        name: String,
        addr_v4: IpAddr,
        addr_v6: IpAddr,
        started: bool,
        peers: Vec<Arc<Peer>>,
    }

    impl Drop for Peer {
        fn drop(&mut self) {
            if let Some(name) = &self.container_name {
                Command::new("docker")
                    .args([
                        "stop", // Run docker
                        &name[5..],
                    ])
                    .status()
                    .ok();

                std::fs::remove_file(name).ok();
                std::fs::remove_file(format!("{}.ngx", name)).ok();
            }
        }
    }

    impl Peer {
        /// Create a new peer with a given endpoint and a list of allowed IPs
        fn new(endpoint: SocketAddr, allowed_ips: Vec<AllowedIp>) -> Peer {
            Peer {
                key: StaticSecret::random_from_rng(OsRng),
                endpoint,
                allowed_ips,
                container_name: None,
            }
        }

        /// Creates a new configuration file that can be used by wg-quick
        fn gen_wg_conf(
            &self,
            local_key: &PublicKey,
            local_addr: &IpAddr,
            local_port: u16,
        ) -> String {
            let mut conf = String::from("[Interface]\n");
            // Each allowed ip, becomes a possible address in the config
            for ip in &self.allowed_ips {
                let _ = writeln!(conf, "Address = {}/{}", ip.ip, ip.cidr);
            }

            // The local endpoint port is the remote listen port
            let _ = writeln!(conf, "ListenPort = {}", self.endpoint.port());
            // HACK: this should consume the key so it can't be reused instead of cloning and serializing
            let _ = writeln!(
                conf,
                "PrivateKey = {}",
                base64::engine::general_purpose::STANDARD.encode(self.key.to_bytes())
            );

            // We are the peer
            let _ = writeln!(conf, "[Peer]");
            let _ = writeln!(
                conf,
                "PublicKey = {}",
                base64::engine::general_purpose::STANDARD.encode(local_key.as_bytes())
            );
            let _ = writeln!(conf, "AllowedIPs = {}", local_addr);
            let _ = write!(conf, "Endpoint = 127.0.0.1:{}", local_port);

            conf
        }

        /// Create a simple nginx config, that will respond with the peer public key
        fn gen_nginx_conf(&self) -> String {
            format!(
                "server {{\n\
                 listen 80;\n\
                 listen [::]:80;\n\
                 location / {{\n\
                 return 200 '{}';\n\
                 }}\n\
                 }}",
                encode(PublicKey::from(&self.key).as_bytes())
            )
        }

        fn start_in_container(
            &mut self,
            local_key: &PublicKey,
            local_addr: &IpAddr,
            local_port: u16,
        ) {
            let peer_config = self.gen_wg_conf(local_key, local_addr, local_port);
            let peer_config_file = temp_path();
            std::fs::write(&peer_config_file, peer_config).unwrap();
            let nginx_config = self.gen_nginx_conf();
            let nginx_config_file = format!("{}.ngx", peer_config_file);
            std::fs::write(&nginx_config_file, nginx_config).unwrap();

            Command::new("docker")
                .args([
                    "run",                 // Run docker
                    "-d",                  // In detached mode
                    "--cap-add=NET_ADMIN", // Grant permissions to open a tunnel
                    "--device=/dev/net/tun",
                    "--sysctl", // Enable ipv6
                    "net.ipv6.conf.all.disable_ipv6=0",
                    "--sysctl",
                    "net.ipv6.conf.default.disable_ipv6=0",
                    "-p", // Open port for the endpoint
                    &format!("{0}:{0}/udp", self.endpoint.port()),
                    "-v", // Map the generated WireGuard config file
                    &format!("{}:/wireguard/wg.conf", peer_config_file),
                    "-v", // Map the nginx config file
                    &format!("{}:/etc/nginx/conf.d/default.conf", nginx_config_file),
                    "--rm", // Cleanup
                    "--name",
                    &peer_config_file[5..],
                    "vkrasnov/wireguard-test",
                ])
                .status()
                .expect("Failed to run docker");

            self.container_name = Some(peer_config_file);
        }

        fn connect(&self) -> std::net::TcpStream {
            let http_addr = SocketAddr::new(self.allowed_ips[0].ip, 80);
            for _i in 0..5 {
                let res = std::net::TcpStream::connect(http_addr);
                if let Err(err) = res {
                    println!("failed to connect: {:?}", err);
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }

                return res.unwrap();
            }

            panic!("failed to connect");
        }

        fn get_request(&self) -> String {
            let mut tcp_conn = self.connect();

            write!(
                tcp_conn,
                "GET / HTTP/1.1\nHost: localhost\nAccept: */*\nConnection: close\n\n"
            )
            .unwrap();

            tcp_conn
                .set_read_timeout(Some(std::time::Duration::from_secs(60)))
                .ok();

            let mut reader = BufReader::new(tcp_conn);
            let mut line = String::new();
            let mut response = String::new();
            let mut len = 0usize;

            // Read response code
            if reader.read_line(&mut line).is_ok() && !line.starts_with("HTTP/1.1 200") {
                return response;
            }
            line.clear();

            // Read headers
            while reader.read_line(&mut line).is_ok() {
                if line.trim() == "" {
                    break;
                }

                {
                    let parsed_line: Vec<&str> = line.split(':').collect();
                    if parsed_line.len() < 2 {
                        return response;
                    }

                    let (key, val) = (parsed_line[0], parsed_line[1]);
                    if key.to_lowercase() == "content-length" {
                        len = match val.trim().parse() {
                            Err(_) => return response,
                            Ok(len) => len,
                        };
                    }
                }
                line.clear();
            }

            // Read body
            let mut buf = [0u8; 256];
            while len > 0 {
                let to_read = len.min(buf.len());
                if reader.read_exact(&mut buf[..to_read]).is_err() {
                    return response;
                }
                response.push_str(&String::from_utf8_lossy(&buf[..to_read]));
                len -= to_read;
            }

            response
        }
    }

    impl WGHandle {
        /// Create a new interface for the tunnel with the given address
        fn init(addr_v4: IpAddr, addr_v6: IpAddr) -> WGHandle {
            WGHandle::init_with_config(
                addr_v4,
                addr_v6,
                DeviceConfig {
                    n_threads: 2,
                    use_connected_socket: true,
                    #[cfg(target_os = "linux")]
                    use_multi_queue: true,
                    #[cfg(target_os = "linux")]
                    uapi_fd: -1,
                },
            )
        }

        /// Create a new interface for the tunnel with the given address
        fn init_with_config(addr_v4: IpAddr, addr_v6: IpAddr, config: DeviceConfig) -> WGHandle {
            // Generate a new name, utun100+ should work on macOS and Linux
            let name = format!("utun{}", NEXT_IFACE_IDX.fetch_add(1, Ordering::Relaxed));
            let _device = DeviceHandle::new(&name, config).unwrap();
            WGHandle {
                _device,
                name,
                addr_v4,
                addr_v6,
                started: false,
                peers: vec![],
            }
        }

        #[cfg(target_os = "macos")]
        /// Starts the tunnel
        fn start(&mut self) {
            // Assign the ipv4 address to the interface
            Command::new("ifconfig")
                .args(&[
                    &self.name,
                    &self.addr_v4.to_string(),
                    &self.addr_v4.to_string(),
                    "alias",
                ])
                .status()
                .expect("failed to assign ip to tunnel");

            // Assign the ipv6 address to the interface
            Command::new("ifconfig")
                .args(&[
                    &self.name,
                    "inet6",
                    &self.addr_v6.to_string(),
                    "prefixlen",
                    "128",
                    "alias",
                ])
                .status()
                .expect("failed to assign ipv6 to tunnel");

            // Start the tunnel
            Command::new("ifconfig")
                .args(&[&self.name, "up"])
                .status()
                .expect("failed to start the tunnel");

            self.started = true;

            // Add each peer to the routing table
            for p in &self.peers {
                for r in &p.allowed_ips {
                    let inet_flag = match r.ip {
                        IpAddr::V4(_) => "-inet",
                        IpAddr::V6(_) => "-inet6",
                    };

                    Command::new("route")
                        .args(&[
                            "-q",
                            "-n",
                            "add",
                            inet_flag,
                            &format!("{}/{}", r.ip, r.cidr),
                            "-interface",
                            &self.name,
                        ])
                        .status()
                        .expect("failed to add route");
                }
            }
        }

        #[cfg(target_os = "linux")]
        /// Starts the tunnel
        fn start(&mut self) {
            Command::new("ip")
                .args([
                    "address",
                    "add",
                    &self.addr_v4.to_string(),
                    "dev",
                    &self.name,
                ])
                .status()
                .expect("failed to assign ip to tunnel");

            Command::new("ip")
                .args([
                    "address",
                    "add",
                    &self.addr_v6.to_string(),
                    "dev",
                    &self.name,
                ])
                .status()
                .expect("failed to assign ipv6 to tunnel");

            // Start the tunnel
            Command::new("ip")
                .args(["link", "set", "mtu", "1400", "up", "dev", &self.name])
                .status()
                .expect("failed to start the tunnel");

            self.started = true;

            // Add each peer to the routing table
            for p in &self.peers {
                for r in &p.allowed_ips {
                    Command::new("ip")
                        .args([
                            "route",
                            "add",
                            &format!("{}/{}", r.ip, r.cidr),
                            "dev",
                            &self.name,
                        ])
                        .status()
                        .expect("failed to add route");
                }
            }
        }

        /// Issue a get command on the interface
        fn wg_get(&self) -> String {
            let path = format!("/var/run/wireguard/{}.sock", self.name);

            let mut socket = UnixStream::connect(path).unwrap();
            write!(socket, "get=1\n\n").unwrap();

            let mut ret = String::new();
            socket.read_to_string(&mut ret).unwrap();
            ret
        }

        /// Issue a set command on the interface
        fn wg_set(&self, setting: &str) -> String {
            let path = format!("/var/run/wireguard/{}.sock", self.name);
            let mut socket = UnixStream::connect(path).unwrap();
            write!(socket, "set=1\n{}\n\n", setting).unwrap();

            let mut ret = String::new();
            socket.read_to_string(&mut ret).unwrap();
            ret
        }

        /// Assign a listen_port to the interface
        fn wg_set_port(&self, port: u16) -> String {
            self.wg_set(&format!("listen_port={}", port))
        }

        /// Assign a private_key to the interface
        fn wg_set_key(&self, key: StaticSecret) -> String {
            self.wg_set(&format!("private_key={}", encode(key.to_bytes())))
        }

        /// Assign a peer to the interface (with public_key, endpoint and a series of nallowed_ip)
        fn wg_set_peer(
            &self,
            key: &PublicKey,
            ep: &SocketAddr,
            allowed_ips: &[AllowedIp],
        ) -> String {
            let mut req = format!("public_key={}\nendpoint={}", encode(key.as_bytes()), ep);
            for AllowedIp { ip, cidr } in allowed_ips {
                let _ = write!(req, "\nallowed_ip={}/{}", ip, cidr);
            }

            self.wg_set(&req)
        }

        /// Add a new known peer
        fn add_peer(&mut self, peer: Arc<Peer>) {
            self.wg_set_peer(
                &PublicKey::from(&peer.key),
                &peer.endpoint,
                &peer.allowed_ips,
            );
            self.peers.push(peer);
        }
    }

    /// Create a new filename in the /tmp dir
    fn temp_path() -> String {
        let mut path = String::from("/tmp/");
        let mut buf = [0u8; 32];
        SystemRandom::new().fill(&mut buf[..]).unwrap();
        path.push_str(&encode(buf));
        path
    }

    #[test]
    #[ignore]
    /// Test if wireguard starts and creates a unix socket that we can read from
    fn test_wireguard_get() {
        let wg = WGHandle::init("192.0.2.0".parse().unwrap(), "::2".parse().unwrap());
        let response = wg.wg_get();
        assert!(response.ends_with("errno=0\n\n"));
    }

    #[test]
    #[ignore]
    /// Test if wireguard starts and creates a unix socket that we can use to set settings
    fn test_wireguard_set() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let own_public_key = PublicKey::from(&private_key);

        let wg = WGHandle::init("192.0.2.0".parse().unwrap(), "::2".parse().unwrap());
        assert!(wg.wg_get().ends_with("errno=0\n\n"));
        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        // Check that the response matches what we expect
        assert_eq!(
            wg.wg_get(),
            format!(
                "own_public_key={}\nlisten_port={}\nerrno=0\n\n",
                encode(own_public_key.as_bytes()),
                port
            )
        );

        let peer_key = StaticSecret::random_from_rng(OsRng);
        let peer_pub_key = PublicKey::from(&peer_key);
        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 0, 0, 1)), 50001);
        let allowed_ips = [
            AllowedIp {
                ip: IpAddr::V4(Ipv4Addr::new(172, 0, 0, 2)),
                cidr: 32,
            },
            AllowedIp {
                ip: IpAddr::V6(Ipv6Addr::new(0xf120, 0, 0, 2, 2, 2, 0, 0)),
                cidr: 100,
            },
        ];

        assert_eq!(
            wg.wg_set_peer(&peer_pub_key, &endpoint, &allowed_ips),
            "errno=0\n\n"
        );

        // Check that the response matches what we expect
        assert_eq!(
            wg.wg_get(),
            format!(
                "own_public_key={}\n\
                 listen_port={}\n\
                 public_key={}\n\
                 endpoint={}\n\
                 allowed_ip={}/{}\n\
                 allowed_ip={}/{}\n\
                 rx_bytes=0\n\
                 tx_bytes=0\n\
                 errno=0\n\n",
                encode(own_public_key.as_bytes()),
                port,
                encode(peer_pub_key.as_bytes()),
                endpoint,
                allowed_ips[0].ip,
                allowed_ips[0].cidr,
                allowed_ips[1].ip,
                allowed_ips[1].cidr
            )
        );
    }

    /// Test if wireguard can handle simple ipv4 connections, don't use a connected socket
    #[test]
    #[ignore]
    fn test_wg_start_ipv4_non_connected() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init_with_config(
            addr_v4,
            addr_v6,
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: false,
                #[cfg(target_os = "linux")]
                use_multi_queue: true,
                #[cfg(target_os = "linux")]
                uapi_fd: -1,
            },
        );

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        // Create a new peer whose endpoint is on this machine
        let mut peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
            vec![AllowedIp {
                ip: next_ip(),
                cidr: 32,
            }],
        );

        peer.start_in_container(&public_key, &addr_v4, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test if wireguard can handle simple ipv4 connections
    #[test]
    #[ignore]
    fn test_wg_start_ipv4() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        // Create a new peer whose endpoint is on this machine
        let mut peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
            vec![AllowedIp {
                ip: next_ip(),
                cidr: 32,
            }],
        );

        peer.start_in_container(&public_key, &addr_v4, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    #[test]
    #[ignore]
    /// Test if wireguard can handle simple ipv6 connections
    fn test_wg_start_ipv6() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        let mut peer = Peer::new(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
            vec![AllowedIp {
                ip: next_ip_v6(),
                cidr: 128,
            }],
        );

        peer.start_in_container(&public_key, &addr_v6, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test if wireguard can handle connection with an ipv6 endpoint
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")] // Can't make docker work with ipv6 on macOS ATM
    fn test_wg_start_ipv6_endpoint() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        let mut peer = Peer::new(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                next_port(),
            ),
            vec![AllowedIp {
                ip: next_ip_v6(),
                cidr: 128,
            }],
        );

        peer.start_in_container(&public_key, &addr_v6, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test if wireguard can handle connection with an ipv6 endpoint
    #[test]
    #[ignore]
    #[cfg(target_os = "linux")] // Can't make docker work with ipv6 on macOS ATM
    fn test_wg_start_ipv6_endpoint_not_connected() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init_with_config(
            addr_v4,
            addr_v6,
            DeviceConfig {
                n_threads: 2,
                use_connected_socket: false,
                #[cfg(target_os = "linux")]
                use_multi_queue: true,
                #[cfg(target_os = "linux")]
                uapi_fd: -1,
            },
        );

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        let mut peer = Peer::new(
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                next_port(),
            ),
            vec![AllowedIp {
                ip: next_ip_v6(),
                cidr: 128,
            }],
        );

        peer.start_in_container(&public_key, &addr_v6, port);

        let peer = Arc::new(peer);

        wg.add_peer(Arc::clone(&peer));
        wg.start();

        let response = peer.get_request();

        assert_eq!(response, encode(PublicKey::from(&peer.key).as_bytes()));
    }

    /// Test many concurrent connections
    #[test]
    #[ignore]
    fn test_wg_concurrent() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        for _ in 0..5 {
            // Create a new peer whose endpoint is on this machine
            let mut peer = Peer::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
                vec![AllowedIp {
                    ip: next_ip(),
                    cidr: 32,
                }],
            );

            peer.start_in_container(&public_key, &addr_v4, port);

            let peer = Arc::new(peer);

            wg.add_peer(Arc::clone(&peer));
        }

        wg.start();

        let mut threads = vec![];

        for p in wg.peers {
            let pub_key = PublicKey::from(&p.key);
            threads.push(thread::spawn(move || {
                for _ in 0..100 {
                    let response = p.get_request();
                    assert_eq!(response, encode(pub_key.as_bytes()));
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    /// Test many concurrent connections
    #[test]
    #[ignore]
    fn test_wg_concurrent_v6() {
        let port = next_port();
        let private_key = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&private_key);
        let addr_v4 = next_ip();
        let addr_v6 = next_ip_v6();

        let mut wg = WGHandle::init(addr_v4, addr_v6);

        assert_eq!(wg.wg_set_port(port), "errno=0\n\n");
        assert_eq!(wg.wg_set_key(private_key), "errno=0\n\n");

        for _ in 0..5 {
            // Create a new peer whose endpoint is on this machine
            let mut peer = Peer::new(
                SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), next_port()),
                vec![AllowedIp {
                    ip: next_ip_v6(),
                    cidr: 128,
                }],
            );

            peer.start_in_container(&public_key, &addr_v6, port);

            let peer = Arc::new(peer);

            wg.add_peer(Arc::clone(&peer));
        }

        wg.start();

        let mut threads = vec![];

        for p in wg.peers {
            let pub_key = PublicKey::from(&p.key);
            threads.push(thread::spawn(move || {
                for _ in 0..100 {
                    let response = p.get_request();
                    assert_eq!(response, encode(pub_key.as_bytes()));
                }
            }));
        }

        for t in threads {
            t.join().unwrap();
        }
    }

    /// A full AmneziaWG 3.0 interface configuration: junk packets, an I1 init
    /// packet, dynamic headers, crypto padding, header protection, content
    /// padding and randomized timings. Every obfuscation layer is on, so a peer
    /// that does not share it cannot parse a single datagram.
    const AWG3_INTERFACE_CONF: &str = "jc=3\n\
         jmin=64\n\
         jmax=256\n\
         s1=16\n\
         s2=16\n\
         s3=16\n\
         s4=16\n\
         h1=1000-1099\n\
         h2=2000-2099\n\
         h3=3000-3099\n\
         h4=4000-4099\n\
         i1=<b 0xc0ffee><r 32>\n\
         header_protection_key=\
         6b6579206b6579206b6579206b6579206b6579206b6579206b6579206b657920\n\
         content_padding_addition=1-32\n\
         rekey_timeout=3-6\n\
         keepalive_timeout=8-12";

    /// Configure one side of a local AmneziaWG pair and return its handle.
    ///
    /// `awg` is the interface-level AmneziaWG block, or an empty string for a
    /// standard WireGuard device. The AmneziaWG keys are sent in the same
    /// `set=1` as the interface keys, before any peer section, which is how
    /// `awg setconf` sends a configuration.
    fn init_local_peer(
        key: StaticSecret,
        port: u16,
        peer_pub: &PublicKey,
        peer_port: u16,
        peer_ip: IpAddr,
        awg: &str,
        keepalive: Option<&str>,
    ) -> WGHandle {
        let wg = WGHandle::init(next_ip(), next_ip_v6());

        let mut iface = format!(
            "listen_port={}\nprivate_key={}",
            port,
            encode(key.to_bytes())
        );
        if !awg.is_empty() {
            let _ = write!(iface, "\n{}", awg);
        }
        assert_eq!(
            wg.wg_set(&iface),
            "errno=0\n\n",
            "interface config rejected"
        );

        let mut peer = format!(
            "public_key={}\nendpoint=127.0.0.1:{}\nallowed_ip={}/32",
            encode(peer_pub.as_bytes()),
            peer_port,
            peer_ip
        );
        if let Some(interval) = keepalive {
            let _ = write!(peer, "\npersistent_keepalive_interval={}", interval);
        }
        assert_eq!(wg.wg_set(&peer), "errno=0\n\n", "peer config rejected");

        wg
    }

    /// Poll `get=1` until the device reports a completed handshake.
    fn wait_for_handshake(wg: &WGHandle, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if wg.wg_get().contains("last_handshake_time_sec=") {
                return true;
            }
            thread::sleep(std::time::Duration::from_millis(100));
        }
        false
    }

    #[test]
    #[ignore]
    /// Two local devices sharing an AmneziaWG 3.0 configuration must complete a
    /// handshake through the full device stack: the UAPI config, the drain of
    /// junk and I-packets ahead of the initiation, and classification of padded,
    /// header-protected datagrams on receive.
    ///
    /// A persistent keepalive on one side is what starts the handshake, since
    /// two TUN interfaces on one host cannot route to each other without
    /// network namespaces.
    ///
    /// A completed handshake on *both* sides is the whole assertion, and it is
    /// a strong one: each side had to classify the other's padded,
    /// header-protected datagrams and authenticate them under a dynamic header.
    /// There is deliberately no `rx_bytes` check — those counters track
    /// decapsulated payload, and this pair passes none.
    fn test_awg3_handshake_between_two_devices() {
        let (port_a, port_b) = (next_port(), next_port());
        let (key_a, key_b) = (
            StaticSecret::random_from_rng(OsRng),
            StaticSecret::random_from_rng(OsRng),
        );
        let (pub_a, pub_b) = (PublicKey::from(&key_a), PublicKey::from(&key_b));
        let (ip_a, ip_b) = (next_ip(), next_ip());

        let wg_b = init_local_peer(
            key_b,
            port_b,
            &pub_a,
            port_a,
            ip_a,
            AWG3_INTERFACE_CONF,
            None,
        );
        let wg_a = init_local_peer(
            key_a,
            port_a,
            &pub_b,
            port_b,
            ip_b,
            AWG3_INTERFACE_CONF,
            Some("1"),
        );

        assert!(
            wait_for_handshake(&wg_a, std::time::Duration::from_secs(15)),
            "initiator never completed an AmneziaWG handshake"
        );
        assert!(
            wait_for_handshake(&wg_b, std::time::Duration::from_secs(5)),
            "responder never completed an AmneziaWG handshake"
        );
    }

    #[test]
    #[ignore]
    /// The negative control for the test above: a peer that does not share the
    /// AmneziaWG configuration must not be able to complete a handshake.
    ///
    /// Without this, a bug that silently ignored the AmneziaWG config would
    /// still pass the positive test, because two plain WireGuard devices also
    /// handshake happily.
    fn test_awg3_does_not_interoperate_with_plain_wireguard() {
        let (port_a, port_b) = (next_port(), next_port());
        let (key_a, key_b) = (
            StaticSecret::random_from_rng(OsRng),
            StaticSecret::random_from_rng(OsRng),
        );
        let (pub_a, pub_b) = (PublicKey::from(&key_a), PublicKey::from(&key_b));
        let (ip_a, ip_b) = (next_ip(), next_ip());

        // The responder speaks standard WireGuard.
        let wg_b = init_local_peer(key_b, port_b, &pub_a, port_a, ip_a, "", None);
        let wg_a = init_local_peer(
            key_a,
            port_a,
            &pub_b,
            port_b,
            ip_b,
            AWG3_INTERFACE_CONF,
            Some("1"),
        );

        assert!(
            !wait_for_handshake(&wg_a, std::time::Duration::from_secs(6)),
            "an AmneziaWG initiator handshook with a plain WireGuard peer, \
             so the obfuscation is not reaching the wire"
        );
        assert!(
            !wait_for_handshake(&wg_b, std::time::Duration::from_secs(1)),
            "a plain WireGuard responder parsed an AmneziaWG datagram"
        );
    }

    #[test]
    #[ignore]
    /// `get=1` must report the AmneziaWG configuration back, so `awg showconf`
    /// round-trips.
    fn test_awg3_config_round_trips_through_the_api() {
        let key = StaticSecret::random_from_rng(OsRng);
        let wg = WGHandle::init(next_ip(), next_ip_v6());

        assert_eq!(
            wg.wg_set(&format!(
                "listen_port={}\nprivate_key={}\n{}",
                next_port(),
                encode(key.to_bytes()),
                AWG3_INTERFACE_CONF
            )),
            "errno=0\n\n"
        );

        let status = wg.wg_get();
        for line in AWG3_INTERFACE_CONF.lines() {
            assert!(
                status.contains(line),
                "get=1 dropped `{}`, full response:\n{}",
                line,
                status
            );
        }
    }

    #[test]
    #[ignore]
    /// A `set=1` carrying one AmneziaWG key must change that key and leave the
    /// rest alone, the way the WireGuard UAPI and amneziawg-go both behave.
    ///
    /// This used to replace the whole AmneziaWG configuration per `set=1`, so
    /// `awg set <if> jc 5` silently wiped S1-S4, H1-H4 and the header
    /// protection key.
    ///
    /// A peer is configured first, so the update also runs the peer rebuild
    /// that a device-level change triggers.
    fn test_awg3_config_updates_are_incremental() {
        let key = StaticSecret::random_from_rng(OsRng);
        let peer_key = PublicKey::from(&StaticSecret::random_from_rng(OsRng));
        let peer_ip = next_ip();
        let wg = WGHandle::init(next_ip(), next_ip_v6());

        assert_eq!(
            wg.wg_set(&format!(
                "listen_port={}\nprivate_key={}\n{}",
                next_port(),
                encode(key.to_bytes()),
                AWG3_INTERFACE_CONF
            )),
            "errno=0\n\n"
        );
        assert_eq!(
            wg.wg_set(&format!(
                "public_key={}\nendpoint=127.0.0.1:{}\nallowed_ip={}/32\n\
                 persistent_keepalive_interval=25",
                encode(peer_key.as_bytes()),
                next_port(),
                peer_ip
            )),
            "errno=0\n\n"
        );

        assert_eq!(wg.wg_set("jc=5"), "errno=0\n\n");

        let status = wg.wg_get();
        assert!(status.contains("jc=5\n"), "jc was not updated:\n{}", status);
        for line in AWG3_INTERFACE_CONF.lines().filter(|l| *l != "jc=3") {
            assert!(
                status.contains(line),
                "a one-key set=1 dropped `{}`, full response:\n{}",
                line,
                status
            );
        }

        // The rebuild preserves the peer and its settings; only the session
        // state behind it is new.
        for line in [
            format!("public_key={}", encode(peer_key.as_bytes())),
            format!("allowed_ip={}/32", peer_ip),
            "persistent_keepalive_interval=25".to_owned(),
        ] {
            assert!(
                status.contains(&line),
                "the peer rebuild lost `{}`, full response:\n{}",
                line,
                status
            );
        }
    }

    #[test]
    #[ignore]
    /// Obfuscation without custom headers is a valid AmneziaWG configuration:
    /// amneziawg-go defaults H1-H4 to the standard WireGuard types and never
    /// refuses them. This used to return EINVAL.
    fn test_awg_padding_without_custom_headers_is_accepted() {
        let key = StaticSecret::random_from_rng(OsRng);
        let wg = WGHandle::init(next_ip(), next_ip_v6());

        assert_eq!(
            wg.wg_set(&format!(
                "listen_port={}\nprivate_key={}\n\
                 jc=3\njmin=64\njmax=256\ns1=16\ns2=16\ns3=16\ns4=16",
                next_port(),
                encode(key.to_bytes()),
            )),
            "errno=0\n\n",
            "junk and padding with default headers must be accepted"
        );

        let status = wg.wg_get();
        assert!(
            status.contains("s1=16\n"),
            "config not applied:\n{}",
            status
        );
    }
}
