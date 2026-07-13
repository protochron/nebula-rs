//! End-to-end forwarding proof with no root/Docker: two in-process nodes,
//! each a `Listener` wrapping a loopback `Session` and a `UnixDatagram`
//! socketpair standing in for a tun. Injecting an IP packet into node A's
//! "tun" must surface it on node B's "tun" — exercising parse → firewall →
//! Session.send on A and Session.recv → firewall → tun-write on B.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixDatagram;
use std::time::Duration;

use nebula_firewall::{FirewallOptions, LocalCidrSpec, PortSpec, Protocol, RuleSet, RuleSetBuilder};
use nebula_protocol::handshake::Cipher;
use nebula_protocol::session::{Session, SessionConfig};

use ipnet::IpNet;
use nebula_listener::{Listener, ListenerConfig};

fn fixture(name: &str) -> Vec<u8> {
    // Reuse nebula-protocol's committed test certs.
    let base = concat!(env!("CARGO_MANIFEST_DIR"), "/../nebula-protocol/tests/fixtures");
    std::fs::read(format!("{base}/{name}")).unwrap()
}

fn allow_any(assigned: Vec<IpNet>) -> RuleSet {
    let mut b = RuleSetBuilder::new(assigned, false, true);
    for incoming in [true, false] {
        b.add_rule(incoming, Protocol::Any, PortSpec::Any, vec![], None, None, LocalCidrSpec::Any, None, None)
            .unwrap();
    }
    b.build()
}

fn fw_options() -> FirewallOptions {
    FirewallOptions {
        tcp_timeout: Duration::from_secs(120),
        udp_timeout: Duration::from_secs(60),
        default_timeout: Duration::from_secs(60),
        in_send_reject: false,
        out_send_reject: false,
        default_local_cidr_any: true,
    }
}

/// One half of a socketpair as an `OwnedFd` for the Listener; the returned
/// `UnixDatagram` is the test's handle to the other end.
fn fake_tun() -> (OwnedFd, UnixDatagram) {
    let (listener_end, test_end) = UnixDatagram::pair().unwrap();
    (OwnedFd::from(listener_end), test_end)
}

/// Minimal IPv4 UDP packet (src→dst, ports 1111→2222, 4-byte payload).
fn udp_packet(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    let mut udp = 1111u16.to_be_bytes().to_vec();
    udp.extend_from_slice(&2222u16.to_be_bytes());
    udp.extend_from_slice(&12u16.to_be_bytes()); // udp length
    udp.extend_from_slice(&[0, 0]); // checksum (unchecked)
    udp.extend_from_slice(b"ping"); // payload

    let total = 20 + udp.len();
    let mut ip = vec![0x45, 0x00];
    ip.extend_from_slice(&(total as u16).to_be_bytes());
    ip.extend_from_slice(&[0, 0, 0x40, 0x00, 64, 17, 0, 0]);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    ip.extend_from_slice(&udp);
    ip
}

#[tokio::test]
async fn packet_injected_into_node_a_tun_arrives_on_node_b_tun() {
    let ca = fixture("ca.crt");
    let a_vpn = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1));
    let a_assigned: Vec<IpNet> = vec!["10.100.0.1/16".parse().unwrap()];
    let b_assigned: Vec<IpNet> = vec!["10.100.0.2/16".parse().unwrap()];

    // Node A session.
    let a_session = Session::new(SessionConfig {
        ca_cert_pem: ca.clone(),
        host_cert_pem: fixture("host-a.crt"),
        host_key_pem: fixture("host-a.key"),
        cipher: Cipher::AesGcm,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        lighthouses: vec![],
        static_hosts: vec![],
    })
    .await
    .unwrap();
    let a_local: SocketAddr = a_session.local_addr().unwrap();

    // Node B session knows A's address statically.
    let b_session = Session::new(SessionConfig {
        ca_cert_pem: ca,
        host_cert_pem: fixture("host-b.crt"),
        host_key_pem: fixture("host-b.key"),
        cipher: Cipher::AesGcm,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        lighthouses: vec![],
        static_hosts: vec![(a_vpn, a_local)],
    })
    .await
    .unwrap();
    let b_local: SocketAddr = b_session.local_addr().unwrap();

    // Teach A where B is so its outbound-first path can connect.
    // (A learns B's socket addr via a manual static host — connect() resolves it.)
    // We do this by rebuilding A's static host knowledge through connect from B first:
    // B initiates so both directions establish; simplest is to connect B→A, then A→B.
    b_session.connect(a_vpn).await.expect("B→A handshake");

    // For A→B we need A to know B's addr; establish it by having A connect once B is known.
    // Register B as a static host for A via a fresh connect using known b_local:
    // (Sessions expose connect(vpn) which resolves via static_hosts/lighthouse; since A
    // had none, we instead drive the outbound packet after A learns B through B's handshake.)
    let _ = b_local; // A already learned B during B→A handshake (peer stored by vpn addr).

    // Build the two listeners with socketpair "tuns".
    let (a_tun_fd, a_tun_test) = fake_tun();
    let (b_tun_fd, b_tun_test) = fake_tun();

    let a_listener = Listener::new(
        ListenerConfig {
            firewall_rules: allow_any(a_assigned.clone()),
            firewall_options: fw_options(),
            assigned_networks: a_assigned,
            unsafe_networks: vec![],
            ca_name: "nebula-protocol interop CA".into(),
            ca_sha: String::new(),
        },
        a_session,
        a_tun_fd,
    )
    .unwrap();

    let b_listener = Listener::new(
        ListenerConfig {
            firewall_rules: allow_any(b_assigned.clone()),
            firewall_options: fw_options(),
            assigned_networks: b_assigned,
            unsafe_networks: vec![],
            ca_name: "nebula-protocol interop CA".into(),
            ca_sha: String::new(),
        },
        b_session,
        b_tun_fd,
    )
    .unwrap();

    tokio::spawn(async move { a_listener.run().await });
    tokio::spawn(async move { b_listener.run().await });

    // Inject an IP packet on A's tun destined for B. A forwards it over the
    // (already-established) tunnel; B's mesh→tun path writes it to B's tun.
    a_tun_test
        .send(&udp_packet(Ipv4Addr::new(10, 100, 0, 1), Ipv4Addr::new(10, 100, 0, 2)))
        .unwrap();

    b_tun_test.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut buf = [0u8; 2048];
    let n = tokio::task::spawn_blocking(move || b_tun_test.recv(&mut buf).map(|n| (n, buf)))
        .await
        .unwrap()
        .expect("packet should arrive on node B's tun within 5s");
    let (len, buf) = n;
    // It is the same IP packet (src=A, dst=B, UDP).
    assert!(len >= 28);
    assert_eq!(buf[9], 17, "protocol should still be UDP");
    assert_eq!(&buf[12..16], &[10, 100, 0, 1]);
    assert_eq!(&buf[16..20], &[10, 100, 0, 2]);
}

#[tokio::test]
async fn aborting_run_releases_the_tun_fd() {
    let ca = fixture("ca.crt");
    let assigned: Vec<IpNet> = vec!["10.100.0.1/16".parse().unwrap()];

    let session = Session::new(SessionConfig {
        ca_cert_pem: ca,
        host_cert_pem: fixture("host-a.crt"),
        host_key_pem: fixture("host-a.key"),
        cipher: Cipher::AesGcm,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        lighthouses: vec![],
        static_hosts: vec![],
    })
    .await
    .unwrap();

    let (tun_fd, tun_test) = fake_tun();
    let listener = Listener::new(
        ListenerConfig {
            firewall_rules: allow_any(assigned.clone()),
            firewall_options: fw_options(),
            assigned_networks: assigned,
            unsafe_networks: vec![],
            ca_name: "nebula-protocol interop CA".into(),
            ca_sha: String::new(),
        },
        session,
        tun_fd,
    )
    .unwrap();

    let handle = tokio::spawn(listener.run());
    // Let the forwarding loops start.
    tokio::time::sleep(Duration::from_millis(100)).await;
    handle.abort();

    // Once the loops are aborted the listener half of the socketpair drops;
    // sends from the test half must start failing (ECONNREFUSED/EPIPE).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if tun_test.send(b"x").is_err() {
            break; // released
        }
        assert!(
            std::time::Instant::now() < deadline,
            "listener kept the tun fd alive after run() was aborted"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
