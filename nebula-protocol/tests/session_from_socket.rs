//! Proves `Session::from_socket` (the injected-socket constructor used by
//! nebula-listener for netns placement) is behaviorally identical to
//! `Session::new`: two sessions built from pre-bound std sockets complete a
//! handshake and exchange bytes over loopback.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use nebula_protocol::handshake::Cipher;
use nebula_protocol::session::{Session, SessionConfig};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn bound_std_socket() -> std::net::UdpSocket {
    std::net::UdpSocket::bind("127.0.0.1:0").unwrap()
}

#[tokio::test]
async fn from_socket_sessions_handshake_and_exchange_bytes() {
    let ca = fixture("ca.crt");
    let a_vpn = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1));
    let b_vpn = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 2));

    let a_sock = bound_std_socket();
    let a_local: SocketAddr = a_sock.local_addr().unwrap();

    let a = Session::from_socket(
        SessionConfig {
            ca_cert_pem: ca.clone(),
            host_cert_pem: fixture("host-a.crt"),
            host_key_pem: fixture("host-a.key"),
            cipher: Cipher::AesGcm,
            bind_addr: "0.0.0.0:0".parse().unwrap(), // unused on the injected path
            lighthouses: vec![],
            static_hosts: vec![],
        },
        a_sock,
    )
    .await
    .unwrap();

    let b = Session::from_socket(
        SessionConfig {
            ca_cert_pem: ca,
            host_cert_pem: fixture("host-b.crt"),
            host_key_pem: fixture("host-b.key"),
            cipher: Cipher::AesGcm,
            bind_addr: "0.0.0.0:0".parse().unwrap(),
            lighthouses: vec![],
            static_hosts: vec![(a_vpn, a_local)],
        },
        bound_std_socket(),
    )
    .await
    .unwrap();

    b.connect(a_vpn).await.expect("handshake should complete");
    b.send(a_vpn, b"hello from b").await.unwrap();

    let (from, bytes) = tokio::time::timeout(Duration::from_secs(5), a.recv())
        .await
        .expect("a should receive within 5s")
        .unwrap();
    assert_eq!(from, b_vpn);
    assert_eq!(bytes, b"hello from b");
}
