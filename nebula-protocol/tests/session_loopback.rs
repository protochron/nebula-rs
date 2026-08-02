//! Two in-process Sessions, connected directly (no lighthouse needed —
//! addresses are known via `static_hosts`), proving the handshake +
//! send/recv path is internally consistent before Tasks 13/14 prove it
//! against a real Go nebula host.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use nebula_protocol::handshake::Cipher;
use nebula_protocol::session::{Session, SessionConfig};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[tokio::test]
async fn two_sessions_handshake_and_exchange_bytes_over_loopback() {
    let ca = fixture("ca.crt");

    let a_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let b_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let a_vpn = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1));
    let b_vpn = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 2));

    let a = Session::new(SessionConfig {
        ca_cert_pem: ca.clone(),
        host_cert_pem: fixture("host-a.crt"),
        host_key_pem: fixture("host-a.key"),
        cipher: Cipher::AesGcm,
        bind_addr: a_addr,
        lighthouses: vec![],
        static_hosts: vec![],
    })
    .await
    .unwrap();
    let a_local = a.local_addr().unwrap();

    let b = Session::new(SessionConfig {
        ca_cert_pem: ca,
        host_cert_pem: fixture("host-b.crt"),
        host_key_pem: fixture("host-b.key"),
        cipher: Cipher::AesGcm,
        bind_addr: b_addr,
        lighthouses: vec![],
        static_hosts: vec![(a_vpn, a_local)],
    })
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

    // And the reverse direction, over the now-established tunnel.
    a.send(b_vpn, b"hello from a").await.unwrap();
    let (from, bytes) = tokio::time::timeout(Duration::from_secs(5), b.recv())
        .await
        .expect("b should receive within 5s")
        .unwrap();
    assert_eq!(from, a_vpn);
    assert_eq!(bytes, b"hello from a");
}
