//! After a handshake, `Session::peer_info(peer_vpn_addr)` returns the
//! verified peer's certificate identity (name, groups, networks) that
//! nebula-listener feeds into the firewall.
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use nebula_protocol::handshake::Cipher;
use nebula_protocol::session::{Session, SessionConfig};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[tokio::test]
async fn peer_info_returns_verified_identity_after_handshake() {
    let ca = fixture("ca.crt");
    let a_vpn = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1));

    let a = Session::new(SessionConfig {
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
    let a_local: SocketAddr = a.local_addr().unwrap();

    let b = Session::new(SessionConfig {
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

    // No identity is known before the handshake.
    assert!(b.peer_info(a_vpn).await.is_none());

    b.connect(a_vpn).await.expect("handshake should complete");

    let info = b.peer_info(a_vpn).await.expect("peer identity known after handshake");
    assert_eq!(info.name, "host-a");
    assert_eq!(info.groups, vec!["test".to_string()]);
    assert_eq!(info.networks.len(), 1);
    assert_eq!(info.networks[0].addr, a_vpn);
    assert_eq!(info.networks[0].prefix_len, 16);
}
