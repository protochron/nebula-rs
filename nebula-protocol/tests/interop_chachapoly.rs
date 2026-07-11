//! Real-nebula interop test (ChaChaPoly): proves nebula-protocol can
//! complete a handshake and exchange an IP packet with the actual Go
//! `nebula` v1.10.3 binary using the ChaChaPoly cipher (and its
//! little-endian nonce path — see the module-level comment in
//! `transport`), not just AES-GCM. Requires Docker.
//!
//! Run with: cargo test --test interop_chachapoly -- --ignored --nocapture
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::Command;
use std::time::Duration;

use nebula_protocol::handshake::Cipher;
use nebula_protocol::session::{Session, SessionConfig};

fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Builds a minimal, valid IPv4 + ICMP echo-request packet — real
/// nebula's tun device only forwards valid IP packets, so a raw payload
/// wouldn't prove anything about the tunnel actually working end to end.
fn build_icmp_echo_request(src: Ipv4Addr, dst: Ipv4Addr, id: u16, seq: u16) -> Vec<u8> {
    let mut icmp = vec![8u8, 0, 0, 0]; // type=8 (echo request), code=0, checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(b"nebula-protocol-interop");
    let cksum = checksum(&icmp);
    icmp[2..4].copy_from_slice(&cksum.to_be_bytes());

    let total_len = 20 + icmp.len();
    let mut ip = vec![0x45, 0x00];
    ip.extend_from_slice(&(total_len as u16).to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x00]); // identification
    ip.extend_from_slice(&[0x40, 0x00]); // flags/fragment offset: don't fragment
    ip.push(64); // TTL
    ip.push(1); // protocol = ICMP
    ip.extend_from_slice(&[0x00, 0x00]); // header checksum placeholder
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ip_cksum = checksum(&ip);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    ip.extend_from_slice(&icmp);
    ip
}

#[tokio::test]
#[ignore]
async fn handshake_and_icmp_echo_with_real_nebula_chachapoly() {
    let harness = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/docker");
    let status = Command::new("bash")
        .arg("run.sh")
        .env("CIPHER", "chachapoly")
        .current_dir(&harness)
        .status()
        .expect("failed to invoke run.sh");
    assert!(status.success(), "docker interop harness failed to start");

    let build = harness.join("build");
    let session = Session::new(SessionConfig {
        ca_cert_pem: std::fs::read(build.join("ca.crt")).unwrap(),
        host_cert_pem: std::fs::read(build.join("rust-peer.crt")).unwrap(),
        host_key_pem: std::fs::read(build.join("rust-peer.key")).unwrap(),
        cipher: Cipher::ChaChaPoly,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        lighthouses: vec!["127.0.0.1:4242".parse().unwrap()],
        // Both the lighthouse (10.100.0.1) and host2 (10.100.0.2) are pinned
        // directly rather than relying on lighthouse-learned addresses: the
        // Docker harness runs both real-nebula containers with
        // --network host on distinct ports (4242/4243, see
        // tests/interop/docker/build.sh) sharing the host's loopback
        // namespace with this Rust test process, and real nebula's
        // HostUpdateNotification advertises the addresses *it* was
        // configured to listen on, not necessarily the exact loopback port
        // this test needs — pinning both here removes that as a variable.
        static_hosts: vec![
            (IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1)), "127.0.0.1:4242".parse::<SocketAddr>().unwrap()),
            (IpAddr::V4(Ipv4Addr::new(10, 100, 0, 2)), "127.0.0.1:4243".parse::<SocketAddr>().unwrap()),
        ],
    })
    .await
    .expect("session should start");

    let host2 = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 2));
    session.connect(host2).await.expect("handshake with real nebula host2 should complete");

    let rust_peer = Ipv4Addr::new(10, 100, 0, 3);
    let echo = build_icmp_echo_request(rust_peer, Ipv4Addr::new(10, 100, 0, 2), 1, 1);
    session.send(host2, &echo).await.expect("send should succeed");

    let (from, reply) = tokio::time::timeout(Duration::from_secs(5), session.recv())
        .await
        .expect("should receive an ICMP echo reply within 5s")
        .expect("recv should succeed");
    assert_eq!(from, host2);
    assert!(reply.len() >= 21, "reply too short to be an IP+ICMP packet: {} bytes", reply.len());
    assert_eq!(reply[20], 0, "expected ICMP type 0 (echo reply), got {}", reply[20]);

    Command::new("bash").arg("cleanup.sh").current_dir(&harness).status().ok();
}
