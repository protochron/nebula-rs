//! Real-nebula interop test: proves the *lighthouse discovery* path itself
//! works — a real Go host reaches a nebula-protocol `Session` purely
//! through lighthouse registration/query, with no static knowledge of the
//! session's address on the Go side.
//!
//! `interop_aes`/`interop_chachapoly` never exercise this: they pin every
//! peer's address statically via `static_hosts` and always have the Rust
//! side initiate outward. That gap let a real protocol bug — nebula-protocol
//! sent lighthouse registration/query traffic as *plaintext*, which real
//! nebula silently drops without ever logging receipt — go undetected. This
//! test fails the same way that bug did: `host2.yml` (see `genconfig.sh`)
//! has no `static_host_map` entry for the rust-peer, so `ping` can only
//! succeed if host2 actually queried the real lighthouse for 10.100.0.3 and
//! got back the address this session registered. Requires Docker.
//!
//! Run with: cargo test --test interop_lighthouse_discovery -- --ignored --nocapture
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

/// Builds a valid ICMP echo reply for `request` (a full IP+ICMP echo
/// request, as delivered by `Session::recv`), preserving the original's
/// identifier/sequence/payload verbatim — real `ping` validates these match
/// before it counts a reply.
fn build_icmp_echo_reply(request: &[u8], reply_src: Ipv4Addr, reply_dst: Ipv4Addr) -> Vec<u8> {
    let mut icmp = request[20..].to_vec();
    icmp[0] = 0; // type: echo reply
    icmp[2] = 0;
    icmp[3] = 0; // checksum placeholder
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
    ip.extend_from_slice(&reply_src.octets());
    ip.extend_from_slice(&reply_dst.octets());
    let ip_cksum = checksum(&ip);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    ip.extend_from_slice(&icmp);
    ip
}

#[tokio::test]
#[ignore]
async fn real_host_discovers_and_pings_us_via_lighthouse_registration() {
    let harness = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/interop/docker");
    let status = Command::new("bash")
        .arg("run.sh")
        .env("CIPHER", "aes")
        .current_dir(&harness)
        .status()
        .expect("failed to invoke run.sh");
    assert!(status.success(), "docker interop harness failed to start");

    let build = harness.join("build");
    let lighthouse = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 1));
    let rust_peer = Ipv4Addr::new(10, 100, 0, 3);
    let host2 = Ipv4Addr::new(10, 100, 0, 2);

    // Deliberately the *only* address given: this test is entirely about
    // whether a real Go host can find *us* through the lighthouse, so we
    // give ourselves nothing but the lighthouse's own address (required —
    // exactly like real nebula, a lighthouse's address can't itself be
    // lighthouse-discovered) and never reach out to host2 ourselves.
    let session = Session::new(SessionConfig {
        ca_cert_pem: std::fs::read(build.join("ca.crt")).unwrap(),
        host_cert_pem: std::fs::read(build.join("rust-peer.crt")).unwrap(),
        host_key_pem: std::fs::read(build.join("rust-peer.key")).unwrap(),
        cipher: Cipher::AesGcm,
        bind_addr: "127.0.0.1:0".parse().unwrap(),
        lighthouses: vec![lighthouse],
        static_hosts: vec![(lighthouse, "127.0.0.1:4242".parse::<SocketAddr>().unwrap())],
    })
    .await
    .expect("session should start and register with the real lighthouse");

    let responder = tokio::spawn(async move {
        let (from, request) = tokio::time::timeout(Duration::from_secs(8), session.recv())
            .await
            .expect("should receive an ICMP echo request from host2 within 8s")
            .expect("recv should succeed");
        assert_eq!(from, IpAddr::V4(host2));
        assert!(
            request.len() >= 21,
            "request too short to be an IP+ICMP packet: {} bytes",
            request.len()
        );
        assert_eq!(
            request[20], 8,
            "expected ICMP type 8 (echo request), got {}",
            request[20]
        );

        let reply = build_icmp_echo_reply(&request, rust_peer, host2);
        session
            .send(from, &reply)
            .await
            .expect("echo reply send should succeed");
    });

    // `docker exec ... ping` blocks the calling OS thread; run it on the
    // blocking pool so the responder task above keeps polling concurrently.
    let ping_status = tokio::task::spawn_blocking(|| {
        Command::new("docker")
            .args([
                "exec",
                "nebula-protocol-interop-host2",
                "ping",
                "-c1",
                "-W5",
                "10.100.0.3",
            ])
            .status()
    })
    .await
    .expect("spawn_blocking should not panic")
    .expect("docker exec ping should run");

    // Check the responder's own outcome first — if discovery or the
    // handshake failed, its panic message is far more specific than "ping
    // failed" (e.g. it names exactly which assertion about the request broke).
    responder.await.expect("responder task should not panic");

    Command::new("bash")
        .arg("cleanup.sh")
        .current_dir(&harness)
        .status()
        .ok();

    assert!(
        ping_status.success(),
        "host2 should discover and reach the Rust peer purely via lighthouse registration"
    );
}
