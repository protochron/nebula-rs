//! Thin Nebula node: builds an allow-any listener from environment config
//! and runs it. Intended to be launched inside a network namespace
//! (`ip netns exec … node`) — the tun and UDP socket it creates are then
//! netns-scoped, and a multi-threaded runtime is fine because every thread
//! inherits the netns.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use ipnet::IpNet;
use nebula_firewall::{
    FirewallOptions, LocalCidrSpec, PortSpec, Protocol, RuleSet, RuleSetBuilder,
};
use nebula_protocol::handshake::Cipher;
use nebula_protocol::session::{Session, SessionConfig};

use nebula_listener::{Listener, ListenerConfig, tun};

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("missing required env var {key}"))
}

fn allow_any(assigned: Vec<IpNet>) -> RuleSet {
    let mut b = RuleSetBuilder::new(assigned, false, true);
    for incoming in [true, false] {
        b.add_rule(
            incoming,
            Protocol::Any,
            PortSpec::Any,
            vec![],
            None,
            None,
            LocalCidrSpec::Any,
            None,
            None,
        )
        .expect("allow-any rule is valid");
    }
    b.build()
}

fn parse_hosts(raw: &str) -> Vec<(IpAddr, SocketAddr)> {
    raw.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|entry| {
            let (ip, sock) = entry
                .split_once('=')
                .expect("static host must be vpn_ip=host:port");
            (
                ip.trim().parse().expect("valid vpn ip"),
                sock.trim().parse().expect("valid socket addr"),
            )
        })
        .collect()
}

/// Lighthouses are configured by VPN address — their reachable UDP address
/// comes from `NEBULA_STATIC_HOSTS` below, exactly like any other peer,
/// since lighthouse traffic is only ever sent over an authenticated tunnel.
fn parse_lighthouses(raw: &str) -> Vec<IpAddr> {
    raw.split(',')
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.trim().parse().expect("valid lighthouse vpn addr"))
        .collect()
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cipher = match std::env::var("NEBULA_CIPHER").as_deref().unwrap_or("aes") {
        "chachapoly" => Cipher::ChaChaPoly,
        _ => Cipher::AesGcm,
    };
    let tun_addr: IpNet = env("NEBULA_TUN_ADDR").parse().expect("valid tun cidr");
    let assigned: Vec<IpNet> = vec![tun_addr];

    // Create the tun and bind the UDP socket in *this* (netns) context.
    let tun_fd = tun::create(&env("NEBULA_TUN_NAME"), tun_addr, 1300)?;
    let udp = std::net::UdpSocket::bind(
        env("NEBULA_BIND")
            .parse::<SocketAddr>()
            .expect("valid bind addr"),
    )?;

    let session = Session::from_socket(
        SessionConfig {
            ca_cert_pem: std::fs::read(env("NEBULA_CA"))?,
            host_cert_pem: std::fs::read(env("NEBULA_CERT"))?,
            host_key_pem: std::fs::read(env("NEBULA_KEY"))?,
            cipher,
            bind_addr: "0.0.0.0:0".parse().unwrap(), // unused on the injected path
            lighthouses: parse_lighthouses(
                &std::env::var("NEBULA_LIGHTHOUSES").unwrap_or_default(),
            ),
            static_hosts: parse_hosts(&std::env::var("NEBULA_STATIC_HOSTS").unwrap_or_default()),
        },
        udp,
    )
    .await
    .map_err(io_other)?;

    let listener = Listener::new(
        ListenerConfig {
            firewall_rules: allow_any(assigned.clone()),
            firewall_options: FirewallOptions {
                tcp_timeout: Duration::from_secs(120),
                udp_timeout: Duration::from_secs(60),
                default_timeout: Duration::from_secs(60),
                in_send_reject: false,
                out_send_reject: false,
                default_local_cidr_any: true,
            },
            assigned_networks: assigned,
            unsafe_networks: vec![],
            ca_name: std::env::var("NEBULA_CA_NAME").unwrap_or_default(),
            ca_sha: String::new(),
        },
        session,
        tun_fd,
    )?;

    eprintln!("nebula-listener node up on tun {}", env("NEBULA_TUN_NAME"));
    listener.run().await
}

fn io_other(e: nebula_protocol::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}
