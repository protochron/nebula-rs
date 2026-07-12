//! Convert a `nebula_protocol::session::PeerInfo` (verified cert identity)
//! into the `nebula_firewall::PeerIdentity` the firewall evaluates against.

use ipnet::IpNet;
use nebula_firewall::PeerIdentity;
use nebula_protocol::cert::der::Network;
use nebula_protocol::session::PeerInfo;

/// A cert network as a firewall `IpNet`, preserving its full prefix.
fn to_ipnet(n: &Network) -> IpNet {
    IpNet::new(n.addr, n.prefix_len).expect("cert prefix_len is a valid prefix length")
}

/// A cert network collapsed to an exact host route (`addr/32` or
/// `addr/128`), matching how the firewall's `PeerIdentity::owns` treats
/// `vpn_networks` (exact match on the peer's own address).
fn to_host_route(n: &Network) -> IpNet {
    IpNet::new(n.addr, max_prefix_len(n.addr)).expect("host prefix length is valid")
}

fn max_prefix_len(addr: std::net::IpAddr) -> u8 {
    match addr {
        std::net::IpAddr::V4(_) => 32,
        std::net::IpAddr::V6(_) => 128,
    }
}

pub fn peer_identity(info: &PeerInfo, ca_name: &str, ca_sha: &str) -> PeerIdentity {
    PeerIdentity {
        name: info.name.clone(),
        groups: info.groups.iter().cloned().collect(),
        ca_name: ca_name.to_string(),
        ca_sha: ca_sha.to_string(),
        vpn_networks: info.networks.iter().map(to_host_route).collect(),
        unsafe_networks: info.unsafe_networks.iter().map(to_ipnet).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn net(addr: &str, prefix_len: u8) -> Network {
        Network { addr: addr.parse::<IpAddr>().unwrap(), prefix_len }
    }

    #[test]
    fn vpn_networks_become_host_routes_and_unsafe_keep_prefix() {
        let info = PeerInfo {
            name: "host-a".into(),
            groups: vec!["test".into(), "host".into()],
            networks: vec![net("10.100.0.3", 16)],
            unsafe_networks: vec![net("192.168.9.0", 24)],
        };
        let id = peer_identity(&info, "my-ca", "deadbeef");

        assert_eq!(id.name, "host-a");
        assert!(id.groups.contains("test") && id.groups.contains("host"));
        assert_eq!(id.ca_name, "my-ca");
        assert_eq!(id.ca_sha, "deadbeef");
        // /16 cert network → /32 host route (exact-match ownership).
        assert_eq!(id.vpn_networks, vec!["10.100.0.3/32".parse::<IpNet>().unwrap()]);
        // unsafe network keeps its full prefix.
        assert_eq!(id.unsafe_networks, vec!["192.168.9.0/24".parse::<IpNet>().unwrap()]);
        // The firewall's ownership check reflects the host-route semantics.
        assert!(id.owns("10.100.0.3".parse().unwrap()));
        assert!(!id.owns("10.100.0.4".parse().unwrap()));
        assert!(id.owns("192.168.9.42".parse().unwrap()));
    }

    #[test]
    fn ipv6_networks_convert_to_128_host_routes() {
        let info = PeerInfo {
            name: "host6".into(),
            groups: vec![],
            networks: vec![net("fd00::3", 64)],
            unsafe_networks: vec![net("fd99::", 64)],
        };
        let id = peer_identity(&info, "ca", "sha");
        assert_eq!(id.vpn_networks, vec!["fd00::3/128".parse::<IpNet>().unwrap()]);
        assert_eq!(id.unsafe_networks, vec!["fd99::/64".parse::<IpNet>().unwrap()]);
        assert!(id.owns("fd00::3".parse().unwrap()));
        assert!(!id.owns("fd00::4".parse().unwrap()));
    }
}
