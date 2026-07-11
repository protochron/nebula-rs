use std::collections::HashSet;
use std::net::IpAddr;

use ipnet::IpNet;

/// Everything nebula's `CachedCertificate` + CA trust-chain resolution
/// would have told the firewall about a peer, flattened into plain data.
/// The consumer builds one of these per peer (typically once, at handshake
/// completion) from a verified certificate — see the design doc's
/// "Dependency on nebula-protocol" non-goal for why this crate doesn't
/// take a certificate type directly.
#[derive(Clone, Debug, Default)]
pub struct PeerIdentity {
    pub name: String,
    pub groups: HashSet<String>,
    pub ca_name: String,
    pub ca_sha: String,
    pub vpn_networks: Vec<IpNet>,
    pub unsafe_networks: Vec<IpNet>,
}

impl PeerIdentity {
    /// True if `addr` is one of this peer's own assigned VPN addresses, or
    /// falls under one of its advertised unsafe-network routes.
    pub fn owns(&self, addr: IpAddr) -> bool {
        self.vpn_networks.iter().any(|n| n.contains(&addr))
            || self.unsafe_networks.iter().any(|n| n.contains(&addr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> PeerIdentity {
        PeerIdentity {
            name: "host1".into(),
            vpn_networks: vec!["10.0.0.5/32".parse().unwrap()],
            unsafe_networks: vec!["192.168.1.0/24".parse().unwrap()],
            ..Default::default()
        }
    }

    #[test]
    fn owns_its_exact_vpn_address() {
        assert!(identity().owns("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn does_not_own_a_different_address_in_the_same_vpn_prefix() {
        // vpn_networks entries are host prefixes (/32), not subnets.
        assert!(!identity().owns("10.0.0.6".parse().unwrap()));
    }

    #[test]
    fn owns_any_address_within_its_unsafe_network() {
        assert!(identity().owns("192.168.1.200".parse().unwrap()));
    }

    #[test]
    fn does_not_own_an_unrelated_address() {
        assert!(!identity().owns("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn owns_ipv6_vpn_and_unsafe_networks() {
        // The primary consumer is IPv6-focused; owns() must handle v6 host
        // routes and unsafe prefixes the same way it does v4.
        let id = PeerIdentity {
            name: "host6".into(),
            vpn_networks: vec!["fd12::34/128".parse().unwrap()],
            unsafe_networks: vec!["fd99::/64".parse().unwrap()],
            ..Default::default()
        };
        assert!(id.owns("fd12::34".parse().unwrap()), "exact v6 vpn address");
        assert!(
            !id.owns("fd12::35".parse().unwrap()),
            "different v6 host is not owned"
        );
        assert!(
            id.owns("fd99::abcd".parse().unwrap()),
            "address within v6 unsafe network"
        );
        assert!(!id.owns("fd00::1".parse().unwrap()), "unrelated v6 address");
    }
}
