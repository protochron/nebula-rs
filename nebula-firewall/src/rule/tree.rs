use std::collections::HashMap;

use ipnet::IpNet;

use crate::identity::PeerIdentity;
use crate::packet::{Packet, Protocol};

pub(crate) const PORT_ANY: i32 = 0;
pub(crate) const PORT_FRAGMENT: i32 = -1;

#[derive(Default, Debug)]
pub(crate) struct LocalCidr {
    pub(crate) any: bool,
    pub(crate) nets: Vec<IpNet>,
}

#[derive(Default, Debug)]
pub(crate) struct PeerRule {
    pub(crate) any: Option<LocalCidr>,
    pub(crate) hosts: HashMap<String, LocalCidr>,
    pub(crate) groups: Vec<(Vec<String>, LocalCidr)>,
    pub(crate) cidrs: Vec<(IpNet, LocalCidr)>,
}

#[derive(Default, Debug)]
pub(crate) struct CaRule {
    pub(crate) any: Option<PeerRule>,
    pub(crate) ca_names: HashMap<String, PeerRule>,
    pub(crate) ca_shas: HashMap<String, PeerRule>,
}

pub(crate) type PortTable = HashMap<i32, CaRule>;

#[derive(Default, Debug)]
pub(crate) struct Direction {
    pub(crate) tcp: PortTable,
    pub(crate) udp: PortTable,
    pub(crate) icmp: PortTable,
    pub(crate) any_proto: PortTable,
}

#[derive(Default, Debug)]
pub struct RuleSet {
    pub(crate) inbound: Direction,
    pub(crate) outbound: Direction,
}

impl LocalCidr {
    pub(crate) fn matches(&self, packet: &Packet) -> bool {
        if self.any {
            return true;
        }
        self.nets.iter().any(|n| n.contains(&packet.local_addr))
    }
}

impl PeerRule {
    pub(crate) fn matches(&self, packet: &Packet, remote: &PeerIdentity) -> bool {
        if let Some(any) = &self.any
            && any.matches(packet)
        {
            return true;
        }

        for (groups, local_cidr) in &self.groups {
            if groups.iter().all(|g| remote.groups.contains(g)) && local_cidr.matches(packet) {
                return true;
            }
        }

        if let Some(local_cidr) = self.hosts.get(&remote.name)
            && local_cidr.matches(packet)
        {
            return true;
        }

        for (net, local_cidr) in &self.cidrs {
            if net.contains(&packet.remote_addr) && local_cidr.matches(packet) {
                return true;
            }
        }

        false
    }
}

impl CaRule {
    pub(crate) fn matches(&self, packet: &Packet, remote: &PeerIdentity) -> bool {
        if let Some(any) = &self.any
            && any.matches(packet, remote)
        {
            return true;
        }
        if let Some(r) = self.ca_shas.get(&remote.ca_sha)
            && r.matches(packet, remote)
        {
            return true;
        }
        if let Some(r) = self.ca_names.get(&remote.ca_name)
            && r.matches(packet, remote)
        {
            return true;
        }
        false
    }
}

pub(crate) fn port_table_matches(
    table: &PortTable,
    packet: &Packet,
    incoming: bool,
    remote: &PeerIdentity,
) -> bool {
    let port = if packet.fragment {
        PORT_FRAGMENT
    } else if incoming {
        packet.local_port as i32
    } else {
        packet.remote_port as i32
    };

    if let Some(ca) = table.get(&port)
        && ca.matches(packet, remote)
    {
        return true;
    }
    if let Some(ca) = table.get(&PORT_ANY)
        && ca.matches(packet, remote)
    {
        return true;
    }
    false
}

impl Direction {
    pub(crate) fn matches(&self, packet: &Packet, incoming: bool, remote: &PeerIdentity) -> bool {
        if port_table_matches(&self.any_proto, packet, incoming, remote) {
            return true;
        }
        match packet.protocol {
            Protocol::Tcp => port_table_matches(&self.tcp, packet, incoming, remote),
            Protocol::Udp => port_table_matches(&self.udp, packet, incoming, remote),
            Protocol::Icmp | Protocol::IcmpV6 => {
                port_table_matches(&self.icmp, packet, incoming, remote)
            }
            Protocol::Any | Protocol::Other(_) => false,
        }
    }
}

impl RuleSet {
    pub(crate) fn matches(&self, packet: &Packet, incoming: bool, remote: &PeerIdentity) -> bool {
        let dir = if incoming {
            &self.inbound
        } else {
            &self.outbound
        };
        dir.matches(packet, incoming, remote)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    fn packet(
        local: &str,
        remote: &str,
        local_port: u16,
        remote_port: u16,
        protocol: Protocol,
        fragment: bool,
    ) -> Packet {
        Packet {
            local_addr: local.parse().unwrap(),
            remote_addr: remote.parse().unwrap(),
            local_port,
            remote_port,
            protocol,
            fragment,
        }
    }

    fn identity(name: &str, groups: &[&str], ca_name: &str, ca_sha: &str) -> PeerIdentity {
        PeerIdentity {
            name: name.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            ca_name: ca_name.into(),
            ca_sha: ca_sha.into(),
            ..Default::default()
        }
    }

    #[test]
    fn local_cidr_any_matches_every_local_address() {
        let lc = LocalCidr {
            any: true,
            nets: vec![],
        };
        let p = packet("9.9.9.9", "1.1.1.1", 1, 1, Protocol::Tcp, false);
        assert!(lc.matches(&p));
    }

    #[test]
    fn local_cidr_with_nets_matches_only_within_them() {
        let lc = LocalCidr {
            any: false,
            nets: vec!["10.0.0.0/24".parse().unwrap()],
        };
        assert!(lc.matches(&packet("10.0.0.5", "1.1.1.1", 1, 1, Protocol::Tcp, false)));
        assert!(!lc.matches(&packet("10.0.1.5", "1.1.1.1", 1, 1, Protocol::Tcp, false)));
    }

    #[test]
    fn peer_rule_groups_requires_all_groups_present_but_matches_across_entries() {
        // Mirrors firewall_test.go's TestFirewall_Drop2: a single group
        // entry requires ALL its groups (AND), but a peer missing one
        // group can still match a *different* groups entry (OR across
        // entries).
        let pr = PeerRule {
            groups: vec![
                (
                    vec!["default-group".into(), "test-group".into()],
                    LocalCidr {
                        any: true,
                        nets: vec![],
                    },
                ),
                (
                    vec!["admins".into()],
                    LocalCidr {
                        any: true,
                        nets: vec![],
                    },
                ),
            ],
            ..Default::default()
        };
        let p = packet("1.1.1.1", "2.2.2.2", 1, 1, Protocol::Tcp, false);

        let has_both = identity("h1", &["default-group", "test-group"], "", "");
        assert!(pr.matches(&p, &has_both));

        let missing_one = identity("h1", &["default-group"], "", "");
        assert!(!pr.matches(&p, &missing_one));

        let only_admin = identity("h1", &["admins"], "", "");
        assert!(pr.matches(&p, &only_admin));
    }

    #[test]
    fn peer_rule_host_and_cidr_are_independent_or_paths() {
        let pr = PeerRule {
            hosts: HashMap::from([(
                "db1".to_string(),
                LocalCidr {
                    any: true,
                    nets: vec![],
                },
            )]),
            cidrs: vec![(
                "172.16.0.0/16".parse().unwrap(),
                LocalCidr {
                    any: true,
                    nets: vec![],
                },
            )],
            ..Default::default()
        };
        let by_host = packet("1.1.1.1", "9.9.9.9", 1, 1, Protocol::Tcp, false);
        assert!(pr.matches(&by_host, &identity("db1", &[], "", "")));
        assert!(!pr.matches(&by_host, &identity("other-host", &[], "", "")));

        let by_cidr = packet("1.1.1.1", "172.16.5.5", 1, 1, Protocol::Tcp, false);
        assert!(pr.matches(&by_cidr, &identity("other-host", &[], "", "")));
    }

    #[test]
    fn ca_rule_any_ca_shas_and_ca_names_are_independent_buckets() {
        // Mirrors TestFirewall_Drop's "ensure signer doesn't get in the
        // way of group checks" / "caSha doesn't drop on match" pairs: a
        // rule scoped to one CA sha must not affect matching for a
        // differently-scoped rule on the same port.
        let matches_default_group = || PeerRule {
            groups: vec![(
                vec!["default-group".into()],
                LocalCidr {
                    any: true,
                    nets: vec![],
                },
            )],
            ..Default::default()
        };
        let ca = CaRule {
            any: None,
            ca_shas: HashMap::from([
                (
                    "signer-shasum-bad".to_string(),
                    PeerRule {
                        groups: vec![(
                            vec!["nope".into()],
                            LocalCidr {
                                any: true,
                                nets: vec![],
                            },
                        )],
                        ..Default::default()
                    },
                ),
                ("signer-shasum".to_string(), matches_default_group()),
            ]),
            ca_names: HashMap::new(),
        };
        let p = packet("1.1.1.1", "2.2.2.2", 1, 1, Protocol::Tcp, false);
        let remote = PeerIdentity {
            name: "host1".into(),
            groups: HashSet::from(["default-group".to_string()]),
            ca_sha: "signer-shasum".into(),
            ..Default::default()
        };
        assert!(ca.matches(&p, &remote));

        let remote_wrong_ca = PeerIdentity {
            ca_sha: "signer-shasum-bad-typo".into(),
            ..remote.clone()
        };
        assert!(!ca.matches(&p, &remote_wrong_ca));
    }

    #[test]
    fn port_table_selects_local_port_when_incoming_and_remote_port_when_outgoing() {
        let mut table: PortTable = HashMap::new();
        table.insert(
            10,
            CaRule {
                any: Some(PeerRule {
                    any: Some(LocalCidr {
                        any: true,
                        nets: vec![],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let p = packet("1.1.1.1", "2.2.2.2", 10, 99, Protocol::Tcp, false);
        let remote = identity("h", &[], "", "");
        assert!(
            port_table_matches(&table, &p, true, &remote),
            "incoming should match on local_port 10"
        );
        assert!(
            !port_table_matches(&table, &p, false, &remote),
            "outgoing should check remote_port 99, not 10"
        );
    }

    #[test]
    fn port_table_falls_back_to_port_any() {
        let mut table: PortTable = HashMap::new();
        table.insert(
            PORT_ANY,
            CaRule {
                any: Some(PeerRule {
                    any: Some(LocalCidr {
                        any: true,
                        nets: vec![],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let p = packet("1.1.1.1", "2.2.2.2", 12345, 1, Protocol::Tcp, false);
        assert!(port_table_matches(
            &table,
            &p,
            true,
            &identity("h", &[], "", "")
        ));
    }

    #[test]
    fn port_table_uses_port_fragment_for_fragments_regardless_of_actual_port() {
        let mut table: PortTable = HashMap::new();
        table.insert(
            PORT_FRAGMENT,
            CaRule {
                any: Some(PeerRule {
                    any: Some(LocalCidr {
                        any: true,
                        nets: vec![],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let p = packet("1.1.1.1", "2.2.2.2", 10, 90, Protocol::Tcp, true);
        assert!(port_table_matches(
            &table,
            &p,
            true,
            &identity("h", &[], "", "")
        ));
    }

    #[test]
    fn direction_checks_any_proto_before_the_protocol_specific_table() {
        let mut dir = Direction::default();
        dir.any_proto.insert(
            PORT_ANY,
            CaRule {
                any: Some(PeerRule {
                    any: Some(LocalCidr {
                        any: true,
                        nets: vec![],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let udp_packet = packet("1.1.1.1", "2.2.2.2", 1, 1, Protocol::Udp, false);
        assert!(dir.matches(&udp_packet, true, &identity("h", &[], "", "")));
    }

    #[test]
    fn direction_rejects_protocol_other_unless_any_proto_matches() {
        let dir = Direction::default();
        let sctp_packet = packet("1.1.1.1", "2.2.2.2", 1, 1, Protocol::Other(132), false);
        assert!(!dir.matches(&sctp_packet, true, &identity("h", &[], "", "")));
    }

    #[test]
    fn direction_routes_icmpv6_to_the_icmp_table() {
        // ICMPv6 packets use the icmp table, mirroring Go's
        // `ProtoICMP, ProtoICMPv6` sharing a case.
        let mut dir = Direction::default();
        dir.icmp.insert(
            PORT_ANY,
            CaRule {
                any: Some(PeerRule {
                    any: Some(LocalCidr {
                        any: true,
                        nets: vec![],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );
        let v6 = packet("fd00::1", "fd00::2", 1, 1, Protocol::IcmpV6, false);
        assert!(dir.matches(&v6, true, &identity("h", &[], "", "")));
    }

    #[test]
    fn peer_cidr_and_local_cidr_match_ipv6() {
        // Remote-CIDR and local_cidr containment over IPv6 (the primary
        // consumer's focus): both the remote and local address must fall in
        // their respective v6 prefixes.
        let pr = PeerRule {
            cidrs: vec![(
                "fd00::/64".parse().unwrap(),
                LocalCidr {
                    any: false,
                    nets: vec!["fd12::/64".parse().unwrap()],
                },
            )],
            ..Default::default()
        };
        let h = identity("h", &[], "", "");
        assert!(
            pr.matches(
                &packet("fd12::5", "fd00::9", 1, 1, Protocol::Tcp, false),
                &h
            ),
            "remote in cidr AND local in local_cidr"
        );
        assert!(
            !pr.matches(
                &packet("fd99::5", "fd00::9", 1, 1, Protocol::Tcp, false),
                &h
            ),
            "local outside local_cidr"
        );
        assert!(
            !pr.matches(
                &packet("fd12::5", "fd99::9", 1, 1, Protocol::Tcp, false),
                &h
            ),
            "remote outside cidr"
        );
    }

    #[test]
    fn ruleset_selects_inbound_or_outbound_by_direction() {
        let mut rules = RuleSet::default();
        rules.inbound.any_proto.insert(
            PORT_ANY,
            CaRule {
                any: Some(PeerRule {
                    any: Some(LocalCidr {
                        any: true,
                        nets: vec![],
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        );

        let p = packet("1.1.1.1", "2.2.2.2", 1, 1, Protocol::Tcp, false);
        let remote = identity("h", &[], "", "");
        assert!(rules.matches(&p, true, &remote));
        assert!(!rules.matches(&p, false, &remote));
    }
}
