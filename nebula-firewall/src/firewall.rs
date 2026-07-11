use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use ipnet::IpNet;

use crate::conntrack::Conntrack;
use crate::identity::PeerIdentity;
use crate::packet::{Packet, Protocol};
use crate::rule::RuleSet;

#[derive(Clone, Debug)]
pub struct FirewallOptions {
    pub tcp_timeout: Duration,
    pub udp_timeout: Duration,
    pub default_timeout: Duration,
    pub in_send_reject: bool,
    pub out_send_reject: bool,
    pub default_local_cidr_any: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, thiserror::Error)]
pub enum DropReason {
    #[error("local address is not in list of handled local addresses")]
    InvalidLocalIp,
    #[error("remote address is not in remote certificate networks")]
    InvalidRemoteIp,
    #[error("no matching rule in firewall table")]
    NoMatchingRule,
}

struct VersionedRules {
    version: u16,
    rules: Arc<RuleSet>,
}

pub struct Firewall {
    rules: RwLock<VersionedRules>,
    conntrack: Mutex<Conntrack>,
    options: FirewallOptions,
    routable_networks: Vec<IpNet>,
}

impl Firewall {
    pub fn new(
        rules: RuleSet,
        options: FirewallOptions,
        assigned_networks: Vec<IpNet>,
        unsafe_networks: Vec<IpNet>,
    ) -> Self {
        // Mirror Go's NewFirewall: assigned networks become *host routes*
        // (`addr/max_prefix_len`) so the local-address check is an exact
        // match on our own address, while unsafe networks keep their full
        // prefix and match by prefix. Do NOT prefix-match assigned_networks
        // directly -- an assigned `1.1.1.1/8` must make only `1.1.1.1`
        // routable, not all of `1.0.0.0/8`
        // (see TestFirewall_Drop_EnforceIPMatch's "allow inbound local
        // matching" case and the design doc's Data Flow step 3).
        let mut routable_networks: Vec<IpNet> = assigned_networks
            .iter()
            .map(|n| {
                IpNet::new(n.addr(), n.max_prefix_len())
                    .expect("max_prefix_len is a valid prefix length")
            })
            .collect();
        routable_networks.extend(unsafe_networks);

        Self {
            rules: RwLock::new(VersionedRules {
                version: 0,
                rules: Arc::new(rules),
            }),
            conntrack: Mutex::new(Conntrack::new()),
            options,
            routable_networks,
        }
    }

    /// Swaps in a new ruleset. Existing conntrack entries are never
    /// touched here — they're revalidated lazily against the new ruleset
    /// the next time a packet for that flow arrives (see `evaluate`),
    /// matching Go's own hot-reload behavior.
    pub fn reload(&self, rules: RuleSet) {
        let mut guard = self.rules.write().unwrap();
        guard.version = guard.version.wrapping_add(1);
        guard.rules = Arc::new(rules);
    }

    pub fn options(&self) -> &FirewallOptions {
        &self.options
    }

    pub fn evaluate(
        &self,
        packet: Packet,
        incoming: bool,
        remote: &PeerIdentity,
    ) -> Result<(), DropReason> {
        let now = Instant::now();
        let (version, rules) = {
            let guard = self.rules.read().unwrap();
            (guard.version, Arc::clone(&guard.rules))
        };

        {
            let mut conntrack = self.conntrack.lock().unwrap();
            if let Some((conn_incoming, conn_version)) = conntrack.get(&packet, now) {
                if conn_version == version {
                    conntrack.record(
                        packet,
                        conn_incoming,
                        version,
                        now,
                        self.timeout_for(packet.protocol),
                    );
                    return Ok(());
                }
                if rules.matches(&packet, conn_incoming, remote) {
                    conntrack.record(
                        packet,
                        conn_incoming,
                        version,
                        now,
                        self.timeout_for(packet.protocol),
                    );
                    return Ok(());
                }
                conntrack.remove(&packet);
            }
        }

        // Order matches Go's Drop(): remote/certificate check first, then
        // the local routable-address check.
        if !remote.owns(packet.remote_addr) {
            return Err(DropReason::InvalidRemoteIp);
        }

        if !self
            .routable_networks
            .iter()
            .any(|n| n.contains(&packet.local_addr))
        {
            return Err(DropReason::InvalidLocalIp);
        }

        if !rules.matches(&packet, incoming, remote) {
            return Err(DropReason::NoMatchingRule);
        }

        self.conntrack.lock().unwrap().record(
            packet,
            incoming,
            version,
            now,
            self.timeout_for(packet.protocol),
        );
        Ok(())
    }

    fn timeout_for(&self, protocol: Protocol) -> Duration {
        match protocol {
            Protocol::Tcp => self.options.tcp_timeout,
            Protocol::Udp => self.options.udp_timeout,
            _ => self.options.default_timeout,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rule::{LocalCidrSpec, PortSpec, RuleSetBuilder};

    fn options() -> FirewallOptions {
        FirewallOptions {
            tcp_timeout: Duration::from_secs(1),
            udp_timeout: Duration::from_secs(60),
            default_timeout: Duration::from_secs(600),
            in_send_reject: false,
            out_send_reject: false,
            default_local_cidr_any: false,
        }
    }

    fn packet() -> Packet {
        Packet {
            local_addr: "1.2.3.4".parse().unwrap(),
            remote_addr: "1.2.3.4".parse().unwrap(),
            local_port: 10,
            remote_port: 90,
            protocol: Protocol::Udp,
            fragment: false,
        }
    }

    fn remote() -> PeerIdentity {
        PeerIdentity {
            name: "host1".into(),
            groups: ["default-group".to_string()].into(),
            vpn_networks: vec!["1.2.3.4/32".parse().unwrap()],
            ..Default::default()
        }
    }

    fn allow_any_firewall() -> Firewall {
        let mut b = RuleSetBuilder::new(vec!["1.2.3.4/32".parse().unwrap()], false, false);
        b.add_rule(
            true,
            Protocol::Any,
            PortSpec::Any,
            vec!["any".into()],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        Firewall::new(
            b.build(),
            options(),
            vec!["1.2.3.4/32".parse().unwrap()],
            vec![],
        )
    }

    #[test]
    fn drops_outbound_when_only_an_inbound_rule_exists() {
        let fw = allow_any_firewall();
        assert_eq!(
            fw.evaluate(packet(), false, &remote()),
            Err(DropReason::NoMatchingRule)
        );
    }

    #[test]
    fn allows_inbound_matching_the_any_rule() {
        let fw = allow_any_firewall();
        assert_eq!(fw.evaluate(packet(), true, &remote()), Ok(()));
    }

    #[test]
    fn conntrack_lets_the_return_leg_through_without_a_matching_outbound_rule() {
        let fw = allow_any_firewall();
        fw.evaluate(packet(), true, &remote()).unwrap();
        assert_eq!(fw.evaluate(packet(), false, &remote()), Ok(()));
    }

    #[test]
    fn rejects_when_local_addr_is_not_routable() {
        let fw = allow_any_firewall();
        let mut p = packet();
        p.local_addr = "9.9.9.9".parse().unwrap();
        assert_eq!(
            fw.evaluate(p, true, &remote()),
            Err(DropReason::InvalidLocalIp)
        );
    }

    #[test]
    fn rejects_when_remote_addr_is_not_owned_by_the_identity() {
        let fw = allow_any_firewall();
        let mut p = packet();
        p.remote_addr = "1.2.3.10".parse().unwrap();
        assert_eq!(
            fw.evaluate(p, true, &remote()),
            Err(DropReason::InvalidRemoteIp)
        );
    }

    #[test]
    fn assigned_network_wider_than_a_host_is_only_routable_at_its_exact_address() {
        // Go stores routableNetworks as host routes, so a local address
        // inside an assigned prefix but not equal to the assigned address is
        // InvalidLocalIp -- TestFirewall_Drop_EnforceIPMatch "allow inbound
        // local matching". Exercised here over IPv6, the primary consumer's
        // focus: assigned fd00::1/8, only fd00::1 itself is routable.
        let assigned = vec!["fd00::1/8".parse().unwrap()];
        let mut b = RuleSetBuilder::new(assigned.clone(), false, false);
        b.add_rule(
            true,
            Protocol::Any,
            PortSpec::Any,
            vec!["any".into()],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        let fw = Firewall::new(b.build(), options(), assigned, vec![]);

        let remote = PeerIdentity {
            name: "host1".into(),
            groups: ["default-group".to_string()].into(),
            vpn_networks: vec!["2222::2/128".parse().unwrap()],
            ..Default::default()
        };

        let on_host = Packet {
            local_addr: "fd00::1".parse().unwrap(),
            remote_addr: "2222::2".parse().unwrap(),
            local_port: 10,
            remote_port: 90,
            protocol: Protocol::Udp,
            fragment: false,
        };
        assert_eq!(
            fw.evaluate(on_host, true, &remote),
            Ok(()),
            "exact assigned address is routable"
        );

        let off_host = Packet {
            local_addr: "fd12::34".parse().unwrap(),
            remote_addr: "2222::2".parse().unwrap(),
            local_port: 10,
            remote_port: 90,
            protocol: Protocol::Udp,
            fragment: false,
        };
        assert_eq!(
            fw.evaluate(off_host, true, &remote),
            Err(DropReason::InvalidLocalIp),
            "another address inside the /8 is not"
        );
    }

    #[test]
    fn allows_inbound_over_ipv6_including_icmpv6() {
        // ICMPv6 shares the icmp table; exercise a v6 allow end-to-end.
        let assigned = vec!["fd12::34/128".parse().unwrap()];
        let mut b = RuleSetBuilder::new(assigned.clone(), false, false);
        b.add_rule(
            true,
            Protocol::IcmpV6,
            PortSpec::Any,
            vec!["any".into()],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        let fw = Firewall::new(b.build(), options(), assigned, vec![]);

        let remote = PeerIdentity {
            name: "host1".into(),
            groups: ["default-group".to_string()].into(),
            vpn_networks: vec!["fd12::34/128".parse().unwrap()],
            ..Default::default()
        };
        let p = Packet {
            local_addr: "fd12::34".parse().unwrap(),
            remote_addr: "fd12::34".parse().unwrap(),
            local_port: 0,
            remote_port: 0,
            protocol: Protocol::IcmpV6,
            fragment: false,
        };
        assert_eq!(fw.evaluate(p, true, &remote), Ok(()));
    }

    #[test]
    fn reload_invalidates_a_conntracked_flow_that_no_longer_matches() {
        let mut b = RuleSetBuilder::new(vec!["1.2.3.4/32".parse().unwrap()], false, false);
        b.add_rule(
            true,
            Protocol::Any,
            PortSpec::Any,
            vec!["any".into()],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        let fw = Firewall::new(
            b.build(),
            options(),
            vec!["1.2.3.4/32".parse().unwrap()],
            vec![],
        );

        fw.evaluate(packet(), true, &remote()).unwrap();
        assert_eq!(
            fw.evaluate(packet(), false, &remote()),
            Ok(()),
            "outbound passes via conntrack before reload"
        );

        let mut b2 = RuleSetBuilder::new(vec!["1.2.3.4/32".parse().unwrap()], false, false);
        b2.add_rule(
            true,
            Protocol::Any,
            PortSpec::Single(11),
            vec!["any".into()],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        fw.reload(b2.build());

        assert_eq!(
            fw.evaluate(packet(), false, &remote()),
            Err(DropReason::NoMatchingRule),
            "port 10 no longer matches the reloaded ruleset"
        );
    }

    #[test]
    fn options_are_readable_by_the_consumer() {
        let fw = allow_any_firewall();
        assert!(!fw.options().in_send_reject);
    }
}
