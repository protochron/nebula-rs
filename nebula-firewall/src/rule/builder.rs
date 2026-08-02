use ipnet::IpNet;

use super::tree::{
    CaRule, Direction, LocalCidr, PORT_ANY, PORT_FRAGMENT, PeerRule, PortTable, RuleSet,
};
use crate::packet::Protocol;

/// Port selector for a rule. Go's config layer has separate `port`/`code`
/// fields that both parse to the same start/end range; this typed API
/// doesn't need that distinction since there's no config-string layer to
/// spell them differently.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PortSpec {
    Any,
    Fragment,
    Single(u16),
    Range(u16, u16),
}

/// `local_cidr` selector for a rule. Unlike `cidr`, "unset" and explicit
/// `Any` are not equivalent here — see [`RuleSetBuilder::new`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalCidrSpec {
    Unset,
    Any,
    Net(IpNet),
}

#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum RuleError {
    #[error("unknown protocol: {0:?}")]
    UnknownProtocol(Protocol),
    #[error("start port {start} was higher than end port {end}")]
    InvalidPortRange { start: u16, end: u16 },
}

/// Advisory warnings mirroring Go's `rule.sanity()` — a rule where `"any"`
/// in one field silently shadows another field the caller also specified.
/// These never block [`RuleSetBuilder::build`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleWarning {
    GroupsShadowedByAny { incoming: bool },
    HostAnyShadowsGroups { incoming: bool, groups: Vec<String> },
    HostAnyShadowsCidr { incoming: bool, cidr: IpNet },
    GroupsAnyShadowsHost { incoming: bool, host: String },
    GroupsAnyShadowsCidr { incoming: bool, cidr: IpNet },
    /// A port was given on an ICMP/ICMPv6 rule. ICMP has no ports, so the
    /// rule is filed under `PortSpec::Any` instead of the requested port —
    /// otherwise it could never match. Mirrors Go's "ignoring port
    /// specification for ICMP firewall rule" warning.
    IcmpPortIgnored { incoming: bool, port: PortSpec },
}

enum LocalCidrDefault {
    Any,
    Nets(Vec<IpNet>),
}

/// Incrementally builds a [`RuleSet`].
pub struct RuleSetBuilder {
    inbound: Direction,
    outbound: Direction,
    default_local_cidr: LocalCidrDefault,
    warnings: Vec<RuleWarning>,
}

impl RuleSetBuilder {
    /// `assigned_networks` and `has_unsafe_networks` should match the
    /// values later passed to `Firewall::new` for the same mesh identity
    /// — they control what an *omitted* `local_cidr` defaults to:
    /// unconditional `Any` unless this identity has unsafe networks and
    /// `default_local_cidr_any` is false, in which case it falls back to
    /// matching only `assigned_networks`. Here the **full** prefixes are
    /// used (a prefix match, mirroring Go's `f.assignedNetworks`), which is
    /// deliberately *different* from `Firewall::new`'s local-address check,
    /// where the same networks are collapsed to host routes for an exact
    /// match. See the design doc's "Local CIDR defaulting" note.
    pub fn new(
        assigned_networks: Vec<IpNet>,
        has_unsafe_networks: bool,
        default_local_cidr_any: bool,
    ) -> Self {
        let default_local_cidr = if !has_unsafe_networks || default_local_cidr_any {
            LocalCidrDefault::Any
        } else {
            LocalCidrDefault::Nets(assigned_networks)
        };

        Self {
            inbound: Direction::default(),
            outbound: Direction::default(),
            default_local_cidr,
            warnings: Vec::new(),
        }
    }

    // The parameter list deliberately mirrors Go's low-level
    // `Firewall.AddRule` field-for-field (see the design doc); introducing
    // a wrapper struct here would diverge from the ported API this crate
    // is matching.
    #[allow(clippy::too_many_arguments)]
    pub fn add_rule(
        &mut self,
        incoming: bool,
        proto: Protocol,
        port: PortSpec,
        groups: Vec<String>,
        host: Option<String>,
        cidr: Option<IpNet>,
        local_cidr: LocalCidrSpec,
        ca_name: Option<String>,
        ca_sha: Option<String>,
    ) -> Result<(), RuleError> {
        let (mut start, mut end) = port_bounds(port)?;

        if matches!(proto, Protocol::Other(_)) {
            return Err(RuleError::UnknownProtocol(proto));
        }

        // ICMP has no ports. `packet::parse` reports ICMP `local_port` as 0
        // and `remote_port` as the echo identifier, so a rule filed under a
        // requested port could never be reached — inbound lookups would miss
        // on 0 and outbound lookups would miss on every identifier but one.
        // Coerce to `PORT_ANY` and warn, matching Go's AddRule (#1609).
        //
        // Unlike Go we coerce *after* `port_bounds`, so an inverted range on
        // an ICMP rule still surfaces as `InvalidPortRange` rather than being
        // silently swallowed — the port is meaningless either way, but an
        // inverted range is a typo worth reporting.
        if matches!(proto, Protocol::Icmp | Protocol::IcmpV6) && port != PortSpec::Any {
            self.warnings
                .push(RuleWarning::IcmpPortIgnored { incoming, port });
            start = PORT_ANY;
            end = PORT_ANY;
        }

        self.check_sanity(incoming, &groups, &host, &cidr);

        let dir = direction_mut(&mut self.inbound, &mut self.outbound, incoming);
        let table: &mut PortTable = match proto {
            Protocol::Any => &mut dir.any_proto,
            Protocol::Tcp => &mut dir.tcp,
            Protocol::Udp => &mut dir.udp,
            Protocol::Icmp | Protocol::IcmpV6 => &mut dir.icmp,
            Protocol::Other(_) => unreachable!("checked above"),
        };

        for p in start..=end {
            let ca = table.entry(p).or_default();
            add_to_ca_rule(
                ca,
                &self.default_local_cidr,
                &groups,
                &host,
                &cidr,
                &local_cidr,
                &ca_name,
                &ca_sha,
            );
        }

        Ok(())
    }

    fn check_sanity(
        &mut self,
        incoming: bool,
        groups: &[String],
        host: &Option<String>,
        cidr: &Option<IpNet>,
    ) {
        let groups_has_any = groups.iter().any(|g| g == "any");
        if groups_has_any && groups.len() > 1 {
            self.warnings
                .push(RuleWarning::GroupsShadowedByAny { incoming });
        }
        if host.as_deref() == Some("any") {
            if !groups.is_empty() {
                self.warnings.push(RuleWarning::HostAnyShadowsGroups {
                    incoming,
                    groups: groups.to_vec(),
                });
            }
            if let Some(c) = cidr {
                self.warnings
                    .push(RuleWarning::HostAnyShadowsCidr { incoming, cidr: *c });
            }
        }
        if groups_has_any {
            if let Some(h) = host
                && h != "any"
            {
                self.warnings.push(RuleWarning::GroupsAnyShadowsHost {
                    incoming,
                    host: h.clone(),
                });
            }
            if let Some(c) = cidr {
                self.warnings
                    .push(RuleWarning::GroupsAnyShadowsCidr { incoming, cidr: *c });
            }
        }
    }

    pub fn warnings(&self) -> &[RuleWarning] {
        &self.warnings
    }

    pub fn build(self) -> RuleSet {
        RuleSet {
            inbound: self.inbound,
            outbound: self.outbound,
        }
    }
}

fn port_bounds(port: PortSpec) -> Result<(i32, i32), RuleError> {
    match port {
        PortSpec::Any => Ok((PORT_ANY, PORT_ANY)),
        PortSpec::Fragment => Ok((PORT_FRAGMENT, PORT_FRAGMENT)),
        PortSpec::Single(p) => Ok((p as i32, p as i32)),
        PortSpec::Range(start, end) => {
            if start > end {
                return Err(RuleError::InvalidPortRange { start, end });
            }
            Ok((start as i32, end as i32))
        }
    }
}

fn direction_mut<'a>(
    inbound: &'a mut Direction,
    outbound: &'a mut Direction,
    incoming: bool,
) -> &'a mut Direction {
    if incoming { inbound } else { outbound }
}

fn is_any(groups: &[String], host: &Option<String>, cidr: &Option<IpNet>) -> bool {
    if groups.is_empty() && host.is_none() && cidr.is_none() {
        return true;
    }
    if groups.iter().any(|g| g == "any") {
        return true;
    }
    if host.as_deref() == Some("any") {
        return true;
    }
    false
}

fn merge_local_cidr(lc: &mut LocalCidr, default: &LocalCidrDefault, spec: &LocalCidrSpec) {
    match spec {
        LocalCidrSpec::Any => lc.any = true,
        LocalCidrSpec::Net(n) => lc.nets.push(*n),
        LocalCidrSpec::Unset => match default {
            LocalCidrDefault::Any => lc.any = true,
            LocalCidrDefault::Nets(nets) => lc.nets.extend(nets.iter().copied()),
        },
    }
}

fn add_to_peer_rule(
    pr: &mut PeerRule,
    default: &LocalCidrDefault,
    groups: &[String],
    host: &Option<String>,
    cidr: &Option<IpNet>,
    local_cidr: &LocalCidrSpec,
) {
    if is_any(groups, host, cidr) {
        let lc = pr.any.get_or_insert_with(LocalCidr::default);
        merge_local_cidr(lc, default, local_cidr);
        return;
    }

    if !groups.is_empty() {
        let mut lc = LocalCidr::default();
        merge_local_cidr(&mut lc, default, local_cidr);
        pr.groups.push((groups.to_vec(), lc));
    }

    if let Some(h) = host {
        let lc = pr.hosts.entry(h.clone()).or_default();
        merge_local_cidr(lc, default, local_cidr);
    }

    if let Some(c) = cidr {
        if let Some(existing) = pr.cidrs.iter_mut().find(|(net, _)| net == c) {
            merge_local_cidr(&mut existing.1, default, local_cidr);
        } else {
            let mut lc = LocalCidr::default();
            merge_local_cidr(&mut lc, default, local_cidr);
            pr.cidrs.push((*c, lc));
        }
    }
}

// Internal helper threading the same fields as `add_rule` one level down;
// see the `#[allow]` note on `add_rule` above.
#[allow(clippy::too_many_arguments)]
fn add_to_ca_rule(
    ca: &mut CaRule,
    default: &LocalCidrDefault,
    groups: &[String],
    host: &Option<String>,
    cidr: &Option<IpNet>,
    local_cidr: &LocalCidrSpec,
    ca_name: &Option<String>,
    ca_sha: &Option<String>,
) {
    if ca_sha.is_none() && ca_name.is_none() {
        let pr = ca.any.get_or_insert_with(PeerRule::default);
        add_to_peer_rule(pr, default, groups, host, cidr, local_cidr);
        return;
    }
    if let Some(sha) = ca_sha {
        let pr = ca.ca_shas.entry(sha.clone()).or_default();
        add_to_peer_rule(pr, default, groups, host, cidr, local_cidr);
    }
    if let Some(name) = ca_name {
        let pr = ca.ca_names.entry(name.clone()).or_default();
        add_to_peer_rule(pr, default, groups, host, cidr, local_cidr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::PeerIdentity;
    use crate::packet::Packet;

    fn packet(
        local: &str,
        remote: &str,
        local_port: u16,
        remote_port: u16,
        protocol: Protocol,
    ) -> Packet {
        Packet {
            local_addr: local.parse().unwrap(),
            remote_addr: remote.parse().unwrap(),
            local_port,
            remote_port,
            protocol,
            fragment: false,
        }
    }

    fn identity(name: &str, groups: &[&str]) -> PeerIdentity {
        PeerIdentity {
            name: name.into(),
            groups: groups.iter().map(|g| g.to_string()).collect(),
            ..Default::default()
        }
    }

    fn open_builder() -> RuleSetBuilder {
        RuleSetBuilder::new(vec![], false, false)
    }

    #[test]
    fn empty_rule_matches_unconditionally() {
        let mut b = open_builder();
        b.add_rule(
            true,
            Protocol::Tcp,
            PortSpec::Single(1),
            vec![],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        let rules = b.build();
        let p = packet("1.1.1.1", "2.2.2.2", 1, 1, Protocol::Tcp);
        assert!(rules.matches(&p, true, &identity("anyone", &[])));
    }

    #[test]
    fn group_rule_requires_the_group() {
        let mut b = open_builder();
        b.add_rule(
            true,
            Protocol::Udp,
            PortSpec::Single(1),
            vec!["g1".into()],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        let rules = b.build();
        let p = packet("1.1.1.1", "2.2.2.2", 1, 1, Protocol::Udp);
        assert!(rules.matches(&p, true, &identity("h", &["g1"])));
        assert!(!rules.matches(&p, true, &identity("h", &["g2"])));
    }

    /// ICMP has no ports, so a port on an ICMP rule can only ever make it
    /// dead: the parser reports `local_port`/`remote_port` for ICMP as the
    /// echo identifier or 0, never a port the operator meant. Go coerces the
    /// rule to `PortAny` and warns rather than silently filing it under an
    /// unreachable key (firewall.go's AddRule, v1.11.0, #1609).
    #[test]
    fn icmp_rule_with_a_port_is_coerced_to_port_any() {
        let mut b = open_builder();
        b.add_rule(
            true,
            Protocol::Icmp,
            PortSpec::Single(8),
            vec![],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            b.warnings(),
            &[RuleWarning::IcmpPortIgnored {
                incoming: true,
                port: PortSpec::Single(8)
            }]
        );

        let rules = b.build();
        // An ICMP packet as the parser actually produces it: no port.
        let p = packet("1.1.1.1", "2.2.2.2", 0, 0, Protocol::Icmp);
        assert!(rules.matches(&p, true, &identity("h", &[])));
    }

    #[test]
    fn icmpv6_rule_with_a_port_range_is_coerced_and_still_matches_outbound() {
        // Outbound lookups key on `remote_port`, which for ICMP carries the
        // echo identifier — so an uncoerced rule would miss on every ping
        // with a different identifier, not just on port-0 packets.
        let mut b = open_builder();
        b.add_rule(
            false,
            Protocol::IcmpV6,
            PortSpec::Range(1, 4),
            vec![],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();

        let rules = b.build();
        let p = packet("fd00::1", "fd00::2", 0, 41337, Protocol::IcmpV6);
        assert!(rules.matches(&p, false, &identity("h", &[])));
    }

    #[test]
    fn icmp_rule_without_a_port_produces_no_warning() {
        let mut b = open_builder();
        b.add_rule(
            true,
            Protocol::Icmp,
            PortSpec::Any,
            vec![],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        assert!(b.warnings().is_empty());
    }

    #[test]
    fn unknown_protocol_is_rejected() {
        let mut b = open_builder();
        let err = b
            .add_rule(
                true,
                Protocol::Other(255),
                PortSpec::Any,
                vec![],
                None,
                None,
                LocalCidrSpec::Unset,
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(err, RuleError::UnknownProtocol(Protocol::Other(255)));
    }

    #[test]
    fn inverted_port_range_is_rejected() {
        let mut b = open_builder();
        let err = b
            .add_rule(
                true,
                Protocol::Tcp,
                PortSpec::Range(10, 5),
                vec![],
                None,
                None,
                LocalCidrSpec::Unset,
                None,
                None,
            )
            .unwrap_err();
        assert_eq!(err, RuleError::InvalidPortRange { start: 10, end: 5 });
    }

    #[test]
    fn ca_sha_scoped_rule_does_not_affect_a_differently_scoped_rule_on_the_same_port() {
        // Mirrors firewall_test.go TestFirewall_Drop's CA-independence checks.
        let mut b = open_builder();
        b.add_rule(
            true,
            Protocol::Any,
            PortSpec::Any,
            vec!["nope".into()],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            Some("signer-shasum-bad".into()),
        )
        .unwrap();
        b.add_rule(
            true,
            Protocol::Any,
            PortSpec::Any,
            vec!["default-group".into()],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            Some("signer-shasum".into()),
        )
        .unwrap();
        let rules = b.build();
        let p = packet("1.1.1.1", "2.2.2.2", 10, 90, Protocol::Udp);
        let remote = PeerIdentity {
            name: "host1".into(),
            groups: ["default-group".to_string()].into(),
            ca_sha: "signer-shasum".into(),
            ..Default::default()
        };
        assert!(rules.matches(&p, true, &remote));
    }

    #[test]
    fn host_targeted_by_two_add_rule_calls_merges_local_cidr_rather_than_overwriting() {
        let mut b = open_builder();
        b.add_rule(
            true,
            Protocol::Tcp,
            PortSpec::Single(1),
            vec![],
            Some("db1".into()),
            None,
            LocalCidrSpec::Net("10.0.0.0/24".parse().unwrap()),
            None,
            None,
        )
        .unwrap();
        b.add_rule(
            true,
            Protocol::Tcp,
            PortSpec::Single(1),
            vec![],
            Some("db1".into()),
            None,
            LocalCidrSpec::Net("10.0.1.0/24".parse().unwrap()),
            None,
            None,
        )
        .unwrap();
        let rules = b.build();
        let remote = identity("db1", &[]);
        assert!(rules.matches(
            &packet("10.0.0.5", "9.9.9.9", 1, 1, Protocol::Tcp),
            true,
            &remote
        ));
        assert!(rules.matches(
            &packet("10.0.1.5", "9.9.9.9", 1, 1, Protocol::Tcp),
            true,
            &remote
        ));
        assert!(!rules.matches(
            &packet("10.0.2.5", "9.9.9.9", 1, 1, Protocol::Tcp),
            true,
            &remote
        ));
    }

    #[test]
    fn local_cidr_unset_defaults_to_any_when_there_are_no_unsafe_networks() {
        let mut b = RuleSetBuilder::new(vec!["10.0.0.9/32".parse().unwrap()], false, false);
        b.add_rule(
            true,
            Protocol::Tcp,
            PortSpec::Single(1),
            vec![],
            Some("h".into()),
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        let rules = b.build();
        let remote = identity("h", &[]);
        assert!(rules.matches(
            &packet("192.168.99.1", "9.9.9.9", 1, 1, Protocol::Tcp),
            true,
            &remote
        ));
    }

    #[test]
    fn local_cidr_unset_falls_back_to_assigned_networks_when_unsafe_networks_exist() {
        let mut b = RuleSetBuilder::new(vec!["10.0.0.9/32".parse().unwrap()], true, false);
        b.add_rule(
            true,
            Protocol::Tcp,
            PortSpec::Single(1),
            vec![],
            Some("h".into()),
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        let rules = b.build();
        let remote = identity("h", &[]);
        assert!(rules.matches(
            &packet("10.0.0.9", "9.9.9.9", 1, 1, Protocol::Tcp),
            true,
            &remote
        ));
        assert!(!rules.matches(
            &packet("192.168.99.1", "9.9.9.9", 1, 1, Protocol::Tcp),
            true,
            &remote
        ));
    }

    #[test]
    fn local_cidr_unset_fallback_uses_the_full_assigned_prefix_not_just_the_host() {
        // The builder's local_cidr default inserts the *full* assigned
        // prefixes (Go's f.assignedNetworks), so a /120 v6 assigned network
        // matches any local address in that /120 -- distinct from the
        // firewall's host-route local check. Exercised over IPv6 since the
        // primary consumer is v6-focused.
        let mut b = RuleSetBuilder::new(vec!["fd12::34/120".parse().unwrap()], true, false);
        b.add_rule(
            true,
            Protocol::Tcp,
            PortSpec::Single(1),
            vec![],
            Some("h".into()),
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        let rules = b.build();
        let remote = identity("h", &[]);
        assert!(
            rules.matches(
                &packet("fd12::99", "9::9", 1, 1, Protocol::Tcp),
                true,
                &remote
            ),
            "another address in the /120 matches"
        );
        assert!(
            !rules.matches(
                &packet("fd12::1:99", "9::9", 1, 1, Protocol::Tcp),
                true,
                &remote
            ),
            "an address outside the /120 does not"
        );
    }

    #[test]
    fn default_local_cidr_any_overrides_the_unsafe_networks_fallback() {
        let mut b = RuleSetBuilder::new(vec!["10.0.0.9/32".parse().unwrap()], true, true);
        b.add_rule(
            true,
            Protocol::Tcp,
            PortSpec::Single(1),
            vec![],
            Some("h".into()),
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        let rules = b.build();
        let remote = identity("h", &[]);
        assert!(rules.matches(
            &packet("192.168.99.1", "9.9.9.9", 1, 1, Protocol::Tcp),
            true,
            &remote
        ));
    }

    #[test]
    fn explicit_local_cidr_any_is_unconditional_even_with_unsafe_networks() {
        let mut b = RuleSetBuilder::new(vec!["10.0.0.9/32".parse().unwrap()], true, false);
        b.add_rule(
            true,
            Protocol::Tcp,
            PortSpec::Single(1),
            vec![],
            Some("h".into()),
            None,
            LocalCidrSpec::Any,
            None,
            None,
        )
        .unwrap();
        let rules = b.build();
        let remote = identity("h", &[]);
        assert!(rules.matches(
            &packet("192.168.99.1", "9.9.9.9", 1, 1, Protocol::Tcp),
            true,
            &remote
        ));
    }

    #[test]
    fn groups_any_alongside_other_groups_warns() {
        let mut b = open_builder();
        b.add_rule(
            true,
            Protocol::Any,
            PortSpec::Any,
            vec!["any".into(), "foo".into()],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            b.warnings(),
            &[RuleWarning::GroupsShadowedByAny { incoming: true }]
        );
    }

    #[test]
    fn host_any_combined_with_groups_warns() {
        let mut b = open_builder();
        b.add_rule(
            false,
            Protocol::Any,
            PortSpec::Any,
            vec!["g1".into()],
            Some("any".into()),
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            b.warnings(),
            &[RuleWarning::HostAnyShadowsGroups {
                incoming: false,
                groups: vec!["g1".into()]
            }]
        );
    }

    #[test]
    fn no_warning_for_a_well_formed_rule() {
        let mut b = open_builder();
        b.add_rule(
            true,
            Protocol::Any,
            PortSpec::Any,
            vec!["g1".into()],
            Some("bob".into()),
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        assert!(b.warnings().is_empty());
    }
}
