use std::time::Duration;

use nebula_firewall::{
    Firewall, FirewallOptions, LocalCidrSpec, Packet, PeerIdentity, PortSpec, Protocol,
    RuleSetBuilder,
};

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

fn packet(local: &str, remote: &str, local_port: u16, remote_port: u16) -> Packet {
    Packet {
        local_addr: local.parse().unwrap(),
        remote_addr: remote.parse().unwrap(),
        local_port,
        remote_port,
        protocol: Protocol::Udp,
        fragment: false,
    }
}

/// Mirrors firewall_test.go's TestFirewall_Drop: an inbound "any" rule
/// lets traffic in, the return leg passes via conntrack (not because
/// there's an outbound rule -- there isn't one), and a remote-address
/// mismatch is rejected before rules are even consulted.
#[test]
fn drop_basic_allow_and_remote_mismatch() {
    let assigned = vec!["1.2.3.4/32".parse().unwrap()];
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
        vpn_networks: vec!["1.2.3.4/32".parse().unwrap()],
        ..Default::default()
    };

    let p = packet("1.2.3.4", "1.2.3.4", 10, 90);
    assert!(
        fw.evaluate(p, false, &remote).is_err(),
        "outbound should have no matching rule"
    );
    assert!(
        fw.evaluate(p, true, &remote).is_ok(),
        "inbound matches the any rule"
    );
    assert!(
        fw.evaluate(p, false, &remote).is_ok(),
        "outbound now passes via conntrack"
    );

    let mut mismatched = p;
    mismatched.remote_addr = "1.2.3.10".parse().unwrap();
    assert!(
        fw.evaluate(mismatched, false, &remote).is_err(),
        "remote address the identity doesn't own is rejected"
    );
}

/// Mirrors TestFirewall_Drop2: a rule naming two groups requires the peer
/// to have BOTH (AND-within-entry), not either.
#[test]
fn drop_group_rule_requires_every_named_group() {
    let assigned = vec!["1.2.3.4/32".parse().unwrap()];
    let mut b = RuleSetBuilder::new(assigned.clone(), false, false);
    b.add_rule(
        true,
        Protocol::Any,
        PortSpec::Any,
        vec!["default-group".into(), "test-group".into()],
        None,
        None,
        LocalCidrSpec::Unset,
        None,
        None,
    )
    .unwrap();
    let fw = Firewall::new(b.build(), options(), assigned, vec![]);

    let p = packet("1.2.3.4", "1.2.3.4", 10, 90);

    let missing_one = PeerIdentity {
        name: "host1".into(),
        groups: ["default-group".to_string(), "test-group-not".to_string()].into(),
        vpn_networks: vec!["1.2.3.4/32".parse().unwrap()],
        ..Default::default()
    };
    assert!(fw.evaluate(p, true, &missing_one).is_err());

    let has_both = PeerIdentity {
        name: "host1".into(),
        groups: ["default-group".to_string(), "test-group".to_string()].into(),
        vpn_networks: vec!["1.2.3.4/32".parse().unwrap()],
        ..Default::default()
    };
    assert!(fw.evaluate(p, true, &has_both).is_ok());
}

/// Mirrors TestFirewall_Drop3: a host-name match, a ca_sha match, and a
/// remote-CIDR match are three independent ways for different rules to
/// admit the same peer.
#[test]
fn drop_host_ca_sha_and_remote_cidr_are_independent_match_paths() {
    // Each identity check below reuses the same 5-tuple `p`, exactly like
    // Go's TestFirewall_Drop3 -- which is why that test calls
    // resetConntrack(fw) between each sub-check: conntrack keys on the
    // packet 5-tuple alone, not on which peer sent it, so a prior pass
    // would otherwise let every later identity through via the fast path
    // regardless of whether it should actually match. This crate doesn't
    // expose a conntrack-reset hook, so a fresh Firewall per check achieves
    // the same isolation through the public API.
    let assigned = vec!["1.2.3.4/32".parse().unwrap()];
    let make_fw = || {
        let mut b = RuleSetBuilder::new(assigned.clone(), false, false);
        b.add_rule(
            true,
            Protocol::Any,
            PortSpec::Single(1),
            vec![],
            Some("host1".into()),
            None,
            LocalCidrSpec::Unset,
            None,
            None,
        )
        .unwrap();
        b.add_rule(
            true,
            Protocol::Any,
            PortSpec::Single(1),
            vec![],
            None,
            None,
            LocalCidrSpec::Unset,
            None,
            Some("signer-sha".into()),
        )
        .unwrap();
        Firewall::new(b.build(), options(), assigned.clone(), vec![])
    };

    let p = packet("1.2.3.4", "1.2.3.4", 1, 1);

    let by_host = PeerIdentity {
        name: "host1".into(),
        vpn_networks: assigned.clone(),
        ca_sha: "signer-sha-bad".into(),
        ..Default::default()
    };
    assert!(
        make_fw().evaluate(p, true, &by_host).is_ok(),
        "matches via host name"
    );

    let by_ca_sha = PeerIdentity {
        name: "host2".into(),
        vpn_networks: assigned.clone(),
        ca_sha: "signer-sha".into(),
        ..Default::default()
    };
    assert!(
        make_fw().evaluate(p, true, &by_ca_sha).is_ok(),
        "matches via ca_sha"
    );

    let neither = PeerIdentity {
        name: "host3".into(),
        vpn_networks: assigned.clone(),
        ca_sha: "signer-sha-bad".into(),
        ..Default::default()
    };
    assert!(
        make_fw().evaluate(p, true, &neither).is_err(),
        "matches neither path"
    );

    let mut b2 = RuleSetBuilder::new(assigned.clone(), false, false);
    b2.add_rule(
        true,
        Protocol::Any,
        PortSpec::Single(1),
        vec![],
        None,
        Some("1.2.3.4/24".parse().unwrap()),
        LocalCidrSpec::Unset,
        None,
        None,
    )
    .unwrap();
    let fw2 = Firewall::new(b2.build(), options(), assigned, vec![]);
    assert!(
        fw2.evaluate(p, true, &neither).is_ok(),
        "matches via remote cidr"
    );
}

/// Mirrors TestFirewall_DropConntrackReload: a reload that changes which
/// port is allowed re-validates the still-conntracked flow lazily and
/// evicts it once it stops matching.
#[test]
fn drop_reload_lazily_revalidates_conntracked_flows() {
    let assigned = vec!["1.2.3.4/32".parse().unwrap()];
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
    let fw = Firewall::new(b.build(), options(), assigned.clone(), vec![]);

    let remote = PeerIdentity {
        name: "host1".into(),
        groups: ["default-group".to_string()].into(),
        vpn_networks: vec!["1.2.3.4/32".parse().unwrap()],
        ..Default::default()
    };
    let p = packet("1.2.3.4", "1.2.3.4", 10, 90);

    assert!(fw.evaluate(p, true, &remote).is_ok());
    assert!(
        fw.evaluate(p, false, &remote).is_ok(),
        "outbound passes via conntrack"
    );

    let mut b2 = RuleSetBuilder::new(assigned.clone(), false, false);
    b2.add_rule(
        true,
        Protocol::Any,
        PortSpec::Single(10),
        vec!["any".into()],
        None,
        None,
        LocalCidrSpec::Unset,
        None,
        None,
    )
    .unwrap();
    fw.reload(b2.build());
    assert!(
        fw.evaluate(p, false, &remote).is_ok(),
        "reloaded ruleset still allows port 10 on revalidation"
    );

    let mut b3 = RuleSetBuilder::new(assigned.clone(), false, false);
    b3.add_rule(
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
    fw.reload(b3.build());
    assert!(
        fw.evaluate(p, false, &remote).is_err(),
        "reloaded ruleset no longer allows port 10"
    );
}

/// Mirrors the *negative* CA-independence checks in TestFirewall_Drop
/// (firewall_test.go:230-232): the peer's own ca_sha bucket names a group it
/// lacks, and the group it does have is scoped to a different bucket -- so
/// neither path matches and the packet is dropped.
#[test]
fn drop_ca_sha_scoping_blocks_when_neither_bucket_grants_the_peer() {
    let assigned = vec!["1.2.3.4/32".parse().unwrap()];
    let mut b = RuleSetBuilder::new(assigned.clone(), false, false);
    b.add_rule(
        true,
        Protocol::Any,
        PortSpec::Any,
        vec!["nope".into()],
        None,
        None,
        LocalCidrSpec::Unset,
        None,
        Some("signer-shasum".into()),
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
        Some("signer-shasum-bad".into()),
    )
    .unwrap();
    let fw = Firewall::new(b.build(), options(), assigned.clone(), vec![]);

    let remote = PeerIdentity {
        name: "host1".into(),
        groups: ["default-group".to_string()].into(),
        vpn_networks: assigned,
        ca_sha: "signer-shasum".into(),
        ..Default::default()
    };
    assert!(
        fw.evaluate(packet("1.2.3.4", "1.2.3.4", 10, 90), true, &remote)
            .is_err(),
        "peer's bucket wants a group it lacks; its group is in another bucket"
    );
}

/// Mirrors TestFirewall_DropV6: the allow / conntrack return-leg / remote
/// mismatch flow over IPv6. IPv6 is the primary consumer's focus, so it gets
/// full end-to-end coverage, not just unit tests.
#[test]
fn drop_basic_allow_over_ipv6() {
    let assigned = vec!["fd12::34/128".parse().unwrap()];
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
        vpn_networks: vec!["fd12::34/128".parse().unwrap()],
        ..Default::default()
    };

    let p = packet("fd12::34", "fd12::34", 10, 90);
    assert!(
        fw.evaluate(p, false, &remote).is_err(),
        "outbound has no matching rule"
    );
    assert!(
        fw.evaluate(p, true, &remote).is_ok(),
        "inbound matches the any rule"
    );
    assert!(
        fw.evaluate(p, false, &remote).is_ok(),
        "outbound now passes via conntrack"
    );

    let mut mismatched = p;
    mismatched.remote_addr = "fd12::56".parse().unwrap();
    assert!(
        fw.evaluate(mismatched, false, &remote).is_err(),
        "unowned v6 remote address is rejected"
    );
}

/// Mirrors TestFirewall_Drop_EnforceIPMatch over IPv6: an assigned prefix
/// wider than a host route only makes its *exact* address routable, so a
/// local address inside the prefix but not equal to the assigned address is
/// InvalidLocalIp -- confirming the host-route derivation end-to-end.
#[test]
fn drop_enforce_ip_match_over_ipv6() {
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

    assert!(
        fw.evaluate(packet("fd00::1", "2222::2", 10, 90), true, &remote)
            .is_ok(),
        "exact assigned v6 address is routable"
    );
    assert!(
        fw.evaluate(packet("fd12::34", "2222::2", 10, 90), true, &remote)
            .is_err(),
        "another address inside the /8 is not routable"
    );
}
