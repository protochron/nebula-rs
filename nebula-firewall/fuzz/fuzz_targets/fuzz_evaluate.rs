#![no_main]

use std::net::IpAddr;
use std::time::Duration;

use arbitrary::{Arbitrary, Unstructured};
use ipnet::IpNet;
use libfuzzer_sys::fuzz_target;

use nebula_firewall::{
    Firewall, FirewallOptions, LocalCidrSpec, Packet, PeerIdentity, PortSpec, Protocol,
    RuleSetBuilder,
};

fn arb_ipnet(u: &mut Unstructured) -> arbitrary::Result<IpNet> {
    let addr = IpAddr::arbitrary(u)?;
    let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
    let prefix = u8::arbitrary(u)? % (max + 1);
    Ok(IpNet::new(addr, prefix).expect("prefix <= max_prefix_len"))
}

fn arb_port(u: &mut Unstructured) -> arbitrary::Result<PortSpec> {
    Ok(match u8::arbitrary(u)? % 4 {
        0 => PortSpec::Any,
        1 => PortSpec::Fragment,
        2 => PortSpec::Single(u16::arbitrary(u)?),
        _ => PortSpec::Range(u16::arbitrary(u)?, u16::arbitrary(u)?),
    })
}

fn arb_identity(u: &mut Unstructured) -> arbitrary::Result<PeerIdentity> {
    let mut groups = std::collections::HashSet::new();
    for _ in 0..(u8::arbitrary(u)? % 4) {
        groups.insert(String::arbitrary(u)?);
    }
    let mut vpn = Vec::new();
    for _ in 0..(u8::arbitrary(u)? % 3) {
        vpn.push(arb_ipnet(u)?);
    }
    let mut unsafe_nets = Vec::new();
    for _ in 0..(u8::arbitrary(u)? % 3) {
        unsafe_nets.push(arb_ipnet(u)?);
    }
    Ok(PeerIdentity {
        name: String::arbitrary(u)?,
        groups,
        ca_name: String::arbitrary(u)?,
        ca_sha: String::arbitrary(u)?,
        vpn_networks: vpn,
        unsafe_networks: unsafe_nets,
    })
}

fn run(data: &[u8]) -> arbitrary::Result<()> {
    let mut u = Unstructured::new(data);

    let has_unsafe = bool::arbitrary(&mut u)?;
    let default_any = bool::arbitrary(&mut u)?;
    let mut assigned = Vec::new();
    for _ in 0..(u8::arbitrary(&mut u)? % 3) {
        assigned.push(arb_ipnet(&mut u)?);
    }

    let mut builder = RuleSetBuilder::new(assigned.clone(), has_unsafe, default_any);
    for _ in 0..8 {
        let incoming = bool::arbitrary(&mut u)?;
        let proto = Protocol::from(u8::arbitrary(&mut u)?);
        let port = arb_port(&mut u)?;
        let mut groups = Vec::new();
        for _ in 0..(u8::arbitrary(&mut u)? % 3) {
            groups.push(String::arbitrary(&mut u)?);
        }
        let host = Option::<String>::arbitrary(&mut u)?;
        let cidr = if bool::arbitrary(&mut u)? { Some(arb_ipnet(&mut u)?) } else { None };
        let local_cidr = match u8::arbitrary(&mut u)? % 3 {
            0 => LocalCidrSpec::Any,
            1 => LocalCidrSpec::Net(arb_ipnet(&mut u)?),
            _ => LocalCidrSpec::Unset,
        };
        let ca_name = Option::<String>::arbitrary(&mut u)?;
        let ca_sha = Option::<String>::arbitrary(&mut u)?;
        // Must return Ok or Err, never panic.
        let _ = builder.add_rule(incoming, proto, port, groups, host, cidr, local_cidr, ca_name, ca_sha);
    }
    let _ = builder.warnings();

    let fw = Firewall::new(
        builder.build(),
        FirewallOptions {
            tcp_timeout: Duration::from_secs(1),
            udp_timeout: Duration::from_secs(60),
            default_timeout: Duration::from_secs(600),
            in_send_reject: false,
            out_send_reject: false,
            default_local_cidr_any: default_any,
        },
        assigned,
        Vec::new(),
    );

    let remote = arb_identity(&mut u)?;

    for _ in 0..8 {
        let packet = Packet {
            local_addr: IpAddr::arbitrary(&mut u)?,
            remote_addr: IpAddr::arbitrary(&mut u)?,
            local_port: u16::arbitrary(&mut u)?,
            remote_port: u16::arbitrary(&mut u)?,
            protocol: Protocol::from(u8::arbitrary(&mut u)?),
            fragment: bool::arbitrary(&mut u)?,
        };
        let incoming = bool::arbitrary(&mut u)?;
        // The core contract: evaluate never panics on any input.
        let _ = fw.evaluate(packet, incoming, &remote);
    }

    Ok(())
}

fuzz_target!(|data: &[u8]| {
    // Err just means "ran out of fuzz bytes" -- not a failure.
    let _ = run(data);
});
