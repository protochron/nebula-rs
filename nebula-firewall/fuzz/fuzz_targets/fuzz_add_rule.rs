#![no_main]

use std::net::IpAddr;

use arbitrary::{Arbitrary, Unstructured};
use ipnet::IpNet;
use libfuzzer_sys::fuzz_target;

use nebula_firewall::{LocalCidrSpec, PortSpec, Protocol, RuleSetBuilder};

fn arb_ipnet(u: &mut Unstructured) -> arbitrary::Result<IpNet> {
    let addr = IpAddr::arbitrary(u)?;
    let max = if addr.is_ipv4() { 32u8 } else { 128u8 };
    let prefix = u8::arbitrary(u)? % (max + 1);
    Ok(IpNet::new(addr, prefix).expect("prefix <= max_prefix_len"))
}

fn run(data: &[u8]) -> arbitrary::Result<()> {
    let mut u = Unstructured::new(data);

    let mut assigned = Vec::new();
    for _ in 0..(u8::arbitrary(&mut u)? % 3) {
        assigned.push(arb_ipnet(&mut u)?);
    }
    let mut builder = RuleSetBuilder::new(assigned, bool::arbitrary(&mut u)?, bool::arbitrary(&mut u)?);

    for _ in 0..16 {
        let incoming = bool::arbitrary(&mut u)?;
        let proto = Protocol::from(u8::arbitrary(&mut u)?);
        let port = match u8::arbitrary(&mut u)? % 4 {
            0 => PortSpec::Any,
            1 => PortSpec::Fragment,
            2 => PortSpec::Single(u16::arbitrary(&mut u)?),
            _ => PortSpec::Range(u16::arbitrary(&mut u)?, u16::arbitrary(&mut u)?),
        };
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
        // Never panics; Ok or Err are both acceptable.
        let _ = builder.add_rule(incoming, proto, port, groups, host, cidr, local_cidr, ca_name, ca_sha);
    }

    let _ = builder.warnings();
    // build() must not panic regardless of what was added.
    let _ = builder.build();
    Ok(())
}

fuzz_target!(|data: &[u8]| {
    let _ = run(data);
});
