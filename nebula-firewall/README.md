# nebula-firewall

A Rust port of [slackhq/nebula](https://github.com/slackhq/nebula) v1.10.x's
firewall rule model and `Firewall.Drop()` evaluation logic — the same rule
options nebula exposes in `nebula.yml`'s `firewall.inbound`/`firewall.outbound`
sections (port/code, proto, host, group/groups, cidr, local_cidr, ca_name,
ca_sha), plus the stateful conntrack fast-path and hot-reload behavior.

This crate is pure logic: no OS packet capture, no tun device, no config file
format, and no dependency on any specific wire protocol crate. See
`docs/superpowers/specs/2026-07-11-nebula-firewall-design.md` for the full
design and `docs/superpowers/plans/2026-07-11-nebula-firewall.md` for how it
was built.

## Usage

```rust
use std::time::Duration;
use nebula_firewall::{Firewall, FirewallOptions, LocalCidrSpec, PeerIdentity, PortSpec, Protocol, RuleSetBuilder};

let assigned_networks = vec!["10.0.0.5/32".parse().unwrap()];
let mut builder = RuleSetBuilder::new(assigned_networks.clone(), false, false);
builder.add_rule(true, Protocol::Tcp, PortSpec::Single(22), vec!["ssh-admins".into()], None, None, LocalCidrSpec::Unset, None, None).unwrap();

let firewall = Firewall::new(
    builder.build(),
    FirewallOptions {
        tcp_timeout: Duration::from_secs(720 * 60),
        udp_timeout: Duration::from_secs(3 * 60),
        default_timeout: Duration::from_secs(10 * 60),
        in_send_reject: false,
        out_send_reject: false,
        default_local_cidr_any: false,
    },
    assigned_networks,
    vec![],
);

let remote = PeerIdentity {
    name: "laptop1".into(),
    groups: ["ssh-admins".to_string()].into(),
    vpn_networks: vec!["10.0.0.9/32".parse().unwrap()],
    ..Default::default()
};
```
