//! nebula-firewall: a Rust port of slackhq/nebula v1.10.x's firewall rule
//! model and `Firewall.Drop()` evaluation logic.
//!
//! This crate is pure logic: no OS packet capture, no tun device, no config
//! file format, no networking, and no dependency on `nebula-protocol` or any
//! other wire-protocol crate. A consumer builds a [`RuleSet`] via
//! [`RuleSetBuilder`], constructs a [`Firewall`] from it, and calls
//! [`Firewall::evaluate`] per decrypted packet -- passing a [`Packet`]
//! 5-tuple and a [`PeerIdentity`] describing the remote peer (built from
//! whatever certificate/identity system the consumer uses) -- to get an
//! accept/reject decision.
//!
//! See `docs/superpowers/specs/2026-07-11-nebula-firewall-design.md` for
//! the full design rationale and how each piece maps to the Go source.

mod conntrack;
mod firewall;
mod identity;
mod packet;
mod rule;

pub use firewall::{DropReason, Firewall, FirewallOptions};
pub use identity::PeerIdentity;
pub use packet::{Packet, Protocol};
pub use rule::{LocalCidrSpec, PortSpec, RuleError, RuleSet, RuleSetBuilder, RuleWarning};
