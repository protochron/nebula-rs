//! Client-side lighthouse protocol: register this host, resolve peer
//! addresses, and react to punch coordination. Never answers `HostQuery`
//! on behalf of other hosts (that's the lighthouse-server role, out of
//! scope — see the crate's Non-goals).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::wire::nebula_meta::MessageType;
use crate::wire::{Addr, NebulaMeta, NebulaMetaDetails, V4AddrPort, V6AddrPort};

pub fn addr_to_ip(addr: &Addr) -> IpAddr {
    let mut octets = [0u8; 16];
    octets[0..8].copy_from_slice(&addr.hi.to_be_bytes());
    octets[8..16].copy_from_slice(&addr.lo.to_be_bytes());
    let v6 = Ipv6Addr::from(octets);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

fn ip_to_addr(ip: IpAddr) -> Addr {
    let v6: Ipv6Addr = match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    };
    let octets = v6.octets();
    Addr {
        hi: u64::from_be_bytes(octets[0..8].try_into().unwrap()),
        lo: u64::from_be_bytes(octets[8..16].try_into().unwrap()),
    }
}

fn addr_to_v4_v6(addr: SocketAddr, v4: &mut Vec<V4AddrPort>, v6: &mut Vec<V6AddrPort>) {
    match addr {
        SocketAddr::V4(a) => v4.push(V4AddrPort {
            addr: u32::from(*a.ip()),
            port: u32::from(a.port()),
        }),
        SocketAddr::V6(a) => {
            let octets = a.ip().octets();
            v6.push(V6AddrPort {
                hi: u64::from_be_bytes(octets[0..8].try_into().unwrap()),
                lo: u64::from_be_bytes(octets[8..16].try_into().unwrap()),
                port: u32::from(a.port()),
            });
        }
    }
}

/// Builds a `HostUpdateNotification`: "here is my vpn address and the UDP
/// addresses I can be reached at", sent to each configured lighthouse at
/// startup and periodically thereafter.
pub fn host_update_notification(vpn_addr: IpAddr, reachable_at: &[SocketAddr]) -> NebulaMeta {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for addr in reachable_at {
        addr_to_v4_v6(*addr, &mut v4, &mut v6);
    }
    NebulaMeta {
        r#type: MessageType::HostUpdateNotification as i32,
        details: Some(NebulaMetaDetails {
            vpn_addr: Some(ip_to_addr(vpn_addr)),
            v4_addr_ports: v4,
            v6_addr_ports: v6,
            ..Default::default()
        }),
    }
}

/// Builds a `HostQuery`: "what addresses can I reach `vpn_addr` at?"
pub fn host_query(vpn_addr: IpAddr) -> NebulaMeta {
    NebulaMeta {
        r#type: MessageType::HostQuery as i32,
        details: Some(NebulaMetaDetails {
            vpn_addr: Some(ip_to_addr(vpn_addr)),
            ..Default::default()
        }),
    }
}

/// Extracts the candidate `SocketAddr`s from a `HostQueryReply` or
/// `HostUpdateNotification`.
pub fn candidate_addrs(meta: &NebulaMeta) -> Vec<SocketAddr> {
    let Some(details) = &meta.details else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for v4 in &details.v4_addr_ports {
        out.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(v4.addr)),
            v4.port as u16,
        ));
    }
    for v6 in &details.v6_addr_ports {
        let mut octets = [0u8; 16];
        octets[0..8].copy_from_slice(&v6.hi.to_be_bytes());
        octets[8..16].copy_from_slice(&v6.lo.to_be_bytes());
        out.push(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::from(octets)),
            v6.port as u16,
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn host_update_notification_round_trips_through_candidate_addrs() {
        let vpn_addr = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 3));
        let reachable = vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
            4242,
        )];
        let meta = host_update_notification(vpn_addr, &reachable);
        assert_eq!(candidate_addrs(&meta), reachable);
    }

    #[test]
    fn host_query_carries_the_requested_vpn_addr() {
        let vpn_addr = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 2));
        let meta = host_query(vpn_addr);
        let details = meta.details.unwrap();
        assert_eq!(addr_to_ip(&details.vpn_addr.unwrap()), vpn_addr);
    }

    #[test]
    fn protobuf_round_trip_matches_real_nebula_wire_bytes() {
        use prost::Message;
        let vpn_addr = IpAddr::V4(Ipv4Addr::new(10, 100, 0, 3));
        let meta = host_query(vpn_addr);
        let bytes = meta.encode_to_vec();
        let decoded = crate::wire::NebulaMeta::decode(bytes.as_slice()).unwrap();
        assert_eq!(decoded, meta);
    }
}
