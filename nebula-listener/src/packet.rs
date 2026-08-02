//! Parse an IPv4/IPv6 packet's addressing 5-tuple and map it — with
//! direction-correct local/remote — onto a `nebula_firewall::Packet`,
//! matching Go nebula's `newFirewallPacket`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use nebula_firewall::{Packet, Protocol};

/// The raw addressing fields pulled from an IP header, before the
/// direction-based local/remote assignment.
struct FiveTuple {
    src: IpAddr,
    dst: IpAddr,
    protocol: Protocol,
    src_port: u16,
    dst_port: u16,
    /// The ICMP/ICMPv6 echo identifier, when this packet carries one. ICMP
    /// has no ports and no orientation, so this bypasses the local/remote
    /// swap below and always lands in `remote_port` — matching Go, which
    /// keys ICMP conntrack on the identifier so concurrent pings between the
    /// same pair of hosts don't share one entry.
    icmp_identifier: Option<u16>,
    fragment: bool,
}

/// Parses `raw` into a `nebula_firewall::Packet`, assigning local/remote by
/// `incoming`. Returns `None` for anything it can't parse (dropped).
pub fn parse(raw: &[u8], incoming: bool) -> Option<Packet> {
    let t = match raw.first()? >> 4 {
        4 => parse_ipv4(raw)?,
        6 => parse_ipv6(raw)?,
        _ => return None,
    };
    let (local_addr, remote_addr, local_port, remote_port) = if incoming {
        (t.dst, t.src, t.dst_port, t.src_port)
    } else {
        (t.src, t.dst, t.src_port, t.dst_port)
    };
    // ICMP is orientation-independent: the identifier always goes in
    // `remote_port` and `local_port` stays 0, whichever way the packet is
    // travelling. Firewall rules never filter on it (ICMP rules are coerced
    // to "any port" — see nebula_firewall's RuleSetBuilder); it exists purely
    // to separate conntrack flows.
    let (local_port, remote_port) = match t.icmp_identifier {
        Some(id) => (0, id),
        None => (local_port, remote_port),
    };
    Some(Packet {
        local_addr,
        remote_addr,
        local_port,
        remote_port,
        protocol: t.protocol,
        fragment: t.fragment,
    })
}

fn read_ports(l4: &[u8]) -> (u16, u16) {
    if l4.len() < 4 {
        return (0, 0);
    }
    let src = u16::from_be_bytes([l4[0], l4[1]]);
    let dst = u16::from_be_bytes([l4[2], l4[3]]);
    (src, dst)
}

fn parse_ipv4(raw: &[u8]) -> Option<FiveTuple> {
    if raw.len() < 20 {
        return None;
    }
    let ihl = ((raw[0] & 0x0f) as usize) * 4;
    if ihl < 20 || raw.len() < ihl {
        return None;
    }
    let proto_num = raw[9];
    let frag_word = u16::from_be_bytes([raw[6], raw[7]]);
    let more_fragments = frag_word & 0x2000 != 0;
    let frag_offset = frag_word & 0x1fff;
    let fragment = more_fragments || frag_offset != 0;

    let src = IpAddr::V4(Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]));
    let dst = IpAddr::V4(Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]));

    let protocol = Protocol::from(proto_num);

    // Anything but a later fragment must carry a complete L4 header for us
    // to key on: 4 bytes for a port pair, 6 for ICMP so the identifier is
    // covered too. Go drops packets shorter than this rather than parsing
    // them with zeroed ports, so the firewall never evaluates a truncated
    // packet as if it were a well-formed one.
    //
    // Gated on `frag_offset` alone, not `fragment`: the first fragment of a
    // fragmented packet (MF set, offset 0) does carry a full L4 header. Note
    // that our `fragment` flag additionally folds in the MF bit, where Go
    // keys it off the offset alone — a pre-existing divergence that only
    // affects which rule table a first fragment is matched against.
    if frag_offset == 0 {
        let need = ihl + if protocol == Protocol::Icmp { 6 } else { 4 };
        if raw.len() < need {
            return None;
        }
    }

    // Ports live in the L4 header, present only on the first fragment
    // (offset 0) of a TCP/UDP packet.
    let (src_port, dst_port) = if frag_offset == 0 && matches!(protocol, Protocol::Tcp | Protocol::Udp) {
        read_ports(&raw[ihl..])
    } else {
        (0, 0)
    };

    // Unlike ICMPv6, every ICMPv4 type has the identifier field at the same
    // offset, so Go reads it unconditionally here.
    let icmp_identifier = (frag_offset == 0 && protocol == Protocol::Icmp)
        .then(|| u16::from_be_bytes([raw[ihl + 4], raw[ihl + 5]]));

    Some(FiveTuple { src, dst, protocol, src_port, dst_port, icmp_identifier, fragment })
}

fn parse_ipv6(raw: &[u8]) -> Option<FiveTuple> {
    if raw.len() < 40 {
        return None;
    }
    let mut src_octets = [0u8; 16];
    src_octets.copy_from_slice(&raw[8..24]);
    let mut dst_octets = [0u8; 16];
    dst_octets.copy_from_slice(&raw[24..40]);
    let src = IpAddr::V6(Ipv6Addr::from(src_octets));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_octets));

    let mut next_header = raw[6];
    let mut offset = 40usize;
    let mut fragment = false;

    // Best-effort: handle a single Fragment extension header (44) directly
    // after the fixed header; deeper ext-header chains are out of scope.
    if next_header == 44 {
        if raw.len() < offset + 8 {
            return None;
        }
        fragment = true;
        // Only the first fragment carries the L4 header. Past that, the bytes
        // after the fragment header are payload continuation, so reading them
        // as ports (or as an ICMP identifier) would key conntrack on garbage
        // and give every later fragment its own entry.
        let frag_offset = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]) & !0x7;
        if frag_offset != 0 {
            let protocol = Protocol::from(raw[offset]);
            return Some(FiveTuple {
                src,
                dst,
                protocol,
                src_port: 0,
                dst_port: 0,
                icmp_identifier: None,
                fragment,
            });
        }
        next_header = raw[offset]; // inner protocol
        offset += 8;
    }

    let protocol = Protocol::from(next_header);
    let (src_port, dst_port) = if matches!(protocol, Protocol::Tcp | Protocol::Udp) {
        read_ports(raw.get(offset..)?)
    } else {
        (0, 0)
    };

    // Unlike ICMPv4, only echo request (128) and echo reply (129) carry an
    // identifier; every other ICMPv6 type has something else in those bytes.
    //
    // Note: Go reads the *code* byte (`data[offset+1]`) here rather than the
    // type at `data[offset]`, so upstream never actually extracts the
    // identifier for real echo traffic — its test happens to build packets
    // with 128 in the code byte, which masks the bug. We read the type.
    let icmp_identifier = if protocol == Protocol::IcmpV6 {
        if raw.len() < offset + 6 {
            return None;
        }
        matches!(raw[offset], 128 | 129)
            .then(|| u16::from_be_bytes([raw[offset + 4], raw[offset + 5]]))
    } else {
        None
    };

    Some(FiveTuple { src, dst, protocol, src_port, dst_port, icmp_identifier, fragment })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal IPv4 header + optional 4 bytes of L4 ports.
    fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], frag_word: u16, l4: &[u8]) -> Vec<u8> {
        let total = 20 + l4.len();
        let mut p = vec![0x45, 0x00];
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]); // id
        p.extend_from_slice(&frag_word.to_be_bytes()); // flags + fragment offset
        p.push(64); // ttl
        p.push(proto);
        p.extend_from_slice(&[0, 0]); // header checksum (unchecked by parser)
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(l4);
        p
    }

    fn ports(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut v = src_port.to_be_bytes().to_vec();
        v.extend_from_slice(&dst_port.to_be_bytes());
        v
    }

    #[test]
    fn ipv4_tcp_outbound_maps_src_to_local() {
        let raw = ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], 0x4000, &ports(1111, 443));
        let pkt = parse(&raw, false).unwrap();
        assert_eq!(pkt.local_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(pkt.remote_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(pkt.local_port, 1111);
        assert_eq!(pkt.remote_port, 443);
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert!(!pkt.fragment);
    }

    #[test]
    fn ipv4_udp_inbound_swaps_local_and_remote() {
        let raw = ipv4(17, [10, 0, 0, 1], [10, 0, 0, 2], 0x4000, &ports(1111, 443));
        let pkt = parse(&raw, true).unwrap();
        // inbound: local=dst, remote=src, local_port=dst_port, remote_port=src_port
        assert_eq!(pkt.local_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(pkt.remote_addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(pkt.local_port, 443);
        assert_eq!(pkt.remote_port, 1111);
        assert_eq!(pkt.protocol, Protocol::Udp);
    }

    /// ICMP header: type, code, checksum:2, identifier:2, sequence:2.
    fn icmp(type_: u8, id: u16, seq: u16) -> Vec<u8> {
        let mut v = vec![type_, 0, 0, 0];
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&seq.to_be_bytes());
        v
    }

    #[test]
    fn ipv4_icmp_echo_carries_the_identifier_as_remote_port() {
        // ICMP has no ports, but the echo identifier distinguishes concurrent
        // ping flows, so conntrack keys on it (Go's parseV4, v1.11.0, #1602).
        // Without it every ICMP exchange between a host pair collapses onto a
        // single conntrack entry.
        let raw = ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], 0x4000, &icmp(8, 0xbeef, 1));
        let pkt = parse(&raw, false).unwrap();
        assert_eq!(pkt.protocol, Protocol::Icmp);
        assert_eq!(pkt.local_port, 0, "orientation doesn't matter for ICMP");
        assert_eq!(pkt.remote_port, 0xbeef);
    }

    #[test]
    fn ipv4_icmp_identifier_is_direction_independent() {
        let raw = ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], 0x4000, &icmp(0, 0xbeef, 1));
        let inbound = parse(&raw, true).unwrap();
        assert_eq!(inbound.local_port, 0);
        assert_eq!(inbound.remote_port, 0xbeef);
    }

    #[test]
    fn ipv4_icmp_truncated_before_the_identifier_is_rejected() {
        // Only type/code/checksum present — Go widens its minimum length by 2
        // for ICMP precisely so this can't read past the buffer.
        let raw = ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], 0x4000, &[8, 0, 0, 0]);
        assert!(parse(&raw, false).is_none());
    }

    #[test]
    fn ipv4_tcp_truncated_before_its_ports_is_rejected() {
        let raw = ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], 0x4000, &[0, 80]);
        assert!(parse(&raw, false).is_none());
    }

    #[test]
    fn ipv4_later_icmp_fragment_has_no_identifier() {
        // A non-first fragment carries no ICMP header to read.
        let raw = ipv4(1, [10, 0, 0, 1], [10, 0, 0, 2], 0x0025, &[]);
        let pkt = parse(&raw, false).unwrap();
        assert!(pkt.fragment);
        assert_eq!(pkt.local_port, 0);
        assert_eq!(pkt.remote_port, 0);
    }

    #[test]
    fn ipv4_more_fragments_flag_marks_fragment() {
        // MF bit (0x2000) set; ports still readable on the first fragment.
        let raw = ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], 0x2000, &ports(1111, 443));
        let pkt = parse(&raw, false).unwrap();
        assert!(pkt.fragment);
    }

    #[test]
    fn ipv4_nonzero_fragment_offset_marks_fragment_and_zeroes_ports() {
        // offset field non-zero (a later fragment) → no L4 header present.
        let raw = ipv4(6, [10, 0, 0, 1], [10, 0, 0, 2], 0x0025, &[]);
        let pkt = parse(&raw, false).unwrap();
        assert!(pkt.fragment);
        assert_eq!(pkt.local_port, 0);
        assert_eq!(pkt.remote_port, 0);
    }

    #[test]
    fn ipv4_truncated_is_rejected() {
        assert!(parse(&[0x45, 0x00, 0x00], false).is_none());
        assert!(parse(&[], false).is_none());
    }

    /// Minimal IPv6 header. `next_header` is whatever follows the 40-byte
    /// fixed header; `payload` is that next header's bytes.
    fn ipv6(next_header: u8, src: [u8; 16], dst: [u8; 16], payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes()); // payload length
        p.push(next_header);
        p.push(64); // hop limit
        p.extend_from_slice(&src);
        p.extend_from_slice(&dst);
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn ipv6_udp_outbound_maps_ports() {
        let src = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let raw = ipv6(17, src, dst, &ports(5353, 53));
        let pkt = parse(&raw, false).unwrap();
        assert_eq!(pkt.local_addr, IpAddr::V6(Ipv6Addr::from(src)));
        assert_eq!(pkt.remote_addr, IpAddr::V6(Ipv6Addr::from(dst)));
        assert_eq!(pkt.local_port, 5353);
        assert_eq!(pkt.remote_port, 53);
        assert_eq!(pkt.protocol, Protocol::Udp);
    }

    #[test]
    fn ipv6_icmpv6_echo_carries_the_identifier_as_remote_port() {
        let src = [0xfd; 16];
        let dst = [0xfe; 16];
        // Type 128 = echo request, code 0.
        let raw = ipv6(58, src, dst, &icmp(128, 0xcafe, 1));
        let pkt = parse(&raw, false).unwrap();
        assert_eq!(pkt.protocol, Protocol::IcmpV6);
        assert_eq!(pkt.local_port, 0);
        assert_eq!(pkt.remote_port, 0xcafe);
    }

    #[test]
    fn ipv6_icmpv6_echo_reply_carries_the_identifier_too() {
        let raw = ipv6(58, [0xfd; 16], [0xfe; 16], &icmp(129, 0xcafe, 1));
        assert_eq!(parse(&raw, true).unwrap().remote_port, 0xcafe);
    }

    #[test]
    fn ipv6_icmpv6_non_echo_type_has_zero_ports() {
        // Only echo request/reply carry an identifier; type 1 (destination
        // unreachable) has an unused word where the identifier would sit, so
        // reading it would key conntrack on garbage.
        let raw = ipv6(58, [0xfd; 16], [0xfe; 16], &icmp(1, 0xcafe, 0));
        let pkt = parse(&raw, false).unwrap();
        assert_eq!(pkt.protocol, Protocol::IcmpV6);
        assert_eq!(pkt.local_port, 0);
        assert_eq!(pkt.remote_port, 0);
    }

    #[test]
    fn ipv6_icmpv6_truncated_before_the_identifier_is_rejected() {
        let raw = ipv6(58, [0xfd; 16], [0xfe; 16], &[128, 0, 0, 0]);
        assert!(parse(&raw, false).is_none());
    }

    #[test]
    fn ipv6_fragment_header_marks_fragment_and_reads_inner_protocol() {
        // Fragment ext header (next_header=44): 8 bytes
        // [inner_nh, reserved, frag_off_hi, frag_off_lo, id x4], then TCP ports.
        let src = [0xfd; 16];
        let dst = [0xfe; 16];
        let mut payload = vec![6u8, 0, 0, 0, 0, 0, 0, 0]; // inner_nh=6 (TCP)
        payload.extend_from_slice(&ports(1234, 80));
        let raw = ipv6(44, src, dst, &payload);
        let pkt = parse(&raw, false).unwrap();
        assert!(pkt.fragment);
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.local_port, 1234);
        assert_eq!(pkt.remote_port, 80);
    }

    #[test]
    fn ipv6_later_fragment_does_not_read_payload_as_ports() {
        // Fragment ext header with a non-zero offset: the bytes after it are
        // payload continuation, not a TCP header. Reading them would give
        // every later fragment a distinct conntrack key.
        let mut payload = vec![6u8, 0]; // inner_nh = 6 (TCP)
        payload.extend_from_slice(&(0x00b8u16).to_be_bytes()); // frag offset != 0
        payload.extend_from_slice(&[0, 0, 0, 0]); // identification
        payload.extend_from_slice(&ports(0xdead, 0xbeef)); // payload, not ports
        let raw = ipv6(44, [0xfd; 16], [0xfe; 16], &payload);

        let pkt = parse(&raw, false).unwrap();
        assert!(pkt.fragment);
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.local_port, 0);
        assert_eq!(pkt.remote_port, 0);
    }

    #[test]
    fn ipv6_truncated_is_rejected() {
        assert!(parse(&[0x60, 0, 0, 0, 0, 0], false).is_none());
    }

    #[test]
    fn unknown_ip_version_is_rejected() {
        assert!(parse(&[0x35, 0, 0, 0], false).is_none());
    }
}
