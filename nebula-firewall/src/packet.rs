use std::net::IpAddr;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
    Other(u8),
}

// `PartialOrd`/`Ord` are needed so `Packet` can be a tiebreaker key inside
// `conntrack::Conntrack`'s `BinaryHeap<Reverse<(Instant, Packet)>>` (the
// heap only really orders by `Instant`; the derived Packet ordering just
// needs to be a valid total order to satisfy the bound, not any particular
// meaningful sequence).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct Packet {
    pub local_addr: IpAddr,
    pub remote_addr: IpAddr,
    pub local_port: u16,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub fragment: bool,
}

impl From<u8> for Protocol {
    fn from(v: u8) -> Self {
        match v {
            0 => Protocol::Any,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            1 => Protocol::Icmp,
            58 => Protocol::IcmpV6,
            other => Protocol::Other(other),
        }
    }
}

impl Protocol {
    pub fn as_u8(&self) -> u8 {
        match self {
            Protocol::Any => 0,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmp => 1,
            Protocol::IcmpV6 => 58,
            Protocol::Other(v) => *v,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn known_protocol_numbers_round_trip() {
        for (num, proto) in [
            (0u8, Protocol::Any),
            (6, Protocol::Tcp),
            (17, Protocol::Udp),
            (1, Protocol::Icmp),
            (58, Protocol::IcmpV6),
        ] {
            assert_eq!(Protocol::from(num), proto);
            assert_eq!(proto.as_u8(), num);
        }
    }

    #[test]
    fn unrecognized_protocol_number_round_trips_via_other() {
        assert_eq!(Protocol::from(132), Protocol::Other(132));
        assert_eq!(Protocol::Other(132).as_u8(), 132);
    }

    #[test]
    fn packet_is_usable_as_a_hashmap_key() {
        let p = Packet {
            local_addr: "10.0.0.1".parse().unwrap(),
            remote_addr: "10.0.0.2".parse().unwrap(),
            local_port: 10,
            remote_port: 90,
            protocol: Protocol::Udp,
            fragment: false,
        };
        let mut m = HashMap::new();
        m.insert(p, "flow-a");
        assert_eq!(m.get(&p), Some(&"flow-a"));
    }
}
