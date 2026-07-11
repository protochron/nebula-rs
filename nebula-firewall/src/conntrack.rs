use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap};
use std::time::{Duration, Instant};

use crate::packet::Packet;

#[derive(Clone, Copy, Debug)]
struct ConnEntry {
    expires: Instant,
    incoming: bool,
    rules_version: u16,
}

/// Tracks flows that have already passed rule evaluation so subsequent
/// packets can skip it until the entry expires, mirroring Go's
/// `FirewallConntrack` + `TimerWheel`. Expiry is purged lazily — only when
/// some packet drives a call into this table, matching Go's own behavior
/// (there is no background ticker; `TimerWheel.Purge()` only ever runs
/// from inside `inConns`).
#[derive(Default)]
pub(crate) struct Conntrack {
    conns: HashMap<Packet, ConnEntry>,
    // Lazy-deletion min-heap for expiry ordering, kept at ~one entry per
    // live flow like Go's TimerWheel. A heap entry is pushed only when a
    // flow is first recorded; a refresh extends `conns[packet].expires` in
    // place without pushing. When an entry is popped, it is compared to the
    // flow's current `expires`: if the flow already expired it is removed,
    // if it was refreshed past this slot it is re-pushed at its current
    // expiry (mirroring Go's `evict` re-add), and if the flow is gone the
    // stale entry is discarded.
    expiry_heap: BinaryHeap<Reverse<(Instant, Packet)>>,
}

impl Conntrack {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Removes any entries whose expiry is at or before `now`. A flow that
    /// was refreshed after its heap slot was scheduled is re-scheduled at
    /// its current expiry rather than dropped, so refreshes never need to
    /// push a new heap entry (keeping the heap bounded on busy flows).
    pub(crate) fn purge_expired(&mut self, now: Instant) {
        while let Some(Reverse((expires, _))) = self.expiry_heap.peek() {
            if *expires > now {
                break;
            }
            let Reverse((_, packet)) = self.expiry_heap.pop().unwrap();
            match self.conns.get(&packet) {
                Some(entry) if entry.expires <= now => {
                    self.conns.remove(&packet);
                }
                Some(entry) => {
                    // Refreshed past this slot: reschedule, don't drop.
                    let next = entry.expires;
                    self.expiry_heap.push(Reverse((next, packet)));
                }
                None => {} // flow already gone; discard stale slot
            }
        }
    }

    /// Looks up `packet`, purging expired entries first. Returns
    /// `(incoming, rules_version)` if a live entry exists.
    pub(crate) fn get(&mut self, packet: &Packet, now: Instant) -> Option<(bool, u16)> {
        self.purge_expired(now);
        self.conns
            .get(packet)
            .map(|e| (e.incoming, e.rules_version))
    }

    /// Records (or refreshes) a passing flow. A heap slot is scheduled only
    /// when the flow is newly tracked; a refresh just extends `expires` in
    /// place (see `purge_expired`), matching Go's `addConn`, which only
    /// touches the TimerWheel when the conn is new.
    pub(crate) fn record(
        &mut self,
        packet: Packet,
        incoming: bool,
        rules_version: u16,
        now: Instant,
        timeout: Duration,
    ) {
        let expires = now + timeout;
        let is_new = !self.conns.contains_key(&packet);
        self.conns.insert(
            packet,
            ConnEntry {
                expires,
                incoming,
                rules_version,
            },
        );
        if is_new {
            self.expiry_heap.push(Reverse((expires, packet)));
        }
    }

    pub(crate) fn remove(&mut self, packet: &Packet) {
        self.conns.remove(packet);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(port: u16) -> Packet {
        use crate::packet::Protocol;
        Packet {
            local_addr: "10.0.0.1".parse().unwrap(),
            remote_addr: "10.0.0.2".parse().unwrap(),
            local_port: port,
            remote_port: 90,
            protocol: Protocol::Udp,
            fragment: false,
        }
    }

    #[test]
    fn record_then_get_within_timeout_returns_the_entry() {
        let mut ct = Conntrack::new();
        let p = packet(1);
        let t0 = Instant::now();
        ct.record(p, true, 3, t0, Duration::from_secs(10));
        assert_eq!(ct.get(&p, t0 + Duration::from_secs(5)), Some((true, 3)));
    }

    #[test]
    fn get_after_expiry_returns_none_and_purges() {
        let mut ct = Conntrack::new();
        let p = packet(1);
        let t0 = Instant::now();
        ct.record(p, true, 0, t0, Duration::from_secs(10));
        assert_eq!(ct.get(&p, t0 + Duration::from_secs(11)), None);
    }

    #[test]
    fn unknown_flow_returns_none() {
        let mut ct = Conntrack::new();
        assert_eq!(ct.get(&packet(1), Instant::now()), None);
    }

    #[test]
    fn purge_expired_removes_only_entries_at_or_before_now() {
        let mut ct = Conntrack::new();
        let t0 = Instant::now();
        ct.record(packet(1), true, 0, t0, Duration::from_secs(5)); // expires t0+5
        ct.record(packet(2), true, 0, t0, Duration::from_secs(50)); // expires t0+50
        ct.purge_expired(t0 + Duration::from_secs(6));
        assert_eq!(ct.get(&packet(1), t0 + Duration::from_secs(6)), None);
        assert_eq!(
            ct.get(&packet(2), t0 + Duration::from_secs(6)),
            Some((true, 0))
        );
    }

    #[test]
    fn remove_evicts_immediately() {
        let mut ct = Conntrack::new();
        let p = packet(1);
        let t0 = Instant::now();
        ct.record(p, true, 0, t0, Duration::from_secs(10));
        ct.remove(&p);
        assert_eq!(ct.get(&p, t0), None);
    }

    #[test]
    fn refreshing_a_flow_survives_the_original_expiry() {
        // When a flow is refreshed with a later expiry, its original heap
        // slot must reschedule (not evict) the flow when it pops.
        let mut ct = Conntrack::new();
        let p = packet(1);
        let t0 = Instant::now();
        ct.record(p, true, 0, t0, Duration::from_secs(10)); // expires t0+10
        ct.record(
            p,
            true,
            0,
            t0 + Duration::from_secs(5),
            Duration::from_secs(10),
        ); // expires t0+15

        ct.purge_expired(t0 + Duration::from_secs(10));
        assert_eq!(
            ct.get(&p, t0 + Duration::from_secs(10)),
            Some((true, 0)),
            "refreshed flow must survive its original expiry"
        );

        ct.purge_expired(t0 + Duration::from_secs(16));
        assert_eq!(
            ct.get(&p, t0 + Duration::from_secs(16)),
            None,
            "flow must expire at its refreshed expiry"
        );
    }

    #[test]
    fn repeated_refreshes_do_not_grow_the_expiry_heap() {
        // The whole point of the push-only-on-insert design: a busy flow
        // refreshed thousands of times keeps a single heap slot, matching
        // Go's TimerWheel (which schedules a timer only for new conns).
        let mut ct = Conntrack::new();
        let p = packet(1);
        let t0 = Instant::now();
        for i in 0..1000 {
            ct.record(
                p,
                true,
                0,
                t0 + Duration::from_secs(i),
                Duration::from_secs(60),
            );
        }
        assert_eq!(
            ct.expiry_heap.len(),
            1,
            "refreshes must not accumulate heap entries"
        );
    }

    #[test]
    fn tracks_ipv6_flows() {
        // Packet keys on IpAddr, so v6 tuples must round-trip through the
        // conntrack table just like v4 (the primary consumer is v6-focused).
        use crate::packet::Protocol;
        let p = Packet {
            local_addr: "fd12::34".parse().unwrap(),
            remote_addr: "fd12::56".parse().unwrap(),
            local_port: 10,
            remote_port: 90,
            protocol: Protocol::IcmpV6,
            fragment: false,
        };
        let mut ct = Conntrack::new();
        let t0 = Instant::now();
        ct.record(p, true, 7, t0, Duration::from_secs(10));
        assert_eq!(ct.get(&p, t0 + Duration::from_secs(5)), Some((true, 7)));
    }
}
