//! The router: one step of the packet loop.
//!
//! [`Router::work`] takes one packet off the input queue and decides what happens to it.
//! It is a *step*, not a loop — the caller owns the thread, which is what both firmware
//! consumers do anyway (neither uses libcsp's own `csp_route_start_task`).
//!
//! # An idle tick is not an error
//!
//! `csp_route_work` returns an error code when the queue is empty, so every caller has to
//! filter a normal tick. The Rust code that wraps it carries the comment
//! *"RDP fires TimedOut every 100 ms when idle."* Here an empty queue is
//! [`Routed::Idle`] — a perfectly ordinary outcome — and [`Router::work`] returns
//! `Result` only for things that are genuinely wrong.
//!
//! # Nothing is dropped silently
//!
//! Every packet that does not get delivered comes back as [`Routed::Dropped`] with a
//! [`DropReason`]. The C increments one of ten `uint8_t` counters, which wrap at 256 and
//! are written from ISR and task context without synchronisation.

use crate::conn::{self, Handle};
use crate::dedup::Dedup;
use crate::pool::{Packet, Pool};
use crate::qfifo::Qfifo;
use csp_core::{Id, Version};

#[cfg(feature = "rtable")]
use csp_core::rtable;

/// What one step of the bridge did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bridged {
    /// Nothing waiting. Ordinary.
    Idle,
    /// The packet should be sent out the opposing interface.
    Forward {
        /// Interface to send on.
        iface: u8,
    },
    /// The packet went no further.
    Dropped(DropReason),
}

/// What one step of the router did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Routed {
    /// The queue was empty. An ordinary outcome, not a failure.
    Idle,
    /// The packet was queued onto a connection for a bound port.
    Delivered {
        /// Destination port.
        port: u8,
        /// Which connection it went to.
        conn: Handle,
    },
    /// The packet was addressed elsewhere and handed to an interface.
    Forwarded {
        /// Interface index.
        iface: u8,
        /// Next hop, or [`rtable::NO_VIA`] for a direct delivery.
        via: u16,
    },
    /// The packet went no further.
    Dropped(DropReason),
}

/// Why a packet was not delivered.
///
/// Distinguishable on purpose: "no route" and "port not bound" and "the receiving
/// connection's queue was full" are three very different operational problems, and the C
/// reports the last two through the same `uint8_t` counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// Seen within the deduplication window.
    Duplicate,
    /// No routing table entry matched, and it is not for us.
    NoRoute,
    /// For us, but nothing is bound to that port.
    PortNotBound,
    /// For us and bound, but every connection slot is in use.
    ConnectionTableFull,
    /// The receiving connection's queue was full.
    ReceiveQueueFull,
    /// The frame did not decode.
    Malformed,
}

/// Counters the router keeps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct Counters {
    pub delivered: u32,
    pub forwarded: u32,
    pub duplicates: u32,
    pub no_route: u32,
    pub port_not_bound: u32,
    pub conn_table_full: u32,
    pub rx_queue_full: u32,
    pub malformed: u32,
}

/// The mutable half of a node: everything the router touches.
///
/// Held by value, not in statics. Two routers in one process share nothing.
#[derive(Debug)]
pub struct Router<const CONNS: usize, const RXQ: usize, const PORTS: usize, const QF: usize> {
    /// Input queue.
    pub qfifo: Qfifo<QF>,
    /// Connection table.
    pub conns: conn::Table<CONNS, RXQ>,
    /// Duplicate suppression.
    pub dedup: Dedup,
    /// Whether duplicate suppression is on.
    pub dedup_enabled: bool,
    /// Routing table.
    #[cfg(feature = "rtable")]
    pub routes: rtable::Table<16>,
    /// Bound ports.
    bound: [bool; PORTS],
    /// Promiscuous tap: slot indices of cloned packets awaiting collection.
    promisc: [Option<u16>; 8],
    promisc_len: usize,
    promisc_enabled: bool,
    promisc_missed: u32,
    /// Counters.
    pub counters: Counters,
    /// Connections delivered to but not yet accepted by the application.
    ///
    /// One queue, not one per port: every consumer of the C binds `CSP_ANY` and dispatches
    /// on the destination port itself, so per-port accept queues would be dead weight.
    accept: [Option<Handle>; 8],
    accept_len: usize,
    accept_missed: u32,
    address: u16,
    version: Version,
}

impl<const CONNS: usize, const RXQ: usize, const PORTS: usize, const QF: usize>
    Router<CONNS, RXQ, PORTS, QF>
{
    /// Compile-time invariants for the router's fixed-capacity tables.
    const SANITY: () = {
        assert!(PORTS > 0, "a node needs at least one bindable port");
        assert!(
            PORTS <= 256,
            "ports are addressed by u8; a table larger than 256 is unreachable"
        );
    };

    /// A router for a node at `address` speaking `version`.
    pub fn new(address: u16, version: Version) -> Self {
        let () = Self::SANITY;
        Router {
            qfifo: Qfifo::new(),
            conns: conn::Table::new(),
            dedup: Dedup::new(),
            dedup_enabled: false,
            #[cfg(feature = "rtable")]
            routes: rtable::Table::new(version),
            bound: [false; PORTS],
            promisc: [None; 8],
            promisc_len: 0,
            promisc_enabled: false,
            promisc_missed: 0,
            counters: Counters::default(),
            accept: [None; 8],
            accept_len: 0,
            accept_missed: 0,
            address,
            version,
        }
    }

    /// Bind a port so packets for it are delivered rather than dropped.
    pub fn bind(&mut self, port: u8) -> csp_core::Result<()> {
        let i = port as usize;
        if i >= PORTS {
            return Err(csp_core::Error::FieldOutOfRange {
                field: csp_core::Field::DestinationPort,
            });
        }
        if self.bound[i] {
            return Err(csp_core::Error::TableFull);
        }
        self.bound[i] = true;
        Ok(())
    }

    /// Release a port.
    pub fn unbind(&mut self, port: u8) {
        if (port as usize) < PORTS {
            self.bound[port as usize] = false;
        }
    }

    /// True if `port` is bound.
    pub fn is_bound(&self, port: u8) -> bool {
        (port as usize) < PORTS && self.bound[port as usize]
    }

    /// Turn the promiscuous tap on or off.
    pub fn set_promisc(&mut self, on: bool) {
        self.promisc_enabled = on;
    }

    /// Packets the tap could not hold because its queue was full.
    ///
    /// The C's tap drops silently.
    pub const fn promisc_missed(&self) -> u32 {
        self.promisc_missed
    }

    /// Collect a packet from the promiscuous tap, if any.
    pub fn promisc_read<'p, const B: usize, const SZ: usize>(
        &mut self,
        pool: &'p Pool<B, SZ>,
    ) -> Option<Packet<'p, B, SZ>> {
        if self.promisc_len == 0 {
            return None;
        }
        for slot in self.promisc.iter_mut() {
            if let Some(idx) = slot.take() {
                self.promisc_len -= 1;
                return pool.from_index(idx);
            }
        }
        None
    }

    /// Take the next connection with data waiting, if any.
    ///
    /// Returns `None` rather than blocking; the caller owns the thread.
    pub fn accept(&mut self) -> Option<Handle> {
        if self.accept_len == 0 {
            return None;
        }
        for slot in self.accept.iter_mut() {
            if let Some(h) = slot.take() {
                self.accept_len -= 1;
                return Some(h);
            }
        }
        None
    }

    /// Connections that could not be queued for accept because the backlog was full.
    pub const fn accept_missed(&self) -> u32 {
        self.accept_missed
    }

    fn queue_accept(&mut self, h: Handle) {
        // Already waiting? A second packet on the same connection must not enqueue it
        // twice, or accept() hands the same connection to two callers.
        if self.accept.iter().flatten().any(|&e| e == h) {
            return;
        }
        if self.accept_len >= self.accept.len() {
            self.accept_missed += 1;
            return;
        }
        for slot in self.accept.iter_mut() {
            if slot.is_none() {
                *slot = Some(h);
                self.accept_len += 1;
                return;
            }
        }
    }

    /// Inject a received packet, as a driver does.
    ///
    /// Takes ownership. If the queue is full the packet is released and counted; it is
    /// never silently retained.
    pub fn receive<const B: usize, const SZ: usize>(
        &mut self,
        packet: Packet<'_, B, SZ>,
        iface: u8,
    ) -> bool {
        self.qfifo.push(packet, iface)
    }

    /// One step of the router.
    ///
    /// Returns [`Routed::Idle`] when there is nothing to do, which is not an error.
    pub fn work<'p, const B: usize, const SZ: usize>(
        &mut self,
        pool: &'p Pool<B, SZ>,
        now_ms: u32,
    ) -> Routed {
        let Some((packet, _iface)) = self.qfifo.pop(pool) else {
            return Routed::Idle;
        };

        // Deduplicate on the framed bytes, matching the C, which prepends the header
        // before checksumming.
        if self.dedup_enabled {
            let mut framed = packet;
            if framed.prepend_header(self.version).is_err() {
                self.counters.malformed += 1;
                return Routed::Dropped(DropReason::Malformed);
            }
            let dup = framed.with_frame(|f| self.dedup.is_duplicate(f, now_ms));
            if dup {
                self.counters.duplicates += 1;
                return Routed::Dropped(DropReason::Duplicate);
            }
            return self.route_one(pool, framed, now_ms);
        }

        self.route_one(pool, packet, now_ms)
    }

    fn route_one<'p, const B: usize, const SZ: usize>(
        &mut self,
        pool: &'p Pool<B, SZ>,
        packet: Packet<'p, B, SZ>,
        now_ms: u32,
    ) -> Routed {
        let id = packet.id();

        // The promiscuous tap sees a *copy*, so it can never affect delivery. The C's tap
        // clones too, but drops silently when its queue is full.
        if self.promisc_enabled {
            if self.promisc_len < self.promisc.len() {
                if let Some(copy) = packet.deep_copy() {
                    for slot in self.promisc.iter_mut() {
                        if slot.is_none() {
                            *slot = Some(copy.into_index());
                            self.promisc_len += 1;
                            break;
                        }
                    }
                } else {
                    self.promisc_missed += 1;
                }
            } else {
                self.promisc_missed += 1;
            }
        }

        if id.dst == self.address || self.version.is_broadcast(id.dst, self.address, 0) {
            return self.deliver_local(packet, id, now_ms);
        }
        self.forward(pool, packet, id)
    }

    fn deliver_local<'p, const B: usize, const SZ: usize>(
        &mut self,
        packet: Packet<'p, B, SZ>,
        id: Id,
        now_ms: u32,
    ) -> Routed {
        if !self.is_bound(id.dport) {
            self.counters.port_not_bound += 1;
            return Routed::Dropped(DropReason::PortNotBound);
        }

        let handle = match self.conns.find(&id) {
            Some(h) => h,
            None => {
                let reply = Id {
                    pri: id.pri,
                    flags: id.flags,
                    src: self.address,
                    dst: id.src,
                    dport: id.sport,
                    sport: id.dport,
                };
                match self.conns.alloc(reply, 0, now_ms) {
                    Ok(h) => {
                        let _ = self.conns.set_id_in(h, id);
                        h
                    }
                    Err(_) => {
                        self.counters.conn_table_full += 1;
                        return Routed::Dropped(DropReason::ConnectionTableFull);
                    }
                }
            }
        };

        let _ = self.conns.touch(handle, now_ms);
        match self.conns.enqueue_rx(handle, packet.into_index()) {
            Ok(true) => {
                self.counters.delivered += 1;
                self.queue_accept(handle);
                Routed::Delivered {
                    port: id.dport,
                    conn: handle,
                }
            }
            _ => {
                self.counters.rx_queue_full += 1;
                Routed::Dropped(DropReason::ReceiveQueueFull)
            }
        }
    }

    #[cfg(feature = "rtable")]
    fn forward<'p, const B: usize, const SZ: usize>(
        &mut self,
        _pool: &'p Pool<B, SZ>,
        packet: Packet<'p, B, SZ>,
        id: Id,
    ) -> Routed {
        match self.routes.find(id.dst) {
            Some(r) => {
                let (iface, via) = (r.iface, r.via);
                drop(packet); // the caller re-sends via the interface; see Csp::forward
                self.counters.forwarded += 1;
                Routed::Forwarded { iface, via }
            }
            None => {
                self.counters.no_route += 1;
                Routed::Dropped(DropReason::NoRoute)
            }
        }
    }

    #[cfg(not(feature = "rtable"))]
    fn forward<'p, const B: usize, const SZ: usize>(
        &mut self,
        _pool: &'p Pool<B, SZ>,
        _packet: Packet<'p, B, SZ>,
        _id: Id,
    ) -> Routed {
        self.counters.no_route += 1;
        Routed::Dropped(DropReason::NoRoute)
    }

    /// Periodic maintenance: expire idle connections and step the RDP timers.
    ///
    /// Returns how many connections were closed. Must be called regularly — the RDP state
    /// machine reads no clock on purpose, so nothing else advances its timers.
    pub fn tick<const B: usize, const SZ: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        now_ms: u32,
        conn_timeout_ms: u32,
    ) -> usize {
        let mut drained = [0u16; 32];
        let (closed, n) = self.conns.expire_idle(now_ms, conn_timeout_ms, &mut drained);
        for &idx in &drained[..n] {
            drop(pool.from_index(idx));
        }

        #[cfg(feature = "rdp")]
        let closed = closed + self.conns.tick_rdp(now_ms, 5);

        closed
    }

    /// One step of a transparent bridge between two interfaces.
    ///
    /// Everything arriving on `a` goes out `b` and vice versa, with no routing decision.
    /// Deduplication still applies, because a bridge is exactly where a packet loops.
    ///
    /// Returns [`Bridged::Idle`] on an empty queue. The C prints a message and returns
    /// void when the interfaces are unset, so a caller cannot tell a misconfigured bridge
    /// from an idle one; here the pair is a parameter and cannot be unset.
    pub fn bridge_work<'p, const B: usize, const SZ: usize>(
        &mut self,
        pool: &'p Pool<B, SZ>,
        a: u8,
        b: u8,
        now_ms: u32,
    ) -> Bridged {
        let Some((mut packet, iface)) = self.qfifo.pop(pool) else {
            return Bridged::Idle;
        };

        if self.dedup_enabled {
            if packet.prepend_header(self.version).is_err() {
                self.counters.malformed += 1;
                return Bridged::Dropped(DropReason::Malformed);
            }
            let dup = packet.with_frame(|f| self.dedup.is_duplicate(f, now_ms));
            if dup {
                self.counters.duplicates += 1;
                return Bridged::Dropped(DropReason::Duplicate);
            }
        }

        if self.promisc_enabled && self.promisc_len < self.promisc.len() {
            if let Some(copy) = packet.deep_copy() {
                for slot in self.promisc.iter_mut() {
                    if slot.is_none() {
                        *slot = Some(copy.into_index());
                        self.promisc_len += 1;
                        break;
                    }
                }
            } else {
                self.promisc_missed += 1;
            }
        }

        // A frame from neither side of the bridge has no opposing interface. The C picks
        // bif_a in that case, because its `if (input.iface == bif_a) else` has no third
        // branch -- so a packet from an unrelated interface is injected into side A.
        let out = if iface == a {
            b
        } else if iface == b {
            a
        } else {
            self.counters.no_route += 1;
            return Bridged::Dropped(DropReason::NoRoute);
        };

        self.counters.forwarded += 1;
        Bridged::Forward { iface: out }
    }

    /// Release everything the router is holding.
    pub fn shutdown<const B: usize, const SZ: usize>(&mut self, pool: &Pool<B, SZ>) {
        self.qfifo.drain(pool);
        while self.promisc_read(pool).is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type P = Pool<16, 264>;
    type R = Router<4, 4, 48, 8>;

    const ME: u16 = 11;

    fn pkt<'p>(pool: &'p P, dst: u16, dport: u8, payload: &[u8]) -> Packet<'p, 16, 264> {
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst,
            dport,
            sport: 10,
        });
        p.set_payload(payload).unwrap();
        p
    }

    #[test]
    fn an_empty_queue_is_idle_not_an_error() {
        // csp_route_work returns an error here, so every caller has to filter a normal
        // tick. SCOPE.md deviation 6.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        assert_eq!(r.work(&pool, 0), Routed::Idle);
        assert_eq!(r.work(&pool, 100), Routed::Idle);
    }

    #[test]
    fn a_packet_for_a_bound_port_is_delivered() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.receive(pkt(&pool, ME, 20, b"hello"), 0);

        match r.work(&pool, 0) {
            Routed::Delivered { port, conn } => {
                assert_eq!(port, 20);
                assert_eq!(r.conns.rx_len(conn).unwrap(), 1);
            }
            other => panic!("expected delivery, got {other:?}"),
        }
        assert_eq!(r.counters.delivered, 1);
    }

    #[test]
    fn an_unbound_port_is_dropped_with_that_reason() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.receive(pkt(&pool, ME, 39, b"nobody home"), 0);
        assert_eq!(
            r.work(&pool, 0),
            Routed::Dropped(DropReason::PortNotBound),
            "must say WHY, not just fail"
        );
        assert_eq!(r.counters.port_not_bound, 1);
        assert_eq!(pool.available(), 16, "and must not leak the packet");
    }

    #[test]
    fn a_packet_for_someone_else_with_no_route_is_dropped() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.receive(pkt(&pool, 25, 20, b"elsewhere"), 0);
        assert_eq!(r.work(&pool, 0), Routed::Dropped(DropReason::NoRoute));
        assert_eq!(r.counters.no_route, 1);
        assert_eq!(pool.available(), 16);
    }

    #[cfg(feature = "rtable")]
    #[test]
    fn a_packet_for_someone_else_with_a_route_is_forwarded() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.routes.set(0, 0, 3, rtable::NO_VIA).unwrap();
        r.receive(pkt(&pool, 25, 20, b"elsewhere"), 0);
        match r.work(&pool, 0) {
            Routed::Forwarded { iface, .. } => assert_eq!(iface, 3),
            other => panic!("expected forwarding, got {other:?}"),
        }
        assert_eq!(r.counters.forwarded, 1);
    }

    #[test]
    fn duplicates_are_suppressed_when_enabled() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.dedup_enabled = true;

        r.receive(pkt(&pool, ME, 20, b"same"), 0);
        assert!(matches!(r.work(&pool, 0), Routed::Delivered { .. }));

        r.receive(pkt(&pool, ME, 20, b"same"), 0);
        assert_eq!(r.work(&pool, 10), Routed::Dropped(DropReason::Duplicate));
        assert_eq!(r.counters.duplicates, 1);
    }

    #[test]
    fn deduplication_is_off_unless_asked_for() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        for _ in 0..2 {
            r.receive(pkt(&pool, ME, 20, b"same"), 0);
            assert!(matches!(r.work(&pool, 0), Routed::Delivered { .. }));
        }
        assert_eq!(r.counters.duplicates, 0);
    }

    #[test]
    fn a_full_connection_table_is_reported_distinctly() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        // Four distinct peers fill the four connection slots.
        for sport in 0..4u8 {
            let mut p = pool.acquire(0).unwrap();
            p.set_id(Id { pri: 2, flags: 0, src: 8, dst: ME, dport: 20, sport });
            p.set_payload(b"x").unwrap();
            r.receive(p, 0);
            assert!(matches!(r.work(&pool, 0), Routed::Delivered { .. }));
        }
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id { pri: 2, flags: 0, src: 8, dst: ME, dport: 20, sport: 9 });
        p.set_payload(b"x").unwrap();
        r.receive(p, 0);
        assert_eq!(
            r.work(&pool, 0),
            Routed::Dropped(DropReason::ConnectionTableFull)
        );
        assert_eq!(r.counters.conn_table_full, 1);
    }

    #[test]
    fn a_full_receive_queue_is_reported_distinctly() {
        // Distinct from "port not bound" and "no route", which the C conflates.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        for _ in 0..4 {
            r.receive(pkt(&pool, ME, 20, b"x"), 0);
            assert!(matches!(r.work(&pool, 0), Routed::Delivered { .. }));
        }
        r.receive(pkt(&pool, ME, 20, b"x"), 0);
        assert_eq!(r.work(&pool, 0), Routed::Dropped(DropReason::ReceiveQueueFull));
        assert_eq!(r.counters.rx_queue_full, 1);
    }

    #[test]
    fn the_promiscuous_tap_sees_a_copy_and_does_not_affect_delivery() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.set_promisc(true);

        r.receive(pkt(&pool, ME, 20, b"tapped"), 0);
        assert!(matches!(r.work(&pool, 0), Routed::Delivered { .. }));

        let seen = r.promisc_read(&pool).expect("the tap should have a copy");
        seen.with_payload(|d| assert_eq!(d, b"tapped"));
        assert!(r.promisc_read(&pool).is_none());
    }

    #[test]
    fn the_tap_counts_what_it_could_not_hold() {
        // The C's tap drops silently when its queue is full.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        // Port deliberately NOT bound: the packet is tapped, then dropped and released,
        // so the pool is not consumed and only the tap's own copies accumulate.
        r.set_promisc(true);
        for _ in 0..12 {
            r.receive(pkt(&pool, ME, 20, b"x"), 0);
            let _ = r.work(&pool, 0);
        }
        assert!(r.promisc_missed() > 0, "overflow must be counted, not silent");
    }

    #[test]
    fn idle_connections_are_reclaimed_by_the_tick() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.receive(pkt(&pool, ME, 20, b"x"), 0);
        assert!(matches!(r.work(&pool, 0), Routed::Delivered { .. }));
        assert_eq!(r.conns.open_count(), 1);

        assert_eq!(r.tick(&pool, 5_000, 10_000), 0, "not yet idle");
        let closed = r.tick(&pool, 30_000, 10_000);
        assert!(closed >= 1, "an idle connection must be reclaimed");
        assert_eq!(r.conns.open_count(), 0);
    }

    #[test]
    fn the_tick_releases_packets_still_queued_on_an_expiring_connection() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.receive(pkt(&pool, ME, 20, b"x"), 0);
        r.work(&pool, 0);
        assert_eq!(pool.available(), 15, "the delivered packet is held on the conn");

        r.tick(&pool, 30_000, 10_000);
        assert_eq!(pool.available(), 16, "expiry must release it, not leak it");
    }

    #[test]
    fn shutdown_releases_everything() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.set_promisc(true);
        r.bind(20).unwrap();
        for _ in 0..3 {
            r.receive(pkt(&pool, ME, 20, b"x"), 0);
        }
        r.work(&pool, 0);
        assert!(pool.available() < 16);

        // drain what is on connections too
        r.tick(&pool, 1_000_000, 1_000);
        r.shutdown(&pool);
        assert_eq!(pool.available(), 16, "nothing may survive shutdown");
    }

    #[test]
    fn a_full_input_queue_drops_and_counts() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        for _ in 0..8 {
            assert!(r.receive(pkt(&pool, ME, 20, b"x"), 0));
        }
        assert!(!r.receive(pkt(&pool, ME, 20, b"x"), 0), "queue is full");
        assert_eq!(r.qfifo.dropped(), 1);
    }

    #[test]
    fn the_bridge_sends_each_side_to_the_other() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.receive(pkt(&pool, 25, 20, b"a to b"), 1);
        assert_eq!(r.bridge_work(&pool, 1, 2, 0), Bridged::Forward { iface: 2 });
        r.receive(pkt(&pool, 25, 20, b"b to a"), 2);
        assert_eq!(r.bridge_work(&pool, 1, 2, 0), Bridged::Forward { iface: 1 });
    }

    #[test]
    fn the_bridge_is_idle_on_an_empty_queue() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        assert_eq!(r.bridge_work(&pool, 1, 2, 0), Bridged::Idle);
    }

    #[test]
    fn a_frame_from_neither_side_is_refused_not_injected_into_side_a() {
        // The C's `if (input.iface == bif_a) destif = bif_b; else destif = bif_a;` has no
        // third branch, so a packet arriving on an unrelated interface is forwarded into
        // side A as though it had come from B.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.receive(pkt(&pool, 25, 20, b"from elsewhere"), 7);
        assert_eq!(
            r.bridge_work(&pool, 1, 2, 0),
            Bridged::Dropped(DropReason::NoRoute)
        );
        assert_eq!(pool.available(), 16, "and must not leak it");
    }

    #[test]
    fn the_bridge_deduplicates() {
        // A bridge is exactly where a packet loops back on itself.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.dedup_enabled = true;
        r.receive(pkt(&pool, 25, 20, b"looping"), 1);
        assert_eq!(r.bridge_work(&pool, 1, 2, 0), Bridged::Forward { iface: 2 });
        r.receive(pkt(&pool, 25, 20, b"looping"), 1);
        assert_eq!(
            r.bridge_work(&pool, 1, 2, 5),
            Bridged::Dropped(DropReason::Duplicate)
        );
    }

    #[test]
    fn a_delivered_connection_becomes_acceptable() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        assert!(r.accept().is_none(), "nothing delivered yet");

        r.receive(pkt(&pool, ME, 20, b"hello"), 0);
        let conn = match r.work(&pool, 0) {
            Routed::Delivered { conn, .. } => conn,
            other => panic!("{other:?}"),
        };
        assert_eq!(r.accept(), Some(conn));
        assert!(r.accept().is_none(), "accepted once only");
    }

    #[test]
    fn a_second_packet_does_not_queue_the_same_connection_twice() {
        // Otherwise accept() hands the same connection to two callers, and both read
        // from the same queue.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        for _ in 0..3 {
            r.receive(pkt(&pool, ME, 20, b"x"), 0);
            r.work(&pool, 0);
        }
        assert!(r.accept().is_some());
        assert!(r.accept().is_none(), "one connection, one accept");
    }

    #[test]
    fn a_full_accept_backlog_is_counted_not_silent() {
        let pool = P::new();
        let mut r: Router<16, 4, 48, 32> = Router::new(ME, Version::V1);
        r.bind(20).unwrap();
        for sport in 0..12u8 {
            let mut p = pool.acquire(0).unwrap();
            p.set_id(Id { pri: 2, flags: 0, src: 8, dst: ME, dport: 20, sport });
            p.set_payload(b"x").unwrap();
            r.receive(p, 0);
            r.work(&pool, 0);
        }
        assert!(r.accept_missed() > 0, "backlog overflow must be counted");
    }

    #[test]
    fn two_routers_share_nothing() {
        let pa = P::new();
        let pb = P::new();
        let mut a = R::new(11, Version::V1);
        let mut b = R::new(12, Version::V1);
        a.bind(20).unwrap();

        a.receive(pkt(&pa, 11, 20, b"for a"), 0);
        assert!(matches!(a.work(&pa, 0), Routed::Delivered { .. }));
        assert_eq!(b.work(&pb, 0), Routed::Idle, "b saw nothing");
        assert_eq!(b.counters, Counters::default());
    }
}
