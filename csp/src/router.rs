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
use csp_core::security::{self, Refusal};
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
    /// The packet was addressed elsewhere and must go out on an interface.
    ///
    /// **The caller must send it.** `packet` is a pool slot index; turn it back into a
    /// [`Packet`] with [`Pool::from_index`] (or [`Node::take_forwarded`]) and hand it to
    /// the interface. Dropping the index without doing so leaks the buffer.
    ///
    /// This carries the packet index rather than the packet because [`Routed`] has no
    /// lifetime or size parameters. An earlier version reported `{ iface, via }` and
    /// *destroyed* the packet, pointing at a `Node::forward` that was never written — so
    /// every forwarded packet was silently discarded and the node forwarded nothing at
    /// all. Found by the node-level differential test against the C, which is the only
    /// thing that could have found it: the codec tests never reach the router, and the
    /// unit tests asserted on `iface`/`via` rather than on a frame reaching the wire.
    Forwarded {
        /// Interface index.
        iface: u8,
        /// Next hop, or [`rtable::NO_VIA`] for a direct delivery.
        via: u16,
        /// Pool slot holding the packet. The caller owns it.
        packet: u16,
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
    /// The endpoint's security policy refused it.
    ///
    /// Distinct from every other reason: this one means the packet arrived intact and was
    /// turned away on policy, which is an operational signal rather than a fault.
    Refused(Refusal),
}

/// How many interfaces one packet can be forwarded to at once.
///
/// `csp_send_direct` has no limit — it walks the whole interface list. Four is what a node
/// with redundant links plausibly has, and exceeding it is counted rather than ignored.
pub const MAX_FANOUT: usize = 4;

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
    /// Authentication failures, kept apart from `rx_error` as the C does.
    pub auth_error: u32,
    /// Other receive errors from the security policy.
    pub rx_error: u32,
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
    /// Which traffic duplicate suppression applies to. Off by default, as in the C.
    pub dedup_mode: crate::dedup::DedupMode,
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
    /// Forwards produced by one packet but not yet handed to the caller.
    ///
    /// `csp_send_direct` does not choose an interface: it iterates every match and clones
    /// the packet for each, so two links owning a destination carry two frames. `Routed`
    /// has nowhere to put a set, so the extras wait here and [`Router::work`] hands them
    /// out one per call — a step at a time, like everything else it does.
    pending_tx: [Option<(u8, u16, u16)>; MAX_FANOUT],
    pending_len: usize,
    /// Fan-out destinations dropped because the pool had no buffer to clone into.
    pending_missed: u32,
    /// Counters.
    pub counters: Counters,
    /// Options every bound port requires of incoming packets.
    ///
    /// The C keeps these per socket; one policy for the node is the shape both firmware
    /// consumers actually use, since each binds `CSP_ANY` once.
    pub endpoint_opts: u32,
    /// HMAC key, if one is configured.
    ///
    /// `None` means a packet claiming authentication cannot be verified, and is refused
    /// rather than trusted.
    pub hmac_key: Option<&'static [u8]>,
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
            dedup_mode: crate::dedup::DedupMode::Off,
            #[cfg(feature = "rtable")]
            routes: rtable::Table::new(version),
            bound: [false; PORTS],
            promisc: [None; 8],
            promisc_len: 0,
            promisc_enabled: false,
            promisc_missed: 0,
            pending_tx: [None; MAX_FANOUT],
            pending_len: 0,
            pending_missed: 0,
            counters: Counters::default(),
            endpoint_opts: 0,
            hmac_key: None,
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
    /// Stop accepting on a port, closing every server connection still open on it.
    ///
    /// Returns how many connections were closed and the slot indices to release.
    ///
    /// `csp_socket_close` drains the socket's queue for the same reason: without it a
    /// connection created before the unbind stays acceptable, and `accept` keeps handing
    /// out connections for a port nothing is serving any more.
    ///
    /// The C also stops after unbinding the **first** port that names the socket
    /// (`csp_port.c:145`, `break`), even though `csp_bind` happily binds one socket to
    /// several ports — it only checks that the *port* is free. So closing a socket bound
    /// to ports 10 and 11 leaves port 11 pointing at a socket whose queue has just been
    /// drained. Here a port is unbound by number, so the situation cannot arise.
    pub fn unbind(&mut self, port: u8, drained: &mut [u16]) -> (usize, usize) {
        if (port as usize) >= PORTS {
            return (0, 0);
        }
        self.bound[port as usize] = false;
        let r = self.conns.close_port(port, drained);
        self.purge_dead_accepts();
        r
    }

    /// Drop backlog entries whose connection is no longer open.
    ///
    /// The accept backlog holds handles, and a connection can be closed underneath one —
    /// by [`unbind`](Self::unbind) or by the idle sweep in [`tick`](Self::tick). Without
    /// this, `accept` hands out a handle that every later call rejects, and the caller has
    /// to learn the connection is dead by being told so three times.
    fn purge_dead_accepts(&mut self) {
        for slot in self.accept.iter_mut() {
            if let Some(h) = *slot {
                if !self.conns.is_live(h) {
                    *slot = None;
                    self.accept_len -= 1;
                }
            }
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
    pub fn work<const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        ifaces: &crate::iflist::IfList<N, A>,
        now_ms: u32,
    ) -> Routed {
        // A packet that fanned out to several interfaces is reported one at a time, so the
        // extras come out before the next input is looked at.
        if let Some(r) = self.pop_pending() {
            return r;
        }

        let Some((packet, ingress)) = self.qfifo.pop(pool) else {
            return Routed::Idle;
        };

        // Deduplication happens inside route_one, after "is this for me?" — the mode says
        // *which* traffic to deduplicate, so the answer is needed first.
        self.route_one(pool, packet, ifaces, ingress, now_ms)
    }

    #[allow(clippy::too_many_arguments)]
    fn route_one<'p, const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &'p Pool<B, SZ>,
        packet: Packet<'p, B, SZ>,
        ifaces: &crate::iflist::IfList<N, A>,
        ingress: u8,
        now_ms: u32,
    ) -> Routed {
        let id = packet.id();

        // "Is this for me?" — the C's `is_to_me`, which is three conditions, none of
        // them a single node address:
        //
        //   * **any** interface's address matches (`csp_iflist_get_by_addr`), so a node
        //     with a CAN interface and a KISS interface answers to both;
        //   * the destination is the broadcast address **of the interface it arrived on**
        //     (`csp_id_is_broadcast(dst, input.iface)`) — the ingress interface's subnet,
        //     not the node's;
        //   * or it is a bound alias (`csp_addr_is_alias`).
        //
        // This compared `id.dst` against one `self.address` and called `is_broadcast` with
        // a hardcoded netmask of `0`. A packet for the node's *other* interface therefore
        // failed the check, fell through to forwarding, and went back out on the wire —
        // measured against the C, which delivers it. `IfList::find_by_addr` covers the
        // interface addresses and the aliases together.
        let for_us = ifaces.find_by_addr(id.dst).is_some()
            || ifaces.is_broadcast_for(id.dst, ingress)
            || id.dst == self.address;

        // Deduplication, gated on the mode *and* on `for_us`, exactly where
        // csp_route.c:238 puts it: after the destination is known and before the tap, so a
        // duplicate never reaches the tap. Checksummed over the framed bytes, because the
        // C prepends the header first.
        let packet = if self.dedup_mode.applies(for_us) {
            let mut framed = packet;
            if framed.prepend_header(self.version).is_err() {
                self.counters.malformed += 1;
                return Routed::Dropped(DropReason::Malformed);
            }
            if framed.with_frame(|f| self.dedup.is_duplicate(f, now_ms)) {
                self.counters.duplicates += 1;
                return Routed::Dropped(DropReason::Duplicate);
            }
            framed
        } else {
            packet
        };

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

        if for_us {
            return self.deliver_local(packet, id, now_ms);
        }
        self.forward(pool, packet, id, ifaces, ingress)
    }

    fn deliver_local<'p, const B: usize, const SZ: usize>(
        &mut self,
        mut packet: Packet<'p, B, SZ>,
        id: Id,
        now_ms: u32,
    ) -> Routed {
        if !self.is_bound(id.dport) {
            self.counters.port_not_bound += 1;
            return Routed::Dropped(DropReason::PortNotBound);
        }

        // The endpoint's policy, before the application sees anything. This is the only
        // thing standing between a node configured to demand HMAC and an unauthenticated
        // peer -- and the "required but absent" half is silent when it is missing.
        let verified_len = packet.with_payload(|body| {
            security::check(
                self.endpoint_opts,
                &id,
                &[],
                body,
                csp_core::crc32::Coverage::PayloadOnly,
                self.hmac_key,
                security::Support::default(),
            )
            .map(|stripped| stripped.len())
        });
        match verified_len {
            Ok(n) => {
                // Drop whatever the policy stripped (CRC, MAC) so the application sees
                // only the payload.
                packet.with_payload_mut(|_| (n, ()));
            }
            Err(refusal) => {
                match refusal.counter() {
                    security::Counter::AuthError => self.counters.auth_error += 1,
                    security::Counter::RxError => self.counters.rx_error += 1,
                }
                return Routed::Dropped(DropReason::Refused(refusal));
            }
        }

        // `is_new` decides whether the application is told about this connection. The C
        // posts a connection to its socket once and immediately nulls `dest_socket`, with
        // the comment "Ensure that this connection will not be posted to this socket
        // again" — so a second packet joins a connection the application already holds
        // without announcing it a second time.
        let (handle, is_new) = match self.conns.find(&id) {
            Some(h) => (h, false),
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
                        (h, true)
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
                // Only on the first packet. This fired on *every* delivery, so an
                // application looping on `accept` was handed the same connection once per
                // packet — and since the backlog is a fixed array, one chatty peer filled
                // it with copies of itself and left every other peer's new connection with
                // nowhere to be announced. Measured against the C in
                // `ctest/suite_conn.c::a_connection_is_offered_to_the_application_only_once`.
                if is_new {
                    self.queue_accept(handle);
                }
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

    /// Decide where a packet that is not for us should go.
    ///
    /// Mirrors `csp_send_direct`'s precedence, which is **three levels, not one**:
    ///
    /// 1. **A local subnet.** Any interface whose subnet contains the destination wins,
    ///    and the routing table is then never consulted (`csp_io.c`: `if (local_found)
    ///    { ...; return; }`).
    /// 2. **The routing table**, for destinations no interface owns.
    /// 3. **The default interfaces**, if no route matched.
    ///
    /// Each level applies split horizon, and each is *terminal*: if a level matched but
    /// split horizon left nothing usable, the packet is dropped rather than falling
    /// through to the next. That is what the C's `local_found` / `route_found` flags do.
    ///
    /// An earlier version began at the routing table, so a route could divert traffic the
    /// C would have put straight onto the interface owning that subnet. Found by a
    /// node-level differential test — and only after it was strengthened to compare
    /// *which interface* the frame left by, because the frame **bytes** are identical
    /// either way and the byte-only version of the test passed.
    #[cfg(feature = "rtable")]
    fn forward<'p, const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        _pool: &'p Pool<B, SZ>,
        packet: Packet<'p, B, SZ>,
        id: Id,
        ifaces: &crate::iflist::IfList<N, A>,
        ingress: u8,
    ) -> Routed {
        // Every match, not the last one seen. `csp_send_direct` sends to all of them.
        let mut dests: [(u8, u16); MAX_FANOUT] = [(0, 0); MAX_FANOUT];
        let mut n_dests = 0usize;
        let mut push = |d: (u8, u16), n: &mut usize| {
            if *n < MAX_FANOUT {
                dests[*n] = d;
                *n += 1;
            }
        };

        // 1. A local subnet owns the destination.
        let mut local_found = false;
        for idx in ifaces.indices() {
            if !ifaces.is_within_subnet(id.dst, idx) {
                continue;
            }
            local_found = true;
            if Self::split_horizon(ifaces, idx, ingress) {
                continue;
            }
            push((idx, rtable::NO_VIA), &mut n_dests);
        }
        if local_found {
            return self.finish_forward(&dests[..n_dests], packet);
        }

        // 2. The routing table.
        let mut route_found = false;
        let placeholder = rtable::Route {
            address: 0,
            netmask: 0,
            iface: 0,
            via: rtable::NO_VIA,
        };
        let mut found = [&placeholder; 4];
        let n = self.routes.find_all(id.dst, &mut found);
        for r in found.iter().take(n) {
            route_found = true;
            if Self::split_horizon(ifaces, r.iface, ingress) {
                continue;
            }
            push((r.iface, r.via), &mut n_dests);
        }
        if route_found {
            return self.finish_forward(&dests[..n_dests], packet);
        }

        // 3. Default interfaces.
        for idx in ifaces.indices() {
            let Some(e) = ifaces.get(idx) else { continue };
            if !e.is_default || Self::split_horizon(ifaces, idx, ingress) {
                continue;
            }
            push((idx, rtable::NO_VIA), &mut n_dests);
        }
        self.finish_forward(&dests[..n_dests], packet)
    }

    /// `is_same_subnet`: the same interface, or one whose address falls inside the
    /// ingress interface's subnet.
    #[cfg(feature = "rtable")]
    fn split_horizon<const N: usize, const A: usize>(
        ifaces: &crate::iflist::IfList<N, A>,
        candidate: u8,
        ingress: u8,
    ) -> bool {
        if candidate == ingress {
            return true;
        }
        match ifaces.get(candidate) {
            Some(e) => ifaces.is_within_subnet(e.addr, ingress),
            None => false,
        }
    }

    #[cfg(feature = "rtable")]
    fn push_pending(&mut self, iface: u8, via: u16, slot: u16) {
        if self.pending_len < MAX_FANOUT {
            self.pending_tx[self.pending_len] = Some((iface, via, slot));
            self.pending_len += 1;
        } else {
            self.pending_missed += 1;
        }
    }

    /// The next forward waiting to be reported, in the order the destinations matched.
    fn pop_pending(&mut self) -> Option<Routed> {
        if self.pending_len == 0 {
            return None;
        }
        let (iface, via, packet) = self.pending_tx[0]?;
        self.pending_tx.copy_within(1..self.pending_len, 0);
        self.pending_tx[self.pending_len - 1] = None;
        self.pending_len -= 1;
        self.counters.forwarded += 1;
        Some(Routed::Forwarded { iface, via, packet })
    }

    /// Fan-out destinations that had no buffer to be cloned into.
    pub const fn fanout_missed(&self) -> u32 {
        self.pending_missed
    }

    // Only the routing path fans out; without `rtable` `forward` refuses immediately, so
    // this and `push_pending` would be dead code there. `pop_pending` stays unconditional
    // because `work` calls it either way and simply finds nothing queued.
    #[cfg(feature = "rtable")]
    /// Queue one forward per destination and report the first.
    ///
    /// The last destination takes the original packet and the earlier ones take clones,
    /// which is what `csp_send_direct` does with its one-behind `next_iface`. A clone that
    /// cannot be made is counted, not silently dropped — and unlike the C, which passes the
    /// result of `csp_buffer_clone` to `send_packet` with no NULL check, running out of
    /// buffers here costs a destination rather than the node.
    fn finish_forward<'p, const B: usize, const SZ: usize>(
        &mut self,
        dests: &[(u8, u16)],
        packet: Packet<'p, B, SZ>,
    ) -> Routed {
        let Some((&last, rest)) = dests.split_last() else {
            self.counters.no_route += 1;
            return Routed::Dropped(DropReason::NoRoute);
        };
        for &(iface, via) in rest {
            match packet.deep_copy() {
                Some(c) => self.push_pending(iface, via, c.into_index()),
                None => self.pending_missed += 1,
            }
        }
        self.push_pending(last.0, last.1, packet.into_index());
        self.pop_pending().expect("a destination was just queued")
    }

    #[cfg(not(feature = "rtable"))]
    fn forward<'p, const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        _pool: &'p Pool<B, SZ>,
        _packet: Packet<'p, B, SZ>,
        _id: Id,
        _ifaces: &crate::iflist::IfList<N, A>,
        _ingress: u8,
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
        let (closed, n) = self
            .conns
            .expire_idle(now_ms, conn_timeout_ms, &mut drained);
        for &idx in &drained[..n] {
            drop(pool.from_index(idx));
        }

        #[cfg(feature = "rdp")]
        let closed = closed + self.conns.tick_rdp(now_ms, 5);

        if closed > 0 {
            self.purge_dead_accepts();
        }

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
    pub fn bridge_work<const B: usize, const SZ: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        a: u8,
        b: u8,
        now_ms: u32,
    ) -> Bridged {
        let Some((mut packet, iface)) = self.qfifo.pop(pool) else {
            return Bridged::Idle;
        };

        // Unconditional, and deliberately not gated on `dedup_mode`: `csp_bridge.c:45`
        // deduplicates every frame without consulting `csp_conf.dedup`. A bridge is
        // forwarding by definition, and one that does not deduplicate loops a frame
        // between its two interfaces forever. This was gated on the flag, so a bridge with
        // deduplication off — the default — looped where the C does not.
        if packet.prepend_header(self.version).is_err() {
            self.counters.malformed += 1;
            return Bridged::Dropped(DropReason::Malformed);
        }
        if packet.with_frame(|f| self.dedup.is_duplicate(f, now_ms)) {
            self.counters.duplicates += 1;
            return Bridged::Dropped(DropReason::Duplicate);
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

        // Fan-out destinations reported but not yet collected. This held a buffer per
        // queued destination, so a node that forwarded onto two links and shut down before
        // draining lost one.
        #[cfg(feature = "rtable")]
        while let Some(Routed::Forwarded { packet, .. }) = self.pop_pending() {
            drop(pool.from_index(packet));
            // pop_pending counts a forward it is about to report; nothing is being
            // reported here, so undo it.
            self.counters.forwarded -= 1;
        }

        // Packets sitting on connection receive queues. `shutdown` has always claimed to
        // release everything the router holds and never released these: a node torn down
        // with anything unread lost a buffer per packet. Looped because `close_all` stops
        // when the scratch array is full.
        loop {
            let mut drained = [0u16; 32];
            let (closed, n) = self.conns.close_all(&mut drained);
            for &slot in &drained[..n] {
                drop(pool.from_index(slot));
            }
            if closed == 0 {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    /// Interfaces for the router tests.
    ///
    /// The router needs these to route at all: local-subnet ownership beats the routing
    /// table and split horizon compares subnets. Index 0 is the interface every test
    /// injects on, so it is also what split horizon excludes.
    fn test_ifaces() -> crate::iflist::IfList<4, 4> {
        let mut l = crate::iflist::IfList::new(csp_core::Version::V1);
        l.add("IF0", 1, 5, false).unwrap();
        l.add("IF1", 2, 5, false).unwrap();
        l.add("IF2", 3, 5, false).unwrap();
        l
    }

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
        assert_eq!(r.work(&pool, &test_ifaces(), 0), Routed::Idle);
        assert_eq!(r.work(&pool, &test_ifaces(), 100), Routed::Idle);
    }

    #[test]
    fn a_packet_for_a_bound_port_is_delivered() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.receive(pkt(&pool, ME, 20, b"hello"), 0);

        match r.work(&pool, &test_ifaces(), 0) {
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
            r.work(&pool, &test_ifaces(), 0),
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
        assert_eq!(
            r.work(&pool, &test_ifaces(), 0),
            Routed::Dropped(DropReason::NoRoute)
        );
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
        match r.work(&pool, &test_ifaces(), 0) {
            Routed::Forwarded { iface, .. } => assert_eq!(iface, 3),
            other => panic!("expected forwarding, got {other:?}"),
        }
        assert_eq!(r.counters.forwarded, 1);
    }

    /// The four modes, against the C.
    ///
    /// The numbers are what `ctest/suite_dedup.c` measured on the real libcsp, not what
    /// this implementation happens to do: two identical packets addressed to the node and
    /// two identical packets through it, per mode.
    ///
    /// | mode | delivered of 2 | forwarded of 2 |
    /// |---|---|---|
    /// | `Off` | 2 | 2 |
    /// | `Forwarded` | 2 | 1 |
    /// | `Incoming` | 1 | 2 |
    /// | `All` | 1 | 1 |
    ///
    /// This was a `bool`, which can express only the first and last rows. The two middle
    /// modes point in opposite directions and `Forwarded` — suppress loops, leave commands
    /// alone — is the one a mesh actually wants, so collapsing them was not a simplification.
    #[cfg(feature = "rtable")]
    #[test]
    fn every_dedup_mode_matches_the_c() {
        use crate::dedup::DedupMode;

        // Two of each, byte-identical within a pair, all inside the 100 ms window.
        fn measure(mode: DedupMode) -> (u32, u32) {
            let pool = P::new();
            let mut r = R::new(ME, Version::V1);
            r.bind(20).unwrap();
            r.routes.set(0, 0, 3, rtable::NO_VIA).unwrap();
            r.dedup_mode = mode;

            let mut delivered = 0;
            for _ in 0..2 {
                r.receive(pkt(&pool, ME, 20, b"identical"), 0);
                if let Routed::Delivered { .. } = r.work(&pool, &test_ifaces(), 10) {
                    delivered += 1;
                }
            }

            let mut forwarded = 0;
            for _ in 0..2 {
                r.receive(pkt(&pool, 25, 20, b"identical"), 0);
                if let Routed::Forwarded { packet, .. } = r.work(&pool, &test_ifaces(), 10) {
                    forwarded += 1;
                    // Claim the slot the router handed over, or the pool drains and the
                    // second pair fails for a reason that has nothing to do with dedup.
                    drop(pool.from_index(packet));
                }
            }
            (delivered, forwarded)
        }

        assert_eq!(measure(DedupMode::Off), (2, 2), "CSP_DEDUP_OFF");
        assert_eq!(measure(DedupMode::Forwarded), (2, 1), "CSP_DEDUP_FWD");
        assert_eq!(measure(DedupMode::Incoming), (1, 2), "CSP_DEDUP_INCOMING");
        assert_eq!(measure(DedupMode::All), (1, 1), "CSP_DEDUP_ALL");
    }

    #[test]
    fn duplicates_are_suppressed_when_enabled() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.dedup_mode = crate::dedup::DedupMode::All;

        r.receive(pkt(&pool, ME, 20, b"same"), 0);
        assert!(matches!(
            r.work(&pool, &test_ifaces(), 0),
            Routed::Delivered { .. }
        ));

        r.receive(pkt(&pool, ME, 20, b"same"), 0);
        assert_eq!(
            r.work(&pool, &test_ifaces(), 10),
            Routed::Dropped(DropReason::Duplicate)
        );
        assert_eq!(r.counters.duplicates, 1);
    }

    #[test]
    fn deduplication_is_off_unless_asked_for() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        for _ in 0..2 {
            r.receive(pkt(&pool, ME, 20, b"same"), 0);
            assert!(matches!(
                r.work(&pool, &test_ifaces(), 0),
                Routed::Delivered { .. }
            ));
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
            p.set_id(Id {
                pri: 2,
                flags: 0,
                src: 8,
                dst: ME,
                dport: 20,
                sport,
            });
            p.set_payload(b"x").unwrap();
            r.receive(p, 0);
            assert!(matches!(
                r.work(&pool, &test_ifaces(), 0),
                Routed::Delivered { .. }
            ));
        }
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 9,
        });
        p.set_payload(b"x").unwrap();
        r.receive(p, 0);
        assert_eq!(
            r.work(&pool, &test_ifaces(), 0),
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
            assert!(matches!(
                r.work(&pool, &test_ifaces(), 0),
                Routed::Delivered { .. }
            ));
        }
        r.receive(pkt(&pool, ME, 20, b"x"), 0);
        assert_eq!(
            r.work(&pool, &test_ifaces(), 0),
            Routed::Dropped(DropReason::ReceiveQueueFull)
        );
        assert_eq!(r.counters.rx_queue_full, 1);
    }

    #[test]
    fn the_promiscuous_tap_sees_a_copy_and_does_not_affect_delivery() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.set_promisc(true);

        r.receive(pkt(&pool, ME, 20, b"tapped"), 0);
        assert!(matches!(
            r.work(&pool, &test_ifaces(), 0),
            Routed::Delivered { .. }
        ));

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
            let _ = r.work(&pool, &test_ifaces(), 0);
        }
        assert!(
            r.promisc_missed() > 0,
            "overflow must be counted, not silent"
        );
    }

    #[test]
    fn idle_connections_are_reclaimed_by_the_tick() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.receive(pkt(&pool, ME, 20, b"x"), 0);
        assert!(matches!(
            r.work(&pool, &test_ifaces(), 0),
            Routed::Delivered { .. }
        ));
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
        r.work(&pool, &test_ifaces(), 0);
        assert_eq!(
            pool.available(),
            15,
            "the delivered packet is held on the conn"
        );

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
        r.work(&pool, &test_ifaces(), 0);
        assert!(pool.available() < 16);

        // drain what is on connections too
        r.tick(&pool, 1_000_000, 1_000);
        r.shutdown(&pool);
        assert_eq!(pool.available(), 16, "nothing may survive shutdown");
    }

    /// `shutdown` on its own, with nothing tidied up first.
    ///
    /// The test above is named for this and does not test it: it calls `tick` beforehand,
    /// which expires the connections and drains them, so `shutdown` is handed a node that
    /// is already clean. Both of the things `shutdown` failed to release were invisible to
    /// it — a packet still queued on a connection, and a fan-out destination reported but
    /// not collected. Each cost one pool buffer per occurrence.
    #[cfg(feature = "rtable")]
    #[test]
    fn shutdown_alone_releases_connections_and_pending_forwards() {
        // A packet delivered to a connection and never read. No tick.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        let before = pool.available();
        r.receive(pkt(&pool, ME, 20, b"unread"), 0);
        assert!(matches!(
            r.work(&pool, &test_ifaces(), 0),
            Routed::Delivered { .. }
        ));
        r.shutdown(&pool);
        assert_eq!(
            pool.available(),
            before,
            "a packet still queued on a connection must not survive shutdown"
        );

        // A packet fanning out to two links, with only the first collected.
        let pool = P::new();
        let mut r = R::new(9999, Version::V2);
        let ifaces = {
            let mut l = crate::iflist::IfList::<4, 4>::new(Version::V2);
            l.add("IN", 40, 12, false).unwrap();
            l.add("A", 8, 12, false).unwrap();
            l.add("B", 9, 12, false).unwrap();
            l
        };
        let before = pool.available();
        r.receive(pkt(&pool, 10, 20, b"onward"), 0);
        match r.work(&pool, &ifaces, 0) {
            Routed::Forwarded { packet, .. } => drop(pool.from_index(packet)),
            other => panic!("expected forwarding, got {other:?}"),
        }
        r.shutdown(&pool);
        assert_eq!(
            pool.available(),
            before,
            "an uncollected fan-out destination must not survive shutdown"
        );
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
        let conn = match r.work(&pool, &test_ifaces(), 0) {
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
            r.work(&pool, &test_ifaces(), 0);
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
            p.set_id(Id {
                pri: 2,
                flags: 0,
                src: 8,
                dst: ME,
                dport: 20,
                sport,
            });
            p.set_payload(b"x").unwrap();
            r.receive(p, 0);
            r.work(&pool, &test_ifaces(), 0);
        }
        assert!(r.accept_missed() > 0, "backlog overflow must be counted");
    }

    #[test]
    fn an_endpoint_that_requires_a_checksum_refuses_a_bare_packet() {
        // csp_route_security_check. Without it a node configured to demand a protection
        // silently stops demanding it -- every packet still arrives.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.endpoint_opts = csp_core::security::opts::CRC32_REQ;

        r.receive(pkt(&pool, ME, 20, b"unprotected"), 0);
        assert_eq!(
            r.work(&pool, &test_ifaces(), 0),
            Routed::Dropped(DropReason::Refused(Refusal::ChecksumRequired))
        );
        assert_eq!(r.counters.rx_error, 1);
        assert_eq!(pool.available(), 16, "and the packet is released");
    }

    #[test]
    fn a_packet_with_a_good_checksum_is_accepted_and_stripped() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.endpoint_opts = csp_core::security::opts::CRC32_REQ;

        let mut buf = [0u8; 64];
        let n = csp_core::crc32::append(
            &[],
            b"protected",
            csp_core::crc32::Coverage::PayloadOnly,
            &mut buf,
        )
        .unwrap();

        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::CRC32,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 10,
        });
        p.set_payload(&buf[..n]).unwrap();
        r.receive(p, 0);

        let conn = match r.work(&pool, &test_ifaces(), 0) {
            Routed::Delivered { conn, .. } => conn,
            other => panic!("expected delivery, got {other:?}"),
        };
        let idx = r.conns.dequeue_rx(conn).unwrap().unwrap();
        let got = pool.from_index(idx).unwrap();
        got.with_payload(|d| {
            assert_eq!(
                d, b"protected",
                "the checksum must be stripped before delivery"
            )
        });
    }

    #[test]
    fn a_corrupted_checksum_is_refused() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();

        let mut buf = [0u8; 64];
        let n = csp_core::crc32::append(
            &[],
            b"protected",
            csp_core::crc32::Coverage::PayloadOnly,
            &mut buf,
        )
        .unwrap();
        buf[0] ^= 0x01;

        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::CRC32,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 10,
        });
        p.set_payload(&buf[..n]).unwrap();
        r.receive(p, 0);

        assert_eq!(
            r.work(&pool, &test_ifaces(), 0),
            Routed::Dropped(DropReason::Refused(Refusal::BadChecksum))
        );
    }

    #[test]
    fn authentication_failures_are_counted_apart_from_link_errors() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.endpoint_opts = csp_core::security::opts::HMAC_REQ;

        r.receive(pkt(&pool, ME, 20, b"unauthenticated"), 0);
        assert!(matches!(
            r.work(&pool, &test_ifaces(), 0),
            Routed::Dropped(DropReason::Refused(Refusal::AuthenticationRequired))
        ));
        assert_eq!(
            r.counters.auth_error, 1,
            "a rising autherr is its own signal"
        );
        assert_eq!(r.counters.rx_error, 0);
    }

    #[test]
    fn two_routers_share_nothing() {
        let pa = P::new();
        let pb = P::new();
        let mut a = R::new(11, Version::V1);
        let mut b = R::new(12, Version::V1);
        a.bind(20).unwrap();

        a.receive(pkt(&pa, 11, 20, b"for a"), 0);
        assert!(matches!(
            a.work(&pa, &test_ifaces(), 0),
            Routed::Delivered { .. }
        ));
        assert_eq!(
            b.work(&pb, &test_ifaces(), 0),
            Routed::Idle,
            "b saw nothing"
        );
        assert_eq!(b.counters, Counters::default());
    }
}
