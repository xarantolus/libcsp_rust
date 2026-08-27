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

/// What one step of the bridge did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bridged {
    /// Nothing waiting. Ordinary.
    Idle,
    /// The packet should be sent out the opposing interface.
    ///
    /// Carries the pool slot, exactly as [`Routed::Forwarded`] does, because naming an
    /// interface is not forwarding. Without it `bridge_work` popped the packet, reported
    /// where it should go, and dropped it on the way out of the function — so a node
    /// running the bridge forwarded nothing at all, and the tests passed because they
    /// compared the interface index.
    Forward {
        /// Interface to send on.
        iface: u8,
        /// Pool slot holding the packet. The caller owns it — take it with
        /// [`Node::take_forwarded`](crate::Node::take_forwarded) and hand it to the
        /// interface.
        packet: u16,
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
    /// The packet went to the connection-less queue, for [`Node::recvfrom`].
    ///
    /// No connection was created and none was consulted — that is the whole difference
    /// between a `CSP_SO_CONN_LESS` port and an ordinary one, and it is why a
    /// connection-less server can take packets from more peers than the node has
    /// connections.
    DeliveredConnLess {
        /// Destination port.
        port: u8,
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
    /// A control frame this node produced and the caller must send.
    ///
    /// The same obligation as [`Routed::Forwarded`] -- take the pool slot and hand it to
    /// the interface -- but it originates here rather than passing through, so an
    /// application can count and log the two apart. RDP's handshake and acknowledgements
    /// arrive this way; without it the router had no outcome that could put a frame on the
    /// wire on its own behalf, so a `SYN` reached a node and nothing came back.
    #[cfg(feature = "rdp")]
    Respond {
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
    /// An RDP control frame the state machine consumed: a handshake step or an
    /// acknowledgement. Not an error -- the packet was for the protocol, not the
    /// application, so there is nothing to deliver and nothing went wrong.
    #[cfg(feature = "rdp")]
    RdpConsumed,
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

/// Largest RDP window this node will accept from a peer's `SYN`.
///
/// `csp_rdp_new_packet` clamps the peer's proposal to what the receive queue can hold;
/// proposing more than that would have the peer send data this node cannot buffer.
#[cfg(feature = "rdp")]
pub const RDP_MAX_WINDOW: u32 = 5;

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
    /// Control frames this node produced: RDP handshake and acknowledgements.
    #[cfg(feature = "rdp")]
    pub responded: u32,
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
    /// The most recent `now_ms` handed to `work`, `receive` or `tick`.
    ///
    /// `Node::read` has no clock of its own but has to be able to acknowledge — the C reads
    /// a global clock there. Passing a literal `0` instead made `should_ack`'s
    /// `now.wrapping_sub(ack_timestamp) > ack_timeout` wrap to a huge value and fire every
    /// time, which turned a delay count of 5 into an acknowledgement per packet.
    last_now_ms: u32,
    /// Routing table.
    pub routes: crate::route_policy::rtable::Table<16>,
    /// Bound ports.
    bound: [bool; PORTS],
    /// The catch-all, libcsp's `csp_bind(socket, CSP_ANY)`.
    any_bound: bool,
    /// Ports bound `CSP_SO_CONN_LESS`. Their packets go to [`Self::cl_rx`], not to a
    /// connection.
    conn_less: [bool; PORTS],
    /// The connection-less receive queue: slot indices waiting for `recvfrom`.
    ///
    /// One queue for the node, not one per port, because the C's is one per *socket* and
    /// both surveyed consumers bind at most one. `RXQ` is its length for the same reason
    /// it is a connection's: the C sizes both with `CSP_CONN_RXQUEUE_LEN`.
    cl_rx: [Option<u16>; RXQ],
    cl_len: usize,
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
    pending_tx: [Option<(u8, u16, u16, bool)>; MAX_FANOUT],
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
            last_now_ms: 0,
            routes: crate::route_policy::rtable::Table::new(version),
            bound: [false; PORTS],
            any_bound: false,
            conn_less: [false; PORTS],
            cl_rx: [None; RXQ],
            cl_len: 0,
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

    /// Bind `port` connection-less — libcsp's `csp_bind` on a socket carrying
    /// `CSP_SO_CONN_LESS`.
    ///
    /// Packets for it go straight to the node's connection-less queue, drained by
    /// [`take_conn_less`](Self::take_conn_less). No connection is created, which is the
    /// point: `csp_route_deliver_conn_less` (`csp_route.c:132`) enqueues the packet and
    /// touches the connection pool not at all, so however many peers write to a
    /// connection-less port, none of them costs a connection.
    ///
    /// Measured before this existed: the port stopped after `CONNS` senders where a real
    /// node kept taking packets until its buffer pool ran out
    /// (`difftest/tests/node_conn_less.rs`).
    ///
    /// The C decides connection-less by *socket*, so it wins even over a connection that
    /// already matches the packet (`csp_route.c:296`) — checked before the connection
    /// table, not after.
    pub fn bind_conn_less(&mut self, port: u8) -> csp_core::Result<()> {
        self.bind(port)?;
        self.conn_less[port as usize] = true;
        Ok(())
    }

    /// True if `port` was bound connection-less.
    pub fn is_conn_less(&self, port: u8) -> bool {
        (port as usize) < PORTS && self.conn_less[port as usize]
    }

    /// Take the next packet waiting on the connection-less queue, as a pool slot index.
    pub fn take_conn_less(&mut self) -> Option<u16> {
        if self.cl_len == 0 {
            return None;
        }
        let slot = self.cl_rx[0]?;
        self.cl_rx.copy_within(1..self.cl_len, 0);
        self.cl_rx[self.cl_len - 1] = None;
        self.cl_len -= 1;
        Some(slot)
    }

    /// Bind the catch-all — libcsp's `csp_bind(socket, CSP_ANY)`.
    ///
    /// Every port in range with no bind of its own is then delivered rather than dropped.
    /// `csp_port_get_socket` (`csp_port.c:54`) does this by keeping the catch-all in a slot
    /// past the port array and reaching it only when the packet's own port has no socket,
    /// so an explicit bind still wins.
    ///
    /// The C's ceiling is `CSP_PORT_MAX_BIND`: a packet for a port above it is dropped even
    /// with the catch-all bound, and never forwarded either. `PORTS` is that ceiling here.
    ///
    /// Idempotent, like the delivery decision it controls — unlike [`bind`](Self::bind),
    /// which reports a second bind of the same port as `TableFull` because the C does.
    pub fn bind_any(&mut self) {
        self.any_bound = true;
    }

    /// Release the catch-all, closing every connection it alone was serving.
    ///
    /// Returns how many connections were closed and the slot indices to release, with the
    /// same call-again contract as [`unbind`](Self::unbind): it stops when `drained` cannot
    /// hold another whole receive queue.
    pub fn unbind_any(&mut self, drained: &mut [u16]) -> (usize, usize) {
        self.any_bound = false;
        let (mut closed, mut n) = (0usize, 0usize);
        for port in 0..PORTS.min(u8::MAX as usize + 1) {
            if self.bound[port] || drained.len() - n < RXQ {
                continue;
            }
            let (c, k) = self.conns.close_port(port as u8, &mut drained[n..]);
            closed += c;
            n += k;
        }
        self.purge_dead_accepts();
        (closed, n)
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

    /// True if a packet for `port` has somewhere to go — an explicit bind, or the catch-all.
    ///
    /// This is `csp_port_get_socket(port) != NULL`: the C answers with the catch-all socket
    /// for a port nothing bound specifically, and with `NULL` for any port above
    /// `CSP_PORT_MAX_BIND` whether or not the catch-all is bound.
    pub fn is_bound(&self, port: u8) -> bool {
        (port as usize) < PORTS && (self.bound[port as usize] || self.any_bound)
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
        ifaces: &mut crate::iflist::IfList<N, A>,
        now_ms: u32,
    ) -> Routed {
        self.last_now_ms = now_ms;
        // A packet that fanned out to several interfaces is reported one at a time, so the
        // extras come out before the next input is looked at.
        if let Some(r) = self.pop_pending() {
            return r;
        }

        let Some((packet, ingress)) = self.qfifo.pop(pool) else {
            return Routed::Idle;
        };

        // Count the packet on the interface it arrived on, before anything can discard it.
        // `csp_route_work` does this at `csp_route.c:229` -- above the deduplication check,
        // so a duplicate still counts as received and then also as dropped.
        //
        // These are the *router's* counters, not the driver's: a driver only sees frames it
        // handed up, while `drop` happens here, after the packet has left it. Nothing wrote
        // `IfList::Entry::stats` at all, so `IF_STATS` reported a permanent zero -- which
        // reads as "this link is idle" rather than as "this node does not count".
        let bytes = packet.with_payload(<[u8]>::len) as u32;
        if let Some(e) = ifaces.get_mut(ingress) {
            e.stats.rx += 1;
            e.stats.rxbytes += bytes;
        }

        // Deduplication happens inside route_one, after "is this for me?" — the mode says
        // *which* traffic to deduplicate, so the answer is needed first.
        self.route_one(pool, packet, ifaces, ingress, now_ms)
    }

    #[allow(clippy::too_many_arguments)]
    fn route_one<'p, const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &'p Pool<B, SZ>,
        packet: Packet<'p, B, SZ>,
        ifaces: &mut crate::iflist::IfList<N, A>,
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
                // `csp_route.c:244`: the ingress interface counts it as dropped too.
                if let Some(e) = ifaces.get_mut(ingress) {
                    e.stats.drop += 1;
                }
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
            return self.deliver_local(pool, packet, id, ifaces, ingress, now_ms);
        }
        self.forward(pool, packet, id, ifaces, ingress)
    }

    fn deliver_local<'p, const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        #[cfg_attr(not(feature = "rdp"), allow(unused_variables))] pool: &'p Pool<B, SZ>,
        mut packet: Packet<'p, B, SZ>,
        id: Id,
        ifaces: &mut crate::iflist::IfList<N, A>,
        ingress: u8,
        now_ms: u32,
    ) -> Routed {
        // A bound port is not the only endpoint. `csp_route_deliver` (`csp_route.c:276-285`)
        // looks the destination port up in the socket table *and* calls
        // `csp_conn_find_existing`, dropping only when neither matches — because a reply to
        // a connection this node opened arrives on the ephemeral source port `connect`
        // chose, and nothing ever binds that.
        //
        // Checking only the port meant every reply to every connection this node opened was
        // refused as `PortNotBound`: `connect` produced a connection that could never
        // receive anything. The client API, the CMP client and RDP's `SYN|ACK` were all
        // dead for that reason, and every test passed, because none of them ever put a
        // reply into a node that had called `connect`.
        if !self.is_bound(id.dport) && self.conns.find(&id).is_none() {
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
                // Node-wide *and* on the interface it arrived by.
                // `csp_route_security_check` takes the ingress interface and charges it
                // directly (`csp_route.c:39`, `:83`, `:87`), which is what CMP `IF_STATS`
                // reports: `autherr` on a link is how an operator sees that link being
                // probed. Only the node-wide totals were kept, so a node under attack
                // answered `IF_STATS` with a zero for every interface.
                match refusal.counter() {
                    security::Counter::AuthError => {
                        self.counters.auth_error += 1;
                        if let Some(e) = ifaces.get_mut(ingress) {
                            e.stats.autherr += 1;
                        }
                    }
                    security::Counter::RxError => {
                        self.counters.rx_error += 1;
                        if let Some(e) = ifaces.get_mut(ingress) {
                            e.stats.rx_error += 1;
                        }
                    }
                }
                return Routed::Dropped(DropReason::Refused(refusal));
            }
        }

        // Connection-less delivery. The C decides this by *socket*, and checks it before
        // it looks at the connection it already found (`csp_route.c:296`), so a
        // connection-less port wins even when a connection matches the packet.
        if self.is_conn_less(id.dport) {
            if self.cl_len == self.cl_rx.len() {
                self.counters.rx_queue_full += 1;
                return Routed::Dropped(DropReason::ReceiveQueueFull);
            }
            self.cl_rx[self.cl_len] = Some(packet.into_index());
            self.cl_len += 1;
            self.counters.delivered += 1;
            return Routed::DeliveredConnLess { port: id.dport };
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

        #[cfg(feature = "rdp")]
        if id.has_flag(csp_core::flags::RDP) {
            return self.deliver_rdp(pool, packet, id, ifaces, handle, is_new, now_ms);
        }

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

    /// Hand an RDP packet to the connection's state machine and act on what it says.
    ///
    /// The C does this at `csp_route_deliver_connection`, gated on `packet->id.flags &
    /// CSP_FRDP` and *returning* rather than enqueueing -- an RDP packet is never queued
    /// for the application as it arrives; the state machine decides what, if anything,
    /// the application gets.
    ///
    /// Before this, the router never constructed an `rdp::Event` at all. The state machine
    /// and its retransmit queue were fully implemented and driven only by `tick`, so a
    /// `SYN` arriving at a bound port was enqueued as though its trailer were payload and
    /// no reply was ever produced: no peer could open a connection with this node.
    #[cfg(feature = "rdp")]
    #[allow(clippy::too_many_arguments)]
    fn deliver_rdp<'p, const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &'p Pool<B, SZ>,
        packet: Packet<'p, B, SZ>,
        id: Id,
        ifaces: &crate::iflist::IfList<N, A>,
        handle: Handle,
        is_new: bool,
        now_ms: u32,
    ) -> Routed {
        use csp_core::rdp;

        let Ok(header) = packet.with_payload(rdp::Header::decode) else {
            self.counters.malformed += 1;
            return Routed::Dropped(DropReason::Malformed);
        };

        if is_new {
            // Seed this connection's initial send sequence number. `csp_rdp.c:548` does
            // `seed = csp_get_ms(); snd_iss = rand_r(&seed)`, re-seeded per SYN -- so the
            // C's ISN is a function of the clock alone and guessable by anyone who can
            // estimate the peer's uptime. This keeps "a function of the clock", because a
            // sans-io core has no entropy source, but does not reproduce `rand_r`: it is
            // not a random number and is not treated as one.
            //
            // The connection struct hardcoded `0`, so every connection this node opened
            // began at sequence 0 -- constant across reboots and across peers, which is
            // strictly worse than the C.
            let iss = Self::initial_seq(now_ms);
            if let Ok(conn) = self.conns.rdp_mut(handle) {
                *conn = csp_core::rdp::Connection::new(iss, csp_core::rdp::SynOptions::default());
            }
        }

        let action = {
            let Ok(conn) = self.conns.rdp_mut(handle) else {
                self.counters.rx_queue_full += 1;
                return Routed::Dropped(DropReason::ReceiveQueueFull);
            };
            // The payload with the trailer removed: what the application would see.
            let body_len = packet.with_payload(|b| rdp::Header::strip(b).map(|x| x.len()));
            let Ok(body_len) = body_len else {
                self.counters.malformed += 1;
                return Routed::Dropped(DropReason::Malformed);
            };
            packet.with_payload(|b| {
                conn.step(
                    rdp::Event::Packet(header, &b[..body_len]),
                    now_ms,
                    RDP_MAX_WINDOW,
                )
            })
        };

        // `step` returns exactly one action, and for in-order data that action is
        // `Deliver` -- so the acknowledgement can only come from `poll_ack`, which is a
        // separate call. Nothing made it, so this node delivered RDP data to the
        // application and never acknowledged any of it: the peer retransmits each packet
        // until `MAX_RETRANSMITS` and gives up, and the connection stalls after the first
        // one. Measured against the C, which puts one ack on the wire per packet with
        // delayed acks off.
        //
        // Queued rather than returned, so it rides alongside whatever the action was; the
        // caller sees it on the next `work` call, the same as a fan-out destination.
        // **Deferred past the action, not taken here.** This used to run before the match
        // below, so a packet the connection had no room for was acknowledged and *then*
        // dropped: the peer was told data had arrived that the application would never see,
        // and had already released its retransmission copy. Measured against a real C peer
        // — it sent 12, the application could read 8, and 4 were acknowledged into nothing.
        // An acknowledgement is a promise about a packet that was kept.
        let mut pending_ack = true;

        let routed = match action {
            // Ahead of the gap: held under its sequence number until the missing packet
            // arrives, rather than dropped and re-acknowledged. `csp_rdp.c:723` does the
            // same with `csp_rdp_rx_queue_add`. The trailer is stripped now, so what comes
            // back out later is what the application should see.
            rdp::Action::Hold(seq) => {
                let mut packet = packet;
                let kept = packet
                    .with_payload(|b| rdp::Header::strip(b).map(|x| x.len()))
                    .unwrap_or(0);
                packet.with_payload_mut(|_| (kept, ()));
                let slot = packet.into_index();
                if self.conns.hold_rx(handle, seq, slot).is_err() {
                    // No room to hold it. Drop rather than leak the slot; the peer
                    // retransmits, which is what happened to every such packet before.
                    drop(pool.from_index(slot));
                    self.counters.rx_queue_full += 1;
                    return Routed::Dropped(DropReason::ReceiveQueueFull);
                }
                Routed::Dropped(DropReason::RdpConsumed)
            }
            rdp::Action::Deliver => {
                // Strip the trailer so the application sees only its own bytes.
                let mut packet = packet;
                let kept = packet
                    .with_payload(|b| rdp::Header::strip(b).map(|x| x.len()))
                    .unwrap_or(0);
                packet.with_payload_mut(|_| (kept, ()));
                match self.conns.enqueue_rx(handle, packet.into_index()) {
                    Ok(true) => {
                        self.counters.delivered += 1;
                        // This packet may have filled a gap. Everything behind it that was
                        // waiting is now in sequence, so hand it over in order.
                        self.release_held(handle);
                        // No `queue_accept` here, unlike the plain path: an RDP connection
                        // can only reach `Deliver` once it is open, and it was announced
                        // when the handshake created it.
                        Routed::Delivered {
                            port: id.dport,
                            conn: handle,
                        }
                    }
                    _ => {
                        // Dropped for want of room. Do not acknowledge it: the peer must
                        // keep its copy and retransmit, which is the whole contract.
                        pending_ack = false;
                        self.counters.rx_queue_full += 1;
                        Routed::Dropped(DropReason::ReceiveQueueFull)
                    }
                }
            }
            rdp::Action::SendControl(h) => {
                drop(packet);
                // A `RST` on a connection this packet just created is a refusal, not the
                // start of one: the state machine sends it when a SYN's option block is
                // absent or short, and stays `Closed`. `csp_rdp.c` frees the connection
                // there and the socket never sees it. This announced it to the application
                // anyway, so one malformed SYN produced an accepted connection whose peer
                // had already been reset -- and left the table slot allocated, so a peer
                // could fill the table with packets a real handshake never sent.
                let refused = is_new && (h.flags & csp_core::rdp::RST) != 0;
                // An *established* connection answering a reset keeps its slot -- it must
                // still answer anything the peer sends afterwards -- but not the packets
                // queued on it. `csp_rdp.c` replies and then `discard_close`s straight into
                // `csp_conn_close`, which releases them; an application that will never
                // read them would otherwise hold a pool buffer each until the sweep.
                let reset_established = !is_new
                    && (h.flags & csp_core::rdp::RST) != 0
                    && self
                        .conns
                        .rdp(handle)
                        .is_ok_and(|c| c.state == csp_core::rdp::State::CloseWait);
                let out = self.emit_rdp(pool, id, ifaces, h, &[], is_new && !refused, handle);
                if reset_established {
                    while let Ok(Some(slot)) = self.conns.dequeue_rx(handle) {
                        drop(pool.from_index(slot));
                    }
                }
                if refused {
                    let mut drained = [0u16; RXQ];
                    if let Ok(n) = self.conns.close(handle, &mut drained) {
                        for slot in drained.iter().take(n) {
                            drop(pool.from_index(*slot));
                        }
                    }
                }
                out
            }
            rdp::Action::SendSyn(h, opts) => {
                drop(packet);
                let mut body = [0u8; rdp::SYN_OPTIONS_LEN];
                let Ok(n) = opts.encode(&mut body) else {
                    self.counters.malformed += 1;
                    return Routed::Dropped(DropReason::Malformed);
                };
                self.emit_rdp(pool, id, ifaces, h, &body[..n], is_new, handle)
            }
            rdp::Action::Opened | rdp::Action::Nothing => {
                drop(packet);
                Routed::Dropped(DropReason::RdpConsumed)
            }
            rdp::Action::Closed(_) => {
                drop(packet);
                // Release anything the peer had queued for an application that will now
                // never read it -- a closed connection that kept its buffers would leak
                // one pool slot per unread packet.
                //
                // Sized by `drain_capacity(RXQ)`, not a literal and not `RXQ`.
                // `Table::close` drains the receive queue *and* the reorder queue and
                // refuses rather than partially draining, so an array shorter than both
                // makes the close fail *silently* and the connection keeps every buffer
                // for good. A reset happens once; unlike `tick`'s sweep there is no later
                // pass to put it right.
                let mut drained = [0u16; RXQ];
                match self.conns.close(handle, &mut drained) {
                    Ok(n) => {
                        for slot in drained.iter().take(n) {
                            drop(pool.from_index(*slot));
                        }
                    }
                    Err(_) => unreachable!("drained is RXQ long, and rx_len <= RXQ"),
                }
                Routed::Dropped(DropReason::RdpConsumed)
            }
        };

        // The acknowledgement, now that it is known the packet was kept — and only while
        // the connection still has a window of spare room.
        //
        // `csp_rdp_check_ack` opens with exactly this gate, and the C's own comment says
        // why: "Only ACK the message if there is room for a full window in the RX buffer.
        // Unacknowledged segments are ACKed by csp_rdp_check_timeouts when the buffer is no
        // longer full." Without it a peer keeps its window open against a node that has
        // stopped consuming, and the overflow is silent. The stall clears in `Node::read`,
        // which is where `csp_io.c:67` clears it too.
        //
        // Only when the queue is deeper than a window. `CSP_CONN_RXQUEUE_LEN` is 16 and
        // `CSP_RDP_MAX_WINDOW` is 5, so the C is never asked to keep headroom it does not
        // have; `RXQ` here is a const generic and can be smaller than the window a peer
        // proposes. Gating unconditionally made `spare < window` true from the first packet
        // on such a node, which then never acknowledged anything at all — caught by
        // `a_delay_count_beyond_the_window_is_bound_by_it`, whose node is `RXQ` 4 against a
        // clamped window of 5.
        let window = self
            .conns
            .rdp(handle)
            .map(|c| c.opts.window_size as usize)
            .unwrap_or(0);
        if RXQ > window && self.conns.rx_spare(handle).unwrap_or(0) < window {
            pending_ack = false;
        }
        if pending_ack {
            if let Some(ack) = self
                .conns
                .rdp_mut(handle)
                .ok()
                .and_then(|c| c.poll_ack(now_ms))
            {
                let _ = self.queue_rdp(pool, id, ifaces, ack, &[], false, handle);
            }
        }
        routed
    }

    /// Route an already-built packet and queue it for the caller to transmit.
    ///
    /// The tail of `queue_rdp_from_tick`, for a frame that exists rather than one being
    /// composed from a header.
    #[cfg(feature = "rdp")]
    fn queue_built<'p, const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        _pool: &'p Pool<B, SZ>,
        ifaces: &crate::iflist::IfList<N, A>,
        idout: Id,
        mut packet: Packet<'p, B, SZ>,
    ) {
        packet.set_id(idout);
        let mut hops = [crate::route_policy::Hop {
            iface: 0,
            via: 0,
            dst: 0,
        }; 1];
        match crate::route_policy::destinations(
            ifaces,
            &self.routes,
            self.version,
            idout.dst,
            None,
            &mut hops,
        ) {
            crate::route_policy::Outcome::Hops(_) => {
                let slot = packet.into_index();
                self.push_pending_tagged(hops[0].iface, hops[0].via, slot, true);
            }
            _ => {
                self.counters.no_route += 1;
            }
        }
    }

    /// Retransmit, release and give up on this node's unacknowledged packets.
    ///
    /// Returns how many connections it closed. Each retransmission is a *copy* -- the held
    /// packet has to stay held, because the peer may not answer this one either, which is
    /// what `csp_buffer_copy` into a fresh buffer does in `csp_rdp_check_timeouts`.
    #[cfg(feature = "rdp")]
    fn sweep_unacked<const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        ifaces: &crate::iflist::IfList<N, A>,
        now_ms: u32,
    ) -> usize {
        use csp_core::rdp::TxAction;

        let mut handles = [None; CONNS];
        let mut n_handles = 0;
        for h in self.conns.rdp_handles() {
            if n_handles < handles.len() {
                handles[n_handles] = Some(h);
                n_handles += 1;
            }
        }

        let mut closed = 0;
        for handle in handles.iter().take(n_handles).flatten().copied() {
            // Sized by `RXQ`: the queue cannot hold more than the shared budget allows, and
            // a short array would leave entries unexamined with their timers unreset.
            let mut actions = [TxAction::GiveUp; RXQ];
            let Ok(count) = self.conns.poll_unacked(handle, now_ms, &mut actions) else {
                continue;
            };
            let Ok(id) = self.conns.id_out(handle) else {
                continue;
            };
            for action in actions.iter().take(count) {
                match *action {
                    TxAction::Release { token } => drop(pool.from_index(token)),
                    TxAction::Retransmit { token, .. } => {
                        // Copy, keep the original queued. Out of buffers means this attempt
                        // is skipped, not that the packet is lost -- the next sweep tries
                        // again, because the entry stays.
                        let Some(held) = pool.from_index(token) else {
                            continue;
                        };
                        let copy = held.deep_copy();
                        // `from_index` took ownership; hand it straight back so the entry
                        // still has something to retransmit next time.
                        let _ = held.into_index();
                        let Some(mut c) = copy else { continue };
                        // "Update to latest outgoing ACK" -- the C rewrites `ack_nr` on
                        // every retransmission so the peer learns what has arrived since.
                        if let Ok(rcv_cur) = self.conns.rdp(handle).map(|r| r.rcv_cur) {
                            // `with_payload_mut` hands over the whole slot capacity, not
                            // the payload: the closure's return value *sets* the length.
                            // Taking `b.len()` for it stretched every retransmission to the
                            // full buffer and wrote the refreshed acknowledgement past the
                            // real trailer. The length has to come from `with_payload`.
                            let len = c.with_payload(<[u8]>::len);
                            c.with_payload_mut(|b| {
                                if len >= csp_core::rdp::HEADER_LEN && len <= b.len() {
                                    let at = len - csp_core::rdp::HEADER_LEN;
                                    if let Ok(mut hd) = csp_core::rdp::Header::decode(&b[at..len]) {
                                        hd.ack_nr = rcv_cur;
                                        let mut t = [0u8; csp_core::rdp::HEADER_LEN];
                                        if let Ok(k) = hd.encode(&[], &mut t) {
                                            b[at..at + k].copy_from_slice(&t[..k]);
                                        }
                                    }
                                }
                                (len, ())
                            });
                        }
                        self.queue_built(pool, ifaces, id, c);
                    }
                    TxAction::GiveUp => {
                        let mut drained = [0u16; RXQ];
                        if let Ok(k) = self.conns.close(handle, &mut drained) {
                            for slot in drained.iter().take(k) {
                                drop(pool.from_index(*slot));
                            }
                            closed += 1;
                        }
                    }
                }
            }
        }
        closed
    }

    /// Deliver everything the just-delivered packet unblocked, in sequence order.
    ///
    /// Stops at the first gap, so a queue holding 5 and 6 while 4 is missing stays put.
    #[cfg(feature = "rdp")]
    fn release_held(&mut self, handle: Handle) {
        loop {
            let Ok(next) = self.conns.rdp(handle).map(|c| c.next_expected()) else {
                return;
            };
            let Some(slot) = self.conns.take_held(handle, next) else {
                return;
            };
            let advanced = self
                .conns
                .rdp_mut(handle)
                .map(|c| c.release_held(next))
                .unwrap_or(false);
            if !advanced || self.conns.enqueue_rx(handle, slot) != Ok(true) {
                // Either the sequence moved under us or the application's queue is full.
                // The slot is ours; releasing it is the only thing that does not leak.
                self.counters.rx_queue_full += 1;
                return;
            }
            self.counters.delivered += 1;
        }
    }

    /// Build an RDP control frame back to the peer and queue it for the caller to send.
    #[cfg(feature = "rdp")]
    #[allow(clippy::too_many_arguments)]
    fn emit_rdp<const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        id: Id,
        ifaces: &crate::iflist::IfList<N, A>,
        header: csp_core::rdp::Header,
        body: &[u8],
        is_new: bool,
        handle: Handle,
    ) -> Routed {
        match self.queue_rdp(pool, id, ifaces, header, body, is_new, handle) {
            Ok(()) => self.pop_pending().expect("a response was just queued"),
            Err(r) => r,
        }
    }

    /// The same, but only queues: the caller decides what to report.
    ///
    /// An acknowledgement travels *alongside* a delivery -- `step` returns one action, and
    /// for in-order data that action is `Deliver`, so the ack comes from the separate
    /// `poll_ack`. Emitting it through `emit_rdp` would have returned `Respond` and thrown
    /// the `Delivered` away.
    /// Queue a frame the RDP timers produced.
    ///
    /// `queue_rdp` builds its reply by swapping an *incoming* header's addresses; a timer
    /// has no incoming packet, only the connection's outgoing id, so it is used directly.
    #[cfg(feature = "rdp")]
    fn queue_rdp_from_tick<const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        idout: Id,
        ifaces: &crate::iflist::IfList<N, A>,
        header: csp_core::rdp::Header,
        body: &[u8],
    ) -> core::result::Result<(), Routed> {
        let Some(mut reply) = pool.acquire(0) else {
            self.counters.rx_queue_full += 1;
            return Err(Routed::Dropped(DropReason::ReceiveQueueFull));
        };
        reply.set_id(idout);
        // Sized for a SYN's option block as well as a bare control frame: the client
        // handshake is the one caller whose body is not empty.
        let mut buf = [0u8; csp_core::rdp::HEADER_LEN + csp_core::rdp::SYN_OPTIONS_LEN];
        let Ok(n) = header.encode(body, &mut buf) else {
            self.counters.malformed += 1;
            return Err(Routed::Dropped(DropReason::Malformed));
        };
        if reply.set_payload(&buf[..n]).is_err() {
            self.counters.malformed += 1;
            return Err(Routed::Dropped(DropReason::Malformed));
        }
        let dst = reply.id().dst;
        let mut hops = [crate::route_policy::Hop {
            iface: 0,
            via: 0,
            dst: 0,
        }; 1];
        match crate::route_policy::destinations(
            ifaces,
            &self.routes,
            self.version,
            dst,
            None,
            &mut hops,
        ) {
            crate::route_policy::Outcome::Hops(_) => {
                let slot = reply.into_index();
                self.push_pending_tagged(hops[0].iface, hops[0].via, slot, true);
                Ok(())
            }
            _ => {
                self.counters.no_route += 1;
                Err(Routed::Dropped(DropReason::NoRoute))
            }
        }
    }

    #[cfg(feature = "rdp")]
    #[allow(clippy::too_many_arguments)]
    fn queue_rdp<const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        id: Id,
        ifaces: &crate::iflist::IfList<N, A>,
        header: csp_core::rdp::Header,
        body: &[u8],
        is_new: bool,
        handle: Handle,
    ) -> core::result::Result<(), Routed> {
        if is_new {
            // The application is told about the connection as soon as the handshake starts,
            // the same as for a plain first packet -- otherwise a peer that only ever sends
            // RDP control frames would hold a connection the application never sees.
            self.queue_accept(handle);
        }

        let Some(mut reply) = pool.acquire(0) else {
            self.counters.rx_queue_full += 1;
            return Err(Routed::Dropped(DropReason::ReceiveQueueFull));
        };
        reply.set_id(Id {
            pri: id.pri,
            flags: id.flags,
            src: id.dst,
            dst: id.src,
            dport: id.sport,
            sport: id.dport,
        });
        let mut buf = [0u8; csp_core::rdp::SYN_OPTIONS_LEN + csp_core::rdp::HEADER_LEN];
        let Ok(n) = header.encode(body, &mut buf) else {
            self.counters.malformed += 1;
            return Err(Routed::Dropped(DropReason::Malformed));
        };
        if reply.set_payload(&buf[..n]).is_err() {
            self.counters.malformed += 1;
            return Err(Routed::Dropped(DropReason::Malformed));
        }

        // Route it the way any outgoing packet is routed -- the reply has to reach the peer,
        // which is not necessarily the interface it arrived on.
        // The same policy every other outgoing packet uses. This had its own three-line
        // version that tried the subnet then the defaults and **never consulted the
        // routing table** -- while its doc comment said it did -- so an RDP reply to a
        // peer reachable only by a route was dropped and the handshake stalled.
        //
        // `None` for the ingress: a reply this node originated is not a forward, so split
        // horizon does not apply to it.
        let dst = reply.id().dst;
        let mut hops = [crate::route_policy::Hop {
            iface: 0,
            via: 0,
            dst: 0,
        }; 1];
        let (iface, via) = match crate::route_policy::destinations(
            ifaces,
            &self.routes,
            self.version,
            dst,
            None,
            &mut hops,
        ) {
            crate::route_policy::Outcome::Hops(_) => (hops[0].iface, hops[0].via),
            _ => {
                self.counters.no_route += 1;
                return Err(Routed::Dropped(DropReason::NoRoute));
            }
        };
        let slot = reply.into_index();
        self.push_pending_tagged(iface, via, slot, true);
        Ok(())
    }

    /// The initial send sequence number for a connection opening at `now_ms`.
    ///
    /// A cheap mix rather than a counter, so two connections opened milliseconds apart do
    /// not start at adjacent sequence numbers. Deterministic on purpose: the differential
    /// tests pin the clock, and an ISN that could not be reproduced could not be compared.
    #[cfg(feature = "rdp")]
    const fn initial_seq(now_ms: u32) -> u16 {
        // Knuth's multiplicative constant, folded to 16 bits.
        let mixed = now_ms.wrapping_mul(2_654_435_761);
        ((mixed >> 16) ^ mixed) as u16
    }

    /// Send any acknowledgement that has come due on time rather than on packet count.
    ///
    /// The receive-queue gate applies here too: a connection with no room to invite more
    /// data should not be inviting it, whatever the ack timer says.
    #[cfg(feature = "rdp")]
    fn sweep_delayed_acks<const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        ifaces: &crate::iflist::IfList<N, A>,
        now_ms: u32,
    ) {
        let mut handles = [None; CONNS];
        let mut n_handles = 0;
        for h in self.conns.rdp_open_handles() {
            if n_handles < handles.len() {
                handles[n_handles] = Some(h);
                n_handles += 1;
            }
        }
        for handle in handles.iter().take(n_handles).flatten().copied() {
            let window = self
                .conns
                .rdp(handle)
                .map(|c| c.opts.window_size as usize)
                .unwrap_or(0);
            if RXQ > window && self.conns.rx_spare(handle).unwrap_or(0) < window {
                continue;
            }
            let Ok(idout) = self.conns.id_out(handle) else {
                continue;
            };
            if let Some(ack) = self
                .conns
                .rdp_mut(handle)
                .ok()
                .and_then(|c| c.poll_ack(now_ms))
            {
                let _ = self.queue_rdp_from_tick(pool, idout, ifaces, ack, &[]);
            }
        }
    }

    /// Acknowledge on the strength of the application having read something.
    ///
    /// The receive-queue gate above stops acknowledging while a connection is nearly full,
    /// which stalls the peer on purpose. Something has to restart it, or the connection is
    /// wedged for good: `csp_io.c:67` re-runs `csp_rdp_check_ack` inside `csp_read`, and
    /// this is that. Queued for the next `work`, like every other frame the node originates.
    #[cfg(feature = "rdp")]
    pub fn ack_after_read<const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        ifaces: &crate::iflist::IfList<N, A>,
        handle: Handle,
    ) {
        let now_ms = self.last_now_ms;
        let window = self
            .conns
            .rdp(handle)
            .map(|c| c.opts.window_size as usize)
            .unwrap_or(0);
        if RXQ > window && self.conns.rx_spare(handle).unwrap_or(0) < window {
            return;
        }
        let Ok(idout) = self.conns.id_out(handle) else {
            return;
        };
        if let Some(ack) = self
            .conns
            .rdp_mut(handle)
            .ok()
            .and_then(|c| c.poll_ack(now_ms))
        {
            let _ = self.queue_rdp_from_tick(pool, idout, ifaces, ack, &[]);
        }
    }

    /// Open an RDP connection this node initiates: queue the `SYN` for the next `work`.
    ///
    /// `csp_rdp_connect` sends the SYN and then blocks until the router task reports the
    /// peer's `SYN|ACK`. There is nowhere to block here, so the SYN is queued and the
    /// caller's next [`Router::work`] hands it to the wire as `Routed::Respond`; the
    /// connection reaches `Open` when the reply arrives through the ordinary receive path.
    ///
    /// The `SYN|ACK` and the final `ACK` need no new code — `State::SynSent` was already
    /// implemented and tested in `csp_core`, and was simply never reachable, because
    /// nothing outside that module ever constructed `Event::Connect`.
    #[cfg(feature = "rdp")]
    pub fn rdp_connect<const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        ifaces: &crate::iflist::IfList<N, A>,
        handle: Handle,
        idout: Id,
        now_ms: u32,
    ) -> csp_core::Result<()> {
        let iss = Self::initial_seq(now_ms);
        let defaults = csp_core::rdp::SynOptions::default();
        let Some((header, opts)) =
            self.conns
                .rdp_connect(handle, iss, defaults, now_ms, RDP_MAX_WINDOW)
        else {
            return Err(csp_core::Error::Unsupported {
                feature: csp_core::Feature::Rdp,
            });
        };
        let mut body = [0u8; csp_core::rdp::SYN_OPTIONS_LEN];
        let n = opts.encode(&mut body)?;
        self.queue_rdp_from_tick(pool, idout, ifaces, header, &body[..n])
            .map_err(|_| csp_core::Error::Unroutable { dst: idout.dst })
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
    fn forward<'p, const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        _pool: &'p Pool<B, SZ>,
        packet: Packet<'p, B, SZ>,
        id: Id,
        ifaces: &crate::iflist::IfList<N, A>,
        ingress: u8,
    ) -> Routed {
        let mut hops = [crate::route_policy::Hop {
            iface: 0,
            via: 0,
            dst: 0,
        }; MAX_FANOUT];
        let n = match crate::route_policy::destinations(
            ifaces,
            &self.routes,
            self.version,
            id.dst,
            Some(ingress),
            &mut hops,
        ) {
            crate::route_policy::Outcome::Hops(n) => n,
            // A stage matched but split horizon left nothing, or nothing matched at all.
            // Both drop the packet; `finish_forward` counts it as no route.
            _ => 0,
        };
        self.finish_forward(&hops[..n], packet)
    }

    fn push_pending(&mut self, iface: u8, via: u16, slot: u16) {
        self.push_pending_tagged(iface, via, slot, false);
    }

    fn push_pending_tagged(&mut self, iface: u8, via: u16, slot: u16, ours: bool) {
        if self.pending_len < MAX_FANOUT {
            self.pending_tx[self.pending_len] = Some((iface, via, slot, ours));
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
        let (iface, via, packet, ours) = self.pending_tx[0]?;
        self.pending_tx.copy_within(1..self.pending_len, 0);
        self.pending_tx[self.pending_len - 1] = None;
        self.pending_len -= 1;
        if ours {
            #[cfg(feature = "rdp")]
            {
                self.counters.responded += 1;
                return Some(Routed::Respond { iface, via, packet });
            }
        }
        self.counters.forwarded += 1;
        Some(Routed::Forwarded { iface, via, packet })
    }

    /// Fan-out destinations that had no buffer to be cloned into.
    pub const fn fanout_missed(&self) -> u32 {
        self.pending_missed
    }

    /// Queue one forward per destination and report the first.
    ///
    /// The last destination takes the original packet and the earlier ones take clones,
    /// which is what `csp_send_direct` does with its one-behind `next_iface`. A clone that
    /// cannot be made is counted, not silently dropped — and unlike the C, which passes the
    /// result of `csp_buffer_clone` to `send_packet` with no NULL check, running out of
    /// buffers here costs a destination rather than the node.
    fn finish_forward<'p, const B: usize, const SZ: usize>(
        &mut self,
        dests: &[crate::route_policy::Hop],
        mut packet: Packet<'p, B, SZ>,
    ) -> Routed {
        let Some((&last, rest)) = dests.split_last() else {
            self.counters.no_route += 1;
            return Routed::Dropped(DropReason::NoRoute);
        };
        for h in rest {
            match packet.deep_copy() {
                Some(mut c) => {
                    Self::set_dst(&mut c, h.dst);
                    self.push_pending(h.iface, h.via, c.into_index());
                }
                None => self.pending_missed += 1,
            }
        }
        Self::set_dst(&mut packet, last.dst);
        self.push_pending(last.iface, last.via, packet.into_index());
        self.pop_pending().expect("a destination was just queued")
    }

    fn set_dst<const B: usize, const SZ: usize>(packet: &mut Packet<'_, B, SZ>, dst: u16) {
        let mut id = packet.id();
        if id.dst != dst {
            id.dst = dst;
            packet.set_id(id);
        }
    }

    /// Periodic maintenance: expire idle connections and step the RDP timers.
    ///
    /// Returns how many connections were closed. Must be called regularly — the RDP state
    /// machine reads no clock on purpose, so nothing else advances its timers.
    // `ifaces` routes the frames the RDP timers produce; with RDP off there are none.
    #[cfg_attr(not(feature = "rdp"), allow(unused_variables))]
    pub fn tick<const B: usize, const SZ: usize, const N: usize, const A: usize>(
        &mut self,
        pool: &Pool<B, SZ>,
        ifaces: &crate::iflist::IfList<N, A>,
        now_ms: u32,
        conn_timeout_ms: u32,
    ) -> usize {
        self.last_now_ms = now_ms;
        // `RXQ`, not a literal: `expire_idle` skips any connection whose queue will not
        // fit, so a scratch array shorter than one connection's queue means that
        // connection never expires at all rather than merely waiting for the next sweep.
        let mut drained = [0u16; RXQ];
        let (closed, n) = self
            .conns
            .expire_idle(now_ms, conn_timeout_ms, &mut drained);
        for &idx in &drained[..n] {
            drop(pool.from_index(idx));
        }

        #[cfg(feature = "rdp")]
        // Frames the RDP timers want to send -- a retransmitted `SYN|ACK`, or the `RST`
        // that gives up on one. Collected first because building them needs `&mut self`,
        // which the sweep already holds; queued below so `work` reports them as
        // `Routed::Respond` like any other frame this node originates.
        #[cfg(feature = "rdp")]
        let mut pending: [Option<(Id, csp_core::rdp::Header)>; CONNS] = [None; CONNS];
        #[cfg(feature = "rdp")]
        let mut n_pending = 0usize;
        #[cfg(feature = "rdp")]
        let closed = closed
            + self.conns.tick_rdp(now_ms, RDP_MAX_WINDOW, |id, h| {
                if n_pending < CONNS {
                    pending[n_pending] = Some((id, h));
                    n_pending += 1;
                }
            });
        #[cfg(feature = "rdp")]
        for entry in pending.iter().take(n_pending) {
            let Some((id, h)) = entry else { continue };
            // `is_new` is false: the connection was announced when the handshake created
            // it, and a retransmission is not a new one.
            let _ = self.queue_rdp_from_tick(pool, *id, ifaces, *h, &[]);
        }

        // The transmit sweep: release what the peer acknowledged, resend what timed out,
        // give up once the attempts run out. `csp_rdp_check_timeouts` does this for every
        // connection on each call, counting one attempt per sweep rather than per packet.
        #[cfg(feature = "rdp")]
        let closed = closed + self.sweep_unacked(pool, ifaces, now_ms);

        // The delayed acknowledgement that only a timer can produce.
        //
        // `csp_rdp_check_timeouts` calls `csp_rdp_check_ack` on every open connection with
        // delayed acks (`csp_rdp.c:451`). Without it, a peer that sends fewer packets than
        // `ack_delay_count` is never acknowledged on `ack_timeout` — nothing else arrives
        // to drive `poll_ack`, so the acknowledgement waits for the peer's retransmission
        // instead. Measured: ten seconds of ticks with one packet outstanding produced
        // **zero** acknowledgements where the C sends one after 250 ms.
        //
        // `should_ack`'s timeout branch was right the whole time and
        // `rdp::a_proposed_ack_timeout_is_adopted` pinned it — by calling `poll_ack` in a
        // loop itself, standing in for the timer the node did not have. A correct piece of
        // the core that the layer above never called, which is this port's commonest defect.
        #[cfg(feature = "rdp")]
        self.sweep_delayed_acks(pool, ifaces, now_ms);

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
        Bridged::Forward {
            iface: out,
            packet: packet.into_index(),
        }
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
            // `RXQ` guarantees progress: `close_all` needs room for at least one whole
            // receive queue, so anything smaller makes it return `closed == 0` for a deep
            // queue and the loop below exits having freed nothing.
            let mut drained = [0u16; RXQ];
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

    /// Forwarding works with the routing table compiled out.
    ///
    /// `csp_send_direct` puts only its middle stage inside `#if CSP_USE_RTABLE`; the
    /// local-subnet scan and the default-interface scan run either way. This port gated
    /// the *whole* of `forward` on the `rtable` feature and substituted a stub that
    /// refused everything, so a node built without the routing table relayed nothing at
    /// all -- not to a directly attached subnet, not out a default link.
    ///
    /// Deliberately **not** gated on the feature: it is the same expected behaviour with
    /// the table present but empty, so it should hold in both configurations. The C
    /// records `route::one_owning_link_sends_one_frame` and
    /// `route::two_default_interfaces_send_two_frames` measure exactly this, with
    /// `CSP_USE_RTABLE=ON` and nothing in the table -- the same code path.
    #[test]
    fn forwarding_does_not_need_the_routing_table() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V2);
        let mut ifaces = {
            let mut l = crate::iflist::IfList::<4, 4>::new(Version::V2);
            l.add("INGRESS", 40, 12, false).unwrap();
            l.add("OWNS_IT", 8, 12, false).unwrap();
            l.add("DEFAULT", 200, 12, true).unwrap();
            l
        };

        let mut send_to = |r: &mut R, dst: u16| -> Option<u8> {
            let mut p = pool.acquire(0).unwrap();
            p.set_id(Id {
                pri: 2,
                flags: 0,
                src: 11,
                dst,
                dport: 12,
                sport: 40,
            });
            p.set_payload(b"onward").unwrap();
            r.receive(p, 0);
            match r.work(&pool, &mut ifaces, 0) {
                Routed::Forwarded { iface, packet, .. } => {
                    drop(pool.from_index(packet));
                    Some(iface)
                }
                _ => None,
            }
        };

        // 10 is inside OWNS_IT's subnet (8..11): the local-subnet stage.
        assert_eq!(
            send_to(&mut r, 10),
            Some(1),
            "a directly attached subnet must be reachable without a routing table"
        );
        // 3000 is in nobody's subnet: the default stage.
        assert_eq!(
            send_to(&mut r, 3000),
            Some(2),
            "a default interface must be usable without a routing table"
        );
    }

    /// An RDP handshake with a peer reachable only through the routing table.
    ///
    /// The reply's destination used to be found by a private three-line lookup that tried
    /// the subnet then the defaults and **never consulted the routing table**, while its
    /// doc comment said it did. A peer no interface's subnet owns and no default reaches
    /// got no `SYN|ACK` at all: the handshake stalled and the connection never opened.
    #[cfg(feature = "rdp")]
    #[test]
    fn a_peer_reachable_only_by_a_route_still_gets_its_handshake() {
        use csp_core::rdp;

        let pool = P::new();
        let mut r = R::new(ME, Version::V2);
        r.bind(7).unwrap();
        // One interface, on a subnet that does not contain the peer, and not a default.
        let mut ifaces = {
            let mut l = crate::iflist::IfList::<4, 4>::new(Version::V2);
            l.add("LINK", 8, 12, false).unwrap();
            l
        };
        // 3000 is in no subnet and there is no default: only the table can reach it.
        r.routes
            .set(
                3000,
                Version::V2.host_bits() as u16,
                0,
                csp_core::rtable::NO_VIA,
            )
            .unwrap();

        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: 3000,
            dst: ME,
            dport: 7,
            sport: 40,
        });
        let mut ob = [0u8; rdp::SYN_OPTIONS_LEN];
        let ol = rdp::SynOptions::default().encode(&mut ob).unwrap();
        let h = rdp::Header {
            flags: rdp::SYN,
            seq_nr: 1000,
            ack_nr: 0,
        };
        let mut f = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
        let n = h.encode(&ob[..ol], &mut f).unwrap();
        p.set_payload(&f[..n]).unwrap();
        r.receive(p, 0);

        match r.work(&pool, &mut ifaces, 0) {
            Routed::Respond { iface, packet, .. } => {
                assert_eq!(iface, 0, "out the interface the route names");
                let reply = pool.from_index(packet).expect("a live slot");
                let hh = reply.with_payload(|b| rdp::Header::decode(b).unwrap());
                assert_eq!(hh.flags, rdp::SYN | rdp::ACK);
                assert_eq!(hh.ack_nr, 1000);
            }
            other => panic!("a routed peer must still get its SYN|ACK, got {other:?}"),
        }
    }

    /// The sequence number a peer actually receives in the `SYN|ACK`, for two handshakes
    /// opened at different times.
    ///
    /// Driven through the router, not by calling the ISN helper: the first version of this
    /// test called `Router::initial_seq` directly, so replacing the *call site* with a
    /// constant left it green. The helper was never the thing at risk.
    ///
    /// `csp_rdp.c:548` re-seeds `rand_r` from `csp_get_ms()` for every `SYN`, so the C's
    /// ISN moves with the clock. This node hardcoded `0`. A constant ISN means a delayed
    /// segment from a previous connection falls inside the window of the next one between
    /// the same pair of ports -- and the handshake record cannot see it, because it checks
    /// that the reply carries this node's *own* ISN and zero equals zero.
    #[cfg(feature = "rdp")]
    #[test]
    fn the_sequence_a_peer_receives_moves_with_the_clock() {
        use csp_core::rdp;

        fn syn_ack_seq(now_ms: u32, sport: u8) -> (u16, u16) {
            let pool = P::new();
            let mut r = R::new(ME, Version::V1);
            r.bind(7).unwrap();
            let mut ifaces = test_ifaces();

            let mut p = pool.acquire(0).unwrap();
            p.set_id(Id {
                pri: 2,
                flags: csp_core::flags::RDP,
                src: 2,
                dst: ME,
                dport: 7,
                sport,
            });
            let mut opts_buf = [0u8; rdp::SYN_OPTIONS_LEN];
            let olen = rdp::SynOptions::default().encode(&mut opts_buf).unwrap();
            let h = rdp::Header {
                flags: rdp::SYN,
                seq_nr: 1000,
                ack_nr: 0,
            };
            let mut framed = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
            let n = h.encode(&opts_buf[..olen], &mut framed).unwrap();
            p.set_payload(&framed[..n]).unwrap();
            r.receive(p, 0);

            match r.work(&pool, &mut ifaces, now_ms) {
                Routed::Respond { packet, .. } => {
                    let reply = pool.from_index(packet).expect("a live slot");
                    let hh = reply.with_payload(|b| rdp::Header::decode(b).unwrap());
                    (hh.seq_nr, hh.ack_nr)
                }
                other => panic!("a SYN must be answered, got {other:?}"),
            }
        }

        let (seq_a, ack_a) = syn_ack_seq(100_000, 40);
        let (seq_b, _) = syn_ack_seq(100_001, 41);
        let (seq_c, _) = syn_ack_seq(7_000_000, 42);

        // It acknowledges the peer's SYN...
        assert_eq!(ack_a, 1000);
        // ...and does not echo the peer's sequence number back as its own.
        assert_ne!(
            seq_a, 1000,
            "the reply must carry this node's ISN, not the peer's"
        );
        // One millisecond apart must not collide.
        assert_ne!(seq_a, seq_b);
        assert_ne!(seq_a, seq_c);
        assert_ne!(seq_b, seq_c);
        // Reproducible for a given clock, which is what lets the differential tests pin it.
        assert_eq!(seq_a, syn_ack_seq(100_000, 40).0);
        // And not simply the clock truncated, which would be as guessable as a counter.
        assert_ne!(seq_a, 100_000u32 as u16);
    }

    /// A peer that resets a connection with unread data must get every buffer back.
    ///
    /// `Table::close` refuses rather than partially draining -- it returns
    /// `BufferTooSmall` if the scratch array cannot hold the whole receive queue, because
    /// a slot removed but not reported is a slot nobody releases. The RST path passed a
    /// fixed `[0u16; 8]` while `RXQ` is a const generic, so with a queue deeper than eight
    /// the close was skipped in silence: the connection stayed open and its buffers were
    /// never returned. `tick` retries its sweep, but a reset happens once.
    ///
    /// Counted in buffers the pool has back, which is what the application runs out of.
    /// A connection torn down while it is still holding an out-of-order packet must give
    /// that buffer back too. The reorder queue is a second place a connection can be
    /// holding pool slots, and `Table::close` drains only what it knows about.
    #[cfg(feature = "rdp")]
    #[test]
    fn a_held_out_of_order_packet_is_returned_on_close() {
        use csp_core::rdp;
        type P = Pool<16, 264>;
        type R = Router<4, 4, 48, 8>;
        let pool = P::new();
        let mut r = R::new(10, Version::V2);
        r.bind(12).unwrap();
        let mut ifaces = crate::iflist::IfList::<4, 4>::new(Version::V2);
        ifaces.add("test", 10, 14, true).unwrap();

        let before = pool.available();
        let mut feed = |r: &mut R, flags: u8, seq: u16, ack: u16, body: &[u8]| {
            let mut buf = [0u8; 64];
            buf[..body.len()].copy_from_slice(body);
            let h = rdp::Header {
                flags,
                seq_nr: seq,
                ack_nr: ack,
            };
            let n = h.encode(&[], &mut buf[body.len()..]).unwrap();
            let mut p = pool.acquire(0).unwrap();
            p.set_id(Id {
                pri: 2,
                flags: csp_core::flags::RDP,
                src: 11,
                dst: 10,
                dport: 12,
                sport: 40,
            });
            p.set_payload(&buf[..body.len() + n]).unwrap();
            r.receive(p, 0);
            loop {
                match r.work(&pool, &mut ifaces, 0) {
                    Routed::Respond { packet, .. } | Routed::Forwarded { packet, .. } => {
                        drop(pool.from_index(packet));
                    }
                    Routed::Idle => break,
                    _ => continue,
                }
            }
        };

        let mut ob = [0u8; rdp::SYN_OPTIONS_LEN];
        let ol = rdp::SynOptions::default().encode(&mut ob).unwrap();
        feed(&mut r, rdp::SYN, 1000, 0, &ob[..ol]);
        let h = r.accept().expect("the handshake announces the connection");
        let iss = r.conns.rdp(h).unwrap().snd_iss;
        feed(&mut r, rdp::ACK, 1001, iss, &[]);

        // Two packets that overtake the gap at 1001, so both are held.
        feed(&mut r, rdp::ACK, 1002, iss, b"b");
        feed(&mut r, rdp::ACK, 1003, iss, b"c");
        assert!(
            pool.available() < before,
            "the held packets must actually be held, or this proves nothing"
        );

        let mut drained = [0u16; 8];
        let n = r
            .conns
            .close(h, &mut drained)
            .expect("RXQ bounds both queues");
        for slot in drained.iter().take(n) {
            drop(pool.from_index(*slot));
        }
        assert_eq!(
            pool.available(),
            before,
            "closing must return what the reorder queue was holding"
        );
    }

    #[cfg(feature = "rdp")]
    #[test]
    fn a_reset_connection_returns_every_buffer_it_held() {
        use csp_core::rdp;

        // RXQ of 12, deliberately more than the eight the RST path used to assume.
        type Deep = Router<4, 12, 48, 8>;
        let pool = Pool::<24, 264>::new();
        let mut r = Deep::new(ME, Version::V1);
        r.bind(7).unwrap();
        let mut ifaces = test_ifaces();
        let before = pool.available();

        let mut feed = |r: &mut Deep, flags: u8, seq: u16, ack: u16, body: &[u8]| {
            let mut p = pool.acquire(0).unwrap();
            p.set_id(Id {
                pri: 2,
                flags: csp_core::flags::RDP,
                src: 2,
                dst: ME,
                dport: 7,
                sport: 40,
            });
            let h = rdp::Header {
                flags,
                seq_nr: seq,
                ack_nr: ack,
            };
            let mut f = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
            let n = h.encode(body, &mut f).unwrap();
            p.set_payload(&f[..n]).unwrap();
            r.receive(p, 0);
            // Drain, releasing anything the node hands back for transmission.
            loop {
                match r.work(&pool, &mut ifaces, 0) {
                    Routed::Respond { packet, .. } | Routed::Forwarded { packet, .. } => {
                        drop(pool.from_index(packet));
                    }
                    Routed::Idle => break,
                    _ => continue,
                }
            }
        };

        let mut ob = [0u8; rdp::SYN_OPTIONS_LEN];
        let ol = rdp::SynOptions::default().encode(&mut ob).unwrap();
        feed(&mut r, rdp::SYN, 1000, 0, &ob[..ol]);
        let h = r.accept().expect("the handshake announces the connection");
        let iss = r.conns.rdp(h).unwrap().snd_iss;
        feed(&mut r, rdp::ACK, 1001, iss, &[]);

        // Nine packets the application never reads -- one more than the old array held.
        for i in 1..=9u16 {
            feed(&mut r, rdp::ACK, 1000 + i, iss, b"x");
        }
        assert!(
            pool.available() < before,
            "the unread packets must actually be held, or this proves nothing"
        );

        // The peer resets.
        feed(&mut r, rdp::RST, 1010, iss, &[]);

        assert_eq!(
            pool.available(),
            before,
            "a reset must return every buffer the connection was holding"
        );
    }

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

    /// A node torn down while an application still holds unread packets returns them all.
    ///
    /// `close_all` stops as soon as its scratch array cannot hold another whole receive
    /// queue, so `shutdown` loops -- but a scratch array shorter than *one* queue makes it
    /// return `closed == 0` immediately and the loop exits having freed nothing. The
    /// existing `shutdown_releases_everything` calls `tick` first, so it hands shutdown an
    /// already-clean node and cannot see this.
    ///
    /// Counted in buffers, at a queue depth deeper than any fixed array in the file.
    #[test]
    fn shutdown_returns_buffers_from_a_deep_unread_queue() {
        type Deep = Router<4, 12, 48, 16>;
        let pool = Pool::<24, 264>::new();
        let mut r = Deep::new(ME, Version::V1);
        r.bind(7).unwrap();
        let mut ifaces = test_ifaces();
        let before = pool.available();

        for _ in 0..10 {
            let mut p = pool.acquire(0).unwrap();
            p.set_id(Id {
                pri: 2,
                flags: 0,
                src: 8,
                dst: ME,
                dport: 7,
                sport: 10,
            });
            p.set_payload(b"x").unwrap();
            r.receive(p, 0);
            let _ = r.work(&pool, &mut ifaces, 0);
        }
        assert!(
            pool.available() < before,
            "the packets must actually be held, or this proves nothing"
        );

        r.shutdown(&pool);
        assert_eq!(
            pool.available(),
            before,
            "shutdown must return every buffer sitting on a connection"
        );
    }

    /// The same for the idle-expiry sweep, which frees the queue of a connection nobody
    /// has touched. `expire_idle` skips any connection whose queue will not fit rather
    /// than partially draining it, so an array shorter than one queue means that
    /// connection is never expired at all -- not merely deferred to the next sweep.
    #[test]
    fn expiring_an_idle_connection_returns_its_whole_queue() {
        type Deep = Router<4, 12, 48, 16>;
        let pool = Pool::<24, 264>::new();
        let mut r = Deep::new(ME, Version::V1);
        r.bind(7).unwrap();
        let mut ifaces = test_ifaces();
        let before = pool.available();

        for _ in 0..10 {
            let mut p = pool.acquire(0).unwrap();
            p.set_id(Id {
                pri: 2,
                flags: 0,
                src: 8,
                dst: ME,
                dport: 7,
                sport: 10,
            });
            p.set_payload(b"x").unwrap();
            r.receive(p, 0);
            let _ = r.work(&pool, &mut ifaces, 0);
        }
        assert!(pool.available() < before);

        // Well past the timeout, in one sweep.
        let closed = r.tick(&pool, &test_ifaces(), 60_000, 1_000);
        assert_eq!(closed, 1, "the idle connection must be expired");
        assert_eq!(
            pool.available(),
            before,
            "expiry must return the whole queue, not part of it"
        );
    }

    #[test]
    fn an_empty_queue_is_idle_not_an_error() {
        // csp_route_work returns an error here, so every caller has to filter a normal
        // tick. SCOPE.md deviation 6.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        assert_eq!(r.work(&pool, &mut test_ifaces(), 0), Routed::Idle);
        assert_eq!(r.work(&pool, &mut test_ifaces(), 100), Routed::Idle);
    }

    #[test]
    fn a_packet_for_a_bound_port_is_delivered() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.receive(pkt(&pool, ME, 20, b"hello"), 0);

        match r.work(&pool, &mut test_ifaces(), 0) {
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
            r.work(&pool, &mut test_ifaces(), 0),
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
            r.work(&pool, &mut test_ifaces(), 0),
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
        r.routes.set(0, 0, 3, csp_core::rtable::NO_VIA).unwrap();
        r.receive(pkt(&pool, 25, 20, b"elsewhere"), 0);
        match r.work(&pool, &mut test_ifaces(), 0) {
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
            r.routes.set(0, 0, 3, csp_core::rtable::NO_VIA).unwrap();
            r.dedup_mode = mode;

            let mut delivered = 0;
            for _ in 0..2 {
                r.receive(pkt(&pool, ME, 20, b"identical"), 0);
                if let Routed::Delivered { .. } = r.work(&pool, &mut test_ifaces(), 10) {
                    delivered += 1;
                }
            }

            let mut forwarded = 0;
            for _ in 0..2 {
                r.receive(pkt(&pool, 25, 20, b"identical"), 0);
                if let Routed::Forwarded { packet, .. } = r.work(&pool, &mut test_ifaces(), 10) {
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
            r.work(&pool, &mut test_ifaces(), 0),
            Routed::Delivered { .. }
        ));

        r.receive(pkt(&pool, ME, 20, b"same"), 0);
        assert_eq!(
            r.work(&pool, &mut test_ifaces(), 10),
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
                r.work(&pool, &mut test_ifaces(), 0),
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
                r.work(&pool, &mut test_ifaces(), 0),
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
            r.work(&pool, &mut test_ifaces(), 0),
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
                r.work(&pool, &mut test_ifaces(), 0),
                Routed::Delivered { .. }
            ));
        }
        r.receive(pkt(&pool, ME, 20, b"x"), 0);
        assert_eq!(
            r.work(&pool, &mut test_ifaces(), 0),
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
            r.work(&pool, &mut test_ifaces(), 0),
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
            let _ = r.work(&pool, &mut test_ifaces(), 0);
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
            r.work(&pool, &mut test_ifaces(), 0),
            Routed::Delivered { .. }
        ));
        assert_eq!(r.conns.open_count(), 1);

        assert_eq!(
            r.tick(&pool, &test_ifaces(), 5_000, 10_000),
            0,
            "not yet idle"
        );
        let closed = r.tick(&pool, &test_ifaces(), 30_000, 10_000);
        assert!(closed >= 1, "an idle connection must be reclaimed");
        assert_eq!(r.conns.open_count(), 0);
    }

    #[test]
    fn the_tick_releases_packets_still_queued_on_an_expiring_connection() {
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);
        r.bind(20).unwrap();
        r.receive(pkt(&pool, ME, 20, b"x"), 0);
        r.work(&pool, &mut test_ifaces(), 0);
        assert_eq!(
            pool.available(),
            15,
            "the delivered packet is held on the conn"
        );

        r.tick(&pool, &test_ifaces(), 30_000, 10_000);
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
        r.work(&pool, &mut test_ifaces(), 0);
        assert!(pool.available() < 16);

        // drain what is on connections too
        r.tick(&pool, &test_ifaces(), 1_000_000, 1_000);
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
            r.work(&pool, &mut test_ifaces(), 0),
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
        let mut ifaces = {
            let mut l = crate::iflist::IfList::<4, 4>::new(Version::V2);
            l.add("IN", 40, 12, false).unwrap();
            l.add("A", 8, 12, false).unwrap();
            l.add("B", 9, 12, false).unwrap();
            l
        };
        let before = pool.available();
        r.receive(pkt(&pool, 10, 20, b"onward"), 0);
        match r.work(&pool, &mut ifaces, 0) {
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
        // Asserting the interface alone is what let the bridge destroy every packet it
        // claimed to forward: `Bridged::Forward` carried no slot, so `bridge_work` popped
        // the packet, named a destination and dropped it. Take the packet and read it.
        let pool = P::new();
        let mut r = R::new(ME, Version::V1);

        let mut check = |ingress: u8, expect_iface: u8, body: &[u8]| {
            r.receive(pkt(&pool, 25, 20, body), ingress);
            let Bridged::Forward { iface, packet } = r.bridge_work(&pool, 1, 2, 0) else {
                panic!("a frame on side {ingress} must be forwarded");
            };
            assert_eq!(iface, expect_iface);
            let p = pool.from_index(packet).expect("the caller owns the packet");
            assert!(
                p.with_frame(|f| f.ends_with(body)),
                "and it must still carry what arrived"
            );
        };
        check(1, 2, b"a to b");
        check(2, 1, b"b to a");
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
        let Bridged::Forward { iface, packet } = r.bridge_work(&pool, 1, 2, 0) else {
            panic!("the first copy is forwarded");
        };
        assert_eq!(iface, 2);
        drop(pool.from_index(packet).expect("the caller owns it"));
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
        let conn = match r.work(&pool, &mut test_ifaces(), 0) {
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
            r.work(&pool, &mut test_ifaces(), 0);
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
            r.work(&pool, &mut test_ifaces(), 0);
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
            r.work(&pool, &mut test_ifaces(), 0),
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

        let conn = match r.work(&pool, &mut test_ifaces(), 0) {
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
            r.work(&pool, &mut test_ifaces(), 0),
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
            r.work(&pool, &mut test_ifaces(), 0),
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
            a.work(&pa, &mut test_ifaces(), 0),
            Routed::Delivered { .. }
        ));
        assert_eq!(
            b.work(&pb, &mut test_ifaces(), 0),
            Routed::Idle,
            "b saw nothing"
        );
        assert_eq!(b.counters, Counters::default());
    }
}
