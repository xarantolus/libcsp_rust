//! The application-facing API: connect, send, accept, read.
//!
//! [`Router`](crate::Router) moves packets between the wire and connection queues.
//! [`Node`] is what an application actually calls.
//!
//! # Sending returns what to do, rather than doing it
//!
//! libcsp's `csp_send` reaches into a global interface list, picks a `nexthop` function
//! pointer and calls it. That is where its `void *` driver data comes from, and it is why
//! the C's ownership contract is uncheckable — "the nexthop owns the packet on success and
//! must not free it on failure".
//!
//! Here [`Node::send`] returns an [`Outbound`] saying which interface to use, and the
//! caller performs the transmit with [`Interface::send`](crate::Interface::send). No trait
//! objects, no function pointers, no allocator, and a failed send leaves the packet in the
//! caller's hands where it can be retried or released.
//!
//! # The transaction wart, fixed
//!
//! `csp_transaction` demands the reply be *exactly* the length of the buffer handed to it,
//! unless given `-1`. Every consumer in the flight repository works around this
//! identically — C, Rust and Python each pass `-1` with a comment explaining why.
//! [`Node::transaction`] returns the reply packet it got.

use crate::conn::Handle;
use crate::pool::{Packet, Pool};
use crate::router::{Routed, Router};
use crate::{Config, CspStorage};
use csp_core::{Error, Id, Result, Version};

#[cfg(feature = "rtable")]
use csp_core::rtable;

/// Why a route was not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unroutable {
    /// No routing table entry matched and no default interface is registered.
    NoRoute,
    /// The only route points back at the interface the packet arrived on.
    ///
    /// **Split horizon.** `csp_send_direct` skips a route whose interface shares a subnet
    /// with the one the packet came from; without it a forwarded packet can go straight
    /// back where it came from and loop.
    SplitHorizon {
        /// The interface it arrived on, and would have gone back out.
        iface: u8,
    },
}

/// Every interface a packet should go out on.
///
/// `csp_send_direct` does **not** pick one destination. It collects every routing-table
/// entry tied for the longest prefix, or — if none matched — every interface marked as a
/// default, and sends a **clone to each**, the last receiving the original. That is how
/// both redundant links and broadcast-to-all-interfaces are configured, and a port that
/// returns a single destination silently makes both single-path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destinations {
    entries: [Destination; 4],
    n: usize,
}

/// A connection's endpoints and options, from a single lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnInfo {
    /// Peer address packets arrive from.
    pub src: u16,
    /// Address packets are sent to.
    pub dst: u16,
    /// Port on this node.
    pub dport: u8,
    /// Port on the peer.
    pub sport: u8,
    /// Socket options (`sfp::opts`).
    pub opts: u32,
}

/// One place a packet goes: which interface, and the next hop on it.
///
/// A named struct rather than a `(u8, u16)` pair, because the two are both small unsigned
/// integers and a destructuring that swaps them compiles and routes every packet to the
/// wrong place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destination {
    /// Interface index, as returned by [`IfList::add`](crate::IfList::add).
    pub iface: u8,
    /// Next hop, or [`rtable::NO_VIA`] to send straight to the destination address.
    pub via: u16,
    /// The destination the frame should carry, which is not always the one asked for.
    ///
    /// `convert_broadcast` turns a routed (L3) broadcast into the local (L2) one -- the
    /// maximum node id -- as it reaches the interface, so a peer whose subnet is masked
    /// differently still recognises it as a broadcast.
    pub dst: u16,
}

impl Destinations {
    /// Every destination this packet goes to.
    pub fn as_slice(&self) -> &[Destination] {
        &self.entries[..self.n]
    }
    /// How many interfaces this packet goes out on.
    pub const fn len(&self) -> usize {
        self.n
    }
    /// True if the packet has nowhere to go.
    pub const fn is_empty(&self) -> bool {
        self.n == 0
    }
    /// How many clones the caller must make: one fewer than the destination count, since
    /// the last destination receives the original.
    pub const fn clones_needed(&self) -> usize {
        self.n.saturating_sub(1)
    }
}

/// Where a packet should go next.
///
/// Always carries the packet, so nothing is dropped behind the caller's back.
#[derive(Debug)]
pub enum Outbound<'p, const B: usize, const SZ: usize> {
    /// Send on this interface, to this next hop.
    Transmit {
        /// Interface index from the routing table.
        iface: u8,
        /// Next hop, or [`rtable::NO_VIA`] when the destination is directly reachable.
        via: u16,
        /// The packet, already carrying its header fields.
        packet: Packet<'p, B, SZ>,
    },
    /// Addressed to this node. Feed it back in with [`Router::receive`].
    Loopback(Packet<'p, B, SZ>),
    /// No usable route. The packet is **returned**, not dropped.
    NoRoute(Packet<'p, B, SZ>, Unroutable),
}

impl<'p, const B: usize, const SZ: usize> Outbound<'p, B, SZ> {
    /// The packet, whatever the outcome.
    pub fn into_packet(self) -> Packet<'p, B, SZ> {
        match self {
            Outbound::Transmit { packet, .. }
            | Outbound::Loopback(packet)
            | Outbound::NoRoute(packet, _) => packet,
        }
    }

    /// True if a route was found.
    pub const fn is_routed(&self) -> bool {
        matches!(self, Outbound::Transmit { .. })
    }
}

/// A CSP node: storage, router, and the application API over both.
#[derive(Debug)]
pub struct Node<
    'a,
    const CONNS: usize,
    const BUFS: usize,
    const BUFSZ: usize,
    const PORTS: usize,
    const QF: usize,
    const RXQ: usize,
> {
    storage: &'a CspStorage<CONNS, BUFS, BUFSZ, PORTS, QF>,
    /// The router. Exposed so a driver can inject received packets and the caller can
    /// drive `work`/`tick` on its own thread.
    pub router: Router<CONNS, RXQ, PORTS, QF>,
    /// Registered interfaces. Needed for the default-route fallback and for resolving an
    /// interface name in CMP `IF_STATS`.
    pub ifaces: crate::iflist::IfList<8, 8>,
    version: Version,
    address: u16,
    /// What this node calls itself, for CMP `IDENT`.
    ///
    /// `Config` has always accepted these and `Node::new` used to drop them, so a node
    /// configured with a hostname had no way to report it and `IDENT` could not be
    /// answered with anything the caller had set.
    hostname: &'a str,
    model: &'a str,
    revision: &'a str,
}

/// Ephemeral source ports start above the well-known service ports.
const EPHEMERAL_FIRST: u8 = 17;

impl<
        'a,
        const CONNS: usize,
        const BUFS: usize,
        const BUFSZ: usize,
        const PORTS: usize,
        const QF: usize,
        const RXQ: usize,
    > Node<'a, CONNS, BUFS, BUFSZ, PORTS, QF, RXQ>
{
    /// Build a node over caller-supplied storage.
    pub fn new(storage: &'a CspStorage<CONNS, BUFS, BUFSZ, PORTS, QF>, config: Config<'a>) -> Self {
        let version = config.version();
        let address = config.addr();
        Node {
            storage,
            router: Router::new(address, version),
            ifaces: crate::iflist::IfList::new(version),
            version,
            address,
            hostname: config.hostname,
            model: config.model,
            revision: config.revision,
        }
    }

    /// Hostname reported by CMP `IDENT`.
    pub const fn hostname(&self) -> &'a str {
        self.hostname
    }

    /// Hardware model reported by CMP `IDENT`.
    pub const fn model(&self) -> &'a str {
        self.model
    }

    /// This node's identity, ready to hand to
    /// [`respond_cmp`](crate::service::respond_cmp).
    ///
    /// One call rather than three field reads at the call site: an application that
    /// assembles the struct itself can leave a field out, and an `IDENT` reply missing a
    /// hostname is indistinguishable from a node that was never given one.
    ///
    /// `date` and `time` are empty. The C splices `__DATE__`/`__TIME__` in at compile
    /// time; an application that wants them passes its own [`Identity`](crate::service::Identity).
    #[cfg(feature = "cmp")]
    pub const fn identity(&self) -> crate::service::Identity<'a> {
        crate::service::Identity {
            hostname: self.hostname,
            model: self.model,
            revision: self.revision,
            date: "",
            time: "",
        }
    }

    /// Software revision reported by CMP `IDENT`.
    pub const fn revision(&self) -> &'a str {
        self.revision
    }

    /// This node's address — see [`Config::address`]. Not the source of what it sends.
    pub const fn address(&self) -> u16 {
        self.address
    }

    /// The wire version.
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The packet pool.
    pub const fn pool(&self) -> &'a Pool<BUFS, BUFSZ> {
        self.storage.pool_ref()
    }

    /// Take a packet from the pool.
    pub fn packet(&self) -> Option<Packet<'a, BUFS, BUFSZ>> {
        self.pool().acquire(0)
    }

    /// Free buffers — the `BUF_FREE` service.
    pub fn buffers_free(&self) -> usize {
        self.pool().available()
    }

    // --- server side ---

    /// Bind a port so packets for it are delivered.
    pub fn bind(&mut self, port: u8) -> Result<()> {
        self.router.bind(port)
    }

    /// Bind a port **connection-less** — `csp_bind` on a socket carrying
    /// `CSP_SO_CONN_LESS`.
    ///
    /// Packets for it are read with [`recvfrom`](Self::recvfrom) and never become a
    /// connection, so a server on such a port costs nothing from the connection table
    /// however many peers write to it. That is the C's own answer to a sink with more
    /// senders than connections, and the port had no equivalent: `recvfrom` drained the
    /// connection table and stopped at `CONNS` where a real node kept going until its
    /// buffer pool ran out.
    pub fn bind_conn_less(&mut self, port: u8) -> Result<()> {
        self.router.bind_conn_less(port)
    }

    /// Bind the catch-all, so every port with no bind of its own is delivered too.
    ///
    /// This is `csp_bind(socket, CSP_ANY)`, which is how both surveyed firmware consumers
    /// use libcsp: one catch-all, then dispatch on [`Delivered::dport`](crate::Delivered).
    /// An explicit [`bind`](Self::bind) still takes precedence, and a port at or above
    /// `PORTS` is dropped either way — both measured against a real node in
    /// `difftest/tests/node_bind_any.rs`.
    pub fn bind_any(&mut self) {
        self.router.bind_any();
    }

    /// Stop delivering ports that only the catch-all was serving.
    ///
    /// Returns how many connections were closed, releasing their queued packets as
    /// [`unbind`](Self::unbind) does.
    pub fn unbind_any(&mut self) -> usize {
        let mut closed = 0usize;
        loop {
            let mut drained = [0u16; RXQ];
            let (c, n) = self.router.unbind_any(&mut drained);
            for &idx in &drained[..n] {
                drop(self.pool().from_index(idx));
            }
            closed += c;
            if c == 0 {
                break;
            }
        }
        closed
    }

    /// Stop accepting on a port, closing every connection still open on it.
    ///
    /// Returns how many connections were closed. Their queued packets are released back
    /// to the pool here, so nothing is left holding a buffer for a port that has stopped
    /// being served.
    pub fn unbind(&mut self, port: u8) -> usize {
        // `close_port` stops as soon as the scratch array cannot hold another whole
        // receive queue and expects to be called again, so this loops and sizes by `RXQ`
        // -- the bound on one queue, which is what guarantees progress.
        //
        // It was a single call with a fixed `[0u16; 32]`. Past that point the remaining
        // connections stayed **open on a port the application had stopped serving**,
        // still matching incoming packets, each holding a buffer per unread packet with
        // nothing left to release them.
        let mut closed = 0usize;
        loop {
            let mut drained = [0u16; RXQ];
            let (c, n) = self.router.unbind(port, &mut drained);
            for &idx in &drained[..n] {
                drop(self.pool().from_index(idx));
            }
            closed += c;
            if c == 0 {
                break;
            }
        }
        closed
    }

    /// Reclaim a packet that [`Router::work`] reported as
    /// [`Routed::Forwarded`](crate::Routed::Forwarded).
    ///
    /// The router hands back a pool slot index rather than the packet, because `Routed`
    /// carries no lifetime. Call this with that index to get the packet and send it on the
    /// reported interface. Not calling it leaks the buffer.
    pub fn take_forwarded(&self, packet: u16) -> Option<Packet<'a, BUFS, BUFSZ>> {
        self.pool().from_index(packet)
    }

    /// Take the next connection with data waiting.
    ///
    /// Non-blocking: returns `None` rather than sleeping, because the caller owns the
    /// thread. `csp_accept` takes a timeout and blocks.
    pub fn accept(&mut self) -> Option<Handle> {
        self.router.accept()
    }

    /// Read the next packet queued on a connection.
    ///
    /// `Ok(None)` means nothing is waiting — an ordinary outcome, not an error.
    pub fn read(&mut self, conn: Handle) -> Result<Option<Packet<'a, BUFS, BUFSZ>>> {
        match self.router.conns.dequeue_rx(conn)? {
            Some(idx) => {
                // Reading freed a slot. On an RDP connection whose queue had filled, the
                // node stopped acknowledging on purpose to stall the peer; this is what
                // restarts it, and without it the connection stays wedged. `csp_read` does
                // the same at `csp_io.c:67`.
                #[cfg(feature = "rdp")]
                {
                    let pool = self.storage.pool_ref();
                    self.router.ack_after_read(pool, &self.ifaces, conn);
                }
                Ok(self.pool().from_index(idx))
            }
            None => Ok(None),
        }
    }

    /// Close a connection, releasing anything still queued on it.
    pub fn close(&mut self, conn: Handle) -> Result<()> {
        // `RXQ`, not a literal: `Table::close` refuses rather than partially draining, so
        // a shorter array made this return `BufferTooSmall` for a connection whose queue
        // was deeper -- leaving it open, with every buffer still held, from the one call a
        // caller makes when it has nothing left to try.
        let mut drained = [0u16; RXQ];
        let n = self.router.conns.close(conn, &mut drained)?;
        for &idx in &drained[..n] {
            drop(self.pool().from_index(idx));
        }
        Ok(())
    }

    /// Destination port of a connection's incoming header — how a dispatcher routes it.
    pub fn conn_dport(&self, conn: Handle) -> Result<u8> {
        self.router.conns.dport(conn)
    }

    /// Source address of a connection's peer.
    pub fn conn_src(&self, conn: Handle) -> Result<u16> {
        Ok(self.router.conns.id_in(conn)?.src)
    }

    /// Source port of a connection's peer.
    pub fn conn_sport(&self, conn: Handle) -> Result<u8> {
        Ok(self.router.conns.id_in(conn)?.sport)
    }

    /// Destination address a connection sends to.
    pub fn conn_dst(&self, conn: Handle) -> Result<u16> {
        Ok(self.router.conns.id_out(conn)?.dst)
    }

    /// Connection options.
    pub fn conn_opts(&self, conn: Handle) -> Result<u32> {
        self.router.conns.opts(conn)
    }

    /// Everything about a connection, in one lookup.
    ///
    /// The C exposes `csp_conn_dst`, `csp_conn_src`, `csp_conn_dport`, `csp_conn_sport`
    /// and `csp_conn_flags` as five separate calls, and the port mirrored them. That means
    /// five fallible lookups to describe one connection, each able to fail differently —
    /// and in practice a caller logging a connection makes all five and unwraps all five.
    /// This is one lookup and one error.
    ///
    /// The individual accessors remain, for the cases that genuinely want one field.
    pub fn conn_info(&self, conn: Handle) -> Result<ConnInfo> {
        let idin = self.router.conns.id_in(conn)?;
        Ok(ConnInfo {
            src: idin.src,
            dst: self.router.conns.id_out(conn)?.dst,
            dport: idin.dport,
            sport: idin.sport,
            opts: self.router.conns.opts(conn)?,
        })
    }

    /// True if the handle still refers to a live connection.
    pub fn conn_is_active(&self, conn: Handle) -> bool {
        self.router.conns.is_live(conn)
    }

    /// True once an RDP connection has completed its handshake.
    ///
    /// [`Node::connect`] returns as soon as the `SYN` is queued, so a caller that opened an
    /// RDP connection needs to know when the peer has answered — data sent before that is
    /// outside the send window and refused. Always false for a connection that is not RDP.
    #[cfg(feature = "rdp")]
    pub fn is_rdp_open(&self, conn: Handle) -> bool {
        self.router
            .conns
            .rdp(conn)
            .is_ok_and(csp_core::rdp::Connection::is_open)
    }

    /// Largest SFP payload per fragment on this connection.
    ///
    /// One method. Both firmware consumers reimplement this same
    /// flags → opts → `csp_sfp_opts_max_mtu` dance by hand.
    #[cfg(feature = "sfp")]
    pub fn conn_sfp_mtu(&self, conn: Handle) -> Result<usize> {
        let opts = self.router.conns.opts(conn)?;
        Ok(csp_core::sfp::max_mtu(BUFSZ - crate::pool::PADDING, opts))
    }

    // --- client side ---

    /// The ephemeral source port for the connection in slot `idx`.
    ///
    /// A function of the slot, exactly as in the C: `csp_conn_init` sets
    /// `conn->sport_outgoing = CSP_PORT_MAX_BIND + 1 + i` **once**, per slot
    /// (`csp_conn.c:58`), and `csp_connect` copies it into the outgoing header. So two
    /// connections that are open at the same time cannot share a source port -- they are
    /// different slots.
    ///
    /// That uniqueness is load-bearing, and both stacks lean on it in the same place:
    /// `Table::find` matches a *client* connection on the incoming destination port alone,
    /// as `csp_conn_find_existing` does, with the C's own comment saying it may because
    /// "outgoing connections are uniquely defined by the source port".
    ///
    /// This was a rotating counter, which gives that guarantee only until it wraps.
    /// Measured against a real node: with one connection still open on port 17, the 47th
    /// subsequent `connect` handed out 17 again, and a reply for either then went to
    /// whichever the scan reached first. See `difftest/tests/node_sport.rs`.
    ///
    /// If a node is configured with more connections than there are ephemeral ports the
    /// span repeats, which no allocation scheme can avoid; the C cannot serve that
    /// configuration either.
    fn sport_for(&self, idx: u16) -> u8 {
        let span = (self.version.max_port() - EPHEMERAL_FIRST) as u16 + 1;
        EPHEMERAL_FIRST + (idx % span) as u8
    }

    /// Open a connection to `dst`.
    ///
    /// `opts` is a mask of [`csp_core::security::opts`]. The protections it asks for are
    /// carried in the header of every packet on the connection, and expected in the header
    /// of every reply — this is what tells the peer to verify a checksum or a MAC, so an
    /// option that does not reach the header is a protection the caller asked for and
    /// silently did not get.
    ///
    /// With `RDP_REQ` the connection is not usable on return: a `SYN` is queued, and the
    /// next [`Node::work`] hands it to the wire as `Routed::Respond`. The connection is
    /// open once the peer's `SYN|ACK` has been fed back through `receive`. `csp_connect`
    /// blocks until that happens; there is nowhere to block here, so the caller drives it.
    /// Without the `rdp` feature `RDP_REQ` is refused outright.
    pub fn connect(
        &mut self,
        pri: u8,
        dst: u16,
        dport: u8,
        opts: u32,
        now_ms: u32,
    ) -> Result<Handle> {
        let flags = Self::conn_flags(opts)?;
        // `csp_connect` leaves the source zero: "CSP does not support 'source address' on
        // outgoing connections so the outgoing source address will be automatically applied
        // after outgoing routing selects which interface the packet will leave from"
        // (`csp_conn.c:259`). `route_from` fills it per destination.
        let mut idout = Id {
            pri,
            flags,
            src: 0,
            dst,
            dport,
            // A placeholder in range. The real one is a function of the slot, which is not
            // known until the connection is allocated.
            sport: EPHEMERAL_FIRST,
        };
        // Validate before consuming a connection slot, so a bad address does not cost one
        // of the node's scarcest resources.
        idout.validate(self.version)?;
        // A connection we opened is a Client: its reply is matched on destination port
        // alone, so a reply from a broadcast address still finds it.
        let h = self
            .router
            .conns
            .alloc_kind(idout, opts, now_ms, crate::conn::Kind::Client)?;
        let sport = self.sport_for(h.index());
        idout.sport = sport;
        self.router.conns.set_id_out(h, idout)?;
        // The reply we expect: their source is our destination and vice versa. The C sets
        // the same flags on both ids, but neither stack matches a reply on them --
        // `csp_conn_find_existing` compares ports and source only, so a reply that drops
        // the protection still finds the connection and is refused by the connection's
        // policy in `deliver_local`, not by failing to match.
        // `incoming_id.dst = 0`: the reply is accepted at whatever address the outgoing
        // interface turns out to have. A client connection is matched on its port alone.
        let idin = Id {
            pri,
            flags,
            src: dst,
            dst: 0,
            dport: sport,
            sport: dport,
        };
        self.router.conns.set_id_in(h, idin)?;

        // An RDP connection is not usable the moment it is allocated: the peer has to
        // answer a SYN first. The frame is queued rather than returned, so `connect` keeps
        // its shape and the caller's next `work()` transmits it like any other outbound
        // frame. `is_open` reports when the handshake finished.
        #[cfg(feature = "rdp")]
        if flags & csp_core::flags::RDP != 0 {
            if let Err(e) =
                self.router
                    .rdp_connect(&self.storage.pool, &self.ifaces, h, idout, now_ms)
            {
                // Do not leave a half-open connection holding a slot when the SYN could
                // not be built or routed.
                let mut drained = [0u16; RXQ];
                if let Ok(n) = self.router.conns.close(h, &mut drained) {
                    for slot in drained.iter().take(n) {
                        drop(self.storage.pool.from_index(*slot));
                    }
                }
                return Err(e);
            }
        }
        Ok(h)
    }

    /// The header flags a connection with these options puts on the wire.
    ///
    /// Mirrors `csp_connect` (`csp_conn.c:279-306`), including the rule that an explicit
    /// `CRC32_PROHIB` wins over `CRC32_REQ` rather than being a contradiction.
    fn conn_flags(opts: u32) -> Result<u8> {
        use csp_core::security::opts as o;

        let mut flags = 0u8;
        #[cfg(feature = "rdp")]
        if opts & o::RDP_REQ != 0 {
            flags |= csp_core::flags::RDP;
        }
        #[cfg(not(feature = "rdp"))]
        if opts & o::RDP_REQ != 0 {
            return Err(Self::rdp_unsupported());
        }
        if opts & o::HMAC_REQ != 0 {
            flags |= csp_core::flags::HMAC;
        }
        if (opts & o::CRC32_REQ != 0) && (opts & o::CRC32_PROHIB == 0) {
            flags |= csp_core::flags::CRC32;
        }
        Ok(flags)
    }

    /// Why `RDP_REQ` is refused in a build without the `rdp` feature.
    ///
    /// Setting `flags::RDP` without the state machine behind it would be worse than
    /// refusing — the peer would read the first five bytes of payload as an RDP header.
    ///
    /// This mirrors what the C does when built without `CSP_USE_RDP`: `csp_connect`
    /// records `CSP_DBG_ERR_UNSUPPORTED` and returns no connection.
    #[cfg(not(feature = "rdp"))]
    fn rdp_unsupported() -> Error {
        Error::Unsupported {
            feature: csp_core::Feature::Rdp,
        }
    }

    /// Send a packet on a connection.
    ///
    /// The packet's header is filled in from the connection. Returns where it should go;
    /// the caller performs the transmit.
    pub fn send(
        &mut self,
        conn: Handle,
        packet: Packet<'a, BUFS, BUFSZ>,
        now_ms: u32,
    ) -> Result<Outbound<'a, BUFS, BUFSZ>> {
        self.send_flagged(conn, packet, 0, now_ms)
    }

    /// Send one fragment of a stream on a connection.
    ///
    /// This is `csp_sfp_send`'s loop body: append the `[u32 offset][u32 total]` trailer at
    /// `data[length]` (`csp_sfp_header_add`) and mark the packet `FRAG`. Everything else —
    /// the header, the RDP trailer and its retransmission copy, routing — is [`Node::send`],
    /// so a fragment on an RDP connection goes out as `[body][sfp][rdp]`, the order
    /// `csp_rdp.c` strips them in.
    ///
    /// `offset` and `total` come from [`sfp::Fragmenter`](csp_core::sfp::Fragmenter), and
    /// each fragment's payload must be at most [`Node::conn_sfp_mtu`] bytes.
    ///
    /// **Why this exists.** `FRAG` is a per-packet flag, and [`Node::send`] stamps the
    /// connection's own id over whatever the caller set, so before this the bit was
    /// unreachable on a connection: the only send taking explicit flags is
    /// [`Node::sendto`], which has no connection and therefore cannot carry RDP either.
    /// A real C node refused a stream sent that way with `CSP_ERR_SFP` — measured, in
    /// `difftest/tests/node_sfp.rs`.
    ///
    /// Unlike the C this does **not** leave `FRAG` set on the connection.
    /// `csp_sfp.c:131` does `conn->idout.flags |= CSP_FFRAG` and nothing ever clears it, so
    /// in libcsp every later plain datagram on that connection is marked a fragment and the
    /// receiver destroys it (SCOPE.md 3).
    #[cfg(feature = "sfp")]
    pub fn send_fragment(
        &mut self,
        conn: Handle,
        mut packet: Packet<'a, BUFS, BUFSZ>,
        offset: u32,
        total: u32,
        now_ms: u32,
    ) -> Result<Outbound<'a, BUFS, BUFSZ>> {
        let mut trailer = [0u8; csp_core::sfp::HEADER_LEN];
        let tn = csp_core::sfp::Fragment::encode(offset, total, &[], &mut trailer)?;
        let len = packet.with_payload(<[u8]>::len);
        let appended = packet.with_payload_mut(|b| {
            if len + tn > b.len() {
                return (len, false);
            }
            b[len..len + tn].copy_from_slice(&trailer[..tn]);
            (len + tn, true)
        });
        if !appended {
            return Err(Error::BufferTooSmall { needed: len + tn });
        }
        self.send_flagged(conn, packet, csp_core::flags::FRAG, now_ms)
    }

    /// [`Node::send`], with `extra_flags` OR-ed into this packet's header only.
    ///
    /// The connection's stored flags are untouched, so the bit does not leak onto the next
    /// packet — which is exactly the C's `CSP_FFRAG` bug.
    fn send_flagged(
        &mut self,
        conn: Handle,
        mut packet: Packet<'a, BUFS, BUFSZ>,
        extra_flags: u8,
        now_ms: u32,
    ) -> Result<Outbound<'a, BUFS, BUFSZ>> {
        let mut id = self.router.conns.id_out(conn)?;
        id.flags |= extra_flags;
        self.router.conns.touch(conn, now_ms)?;

        // On an RDP connection the payload carries a trailer and a copy stays behind until
        // the peer acknowledges it. Without this the connection is reliable in name only:
        // the frame goes out once, a C peer does not recognise it as RDP data at all, and
        // nothing retransmits it. `csp_rdp_send` does exactly this -- stamp
        // `seq_nr = snd_nxt`, `ack_nr = rcv_cur`, set `ACK`, clone into the transmit queue.
        #[cfg(feature = "rdp")]
        let cur_len = packet.with_payload(<[u8]>::len);
        #[cfg(feature = "rdp")]
        if id.has_flag(csp_core::flags::RDP) {
            // Two different refusals, and a caller has to tell them apart: a full window
            // clears when an acknowledgement arrives, a reset connection never does.
            // Returning `SendWindowFull` for both meant an application retried for ever
            // against a peer that had hung up. `csp_rdp_send` (`csp_rdp.c:863`) separates
            // them the same way — `CSP_ERR_RESET` when the state is not open.
            if !self.is_rdp_open(conn) {
                return Err(Error::ConnectionReset);
            }
            let Some(h) = self.router.conns.begin_rdp_send(conn, now_ms) else {
                return Err(Error::SendWindowFull);
            };
            // The RDP header is a *trailer*: `csp_rdp_header_add` writes it at
            // `data[length]` and extends the length, so it lands after the payload.
            let mut trailer = [0u8; csp_core::rdp::HEADER_LEN];
            let tn = h.encode(&[], &mut trailer)?;
            let appended = packet.with_payload_mut(|b| {
                let len = b.len().min(cur_len);
                if len + tn > b.len() {
                    return (len, false);
                }
                b[len..len + tn].copy_from_slice(&trailer[..tn]);
                (len + tn, true)
            });
            if !appended {
                return Err(Error::BufferTooSmall {
                    needed: cur_len + tn,
                });
            }
            packet.set_id(id);
            // The copy is what gets retransmitted; the original goes out now.
            if let Some(copy) = packet.deep_copy() {
                let slot = copy.into_index();
                if self
                    .router
                    .conns
                    .hold_unacked(conn, h.seq_nr, slot, now_ms)
                    .is_err()
                {
                    // No room to hold it. Release rather than leak; the packet still goes
                    // out, and this connection simply has nothing to retransmit from.
                    drop(self.storage.pool_ref().from_index(slot));
                }
            }
            return Ok(self.route(packet, id));
        }

        packet.set_id(id);
        Ok(self.route(packet, id))
    }

    /// Send without a connection.
    pub fn sendto(
        &mut self,
        pri: u8,
        dst: u16,
        dport: u8,
        sport: u8,
        flags: u8,
        mut packet: Packet<'a, BUFS, BUFSZ>,
    ) -> Result<Outbound<'a, BUFS, BUFSZ>> {
        // `csp_sendto` sets no source; the interface the packet leaves by does.
        let id = Id {
            pri,
            flags,
            src: 0,
            dst,
            dport,
            sport,
        };
        id.validate(self.version)?;
        packet.set_id(id);
        Ok(self.route(packet, id))
    }

    /// Reply to a request without holding its connection open.
    ///
    /// This is `csp_sendto_reply(request, reply, CSP_O_SAME)`, used for deferred replies
    /// where the original connection is gone. In the C the request and the reply are
    /// **the same pointer** at the one call site that matters, passed as both a `const`
    /// and a mutable argument — which works only because of the order the fields happen to
    /// be read and written. Here they are two distinct values.
    ///
    /// The reply is sourced from the address the request was sent to — an alias answers as
    /// the alias, a subnet broadcast is echoed verbatim — except the all-nodes broadcast:
    /// `csp_sendto_reply` leaves that source zero (`csp_io.c:431`), and routing fills it
    /// with the address of the interface the reply leaves by, so `ping 0x3FFF` is answered
    /// by each node as itself. Sourced from `0x3FFF`, a reply is an answer from nobody, and
    /// that ping is how an operator learns who is on the bus. Measured in
    /// `difftest/tests/node_source_address.rs`.
    pub fn reply_to(
        &mut self,
        request: &Packet<'a, BUFS, BUFSZ>,
        mut reply: Packet<'a, BUFS, BUFSZ>,
    ) -> Result<Outbound<'a, BUFS, BUFSZ>> {
        let req = request.id();
        let src = if req.dst == self.version.max_node_id() {
            0
        } else {
            req.dst
        };
        let id = Id {
            pri: req.pri,
            flags: req.flags,
            src,
            dst: req.src,
            dport: req.sport,
            sport: req.dport,
        };
        id.validate(self.version)?;
        reply.set_id(id);
        Ok(self.route(reply, id))
    }

    /// Send overriding the connection's priority.
    ///
    /// `csp_send_prio` mutates `conn->idout.pri` permanently as a side effect, so every
    /// later packet on that connection inherits the new priority. Here the override
    /// applies to this packet only.
    pub fn send_prio(
        &mut self,
        conn: Handle,
        pri: u8,
        mut packet: Packet<'a, BUFS, BUFSZ>,
        now_ms: u32,
    ) -> Result<Outbound<'a, BUFS, BUFSZ>> {
        let mut id = self.router.conns.id_out(conn)?;
        id.pri = pri;
        id.validate(self.version)?;
        self.router.conns.touch(conn, now_ms)?;
        packet.set_id(id);
        Ok(self.route(packet, id))
    }

    /// Take the next packet from a [`bind_conn_less`](Self::bind_conn_less) port.
    ///
    /// This is `csp_recvfrom`, and like it, it answers only for a connection-less port:
    /// `csp_recvfrom` returns NULL for a socket without `CSP_SO_CONN_LESS`
    /// (`csp_io.c:379`), and an ordinary bound port is read with
    /// [`accept`](Self::accept) + [`read`](Self::read).
    ///
    /// The packet carries the header it arrived with, so the sender is `id().src` /
    /// `id().sport` — there is no connection to ask.
    pub fn recvfrom(&mut self) -> Result<Option<Packet<'a, BUFS, BUFSZ>>> {
        Ok(self
            .router
            .take_conn_less()
            .and_then(|idx| self.pool().from_index(idx)))
    }

    /// Wait for a reply on a connection, driving the router meanwhile.
    ///
    /// Returns the reply **packet**, whatever length it is. `csp_transaction` demands the
    /// reply be exactly the length of the buffer handed to it unless given `-1`, and all
    /// three consumers in the flight repository pass `-1` with a comment explaining why —
    /// C, Rust and Python arrived at the same workaround independently.
    ///
    /// `clock` is called for the current time each iteration rather than a `now` being
    /// passed once, so this works against a real clock instead of a synthetic tick.
    /// Returns [`Error::Truncated`] when `deadline_ms` passes with no reply.
    ///
    /// Transmission is the caller's: hand the request to an interface first, then wait
    /// here. Keeping the two apart is what lets one function serve a node whose interfaces
    /// are CAN, KISS, or a test double.
    pub fn transaction(
        &mut self,
        conn: Handle,
        deadline_ms: u32,
        mut clock: impl FnMut() -> u32,
    ) -> Result<Packet<'a, BUFS, BUFSZ>> {
        loop {
            if let Some(idx) = self.router.conns.dequeue_rx(conn)? {
                if let Some(p) = self.pool().from_index(idx) {
                    return Ok(p);
                }
            }
            let now = clock();
            if now >= deadline_ms {
                return Err(Error::Truncated);
            }
            // An idle step is ordinary here, which is exactly why csp_route_work's
            // idle-is-an-error behaviour had to go.
            let _ = self.work(now);
        }
    }

    /// Resolve where a packet goes, ignoring where it came from.
    fn route(&mut self, packet: Packet<'a, BUFS, BUFSZ>, id: Id) -> Outbound<'a, BUFS, BUFSZ> {
        self.route_from(packet, id, None)
    }

    /// Every interface a packet for `dst` should go out on.
    ///
    /// `csp_send_direct`'s policy, in its order: an interface whose **subnet owns** the
    /// destination first, then all routing-table entries tied for the longest prefix, and
    /// only if neither matched, every interface marked as a default. Each stage that finds
    /// anything suppresses the ones after it, even when split horizon leaves the match
    /// unusable — the C returns as soon as its `local_found` or `route_found` is set.
    ///
    /// Split horizon applies to all three: a destination on the interface the packet
    /// arrived on is skipped, or a forwarded packet goes straight back where it came from
    /// and loops.
    ///
    /// Each [`Destination`] carries the address its frame should be sent to, which differs
    /// from `dst` for a subnet broadcast — see [`Destination::dst`].
    pub fn resolve(
        &self,
        dst: u16,
        routed_from: Option<u8>,
    ) -> core::result::Result<Destinations, Unroutable> {
        let mut hops = [crate::route_policy::Hop {
            iface: 0,
            via: 0,
            dst: 0,
        }; 4];
        match crate::route_policy::destinations(
            &self.ifaces,
            &self.router.routes,
            self.version,
            dst,
            routed_from,
            &mut hops,
        ) {
            crate::route_policy::Outcome::Hops(n) => {
                let mut out = Destinations {
                    entries: [Destination {
                        iface: 0,
                        via: 0,
                        dst: 0,
                    }; 4],
                    n: 0,
                };
                for h in hops.iter().take(n) {
                    out.entries[out.n] = Destination {
                        iface: h.iface,
                        via: h.via,
                        dst: h.dst,
                    };
                    out.n += 1;
                }
                Ok(out)
            }
            crate::route_policy::Outcome::SplitHorizon => Err(Unroutable::SplitHorizon {
                iface: routed_from.unwrap_or(0),
            }),
            crate::route_policy::Outcome::NoRoute => Err(Unroutable::NoRoute),
        }
    }

    /// Resolve where a packet goes, given the interface it arrived on.
    ///
    /// Pass `routed_from` when **forwarding**: a route pointing back at that interface is
    /// skipped, which is split horizon. Pass `None` for locally originated traffic.
    ///
    /// Returns the **first** destination. When a packet has several — redundant routes, or
    /// several default interfaces — use [`Node::resolve`] and clone the packet for all but
    /// the last, which is what `csp_send_direct` does.
    pub fn route_from(
        &mut self,
        packet: Packet<'a, BUFS, BUFSZ>,
        id: Id,
        routed_from: Option<u8>,
    ) -> Outbound<'a, BUFS, BUFSZ> {
        let from_me = routed_from.is_none();
        if id.dst == self.address {
            let mut packet = packet;
            if from_me && id.src == 0 {
                // The loopback interface carries the node's own address.
                let mut out_id = id;
                out_id.src = self.address;
                packet.set_id(out_id);
            }
            return Outbound::Loopback(packet);
        }
        match self.resolve(id.dst, routed_from) {
            Ok(d) => {
                let first = d.as_slice()[0];
                let mut packet = packet;
                let mut out_id = id;
                out_id.dst = first.dst;
                // `send_packet` (`csp_io.c:119`): a packet this node originates is sourced
                // from the interface it leaves by, chosen only now. libcsp has no node
                // address, and a node with a CAN link and a radio link answers on each as
                // that link. Measured in `difftest/tests/node_source_address.rs`.
                if from_me && out_id.src == 0 {
                    out_id.src = self
                        .ifaces
                        .get(first.iface)
                        .map(|e| e.addr)
                        .unwrap_or(self.address);
                }
                if out_id != id {
                    packet.set_id(out_id);
                }
                // Only traffic this node originates is protected -- `csp_io.c:249`'s
                // `if (from_me)`, which is `routed_from.is_none()` here. A forwarded packet
                // already carries whatever its sender put on it, and appending again would
                // corrupt it.
                // `csp_send_direct_iface` frees the packet and counts `tx_error` when the
                // append fails (`csp_io.c:290`); here the caller gets it back to release.
                if from_me
                    && crate::egress::protect(&mut packet, id.flags, self.router.hmac_key).is_err()
                {
                    return Outbound::NoRoute(packet, Unroutable::NoRoute);
                }
                Outbound::Transmit {
                    iface: first.iface,
                    via: first.via,
                    packet,
                }
            }
            Err(why) => Outbound::NoRoute(packet, why),
        }
    }

    /// Install a route.
    #[cfg(feature = "rtable")]
    pub fn route_set(&mut self, address: u16, netmask: u16, iface: u8, via: u16) -> Result<()> {
        self.router.routes.set(address, netmask, iface, via)
    }

    /// Install the default route.
    #[cfg(feature = "rtable")]
    pub fn route_default(&mut self, iface: u8) -> Result<()> {
        self.router.routes.set(0, 0, iface, rtable::NO_VIA)
    }

    // --- the loop ---

    /// One step of the router.
    pub fn work(&mut self, now_ms: u32) -> Routed {
        let pool = self.storage.pool_ref();
        // The router cannot make a correct routing decision without the interface list:
        // local-subnet ownership beats the routing table, and split horizon compares
        // subnets. Passing it here is what closes that.
        self.router.work(pool, &mut self.ifaces, now_ms)
    }

    /// Periodic maintenance: RDP timers, and expiry of idle **server** connections.
    ///
    /// Returns how many connections it closed. `conn_timeout_ms` applies only to
    /// connections a peer opened by sending to a bound port — the ones nothing else will
    /// ever close. A connection this node's application opened with
    /// [`connect`](Self::connect) is never taken from under it however long it stays quiet,
    /// which is what libcsp does: `csp_conn_check_timeouts` looks at RDP connections and
    /// nothing else (`csp_conn.c:32`). See `difftest/tests/node_idle.rs`.
    pub fn tick(&mut self, now_ms: u32, conn_timeout_ms: u32) -> usize {
        let pool = self.storage.pool_ref();
        self.router
            .tick(pool, &self.ifaces, now_ms, conn_timeout_ms)
    }

    /// Release everything the node is holding.
    pub fn shutdown(&mut self) {
        let pool = self.storage.pool_ref();
        self.router.shutdown(pool);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type S = CspStorage<4, 16, 264, 48, 8>;
    type N<'a> = Node<'a, 4, 16, 264, 48, 8, 4>;

    const ME: u16 = 11;

    fn node(s: &S) -> N<'_> {
        Node::new(s, Config::new(Version::V1).address(ME))
    }

    /// The whole path from the public builder to the bytes a peer receives.
    ///
    /// `Node::new` used to read only `version` and `address` off the `Config` and drop
    /// the other three, so `Config::hostname(..)` was a setter with no effect on the only
    /// type that can route -- and a CMP `IDENT` could not be answered with the identity
    /// the application had configured. Nothing noticed, because nothing joined the two
    /// ends up: the builder had tests, the encoder had tests, and no test went from one
    /// to the other.
    /// An application closing a connection with unread packets gets its buffers back.
    ///
    /// `Table::close` refuses rather than partially draining, and `Node::close` passed a
    /// fixed `[0u16; 32]` and propagated the error with `?`. So on a connection whose
    /// queue is deeper than that, the application's own `close` **fails**, the connection
    /// stays open and every buffer stays held -- an error return from a teardown call is
    /// the one place a caller has no remaining move.
    #[test]
    fn closing_a_connection_with_a_deep_queue_returns_its_buffers() {
        type S3 = CspStorage<4, 64, 264, 48, 32>;
        type N3<'a> = Node<'a, 4, 64, 264, 48, 32, 40>;

        let s = S3::new();
        let mut n = N3::new(&s, Config::new(Version::V1).address(ME));
        n.ifaces.add("IF0", ME, 5, true).unwrap();
        n.bind(7).unwrap();
        let before = n.buffers_free();

        // 33 unread packets, one more than the fixed array held.
        for _ in 0..33 {
            let mut p = n.packet().expect("the pool is empty");
            p.set_id(Id {
                pri: 2,
                flags: 0,
                src: 8,
                dst: ME,
                dport: 7,
                sport: 40,
            });
            p.set_payload(b"x").unwrap();
            n.router.receive(p, 0);
            let _ = n.work(0);
        }
        let c = n.accept().expect("the connection is announced");
        assert!(n.buffers_free() < before);

        n.close(c)
            .expect("closing a connection must not fail on a deep queue");
        assert_eq!(
            n.buffers_free(),
            before,
            "close must return every buffer the connection was holding"
        );
    }

    /// Unbinding a port returns every buffer its connections were holding.
    ///
    /// `Table::close_port` stops as soon as its scratch array cannot hold another whole
    /// receive queue and expects to be called again -- `Node::unbind` called it once with
    /// a fixed `[0u16; 32]`. Past that point the remaining connections stay open, still
    /// bound to a port the application has stopped serving, holding a buffer per unread
    /// packet for good. `shutdown`, `tick` and the RST path were all corrected to size by
    /// `RXQ` and loop; this one was missed.
    ///
    /// Counted in buffers, with three connections deep enough that 32 cannot hold them.
    #[test]
    fn unbinding_a_port_returns_every_buffer_its_connections_held() {
        type S3 = CspStorage<4, 48, 264, 48, 32>;
        type N3<'a> = Node<'a, 4, 48, 264, 48, 32, 12>;

        let s = S3::new();
        let mut n = N3::new(&s, Config::new(Version::V1).address(ME));
        n.ifaces.add("IF0", ME, 5, true).unwrap();
        n.bind(7).unwrap();
        let before = n.buffers_free();

        // Three peers, twelve unread packets each: 36 slots, more than the 32 the fixed
        // array held.
        for sport in 40u8..43 {
            for _ in 0..12 {
                let mut p = n.packet().expect("the pool is empty");
                p.set_id(Id {
                    pri: 2,
                    flags: 0,
                    src: 8,
                    dst: ME,
                    dport: 7,
                    sport,
                });
                p.set_payload(b"x").unwrap();
                n.router.receive(p, 0);
                let _ = n.work(0);
            }
        }
        assert!(
            n.buffers_free() < before,
            "the packets must actually be held, or this proves nothing"
        );

        let closed = n.unbind(7);
        assert_eq!(closed, 3, "every connection on the port must be closed");
        assert_eq!(
            n.buffers_free(),
            before,
            "unbind must return every buffer the port's connections were holding"
        );
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn the_configured_identity_reaches_an_ident_reply() {
        let s = S::new();
        let n = Node::<'_, 4, 16, 264, 48, 8, 4>::new(
            &s,
            Config::new(Version::V1)
                .address(ME)
                .hostname("flight-node")
                .model("move-iiia")
                .revision("v2.1"),
        );

        struct NoHooks;
        impl crate::hooks::Hooks<16, 264> for NoHooks {}

        let mut out = [0u8; 256];
        let n_bytes = crate::service::respond_cmp(
            csp_core::cmp::Query::Ident,
            &n.identity(),
            Version::V1,
            &mut NoHooks,
            &mut out,
        )
        .unwrap()
        .expect("IDENT is always answerable");

        let reply = csp_core::cmp::Ident::decode(&out[..n_bytes]).unwrap();
        assert_eq!(reply.hostname, "flight-node");
        assert_eq!(reply.model, "move-iiia");
        assert_eq!(reply.revision, "v2.1");
    }

    #[cfg(feature = "rtable")]
    #[test]
    fn connect_send_and_route() {
        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();

        let c = n.connect(2, 8, 20, 0, 0).unwrap();
        assert_eq!(n.conn_dst(c).unwrap(), 8);

        let mut p = n.packet().unwrap();
        p.set_payload(b"command").unwrap();
        // Bound, not matched inline: a match scrutinee temporary lives to the end of the
        // match and would outlive the storage `n` borrows.
        let out = n.send(c, p, 0).unwrap();
        match out {
            Outbound::Transmit { iface, packet, .. } => {
                assert_eq!(iface, 3);
                assert_eq!(packet.id().dst, 8);
                assert_eq!(packet.id().src, ME);
                assert_eq!(packet.id().dport, 20);
                packet.with_payload(|d| assert_eq!(d, b"command"));
            }
            other => panic!("expected a transmit, got {other:?}"),
        }
    }

    #[test]
    fn a_packet_with_no_route_comes_back_rather_than_disappearing() {
        let s = S::new();
        let mut n = node(&s);
        let c = n.connect(2, 8, 20, 0, 0).unwrap();
        let p = n.packet().unwrap();
        let before = n.buffers_free();
        let out = n.send(c, p, 0).unwrap();
        assert!(!out.is_routed());
        assert!(matches!(out, Outbound::NoRoute(_, Unroutable::NoRoute)));
        let back = out.into_packet();
        assert_eq!(back.id().dst, 8, "still ours, still addressed");
        drop(back);
        assert_eq!(n.buffers_free(), before + 1);
    }

    #[cfg(feature = "rtable")]
    #[test]
    fn a_packet_to_ourselves_loops_back() {
        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();
        let mut p = n.packet().unwrap();
        p.set_payload(b"self").unwrap();
        let out = n.sendto(2, ME, 20, 10, 0, p).unwrap();
        assert!(
            matches!(out, Outbound::Loopback(_)),
            "must not go out a wire"
        );
    }

    #[test]
    fn connect_validates_before_consuming_a_connection_slot() {
        // Connection slots are the scarcest resource on the node; a bad address must not
        // cost one.
        let s = S::new();
        let mut n = node(&s);
        assert!(n.connect(2, 1000, 20, 0, 0).is_err(), "1000 needs 14 bits");
        assert_eq!(n.router.conns.open_count(), 0, "no slot consumed");
        // and the table is still fully usable
        for _ in 0..4 {
            n.connect(2, 8, 20, 0, 0).unwrap();
        }
    }

    #[test]
    fn a_full_connection_table_reports_rather_than_returning_nothing() {
        let s = S::new();
        let mut n = node(&s);
        for _ in 0..4 {
            n.connect(2, 8, 20, 0, 0).unwrap();
        }
        assert_eq!(n.connect(2, 8, 20, 0, 0), Err(Error::TableFull));
    }

    #[test]
    fn ephemeral_source_ports_do_not_collide_with_service_ports() {
        let s = S::new();
        let mut n = node(&s);
        for _ in 0..4 {
            let c = n.connect(2, 8, 20, 0, 0).unwrap();
            let sport = n.router.conns.id_out(c).unwrap().sport;
            assert!(
                sport >= EPHEMERAL_FIRST,
                "sport {sport} collides with the service port range"
            );
            assert!(sport <= Version::V1.max_port());
            n.close(c).unwrap();
        }
    }

    #[test]
    fn unbinding_a_port_returns_its_queued_buffers_to_the_pool() {
        // Clearing the bound flag is not enough: a connection created before the unbind
        // stays acceptable, so accept keeps handing out connections for a port nothing
        // serves -- and each one holds a pool buffer until it times out.
        let s = S::new();
        let mut n = node(&s);
        n.bind(20).unwrap();
        let free = n.buffers_free();

        let mut p = n.packet().unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"request").unwrap();
        n.router.receive(p, 0);
        assert!(matches!(n.work(0), Routed::Delivered { .. }));
        assert_eq!(
            n.buffers_free(),
            free - 1,
            "the packet is queued on a connection"
        );

        assert_eq!(n.unbind(20), 1, "one connection was still open on it");
        assert_eq!(n.buffers_free(), free, "and its buffer came back");
        assert!(
            n.accept().is_none(),
            "nothing is acceptable on an unbound port"
        );
    }

    #[test]
    fn unbinding_a_port_nothing_is_using_is_not_an_error() {
        let s = S::new();
        let mut n = node(&s);
        assert_eq!(n.unbind(20), 0);
        n.bind(20).unwrap();
        assert_eq!(n.unbind(20), 0, "bound but idle");
        // And it can be bound again afterwards.
        assert!(n.bind(20).is_ok());
    }

    #[test]
    fn a_connection_that_times_out_before_being_accepted_is_not_handed_out_dead() {
        // The accept backlog holds handles, and the idle sweep can close a connection
        // underneath one. Without purging, accept returns a handle that every later call
        // rejects -- the caller learns the connection is dead by being told so three
        // times, once per method.
        let s = S::new();
        let mut n = node(&s);
        n.bind(20).unwrap();

        let mut p = n.packet().unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"request").unwrap();
        n.router.receive(p, 0);
        assert!(matches!(n.work(0), Routed::Delivered { .. }));

        // Nobody accepted it, and the connection times out.
        assert_eq!(n.tick(60_000, 10_000), 1, "the idle sweep closed it");
        assert!(
            n.accept().is_none(),
            "a closed connection must not still be acceptable"
        );
    }

    #[test]
    fn conn_info_agrees_with_the_individual_accessors() {
        // Five accessors and one struct must not drift apart, or a caller that switches
        // between them sees a different connection.
        let s = S::new();
        let mut n = node(&s);
        n.bind(20).unwrap();

        let mut p = n.packet().unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"x").unwrap();
        n.router.receive(p, 0);
        assert!(matches!(n.work(0), Routed::Delivered { .. }));
        let c = n.accept().unwrap();

        let i = n.conn_info(c).unwrap();
        assert_eq!(i.src, n.conn_src(c).unwrap());
        assert_eq!(i.dst, n.conn_dst(c).unwrap());
        assert_eq!(i.dport, n.conn_dport(c).unwrap());
        assert_eq!(i.sport, n.conn_sport(c).unwrap());
        assert_eq!(i.opts, n.conn_opts(c).unwrap());
        assert_eq!((i.src, i.dport, i.sport), (8, 20, 10));
    }

    #[test]
    fn conn_info_on_a_closed_connection_fails_once_rather_than_five_times() {
        let s = S::new();
        let mut n = node(&s);
        let c = n.connect(2, 8, 20, 0, 0).unwrap();
        n.close(c).unwrap();
        assert!(n.conn_info(c).is_err());
    }

    #[test]
    fn end_to_end_receive_accept_read() {
        let s = S::new();
        let mut n = node(&s);
        n.bind(20).unwrap();

        // a driver injects a received packet
        let mut p = n.packet().unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"request").unwrap();
        n.router.receive(p, 0);

        assert!(matches!(n.work(0), Routed::Delivered { .. }));

        let c = n.accept().expect("a connection should be waiting");
        assert_eq!(n.conn_dport(c).unwrap(), 20);
        assert_eq!(n.conn_src(c).unwrap(), 8);
        assert_eq!(n.conn_sport(c).unwrap(), 10);

        let got = n.read(c).unwrap().expect("a packet should be queued");
        got.with_payload(|d| assert_eq!(d, b"request"));
        assert!(n.read(c).unwrap().is_none(), "only one was sent");
    }

    #[test]
    fn reading_an_empty_connection_is_not_an_error() {
        let s = S::new();
        let mut n = node(&s);
        let c = n.connect(2, 8, 20, 0, 0).unwrap();
        assert!(n.read(c).unwrap().is_none());
    }

    #[test]
    fn reading_a_closed_connection_reports_a_stale_handle() {
        let s = S::new();
        let mut n = node(&s);
        let c = n.connect(2, 8, 20, 0, 0).unwrap();
        n.close(c).unwrap();
        assert!(!n.conn_is_active(c));
        assert!(matches!(n.read(c), Err(Error::NoTransferInProgress)));
    }

    #[test]
    fn close_releases_queued_packets() {
        let s = S::new();
        let mut n = node(&s);
        n.bind(20).unwrap();
        let mut p = n.packet().unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"x").unwrap();
        n.router.receive(p, 0);
        n.work(0);

        let c = n.accept().unwrap();
        let before = n.buffers_free();
        n.close(c).unwrap();
        assert_eq!(
            n.buffers_free(),
            before + 1,
            "the queued packet must come back"
        );
    }

    #[cfg(feature = "rtable")]
    #[test]
    fn reply_to_swaps_the_addresses_and_ports() {
        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();

        let mut req = n.packet().unwrap();
        req.set_id(Id {
            pri: 1,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 33,
        });

        let mut rep = n.packet().unwrap();
        rep.set_payload(b"answer").unwrap();
        let out = n.reply_to(&req, rep).unwrap();
        let p = out.into_packet();
        let id = p.id();
        assert_eq!(id.dst, 8, "back to the sender");
        assert_eq!(id.src, ME);
        assert_eq!(id.dport, 33, "their source port becomes our destination");
        assert_eq!(id.sport, 20);
    }

    #[test]
    fn the_request_is_untouched_by_replying_to_it() {
        // In the C the request and the reply are the same pointer at the call site that
        // matters, passed as both a const and a mutable argument.
        let s = S::new();
        let mut n = node(&s);
        let mut req = n.packet().unwrap();
        req.set_id(Id {
            pri: 1,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 33,
        });
        req.set_payload(b"original request").unwrap();

        let rep = n.packet().unwrap();
        let _ = n.reply_to(&req, rep).unwrap();

        assert_eq!(req.id().src, 8, "request header must be unchanged");
        req.with_payload(|d| assert_eq!(d, b"original request"));
    }

    #[cfg(feature = "sfp")]
    #[test]
    fn the_sfp_mtu_is_one_call_not_a_dance() {
        // Both firmware consumers reimplement flags -> opts -> csp_sfp_opts_max_mtu.
        let s = S::new();
        let mut n = node(&s);
        let plain = n.connect(2, 8, 20, 0, 0).unwrap();
        let signed = n
            .connect(2, 8, 20, csp_core::security::opts::HMAC_REQ, 0)
            .unwrap();
        assert!(
            n.conn_sfp_mtu(signed).unwrap() < n.conn_sfp_mtu(plain).unwrap(),
            "the MAC has to come out of the usable MTU"
        );
    }

    /// The options a connection is opened with have to reach the header of what it sends,
    /// or the caller asked for a protection and silently did not get it: the peer only
    /// knows to verify a checksum or a MAC because the flag says so.
    ///
    /// Asserted on the emitted packet rather than on the connection, because the header is
    /// the only part the peer can see.
    #[cfg(feature = "rtable")]
    #[test]
    fn connect_options_reach_the_header() {
        use csp_core::security::opts as o;

        fn flags_on_the_wire(n: &mut N<'_>, opts: u32) -> u8 {
            let c = n.connect(2, 8, 20, opts, 0).unwrap();
            let p = n.packet().unwrap();
            match n.send(c, p, 0).unwrap() {
                Outbound::Transmit { packet, .. } => packet.id().flags,
                _ => panic!("expected a transmit"),
            }
        }

        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();

        assert_eq!(flags_on_the_wire(&mut n, 0), 0);
        assert_eq!(
            flags_on_the_wire(&mut n, o::CRC32_REQ),
            csp_core::flags::CRC32,
            "CSP_O_CRC32 sets CSP_FCRC32 in csp_connect"
        );
        // A MAC cannot be appended without a key, and `csp_hmac_append` failing is
        // `goto tx_err` in the C: the packet is freed and `tx_error` counted, not sent
        // unauthenticated with the flag set (`csp_io.c:249-256`).
        let c = n.connect(2, 8, 20, o::HMAC_REQ, 0).unwrap();
        let p = n.packet().unwrap();
        assert!(
            matches!(n.send(c, p, 0), Ok(Outbound::NoRoute(..))),
            "an HMAC connection on a node with no key must refuse rather than emit an \
             unprotected packet claiming to be protected"
        );
        // The table holds four and each check above opened one.
        n.close(c).unwrap();
        n.router.hmac_key = Some(b"0123456789abcdef");
        assert_eq!(
            flags_on_the_wire(&mut n, o::HMAC_REQ),
            csp_core::flags::HMAC
        );
        n.router.hmac_key = None;
        // csp_conn.c:279 — an explicit prohibition clears the request rather than being a
        // contradiction that stops the connection.
        assert_eq!(flags_on_the_wire(&mut n, o::CRC32_REQ | o::CRC32_PROHIB), 0);
    }

    /// A connection that flags RDP and does not speak it is worse than no connection: the
    /// peer reads the first five payload bytes as an RDP header.
    #[cfg(not(feature = "rdp"))]
    #[test]
    fn connect_refuses_rdp_rather_than_flagging_it() {
        let s = S::new();
        let mut n = node(&s);
        assert_eq!(
            n.connect(2, 8, 20, csp_core::security::opts::RDP_REQ, 0),
            Err(Error::Unsupported {
                feature: csp_core::Feature::Rdp
            })
        );
    }

    /// Opening an RDP connection puts a `SYN` on the wire and does not report the
    /// connection as usable until the peer has answered it.
    ///
    /// Asserted through what a peer would see and what the application may do, not through
    /// the state machine's own fields: a `connect` that returned an open connection before
    /// the handshake finished would let the caller send data the peer discards.
    /// An acknowledgement owed on the ack *timer* is sent by the tick, with nothing arriving.
    ///
    /// With delayed acks on — the default — a peer that sends fewer packets than
    /// `ack_delay_count` is acknowledged only when `ack_timeout` elapses.
    /// `csp_rdp_check_timeouts` calls `csp_rdp_check_ack` on every open connection for
    /// exactly this (`csp_rdp.c:451`). The port's `should_ack` had the timeout branch and
    /// nothing ever called it outside the receive path, so the acknowledgement waited for
    /// the peer to retransmit instead: measured at **zero** acknowledgements across ten
    /// seconds of ticks, where the C sends one after 250 ms.
    ///
    /// `rdp::a_proposed_ack_timeout_is_adopted` did not catch it, because its replay drives
    /// `poll_ack` in a loop itself — standing in for the timer the node did not have.
    #[cfg(feature = "rdp")]
    #[test]
    fn an_acknowledgement_owed_on_the_timer_is_sent_by_the_tick() {
        use csp_core::rdp;

        const PEER: u16 = 8;
        const PORT: u8 = 22;
        const PEER_ISS: u16 = 900;
        const ACK_TIMEOUT_MS: u32 = 250;

        let s = S::new();
        let mut n = node(&s);
        n.ifaces.add("test", ME, 5, true).unwrap();
        n.bind(PORT).unwrap();

        // Delay count 4, so one packet cannot reach it: only the timer can produce the ack.
        let opts = rdp::SynOptions {
            window_size: 2,
            delayed_acks: true,
            ack_delay_count: 4,
            ack_timeout: ACK_TIMEOUT_MS,
            ..rdp::SynOptions::default()
        };
        let mut body = [0u8; rdp::SYN_OPTIONS_LEN];
        let bn = opts.encode(&mut body).unwrap();
        let mut buf = [0u8; rdp::HEADER_LEN + rdp::SYN_OPTIONS_LEN];
        let k = rdp::Header {
            flags: rdp::SYN,
            seq_nr: PEER_ISS,
            ack_nr: 0,
        }
        .encode(&body[..bn], &mut buf)
        .unwrap();
        let pid = Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: ME,
            dport: PORT,
            sport: 42,
        };
        let mut syn = n.packet().expect("pool");
        syn.set_id(pid);
        syn.set_payload(&buf[..k]).unwrap();
        n.router.receive(syn, 0);

        let mut our_iss = 0u16;
        loop {
            match n.work(1000) {
                Routed::Respond { packet, .. } => {
                    let p = n.take_forwarded(packet).expect("slot");
                    p.with_payload(|b| {
                        if let Ok(h) = rdp::Header::decode(b) {
                            our_iss = h.seq_nr;
                        }
                    });
                    drop(p);
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
        let conn = n.accept().expect("announced");

        let mut third = n.packet().expect("pool");
        third.set_id(pid);
        let mut tb = [0u8; rdp::HEADER_LEN];
        let tk = rdp::Header {
            flags: rdp::ACK,
            seq_nr: PEER_ISS,
            ack_nr: our_iss,
        }
        .encode(&[], &mut tb)
        .unwrap();
        third.set_payload(&tb[..tk]).unwrap();
        n.router.receive(third, 0);
        while !matches!(n.work(1000), Routed::Idle) {}
        assert!(n.is_rdp_open(conn));

        // One data packet, well under the delay count, and nothing acknowledged for it yet.
        let mut d = n.packet().expect("pool");
        d.set_id(pid);
        let mut db = [0u8; rdp::HEADER_LEN + 4];
        let dk = rdp::Header {
            flags: rdp::ACK,
            seq_nr: PEER_ISS.wrapping_add(1),
            ack_nr: our_iss,
        }
        .encode(b"d", &mut db)
        .unwrap();
        d.set_payload(&db[..dk]).unwrap();
        n.router.receive(d, 0);
        let mut early = 0;
        while !matches!(n.work(1000), Routed::Idle) {
            early += 1;
        }
        let _ = early;

        // Now only time passes. Nothing else arrives; the application does not read.
        let mut acks = 0;
        for step in 1..=8u32 {
            let now = 1000 + step * ACK_TIMEOUT_MS;
            n.tick(now, 20_000);
            loop {
                match n.work(now) {
                    Routed::Respond { packet, .. } => {
                        let p = n.take_forwarded(packet).expect("slot");
                        p.with_payload(|b| {
                            if let Ok(h) = rdp::Header::decode(b) {
                                if h.flags & rdp::ACK != 0 {
                                    acks += 1;
                                }
                            }
                        });
                        drop(p);
                    }
                    Routed::Idle => break,
                    _ => continue,
                }
            }
        }

        assert!(
            acks > 0,
            "the ack timer produced nothing in {}ms with a packet outstanding -- the peer \
             is left to retransmit for an acknowledgement that was already owed",
            8 * ACK_TIMEOUT_MS
        );
    }

    /// With no headroom to keep, the queue fills — and nothing dropped is acknowledged.
    ///
    /// The receive-queue gate is skipped when `RXQ` is not deeper than the peer's window,
    /// because a node that cannot offer a window of headroom has none to keep. (The C never
    /// meets this: `CSP_CONN_RXQUEUE_LEN` is 16 against a maximum window of 5. `RXQ` here is
    /// a const generic and a caller may size it below what a peer proposes.)
    ///
    /// That is the configuration where the queue genuinely overflows, and the only one in
    /// which the drop-path guard is reachable at all — with the gate on, the peer is stalled
    /// before the queue can fill. What must hold either way: **the node never acknowledges
    /// more packets than the application can actually read.** An acknowledgement the
    /// application never sees is a packet the peer has already forgotten.
    #[cfg(feature = "rdp")]
    #[test]
    fn without_headroom_to_keep_nothing_dropped_is_acknowledged() {
        use csp_core::rdp;

        const PEER: u16 = 8;
        const PORT: u8 = 21;
        const PEER_ISS: u16 = 700;

        let s = S::new();
        let mut n = node(&s);
        n.ifaces.add("test", ME, 5, true).unwrap();
        n.bind(PORT).unwrap();

        // Window 5 against `RXQ` 4: no headroom to keep, so the gate stands aside.
        let opts = rdp::SynOptions {
            window_size: 5,
            delayed_acks: false,
            ..rdp::SynOptions::default()
        };
        let mut body = [0u8; rdp::SYN_OPTIONS_LEN];
        let bn = opts.encode(&mut body).unwrap();
        let mut buf = [0u8; rdp::HEADER_LEN + rdp::SYN_OPTIONS_LEN];
        let k = rdp::Header {
            flags: rdp::SYN,
            seq_nr: PEER_ISS,
            ack_nr: 0,
        }
        .encode(&body[..bn], &mut buf)
        .unwrap();
        let peer_id = Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: ME,
            dport: PORT,
            sport: 41,
        };
        let mut syn = n.packet().expect("pool");
        syn.set_id(peer_id);
        syn.set_payload(&buf[..k]).unwrap();
        n.router.receive(syn, 0);

        let mut our_iss = 0u16;
        loop {
            match n.work(1000) {
                Routed::Respond { packet, .. } => {
                    let p = n.take_forwarded(packet).expect("slot");
                    p.with_payload(|b| {
                        if let Ok(h) = rdp::Header::decode(b) {
                            our_iss = h.seq_nr;
                        }
                    });
                    drop(p);
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
        let conn = n.accept().expect("announced");

        let mut third = n.packet().expect("pool");
        third.set_id(peer_id);
        let mut tb = [0u8; rdp::HEADER_LEN];
        let tk = rdp::Header {
            flags: rdp::ACK,
            seq_nr: PEER_ISS,
            ack_nr: our_iss,
        }
        .encode(&[], &mut tb)
        .unwrap();
        third.set_payload(&tb[..tk]).unwrap();
        n.router.receive(third, 0);
        while !matches!(n.work(1000), Routed::Idle) {}
        assert!(n.is_rdp_open(conn));

        // More packets than the queue holds, none read until the end.
        let mut acks = 0usize;
        for i in 1..=8u16 {
            let mut p = n.packet().expect("pool");
            p.set_id(peer_id);
            let mut b = [0u8; rdp::HEADER_LEN + 4];
            let k = rdp::Header {
                flags: rdp::ACK,
                seq_nr: PEER_ISS.wrapping_add(i),
                ack_nr: our_iss,
            }
            .encode(b"d", &mut b)
            .unwrap();
            p.set_payload(&b[..k]).unwrap();
            n.router.receive(p, 0);
            loop {
                match n.work(1000 + i as u32) {
                    Routed::Respond { packet, .. } => {
                        let p = n.take_forwarded(packet).expect("slot");
                        p.with_payload(|b| {
                            if let Ok(h) = rdp::Header::decode(b) {
                                if h.flags & rdp::ACK != 0 {
                                    acks += 1;
                                }
                            }
                        });
                        drop(p);
                    }
                    Routed::Idle => break,
                    _ => continue,
                }
            }
        }

        let mut read = 0usize;
        while let Ok(Some(p)) = n.read(conn) {
            read += 1;
            drop(p);
        }

        assert!(
            acks <= read,
            "acknowledged {acks} packet(s) but the application could only read {read} -- \
             the difference was promised to the peer and then dropped, and the peer has \
             already released its only copy"
        );
    }

    /// A full receive queue stalls the peer, and reading restarts it.
    ///
    /// Three properties, all of them about what a peer sees:
    ///
    /// 1. **Nothing dropped is ever acknowledged.** An acknowledgement is a promise that a
    ///    packet was kept; the peer discards its only copy on the strength of it. This
    ///    node used to acknowledge *before* attempting the enqueue, so a packet it had no
    ///    room for was promised and then thrown away. Measured against a real C peer before
    ///    the fix: it sent 12, the application could read 8, and 4 were acknowledged into
    ///    nothing.
    /// 2. **Acknowledgement stops before the queue overflows.** `csp_rdp_check_ack` keeps a
    ///    window of headroom for exactly this reason, so the peer stalls rather than
    ///    overflowing a node whose application has stopped reading.
    /// 3. **Reading restarts it.** Without that the stall is permanent and the connection
    ///    is wedged; `csp_read` re-runs the same check at `csp_io.c:67`.
    #[cfg(feature = "rdp")]
    #[test]
    fn a_full_receive_queue_stalls_the_peer_and_reading_restarts_it() {
        use csp_core::rdp;

        const PEER: u16 = 8;
        const PORT: u8 = 20;
        const PEER_ISS: u16 = 500;

        let s = S::new();
        let mut n = node(&s);
        n.ifaces.add("test", ME, 5, true).unwrap();
        n.bind(PORT).unwrap();

        // A peer opens an RDP connection, proposing a window smaller than our queue so the
        // gate has headroom to keep. `RXQ` here is 4.
        let opts = rdp::SynOptions {
            window_size: 2,
            delayed_acks: false,
            ..rdp::SynOptions::default()
        };
        let mut body = [0u8; rdp::SYN_OPTIONS_LEN];
        let bn = opts.encode(&mut body).unwrap();
        let mut buf = [0u8; rdp::HEADER_LEN + rdp::SYN_OPTIONS_LEN];
        let k = rdp::Header {
            flags: rdp::SYN,
            seq_nr: PEER_ISS,
            ack_nr: 0,
        }
        .encode(&body[..bn], &mut buf)
        .unwrap();
        let peer_id = Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: ME,
            dport: PORT,
            sport: 40,
        };
        let mut syn = n.packet().expect("pool");
        syn.set_id(peer_id);
        syn.set_payload(&buf[..k]).unwrap();
        n.router.receive(syn, 0);

        // Drain the handshake, remembering our own initial sequence for the peer's ACK.
        let mut our_iss = 0u16;
        loop {
            match n.work(1000) {
                Routed::Respond { packet, .. } => {
                    let p = n.take_forwarded(packet).expect("slot");
                    p.with_payload(|b| {
                        if let Ok(h) = rdp::Header::decode(b) {
                            our_iss = h.seq_nr;
                        }
                    });
                    drop(p);
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
        // A handshake carries no data, so the connection arrives through `accept`, not
        // through a `Delivered` event.
        let conn = n.accept().expect("the handshake announced a connection");

        // The handshake's third leg. Without it the connection sits in `SynRcvd` and every
        // data packet below is ignored -- which is what this test did at first, while its
        // comment claimed otherwise.
        let mut third = n.packet().expect("pool");
        third.set_id(peer_id);
        let mut tb = [0u8; rdp::HEADER_LEN];
        let tk = rdp::Header {
            flags: rdp::ACK,
            seq_nr: PEER_ISS,
            ack_nr: our_iss,
        }
        .encode(&[], &mut tb)
        .unwrap();
        third.set_payload(&tb[..tk]).unwrap();
        n.router.receive(third, 0);
        while !matches!(n.work(1000), Routed::Idle) {}
        assert!(n.is_rdp_open(conn), "the third leg opens the connection");

        // One data packet from the peer, per step, never read by the application.
        let deliver = |n: &mut N<'_>, seq: u16, now: u32| -> bool {
            let mut p = n.packet().expect("pool");
            p.set_id(peer_id);
            let mut b = [0u8; rdp::HEADER_LEN + 4];
            let k = rdp::Header {
                flags: rdp::ACK,
                seq_nr: seq,
                ack_nr: our_iss,
            }
            .encode(b"d", &mut b)
            .unwrap();
            p.set_payload(&b[..k]).unwrap();
            n.router.receive(p, 0);
            let mut acked = false;
            loop {
                match n.work(now) {
                    Routed::Respond { packet, .. } => {
                        let p = n.take_forwarded(packet).expect("slot");
                        p.with_payload(|b| {
                            if let Ok(h) = rdp::Header::decode(b) {
                                if h.flags & rdp::ACK != 0 {
                                    acked = true;
                                }
                            }
                        });
                        drop(p);
                    }
                    Routed::Idle => break,
                    _ => continue,
                }
            }
            acked
        };

        // Data until the queue is full, none of it read.
        // `no_std`: a fixed array, not a Vec.
        let mut acks = [false; 6];
        for (i, slot) in acks.iter_mut().enumerate() {
            let seq = PEER_ISS.wrapping_add(i as u16 + 1);
            *slot = deliver(&mut n, seq, 1000 + i as u32);
        }
        assert!(
            acks.iter().any(|a| !a),
            "acknowledgement must stop once the queue is nearly full -- every one of the \
             six was acknowledged, so the peer is never told to slow down and the overflow \
             is silent"
        );

        // What the application can actually read is what was kept; nothing beyond it was
        // acknowledged, because the ack now follows a successful enqueue.
        let mut read = 0;
        while let Ok(Some(p)) = n.read(conn) {
            read += 1;
            drop(p);
        }
        assert!(read > 0, "the application receives what fitted");

        // Reading freed room, so the node acknowledges again and the peer may resume.
        let mut resumed = false;
        loop {
            match n.work(2000) {
                Routed::Respond { packet, .. } => {
                    let p = n.take_forwarded(packet).expect("slot");
                    p.with_payload(|b| {
                        if let Ok(h) = rdp::Header::decode(b) {
                            if h.flags & rdp::ACK != 0 {
                                resumed = true;
                            }
                        }
                    });
                    drop(p);
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
        assert!(
            resumed,
            "reading must restart the peer -- without an acknowledgement after the queue \
             drains the stall is permanent and the connection is wedged for good"
        );
    }

    #[cfg(feature = "rdp")]
    #[test]
    fn connect_over_rdp_sends_a_syn_and_opens_only_on_the_reply() {
        use csp_core::rdp;

        const PEER: u16 = 8;

        let s = S::new();
        let mut n = node(&s);
        n.ifaces.add("test", ME, 5, true).unwrap();

        let h = n
            .connect(2, PEER, 20, csp_core::security::opts::RDP_REQ, 1000)
            .expect("an RDP connect is accepted");

        // The SYN reaches the wire, carrying the option block a peer needs to answer.
        let mut syn = None;
        loop {
            match n.work(1000) {
                Routed::Respond { packet, .. } => {
                    let p = n.take_forwarded(packet).expect("a live slot");
                    syn = p.with_payload(|b| rdp::Header::decode(b).ok().map(|hd| (hd, b.len())));
                    drop(p);
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
        let (hd, len) = syn.expect("connect queued a SYN");
        assert_eq!(hd.flags, rdp::SYN);
        assert_eq!(len - rdp::HEADER_LEN, rdp::SYN_OPTIONS_LEN);

        // Until the peer answers, the connection is not open and carries no data.
        assert!(!n.is_rdp_open(h));

        // The peer's SYN|ACK, acknowledging the sequence we proposed. It has to be
        // addressed to the ephemeral source port `connect` chose, or it matches no
        // connection and the handshake never finishes.
        let info = n.conn_info(h).expect("the connection is live");
        let mut reply = n.packet().expect("the pool is empty");
        reply.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: ME,
            dport: info.dport,
            sport: info.sport,
        });
        let ack = rdp::Header {
            flags: rdp::SYN | rdp::ACK,
            seq_nr: 500,
            ack_nr: hd.seq_nr,
        };
        let mut buf = [0u8; rdp::HEADER_LEN + rdp::SYN_OPTIONS_LEN];
        let opts = rdp::SynOptions::default();
        let mut body = [0u8; rdp::SYN_OPTIONS_LEN];
        let bn = opts.encode(&mut body).unwrap();
        let k = ack.encode(&body[..bn], &mut buf).unwrap();
        reply.set_payload(&buf[..k]).unwrap();
        n.router.receive(reply, 0);
        while !matches!(n.work(1100), Routed::Idle) {}

        assert!(
            n.is_rdp_open(h),
            "the connection opens once the peer's SYN|ACK arrives"
        );
    }

    #[cfg(feature = "rtable")]
    #[test]
    fn send_prio_does_not_change_the_connection_permanently() {
        // csp_send_prio mutates conn->idout.pri as a side effect, so every later packet
        // on that connection silently inherits the override.
        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();
        let c = n.connect(2, 8, 20, 0, 0).unwrap();

        let out = n.send_prio(c, 0, n.packet().unwrap(), 0).unwrap();
        assert_eq!(out.into_packet().id().pri, 0);

        let out = n.send(c, n.packet().unwrap(), 0).unwrap();
        assert_eq!(
            out.into_packet().id().pri,
            2,
            "the connection keeps its own priority"
        );
    }

    /// A packet arriving on a connection-less port keeps the sender in its own header —
    /// there is no connection to ask who sent it.
    #[test]
    fn recvfrom_hands_back_the_packet_with_the_senders_header() {
        let s = S::new();
        let mut n = node(&s);
        n.bind_conn_less(20).unwrap();
        let mut p = n.packet().unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"connectionless").unwrap();
        n.router.receive(p, 0);
        n.work(0);

        let got = n.recvfrom().unwrap().expect("a packet should be waiting");
        got.with_payload(|d| assert_eq!(d, b"connectionless"));
        assert_eq!((got.id().src, got.id().sport), (8, 10), "who sent it");
        assert_eq!(got.id().dport, 20, "and which port it was for");
    }

    /// `csp_recvfrom` answers only for a `CSP_SO_CONN_LESS` socket (`csp_io.c:379`).
    ///
    /// The packet must still be delivered — to `accept` + `read`, the ordinary way — so
    /// this is about which door it comes out of, not whether it arrives.
    #[test]
    fn recvfrom_says_nothing_about_an_ordinary_bound_port() {
        let s = S::new();
        let mut n = node(&s);
        n.bind(20).unwrap();
        let mut p = n.packet().unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst: ME,
            dport: 20,
            sport: 10,
        });
        p.set_payload(b"connection-oriented").unwrap();
        n.router.receive(p, 0);
        n.work(0);

        assert!(n.recvfrom().unwrap().is_none(), "not a conn-less port");
        let conn = n.accept().expect("but the ordinary path has it");
        let got = n.read(conn).unwrap().expect("a packet");
        got.with_payload(|d| assert_eq!(d, b"connection-oriented"));
    }

    #[test]
    fn recvfrom_on_an_idle_node_is_not_an_error() {
        let s = S::new();
        let mut n = node(&s);
        n.bind_conn_less(20).unwrap();
        assert!(n.recvfrom().unwrap().is_none());
    }

    #[test]
    fn a_transaction_returns_the_reply_whatever_its_length() {
        // csp_transaction demands an exact length unless given -1; all three consumers
        // in the flight repo pass -1 with a comment explaining why.
        let s = S::new();
        let mut n = node(&s);
        let c = n.connect(2, 8, 20, 0, 0).unwrap();

        // The peer's reply arrives on the connection's expected incoming header.
        let idin = n.router.conns.id_in(c).unwrap();
        let mut reply = n.packet().unwrap();
        reply.set_id(idin);
        reply
            .set_payload(b"a reply of some arbitrary length")
            .unwrap();
        let idx = reply.into_index();
        n.router.conns.enqueue_rx(c, idx).unwrap();

        let got = n.transaction(c, 100, || 0).unwrap();
        got.with_payload(|d| assert_eq!(d, b"a reply of some arbitrary length"));
    }

    #[test]
    fn a_transaction_that_gets_no_reply_times_out() {
        let s = S::new();
        let mut n = node(&s);
        let c = n.connect(2, 8, 20, 0, 0).unwrap();
        // A clock that advances, so the deadline is actually reached rather than spun on.
        let mut t = 0u32;
        assert!(matches!(
            n.transaction(c, 50, || {
                t += 10;
                t
            }),
            Err(Error::Truncated)
        ));
    }

    #[cfg(feature = "sfp")]
    #[test]
    fn the_fragment_flag_is_per_packet_not_sticky_on_the_connection() {
        // csp_sfp.c:131 does `conn->idout.flags |= CSP_FFRAG` inside the send loop and
        // NOTHING in the library ever clears it. So after one SFP transfer, every later
        // plain datagram on that connection is marked as a fragment -- and the receiver,
        // per SCOPE.md 3, parses it as one, fails, and FREES it. The sender causes the
        // condition and the receiver destroys the packet.
        //
        // This used to set `FRAG` on the packet `send` had already returned and then check
        // the next one did not have it -- which is true of any two packets and says nothing
        // about the connection. It read as coverage because the port had no way to send a
        // fragment at all; `send_fragment` is what makes the question askable.
        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();
        let c = n.connect(2, 8, 20, 0, 0).unwrap();

        let mut frag = n.packet().unwrap();
        frag.set_payload(b"fragment").unwrap();
        let out = n.send_fragment(c, frag, 0, 8, 0).unwrap();
        assert!(
            out.into_packet().id().is_fragment(),
            "a fragment must leave marked as one"
        );

        // A later plain packet on the SAME connection must not inherit it.
        let plain = n.packet().unwrap();
        let out = n.send(c, plain, 0).unwrap();
        assert!(
            !out.into_packet().id().is_fragment(),
            "the connection must not carry FRAG over to the next packet"
        );
    }

    #[cfg(feature = "sfp")]
    #[test]
    fn a_fragment_carries_its_offset_and_total_where_the_c_looks_for_them() {
        // `csp_sfp_header_add` writes the trailer at `data[length]` and extends the length,
        // so it lands after the payload, big-endian. Parsing it back with the reader the
        // port would use on the receiving side is the round trip; that a *real C node*
        // accepts the same bytes is `difftest/tests/node_sfp.rs`.
        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();
        let c = n.connect(2, 8, 20, 0, 0).unwrap();

        let mut p = n.packet().unwrap();
        p.set_payload(b"second").unwrap();
        let out = n.send_fragment(c, p, 6, 12, 0).unwrap();
        let packet = out.into_packet();
        let (offset, total, payload) = packet.with_payload(|d| {
            let f = csp_core::sfp::Fragment::parse(true, d).expect("a trailer the reader knows");
            (f.offset, f.total, f.payload.to_vec())
        });
        assert_eq!(offset, 6);
        assert_eq!(total, 12);
        assert_eq!(payload, b"second");
    }

    #[cfg(feature = "rtable")]
    #[test]
    fn split_horizon_refuses_to_send_a_packet_back_where_it_came_from() {
        // csp_send_direct skips a route whose interface matches the one the packet
        // arrived on. Without it, a forwarded packet can go straight back and loop.
        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();

        let mut p = n.packet().unwrap();
        let id = Id {
            pri: 2,
            flags: 0,
            src: 8,
            dst: 25,
            dport: 20,
            sport: 10,
        };
        p.set_id(id);

        // Arrived on interface 3, and the only route points back at 3.
        let out = n.route_from(p, id, Some(3));
        assert!(
            matches!(
                out,
                Outbound::NoRoute(_, Unroutable::SplitHorizon { iface: 3 })
            ),
            "must refuse, and say why"
        );

        // Arrived on a different interface: forwarding is fine.
        let mut p2 = n.packet().unwrap();
        p2.set_id(id);
        assert!(n.route_from(p2, id, Some(1)).is_routed());
    }

    #[cfg(feature = "rtable")]
    #[test]
    fn locally_originated_traffic_is_not_subject_to_split_horizon() {
        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();
        let c = n.connect(2, 8, 20, 0, 0).unwrap();
        let out = n.send(c, n.packet().unwrap(), 0).unwrap();
        assert!(
            out.is_routed(),
            "a packet we originated has no ingress interface"
        );
    }

    #[test]
    fn a_packet_with_no_route_falls_back_to_the_default_interfaces() {
        // csp_send_direct falls through to csp_iflist_get_by_isdfl when nothing matched.
        // Without it, a node with a default interface and an empty routing table can send
        // nothing at all.
        let s = S::new();
        let mut n = node(&s);
        n.ifaces.add("CAN", 1, 5, true).unwrap();
        n.ifaces.add("KISS", 2, 5, false).unwrap();

        let d = n
            .resolve(25, None)
            .expect("the default interface must be used");
        assert_eq!(d.len(), 1);
        assert_eq!(d.as_slice()[0].iface, 0, "only the default-marked one");
    }

    /// Split horizon is a **subnet** test, not an interface-identity test.
    ///
    /// `is_same_subnet` (`csp_io.c:93`) is two clauses: the candidate *is* the interface
    /// the packet arrived on, **or** the candidate's address falls inside that interface's
    /// subnet. Two links on the same subnet are two ways onto the same wire, so relaying
    /// between them is the loop split horizon exists to stop -- and only the second clause
    /// catches it.
    ///
    /// `Router::split_horizon` has both. `resolve` had only the first, so it relayed a
    /// packet back onto the wire it came from by way of the other link. Measured against
    /// the C in `route::split_horizon_vetoes_a_second_link_on_the_same_subnet`, where the
    /// C emits nothing.
    #[test]
    fn split_horizon_vetoes_another_link_on_the_same_subnet() {
        let s = S::new();
        let mut n = N::new(&s, Config::new(Version::V2).address(9999));
        // Both own 8..11, and each address is inside the other's subnet.
        n.ifaces.add("LINK_A", 8, 12, false).unwrap();
        n.ifaces.add("LINK_B", 9, 12, false).unwrap();

        assert!(
            matches!(
                n.resolve(10, Some(0)),
                Err(Unroutable::SplitHorizon { iface: 0 })
            ),
            "a second link on the same subnet is the loop split horizon exists to stop"
        );
        // Arriving from somewhere else, both are usable.
        n.ifaces.add("ELSEWHERE", 40, 12, false).unwrap();
        assert_eq!(n.resolve(10, Some(2)).unwrap().len(), 2);
    }

    /// Split horizon on the subnet path, which the routing-table and default paths each
    /// have their own test for. The C applies `is_same_subnet(iface, routed_from)` in all
    /// three loops; only this one had no coverage.
    #[test]
    fn split_horizon_applies_to_the_local_subnet_too() {
        let s = S::new();
        let mut n = N::new(&s, Config::new(Version::V2).address(9999));
        // 8/12 owns 8..11, so it owns 10.
        n.ifaces.add("LINK_A", 8, 12, false).unwrap();

        // Arriving on LINK_A itself: sending back out of it is the loop.
        assert!(matches!(
            n.resolve(10, Some(0)),
            Err(Unroutable::SplitHorizon { iface: 0 })
        ));
        // A subnet match suppresses the default fallback even when split horizon left
        // nothing usable, so adding a default does not rescue it.
        n.ifaces.add("DFL", 40, 12, true).unwrap();
        assert!(matches!(
            n.resolve(10, Some(0)),
            Err(Unroutable::SplitHorizon { iface: 0 })
        ));
    }

    #[test]
    fn several_default_interfaces_all_receive_a_copy() {
        // The C clones to each and gives the last the original -- that is how
        // broadcast-to-all-interfaces is configured.
        let s = S::new();
        let mut n = node(&s);
        n.ifaces.add("CAN", 1, 5, true).unwrap();
        n.ifaces.add("KISS", 2, 5, true).unwrap();

        let d = n.resolve(25, None).unwrap();
        assert_eq!(d.len(), 2, "both defaults");
        assert_eq!(d.clones_needed(), 1, "the last gets the original");
    }

    #[cfg(feature = "rtable")]
    #[test]
    fn redundant_routes_all_receive_a_copy() {
        let s = S::new();
        let mut n = node(&s);
        n.route_set(8, 5, 1, csp_core::rtable::NO_VIA).unwrap();
        n.route_set(8, 5, 2, csp_core::rtable::NO_VIA).unwrap();

        let d = n.resolve(8, None).unwrap();
        assert_eq!(d.len(), 2, "both redundant paths");
        assert_eq!(d.clones_needed(), 1);
    }

    #[cfg(feature = "rtable")]
    #[test]
    fn a_routing_table_match_suppresses_the_default_fallback() {
        // The C returns as soon as route_found is set; the defaults are a fallback, not an
        // addition. Otherwise every routed packet would also flood every default link.
        let s = S::new();
        let mut n = node(&s);
        n.ifaces.add("DFL", 1, 5, true).unwrap();
        n.route_set(8, 5, 3, csp_core::rtable::NO_VIA).unwrap();

        let d = n.resolve(8, None).unwrap();
        assert_eq!(d.len(), 1);
        assert_eq!(d.as_slice()[0].iface, 3, "the route, not the default");
    }

    #[test]
    fn split_horizon_applies_to_the_default_fallback_too() {
        let s = S::new();
        let mut n = node(&s);
        n.ifaces.add("CAN", 1, 5, true).unwrap();
        assert!(matches!(
            n.resolve(25, Some(0)),
            Err(Unroutable::SplitHorizon { iface: 0 })
        ));
        // and a different ingress interface is fine
        assert!(n.resolve(25, Some(1)).is_ok());
    }

    #[test]
    fn a_node_with_no_routes_and_no_defaults_says_no_route() {
        let s = S::new();
        let n = node(&s);
        assert_eq!(n.resolve(25, None), Err(Unroutable::NoRoute));
    }

    #[test]
    fn two_nodes_run_independently_in_one_process() {
        let sa = S::new();
        let sb = S::new();
        let mut a: N = Node::new(&sa, Config::new(Version::V1).address(11));
        let mut b: N = Node::new(&sb, Config::new(Version::V2).address(2000));

        a.bind(20).unwrap();
        assert_eq!(a.address(), 11);
        assert_eq!(b.address(), 2000);
        assert_eq!(a.version(), Version::V1);
        assert_eq!(b.version(), Version::V2);

        // b can address 2000, which does not fit a v1 header at all
        assert!(b.connect(2, 3000, 20, 0, 0).is_ok());
        assert!(a.connect(2, 3000, 20, 0, 0).is_err());
    }

    #[test]
    fn shutdown_releases_everything() {
        let s = S::new();
        let mut n = node(&s);
        n.bind(20).unwrap();
        for _ in 0..3 {
            let mut p = n.packet().unwrap();
            p.set_id(Id {
                pri: 2,
                flags: 0,
                src: 8,
                dst: ME,
                dport: 20,
                sport: 10,
            });
            p.set_payload(b"x").unwrap();
            n.router.receive(p, 0);
        }
        n.work(0);
        n.tick(1_000_000, 1_000);
        n.shutdown();
        assert_eq!(n.buffers_free(), 16, "nothing may survive shutdown");
    }
}
