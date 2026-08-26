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

/// No next hop: send straight to the destination address.
///
/// The same value either way; named once so the subnet and default paths cannot disagree
/// about it when the routing table is compiled out.
#[cfg(feature = "rtable")]
const NO_VIA_ADDR: u16 = rtable::NO_VIA;
#[cfg(not(feature = "rtable"))]
const NO_VIA_ADDR: u16 = 0xFFFF;

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
    /// Next ephemeral source port. Wraps within the dynamic range.
    sport_next: u8,
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
            sport_next: EPHEMERAL_FIRST,
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

    /// This node's address.
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

    /// Stop accepting on a port, closing every connection still open on it.
    ///
    /// Returns how many connections were closed. Their queued packets are released back
    /// to the pool here, so nothing is left holding a buffer for a port that has stopped
    /// being served.
    pub fn unbind(&mut self, port: u8) -> usize {
        let mut drained = [0u16; 32];
        let (closed, n) = self.router.unbind(port, &mut drained);
        for &idx in &drained[..n] {
            drop(self.pool().from_index(idx));
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
            Some(idx) => Ok(self.pool().from_index(idx)),
            None => Ok(None),
        }
    }

    /// Close a connection, releasing anything still queued on it.
    pub fn close(&mut self, conn: Handle) -> Result<()> {
        let mut drained = [0u16; 32];
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

    fn next_sport(&mut self) -> u8 {
        let s = self.sport_next;
        // Stay inside the dynamic range and never collide with a service port.
        self.sport_next = if self.sport_next >= self.version.max_port() {
            EPHEMERAL_FIRST
        } else {
            self.sport_next + 1
        };
        s
    }

    /// Open a connection to `dst`.
    ///
    /// `opts` is a mask of [`csp_core::security::opts`]. The protections it asks for are
    /// carried in the header of every packet on the connection, and expected in the header
    /// of every reply — this is what tells the peer to verify a checksum or a MAC, so an
    /// option that does not reach the header is a protection the caller asked for and
    /// silently did not get.
    ///
    /// `RDP_REQ` is refused. See [`Node::rdp_unsupported`].
    pub fn connect(
        &mut self,
        pri: u8,
        dst: u16,
        dport: u8,
        opts: u32,
        now_ms: u32,
    ) -> Result<Handle> {
        let flags = Self::conn_flags(opts)?;
        let sport = self.next_sport();
        let idout = Id {
            pri,
            flags,
            src: self.address,
            dst,
            dport,
            sport,
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
        // The reply we expect: their source is our destination and vice versa. The C sets
        // the same flags on both ids, so a reply that drops the protection no longer
        // matches the connection.
        let idin = Id {
            pri,
            flags,
            src: dst,
            dst: self.address,
            dport: sport,
            sport: dport,
        };
        self.router.conns.set_id_in(h, idin)?;
        Ok(h)
    }

    /// The header flags a connection with these options puts on the wire.
    ///
    /// Mirrors `csp_connect` (`csp_conn.c:279-306`), including the rule that an explicit
    /// `CRC32_PROHIB` wins over `CRC32_REQ` rather than being a contradiction.
    fn conn_flags(opts: u32) -> Result<u8> {
        use csp_core::security::opts as o;

        if opts & o::RDP_REQ != 0 {
            return Err(Self::rdp_unsupported());
        }

        let mut flags = 0u8;
        if opts & o::HMAC_REQ != 0 {
            flags |= csp_core::flags::HMAC;
        }
        if (opts & o::CRC32_REQ != 0) && (opts & o::CRC32_PROHIB == 0) {
            flags |= csp_core::flags::CRC32;
        }
        Ok(flags)
    }

    /// Why `RDP_REQ` is refused.
    ///
    /// The RDP state machine in `csp_core::rdp` is complete, but nothing in this crate
    /// drives it: no `SYN` is sent, no received packet is fed to it, and there is no
    /// retransmission queue. Setting `flags::RDP` anyway would be worse than refusing —
    /// the peer would read the first five bytes of payload as an RDP header.
    ///
    /// This mirrors what the C does when built without `CSP_USE_RDP`: `csp_connect`
    /// records `CSP_DBG_ERR_UNSUPPORTED` and returns no connection.
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
        mut packet: Packet<'a, BUFS, BUFSZ>,
        now_ms: u32,
    ) -> Result<Outbound<'a, BUFS, BUFSZ>> {
        let id = self.router.conns.id_out(conn)?;
        self.router.conns.touch(conn, now_ms)?;
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
        let id = Id {
            pri,
            flags,
            src: self.address,
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
    pub fn reply_to(
        &mut self,
        request: &Packet<'a, BUFS, BUFSZ>,
        mut reply: Packet<'a, BUFS, BUFSZ>,
    ) -> Result<Outbound<'a, BUFS, BUFSZ>> {
        let req = request.id();
        let id = Id {
            pri: req.pri,
            flags: req.flags,
            src: req.dst,
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

    /// Receive on a bound port without a connection.
    ///
    /// Drains the next connection that has data and hands back the packet with the header
    /// it arrived with, closing the connection. This is `csp_recvfrom`: the
    /// connection-less server pattern.
    pub fn recvfrom(&mut self) -> Result<Option<Packet<'a, BUFS, BUFSZ>>> {
        let Some(conn) = self.accept() else {
            return Ok(None);
        };
        let packet = match self.router.conns.dequeue_rx(conn)? {
            Some(idx) => self.pool().from_index(idx),
            None => None,
        };
        self.close(conn)?;
        Ok(packet)
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
        #[cfg_attr(not(feature = "rtable"), allow(unused_variables))] dst: u16,
        routed_from: Option<u8>,
    ) -> core::result::Result<Destinations, Unroutable> {
        let mut out = Destinations {
            entries: [Destination {
                iface: 0,
                via: 0,
                dst: 0,
            }; 4],
            n: 0,
        };
        let mut skipped_self = false;

        // A local subnet owns the destination. `csp_send_direct` tries this **first**, and
        // a match returns before the routing table is consulted at all.
        //
        // This step was missing: resolve went straight to the table, so an application
        // sending to an address on a directly attached link fell through to the default
        // interfaces -- out the wrong link, or nowhere when no default was configured.
        // Every test here used a netmask under which each interface owns only its own
        // address, so none of them could tell.
        {
            let mut local_found = false;
            let mut out_dst = dst;
            for idx in self.ifaces.indices() {
                if !self.ifaces.is_within_subnet(dst, idx) {
                    continue;
                }
                local_found = true;
                if routed_from == Some(idx) {
                    skipped_self = true;
                    continue;
                }
                if self.ifaces.is_broadcast_for(dst, idx) {
                    out_dst = self.version.max_node_id();
                }
                if out.n < out.entries.len() {
                    out.entries[out.n] = Destination {
                        iface: idx,
                        via: NO_VIA_ADDR,
                        dst: out_dst,
                    };
                    out.n += 1;
                }
            }
            if local_found {
                return if out.n > 0 {
                    Ok(out)
                } else {
                    Err(Unroutable::SplitHorizon {
                        iface: routed_from.unwrap_or(0),
                    })
                };
            }
        }

        #[cfg(feature = "rtable")]
        {
            let placeholder = rtable::Route {
                address: 0,
                netmask: 0,
                iface: 0,
                via: rtable::NO_VIA,
            };
            let mut found = [&placeholder; 4];
            let n = self.router.routes.find_all(dst, &mut found);
            for r in found.iter().take(n) {
                if routed_from == Some(r.iface) {
                    skipped_self = true;
                    continue;
                }
                if out.n < out.entries.len() {
                    out.entries[out.n] = Destination {
                        iface: r.iface,
                        via: r.via,
                        dst,
                    };
                    out.n += 1;
                }
            }
            if n > 0 {
                // A routing-table match suppresses the default fallback entirely, even if
                // split horizon left nothing usable. The C returns as soon as
                // route_found is set.
                return if out.n > 0 {
                    Ok(out)
                } else {
                    Err(Unroutable::SplitHorizon {
                        iface: routed_from.unwrap_or(0),
                    })
                };
            }
        }

        // No route matched: fall back to every default-marked interface.
        for idx in self.ifaces.indices() {
            let Some(e) = self.ifaces.get(idx) else {
                continue;
            };
            if !e.is_default {
                continue;
            }
            if routed_from == Some(idx) {
                skipped_self = true;
                continue;
            }
            if out.n < out.entries.len() {
                out.entries[out.n] = Destination {
                    iface: idx,
                    via: NO_VIA_ADDR,
                    dst,
                };
                out.n += 1;
            }
        }

        if out.n > 0 {
            Ok(out)
        } else if skipped_self {
            Err(Unroutable::SplitHorizon {
                iface: routed_from.unwrap_or(0),
            })
        } else {
            Err(Unroutable::NoRoute)
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
        if id.dst == self.address {
            return Outbound::Loopback(packet);
        }
        match self.resolve(id.dst, routed_from) {
            Ok(d) => {
                let first = d.as_slice()[0];
                let mut packet = packet;
                if id.dst != first.dst {
                    let mut out_id = id;
                    out_id.dst = first.dst;
                    packet.set_id(out_id);
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
        self.router.work(pool, &self.ifaces, now_ms)
    }

    /// Periodic maintenance: RDP timers and idle connection expiry.
    pub fn tick(&mut self, now_ms: u32, conn_timeout_ms: u32) -> usize {
        let pool = self.storage.pool_ref();
        self.router.tick(pool, now_ms, conn_timeout_ms)
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
        assert_eq!(
            flags_on_the_wire(&mut n, o::HMAC_REQ),
            csp_core::flags::HMAC
        );
        // csp_conn.c:279 — an explicit prohibition clears the request rather than being a
        // contradiction that stops the connection.
        assert_eq!(flags_on_the_wire(&mut n, o::CRC32_REQ | o::CRC32_PROHIB), 0);
    }

    /// A connection that flags RDP and does not speak it is worse than no connection: the
    /// peer reads the first five payload bytes as an RDP header.
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

    #[test]
    fn recvfrom_returns_a_packet_and_releases_the_connection() {
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
        p.set_payload(b"connectionless").unwrap();
        n.router.receive(p, 0);
        n.work(0);

        let got = n.recvfrom().unwrap().expect("a packet should be waiting");
        got.with_payload(|d| assert_eq!(d, b"connectionless"));
        assert_eq!(
            n.router.conns.open_count(),
            0,
            "the connection must be released"
        );
    }

    #[test]
    fn recvfrom_on_an_idle_node_is_not_an_error() {
        let s = S::new();
        let mut n = node(&s);
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
        let s = S::new();
        let mut n = node(&s);
        n.route_default(3).unwrap();
        let c = n.connect(2, 8, 20, 0, 0).unwrap();

        // Send something that looks like a fragment, by setting the flag on the packet.
        let mut frag = n.packet().unwrap();
        frag.set_payload(b"fragment").unwrap();
        let out = n.send(c, frag, 0).unwrap();
        let mut p = out.into_packet();
        p.set_id(csp_core::Id {
            flags: csp_core::flags::FRAG,
            ..p.id()
        });
        assert!(p.id().is_fragment());
        drop(p);

        // A later plain packet on the SAME connection must not inherit it.
        let plain = n.packet().unwrap();
        let out = n.send(c, plain, 0).unwrap();
        assert!(
            !out.into_packet().id().is_fragment(),
            "the connection must not carry FRAG over to the next packet"
        );
    }

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
