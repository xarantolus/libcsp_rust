//! The connection table.
//!
//! Fixed capacity, caller-owned, no allocation. Each connection carries its own receive
//! queue of slot indices (same reason as [`crate::qfifo`]) and, with the `rdp` feature,
//! its own RDP state.
//!
//! # Why connections are scarce, and why that matters
//!
//! There are `N` of them for the whole node — 8 by default, 16 in the flight
//! configuration. A connection that is never closed is gone until reboot. That is why
//! [`Table::alloc`] returns an error rather than a null, why the idle timeout is enforced
//! here, and why the RDP `SYN` option clamping in `csp_core::rdp` treats an unbounded
//! `conn_timeout` as an attack rather than a preference.

use csp_core::{Error, Id, Result};

#[cfg(feature = "rdp")]
use csp_core::rdp;

/// Which end opened the connection.
///
/// This changes how an incoming packet is matched to it, and the difference is not
/// cosmetic — see [`Table::find`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// We opened it with `connect`. Our source port is ephemeral and therefore unique.
    Client,
    /// A peer opened it by sending to a bound port.
    Server,
}

/// Connection lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Slot is free.
    Closed,
    /// In use.
    Open,
}

/// A connection handle: an index into the table plus a generation.
///
/// The generation is what makes a stale handle detectable. Without it, closing a
/// connection and opening a new one recycles the index, and a caller still holding the old
/// handle silently operates on someone else's connection — the use-after-free that a
/// `csp_conn_t *` makes easy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Handle {
    idx: u16,
    generation: u16,
}

impl Handle {
    /// The table slot this refers to.
    pub const fn index(&self) -> u16 {
        self.idx
    }
}

/// One connection.
#[derive(Debug)]
struct Entry<const RXQ: usize> {
    state: State,
    kind: Kind,
    generation: u16,
    /// Header of packets arriving on this connection.
    idin: Id,
    /// Header applied to packets sent on it.
    idout: Id,
    /// Socket options (`sfp::opts`).
    opts: u32,
    /// Receive queue of slot indices.
    rx: [Option<u16>; RXQ],
    rx_head: usize,
    rx_tail: usize,
    rx_len: usize,
    /// Last time this connection saw traffic, ms.
    last_activity: u32,
    #[cfg(feature = "rdp")]
    rdp: rdp::Connection,
}

impl<const RXQ: usize> Entry<RXQ> {
    fn new() -> Self {
        Entry {
            state: State::Closed,
            kind: Kind::Server,
            generation: 0,
            idin: Id::default(),
            idout: Id::default(),
            opts: 0,
            rx: [None; RXQ],
            rx_head: 0,
            rx_tail: 0,
            rx_len: 0,
            last_activity: 0,
            #[cfg(feature = "rdp")]
            rdp: rdp::Connection::new(0, rdp::SynOptions::default()),
        }
    }

    fn reset(&mut self) {
        let g = self.generation.wrapping_add(1);
        *self = Entry::new();
        self.generation = g;
    }
}

/// The connection table.
#[derive(Debug)]
pub struct Table<const N: usize, const RXQ: usize> {
    conns: [Entry<RXQ>; N],
    /// Round-robin cursor, so a closed-then-reopened connection does not immediately
    /// reuse the same slot. The C keeps this as a non-atomic `uint8_t` written after a
    /// successful CAS.
    cursor: usize,
}

impl<const N: usize, const RXQ: usize> Default for Table<N, RXQ> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const RXQ: usize> Table<N, RXQ> {
    /// Compile-time invariants: both counts index modulo themselves, and a zero-capacity
    /// connection table would make every `alloc` fail with `TableFull` — technically
    /// correct, and impossible to debug.
    const SANITY: () = {
        assert!(N > 0, "a node needs at least one connection slot");
        assert!(RXQ > 0, "a connection needs at least one receive slot");
    };

    /// An empty table.
    pub fn new() -> Self {
        let () = Self::SANITY;
        Table {
            conns: core::array::from_fn(|_| Entry::new()),
            cursor: 0,
        }
    }

    /// Connections currently open.
    pub fn open_count(&self) -> usize {
        self.conns.iter().filter(|c| c.state == State::Open).count()
    }

    /// Total capacity.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Open a connection.
    ///
    /// Returns [`Error::TableFull`] when every slot is in use — an error carrying that
    /// meaning, rather than a null the caller may or may not check.
    pub fn alloc(&mut self, idout: Id, opts: u32, now_ms: u32) -> Result<Handle> {
        self.alloc_kind(idout, opts, now_ms, Kind::Server)
    }

    /// Open a connection, saying which end initiated it.
    pub fn alloc_kind(
        &mut self,
        idout: Id,
        opts: u32,
        now_ms: u32,
        kind: Kind,
    ) -> Result<Handle> {
        for step in 0..N {
            let i = (self.cursor + step + 1) % N;
            if self.conns[i].state == State::Closed {
                let gen = self.conns[i].generation;
                self.conns[i].reset();
                let c = &mut self.conns[i];
                c.generation = gen;
                c.state = State::Open;
                c.kind = kind;
                c.idout = idout;
                c.opts = opts;
                c.last_activity = now_ms;
                self.cursor = i;
                return Ok(Handle {
                    idx: i as u16,
                    generation: gen,
                });
            }
        }
        Err(Error::TableFull)
    }

    /// Look up a live connection, rejecting a stale handle.
    fn entry(&self, h: Handle) -> Result<&Entry<RXQ>> {
        let c = self
            .conns
            .get(h.idx as usize)
            .ok_or(Error::NoTransferInProgress)?;
        if c.state != State::Open || c.generation != h.generation {
            return Err(Error::NoTransferInProgress);
        }
        Ok(c)
    }

    fn entry_mut(&mut self, h: Handle) -> Result<&mut Entry<RXQ>> {
        let c = self
            .conns
            .get_mut(h.idx as usize)
            .ok_or(Error::NoTransferInProgress)?;
        if c.state != State::Open || c.generation != h.generation {
            return Err(Error::NoTransferInProgress);
        }
        Ok(c)
    }

    /// True if the handle still refers to the connection it was issued for.
    pub fn is_live(&self, h: Handle) -> bool {
        self.entry(h).is_ok()
    }

    /// The outgoing header.
    pub fn id_out(&self, h: Handle) -> Result<Id> {
        Ok(self.entry(h)?.idout)
    }

    /// The incoming header.
    pub fn id_in(&self, h: Handle) -> Result<Id> {
        Ok(self.entry(h)?.idin)
    }

    /// Set the incoming header, as the router does when a connection is accepted.
    pub fn set_id_in(&mut self, h: Handle, id: Id) -> Result<()> {
        self.entry_mut(h)?.idin = id;
        Ok(())
    }

    /// Socket options.
    pub fn opts(&self, h: Handle) -> Result<u32> {
        Ok(self.entry(h)?.opts)
    }

    /// Destination port of the incoming header.
    pub fn dport(&self, h: Handle) -> Result<u8> {
        Ok(self.entry(h)?.idin.dport)
    }

    /// Note that traffic was seen.
    pub fn touch(&mut self, h: Handle, now_ms: u32) -> Result<()> {
        self.entry_mut(h)?.last_activity = now_ms;
        Ok(())
    }

    /// Queue a received packet index onto a connection.
    ///
    /// Returns `false` if the receive queue is full, in which case the caller must release
    /// the packet. Reports rather than silently overwriting.
    pub fn enqueue_rx(&mut self, h: Handle, packet_idx: u16) -> Result<bool> {
        let c = self.entry_mut(h)?;
        if c.rx_len == RXQ {
            return Ok(false);
        }
        c.rx[c.rx_tail] = Some(packet_idx);
        c.rx_tail = (c.rx_tail + 1) % RXQ;
        c.rx_len += 1;
        Ok(true)
    }

    /// Take the next received packet index.
    pub fn dequeue_rx(&mut self, h: Handle) -> Result<Option<u16>> {
        let c = self.entry_mut(h)?;
        if c.rx_len == 0 {
            return Ok(None);
        }
        let idx = c.rx[c.rx_head].take();
        c.rx_head = (c.rx_head + 1) % RXQ;
        c.rx_len -= 1;
        Ok(idx)
    }

    /// Packets waiting on a connection.
    pub fn rx_len(&self, h: Handle) -> Result<usize> {
        Ok(self.entry(h)?.rx_len)
    }

    /// Close a connection, returning any packet indices still queued so the caller can
    /// release them.
    ///
    /// Draining is not optional: the queue holds indices, so anything left behind leaks.
    pub fn close(&mut self, h: Handle, drained: &mut [u16]) -> Result<usize> {
        let c = self.entry_mut(h)?;
        let mut n = 0;
        while c.rx_len > 0 {
            if let Some(idx) = c.rx[c.rx_head].take() {
                if n < drained.len() {
                    drained[n] = idx;
                    n += 1;
                }
            }
            c.rx_head = (c.rx_head + 1) % RXQ;
            c.rx_len -= 1;
        }
        c.reset();
        Ok(n)
    }

    /// Close every connection idle for longer than `timeout_ms`, returning how many.
    ///
    /// Connection slots are the scarcest resource on the node; without this a peer that
    /// opens connections and walks away exhausts the table permanently.
    pub fn expire_idle(&mut self, now_ms: u32, timeout_ms: u32, drained: &mut [u16]) -> (usize, usize) {
        let mut closed = 0;
        let mut n = 0;
        for c in self.conns.iter_mut() {
            if c.state != State::Open {
                continue;
            }
            if now_ms.wrapping_sub(c.last_activity) <= timeout_ms {
                continue;
            }
            while c.rx_len > 0 {
                if let Some(idx) = c.rx[c.rx_head].take() {
                    if n < drained.len() {
                        drained[n] = idx;
                        n += 1;
                    }
                }
                c.rx_head = (c.rx_head + 1) % RXQ;
                c.rx_len -= 1;
            }
            c.reset();
            closed += 1;
        }
        (closed, n)
    }

    /// The kind of a connection.
    pub fn kind(&self, h: Handle) -> Result<Kind> {
        Ok(self.entry(h)?.kind)
    }

    /// Find the open connection an incoming header belongs to.
    ///
    /// The matching rule **differs by kind**, and the difference matters:
    ///
    /// - A [`Kind::Client`] connection matches on **destination port alone**. Our source
    ///   port was ephemeral and is therefore unique, so the reply's destination port
    ///   identifies the connection by itself. The C spells out why this is deliberate:
    ///   *"responses to broadcast addresses are accepted as long as the incoming port
    ///   matches the unique source port of the connection"*. Matching on source address
    ///   too would send every broadcast reply to a new connection instead of the one
    ///   waiting for it.
    /// - A [`Kind::Server`] connection matches on destination port, source port **and**
    ///   source address, because several peers can talk to one bound port at once.
    pub fn find(&self, id: &Id) -> Option<Handle> {
        for (i, c) in self.conns.iter().enumerate() {
            if c.state != State::Open {
                continue;
            }
            let matches = match c.kind {
                Kind::Client => c.idin.dport == id.dport,
                Kind::Server => {
                    c.idin.dport == id.dport
                        && c.idin.sport == id.sport
                        && c.idin.src == id.src
                }
            };
            if matches {
                return Some(Handle {
                    idx: i as u16,
                    generation: c.generation,
                });
            }
        }
        None
    }

    /// The RDP state machine for a connection.
    #[cfg(feature = "rdp")]
    pub fn rdp_mut(&mut self, h: Handle) -> Result<&mut rdp::Connection> {
        Ok(&mut self.entry_mut(h)?.rdp)
    }

    /// Read-only RDP state.
    #[cfg(feature = "rdp")]
    pub fn rdp(&self, h: Handle) -> Result<&rdp::Connection> {
        Ok(&self.entry(h)?.rdp)
    }

    /// Step every open connection's RDP timers, closing any that time out.
    ///
    /// Returns the number closed. This is what drives retransmission and connection
    /// timeout — without it the RDP state machine never advances on its own, because it
    /// deliberately reads no clock.
    #[cfg(feature = "rdp")]
    pub fn tick_rdp(&mut self, now_ms: u32, max_window: u32) -> usize {
        let mut closed = 0;
        for c in self.conns.iter_mut() {
            if c.state != State::Open {
                continue;
            }
            if let rdp::Action::Closed(_) = c.rdp.step(rdp::Event::Tick, now_ms, max_window) {
                c.reset();
                closed += 1;
            }
        }
        closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type T = Table<4, 4>;

    fn id(sport: u8) -> Id {
        Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport,
        }
    }

    #[test]
    fn alloc_and_close_are_balanced() {
        let mut t = T::new();
        assert_eq!(t.open_count(), 0);
        let h = t.alloc(id(10), 0, 0).unwrap();
        assert_eq!(t.open_count(), 1);
        let mut drained = [0u16; 4];
        t.close(h, &mut drained).unwrap();
        assert_eq!(t.open_count(), 0);
    }

    #[test]
    fn a_full_table_reports_rather_than_returning_nothing_useful() {
        let mut t = T::new();
        for i in 0..4u8 {
            t.alloc(id(i), 0, 0).unwrap();
        }
        assert_eq!(t.alloc(id(9), 0, 0), Err(Error::TableFull));
    }

    #[test]
    fn a_stale_handle_is_rejected_rather_than_hitting_someone_elses_connection() {
        // The use-after-free a raw csp_conn_t* invites: close, reopen, and the recycled
        // slot silently answers to the old pointer.
        let mut t = T::new();
        let h = t.alloc(id(10), 0, 0).unwrap();
        let mut drained = [0u16; 4];
        t.close(h, &mut drained).unwrap();

        assert!(!t.is_live(h));
        assert_eq!(t.id_out(h), Err(Error::NoTransferInProgress));

        // reopen; the new handle works, the old one still does not
        let h2 = t.alloc(id(11), 0, 0).unwrap();
        assert!(t.is_live(h2));
        assert!(!t.is_live(h), "the recycled slot must not answer the old handle");
    }

    #[test]
    fn rx_queue_is_fifo_and_reports_when_full() {
        let mut t = T::new();
        let h = t.alloc(id(10), 0, 0).unwrap();
        for i in 0..4u16 {
            assert!(t.enqueue_rx(h, i).unwrap());
        }
        assert!(!t.enqueue_rx(h, 99).unwrap(), "full must be reported");
        assert_eq!(t.rx_len(h).unwrap(), 4);
        for i in 0..4u16 {
            assert_eq!(t.dequeue_rx(h).unwrap(), Some(i));
        }
        assert_eq!(t.dequeue_rx(h).unwrap(), None);
    }

    #[test]
    fn close_returns_queued_indices_so_they_can_be_released() {
        // The queue holds indices, so anything left behind leaks.
        let mut t = T::new();
        let h = t.alloc(id(10), 0, 0).unwrap();
        for i in 0..3u16 {
            t.enqueue_rx(h, i).unwrap();
        }
        let mut drained = [0u16; 8];
        let n = t.close(h, &mut drained).unwrap();
        assert_eq!(n, 3);
        assert_eq!(&drained[..3], &[0, 1, 2]);
    }

    #[test]
    fn idle_connections_are_reclaimed() {
        // Connection slots are the scarcest resource on the node.
        let mut t = T::new();
        let h = t.alloc(id(10), 0, 0).unwrap();
        t.enqueue_rx(h, 7).unwrap();
        let mut drained = [0u16; 8];

        let (closed, n) = t.expire_idle(5_000, 10_000, &mut drained);
        assert_eq!(closed, 0, "not yet idle");
        assert_eq!(n, 0);

        let (closed, n) = t.expire_idle(20_000, 10_000, &mut drained);
        assert_eq!(closed, 1);
        assert_eq!(n, 1, "its queued packet must come back for release");
        assert_eq!(drained[0], 7);
        assert_eq!(t.open_count(), 0);
    }

    #[test]
    fn touch_defers_expiry() {
        let mut t = T::new();
        let h = t.alloc(id(10), 0, 0).unwrap();
        t.touch(h, 9_000).unwrap();
        let mut drained = [0u16; 4];
        let (closed, _) = t.expire_idle(15_000, 10_000, &mut drained);
        assert_eq!(closed, 0, "recent traffic must defer expiry");
    }

    #[test]
    fn expiry_survives_a_wrapping_clock() {
        let mut t = T::new();
        let h = t.alloc(id(10), 0, 0).unwrap();
        t.touch(h, u32::MAX - 1_000).unwrap();
        let mut drained = [0u16; 4];
        // 1500 ms later, having wrapped through zero
        let (closed, _) = t.expire_idle(500, 10_000, &mut drained);
        assert_eq!(closed, 0, "must not close merely because the clock wrapped");
    }

    #[test]
    fn find_matches_on_the_incoming_header() {
        let mut t = T::new();
        let h = t.alloc(id(10), 0, 0).unwrap();
        t.set_id_in(h, id(10)).unwrap();
        assert_eq!(t.find(&id(10)), Some(h));
        assert_eq!(t.find(&id(11)), None);
    }

    #[test]
    fn a_client_connection_accepts_a_reply_from_any_source() {
        // The C matches a client connection on dport alone, and says why: "responses to
        // broadcast addresses are accepted as long as the incoming port matches the
        // unique source port of the connection". Matching on source too would hand every
        // broadcast reply to a NEW connection instead of the one waiting for it.
        let mut t = T::new();
        let out = Id { pri: 2, flags: 0, src: 11, dst: 31, dport: 20, sport: 17 };
        let h = t.alloc_kind(out, 0, 0, Kind::Client).unwrap();
        // We expect replies addressed to our ephemeral source port 17.
        t.set_id_in(h, Id { pri: 2, flags: 0, src: 31, dst: 11, dport: 17, sport: 20 })
            .unwrap();

        // A reply from node 8 rather than the broadcast address still belongs to us.
        let reply = Id { pri: 2, flags: 0, src: 8, dst: 11, dport: 17, sport: 20 };
        assert_eq!(t.find(&reply), Some(h), "a broadcast reply must find its connection");

        // But a reply to a different port does not.
        let other = Id { dport: 18, ..reply };
        assert_eq!(t.find(&other), None);
    }

    #[test]
    fn a_server_connection_distinguishes_its_peers() {
        // Several peers can talk to one bound port at once, so a server connection must
        // match on source address and source port as well.
        let mut t = T::new();
        let a = t.alloc_kind(id(10), 0, 0, Kind::Server).unwrap();
        t.set_id_in(a, Id { pri: 2, flags: 0, src: 8, dst: 11, dport: 20, sport: 30 })
            .unwrap();

        let from_a = Id { pri: 2, flags: 0, src: 8, dst: 11, dport: 20, sport: 30 };
        assert_eq!(t.find(&from_a), Some(a));

        // Same port, different peer: not this connection.
        let from_b = Id { src: 9, ..from_a };
        assert_eq!(t.find(&from_b), None, "a different peer is a different connection");

        // Same peer, different source port: also not.
        let from_a2 = Id { sport: 31, ..from_a };
        assert_eq!(t.find(&from_a2), None);
    }

    #[test]
    fn the_kind_is_recorded() {
        let mut t = T::new();
        let c = t.alloc_kind(id(1), 0, 0, Kind::Client).unwrap();
        let s = t.alloc_kind(id(2), 0, 0, Kind::Server).unwrap();
        assert_eq!(t.kind(c).unwrap(), Kind::Client);
        assert_eq!(t.kind(s).unwrap(), Kind::Server);
    }

    #[test]
    fn slots_are_handed_out_round_robin() {
        // Reusing the just-freed slot immediately maximises the chance a stale handle
        // lands on a live connection.
        let mut t = T::new();
        let h1 = t.alloc(id(1), 0, 0).unwrap();
        let mut drained = [0u16; 4];
        t.close(h1, &mut drained).unwrap();
        let h2 = t.alloc(id(2), 0, 0).unwrap();
        assert_ne!(h1.index(), h2.index(), "should not reuse the slot at once");
    }

    #[cfg(feature = "rdp")]
    #[test]
    fn the_router_tick_drives_rdp_timeouts() {
        // The RDP machine reads no clock on purpose, so something has to step it.
        let mut t = T::new();
        let h = t.alloc(id(10), 0, 0).unwrap();
        {
            let c = t.rdp_mut(h).unwrap();
            c.state = rdp::State::Open;
            c.last_activity = 0;
        }
        assert_eq!(t.tick_rdp(5_000, 5), 0, "not yet timed out");
        assert_eq!(t.tick_rdp(60_000, 5), 1, "must close on timeout");
        assert_eq!(t.open_count(), 0);
    }

    #[cfg(feature = "rdp")]
    #[test]
    fn each_connection_has_its_own_rdp_state() {
        // The C keeps its six RDP tunables in file statics shared by every connection.
        let mut t = T::new();
        let a = t.alloc(id(1), 0, 0).unwrap();
        let b = t.alloc(id(2), 0, 0).unwrap();
        t.rdp_mut(a).unwrap().opts.packet_timeout = 100;
        t.rdp_mut(b).unwrap().opts.packet_timeout = 5_000;
        assert_eq!(t.rdp(a).unwrap().opts.packet_timeout, 100);
        assert_eq!(t.rdp(b).unwrap().opts.packet_timeout, 5_000);
    }
}
