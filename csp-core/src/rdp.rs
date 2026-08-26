//! RDP — the Reliable Datagram Protocol, as a sans-io state machine.
//!
//! The C is 1 022 lines with 30 `goto`s, including a backward `goto front` that re-enters
//! a loop, and it reads the wall clock and the buffer pool from inside the protocol logic.
//! Here the protocol is a pure function of `(state, event, now)` returning [`Action`]s the
//! caller performs. That is what makes it testable without a scheduler — the C's own RDP
//! tests have to build a fake interface and drive the router to get at it.
//!
//! ## Wire format
//!
//! Every RDP packet carries a 5-byte trailer *after* the payload:
//!
//! ```text
//! [ payload ][ flags:u8 ][ seq_nr:u16 ][ ack_nr:u16 ]    big-endian
//! ```
//!
//! A `SYN` additionally carries a 24-byte option block *before* the trailer: six
//! big-endian `u32`s — window size, connection timeout, packet timeout, delayed-ack flag,
//! ack timeout, ack delay count.
//!
//! ## Option clamping is a security control, not tidiness
//!
//! A `SYN` arrives from an unauthenticated peer and dictates this node's timers and window
//! for the life of the connection. Unclamped, a hostile or corrupted `SYN` sets a 0-length
//! window (deadlock) or a multi-hour connection timeout (a connection slot never released
//! — and there are only `CSP_CONN_MAX`, typically 8 or 16, on the whole spacecraft).
//! [`SynOptions::decode_clamped`] bounds every field, and the tests pin each bound.

use crate::{Error, Result};

/// Size of the RDP trailer.
pub const HEADER_LEN: usize = 5;
/// Size of the option block a `SYN` carries.
pub const SYN_OPTIONS_LEN: usize = 24;

/// Synchronise: open a connection.
pub const SYN: u8 = 0x08;
/// Acknowledge.
pub const ACK: u8 = 0x04;
/// Extended acknowledge (selective). Parsed but not generated, as in the C.
pub const EAK: u8 = 0x02;
/// Reset: tear the connection down.
pub const RST: u8 = 0x01;

// Bounds from csp_rdp.h. Applied to option values from an unauthenticated peer.
/// Smallest accepted connection timeout, ms.
pub const MIN_CONN_TIMEOUT: u32 = 1_000;
/// Largest accepted connection timeout, ms.
pub const MAX_CONN_TIMEOUT: u32 = 60_000;
/// Smallest accepted packet timeout, ms.
pub const MIN_PACKET_TIMEOUT: u32 = 100;
/// Largest accepted packet timeout, ms.
pub const MAX_PACKET_TIMEOUT: u32 = 60_000;
/// Smallest accepted delayed-ack timeout, ms.
pub const MIN_ACK_TIMEOUT: u32 = 10;

/// The RDP trailer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Header {
    /// Any of [`SYN`], [`ACK`], [`EAK`], [`RST`].
    pub flags: u8,
    /// Sequence number of this packet.
    pub seq_nr: u16,
    /// Highest sequence number received in order.
    pub ack_nr: u16,
}

impl Header {
    /// Parse the trailer from the end of a packet payload.
    pub fn decode(data: &[u8]) -> Result<Header> {
        if data.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let t = &data[data.len() - HEADER_LEN..];
        Ok(Header {
            flags: t[0],
            seq_nr: u16::from_be_bytes([t[1], t[2]]),
            ack_nr: u16::from_be_bytes([t[3], t[4]]),
        })
    }

    /// Append the trailer to `payload`, writing into `out`.
    pub fn encode(&self, payload: &[u8], out: &mut [u8]) -> Result<usize> {
        let needed = payload.len() + HEADER_LEN;
        if out.len() < needed {
            return Err(Error::BufferTooSmall { needed });
        }
        out[..payload.len()].copy_from_slice(payload);
        let t = &mut out[payload.len()..needed];
        t[0] = self.flags;
        t[1..3].copy_from_slice(&self.seq_nr.to_be_bytes());
        t[3..5].copy_from_slice(&self.ack_nr.to_be_bytes());
        Ok(needed)
    }

    /// The payload with the trailer removed.
    pub fn strip(data: &[u8]) -> Result<&[u8]> {
        if data.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        Ok(&data[..data.len() - HEADER_LEN])
    }

    /// True if any of `f` is set.
    pub const fn has(&self, f: u8) -> bool {
        (self.flags & f) != 0
    }
}

/// Connection parameters negotiated by a `SYN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SynOptions {
    /// Packets in flight.
    pub window_size: u32,
    /// Idle time before the connection is torn down, ms.
    pub conn_timeout: u32,
    /// Time before an unacknowledged packet is retransmitted, ms.
    pub packet_timeout: u32,
    /// Whether acknowledgements may be delayed.
    pub delayed_acks: bool,
    /// How long an acknowledgement may be delayed, ms.
    pub ack_timeout: u32,
    /// How many packets may go unacknowledged before an ack is forced.
    pub ack_delay_count: u32,
}

impl Default for SynOptions {
    /// The C's compiled-in defaults.
    fn default() -> Self {
        SynOptions {
            window_size: 4,
            conn_timeout: 10_000,
            packet_timeout: 1_000,
            delayed_acks: true,
            ack_timeout: 250,
            ack_delay_count: 2,
        }
    }
}

const fn clamp(v: u32, lo: u32, hi: u32) -> u32 {
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

impl SynOptions {
    /// Decode the option block, clamping every field into a safe range.
    ///
    /// `max_window` is this node's compiled-in `CSP_RDP_MAX_WINDOW`; a peer cannot ask for
    /// more in-flight packets than the local pool can hold.
    ///
    /// The order matters: `ack_timeout` is bounded by the *already clamped* `conn_timeout`
    /// and `ack_delay_count` by the *already clamped* `window_size`, so a peer cannot use
    /// one field to widen the bound on another.
    pub fn decode_clamped(data: &[u8], max_window: u32) -> Result<SynOptions> {
        if data.len() < SYN_OPTIONS_LEN {
            return Err(Error::Truncated);
        }
        let w = |i: usize| {
            u32::from_be_bytes([
                data[i * 4],
                data[i * 4 + 1],
                data[i * 4 + 2],
                data[i * 4 + 3],
            ])
        };
        let window_size = clamp(w(0), 1, max_window);
        let conn_timeout = clamp(w(1), MIN_CONN_TIMEOUT, MAX_CONN_TIMEOUT);
        let packet_timeout = clamp(w(2), MIN_PACKET_TIMEOUT, MAX_PACKET_TIMEOUT);
        Ok(SynOptions {
            window_size,
            conn_timeout,
            packet_timeout,
            delayed_acks: w(3) != 0,
            ack_timeout: clamp(w(4), MIN_ACK_TIMEOUT, conn_timeout),
            ack_delay_count: clamp(w(5), 1, window_size),
        })
    }

    /// Encode the option block.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < SYN_OPTIONS_LEN {
            return Err(Error::BufferTooSmall {
                needed: SYN_OPTIONS_LEN,
            });
        }
        for (i, v) in [
            self.window_size,
            self.conn_timeout,
            self.packet_timeout,
            self.delayed_acks as u32,
            self.ack_timeout,
            self.ack_delay_count,
        ]
        .iter()
        .enumerate()
        {
            out[i * 4..i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        Ok(SYN_OPTIONS_LEN)
    }
}

/// Is `seq` within `[start, end]` in wrapping 16-bit sequence space?
///
/// Mirrors `csp_rdp_seq_between`. Written as unsigned wrapping subtraction so it stays
/// correct across the 16-bit wrap, which a naive `start <= seq && seq <= end` does not.
pub const fn seq_between(seq: u16, start: u16, end: u16) -> bool {
    end.wrapping_sub(start) >= seq.wrapping_sub(start)
}

/// Connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// No connection.
    Closed,
    /// We sent a `SYN` and are waiting for `SYN|ACK`.
    SynSent,
    /// We received a `SYN` and sent `SYN|ACK`.
    SynRcvd,
    /// Established.
    Open,
    /// Torn down, waiting out the linger period.
    CloseWait,
}

/// Why a connection closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedBy {
    /// The local application closed it.
    UserSpace,
    /// The peer sent `RST`, or the protocol was violated.
    Protocol,
    /// Nothing was heard within `conn_timeout`.
    Timeout,
}

/// What the caller should do as a result of an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Send a control packet with these header fields and no payload.
    SendControl(Header),
    /// Send a `SYN` carrying the option block.
    SendSyn(Header, SynOptions),
    /// Deliver the payload to the application.
    Deliver,
    /// In the window but ahead of the gap: hold it until the missing packet arrives.
    ///
    /// `csp_rdp.c:723` stores it with `csp_rdp_rx_queue_add` and walks the queue once the
    /// hole is filled. The caller owns the packet, so it does the holding -- this only says
    /// which sequence number it is holding it under.
    Hold(u16),
    /// The connection is now open.
    Opened,
    /// The connection has closed.
    Closed(ClosedBy),
    /// Nothing to do.
    Nothing,
}

/// Events the machine reacts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event<'a> {
    /// The application asked to connect.
    Connect,
    /// A packet arrived: its RDP header, and the payload with the trailer already removed.
    Packet(Header, &'a [u8]),
    /// The application asked to close.
    Close,
    /// Time passed; check the timers.
    Tick,
}

/// How many retransmissions of the same data before a peer is given up on.
pub const MAX_RETRANSMITS: u32 = 10;

/// What to do with a queued packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxAction {
    /// The peer acknowledged it. Release the buffer.
    Release {
        /// Caller's handle for the buffer.
        token: u16,
    },
    /// Its timeout expired. Send it again.
    Retransmit {
        /// Caller's handle for the buffer.
        token: u16,
        /// Sequence number, for logging and for updating the piggybacked ack.
        seq_nr: u16,
    },
    /// The peer has not acknowledged anything after [`MAX_RETRANSMITS`] tries.
    ///
    /// Without this a connection retransmits for as long as it happens to live, holding a
    /// buffer per unacknowledged packet out of a pool of 15.
    GiveUp,
}

/// One unacknowledged packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TxEntry {
    seq_nr: u16,
    sent_at: u32,
    token: u16,
}

/// Packets sent but not yet acknowledged, held for retransmission.
///
/// `token` is whatever handle the caller uses for a buffer — this module never touches
/// packet memory, which is what keeps it allocation-free and testable without a pool.
///
/// The C keeps **one** TX queue and one RX queue as file statics shared by every
/// connection, scans them linearly and tells entries apart by comparing `packet->conn`.
/// One queue per connection here, so a busy connection cannot crowd out a quiet one.
#[derive(Debug)]
pub struct TxQueue<const N: usize> {
    entries: [Option<TxEntry>; N],
    retransmits: u32,
}

impl<const N: usize> Default for TxQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> TxQueue<N> {
    /// Compile-time invariant: a zero-length queue would silently discard every packet
    /// the moment it was sent, and the connection would look reliable while losing
    /// everything.
    const SANITY: () = assert!(N > 0, "the RDP transmit queue needs at least one slot");

    /// An empty queue.
    pub const fn new() -> Self {
        let () = Self::SANITY;
        TxQueue {
            entries: [None; N],
            retransmits: 0,
        }
    }

    /// Packets awaiting acknowledgement.
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// True if everything has been acknowledged.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Consecutive retransmissions without progress.
    pub const fn retransmits(&self) -> u32 {
        self.retransmits
    }

    /// Record a packet as sent and awaiting acknowledgement.
    ///
    /// Returns [`Error::TableFull`] when the window is full — the caller must not send
    /// more than the negotiated window, and silently dropping the record would make the
    /// packet unretransmittable while the peer still expects it.
    pub fn push(&mut self, seq_nr: u16, token: u16, now_ms: u32) -> Result<()> {
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(TxEntry {
                    seq_nr,
                    sent_at: now_ms,
                    token,
                });
                return Ok(());
            }
        }
        Err(Error::TableFull)
    }

    /// Decide what to do with every queued packet.
    ///
    /// `snd_una` is the oldest unacknowledged sequence number: anything before it has been
    /// acknowledged and is released. Anything older than `packet_timeout_ms` is
    /// retransmitted, and its timer restarts.
    ///
    /// Writes into `out` and returns how many actions were produced.
    pub fn poll(
        &mut self,
        now_ms: u32,
        packet_timeout_ms: u32,
        snd_una: u16,
        out: &mut [TxAction],
    ) -> usize {
        let mut n = 0;
        let mut retransmitted = false;

        for slot in self.entries.iter_mut() {
            let Some(e) = slot.as_mut() else { continue };

            // No room to report? Leave the entry alone and come back to it next call.
            // Releasing it here would hand the caller no token and leak the buffer;
            // restarting its timer here would silently skip a retransmission.
            if n >= out.len() {
                break;
            }

            // Acknowledged? seq strictly before snd_una, in wrapping space.
            if seq_before(e.seq_nr, snd_una) {
                out[n] = TxAction::Release { token: e.token };
                n += 1;
                *slot = None;
                continue;
            }

            // Wrapping subtraction: a free-running millisecond clock wraps every 49 days,
            // and `now > sent_at + timeout` would retransmit everything at the wrap.
            if now_ms.wrapping_sub(e.sent_at) > packet_timeout_ms {
                out[n] = TxAction::Retransmit {
                    token: e.token,
                    seq_nr: e.seq_nr,
                };
                n += 1;
                e.sent_at = now_ms;
                retransmitted = true;
            }
        }

        if retransmitted {
            self.retransmits += 1;
            if self.retransmits > MAX_RETRANSMITS && n < out.len() {
                out[n] = TxAction::GiveUp;
                n += 1;
            }
        }
        n
    }

    /// Note that the peer made progress, resetting the give-up counter.
    pub fn note_progress(&mut self) {
        self.retransmits = 0;
    }

    /// Take any queued entry, without caring which.
    ///
    /// For releasing what a dead connection still holds. [`flush`](Self::flush) does the
    /// same into a caller-sized array; this one suits a caller draining in a loop.
    pub fn take_any(&mut self) -> Option<u16> {
        for e in self.entries.iter_mut() {
            if let Some(entry) = e.take() {
                return Some(entry.token);
            }
        }
        None
    }

    /// Abandon everything, returning the tokens so the caller can release them.
    ///
    /// Not optional: the queue holds tokens, so anything left behind leaks.
    pub fn flush(&mut self, out: &mut [u16]) -> usize {
        let mut n = 0;
        for slot in self.entries.iter_mut() {
            if let Some(e) = slot.take() {
                if n < out.len() {
                    out[n] = e.token;
                    n += 1;
                }
            }
        }
        self.retransmits = 0;
        n
    }
}

/// One out-of-order packet, held until the gap before it fills.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RxEntry {
    seq_nr: u16,
    token: u16,
}

/// Packets that arrived out of order, held until they can be delivered in sequence.
///
/// Without this, a packet arriving after a gap is **discarded** and the peer has to
/// retransmit it — so a single lost packet costs a retransmission of everything sent
/// after it, which on a link with any real latency is most of the window.
///
/// The C's version scans linearly and restarts from the front after every delivery (the
/// backward `goto front` at `csp_rdp.c:256`). Here that is a `while let` loop in the
/// caller, which is the same algorithm without the label.
#[derive(Debug)]
pub struct RxQueue<const N: usize> {
    entries: [Option<RxEntry>; N],
}

impl<const N: usize> Default for RxQueue<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> RxQueue<N> {
    /// Compile-time invariant: with no slots, every out-of-order packet is dropped and
    /// the connection silently degrades to stop-and-wait.
    const SANITY: () = assert!(N > 0, "the RDP receive queue needs at least one slot");

    /// An empty queue.
    pub const fn new() -> Self {
        let () = Self::SANITY;
        RxQueue { entries: [None; N] }
    }

    /// Packets held.
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// True if nothing is held.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Is this sequence number already buffered?
    pub fn contains(&self, seq_nr: u16) -> bool {
        self.entries.iter().flatten().any(|e| e.seq_nr == seq_nr)
    }

    /// Hold an out-of-order packet.
    ///
    /// [`Error::DuplicateSequence`] means the peer retransmitted something already held —
    /// expected, not a fault, and the caller should release its copy.
    /// [`Error::TableFull`] means the window is exhausted.
    pub fn insert(&mut self, seq_nr: u16, token: u16) -> Result<()> {
        if self.contains(seq_nr) {
            return Err(Error::DuplicateSequence { seq: seq_nr });
        }
        for slot in self.entries.iter_mut() {
            if slot.is_none() {
                *slot = Some(RxEntry { seq_nr, token });
                return Ok(());
            }
        }
        Err(Error::TableFull)
    }

    /// Take the packet with sequence number `seq_nr`, if it is held.
    ///
    /// Drive it in a loop to drain everything the newly-arrived packet unblocked:
    ///
    /// ```ignore
    /// while let Some(token) = rx.take(conn.rcv_cur.wrapping_add(1)) {
    ///     deliver(token);
    ///     conn.rcv_cur = conn.rcv_cur.wrapping_add(1);
    /// }
    /// ```
    pub fn take(&mut self, seq_nr: u16) -> Option<u16> {
        for slot in self.entries.iter_mut() {
            if matches!(slot, Some(e) if e.seq_nr == seq_nr) {
                return slot.take().map(|e| e.token);
            }
        }
        None
    }

    /// Take any held entry, without caring which.
    ///
    /// For releasing what a dead connection still holds: every one is a pool slot nobody
    /// else will ever return.
    pub fn take_any(&mut self) -> Option<u16> {
        for e in self.entries.iter_mut() {
            if let Some(entry) = e.take() {
                return Some(entry.token);
            }
        }
        None
    }

    /// Abandon everything, returning the tokens so the caller can release them.
    pub fn flush(&mut self, out: &mut [u16]) -> usize {
        let mut n = 0;
        for slot in self.entries.iter_mut() {
            if let Some(e) = slot.take() {
                if n < out.len() {
                    out[n] = e.token;
                    n += 1;
                }
            }
        }
        n
    }
}

/// Is `a` strictly before `b` in wrapping 16-bit sequence space?
pub const fn seq_before(a: u16, b: u16) -> bool {
    // Half the space is "before"; this is the standard wrapping comparison.
    (b.wrapping_sub(a)) != 0 && (b.wrapping_sub(a)) < 0x8000
}

/// One end of an RDP connection.
///
/// Holds no buffers and reads no clock: `now_ms` is passed in. Two of these can run in one
/// process with different options, which the C cannot do — its RDP tunables are six file
/// statics shared by every connection.
#[derive(Debug, Clone, Copy)]
pub struct Connection {
    /// Current state.
    pub state: State,
    /// Negotiated options.
    pub opts: SynOptions,
    /// Next sequence number to send.
    pub snd_nxt: u16,
    /// Oldest unacknowledged sequence number.
    pub snd_una: u16,
    /// Our initial sequence number.
    pub snd_iss: u16,
    /// Highest sequence number received in order.
    pub rcv_cur: u16,
    /// Peer's initial sequence number.
    pub rcv_irs: u16,
    /// Last sequence number we acknowledged.
    pub rcv_lsa: u16,
    /// When the connection last saw traffic, ms.
    pub last_activity: u32,
    /// When an acknowledgement was last sent, ms.
    pub ack_timestamp: u32,
    /// Retransmission counter.
    pub retransmits: u32,
}

impl Connection {
    /// A closed connection with the given initial sequence number.
    ///
    /// `iss` should be unpredictable in production: a guessable initial sequence number
    /// lets an off-path attacker inject data into an established connection.
    pub fn new(iss: u16, opts: SynOptions) -> Self {
        Connection {
            state: State::Closed,
            opts,
            snd_nxt: iss.wrapping_add(1),
            snd_una: iss.wrapping_add(1),
            snd_iss: iss,
            rcv_cur: 0,
            rcv_irs: 0,
            rcv_lsa: 0,
            last_activity: 0,
            ack_timestamp: 0,
            retransmits: 0,
        }
    }

    /// Is an acknowledgement due?
    ///
    /// Mirrors `csp_rdp_should_ack`, which has three conditions and is checked separately
    /// from packet handling — `csp_rdp_check_ack` is called by the router, not by the
    /// receive path.
    ///
    /// Delaying acks is a bandwidth optimisation: one ack can cover several packets. But
    /// *never* acking is not, and that is what this port did before the audit — in-order
    /// data was delivered and never acknowledged, so the sender only learned of it when
    /// its own retransmission timer fired. Every packet cost a full `packet_timeout` of
    /// latency and a duplicate on the link.
    pub fn should_ack(&self, now_ms: u32) -> bool {
        // Nothing to acknowledge. **Deliberately unlike the C**, which returns true
        // unconditionally when delayed acks are off and so transmits an acknowledgement for
        // a sequence number the peer already has. Measured in
        // `ctest/suite_rdp.c::an_ack_is_sent_even_with_nothing_to_acknowledge`; recorded in
        // SCOPE.md. A redundant frame costs power on a link that has none to spare, and a
        // peer that does not receive it loses nothing.
        if self.rcv_cur == self.rcv_lsa {
            return false;
        }
        if !self.opts.delayed_acks {
            return true;
        }
        // Wrapping subtraction, so the 49-day clock wrap does not suppress every ack.
        if now_ms.wrapping_sub(self.ack_timestamp) > self.opts.ack_timeout {
            return true;
        }
        // Enough packets have gone unacknowledged.
        //
        // Strictly greater, not `>=`. The C tests
        // `csp_rdp_seq_after(rcv_cur, rcv_lsa + ack_delay_count)`, so the acknowledgement
        // fires once the outstanding count *exceeds* the delay — at count + 1. This used
        // `>=` and fired one packet early, which is 50% more acknowledgements at the
        // default count of 2. Not a correctness difference, and not worth having: the
        // extra frames cost power on a downlink that is already the scarce resource.
        // `ctest/suite_rdp.c::the_delay_count_fires_one_packet_after_it` measures it —
        // [0,0,1,1,1] for a count of 2.
        let outstanding = self.rcv_cur.wrapping_sub(self.rcv_lsa);
        outstanding as u32 > self.opts.ack_delay_count
    }

    /// Claim the header for one outgoing data packet, or `None` if it cannot be sent yet.
    ///
    /// Mirrors `csp_rdp_send`: refuses unless the connection is open and the send window
    /// has room (`snd_nxt` no further than `snd_una + window_size - 1`), then stamps
    /// `seq_nr = snd_nxt`, `ack_nr = rcv_cur`, sets `ACK`, and advances `snd_nxt`.
    ///
    /// `None` for a full window is where the C blocks on `tx_wait`. Sans-io has nowhere to
    /// block, so the caller decides: retry after `work`, or report back-pressure.
    ///
    /// The caller must hold the packet until it is acknowledged — see [`TxQueue`] — or the
    /// connection is not reliable, whatever the header says.
    pub fn begin_send(&mut self, now_ms: u32) -> Option<Header> {
        if self.state != State::Open {
            return None;
        }
        // `snd_una + window_size - 1` is the last sequence the window admits.
        let last = self
            .snd_una
            .wrapping_add(self.opts.window_size as u16)
            .wrapping_sub(1);
        // `seq_after(snd_nxt, last)`, spelled with the comparator this module has.
        if seq_before(last, self.snd_nxt) {
            return None;
        }
        let h = Header {
            flags: ACK,
            seq_nr: self.snd_nxt,
            ack_nr: self.rcv_cur,
        };
        // Every outgoing frame carries the latest acknowledgement, so the delayed-ack
        // bookkeeping restarts here exactly as `csp_rdp_send_cmp` restarts it.
        self.rcv_lsa = self.rcv_cur;
        self.ack_timestamp = now_ms;
        self.snd_nxt = self.snd_nxt.wrapping_add(1);
        Some(h)
    }

    /// Accept a packet that was held out of order, now that it is next in sequence.
    ///
    /// Returns false if it is not next, so a caller cannot advance the sequence by handing
    /// back the wrong one.
    pub fn release_held(&mut self, seq_nr: u16) -> bool {
        if self.state != State::Open || seq_nr != self.rcv_cur.wrapping_add(1) {
            return false;
        }
        self.rcv_cur = seq_nr;
        true
    }

    /// The sequence number a held packet must carry to be released next.
    pub const fn next_expected(&self) -> u16 {
        self.rcv_cur.wrapping_add(1)
    }

    /// Take the acknowledgement that is due, if any.
    ///
    /// Records that it was sent, so the delay counters restart.
    pub fn poll_ack(&mut self, now_ms: u32) -> Option<Header> {
        if self.state != State::Open || !self.should_ack(now_ms) {
            return None;
        }
        self.rcv_lsa = self.rcv_cur;
        self.ack_timestamp = now_ms;
        Some(Header {
            flags: ACK,
            seq_nr: self.snd_nxt,
            ack_nr: self.rcv_cur,
        })
    }

    /// Step the machine. Returns what the caller should do.
    pub fn step(&mut self, ev: Event<'_>, now_ms: u32, max_window: u32) -> Action {
        match ev {
            Event::Connect => {
                if self.state != State::Closed {
                    return Action::Nothing;
                }
                self.state = State::SynSent;
                self.last_activity = now_ms;
                Action::SendSyn(
                    Header {
                        flags: SYN,
                        seq_nr: self.snd_iss,
                        ack_nr: 0,
                    },
                    self.opts,
                )
            }

            Event::Close => {
                if self.state == State::Closed {
                    return Action::Nothing;
                }
                self.state = State::CloseWait;
                self.last_activity = now_ms;
                Action::SendControl(Header {
                    flags: RST,
                    seq_nr: self.snd_nxt,
                    ack_nr: self.rcv_cur,
                })
            }

            Event::Tick => {
                if self.state == State::Closed {
                    return Action::Nothing;
                }
                // Only before the connection is established. `csp_rdp_check_timeouts`
                // guards its CONNECTION TIMEOUT with `conn->dest_socket != NULL`, and
                // `dest_socket` is cleared the moment the connection is *announced* to the
                // socket (`csp_rdp.c:695`, "the connection handle has been passed to
                // userspace") -- not when the application accepts it. So libcsp reaps a
                // half-finished handshake and never an established connection.
                //
                // This closed any state, so an idle-but-alive connection was dropped while
                // the C kept answering on it: a telemetry link quiet between passes, whose
                // next packet then goes unanswered. Worse, `conn_timeout` is *proposed by
                // the peer*, so it was a lever a peer could pull to make this node discard
                // its own connection early.
                //
                // Idle expiry as resource management still happens, in
                // `ConnTable::expire_idle`, against the timeout the *node* chooses.
                if self.state != State::Open
                    && now_ms.wrapping_sub(self.last_activity) > self.opts.conn_timeout
                {
                    self.state = State::Closed;
                    return Action::Closed(ClosedBy::Timeout);
                }

                // An unacknowledged `SYN|ACK` is repeated until the peer answers or the
                // retransmit limit is reached, and then the connection is reset.
                //
                // This did nothing but check the connection timeout. A `SYN|ACK` lost on
                // the way out was never repeated, so the peer waited for a connection this
                // node believed it had opened and neither side ever learned otherwise --
                // the RST below is the only thing that tells it. `csp_rdp_check_timeouts`
                // does this; measured in
                // `rdp::an_unacknowledged_syn_ack_is_retransmitted_then_reset`, where the C
                // sends at least `MAX_RETRANSMITS` frames and this sent none.
                //
                // Only `SynRcvd` is handled: it is the one state in which this port has
                // something outstanding of its own. Data retransmission needs the send
                // side, which the node does not have -- see SCOPE.md.
                if self.state == State::SynRcvd
                    && now_ms.wrapping_sub(self.ack_timestamp) > self.opts.packet_timeout
                {
                    self.ack_timestamp = now_ms;
                    if self.retransmits >= MAX_RETRANSMITS {
                        self.state = State::Closed;
                        return Action::SendControl(Header {
                            flags: RST,
                            seq_nr: self.snd_nxt,
                            ack_nr: self.rcv_cur,
                        });
                    }
                    self.retransmits += 1;
                    return Action::SendControl(Header {
                        flags: SYN | ACK,
                        seq_nr: self.snd_iss,
                        // `rcv_cur`, not `rcv_irs`. `csp_rdp_check_timeouts` refreshes the
                        // acknowledgement on every retransmission -- "Update to latest
                        // outgoing ACK" -- keeping the sequence number as it was.
                        //
                        // The two are equal throughout `SynRcvd`, since nothing advances
                        // `rcv_cur` before the handshake completes, so no record can tell
                        // them apart here and none is claimed to. Written this way because
                        // it is the quantity the C takes, not because a test caught it.
                        ack_nr: self.rcv_cur,
                    });
                }
                Action::Nothing
            }

            Event::Packet(h, payload) => self.on_packet(h, payload, now_ms, max_window),
        }
    }

    fn on_packet(&mut self, h: Header, payload: &[u8], now_ms: u32, max_window: u32) -> Action {
        self.last_activity = now_ms;

        // A reset is honoured only **in sequence**. `csp_rdp.c` compares
        // `rx_header->seq_nr == conn->rdp.rcv_cur + 1` and, failing that, takes the branch
        // spelled "RST out of sequence, keep connection open".
        //
        // That is a blind-reset defence, and this had none: any RST in any state closed the
        // connection, so one injected frame with the right addresses and ports -- no
        // knowledge of the sequence number needed -- dropped a link. On a spacecraft that
        // is a telemetry pass ended by a single spoofed packet.
        //
        // The in-sequence case was wrong too, quietly: the C answers `ACK|RST` so the peer
        // learns its close arrived, and this replied nothing at all.
        if h.has(RST) {
            match self.state {
                // Nothing to reset.
                State::Closed => return Action::Nothing,
                // Our own reset came back acknowledged; stop waiting.
                State::CloseWait => {
                    self.state = State::Closed;
                    return Action::Closed(ClosedBy::Protocol);
                }
                _ if h.seq_nr == self.rcv_cur.wrapping_add(1) => {
                    self.state = State::CloseWait;
                    return Action::SendControl(Header {
                        flags: ACK | RST,
                        seq_nr: self.snd_nxt,
                        ack_nr: self.rcv_cur,
                    });
                }
                // Out of sequence: ignored, and the connection carries on.
                _ => return Action::Nothing,
            }
        }

        match self.state {
            State::Closed => {
                if h.has(SYN) && !h.has(ACK) {
                    // Incoming connection. A SYN must carry a complete option block; the
                    // C sends RST and closes otherwise, rather than using defaults.
                    let Ok(opts) = SynOptions::decode_clamped(payload, max_window) else {
                        return Action::SendControl(Header {
                            flags: RST,
                            seq_nr: self.snd_nxt,
                            ack_nr: self.rcv_cur,
                        });
                    };
                    self.opts = opts;
                    self.rcv_cur = h.seq_nr;
                    self.rcv_irs = h.seq_nr;
                    // `rcv_lsa = seq_nr`, not `seq_nr - 1`: nothing is outstanding yet, so
                    // the handshake itself must not leave an acknowledgement owing.
                    //
                    // `csp_rdp.c:556` sets all three equal on **this** path and only uses
                    // `seq_nr - 1` on the *client* path at line 601, where acking at once
                    // is the point. The client-side assignment had been copied here, so
                    // every incoming handshake left `rcv_cur != rcv_lsa` and the next
                    // `poll_ack` produced a gratuitous frame. Invisible until the router
                    // started calling `poll_ack` at all -- 49 unit tests never polled one
                    // after a handshake.
                    self.rcv_lsa = h.seq_nr;
                    self.state = State::SynRcvd;
                    // When this went out, so `Tick` can tell how long it has gone
                    // unanswered.
                    self.ack_timestamp = now_ms;
                    self.retransmits = 0;
                    return Action::SendControl(Header {
                        flags: SYN | ACK,
                        seq_nr: self.snd_iss,
                        ack_nr: self.rcv_irs,
                    });
                }
                Action::Nothing
            }

            State::SynSent => {
                if h.has(SYN) && h.has(ACK) {
                    self.rcv_cur = h.seq_nr;
                    self.rcv_irs = h.seq_nr;
                    self.rcv_lsa = h.seq_nr.wrapping_sub(1);
                    self.snd_una = h.ack_nr.wrapping_add(1);
                    self.retransmits = 0;
                    self.ack_timestamp = now_ms;
                    self.state = State::Open;
                    return Action::Opened;
                }
                Action::Nothing
            }

            State::SynRcvd => {
                if h.has(ACK) && h.ack_nr == self.snd_iss {
                    self.snd_una = h.ack_nr.wrapping_add(1);
                    self.ack_timestamp = now_ms;
                    // The peer answered, so the attempts spent getting here are spent, not
                    // owed. `csp_rdp.c` clears the counter on this ack and the port's other
                    // two transitions into an open state already did; this one did not.
                    //
                    // **No record can catch this today.** `retransmits` is read in exactly
                    // one place -- the `SynRcvd` arm of `Tick`, for the `SYN|ACK` repeat --
                    // and a connection never returns to `SynRcvd`, so a stale value is
                    // never consulted again. Changed because it is what the C does and what
                    // the neighbouring arms do, not because anything observed it.
                    self.retransmits = 0;
                    self.state = State::Open;
                    return Action::Opened;
                }
                Action::Nothing
            }

            State::Open => {
                // An extended acknowledgement is acknowledgement *only*. `csp_rdp.c:712`
                // updates `snd_una`, clears the retransmit counter, and then
                // `goto discard_open` -- the packet is thrown away including any payload.
                //
                // This module defined the flag and never read it, so a packet carrying
                // `ACK|EAK` and a body was delivered to the application: data a peer had
                // marked as pure acknowledgement, handed over as if it were a message. It
                // was also answered, which the C does not do.
                if h.has(EAK) {
                    if h.has(ACK) {
                        self.snd_una = h.ack_nr.wrapping_add(1);
                    }
                    self.retransmits = 0;
                    return Action::Nothing;
                }

                if !payload.is_empty() {
                    let expected = self.rcv_cur.wrapping_add(1);
                    if h.seq_nr == expected {
                        self.rcv_cur = h.seq_nr;
                        return Action::Deliver;
                    }
                    // Ahead of the gap but inside the window: held, not dropped. This
                    // re-acknowledged and discarded it, so one lost packet cost a
                    // retransmission of everything behind it -- on a link with real
                    // latency, most of the window. Measured against the C by
                    // `rdp::a_gap_filled_late_delivers_both_in_order`.
                    if seq_between(h.seq_nr, expected, expected.wrapping_add(max_window as u16)) {
                        return Action::Hold(h.seq_nr);
                    }
                    // A duplicate or genuinely out-of-window sequence number is
                    // re-acknowledged — that is how the peer learns to stop retransmitting.
                    return Action::SendControl(Header {
                        flags: ACK,
                        seq_nr: self.snd_nxt,
                        ack_nr: self.rcv_cur,
                    });
                }
                if h.has(ACK) {
                    self.snd_una = h.ack_nr.wrapping_add(1);
                    self.retransmits = 0;
                }
                Action::Nothing
            }

            State::CloseWait => {
                if now_ms.wrapping_sub(self.last_activity) > self.opts.conn_timeout {
                    self.state = State::Closed;
                    return Action::Closed(ClosedBy::UserSpace);
                }
                // Anything still arriving is answered with a reset -- `csp_rdp.c`'s
                // `case RDP_CLOSE_WAIT`, "Send back a reset". Silence here left a peer
                // that kept sending with nothing to tell it the connection was over.
                //
                // The C additionally range-checks `ack_nr` against the send window before
                // replying, and discards without answering if it is outside. That is not
                // reproduced: no record distinguishes it, so it would be a guard added
                // from reading rather than from measurement.
                Action::SendControl(Header {
                    flags: ACK | RST,
                    seq_nr: self.snd_nxt,
                    ack_nr: self.rcv_cur,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX_WINDOW: u32 = 5;

    #[test]
    fn header_roundtrip_and_placement() {
        let h = Header {
            flags: SYN | ACK,
            seq_nr: 0x1234,
            ack_nr: 0xABCD,
        };
        let payload = b"data";
        let mut out = [0u8; 32];
        let n = h.encode(payload, &mut out).unwrap();
        assert_eq!(n, payload.len() + HEADER_LEN);
        // trailer, not header: payload first
        assert_eq!(&out[..4], b"data");
        assert_eq!(&out[4..9], &[SYN | ACK, 0x12, 0x34, 0xAB, 0xCD]);
        assert_eq!(Header::decode(&out[..n]).unwrap(), h);
        assert_eq!(Header::strip(&out[..n]).unwrap(), payload);
    }

    #[test]
    fn truncated_header_is_refused() {
        assert_eq!(Header::decode(&[0u8; 4]), Err(Error::Truncated));
        assert_eq!(Header::strip(&[0u8; 4]), Err(Error::Truncated));
    }

    #[test]
    fn syn_options_roundtrip_when_already_in_range() {
        let o = SynOptions {
            window_size: 3,
            conn_timeout: 10_000,
            packet_timeout: 1_000,
            delayed_acks: true,
            ack_timeout: 250,
            ack_delay_count: 2,
        };
        let mut buf = [0u8; 32];
        let n = o.encode(&mut buf).unwrap();
        assert_eq!(n, SYN_OPTIONS_LEN);
        assert_eq!(SynOptions::decode_clamped(&buf, MAX_WINDOW).unwrap(), o);
    }

    #[test]
    fn a_partial_option_block_is_refused() {
        // The C sends RST and closes rather than filling in defaults.
        assert_eq!(
            SynOptions::decode_clamped(&[0u8; 23], MAX_WINDOW),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn hostile_options_are_clamped_at_every_bound() {
        // All-zero: every minimum.
        let zero = [0u8; SYN_OPTIONS_LEN];
        let o = SynOptions::decode_clamped(&zero, MAX_WINDOW).unwrap();
        assert_eq!(o.window_size, 1, "a zero window would deadlock");
        assert_eq!(o.conn_timeout, MIN_CONN_TIMEOUT);
        assert_eq!(o.packet_timeout, MIN_PACKET_TIMEOUT);
        assert!(!o.delayed_acks);
        assert_eq!(o.ack_timeout, MIN_ACK_TIMEOUT);
        assert_eq!(o.ack_delay_count, 1);

        // All-ones: every maximum.
        let ones = [0xFFu8; SYN_OPTIONS_LEN];
        let o = SynOptions::decode_clamped(&ones, MAX_WINDOW).unwrap();
        assert_eq!(o.window_size, MAX_WINDOW, "cannot exceed the local pool");
        assert_eq!(
            o.conn_timeout, MAX_CONN_TIMEOUT,
            "an unbounded timeout would hold a connection slot forever"
        );
        assert_eq!(o.packet_timeout, MAX_PACKET_TIMEOUT);
        assert!(o.delayed_acks);
        assert_eq!(
            o.ack_timeout, o.conn_timeout,
            "bounded by the clamped conn_timeout"
        );
        assert_eq!(
            o.ack_delay_count, o.window_size,
            "bounded by the clamped window"
        );
    }

    #[test]
    fn one_field_cannot_widen_anothers_bound() {
        // ack_timeout is clamped against the ALREADY clamped conn_timeout, so asking for
        // a huge conn_timeout does not buy a huge ack_timeout.
        let mut buf = [0u8; SYN_OPTIONS_LEN];
        buf[4..8].copy_from_slice(&u32::MAX.to_be_bytes()); // conn_timeout
        buf[16..20].copy_from_slice(&u32::MAX.to_be_bytes()); // ack_timeout
        let o = SynOptions::decode_clamped(&buf, MAX_WINDOW).unwrap();
        assert_eq!(o.conn_timeout, MAX_CONN_TIMEOUT);
        assert_eq!(o.ack_timeout, MAX_CONN_TIMEOUT);
        assert!(o.ack_timeout <= MAX_CONN_TIMEOUT);
    }

    #[test]
    fn sequence_comparison_survives_the_wrap() {
        assert!(seq_between(5, 1, 10));
        assert!(seq_between(1, 1, 10));
        assert!(seq_between(10, 1, 10));
        assert!(!seq_between(11, 1, 10));
        // across the 16-bit wrap, where a naive comparison fails
        assert!(seq_between(0, 0xFFFE, 2));
        assert!(seq_between(0xFFFF, 0xFFFE, 2));
        assert!(seq_between(2, 0xFFFE, 2));
        assert!(!seq_between(3, 0xFFFE, 2));
    }

    fn syn_payload(o: &SynOptions) -> [u8; SYN_OPTIONS_LEN] {
        let mut b = [0u8; SYN_OPTIONS_LEN];
        o.encode(&mut b).unwrap();
        b
    }

    #[test]
    fn three_way_handshake_as_the_initiator() {
        let mut c = Connection::new(100, SynOptions::default());
        assert_eq!(c.state, State::Closed);

        let a = c.step(Event::Connect, 0, MAX_WINDOW);
        assert!(matches!(a, Action::SendSyn(h, _) if h.flags == SYN && h.seq_nr == 100));
        assert_eq!(c.state, State::SynSent);

        // peer replies SYN|ACK
        let a = c.step(
            Event::Packet(
                Header {
                    flags: SYN | ACK,
                    seq_nr: 500,
                    ack_nr: 100,
                },
                &[],
            ),
            10,
            MAX_WINDOW,
        );
        assert_eq!(a, Action::Opened);
        assert_eq!(c.state, State::Open);
        assert_eq!(c.rcv_irs, 500);
    }

    #[test]
    fn three_way_handshake_as_the_responder() {
        let mut c = Connection::new(900, SynOptions::default());
        let opts = SynOptions::default();
        let a = c.step(
            Event::Packet(
                Header {
                    flags: SYN,
                    seq_nr: 42,
                    ack_nr: 0,
                },
                &syn_payload(&opts),
            ),
            0,
            MAX_WINDOW,
        );
        assert!(
            matches!(a, Action::SendControl(h) if h.flags == SYN | ACK && h.ack_nr == 42),
            "must answer SYN|ACK acknowledging the peer's ISS"
        );
        assert_eq!(c.state, State::SynRcvd);

        let a = c.step(
            Event::Packet(
                Header {
                    flags: ACK,
                    seq_nr: 43,
                    ack_nr: 900,
                },
                &[],
            ),
            5,
            MAX_WINDOW,
        );
        assert_eq!(a, Action::Opened);
        assert_eq!(c.state, State::Open);
    }

    #[test]
    fn a_syn_without_options_is_reset_not_defaulted() {
        // Using defaults here would let a truncated SYN silently pick this node's timers.
        let mut c = Connection::new(1, SynOptions::default());
        let a = c.step(
            Event::Packet(
                Header {
                    flags: SYN,
                    seq_nr: 7,
                    ack_nr: 0,
                },
                &[0u8; 8],
            ),
            0,
            MAX_WINDOW,
        );
        assert!(matches!(a, Action::SendControl(h) if h.flags == RST));
        assert_eq!(c.state, State::Closed, "must not half-open");
    }

    /// Both halves, measured against libcsp on 2026-08-26. This asserted that *any* reset
    /// closes from any live state, with `seq_nr: 0` -- which is out of sequence -- and so
    /// pinned the blind-reset hole it was meant to guard. `csp_rdp.c` honours a reset only
    /// at `rcv_cur + 1`; anything else is "RST out of sequence, keep connection open".
    /// End to end in `rdp::an_in_sequence_rst_is_answered` and
    /// `rdp::an_out_of_sequence_rst_is_ignored`.
    #[test]
    fn a_reset_is_honoured_only_in_sequence() {
        let rst = |seq: u16| {
            Event::Packet(
                Header {
                    flags: RST,
                    seq_nr: seq,
                    ack_nr: 0,
                },
                &[] as &[u8],
            )
        };

        for setup in [State::SynSent, State::SynRcvd, State::Open] {
            // In sequence: answered with `ACK|RST`, and the connection waits to be closed.
            let mut c = Connection::new(1, SynOptions::default());
            c.state = setup;
            c.rcv_cur = 10;
            let a = c.step(rst(11), 0, MAX_WINDOW);
            assert!(
                matches!(a, Action::SendControl(h) if h.flags == ACK | RST),
                "from {setup:?} the peer must be told its reset arrived"
            );
            assert_eq!(c.state, State::CloseWait, "from {setup:?}");

            // Out of sequence: ignored, and the connection carries on. One spoofed frame
            // must not be able to drop a link.
            let mut c = Connection::new(1, SynOptions::default());
            c.state = setup;
            c.rcv_cur = 10;
            assert_eq!(
                c.step(rst(9999), 0, MAX_WINDOW),
                Action::Nothing,
                "from {setup:?}"
            );
            assert_eq!(c.state, setup, "from {setup:?} the connection must survive");
        }
    }

    #[test]
    fn in_order_data_is_delivered_and_advances_the_sequence() {
        let mut c = Connection::new(1, SynOptions::default());
        c.state = State::Open;
        c.rcv_cur = 10;
        let a = c.step(
            Event::Packet(
                Header {
                    flags: ACK,
                    seq_nr: 11,
                    ack_nr: 0,
                },
                b"payload",
            ),
            0,
            MAX_WINDOW,
        );
        assert_eq!(a, Action::Deliver);
        assert_eq!(c.rcv_cur, 11);
    }

    #[test]
    fn a_duplicate_is_reacknowledged_not_delivered() {
        // Delivering a duplicate would hand the application the same bytes twice; not
        // acknowledging it would make the peer retransmit forever.
        let mut c = Connection::new(1, SynOptions::default());
        c.state = State::Open;
        c.rcv_cur = 10;
        let a = c.step(
            Event::Packet(
                Header {
                    flags: ACK,
                    seq_nr: 10,
                    ack_nr: 0,
                },
                b"again",
            ),
            0,
            MAX_WINDOW,
        );
        assert!(matches!(a, Action::SendControl(h) if h.flags == ACK && h.ack_nr == 10));
        assert_eq!(c.rcv_cur, 10, "must not advance on a duplicate");
    }

    #[test]
    fn an_out_of_window_packet_is_reacknowledged_not_delivered() {
        let mut c = Connection::new(1, SynOptions::default());
        c.state = State::Open;
        c.rcv_cur = 10;
        let a = c.step(
            Event::Packet(
                Header {
                    flags: ACK,
                    seq_nr: 99,
                    ack_nr: 0,
                },
                b"jump",
            ),
            0,
            MAX_WINDOW,
        );
        assert!(matches!(a, Action::SendControl(h) if h.flags == ACK));
        assert_eq!(c.rcv_cur, 10);
    }

    /// Measured against libcsp on 2026-08-26, and the opposite of what this test asserted
    /// before: an **established** connection is not reaped on `conn_timeout`.
    /// `csp_rdp_check_timeouts` guards its CONNECTION TIMEOUT with `dest_socket != NULL`,
    /// and `dest_socket` is cleared when the connection is announced to the socket, so the
    /// branch only ever covers a handshake that never finished. Pinned end to end by
    /// `rdp::a_proposed_conn_timeout_is_adopted`.
    /// `csp_rdp_send` refuses once `snd_nxt` reaches `snd_una + window_size - 1`; the C
    /// blocks on `tx_wait` there, and a sans-io node reports it. Without the bound a sender
    /// runs ahead of what the peer can acknowledge and the window means nothing.
    #[test]
    fn the_send_window_bounds_what_may_be_claimed() {
        let mut c = Connection::new(
            1,
            SynOptions {
                window_size: 3,
                ..SynOptions::default()
            },
        );
        c.state = State::Open;
        c.snd_una = c.snd_nxt;

        // Three fit.
        for i in 0..3 {
            assert!(c.begin_send(0).is_some(), "packet {i} must fit the window");
        }
        // The fourth does not, until the peer acknowledges something.
        assert!(c.begin_send(0).is_none(), "a full window must refuse");
        c.snd_una = c.snd_una.wrapping_add(1);
        assert!(c.begin_send(0).is_some(), "an acknowledgement reopens it");
    }

    #[test]
    fn only_an_unestablished_connection_times_out() {
        // Established: stays, however long it is quiet. A telemetry link between passes.
        let mut open = Connection::new(1, SynOptions::default());
        open.state = State::Open;
        open.last_activity = 0;
        assert_eq!(open.step(Event::Tick, 5_000, MAX_WINDOW), Action::Nothing);
        assert_eq!(open.step(Event::Tick, 10_001, MAX_WINDOW), Action::Nothing);
        assert_eq!(open.state, State::Open);

        // A handshake that never completed: reaped, so a half-open connection cannot hold
        // a slot for ever.
        let mut half = Connection::new(1, SynOptions::default());
        half.state = State::SynSent;
        half.last_activity = 0;
        assert_eq!(half.step(Event::Tick, 5_000, MAX_WINDOW), Action::Nothing);
        assert_eq!(
            half.step(Event::Tick, 10_001, MAX_WINDOW),
            Action::Closed(ClosedBy::Timeout)
        );
        assert_eq!(half.state, State::Closed);
    }

    #[test]
    fn the_timeout_survives_a_wrapping_clock() {
        // now_ms is a free-running 32-bit millisecond counter; it wraps every 49 days.
        // A naive `now - last > timeout` with signed maths closes every connection at
        // the wrap.
        let mut c = Connection::new(1, SynOptions::default());
        c.state = State::Open;
        c.last_activity = u32::MAX - 1_000;
        // 500 ms later, having wrapped through zero
        assert_eq!(
            c.step(Event::Tick, 1_000u32.wrapping_sub(1_500), MAX_WINDOW),
            Action::Nothing,
            "must not close merely because the clock wrapped"
        );
    }

    #[test]
    fn close_sends_rst_and_enters_close_wait() {
        let mut c = Connection::new(1, SynOptions::default());
        c.state = State::Open;
        let a = c.step(Event::Close, 0, MAX_WINDOW);
        assert!(matches!(a, Action::SendControl(h) if h.flags == RST));
        assert_eq!(c.state, State::CloseWait);
    }

    #[test]
    fn closing_an_already_closed_connection_does_nothing() {
        let mut c = Connection::new(1, SynOptions::default());
        assert_eq!(c.step(Event::Close, 0, MAX_WINDOW), Action::Nothing);
        assert_eq!(c.step(Event::Tick, 999_999, MAX_WINDOW), Action::Nothing);
    }

    #[test]
    fn connecting_twice_does_nothing_the_second_time() {
        let mut c = Connection::new(1, SynOptions::default());
        assert!(matches!(
            c.step(Event::Connect, 0, MAX_WINDOW),
            Action::SendSyn(..)
        ));
        assert_eq!(c.step(Event::Connect, 0, MAX_WINDOW), Action::Nothing);
    }

    #[test]
    fn two_connections_can_use_different_options() {
        // The C keeps its six RDP tunables in file statics shared by every connection, so
        // this is not expressible there at all.
        let fast = SynOptions {
            packet_timeout: 100,
            ..SynOptions::default()
        };
        let slow = SynOptions {
            packet_timeout: 5_000,
            ..SynOptions::default()
        };
        let a = Connection::new(1, fast);
        let b = Connection::new(2, slow);
        assert_eq!(a.opts.packet_timeout, 100);
        assert_eq!(b.opts.packet_timeout, 5_000);
    }

    // --- acknowledgement ---

    fn open_conn() -> Connection {
        let mut c = Connection::new(100, SynOptions::default());
        c.state = State::Open;
        c.rcv_cur = 10;
        c.rcv_lsa = 10;
        c.ack_timestamp = 0;
        c
    }

    #[test]
    fn received_data_is_eventually_acknowledged() {
        // Before this audit, in-order data was delivered and NEVER acknowledged, so the
        // sender only learned of it when its own retransmit timer fired -- a full
        // packet_timeout of latency and a duplicate on the link, per packet.
        let mut c = open_conn();
        assert_eq!(
            c.step(
                Event::Packet(
                    Header {
                        flags: ACK,
                        seq_nr: 11,
                        ack_nr: 0
                    },
                    b"data"
                ),
                10,
                MAX_WINDOW
            ),
            Action::Deliver
        );
        // Past the ack timeout, an acknowledgement is due.
        let ack = c
            .poll_ack(10_000)
            .expect("an ack must eventually be produced");
        assert_eq!(ack.flags, ACK);
        assert_eq!(ack.ack_nr, 11, "must acknowledge what was received");
    }

    #[test]
    fn nothing_received_means_nothing_to_acknowledge() {
        let mut c = open_conn();
        assert!(!c.should_ack(999_999));
        assert_eq!(c.poll_ack(999_999), None);
    }

    #[test]
    fn with_delayed_acks_off_every_packet_is_acknowledged_at_once() {
        let mut c = open_conn();
        c.opts.delayed_acks = false;
        c.rcv_cur = 11;
        assert!(c.should_ack(0), "no delay means acknowledge immediately");
    }

    #[test]
    fn a_delayed_ack_fires_on_the_timeout() {
        let mut c = open_conn();
        c.opts.delayed_acks = true;
        c.opts.ack_timeout = 250;
        c.opts.ack_delay_count = 100; // so only the timeout can trigger it
        c.rcv_cur = 11;
        assert!(!c.should_ack(100), "still inside the ack timeout");
        assert!(c.should_ack(500), "past the ack timeout");
    }

    /// The acknowledgement fires once the outstanding count *exceeds* the delay, not when
    /// it reaches it -- `csp_rdp_seq_after(rcv_cur, rcv_lsa + ack_delay_count)` is strictly
    /// after. This asserted `>=`, describing a policy one packet more eager than the C's.
    /// `ctest/suite_rdp.c` measures the real thing: with a delay count of 2, five packets
    /// produce acknowledgements [0, 0, 1, 1, 1].
    #[test]
    fn a_delayed_ack_fires_one_packet_after_the_count() {
        let mut c = open_conn();
        c.opts.delayed_acks = true;
        c.opts.ack_timeout = 100_000; // so only the count can trigger it
        c.opts.ack_delay_count = 2;

        c.rcv_cur = 11;
        assert!(!c.should_ack(0), "one outstanding, below the delay count");
        c.rcv_cur = 12;
        assert!(!c.should_ack(0), "two outstanding only *reaches* the count");
        c.rcv_cur = 13;
        assert!(c.should_ack(0), "three outstanding exceeds it");
    }

    #[test]
    fn taking_an_ack_restarts_both_delay_counters() {
        let mut c = open_conn();
        c.opts.ack_delay_count = 1;
        c.rcv_cur = 11;
        assert!(c.poll_ack(500).is_some());
        assert!(!c.should_ack(500), "nothing outstanding right after acking");
        assert_eq!(c.rcv_lsa, 11);
        assert_eq!(c.ack_timestamp, 500);
    }

    #[test]
    fn acking_survives_the_clock_wrap() {
        // `now > ack_timestamp + timeout` would suppress every ack at the wrap.
        let mut c = open_conn();
        c.opts.ack_timeout = 250;
        c.opts.ack_delay_count = 100;
        c.rcv_cur = 11;
        c.ack_timestamp = u32::MAX - 100;
        assert!(
            !c.should_ack(u32::MAX.wrapping_add(50)),
            "50 ms later is still inside the timeout, wrap or not"
        );
        assert!(
            c.should_ack(u32::MAX.wrapping_add(500)),
            "500 ms later is past it"
        );
    }

    #[test]
    fn a_closed_connection_produces_no_acks() {
        let mut c = open_conn();
        c.rcv_cur = 11;
        c.state = State::Closed;
        assert_eq!(c.poll_ack(999_999), None);
    }

    // --- receive reorder queue ---

    #[test]
    fn an_out_of_order_packet_is_held_not_discarded() {
        // Discarding it costs a retransmission of everything after the gap.
        let mut q: RxQueue<4> = RxQueue::new();
        q.insert(12, 112).unwrap();
        assert_eq!(q.len(), 1);
        assert!(q.contains(12));
        // The gap has not filled, so 12 is not deliverable yet.
        assert_eq!(q.take(11), None);
    }

    #[test]
    fn filling_a_gap_releases_everything_it_unblocked() {
        // The C restarts its scan from the front after each delivery (goto front); here
        // that is a while-let in the caller.
        let mut q: RxQueue<8> = RxQueue::new();
        // 12, 13, 14 arrived; 11 was lost and has just been retransmitted.
        for (seq, tok) in [(12u16, 112u16), (13, 113), (14, 114)] {
            q.insert(seq, tok).unwrap();
        }
        let mut rcv_cur = 10u16;
        let mut delivered = heapless::Vec8::new();
        // 11 arrives in order and is delivered directly.
        rcv_cur = rcv_cur.wrapping_add(1);
        delivered.push(111);
        // Now drain what it unblocked.
        while let Some(tok) = q.take(rcv_cur.wrapping_add(1)) {
            delivered.push(tok);
            rcv_cur = rcv_cur.wrapping_add(1);
        }
        assert_eq!(delivered.as_slice(), &[111, 112, 113, 114]);
        assert!(q.is_empty());
        assert_eq!(rcv_cur, 14);
    }

    #[test]
    fn a_gap_that_does_not_fill_holds_the_rest_back() {
        let mut q: RxQueue<8> = RxQueue::new();
        // 13 and 14 arrived, but 12 is still missing.
        q.insert(13, 113).unwrap();
        q.insert(14, 114).unwrap();
        let rcv_cur = 11u16;
        assert_eq!(q.take(rcv_cur.wrapping_add(1)), None, "12 is still missing");
        assert_eq!(q.len(), 2, "and the rest stay held");
    }

    #[test]
    fn a_retransmitted_duplicate_is_reported_as_such() {
        // Retransmission is how RDP recovers, so this is expected rather than a fault --
        // and the caller must release its copy rather than leak it.
        let mut q: RxQueue<4> = RxQueue::new();
        q.insert(12, 112).unwrap();
        assert_eq!(q.insert(12, 999), Err(Error::DuplicateSequence { seq: 12 }));
        assert_eq!(q.len(), 1, "the original is kept, not replaced");
        assert_eq!(q.take(12), Some(112), "and it is the original token");
    }

    #[test]
    fn a_full_receive_window_is_reported() {
        let mut q: RxQueue<2> = RxQueue::new();
        q.insert(1, 1).unwrap();
        q.insert(2, 2).unwrap();
        assert_eq!(q.insert(3, 3), Err(Error::TableFull));
    }

    #[test]
    fn the_reorder_queue_works_across_the_sequence_wrap() {
        let mut q: RxQueue<4> = RxQueue::new();
        q.insert(0, 200).unwrap();
        q.insert(1, 201).unwrap();
        let mut rcv_cur = 0xFFFEu16;
        let mut got = heapless::Vec8::new();
        rcv_cur = rcv_cur.wrapping_add(1); // 0xFFFF delivered in order
        while let Some(t) = q.take(rcv_cur.wrapping_add(1)) {
            got.push(t);
            rcv_cur = rcv_cur.wrapping_add(1);
        }
        assert_eq!(got.as_slice(), &[200, 201], "must not stall at the wrap");
        assert_eq!(rcv_cur, 1);
    }

    #[test]
    fn rx_flush_returns_every_token_so_nothing_leaks() {
        let mut q: RxQueue<4> = RxQueue::new();
        q.insert(1, 101).unwrap();
        q.insert(2, 102).unwrap();
        let mut out = [0u16; 8];
        let n = q.flush(&mut out);
        assert_eq!(n, 2);
        assert!(out[..n].contains(&101) && out[..n].contains(&102));
        assert!(q.is_empty());
    }

    mod heapless {
        pub struct Vec8 {
            items: [u16; 8],
            len: usize,
        }
        impl Vec8 {
            pub fn new() -> Self {
                Vec8 {
                    items: [0; 8],
                    len: 0,
                }
            }
            pub fn push(&mut self, v: u16) {
                self.items[self.len] = v;
                self.len += 1;
            }
            pub fn as_slice(&self) -> &[u16] {
                &self.items[..self.len]
            }
        }
    }

    // --- retransmission queue ---

    fn drain(q: &mut TxQueue<4>, now: u32, timeout: u32, una: u16) -> ([TxAction; 8], usize) {
        let mut out = [TxAction::GiveUp; 8];
        let n = q.poll(now, timeout, una, &mut out);
        (out, n)
    }

    #[test]
    fn seq_before_survives_the_wrap() {
        assert!(seq_before(1, 2));
        assert!(!seq_before(2, 1));
        assert!(!seq_before(5, 5), "not strictly before itself");
        assert!(seq_before(0xFFFF, 0), "across the wrap");
        assert!(!seq_before(0, 0xFFFF));
    }

    #[test]
    fn nothing_happens_before_the_timeout() {
        let mut q: TxQueue<4> = TxQueue::new();
        q.push(10, 100, 0).unwrap();
        let (_, n) = drain(&mut q, 500, 1_000, 10);
        assert_eq!(n, 0, "still within the packet timeout");
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn an_unacknowledged_packet_is_retransmitted_after_its_timeout() {
        // Without this the "Reliable" in Reliable Datagram Protocol is false.
        let mut q: TxQueue<4> = TxQueue::new();
        q.push(10, 100, 0).unwrap();
        let (out, n) = drain(&mut q, 1_500, 1_000, 10);
        assert_eq!(n, 1);
        assert_eq!(
            out[0],
            TxAction::Retransmit {
                token: 100,
                seq_nr: 10
            }
        );
        assert_eq!(q.len(), 1, "still queued until acknowledged");
    }

    #[test]
    fn the_retransmit_timer_restarts_so_it_does_not_fire_every_poll() {
        let mut q: TxQueue<4> = TxQueue::new();
        q.push(10, 100, 0).unwrap();
        let (_, n) = drain(&mut q, 1_500, 1_000, 10);
        assert_eq!(n, 1);
        let (_, n) = drain(&mut q, 1_600, 1_000, 10);
        assert_eq!(n, 0, "must wait a full timeout again, not spin");
        let (_, n) = drain(&mut q, 2_600, 1_000, 10);
        assert_eq!(n, 1);
    }

    #[test]
    fn an_acknowledged_packet_is_released() {
        let mut q: TxQueue<4> = TxQueue::new();
        q.push(10, 100, 0).unwrap();
        q.push(11, 101, 0).unwrap();
        // snd_una = 11 means 10 is acknowledged, 11 is not.
        let (out, n) = drain(&mut q, 0, 1_000, 11);
        assert_eq!(n, 1);
        assert_eq!(out[0], TxAction::Release { token: 100 });
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn acknowledgement_wins_over_retransmission() {
        // A packet acknowledged and overdue must be released, not sent again -- otherwise
        // every ack that arrives late costs a duplicate on the link.
        let mut q: TxQueue<4> = TxQueue::new();
        q.push(10, 100, 0).unwrap();
        let (out, n) = drain(&mut q, 99_999, 1_000, 11);
        assert_eq!(n, 1);
        assert_eq!(out[0], TxAction::Release { token: 100 });
    }

    #[test]
    fn a_peer_that_never_acknowledges_is_given_up_on() {
        // The C closes after CSP_RDP_MAX_RETRANSMITS; without it a connection retransmits
        // for as long as it lives, holding a buffer per unacknowledged packet.
        let mut q: TxQueue<4> = TxQueue::new();
        q.push(10, 100, 0).unwrap();
        let mut gave_up = false;
        for i in 1..=(MAX_RETRANSMITS + 2) {
            let (out, n) = drain(&mut q, i * 2_000, 1_000, 10);
            if out[..n].contains(&TxAction::GiveUp) {
                gave_up = true;
                break;
            }
        }
        assert!(gave_up, "must stop retransmitting eventually");
    }

    #[test]
    fn progress_resets_the_give_up_counter() {
        let mut q: TxQueue<4> = TxQueue::new();
        q.push(10, 100, 0).unwrap();
        for i in 1..=5 {
            drain(&mut q, i * 2_000, 1_000, 10);
        }
        assert!(q.retransmits() > 0);
        q.note_progress();
        assert_eq!(q.retransmits(), 0, "an ack means the peer is alive");
    }

    #[test]
    fn retransmission_survives_the_clock_wrap() {
        // `now > sent_at + timeout` would retransmit the whole window at the wrap.
        let mut q: TxQueue<4> = TxQueue::new();
        let sent = u32::MAX - 500;
        q.push(10, 100, sent).unwrap();
        // 100 ms later, having wrapped through zero. Well inside a 1000 ms timeout.
        let (_, n) = drain(&mut q, sent.wrapping_add(100), 1_000, 10);
        assert_eq!(n, 0, "must not retransmit merely because the clock wrapped");
    }

    #[test]
    fn a_full_window_is_reported_rather_than_dropped() {
        // Silently discarding the record leaves the packet unretransmittable while the
        // peer still expects it.
        let mut q: TxQueue<4> = TxQueue::new();
        for i in 0..4u16 {
            q.push(i, i, 0).unwrap();
        }
        assert_eq!(q.push(9, 9, 0), Err(Error::TableFull));
    }

    #[test]
    fn flush_returns_every_token_so_nothing_leaks() {
        let mut q: TxQueue<4> = TxQueue::new();
        for i in 0..3u16 {
            q.push(i, 100 + i, 0).unwrap();
        }
        let mut out = [0u16; 8];
        let n = q.flush(&mut out);
        assert_eq!(n, 3);
        assert!(out[..n].contains(&100) && out[..n].contains(&101) && out[..n].contains(&102));
        assert!(q.is_empty());
        assert_eq!(q.retransmits(), 0);
    }

    #[test]
    fn a_short_action_buffer_does_not_lose_the_queue() {
        // poll writes what fits; the entries it could not report are still queued and
        // come back on the next call, rather than being silently dropped.
        let mut q: TxQueue<4> = TxQueue::new();
        for i in 0..4u16 {
            q.push(i, i, 0).unwrap();
        }
        let mut tiny = [TxAction::GiveUp; 1];
        let n = q.poll(0, 1_000, 4, &mut tiny);
        assert_eq!(n, 1);
        assert_eq!(q.len(), 3, "only the reported one was released");
        let mut rest = [TxAction::GiveUp; 8];
        let n2 = q.poll(0, 1_000, 4, &mut rest);
        assert_eq!(n2, 3, "the remainder comes back rather than being lost");
        assert!(q.is_empty());
    }

    #[test]
    fn arbitrary_packets_never_panic_in_any_state() {
        let states = [
            State::Closed,
            State::SynSent,
            State::SynRcvd,
            State::Open,
            State::CloseWait,
        ];
        let mut x: u32 = 0x5EED_1234;
        let mut payload = [0u8; 40];
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            for st in states {
                let mut c = Connection::new(x as u16, SynOptions::default());
                c.state = st;
                for (i, b) in payload.iter_mut().enumerate() {
                    *b = (x >> (i % 24)) as u8;
                }
                let h = Header {
                    flags: x as u8,
                    seq_nr: (x >> 8) as u16,
                    ack_nr: (x >> 16) as u16,
                };
                let n = (x as usize) % payload.len();
                let _ = c.step(Event::Packet(h, &payload[..n]), x, MAX_WINDOW);
                let _ = c.step(Event::Tick, x.wrapping_add(1), MAX_WINDOW);
            }
        }
    }

    #[test]
    fn the_defaults_are_the_cs_compiled_in_values() {
        // libcsp keeps these in six file-scope statics (csp_rdp.c:37-42) that
        // csp_rdp_set_opt overwrites process-wide -- so one library changing the window
        // size changes it for every connection in the node, including ones already open.
        // Here they are per-connection defaults, and these numbers must still match or a
        // Rust node and a C node negotiate differently.
        let d = SynOptions::default();
        assert_eq!(d.window_size, 4);
        assert_eq!(d.conn_timeout, 10_000);
        assert_eq!(d.packet_timeout, 1_000);
        assert!(d.delayed_acks);
        assert_eq!(d.ack_timeout, 250, "csp_rdp_ack_timeout = 1000 / 4");
        assert_eq!(d.ack_delay_count, 2, "csp_rdp_ack_delay_count = 4 / 2");
    }
}
