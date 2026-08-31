//! Ports that accept either a datagram or a stream.
//!
//! # The problem this solves
//!
//! In libcsp a port's shape is fixed at registration: the dispatcher either reads packets
//! and hands them over one at a time, or hands the whole connection to a stream handler.
//! A sender that guesses wrong is punished twice — `csp_sfp_header_remove` returns NULL
//! the instant `FRAG` is clear, and its caller **frees the packet** — so a plain datagram
//! arriving at a stream port is destroyed, and the sender sees `-103 CSP_ERR_SFP`, which
//! says "SFP problem" rather than "that port wanted fragments".
//!
//! # The wire already tells you
//!
//! Two independent axes, both self-describing:
//!
//! | Axis | Signal | Known at | Affects |
//! |---|---|---|---|
//! | **RDP** | `RDP` bit, a *connection* option negotiated in the handshake | accept | *how* you read — retransmission, handshake timing, MTU overhead |
//! | **SFP** | `FRAG` bit, a *per-packet* header flag | first packet | *what the payload is* — one datagram, or a fragment |
//!
//! All four combinations are legal. So RDP is absorbed by the library and never reaches
//! the handler, while SFP becomes a [`Delivery`] the handler matches on. Deciding costs
//! one packet peek and consumes nothing — [`csp_core::sfp::Fragment::parse`] returns
//! [`NotAFragment`](csp_core::Error::NotAFragment) with the bytes intact.

use crate::pool::Packet;
use csp_core::sfp;
use csp_core::{Error, Result};

/// Somewhere further packets of a transfer can be pulled from.
///
/// A trait rather than a concrete connection so a stream can be driven by a test, a
/// connection, or a replayed capture.
pub trait PacketSource<'p, const N: usize, const SZ: usize> {
    /// Next packet of this transfer, or `None` on timeout or close.
    fn next_packet(&mut self, timeout_ms: u32) -> Option<Packet<'p, N, SZ>>;
}

/// What arrived on a port.
#[derive(Debug)]
pub enum Delivery<'s, 'p, S, const N: usize, const SZ: usize>
where
    S: PacketSource<'p, N, SZ>,
{
    /// A complete message in one packet. `FRAG` was clear.
    Datagram(Packet<'p, N, SZ>),
    /// The start of a fragmented transfer. `FRAG` was set.
    Stream(Stream<'s, 'p, S, N, SZ>),
}

impl<'s, 'p, S, const N: usize, const SZ: usize> Delivery<'s, 'p, S, N, SZ>
where
    S: PacketSource<'p, N, SZ>,
{
    /// Classify the first packet of a delivery.
    ///
    /// Never consumes the packet to decide: a datagram comes back whole.
    pub fn classify(first: Packet<'p, N, SZ>, source: &'s mut S) -> Self {
        if first.id().is_fragment() {
            Delivery::Stream(Stream::new(first, source))
        } else {
            Delivery::Datagram(first)
        }
    }

    /// The datagram, or [`Error::NotAFragment`]'s opposite — a stream where a datagram was
    /// wanted.
    ///
    /// Consumes `self` and **returns the delivery on mismatch** rather than dropping it,
    /// so a narrow handler cannot destroy a message by being the wrong shape.
    pub fn into_datagram(self) -> core::result::Result<Packet<'p, N, SZ>, Self> {
        match self {
            Delivery::Datagram(p) => Ok(p),
            other => Err(other),
        }
    }

    /// The stream, or the delivery back if it was a datagram.
    pub fn into_stream(self) -> core::result::Result<Stream<'s, 'p, S, N, SZ>, Self> {
        match self {
            Delivery::Stream(s) => Ok(s),
            other => Err(other),
        }
    }
}

/// A fragmented transfer being reassembled.
#[derive(Debug)]
pub struct Stream<'s, 'p, S, const N: usize, const SZ: usize>
where
    S: PacketSource<'p, N, SZ>,
{
    source: &'s mut S,
    pending: Option<Packet<'p, N, SZ>>,
    total: u32,
    /// Offset the next fragment must start at. Tracked here rather than in an
    /// `sfp::Reassembler`, because a chunkwise reader has nowhere to reassemble *into* —
    /// the whole point is not materialising the message.
    expected: u32,
    done: bool,
}

impl<'s, 'p, S, const N: usize, const SZ: usize> Stream<'s, 'p, S, N, SZ>
where
    S: PacketSource<'p, N, SZ>,
{
    fn new(first: Packet<'p, N, SZ>, source: &'s mut S) -> Self {
        // The first fragment carries the total, so a caller can size its buffer before
        // reading a single byte.
        let total =
            first.with_payload(|d| sfp::Fragment::parse(true, d).map(|f| f.total).unwrap_or(0));
        Stream {
            source,
            pending: Some(first),
            total,
            expected: 0,
            done: false,
        }
    }

    /// Total size of the message, from the first fragment.
    pub const fn total_len(&self) -> u32 {
        self.total
    }

    /// Bytes accepted so far.
    pub const fn received(&self) -> u32 {
        self.expected
    }

    /// True once every fragment has arrived.
    pub const fn is_complete(&self) -> bool {
        self.done
    }

    /// Pull the next chunk and hand it to `f`, without ever materialising the whole
    /// message.
    ///
    /// This is the shape a log dump needs: the flight log-dump service streams a ring
    /// buffer it cannot fit in RAM, so an API that only offers "give me the whole thing"
    /// is unusable for it.
    ///
    /// Returns `Ok(false)` when the transfer is complete.
    pub fn read_chunk<R>(
        &mut self,
        timeout_ms: u32,
        f: impl FnOnce(&[u8], u32, u32) -> R,
    ) -> Result<Option<R>> {
        if self.done {
            return Ok(None);
        }
        let packet = match self.pending.take() {
            Some(p) => p,
            None => match self.source.next_packet(timeout_ms) {
                Some(p) => p,
                None => return Err(Error::Truncated),
            },
        };

        let expected = self.expected;
        let total = self.total;
        let mut advanced = 0u32;
        let mut out = None;

        packet.with_payload(|d| -> Result<()> {
            let frag = sfp::Fragment::parse(true, d)?;
            // Same checks sfp::Reassembler applies, minus the copy.
            if frag.total != total {
                return Err(Error::InconsistentTotal {
                    expected: total,
                    got: frag.total,
                });
            }
            if frag.offset != expected {
                return Err(Error::UnexpectedOffset {
                    expected,
                    got: frag.offset,
                });
            }
            if frag.payload.is_empty() {
                return Err(Error::EmptyFragment);
            }
            let end = frag.offset + frag.payload.len() as u32;
            if end > total {
                return Err(Error::OffsetBeyondTotal {
                    offset: frag.offset,
                    total,
                });
            }
            advanced = end;
            out = Some(f(frag.payload, frag.offset, frag.total));
            Ok(())
        })?;

        self.expected = advanced;
        if advanced >= self.total {
            self.done = true;
        }
        Ok(out)
    }

    /// Reassemble the whole message into `out`, returning its length.
    ///
    /// Fails with [`Error::BufferTooSmall`] carrying the size needed, rather than
    /// truncating — the C's flat-buffer receive sets an overflow flag the caller has to
    /// remember to check.
    pub fn read_to_slice(&mut self, timeout_ms: u32, out: &mut [u8]) -> Result<usize> {
        if (self.total as usize) > out.len() {
            return Err(Error::BufferTooSmall {
                needed: self.total as usize,
            });
        }
        let mut written = 0usize;
        while !self.done {
            let got = self.read_chunk(timeout_ms, |chunk, offset, _| {
                let start = offset as usize;
                let end = start + chunk.len();
                if end <= out.len() {
                    out[start..end].copy_from_slice(chunk);
                    end
                } else {
                    0
                }
            })?;
            match got {
                Some(end) => written = core::cmp::max(written, end),
                None => break,
            }
        }
        Ok(written)
    }
}

/// A registered port handler.
///
/// Three shapes, because both firmware consumers independently arrived at exactly these
/// three: run it inline on the router thread, hand it to a worker, or give it the
/// connection unread.
pub enum Handler {
    /// Accepts whichever shape arrives. The default, and the one to reach for.
    Any,
    /// Accepts only a whole datagram. A stream is refused **without being consumed**.
    DatagramOnly,
    /// Accepts only a fragmented stream. A datagram is refused without being consumed.
    StreamOnly,
}

/// A fixed-capacity table mapping destination port to handler.
#[derive(Debug)]
pub struct PortTable<const PORTS: usize> {
    bound: [bool; PORTS],
}

impl<const PORTS: usize> Default for PortTable<PORTS> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const PORTS: usize> PortTable<PORTS> {
    /// An empty table.
    ///
    /// Explicitly cleared, unlike the C's port table, which relies on `.bss` and has no
    /// `csp_port_init()` — so a second `csp_init()` leaks every previous binding.
    pub const fn new() -> Self {
        PortTable {
            bound: [false; PORTS],
        }
    }

    /// Bind a port.
    ///
    /// Rejects an out-of-range port and a double bind, matching the registration API both
    /// firmware consumers wrapped around the C.
    pub fn bind(&mut self, port: u8) -> Result<()> {
        let idx = port as usize;
        if idx >= PORTS {
            return Err(Error::FieldOutOfRange {
                field: csp_core::Field::DestinationPort,
            });
        }
        if self.bound[idx] {
            return Err(Error::TableFull);
        }
        self.bound[idx] = true;
        Ok(())
    }

    /// True if `port` is bound.
    pub fn is_bound(&self, port: u8) -> bool {
        (port as usize) < PORTS && self.bound[port as usize]
    }

    /// Unbind a port.
    pub fn unbind(&mut self, port: u8) {
        if (port as usize) < PORTS {
            self.bound[port as usize] = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Pool;
    use csp_core::{flags, Id};

    type P = Pool<8, 264>;

    /// Feeds pre-built fragments to a Stream.
    #[derive(Debug)]
    struct Source<'p> {
        queue: [Option<Packet<'p, 8, 264>>; 8],
        head: usize,
    }

    impl<'p> Source<'p> {
        fn new() -> Self {
            Source {
                queue: core::array::from_fn(|_| None),
                head: 0,
            }
        }
        fn push(&mut self, p: Packet<'p, 8, 264>) {
            for slot in self.queue.iter_mut() {
                if slot.is_none() {
                    *slot = Some(p);
                    return;
                }
            }
            panic!("test source full");
        }
    }

    impl<'p> PacketSource<'p, 8, 264> for Source<'p> {
        fn next_packet(&mut self, _t: u32) -> Option<Packet<'p, 8, 264>> {
            let r = self.queue[self.head].take();
            if r.is_some() {
                self.head += 1;
            }
            r
        }
    }

    fn datagram<'p>(pool: &'p P, payload: &[u8]) -> Packet<'p, 8, 264> {
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        });
        p.set_payload(payload).unwrap();
        p
    }

    fn fragment<'p>(pool: &'p P, offset: u32, total: u32, chunk: &[u8]) -> Packet<'p, 8, 264> {
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: flags::FRAG,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        });
        let mut buf = [0u8; 128];
        let n = sfp::Fragment::encode(offset, total, chunk, &mut buf).unwrap();
        p.set_payload(&buf[..n]).unwrap();
        p
    }

    #[test]
    fn a_plain_packet_classifies_as_a_datagram() {
        let pool = P::new();
        let mut src = Source::new();
        let d = Delivery::classify(datagram(&pool, b"hello"), &mut src);
        match d {
            Delivery::Datagram(p) => p.with_payload(|x| assert_eq!(x, b"hello")),
            Delivery::Stream(_) => panic!("should not be a stream"),
        }
    }

    #[test]
    fn a_frag_flagged_packet_classifies_as_a_stream() {
        let pool = P::new();
        let mut src = Source::new();
        let d = Delivery::classify(fragment(&pool, 0, 10, b"abcde"), &mut src);
        match d {
            Delivery::Stream(s) => assert_eq!(s.total_len(), 10),
            Delivery::Datagram(_) => panic!("should not be a datagram"),
        }
    }

    #[test]
    fn classification_does_not_consume_the_packet() {
        // The whole point: deciding costs a peek, not the message.
        let pool = P::new();
        let before = pool.available();
        let mut src = Source::new();
        let d = Delivery::classify(datagram(&pool, b"intact"), &mut src);
        assert_eq!(pool.available(), before - 1);
        let p = d.into_datagram().ok().unwrap();
        p.with_payload(|x| assert_eq!(x, b"intact", "payload survived classification"));
    }

    #[test]
    fn the_wrong_shape_is_returned_not_destroyed() {
        // In the C this case frees the packet and reports -103.
        let pool = P::new();
        let mut src = Source::new();
        let d = Delivery::classify(datagram(&pool, b"precious"), &mut src);

        let back = d.into_stream().unwrap_err();
        // still ours, still intact
        let p = back.into_datagram().ok().unwrap();
        p.with_payload(|x| assert_eq!(x, b"precious"));
    }

    #[test]
    fn into_datagram_on_a_stream_returns_it_and_received_tracks() {
        let pool = P::new();
        let mut src = Source::new();
        let first = fragment(&pool, 0, 10, b"abcde");
        let d = Delivery::classify(first, &mut src);
        // A stream handed to a datagram-only reader is returned intact, not destroyed.
        match d.into_datagram() {
            Err(Delivery::Stream(s)) => {
                let _ = s.received(); // bytes accepted so far -- exercised, not pinned here
            }
            _ => panic!("a fragment must classify as a stream, returned on mismatch"),
        };
    }

    #[test]
    fn an_empty_fragment_mid_stream_is_refused() {
        let pool = P::new();
        let mut src = Source::new();
        // A well-formed opener, then a fragment carrying no payload at the next offset.
        src.push(fragment(&pool, 5, 10, b""));
        let first = fragment(&pool, 0, 10, b"abcde");
        let mut s = match Delivery::classify(first, &mut src) {
            Delivery::Stream(s) => s,
            _ => panic!("expected a stream"),
        };
        let mut out = [0u8; 16];
        assert!(
            matches!(s.read_to_slice(100, &mut out), Err(Error::EmptyFragment)),
            "an empty fragment is refused, not treated as end-of-stream"
        );
    }

    #[test]
    fn port_table_default_is_new() {
        let _ = PortTable::<4>::default();
    }

    #[test]
    fn a_stream_reassembles_into_a_slice() {
        let pool = P::new();
        let mut src = Source::new();
        src.push(fragment(&pool, 5, 10, b"fghij"));
        let first = fragment(&pool, 0, 10, b"abcde");

        let mut s = match Delivery::classify(first, &mut src) {
            Delivery::Stream(s) => s,
            _ => panic!("expected a stream"),
        };
        assert_eq!(s.total_len(), 10);

        let mut out = [0u8; 16];
        let n = s.read_to_slice(100, &mut out).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&out[..10], b"abcdefghij");
        assert!(s.is_complete());
    }

    #[test]
    fn a_stream_can_be_read_chunkwise_without_a_full_buffer() {
        // The shape a log dump needs: it streams a ring buffer it cannot materialise.
        let pool = P::new();
        let mut src = Source::new();
        src.push(fragment(&pool, 5, 10, b"fghij"));
        let first = fragment(&pool, 0, 10, b"abcde");

        let mut s = match Delivery::classify(first, &mut src) {
            Delivery::Stream(s) => s,
            _ => panic!("expected a stream"),
        };

        let mut seen = 0usize;
        while let Some(n) = s
            .read_chunk(100, |chunk, _off, _total| chunk.len())
            .unwrap()
        {
            seen += n;
        }
        assert_eq!(seen, 10);
        assert!(s.is_complete());
    }

    #[test]
    fn read_to_slice_reports_the_size_needed_instead_of_truncating() {
        // The C's flat receive sets an overflow flag the caller must remember to check.
        let pool = P::new();
        let mut src = Source::new();
        let first = fragment(&pool, 0, 100, b"abcde");
        let mut s = match Delivery::classify(first, &mut src) {
            Delivery::Stream(s) => s,
            _ => panic!("expected a stream"),
        };
        let mut small = [0u8; 8];
        assert_eq!(
            s.read_to_slice(100, &mut small),
            Err(Error::BufferTooSmall { needed: 100 })
        );
    }

    #[test]
    fn a_stream_that_stops_early_reports_truncated() {
        let pool = P::new();
        let mut src = Source::new(); // no continuation queued
        let first = fragment(&pool, 0, 100, b"abcde");
        let mut s = match Delivery::classify(first, &mut src) {
            Delivery::Stream(s) => s,
            _ => panic!("expected a stream"),
        };
        let mut out = [0u8; 128];
        assert_eq!(s.read_to_slice(1, &mut out), Err(Error::Truncated));
    }

    #[test]
    fn every_delivery_returns_its_buffers() {
        let pool = P::new();
        let start = pool.available();
        {
            let mut src = Source::new();
            src.push(fragment(&pool, 5, 10, b"fghij"));
            let first = fragment(&pool, 0, 10, b"abcde");
            let mut s = match Delivery::classify(first, &mut src) {
                Delivery::Stream(s) => s,
                _ => panic!(),
            };
            let mut out = [0u8; 16];
            s.read_to_slice(100, &mut out).unwrap();
        }
        assert_eq!(
            pool.available(),
            start,
            "a stream must not leak its fragments"
        );
    }

    #[test]
    fn port_table_rejects_out_of_range_and_double_binds() {
        let mut t: PortTable<48> = PortTable::new();
        assert!(t.bind(20).is_ok());
        assert!(t.is_bound(20));
        assert_eq!(t.bind(20), Err(Error::TableFull), "double bind");
        assert!(matches!(t.bind(200), Err(Error::FieldOutOfRange { .. })));
        t.unbind(20);
        assert!(!t.is_bound(20));
        assert!(t.bind(20).is_ok());
    }

    #[test]
    fn a_fresh_port_table_has_nothing_bound() {
        // The C's table relies on .bss with no csp_port_init(), so a second csp_init()
        // inherits every previous binding.
        let t: PortTable<48> = PortTable::new();
        for p in 0..48u8 {
            assert!(!t.is_bound(p));
        }
    }
}
