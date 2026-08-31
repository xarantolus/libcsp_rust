//! The router input queue.
//!
//! Interfaces push received packets here; the router pops them. A fixed-capacity ring of
//! *slot indices*, not packet handles — see [`Packet::into_index`](crate::Packet::into_index)
//! for why.
//!
//! # Full means dropped, and counted
//!
//! `csp_qfifo_write` frees the packet when the queue is full and bumps a counter. Same
//! here, except the drop is explicit and [`Qfifo::dropped`] is a real number rather than a
//! `uint8_t` global that wraps at 256 and is written from two contexts without
//! synchronisation.

use crate::pool::{Packet, Pool};

/// One queued arrival: a packet, and which interface it came in on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    idx: u16,
    iface: u8,
}

/// Fixed-capacity router input queue.
#[derive(Debug)]
pub struct Qfifo<const N: usize> {
    ring: [Option<Entry>; N],
    head: usize,
    tail: usize,
    len: usize,
    dropped: u32,
}

impl<const N: usize> Default for Qfifo<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Qfifo<N> {
    /// Compile-time invariant: the ring indexes modulo `N`, so a zero-length queue would
    /// divide by zero on the first push.
    const SANITY: () = assert!(N > 0, "the router queue needs at least one slot");

    /// An empty queue.
    pub const fn new() -> Self {
        let () = Self::SANITY;
        Qfifo {
            ring: [None; N],
            head: 0,
            tail: 0,
            len: 0,
            dropped: 0,
        }
    }

    /// Packets waiting.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True if nothing is waiting.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Packets dropped because the queue was full.
    ///
    /// A rising count here is the signature of a router that cannot keep up — the failure
    /// mode that looks like packet loss on a link that is actually fine.
    pub const fn dropped(&self) -> u32 {
        self.dropped
    }

    /// Enqueue a received packet.
    ///
    /// Takes ownership. On a full queue the packet is **released** and [`Qfifo::dropped`]
    /// increments; it is never silently retained.
    pub fn push<const B: usize, const SZ: usize>(
        &mut self,
        packet: Packet<'_, B, SZ>,
        iface: u8,
    ) -> bool {
        if self.len == N {
            self.dropped += 1;
            drop(packet); // explicit: this is the C's free-on-full path
            return false;
        }
        self.ring[self.tail] = Some(Entry {
            idx: packet.into_index(),
            iface,
        });
        self.tail = (self.tail + 1) % N;
        self.len += 1;
        true
    }

    /// Dequeue the oldest packet, if any.
    pub fn pop<'p, const B: usize, const SZ: usize>(
        &mut self,
        pool: &'p Pool<B, SZ>,
    ) -> Option<(Packet<'p, B, SZ>, u8)> {
        if self.len == 0 {
            return None;
        }
        let e = self.ring[self.head].take()?;
        self.head = (self.head + 1) % N;
        self.len -= 1;
        // A stale index cannot resurrect a freed slot: from_index refuses it.
        pool.from_index(e.idx).map(|p| (p, e.iface))
    }

    /// Release everything queued.
    ///
    /// Needed on shutdown: without it every queued packet leaks, because the queue holds
    /// raw indices rather than handles.
    pub fn drain<const B: usize, const SZ: usize>(&mut self, pool: &Pool<B, SZ>) {
        while self.pop(pool).is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_new() {
        let _ = Qfifo::<4>::default();
    }

    type P = Pool<8, 264>;

    fn packet(pool: &P) -> Packet<'_, 8, 264> {
        let mut p = pool.acquire(0).unwrap();
        p.set_payload(b"x").unwrap();
        p
    }

    #[test]
    fn fifo_order_is_preserved() {
        let pool = P::new();
        let mut q: Qfifo<4> = Qfifo::new();
        for i in 0..3u8 {
            let mut p = pool.acquire(0).unwrap();
            p.set_payload(&[i]).unwrap();
            assert!(q.push(p, i));
        }
        for i in 0..3u8 {
            let (p, iface) = q.pop(&pool).unwrap();
            assert_eq!(iface, i);
            p.with_payload(|d| assert_eq!(d, &[i]));
        }
        assert!(q.pop(&pool).is_none());
    }

    #[test]
    fn queued_packets_hold_their_slots() {
        let pool = P::new();
        let mut q: Qfifo<4> = Qfifo::new();
        let before = pool.available();
        q.push(packet(&pool), 0);
        assert_eq!(
            pool.available(),
            before - 1,
            "a queued packet is still allocated"
        );
        let (p, _) = q.pop(&pool).unwrap();
        drop(p);
        assert_eq!(pool.available(), before);
    }

    #[test]
    fn a_full_queue_drops_and_counts_rather_than_retaining() {
        let pool = P::new();
        let mut q: Qfifo<2> = Qfifo::new();
        assert!(q.push(packet(&pool), 0));
        assert!(q.push(packet(&pool), 0));
        let before = pool.available();
        assert!(!q.push(packet(&pool), 0), "third must be refused");
        assert_eq!(q.dropped(), 1);
        assert_eq!(
            pool.available(),
            before,
            "the dropped packet must be released, not leaked"
        );
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn the_ring_wraps_without_losing_packets() {
        let pool = P::new();
        let mut q: Qfifo<3> = Qfifo::new();
        for round in 0..10u8 {
            let mut p = pool.acquire(0).unwrap();
            p.set_payload(&[round]).unwrap();
            assert!(q.push(p, round));
            let (got, iface) = q.pop(&pool).unwrap();
            assert_eq!(iface, round, "round {round}");
            got.with_payload(|d| assert_eq!(d, &[round]));
        }
        assert!(q.is_empty());
        assert_eq!(pool.available(), 8, "nothing leaked across 10 wraps");
    }

    #[test]
    fn drain_releases_everything() {
        // Without this, shutting down with a non-empty queue leaks every packet in it,
        // because the queue holds indices rather than handles.
        let pool = P::new();
        let mut q: Qfifo<4> = Qfifo::new();
        for _ in 0..4 {
            q.push(packet(&pool), 0);
        }
        assert_eq!(pool.available(), 4);
        q.drain(&pool);
        assert_eq!(pool.available(), 8);
        assert!(q.is_empty());
    }

    #[test]
    fn a_stale_index_cannot_resurrect_a_freed_slot() {
        let pool = P::new();
        let idx = {
            let p = pool.acquire(0).unwrap();
            p.into_index()
        };
        // Reclaim once: valid, and releases the slot.
        assert!(pool.from_index(idx).is_some());
        // Now the slot is free; reclaiming again must refuse.
        assert!(
            pool.from_index(idx).is_none(),
            "a freed slot must not be reclaimable"
        );
        assert!(pool.from_index(9999).is_none(), "out of range");
    }
}
