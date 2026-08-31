//! The packet buffer pool.
//!
//! This module is where the three properties that make libcsp's memory model
//! untranslatable all dissolve, and they dissolve together.
//!
//! | The C | Here |
//! |---|---|
//! | `frame_begin` is a pointer **into the packet's own array** (`packet->data - 4`), so moving a packet silently invalidates it and `csp_buffer_copy` has to recompute it after a `memcpy` | `frame_begin` is a `u16` **offset**. Moving is free and copying is exact |
//! | The free path uses `CONTAINER_OF` to walk **16 bytes backwards** from the pointer the user holds, to reach a refcount and a canary | The handle carries a **slot index**. There is nothing before it to walk to |
//! | The refcount is a plain `unsigned int`, incremented and decremented from ISR *and* task context with no synchronisation | `AtomicU8` |
//!
//! And the consequence that matters operationally: a [`Packet`] releases its slot on
//! `Drop`. The flight test suite contains a test whose entire purpose is catching handlers
//! that forget `csp_buffer_free` — it fires 100 undecodable requests at a port and checks
//! the pool afterwards, because in C a handler that returns early leaks one buffer per
//! request out of a pool of 64. That whole class of bug is unrepresentable here.

use core::cell::RefCell;
use core::sync::atomic::{AtomicU8, Ordering};

/// Scratch space reserved *before* the payload so a header can be prepended without
/// moving the payload. Matches `CSP_PACKET_PADDING_BYTES`.
pub const PADDING: usize = 8;

/// Per-slot storage: the padding, then the payload.
#[derive(Debug)]
struct Slot<const SZ: usize> {
    /// `PADDING` bytes of header scratch followed by `SZ` bytes of payload.
    bytes: [u8; SZ],
    /// Offset of the first frame byte within `bytes`. The header lives at
    /// `frame_begin .. PADDING`, the payload at `PADDING ..`.
    frame_begin: u16,
    /// Length of the framed bytes starting at `frame_begin`.
    frame_len: u16,
    /// Length of the payload.
    len: u16,
    /// The CSP header.
    id: csp_core::Id,
}

impl<const SZ: usize> Slot<SZ> {
    const fn new() -> Self {
        Slot {
            bytes: [0; SZ],
            frame_begin: PADDING as u16,
            frame_len: 0,
            len: 0,
            id: csp_core::Id {
                pri: 0,
                flags: 0,
                src: 0,
                dst: 0,
                dport: 0,
                sport: 0,
            },
        }
    }
}

/// A fixed-capacity packet pool.
///
/// `N` slots of `SZ` bytes each, where `SZ` must include [`PADDING`]. Lives in caller
/// storage — there is no allocator and no global.
#[derive(Debug)]
pub struct Pool<const N: usize, const SZ: usize> {
    slots: [RefCell<Slot<SZ>>; N],
    /// `0` means free. Atomic because a driver may free from an interrupt.
    refcounts: [AtomicU8; N],
}

impl<const N: usize, const SZ: usize> Default for Pool<N, SZ> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize, const SZ: usize> Pool<N, SZ> {
    /// Compile-time invariants. Violating either would be a bug in the caller's storage
    /// sizing, and both would otherwise fail at runtime in an obscure way: `SZ <= PADDING`
    /// makes `payload_capacity()` underflow to a huge number, and `N == 0` makes
    /// `acquire` always return `None` for no visible reason.
    const SANITY: () = {
        assert!(
            SZ > PADDING,
            "buffer size must exceed the header padding; see pool::PADDING"
        );
        assert!(N > 0, "a pool needs at least one buffer");
    };

    /// Create an empty pool.
    pub fn new() -> Self {
        let () = Self::SANITY;
        Pool {
            slots: core::array::from_fn(|_| RefCell::new(Slot::new())),
            refcounts: core::array::from_fn(|_| AtomicU8::new(0)),
        }
    }

    /// Total slots.
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Payload bytes per slot.
    pub const fn payload_capacity(&self) -> usize {
        SZ - PADDING
    }

    /// Slots currently free.
    pub fn available(&self) -> usize {
        self.refcounts
            .iter()
            .filter(|r| r.load(Ordering::Acquire) == 0)
            .count()
    }

    /// Rebuild a handle from an index produced by [`Packet::into_index`].
    ///
    /// Takes back the reference that `into_index` left outstanding, so the slot is
    /// released when the returned handle drops.
    ///
    /// Returns `None` for an index that is out of range or not currently allocated, so a
    /// corrupted queue entry cannot resurrect a freed slot.
    pub fn from_index(&self, idx: u16) -> Option<Packet<'_, N, SZ>> {
        let i = idx as usize;
        if i >= N || self.refcounts[i].load(Ordering::Acquire) == 0 {
            return None;
        }
        Some(Packet { pool: self, idx })
    }

    /// Take a slot, or `None` if the pool is exhausted.
    ///
    /// `reserve` keeps that many slots back, so a low-priority allocation cannot starve
    /// the acknowledgements that free the pool again. Matches `CSP_BUFFER_RESERVED_COUNT`.
    ///
    /// Unlike `csp_buffer_get_always`, there is no variant that panics and spins forever
    /// on exhaustion — the C's version calls `csp_panic` and then `while(1)`, and the
    /// default `csp_panic` just returns, so the real behaviour is a silent hang.
    pub fn acquire(&self, reserve: usize) -> Option<Packet<'_, N, SZ>> {
        if self.available() <= reserve {
            return None;
        }
        for (i, rc) in self.refcounts.iter().enumerate() {
            if rc
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // Only one Packet can exist per slot, so this borrow cannot fail.
                let mut s = self.slots[i].borrow_mut();
                *s = Slot::new();
                drop(s);
                return Some(Packet {
                    pool: self,
                    idx: i as u16,
                });
            }
        }
        None
    }
}

/// An owned handle to one pool slot.
///
/// Releases the slot on `Drop`. There is no way to leak one short of `mem::forget`, and no
/// way to free one twice.
#[derive(Debug)]
pub struct Packet<'p, const N: usize, const SZ: usize> {
    pool: &'p Pool<N, SZ>,
    idx: u16,
}

impl<'p, const N: usize, const SZ: usize> Packet<'p, N, SZ> {
    /// The CSP header.
    pub fn id(&self) -> csp_core::Id {
        self.pool.slots[self.idx as usize].borrow().id
    }

    /// Set the CSP header.
    pub fn set_id(&mut self, id: csp_core::Id) {
        self.pool.slots[self.idx as usize].borrow_mut().id = id;
    }

    /// Payload length.
    pub fn len(&self) -> usize {
        self.pool.slots[self.idx as usize].borrow().len as usize
    }

    /// True if the payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Largest payload this packet can hold.
    pub const fn capacity(&self) -> usize {
        SZ - PADDING
    }

    /// Copy `data` into the payload.
    pub fn set_payload(&mut self, data: &[u8]) -> csp_core::Result<()> {
        if data.len() > self.capacity() {
            return Err(csp_core::Error::BufferTooSmall {
                needed: data.len() + PADDING,
            });
        }
        let mut s = self.pool.slots[self.idx as usize].borrow_mut();
        s.bytes[PADDING..PADDING + data.len()].copy_from_slice(data);
        s.len = data.len() as u16;
        Ok(())
    }

    /// Read the payload.
    pub fn with_payload<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        let s = self.pool.slots[self.idx as usize].borrow();
        f(&s.bytes[PADDING..PADDING + s.len as usize])
    }

    /// Mutate the payload in place, setting its new length.
    pub fn with_payload_mut<R>(&mut self, f: impl FnOnce(&mut [u8]) -> (usize, R)) -> R {
        let mut s = self.pool.slots[self.idx as usize].borrow_mut();
        let cap = SZ - PADDING;
        let (n, r) = f(&mut s.bytes[PADDING..PADDING + cap]);
        s.len = core::cmp::min(n, cap) as u16;
        r
    }

    /// Encode `id` into the padding immediately before the payload, producing a frame.
    ///
    /// This is `csp_id_prepend`, minus the interior pointer: it records an **offset**.
    /// Note that a `nexthop` is handed an unframed packet — prepending is the interface's
    /// job, which is easy to miss and produces zero-length frames when it is.
    pub fn prepend_header(&mut self, version: csp_core::Version) -> csp_core::Result<()> {
        let hdr = version.header_size();
        let id = self.id();
        let mut s = self.pool.slots[self.idx as usize].borrow_mut();
        let begin = PADDING - hdr;
        let mut tmp = [0u8; 8];
        id.encode(version, &mut tmp)?;
        s.bytes[begin..PADDING].copy_from_slice(&tmp[..hdr]);
        s.frame_begin = begin as u16;
        s.frame_len = (hdr + s.len as usize) as u16;
        Ok(())
    }

    /// Read the framed bytes — header followed by payload.
    ///
    /// Empty until [`Packet::prepend_header`] has run.
    pub fn with_frame<R>(&self, f: impl FnOnce(&[u8]) -> R) -> R {
        let s = self.pool.slots[self.idx as usize].borrow();
        let b = s.frame_begin as usize;
        f(&s.bytes[b..b + s.frame_len as usize])
    }

    /// Build a packet from received frame bytes: decode the header, keep the payload.
    pub fn set_frame(&mut self, version: csp_core::Version, frame: &[u8]) -> csp_core::Result<()> {
        let hdr = version.header_size();
        if frame.len() < hdr {
            return Err(csp_core::Error::Truncated);
        }
        let id = csp_core::Id::decode(version, frame)?;
        let payload = &frame[hdr..];
        if payload.len() > self.capacity() {
            return Err(csp_core::Error::BufferTooSmall {
                needed: payload.len() + PADDING,
            });
        }
        self.set_id(id);
        self.set_payload(payload)
    }

    /// Give up the handle without releasing the slot, yielding its index.
    ///
    /// This is how a packet is put into a queue. A queue cannot hold [`Packet`] handles:
    /// they borrow the pool, and the pool lives in the same storage the queue does, so
    /// storing one would make the storage self-referential. Holding an index sidesteps
    /// that entirely.
    ///
    /// The reference count is **not** decremented, so the slot stays live. Every
    /// `into_index` must be paired with a [`Pool::from_index`] or the slot leaks — the
    /// one place in this crate where a leak is expressible, and it is contained to the
    /// queue implementations.
    pub fn into_index(self) -> u16 {
        let idx = self.idx;
        core::mem::forget(self);
        idx
    }

    /// Take another reference to the same slot.
    ///
    /// Both handles must be dropped before the slot returns to the pool.
    ///
    /// `csp_buffer_refc_inc`'s counterpart. **Nothing in this crate calls it**: the
    /// promiscuous tap `deep_copy`s instead (which is why `promisc::read_transfers_ownership`
    /// measures the tapped packet as a distinct buffer), so the refcount never exceeds 1
    /// inside the port. Sharing a slot is something an application does, deliberately.
    pub fn add_ref(&self) -> Packet<'p, N, SZ> {
        self.pool.refcounts[self.idx as usize].fetch_add(1, Ordering::AcqRel);
        Packet {
            pool: self.pool,
            idx: self.idx,
        }
    }

    /// Copy this packet into a fresh slot.
    ///
    /// A real copy, not a second reference. `csp_buffer_clone` copies a partial struct and
    /// leaves the clone carrying the source's stale `next` and `conn` pointers — nothing
    /// clears them. Here there is nothing to leave stale.
    pub fn deep_copy(&self) -> Option<Packet<'p, N, SZ>> {
        let mut new = self.pool.acquire(0)?;
        let src = self.pool.slots[self.idx as usize].borrow();
        {
            let mut dst = self.pool.slots[new.idx as usize].borrow_mut();
            dst.bytes = src.bytes;
            dst.frame_begin = src.frame_begin;
            dst.frame_len = src.frame_len;
            dst.len = src.len;
            dst.id = src.id;
        }
        new.set_id(src.id);
        Some(new)
    }
}

impl<const N: usize, const SZ: usize> Drop for Packet<'_, N, SZ> {
    fn drop(&mut self) {
        // Releases on the last reference. The C sets an *error* code on this perfectly
        // normal "still referenced" path.
        self.pool.refcounts[self.idx as usize].fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use csp_core::{Id, Version};

    type P = Pool<4, 264>;

    #[test]
    fn default_and_accessors_and_oversized_frame() {
        let pool = P::default();
        assert_eq!(pool.payload_capacity(), 264 - PADDING);
        let mut p = pool.acquire(0).expect("a slot");
        assert!(p.is_empty(), "a fresh packet has no payload");
        p.set_payload(&[1, 2, 3]).unwrap();
        assert!(!p.is_empty());
        // A frame whose payload cannot fit the slot is refused, not truncated.
        let frame = [0u8; Version::V2 as usize + 6 + 300];
        assert!(matches!(
            p.set_frame(Version::V2, &frame),
            Err(csp_core::Error::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn acquire_and_release_are_balanced() {
        let pool = P::new();
        assert_eq!(pool.available(), 4);
        {
            let _a = pool.acquire(0).unwrap();
            assert_eq!(pool.available(), 3);
            let _b = pool.acquire(0).unwrap();
            assert_eq!(pool.available(), 2);
        }
        assert_eq!(pool.available(), 4, "both must return on drop");
    }

    #[test]
    fn exhaustion_returns_none_rather_than_hanging() {
        // csp_buffer_get_always calls csp_panic then while(1), and the default csp_panic
        // returns -- so the C's real behaviour on exhaustion is a silent hang.
        let pool = P::new();
        let _held: [_; 4] = core::array::from_fn(|_| pool.acquire(0).unwrap());
        assert!(pool.acquire(0).is_none());
    }

    #[test]
    fn the_reserve_keeps_slots_back() {
        let pool = P::new();
        let _a = pool.acquire(0).unwrap();
        let _b = pool.acquire(0).unwrap();
        // 2 left, reserve 2 => refuse
        assert!(pool.acquire(2).is_none());
        assert!(pool.acquire(1).is_some());
    }

    #[test]
    fn a_leak_is_unrepresentable() {
        // This is the test hw_tests/tests/csp/test_csp_robustness.py exists to do in C:
        // fire many requests at a handler that returns early, then check the pool.
        let pool = P::new();
        for _ in 0..1000 {
            let p = pool.acquire(0).unwrap();
            // a handler that "forgets to free" simply returns
            let _ = p.id();
        }
        assert_eq!(pool.available(), 4, "no handler can leak a buffer");
    }

    #[test]
    fn payload_roundtrip() {
        let pool = P::new();
        let mut p = pool.acquire(0).unwrap();
        p.set_payload(b"hello").unwrap();
        assert_eq!(p.len(), 5);
        p.with_payload(|d| assert_eq!(d, b"hello"));
    }

    #[test]
    fn an_oversized_payload_is_refused_with_the_size_needed() {
        let pool = P::new();
        let mut p = pool.acquire(0).unwrap();
        let big = [0u8; 300];
        assert_eq!(
            p.set_payload(&big),
            Err(csp_core::Error::BufferTooSmall { needed: 308 })
        );
    }

    #[test]
    fn header_is_prepended_into_the_padding_not_over_the_payload() {
        let pool = P::new();
        for version in [Version::V1, Version::V2] {
            let mut p = pool.acquire(0).unwrap();
            p.set_id(Id {
                pri: 2,
                flags: 0,
                src: 1,
                dst: 8,
                dport: 20,
                sport: 10,
            });
            p.set_payload(b"payload").unwrap();
            p.prepend_header(version).unwrap();

            p.with_frame(|f| {
                assert_eq!(f.len(), version.header_size() + 7);
                assert_eq!(&f[version.header_size()..], b"payload");
                assert_eq!(
                    Id::decode(version, f).unwrap(),
                    Id {
                        pri: 2,
                        flags: 0,
                        src: 1,
                        dst: 8,
                        dport: 20,
                        sport: 10
                    }
                );
            });
            // the payload is still readable unchanged
            p.with_payload(|d| assert_eq!(d, b"payload"));
        }
    }

    #[test]
    fn frame_is_empty_until_the_header_is_prepended() {
        // A nexthop is handed an UNFRAMED packet; forgetting to prepend produces a
        // zero-length frame rather than a wrong one.
        let pool = P::new();
        let mut p = pool.acquire(0).unwrap();
        p.set_payload(b"x").unwrap();
        p.with_frame(|f| assert!(f.is_empty()));
    }

    #[test]
    fn set_frame_decodes_a_received_frame() {
        let pool = P::new();
        let id = Id {
            pri: 1,
            flags: 0x10,
            src: 3,
            dst: 9,
            dport: 7,
            sport: 11,
        };
        let mut src = pool.acquire(0).unwrap();
        src.set_id(id);
        src.set_payload(b"received").unwrap();
        src.prepend_header(Version::V1).unwrap();

        let mut frame = [0u8; 64];
        let n = src.with_frame(|f| {
            frame[..f.len()].copy_from_slice(f);
            f.len()
        });

        let mut dst = pool.acquire(0).unwrap();
        dst.set_frame(Version::V1, &frame[..n]).unwrap();
        assert_eq!(dst.id(), id);
        dst.with_payload(|d| assert_eq!(d, b"received"));
    }

    #[test]
    fn set_frame_refuses_a_frame_shorter_than_its_header() {
        let pool = P::new();
        let mut p = pool.acquire(0).unwrap();
        assert_eq!(
            p.set_frame(Version::V2, &[0u8; 5]),
            Err(csp_core::Error::Truncated)
        );
    }

    #[test]
    fn add_ref_holds_the_slot_until_both_are_dropped() {
        let pool = P::new();
        assert_eq!(pool.available(), 4);
        let a = pool.acquire(0).unwrap();
        let b = a.add_ref();
        assert_eq!(pool.available(), 3);
        drop(a);
        assert_eq!(pool.available(), 3, "still referenced");
        drop(b);
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn deep_copy_is_independent_of_its_source() {
        // csp_buffer_clone copies a partial struct and leaves the clone carrying the
        // source's stale next/conn pointers.
        let pool = P::new();
        let mut a = pool.acquire(0).unwrap();
        a.set_id(Id {
            pri: 1,
            flags: 0,
            src: 1,
            dst: 2,
            dport: 3,
            sport: 4,
        });
        a.set_payload(b"original").unwrap();

        let mut b = a.deep_copy().unwrap();
        assert_eq!(b.id(), a.id());
        b.with_payload(|d| assert_eq!(d, b"original"));

        b.set_payload(b"changed").unwrap();
        a.with_payload(|d| assert_eq!(d, b"original", "source must be untouched"));
        assert_eq!(pool.available(), 2, "a copy consumes a second slot");
    }

    #[test]
    fn deep_copy_fails_cleanly_when_the_pool_is_empty() {
        let pool = P::new();
        let a = pool.acquire(0).unwrap();
        let _rest: [_; 3] = core::array::from_fn(|_| pool.acquire(0).unwrap());
        assert!(a.deep_copy().is_none());
    }

    #[test]
    fn a_reused_slot_starts_clean() {
        // csp_buffer_get is expected to hand back a zeroed packet; libcsp issue #734 was
        // that it did not.
        let pool = P::new();
        {
            let mut p = pool.acquire(0).unwrap();
            p.set_payload(b"secrets").unwrap();
            p.set_id(Id {
                pri: 3,
                flags: 0xff,
                src: 9,
                dst: 9,
                dport: 9,
                sport: 9,
            });
        }
        let p = pool.acquire(0).unwrap();
        assert_eq!(p.len(), 0);
        assert_eq!(p.id(), Id::default());
        p.with_frame(|f| assert!(f.is_empty()));
    }

    #[test]
    fn deep_copy_preserves_the_frame() {
        // libcsp unittests/buffer.c::test_clone_frame_begin_fixed. In the C, frame_begin
        // is a POINTER into the packet's own array, so csp_buffer_copy has to recompute it
        // after the memcpy -- get that wrong and the clone's frame points into the source.
        // Here it is an offset, so the copy is exact by construction; this pins it anyway.
        let pool = P::new();
        for version in [Version::V1, Version::V2] {
            let mut src = pool.acquire(0).unwrap();
            src.set_id(Id {
                pri: 2,
                flags: 0,
                src: 1,
                dst: 8,
                dport: 20,
                sport: 10,
            });
            src.set_payload(b"hello").unwrap();
            src.prepend_header(version).unwrap();

            let mut clone = src.deep_copy().unwrap();
            let mut sf = [0u8; 32];
            let sn = src.with_frame(|f| {
                sf[..f.len()].copy_from_slice(f);
                f.len()
            });
            clone.with_frame(|cf| {
                assert_eq!(cf, &sf[..sn], "{version:?}: the clone's frame must match");
            });

            // Modifying the source must not touch the clone.
            src.set_payload(b"world").unwrap();
            clone.with_payload(|d| assert_eq!(d, b"hello", "{version:?}: clone is independent"));

            // And the clone's frame is still its own.
            clone.set_payload(b"third").unwrap();
            src.with_payload(|d| assert_eq!(d, b"world"));
        }
    }

    #[test]
    fn every_slot_comes_back_clean_after_carrying_data() {
        // libcsp issue #734, ported: fill every buffer with distinct data, free them all,
        // then re-acquire and check nothing survived. A reused buffer that still holds the
        // previous packet leaks it into whatever is sent next.
        let pool = P::new();
        for round in 0..3u8 {
            {
                let mut held: [Option<Packet<'_, 4, 264>>; 4] = core::array::from_fn(|_| None);
                for (i, slot) in held.iter_mut().enumerate() {
                    let mut p = pool.acquire(0).unwrap();
                    p.set_payload(&[0xA0 + i as u8 + round; 32]).unwrap();
                    // 0x3f, not 0xff: v2 flags are six bits, and encode refuses an
                    // oversized value rather than shifting it into the next field.
                    p.set_id(Id {
                        pri: 3,
                        flags: 0x3f,
                        src: 9,
                        dst: 9,
                        dport: 9,
                        sport: 9,
                    });
                    p.prepend_header(Version::V2).unwrap();
                    *slot = Some(p);
                }
            } // every one released here

            let checked: [Option<Packet<'_, 4, 264>>; 4] = core::array::from_fn(|_| {
                let p = pool.acquire(0).unwrap();
                assert_eq!(p.len(), 0, "round {round}: length must reset");
                assert_eq!(p.id(), Id::default(), "round {round}: header must reset");
                p.with_frame(|f| assert!(f.is_empty(), "round {round}: frame must reset"));
                Some(p)
            });
            drop(checked);
            assert_eq!(pool.available(), 4, "round {round}: all returned");
        }
    }

    #[test]
    fn a_reference_and_a_copy_are_different_things() {
        // add_ref shares the slot; deep_copy takes a new one. Confusing the two is how a
        // "clone" ends up aliasing its source.
        let pool = P::new();
        let mut a = pool.acquire(0).unwrap();
        a.set_payload(b"original").unwrap();

        let shared = a.add_ref();
        let copied = a.deep_copy().unwrap();
        assert_eq!(pool.available(), 2, "one shared slot, one new one");

        a.set_payload(b"mutated!").unwrap();
        shared.with_payload(|d| assert_eq!(d, b"mutated!", "a reference sees the change"));
        copied.with_payload(|d| assert_eq!(d, b"original", "a copy does not"));
    }

    #[test]
    fn two_pools_are_completely_independent() {
        let a = P::new();
        let b = P::new();
        let _held: [_; 4] = core::array::from_fn(|_| a.acquire(0).unwrap());
        assert_eq!(a.available(), 0);
        assert_eq!(b.available(), 4, "a second pool is unaffected");
        assert!(b.acquire(0).is_some());
    }
}
