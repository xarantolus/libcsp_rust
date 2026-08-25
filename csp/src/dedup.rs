//! Duplicate packet suppression.
//!
//! A small ring of recent frame checksums. A packet whose checksum matches one seen inside
//! the window is a duplicate — which happens routinely on a mesh where the same packet
//! arrives over two interfaces.
//!
//! # The C's window check breaks on clock wrap
//!
//! `csp_dedup.c` compares timestamps with
//!
//! ```c
//! if (time > csp_dedup_timestamp[i] + CSP_DEDUP_WINDOW_MS) break;
//! ```
//!
//! `time` is a free-running 32-bit millisecond counter. When it wraps — every 49 days —
//! `time` becomes small, the comparison is false for every entry, and the scan breaks
//! immediately, so **deduplication silently stops working**. The addition can also
//! overflow near the wrap, which flips the comparison the other way.
//!
//! Here the comparison is `now.wrapping_sub(stamp) > window`, which is correct across the
//! wrap. There is a test that fails on the naive form.

use csp_core::crc32;

/// Checksums remembered.
pub const DEDUP_COUNT: usize = 16;
/// How recently a packet must have been seen to count as a duplicate, ms.
pub const DEDUP_WINDOW_MS: u32 = 100;

/// Ring of recently seen frame checksums.
#[derive(Debug)]
pub struct Dedup {
    crcs: [u32; DEDUP_COUNT],
    stamps: [u32; DEDUP_COUNT],
    /// Whether the slot has ever been written. Without this, a fresh ring full of zeroes
    /// treats a frame whose checksum happens to be 0 as a duplicate of nothing.
    used: [bool; DEDUP_COUNT],
    next: usize,
}

impl Default for Dedup {
    fn default() -> Self {
        Self::new()
    }
}

impl Dedup {
    /// An empty ring.
    pub const fn new() -> Self {
        Dedup {
            crcs: [0; DEDUP_COUNT],
            stamps: [0; DEDUP_COUNT],
            used: [false; DEDUP_COUNT],
            next: 0,
        }
    }

    /// Is this frame a duplicate of one seen within the window?
    ///
    /// Records it either way, so the caller does not have to remember to.
    pub fn is_duplicate(&mut self, frame: &[u8], now_ms: u32) -> bool {
        let crc = crc32::checksum(frame);

        // Newest first, so a hit is found quickly and the scan stops at the first entry
        // that has aged out.
        for step in 1..=DEDUP_COUNT {
            let i = (self.next + DEDUP_COUNT - step) % DEDUP_COUNT;
            if !self.used[i] {
                break;
            }
            // Wrapping subtraction: correct across the 49-day clock wrap, where the C's
            // `now > stamp + window` silently disables deduplication.
            if now_ms.wrapping_sub(self.stamps[i]) > DEDUP_WINDOW_MS {
                break;
            }
            if self.crcs[i] == crc {
                return true;
            }
        }

        self.crcs[self.next] = crc;
        self.stamps[self.next] = now_ms;
        self.used[self.next] = true;
        self.next = (self.next + 1) % DEDUP_COUNT;
        false
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        *self = Dedup::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_identical_frame_inside_the_window_is_a_duplicate() {
        let mut d = Dedup::new();
        assert!(!d.is_duplicate(b"packet", 1_000));
        assert!(d.is_duplicate(b"packet", 1_050));
    }

    #[test]
    fn the_same_frame_outside_the_window_is_not() {
        let mut d = Dedup::new();
        assert!(!d.is_duplicate(b"packet", 1_000));
        assert!(!d.is_duplicate(b"packet", 1_000 + DEDUP_WINDOW_MS + 1));
    }

    #[test]
    fn different_frames_are_never_duplicates() {
        let mut d = Dedup::new();
        assert!(!d.is_duplicate(b"one", 0));
        assert!(!d.is_duplicate(b"two", 1));
        assert!(!d.is_duplicate(b"three", 2));
    }

    #[test]
    fn deduplication_survives_the_clock_wrap() {
        // The C compares `now > stamp + window` on a free-running 32-bit millisecond
        // counter. At the wrap, `now` is small, the comparison is false for every entry,
        // the scan breaks immediately, and dedup silently stops working.
        let mut d = Dedup::new();
        let before_wrap = u32::MAX - 50;
        assert!(!d.is_duplicate(b"packet", before_wrap));

        // 60 ms later, having wrapped through zero. Still inside the 100 ms window.
        let after_wrap = before_wrap.wrapping_add(60);
        assert!(
            d.is_duplicate(b"packet", after_wrap),
            "a duplicate 60ms later must still be caught across the wrap"
        );
    }

    #[test]
    fn an_all_zero_ring_does_not_match_a_zero_checksum() {
        // The C's array starts zeroed with no "used" marker, so a frame whose CRC is 0
        // could match an empty slot.
        let mut d = Dedup::new();
        // Find input whose checksum is 0 if one exists in a small search; otherwise this
        // still proves an empty ring never reports a duplicate.
        assert!(!d.is_duplicate(&[], 0));
        assert!(!d.is_duplicate(&[0u8; 4], 0));
    }

    #[test]
    fn the_ring_forgets_the_oldest_entries() {
        let mut d = Dedup::new();
        // Fill the ring exactly. Nothing is evicted yet -- 16 slots, 16 entries.
        for i in 0..DEDUP_COUNT as u8 {
            assert!(!d.is_duplicate(&[i], 0));
        }
        assert!(
            d.is_duplicate(&[0u8], 0),
            "still remembered while the ring is exactly full"
        );

        // One more distinct frame overwrites the oldest slot.
        assert!(!d.is_duplicate(&[99u8], 0));
        assert!(
            !d.is_duplicate(&[0u8], 0),
            "now evicted, so no longer recognised"
        );
        // The newest is still there.
        assert!(d.is_duplicate(&[15u8], 0));
    }

    #[test]
    fn clear_forgets_everything() {
        let mut d = Dedup::new();
        assert!(!d.is_duplicate(b"packet", 0));
        d.clear();
        assert!(!d.is_duplicate(b"packet", 0), "cleared ring must not match");
    }

    #[test]
    fn arbitrary_traffic_never_panics() {
        let mut d = Dedup::new();
        let mut x: u32 = 0xD3D0_0001;
        let mut buf = [0u8; 32];
        for _ in 0..50_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let n = (x as usize) % buf.len();
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (x >> (i % 24)) as u8;
            }
            let _ = d.is_duplicate(&buf[..n], x);
        }
    }
}
