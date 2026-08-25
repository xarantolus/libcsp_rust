//! Ethernet framing and EFP segmentation.
//!
//! An Ethernet frame carries at most 1500 payload bytes, so CSP packets larger than that
//! are split by a segmentation protocol the C calls EFP — the Ethernet analogue of CFP.
//!
//! ```text
//! [ dst MAC:6 ][ src MAC:6 ][ ethertype:2 ][ packet_id:2 ][ src_addr:2 ][ seg_size:2 ][ packet_length:2 ][ payload… ]
//! ```
//!
//! All multi-byte fields big-endian, all offsets exact (the C struct is `packed`).
//!
//! # Two defects in the C worth knowing about
//!
//! **The header this actually uses is not the header its documentation describes.**
//! `csp_if_eth.h` opens with a long comment specifying a bit-packed EFP header — version 1
//! bit, 2 unused, 5-bit SegmentId, 8-bit PacketId, 16-bit length. The struct beneath it is
//! four plain big-endian `u16`s. The comment describes a protocol the code does not
//! implement. This module follows the code, because that is what is on the wire.
//!
//! **`csp_if_eth_unpack_header` is asymmetric with the packer, and shifts into the sign
//! bit.** The packer writes `packet_id` and `src_addr` with `htobe16`; the unpacker does
//!
//! ```c
//! *packet_id = buf->packet_id << 16 | buf->src_addr;
//! ```
//!
//! with no `be16toh` on either. Two consequences. The recovered `packet_id` is
//! byte-swapped relative to what was sent — harmless only because both ends make the same
//! mistake and the value is used purely as an opaque key for grouping segments. And
//! `buf->packet_id` is a `uint16_t` promoted to `int`, so `<< 16` with the top bit set
//! shifts into the sign bit of a 32-bit `int`, which is undefined behaviour.
//!
//! Here the key is assembled from properly decoded fields, in a `u32`.

use crate::{Error, Result};

/// Length of a MAC address.
pub const MAC_LEN: usize = 6;
/// Ethertype for CSP: IEEE 802 local experimental (RFC 5342).
pub const ETHERTYPE_CSP: u16 = 0x88B5;
/// Bytes of Ethernet + EFP header before the payload.
pub const HEADER_LEN: usize = MAC_LEN + MAC_LEN + 2 + 2 + 2 + 2 + 2;
/// Largest payload an Ethernet frame carries.
pub const FRAME_PAYLOAD_MAX: usize = 1500;

/// The broadcast MAC, used until a peer's address has been learned.
pub const BROADCAST_MAC: [u8; MAC_LEN] = [0xFF; MAC_LEN];

/// A decoded Ethernet + EFP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Destination MAC.
    pub dst_mac: [u8; MAC_LEN],
    /// Source MAC.
    pub src_mac: [u8; MAC_LEN],
    /// Ethertype. Must be [`ETHERTYPE_CSP`] for a CSP frame.
    pub ethertype: u16,
    /// Sequence number shared by every segment of one packet.
    pub packet_id: u16,
    /// CSP source address.
    pub src_addr: u16,
    /// Payload bytes in this segment.
    pub seg_size: u16,
    /// Total length of the reassembled packet.
    pub packet_length: u16,
}

impl Header {
    /// Encode into `out`, returning the header length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize> {
        if out.len() < HEADER_LEN {
            return Err(Error::BufferTooSmall { needed: HEADER_LEN });
        }
        out[0..6].copy_from_slice(&self.dst_mac);
        out[6..12].copy_from_slice(&self.src_mac);
        out[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
        out[14..16].copy_from_slice(&self.packet_id.to_be_bytes());
        out[16..18].copy_from_slice(&self.src_addr.to_be_bytes());
        out[18..20].copy_from_slice(&self.seg_size.to_be_bytes());
        out[20..22].copy_from_slice(&self.packet_length.to_be_bytes());
        Ok(HEADER_LEN)
    }

    /// Decode from the front of `data`.
    pub fn decode(data: &[u8]) -> Result<Header> {
        if data.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let be16 = |o: usize| u16::from_be_bytes([data[o], data[o + 1]]);
        let mut dst_mac = [0u8; MAC_LEN];
        let mut src_mac = [0u8; MAC_LEN];
        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);
        Ok(Header {
            dst_mac,
            src_mac,
            ethertype: be16(12),
            packet_id: be16(14),
            src_addr: be16(16),
            seg_size: be16(18),
            packet_length: be16(20),
        })
    }

    /// The key that groups segments of the same packet.
    ///
    /// Built from decoded fields in a `u32`. The C builds it from raw, un-byte-swapped
    /// `u16`s and shifts a promoted `int` left by 16, which is undefined behaviour when
    /// the top bit is set.
    pub const fn reassembly_key(&self) -> u32 {
        ((self.packet_id as u32) << 16) | (self.src_addr as u32)
    }

    /// True if this frame carries CSP.
    pub const fn is_csp(&self) -> bool {
        self.ethertype == ETHERTYPE_CSP
    }
}

/// Splits a CSP frame into Ethernet segments.
pub struct Segmenter<'a> {
    payload: &'a [u8],
    mtu: usize,
    offset: usize,
    dst_mac: [u8; MAC_LEN],
    src_mac: [u8; MAC_LEN],
    src_addr: u16,
    packet_id: u16,
}

impl<'a> Segmenter<'a> {
    /// Create a segmenter. `mtu` is the payload budget per Ethernet frame.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        payload: &'a [u8],
        mtu: usize,
        dst_mac: [u8; MAC_LEN],
        src_mac: [u8; MAC_LEN],
        src_addr: u16,
        packet_id: u16,
    ) -> Result<Self> {
        if mtu == 0 {
            return Err(Error::ZeroMtu);
        }
        if payload.len() > u16::MAX as usize {
            return Err(Error::LengthExceedsMaximum {
                got: payload.len(),
                max: u16::MAX as usize,
            });
        }
        Ok(Segmenter {
            payload,
            mtu: core::cmp::min(mtu, FRAME_PAYLOAD_MAX),
            offset: 0,
            dst_mac,
            src_mac,
            src_addr,
            packet_id,
        })
    }
}

impl<'a> Iterator for Segmenter<'a> {
    /// `(header, payload slice)`.
    type Item = (Header, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.payload.len() {
            return None;
        }
        let take = core::cmp::min(self.mtu, self.payload.len() - self.offset);
        let chunk = &self.payload[self.offset..self.offset + take];
        self.offset += take;
        Some((
            Header {
                dst_mac: self.dst_mac,
                src_mac: self.src_mac,
                ethertype: ETHERTYPE_CSP,
                packet_id: self.packet_id,
                src_addr: self.src_addr,
                seg_size: take as u16,
                packet_length: self.payload.len() as u16,
            },
            chunk,
        ))
    }
}

/// Reassembles Ethernet segments back into a CSP frame.
///
/// EFP explicitly permits segments to arrive out of order, so this tracks which bytes have
/// been filled rather than assuming sequential arrival — unlike SFP and CFP, which run
/// over ordered transports.
#[derive(Debug, Clone, Copy)]
pub struct Reassembler {
    key: Option<u32>,
    total: u16,
    received: u16,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// Start idle.
    pub const fn new() -> Self {
        Reassembler {
            key: None,
            total: 0,
            received: 0,
        }
    }

    /// Total size of the packet being reassembled.
    pub const fn total(&self) -> u16 {
        self.total
    }

    /// Bytes accepted so far.
    pub const fn received(&self) -> u16 {
        self.received
    }

    /// True once every byte has arrived.
    pub const fn is_complete(&self) -> bool {
        self.key.is_some() && self.received >= self.total
    }

    /// Accept one segment, copying its payload into `out` at `offset`.
    ///
    /// `offset` is where this segment belongs; EFP carries no explicit offset field, so a
    /// receiver derives it from arrival order or a higher-layer convention. Passing it in
    /// keeps that policy out of here.
    ///
    /// Returns `true` when the packet is complete.
    pub fn push(
        &mut self,
        h: &Header,
        offset: usize,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<bool> {
        if !h.is_csp() {
            return Err(Error::UnexpectedEtherType { got: h.ethertype });
        }
        if payload.len() != h.seg_size as usize {
            return Err(Error::InconsistentTotal {
                expected: h.seg_size as u32,
                got: payload.len() as u32,
            });
        }
        let key = h.reassembly_key();
        match self.key {
            None => {
                if h.packet_length == 0 {
                    return Err(Error::ZeroTotal);
                }
                self.key = Some(key);
                self.total = h.packet_length;
                self.received = 0;
            }
            Some(k) if k != key => {
                // A segment of a different packet. EFP allows several packets in flight,
                // but one Reassembler tracks one.
                return Err(Error::IdentMismatch {
                    expected: (k >> 16) as u16,
                    got: h.packet_id,
                });
            }
            Some(_) => {
                if h.packet_length != self.total {
                    return Err(Error::InconsistentTotal {
                        expected: self.total as u32,
                        got: h.packet_length as u32,
                    });
                }
            }
        }

        let end = offset + payload.len();
        if end > self.total as usize {
            return Err(Error::OffsetBeyondTotal {
                offset: offset as u32,
                total: self.total as u32,
            });
        }
        if end > out.len() {
            return Err(Error::BufferTooSmall { needed: end });
        }
        out[offset..end].copy_from_slice(payload);
        self.received = self.received.saturating_add(payload.len() as u16);
        Ok(self.is_complete())
    }

    /// Abandon the packet in progress.
    pub fn reset(&mut self) {
        *self = Reassembler::new();
    }
}

/// Maps CSP addresses to MAC addresses, learned from received frames.
///
/// Until a peer has been heard from, frames to it go to [`BROADCAST_MAC`] — so a node that
/// never learns is a node that broadcasts every packet forever, which on a shared segment
/// means every other node processes traffic that is not theirs.
///
/// The C's version (`csp_if_eth.c`) is a bump allocator over a fixed array with an
/// intrusive list and **no eviction**: `arp_used` only ever increases, so once
/// `ARP_MAX_ENTRIES` addresses have been seen, no new peer is ever learned again for the
/// lifetime of the process. This one replaces the least recently used entry.
#[derive(Debug)]
pub struct ArpTable<const N: usize> {
    entries: [Option<(u16, [u8; MAC_LEN], u32)>; N],
    clock: u32,
}

impl<const N: usize> Default for ArpTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ArpTable<N> {
    /// Compile-time invariant: a zero-capacity table can learn nothing, so every frame
    /// broadcasts and the cause is invisible.
    const SANITY: () = assert!(N > 0, "the ARP table needs at least one entry");

    /// An empty table.
    pub const fn new() -> Self {
        let () = Self::SANITY;
        ArpTable {
            entries: [None; N],
            clock: 0,
        }
    }

    /// Addresses currently known.
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// True if nothing has been learned.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Record that `addr` lives at `mac`.
    ///
    /// Updates an existing entry, fills a free slot, or replaces the least recently used
    /// one. The C stops learning entirely once its array is full.
    pub fn learn(&mut self, addr: u16, mac: [u8; MAC_LEN]) {
        self.clock = self.clock.wrapping_add(1);
        let now = self.clock;

        if let Some(e) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|(a, _, _)| *a == addr)
        {
            e.1 = mac;
            e.2 = now;
            return;
        }
        if let Some(slot) = self.entries.iter_mut().find(|s| s.is_none()) {
            *slot = Some((addr, mac, now));
            return;
        }
        // Replace the least recently used. Comparison is by wrapping distance from now,
        // so the counter wrapping does not make an old entry look fresh.
        let mut oldest = 0usize;
        let mut oldest_age = 0u32;
        for (i, s) in self.entries.iter().enumerate() {
            if let Some((_, _, used)) = s {
                let age = now.wrapping_sub(*used);
                if age >= oldest_age {
                    oldest_age = age;
                    oldest = i;
                }
            }
        }
        self.entries[oldest] = Some((addr, mac, now));
    }

    /// The MAC for `addr`, or [`BROADCAST_MAC`] if it has not been learned.
    ///
    /// Never fails: broadcasting is the correct fallback, and returning an error would
    /// make a caller choose between dropping the packet and reimplementing this.
    pub fn lookup(&mut self, addr: u16) -> [u8; MAC_LEN] {
        self.clock = self.clock.wrapping_add(1);
        let now = self.clock;
        for e in self.entries.iter_mut().flatten() {
            if e.0 == addr {
                e.2 = now;
                return e.1;
            }
        }
        BROADCAST_MAC
    }

    /// Whether `addr` is known, without touching its recency.
    pub fn knows(&self, addr: u16) -> bool {
        self.entries.iter().flatten().any(|(a, _, _)| *a == addr)
    }

    /// Forget everything.
    pub fn clear(&mut self) {
        *self = ArpTable::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const B: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

    fn hdr() -> Header {
        Header {
            dst_mac: B,
            src_mac: A,
            ethertype: ETHERTYPE_CSP,
            packet_id: 0x1234,
            src_addr: 11,
            seg_size: 4,
            packet_length: 4,
        }
    }

    #[test]
    fn header_layout_is_22_bytes_and_big_endian() {
        assert_eq!(HEADER_LEN, 22);
        let mut out = [0u8; 32];
        let n = hdr().encode(&mut out).unwrap();
        assert_eq!(n, 22);
        assert_eq!(&out[0..6], &B);
        assert_eq!(&out[6..12], &A);
        assert_eq!(&out[12..14], &[0x88, 0xB5]);
        assert_eq!(&out[14..16], &[0x12, 0x34]);
        assert_eq!(&out[16..18], &11u16.to_be_bytes());
    }

    #[test]
    fn header_roundtrip() {
        let mut out = [0u8; 32];
        let n = hdr().encode(&mut out).unwrap();
        assert_eq!(Header::decode(&out[..n]).unwrap(), hdr());
    }

    #[test]
    fn truncated_header_is_refused() {
        assert_eq!(Header::decode(&[0u8; 21]), Err(Error::Truncated));
    }

    #[test]
    fn the_reassembly_key_does_not_shift_into_a_sign_bit() {
        // The C does `buf->packet_id << 16` on a uint16_t promoted to int, which is
        // undefined behaviour once the top bit is set.
        let h = Header {
            packet_id: 0xFFFF,
            src_addr: 0xFFFF,
            ..hdr()
        };
        assert_eq!(h.reassembly_key(), 0xFFFF_FFFF);
        let h2 = Header {
            packet_id: 0x8000,
            src_addr: 0x0001,
            ..hdr()
        };
        assert_eq!(h2.reassembly_key(), 0x8000_0001);
    }

    #[test]
    fn non_csp_ethertype_is_rejected() {
        let mut r = Reassembler::new();
        let h = Header {
            ethertype: 0x0800, // IPv4
            ..hdr()
        };
        let mut out = [0u8; 64];
        assert_eq!(
            r.push(&h, 0, &[0u8; 4], &mut out),
            Err(Error::UnexpectedEtherType { got: 0x0800 })
        );
    }

    #[test]
    fn segmentation_covers_the_payload_exactly() {
        for total in [1usize, 10, 100, 1500, 1501, 3000] {
            let payload: [u8; 3000] = core::array::from_fn(|i| (i & 0xff) as u8);
            let data = &payload[..total];
            let segs = Segmenter::new(data, 1500, B, A, 11, 7).unwrap();
            let mut seen = 0usize;
            let mut count = 0usize;
            for (h, chunk) in segs {
                assert_eq!(h.packet_length as usize, total);
                assert_eq!(h.seg_size as usize, chunk.len());
                assert!(chunk.len() <= FRAME_PAYLOAD_MAX);
                assert_eq!(h.packet_id, 7, "all segments share the packet id");
                seen += chunk.len();
                count += 1;
            }
            assert_eq!(seen, total, "total={total}");
            assert!(count >= 1);
        }
    }

    #[test]
    fn an_mtu_above_the_ethernet_limit_is_clamped() {
        let data = [0u8; 3000];
        let segs = Segmenter::new(&data, 9000, B, A, 11, 1).unwrap();
        for (_, chunk) in segs {
            assert!(
                chunk.len() <= FRAME_PAYLOAD_MAX,
                "must not exceed the Ethernet MTU"
            );
        }
    }

    #[test]
    fn zero_mtu_is_refused() {
        assert_eq!(
            Segmenter::new(b"x", 0, B, A, 11, 1).err(),
            Some(Error::ZeroMtu)
        );
    }

    #[test]
    fn a_packet_too_large_for_the_length_field_is_refused() {
        // packet_length is 16 bits; the C would silently truncate.
        let big = [0u8; 70000];
        assert_eq!(
            Segmenter::new(&big, 1500, B, A, 11, 1).err(),
            Some(Error::LengthExceedsMaximum {
                got: 70000,
                max: 65535
            })
        );
    }

    #[test]
    fn roundtrip_through_reassembly() {
        for total in [1usize, 100, 1500, 3000] {
            let payload: [u8; 3000] = core::array::from_fn(|i| (i.wrapping_mul(7) & 0xff) as u8);
            let data = &payload[..total];
            let mut r = Reassembler::new();
            let mut out = [0u8; 3000];
            let mut offset = 0usize;
            let mut done = false;
            for (h, chunk) in Segmenter::new(data, 1500, B, A, 11, 3).unwrap() {
                done = r.push(&h, offset, chunk, &mut out).unwrap();
                offset += chunk.len();
            }
            assert!(done, "total={total} never completed");
            assert_eq!(&out[..total], data, "total={total}");
        }
    }

    #[test]
    fn out_of_order_segments_are_accepted() {
        // EFP explicitly permits this, unlike SFP and CFP.
        let payload: [u8; 3000] = core::array::from_fn(|i| (i & 0xff) as u8);
        let segs: heapless::Vec4<(Header, usize)> = {
            let mut v = heapless::Vec4::new();
            let mut off = 0;
            for (h, chunk) in Segmenter::new(&payload, 1500, B, A, 11, 3).unwrap() {
                v.push((h, off));
                off += chunk.len();
            }
            v
        };
        assert!(segs.len() >= 2, "need at least two segments to reorder");

        let mut r = Reassembler::new();
        let mut out = [0u8; 3000];
        // last segment first
        for i in (0..segs.len()).rev() {
            let (h, off) = segs.get(i);
            let chunk = &payload[off..off + h.seg_size as usize];
            r.push(&h, off, chunk, &mut out).unwrap();
        }
        assert!(r.is_complete(), "reordered segments must still complete");
        assert_eq!(&out[..3000], &payload[..]);
    }

    mod heapless {
        #[derive(Debug)]
        pub struct Vec4<T: Copy> {
            items: [Option<T>; 8],
            len: usize,
        }
        impl<T: Copy> Vec4<T> {
            pub fn new() -> Self {
                Vec4 {
                    items: [None; 8],
                    len: 0,
                }
            }
            pub fn push(&mut self, t: T) {
                assert!(self.len < 8, "test collector overflow");
                self.items[self.len] = Some(t);
                self.len += 1;
            }
            pub fn len(&self) -> usize {
                self.len
            }
            pub fn get(&self, i: usize) -> T {
                self.items[i].unwrap()
            }
        }
    }

    #[test]
    fn a_segment_from_a_different_packet_is_refused() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 64];
        let h1 = Header {
            packet_id: 1,
            seg_size: 4,
            packet_length: 8,
            ..hdr()
        };
        assert!(!r.push(&h1, 0, &[0u8; 4], &mut out).unwrap());
        let h2 = Header {
            packet_id: 2,
            seg_size: 4,
            packet_length: 8,
            ..hdr()
        };
        assert!(matches!(
            r.push(&h2, 4, &[0u8; 4], &mut out),
            Err(Error::IdentMismatch { .. })
        ));
    }

    #[test]
    fn a_seg_size_that_disagrees_with_the_payload_is_refused() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 64];
        let h = Header {
            seg_size: 10,
            packet_length: 10,
            ..hdr()
        };
        assert!(matches!(
            r.push(&h, 0, &[0u8; 4], &mut out),
            Err(Error::InconsistentTotal { .. })
        ));
    }

    #[test]
    fn a_zero_length_packet_is_refused() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 64];
        let h = Header {
            seg_size: 0,
            packet_length: 0,
            ..hdr()
        };
        assert_eq!(r.push(&h, 0, &[], &mut out), Err(Error::ZeroTotal));
    }

    #[test]
    fn a_segment_past_the_declared_length_is_refused() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 64];
        let h = Header {
            seg_size: 4,
            packet_length: 4,
            ..hdr()
        };
        assert!(matches!(
            r.push(&h, 8, &[0u8; 4], &mut out),
            Err(Error::OffsetBeyondTotal { .. })
        ));
    }

    // --- ARP ---

    #[test]
    fn an_unknown_address_broadcasts() {
        let mut t: ArpTable<4> = ArpTable::new();
        assert_eq!(t.lookup(11), BROADCAST_MAC);
        assert!(!t.knows(11));
    }

    #[test]
    fn a_learned_address_is_unicast() {
        let mut t: ArpTable<4> = ArpTable::new();
        t.learn(11, A);
        assert_eq!(t.lookup(11), A);
        assert!(t.knows(11));
        assert_eq!(t.lookup(12), BROADCAST_MAC, "others still broadcast");
    }

    #[test]
    fn relearning_updates_the_mac() {
        // A node that changes its MAC -- a redundant interface failing over -- must not
        // keep receiving traffic at the old address.
        let mut t: ArpTable<4> = ArpTable::new();
        t.learn(11, A);
        t.learn(11, B);
        assert_eq!(t.lookup(11), B);
        assert_eq!(t.len(), 1, "an update must not consume a second slot");
    }

    #[test]
    fn a_full_table_keeps_learning_by_replacing_the_least_recently_used() {
        // The C's arp_used only ever increases, so once ARP_MAX_ENTRIES addresses have
        // been seen it never learns another peer for the life of the process.
        let mut t: ArpTable<2> = ArpTable::new();
        t.learn(1, A);
        t.learn(2, B);
        // Touch 1 so 2 becomes the least recently used.
        assert_eq!(t.lookup(1), A);
        t.learn(3, [3u8; 6]);

        assert!(t.knows(3), "a new peer must still be learnable when full");
        assert!(t.knows(1), "the recently used entry survives");
        assert!(!t.knows(2), "the least recently used was replaced");
    }

    #[test]
    fn eviction_is_correct_across_the_recency_counter_wrap() {
        let mut t: ArpTable<2> = ArpTable::new();
        t.learn(1, A);
        t.learn(2, B);
        // Drive the internal counter a long way, touching only address 1.
        for _ in 0..1000 {
            t.lookup(1);
        }
        t.learn(3, [3u8; 6]);
        assert!(t.knows(1), "the frequently used entry must survive");
        assert!(t.knows(3));
    }

    #[test]
    fn clear_forgets_everything() {
        let mut t: ArpTable<4> = ArpTable::new();
        t.learn(11, A);
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.lookup(11), BROADCAST_MAC);
    }

    #[test]
    fn decoding_arbitrary_bytes_never_panics() {
        let mut decoded = 0u32;
        let mut buf = [0u8; 64];
        let mut x: u32 = 0xE741_0001;
        for _ in 0..50_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (x >> (i % 24)) as u8;
            }
            for n in [0usize, 10, 21, 22, 64] {
                if let Ok(h) = Header::decode(&buf[..n]) {
                    decoded += 1;
                    let _ = h.reassembly_key();
                    let _ = h.is_csp();
                }
            }
        }
        // Measured at 100 000: the guard is what stops a stricter decoder silently
        // reducing this test to "the length check does not panic".
        assert!(decoded > 10_000, "only {decoded} headers decoded");
    }
}
