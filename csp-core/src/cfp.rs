//! CFP — the CAN Fragmentation Protocol, which carries CSP packets over 8-byte CAN frames.
//!
//! Two incompatible layouts, selected by the CSP wire version. Both pack their control
//! fields into the 29-bit extended CAN identifier; they disagree about everything else.
//!
//! # CFP 1 (CSP v1)
//!
//! ```text
//! CAN id:  [ src:5 ][ dst:5 ][ type:1 ][ remain:8 ][ ident:10 ]
//!            bit 24    19        18        10           0
//!
//! begin frame data: [ CSP header:4 ][ length:2 ][ payload:0..2 ]
//! more  frame data: [ payload:0..8 ]
//! ```
//!
//! `remain` counts the frames still to come, so a receiver can size the transfer up front.
//!
//! # CFP 2 (CSP v2)
//!
//! ```text
//! CAN id:  [ pri:2 ][ dst:14 ][ sender:6 ][ sc:2 ][ fc:3 ][ begin:1 ][ end:1 ]
//!            bit 27     13         7         5       2        1         0
//!
//! begin frame data: [ src:14 dport:6 sport:6 flags:6 packed BE u32 ][ payload:0..4 ]
//! more  frame data: [ payload:0..8 ]
//! ```
//!
//! CFP 2 has no length field. The transfer ends when a frame arrives with `end` set, and
//! `fc` is only **3 bits** — it wraps every 8 frames, so a receiver cannot detect the loss
//! of exactly 8 consecutive fragments. That is a property of the wire format, not of this
//! implementation.

use crate::{Error, Id, Result, Version};

/// Bytes in a classic CAN frame.
pub const CAN_FRAME_SIZE: usize = 8;

/// A single CAN frame produced by fragmentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Frame {
    /// 29-bit extended CAN identifier.
    pub id: u32,
    data: [u8; CAN_FRAME_SIZE],
    len: u8,
}

impl Frame {
    /// The frame's data bytes.
    pub fn data(&self) -> &[u8] {
        &self.data[..self.len as usize]
    }
    /// Data length code.
    pub const fn dlc(&self) -> u8 {
        self.len
    }
}

// --- CFP 1 identifier layout ---
const V1_HOST_BITS: u32 = 5;
const V1_TYPE_BITS: u32 = 1;
const V1_REMAIN_BITS: u32 = 8;
const V1_IDENT_BITS: u32 = 10;

const V1_IDENT_OFFSET: u32 = 0;
const V1_REMAIN_OFFSET: u32 = V1_IDENT_BITS;
const V1_TYPE_OFFSET: u32 = V1_REMAIN_OFFSET + V1_REMAIN_BITS;
const V1_DST_OFFSET: u32 = V1_TYPE_OFFSET + V1_TYPE_BITS;
const V1_SRC_OFFSET: u32 = V1_DST_OFFSET + V1_HOST_BITS;

/// Frame kind in CFP 1.
pub const TYPE_BEGIN: u32 = 0;
/// Continuation frame in CFP 1.
pub const TYPE_MORE: u32 = 1;

const V1_HEADER_SIZE: usize = 4;
const V1_LEN_SIZE: usize = 2;
const V1_DATA_OFFSET: usize = V1_HEADER_SIZE + V1_LEN_SIZE; // 6
const V1_DATA_IN_BEGIN: usize = CAN_FRAME_SIZE - V1_DATA_OFFSET; // 2

// --- CFP 2 identifier layout ---
const V2_PRIO_OFFSET: u32 = 27;
const V2_DST_OFFSET: u32 = 13;
const V2_SENDER_OFFSET: u32 = 7;
const V2_SC_OFFSET: u32 = 5;
const V2_FC_OFFSET: u32 = 2;
const V2_BEGIN_OFFSET: u32 = 1;
const V2_END_OFFSET: u32 = 0;

const V2_PRIO_MASK: u32 = 0x3;
const V2_DST_MASK: u32 = 0x3FFF;
const V2_SENDER_MASK: u32 = 0x3F;
const V2_SC_MASK: u32 = 0x3;
const V2_FC_MASK: u32 = 0x7;

const V2_SRC_OFFSET: u32 = 18;
const V2_DPORT_OFFSET: u32 = 12;
const V2_SPORT_OFFSET: u32 = 6;
const V2_FLAGS_OFFSET: u32 = 0;
const V2_SRC_MASK: u32 = 0x3FFF;
const V2_DPORT_MASK: u32 = 0x3F;
const V2_SPORT_MASK: u32 = 0x3F;
const V2_FLAGS_MASK: u32 = 0x3F;

const V2_EXT_SIZE: usize = 4;
const V2_DATA_IN_BEGIN: usize = CAN_FRAME_SIZE - V2_EXT_SIZE; // 4

/// Build a CFP 1 CAN identifier.
pub const fn v1_id(src: u16, dst: u16, kind: u32, remain: u32, ident: u16) -> u32 {
    ((src as u32 & mask(V1_HOST_BITS)) << V1_SRC_OFFSET)
        | ((dst as u32 & mask(V1_HOST_BITS)) << V1_DST_OFFSET)
        | ((kind & mask(V1_TYPE_BITS)) << V1_TYPE_OFFSET)
        | ((remain & mask(V1_REMAIN_BITS)) << V1_REMAIN_OFFSET)
        | ((ident as u32 & mask(V1_IDENT_BITS)) << V1_IDENT_OFFSET)
}

/// Fields of a CFP 1 identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub struct V1Id {
    pub src: u16,
    pub dst: u16,
    pub kind: u32,
    pub remain: u32,
    pub ident: u16,
}

/// Take a CFP 1 identifier apart.
pub const fn v1_parse(id: u32) -> V1Id {
    V1Id {
        src: ((id >> V1_SRC_OFFSET) & mask(V1_HOST_BITS)) as u16,
        dst: ((id >> V1_DST_OFFSET) & mask(V1_HOST_BITS)) as u16,
        kind: (id >> V1_TYPE_OFFSET) & mask(V1_TYPE_BITS),
        remain: (id >> V1_REMAIN_OFFSET) & mask(V1_REMAIN_BITS),
        ident: ((id >> V1_IDENT_OFFSET) & mask(V1_IDENT_BITS)) as u16,
    }
}

const fn mask(bits: u32) -> u32 {
    (1u32 << bits) - 1
}

/// Fragments a CSP packet into CFP 1 CAN frames.
pub struct V1Fragmenter<'a> {
    header: [u8; V1_HEADER_SIZE],
    payload: &'a [u8],
    src: u16,
    dest: u16,
    ident: u16,
    sent: usize,
    started: bool,
}

impl<'a> V1Fragmenter<'a> {
    /// `header` is the 4-byte encoded CSP v1 header; `dest` is the next hop, which is the
    /// route's via address when there is one, **not** necessarily `id.dst`.
    pub fn new(
        header: [u8; V1_HEADER_SIZE],
        src: u16,
        dest: u16,
        ident: u16,
        payload: &'a [u8],
    ) -> Self {
        V1Fragmenter {
            header,
            payload,
            src,
            dest,
            ident,
            sent: 0,
            started: false,
        }
    }
}

impl Iterator for V1Fragmenter<'_> {
    type Item = Frame;

    fn next(&mut self) -> Option<Frame> {
        let total = self.payload.len();
        if !self.started {
            self.started = true;
            let n = core::cmp::min(V1_DATA_IN_BEGIN, total);
            // remain counts the frames still to come after this one.
            let remain = (total + V1_DATA_OFFSET - 1) / CAN_FRAME_SIZE;
            let mut data = [0u8; CAN_FRAME_SIZE];
            data[..V1_HEADER_SIZE].copy_from_slice(&self.header);
            data[V1_HEADER_SIZE..V1_DATA_OFFSET].copy_from_slice(&(total as u16).to_be_bytes());
            data[V1_DATA_OFFSET..V1_DATA_OFFSET + n].copy_from_slice(&self.payload[..n]);
            self.sent = n;
            return Some(Frame {
                id: v1_id(self.src, self.dest, TYPE_BEGIN, remain as u32, self.ident),
                data,
                len: (V1_DATA_OFFSET + n) as u8,
            });
        }
        if self.sent >= total {
            return None;
        }
        let n = core::cmp::min(CAN_FRAME_SIZE, total - self.sent);
        let remain = (total - self.sent - n).div_ceil(CAN_FRAME_SIZE);
        let mut data = [0u8; CAN_FRAME_SIZE];
        data[..n].copy_from_slice(&self.payload[self.sent..self.sent + n]);
        self.sent += n;
        Some(Frame {
            id: v1_id(self.src, self.dest, TYPE_MORE, remain as u32, self.ident),
            data,
            len: n as u8,
        })
    }
}

/// Fragments a CSP packet into CFP 2 CAN frames.
pub struct V2Fragmenter<'a> {
    id: Id,
    sender: u16,
    sender_count: u32,
    payload: &'a [u8],
    sent: usize,
    fragment_count: u32,
    started: bool,
}

impl<'a> V2Fragmenter<'a> {
    /// `sender` is the transmitting interface's own address, which CFP 2 puts in the CAN
    /// id in place of the CSP source address.
    pub fn new(id: Id, sender: u16, sender_count: u32, payload: &'a [u8]) -> Self {
        V2Fragmenter {
            id,
            sender,
            sender_count,
            payload,
            sent: 0,
            fragment_count: 1,
            started: false,
        }
    }

    fn base_id(&self) -> u32 {
        ((self.id.pri as u32 & V2_PRIO_MASK) << V2_PRIO_OFFSET)
            | ((self.id.dst as u32 & V2_DST_MASK) << V2_DST_OFFSET)
            | ((self.sender as u32 & V2_SENDER_MASK) << V2_SENDER_OFFSET)
            | ((self.sender_count & V2_SC_MASK) << V2_SC_OFFSET)
    }

    /// The 4-byte header extension carried in the first frame.
    pub fn header_extension(&self) -> [u8; V2_EXT_SIZE] {
        let ext = ((self.id.src as u32 & V2_SRC_MASK) << V2_SRC_OFFSET)
            | ((self.id.dport as u32 & V2_DPORT_MASK) << V2_DPORT_OFFSET)
            | ((self.id.sport as u32 & V2_SPORT_MASK) << V2_SPORT_OFFSET)
            | ((self.id.flags as u32 & V2_FLAGS_MASK) << V2_FLAGS_OFFSET);
        ext.to_be_bytes()
    }
}

impl Iterator for V2Fragmenter<'_> {
    type Item = Frame;

    fn next(&mut self) -> Option<Frame> {
        let total = self.payload.len();
        if !self.started {
            self.started = true;
            let n = core::cmp::min(V2_DATA_IN_BEGIN, total);
            let mut data = [0u8; CAN_FRAME_SIZE];
            data[..V2_EXT_SIZE].copy_from_slice(&self.header_extension());
            data[V2_EXT_SIZE..V2_EXT_SIZE + n].copy_from_slice(&self.payload[..n]);
            self.sent = n;
            let mut id = self.base_id() | (1 << V2_BEGIN_OFFSET);
            if n == total {
                id |= 1 << V2_END_OFFSET;
            }
            return Some(Frame {
                id,
                data,
                len: (V2_EXT_SIZE + n) as u8,
            });
        }
        if self.sent >= total {
            return None;
        }
        let n = core::cmp::min(CAN_FRAME_SIZE, total - self.sent);
        let mut id = self.base_id() | ((self.fragment_count & V2_FC_MASK) << V2_FC_OFFSET);
        self.fragment_count += 1;
        if self.sent + n == total {
            id |= 1 << V2_END_OFFSET;
        }
        let mut data = [0u8; CAN_FRAME_SIZE];
        data[..n].copy_from_slice(&self.payload[self.sent..self.sent + n]);
        self.sent += n;
        Some(Frame {
            id,
            data,
            len: n as u8,
        })
    }
}

/// Fields that identify one CFP 2 transfer: priority, destination, sender and the
/// 2-bit sender count. Everything else in the identifier varies between fragments.
pub const V2_CONN_MASK: u32 = (V2_DST_MASK << V2_DST_OFFSET)
    | (V2_SENDER_MASK << V2_SENDER_OFFSET)
    | (V2_PRIO_MASK << V2_PRIO_OFFSET)
    | (V2_SC_MASK << V2_SC_OFFSET);

/// Reassembles CFP 2 frames back into a CSP packet.
///
/// CFP 2 carries no length field: the transfer ends when a frame arrives with the `end`
/// bit set. The fragment counter is **3 bits**, so it wraps every 8 frames and losing
/// exactly 8 consecutive fragments is undetectable — a property of the wire format, not of
/// this implementation.
#[derive(Debug, Clone, Copy)]
pub struct V2Reassembler {
    id: Option<Id>,
    next_fc: u32,
    len: usize,
}

impl Default for V2Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl V2Reassembler {
    /// Start idle.
    pub const fn new() -> Self {
        V2Reassembler {
            id: None,
            next_fc: 1,
            len: 0,
        }
    }

    /// Bytes accepted so far.
    pub const fn received(&self) -> usize {
        self.len
    }

    /// Feed a frame.
    ///
    /// Returns `Some((id, len))` once the `end` bit arrives: the decoded CSP header and
    /// how many payload bytes were written to `out`. Returning the length matters because
    /// CFP 2 has no length field — without it the caller cannot tell how much of `out`
    /// is the packet.
    pub fn push(
        &mut self,
        can_id: u32,
        data: &[u8],
        out: &mut [u8],
    ) -> Result<Option<(Id, usize)>> {
        let begin = (can_id >> V2_BEGIN_OFFSET) & 1 != 0;
        let end = (can_id >> V2_END_OFFSET) & 1 != 0;

        let payload = if begin {
            // The CSP header is split: its first two bytes live in the CAN identifier
            // (priority and destination), the next four in the frame data.
            if data.len() < V2_EXT_SIZE {
                return Err(Error::Truncated);
            }
            let first_two = ((can_id >> V2_DST_OFFSET) as u16).to_be_bytes();
            let mut header = [0u8; 6];
            header[..2].copy_from_slice(&first_two);
            header[2..6].copy_from_slice(&data[..V2_EXT_SIZE]);
            self.id = Some(Id::decode(Version::V2, &header)?);
            self.next_fc = 1;
            self.len = 0;
            &data[V2_EXT_SIZE..]
        } else {
            // A continuation with no transfer in progress means the opening frame was
            // lost. Reassembling anyway would produce a packet with a garbage header.
            if self.id.is_none() {
                return Err(Error::NoTransferInProgress);
            }
            let fc = (can_id >> V2_FC_OFFSET) & V2_FC_MASK;
            if fc != self.next_fc {
                // A gap. The C drops the whole packet here too, because with a 3-bit
                // counter there is no way to tell one lost fragment from nine.
                let expected = self.next_fc as u16;
                self.reset();
                return Err(Error::UnexpectedOffset {
                    expected: expected as u32,
                    got: fc,
                });
            }
            self.next_fc = (self.next_fc + 1) & V2_FC_MASK;
            data
        };

        let end_off = self.len + payload.len();
        if end_off > out.len() {
            self.reset();
            return Err(Error::BufferTooSmall { needed: end_off });
        }
        out[self.len..end_off].copy_from_slice(payload);
        self.len = end_off;

        if end {
            let id = self.id.ok_or(Error::NoTransferInProgress)?;
            let len = self.len;
            self.reset();
            return Ok(Some((id, len)));
        }
        Ok(None)
    }

    fn reset(&mut self) {
        self.id = None;
        self.next_fc = 1;
        self.len = 0;
    }
}

/// Several reassemblies in flight at once, keyed by transfer.
///
/// On a shared bus, fragments from different senders interleave. A single reassembler
/// drops every interleaved transfer, so the C keeps a pool (`csp_if_can_pbuf.c`) keyed by
/// the connection fields of the identifier. This is that, generic over the reassembler so
/// CFP 1, CFP 2 and Ethernet can share it.
#[derive(Debug)]
pub struct Pbufs<R, const N: usize> {
    slots: [Option<(u32, u32, R)>; N],
}

impl<R: Default + Copy, const N: usize> Default for Pbufs<R, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<R: Default + Copy, const N: usize> Pbufs<R, N> {
    /// Compile-time invariant: a zero-capacity pool can reassemble nothing, which would
    /// look like total packet loss rather than a sizing mistake.
    const SANITY: () = assert!(N > 0, "the reassembly pool needs at least one slot");

    /// An empty pool.
    pub fn new() -> Self {
        let () = Self::SANITY;
        Pbufs { slots: [None; N] }
    }

    /// Reassemblies in flight.
    pub fn len(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    /// True if nothing is in flight.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The reassembler for `key`, creating one if this is a new transfer.
    ///
    /// Returns `None` when the pool is full — every slot is a transfer in progress, and
    /// evicting one to make room would corrupt it.
    pub fn get_or_create(&mut self, key: u32, now_ms: u32) -> Option<&mut R> {
        self.get_or_create_with(key, now_ms, R::default)
    }

    /// [`get_or_create`](Self::get_or_create), with the caller building a new reassembler.
    ///
    /// `R::default` is not always the right starting state: `eth::Reassembler` needs the
    /// minimum declared length for its wire version, which the pool has no way to know and
    /// which `Default` leaves at zero — silently dropping the guard that refuses a packet
    /// too short to hold a CSP header.
    pub fn get_or_create_with(
        &mut self,
        key: u32,
        now_ms: u32,
        make: impl FnOnce() -> R,
    ) -> Option<&mut R> {
        if let Some(i) = self
            .slots
            .iter()
            .position(|s| matches!(s, Some((k, _, _)) if *k == key))
        {
            let slot = self.slots[i].as_mut()?;
            slot.1 = now_ms;
            return Some(&mut slot.2);
        }
        let i = self.slots.iter().position(|s| s.is_none())?;
        self.slots[i] = Some((key, now_ms, make()));
        self.slots[i].as_mut().map(|s| &mut s.2)
    }

    /// Forget a transfer — on completion, or when it went wrong.
    pub fn release(&mut self, key: u32) {
        for s in self.slots.iter_mut() {
            if matches!(s, Some((k, _, _)) if *k == key) {
                *s = None;
            }
        }
    }

    /// Drop transfers with no fragment for longer than `timeout_ms`, returning how many.
    ///
    /// Not optional: a sender that starts a transfer and stops holds a slot forever, and
    /// there are only `N`.
    pub fn expire(&mut self, now_ms: u32, timeout_ms: u32) -> usize {
        let mut n = 0;
        for s in self.slots.iter_mut() {
            if let Some((_, last, _)) = s {
                if now_ms.wrapping_sub(*last) > timeout_ms {
                    *s = None;
                    n += 1;
                }
            }
        }
        n
    }
}

/// Reassembles CFP 1 frames back into a CSP packet.
///
/// Rejects a `MORE` frame that arrives without a preceding `BEGIN`, and refuses a
/// declared length that will not fit the caller's buffer — the C copies first and checks
/// afterwards.
pub struct V1Reassembler {
    ident: Option<u16>,
    header: [u8; V1_HEADER_SIZE],
    expected: usize,
    received: usize,
}

impl Default for V1Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl V1Reassembler {
    /// Start idle.
    pub const fn new() -> Self {
        V1Reassembler {
            ident: None,
            header: [0; V1_HEADER_SIZE],
            expected: 0,
            received: 0,
        }
    }

    /// Feed a frame. Returns `Some(id)` with the decoded CSP header once complete.
    pub fn push(&mut self, can_id: u32, data: &[u8], out: &mut [u8]) -> Result<Option<Id>> {
        let f = v1_parse(can_id);
        if f.kind == TYPE_BEGIN {
            if data.len() < V1_DATA_OFFSET {
                return Err(Error::Truncated);
            }
            self.header.copy_from_slice(&data[..V1_HEADER_SIZE]);
            let declared =
                u16::from_be_bytes([data[V1_HEADER_SIZE], data[V1_HEADER_SIZE + 1]]) as usize;
            if declared > out.len() {
                return Err(Error::BufferTooSmall { needed: declared });
            }
            self.ident = Some(f.ident);
            self.expected = declared;
            self.received = 0;
            let n = data.len() - V1_DATA_OFFSET;
            let take = core::cmp::min(n, declared);
            out[..take].copy_from_slice(&data[V1_DATA_OFFSET..V1_DATA_OFFSET + take]);
            self.received = take;
        } else {
            // A continuation with no transfer in progress is a lost BEGIN, not a packet.
            let Some(ident) = self.ident else {
                return Err(Error::NoTransferInProgress);
            };
            if ident != f.ident {
                return Err(Error::IdentMismatch {
                    expected: ident,
                    got: f.ident,
                });
            }
            let n = data.len();
            if self.received + n > self.expected {
                return Err(Error::OffsetBeyondTotal {
                    offset: (self.received + n) as u32,
                    total: self.expected as u32,
                });
            }
            out[self.received..self.received + n].copy_from_slice(&data[..n]);
            self.received += n;
        }

        if self.received >= self.expected {
            self.ident = None;
            let id = Id::decode(Version::V1, &self.header)?;
            return Ok(Some(id));
        }
        Ok(None)
    }

    /// Bytes accepted into the current transfer.
    pub const fn received(&self) -> usize {
        self.received
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flags;

    fn hdr(id: &Id) -> [u8; 4] {
        let mut h = [0u8; 4];
        id.encode(Version::V1, &mut h).unwrap();
        h
    }

    #[test]
    fn v1_id_fields_roundtrip() {
        for &(src, dst, kind, remain, ident) in &[
            (0u16, 0u16, TYPE_BEGIN, 0u32, 0u16),
            (1, 8, TYPE_BEGIN, 3, 42),
            (31, 31, TYPE_MORE, 255, 1023),
        ] {
            let id = v1_id(src, dst, kind, remain, ident);
            let p = v1_parse(id);
            assert_eq!(
                (p.src, p.dst, p.kind, p.remain, p.ident),
                (src, dst, kind, remain, ident)
            );
            assert!(id < (1 << 29), "must fit a 29-bit extended identifier");
        }
    }

    #[test]
    fn v1_begin_frame_layout() {
        let id = Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        };
        let payload = [0xAA, 0xBB, 0xCC];
        let f: Frame = V1Fragmenter::new(hdr(&id), 1, 8, 7, &payload)
            .next()
            .unwrap();
        assert_eq!(&f.data()[..4], &hdr(&id));
        assert_eq!(&f.data()[4..6], &3u16.to_be_bytes(), "length field");
        assert_eq!(&f.data()[6..], &[0xAA, 0xBB], "only 2 payload bytes fit");
        assert_eq!(f.dlc(), 8);
    }

    #[test]
    fn v1_empty_payload_is_one_frame() {
        let id = Id::default();
        let frames: heapless_vec::Vec8<Frame> = V1Fragmenter::new(hdr(&id), 0, 0, 0, &[]).collect();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames.get(0).dlc(), 6, "header + length only");
    }

    /// Minimal fixed-capacity collector so these tests need no alloc.
    mod heapless_vec {
        #[derive(Debug)]
        pub struct Vec8<T: Copy + Default> {
            items: [T; 300],
            len: usize,
        }
        impl<T: Copy + Default> Vec8<T> {
            pub fn len(&self) -> usize {
                self.len
            }
            pub fn get(&self, i: usize) -> T {
                self.items[i]
            }
            pub fn as_slice(&self) -> &[T] {
                &self.items[..self.len]
            }
        }
        impl<T: Copy + Default> FromIterator<T> for Vec8<T> {
            fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
                let mut v = Vec8 {
                    items: [T::default(); 300],
                    len: 0,
                };
                for it in iter {
                    assert!(v.len < 300, "test collector overflow");
                    v.items[v.len] = it;
                    v.len += 1;
                }
                v
            }
        }
    }

    #[test]
    fn v1_fragmentation_covers_the_payload_exactly() {
        let id = Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        };
        for total in [0usize, 1, 2, 3, 7, 8, 9, 10, 16, 100, 200] {
            let payload: heapless_vec::Vec8<u8> = (0..total).map(|i| (i & 0xff) as u8).collect();
            let frames: heapless_vec::Vec8<Frame> =
                V1Fragmenter::new(hdr(&id), 1, 8, 3, payload.as_slice()).collect();
            assert!(frames.len() >= 1);

            let mut seen = 0usize;
            for i in 0..frames.len() {
                let f = frames.get(i);
                let p = v1_parse(f.id);
                assert_eq!(p.ident, 3);
                if i == 0 {
                    assert_eq!(p.kind, TYPE_BEGIN);
                    seen += f.dlc() as usize - V1_DATA_OFFSET;
                } else {
                    assert_eq!(p.kind, TYPE_MORE);
                    seen += f.dlc() as usize;
                }
                // remain must count the frames actually still to come
                assert_eq!(
                    p.remain as usize,
                    frames.len() - 1 - i,
                    "total={total} frame {i}: remain wrong"
                );
            }
            assert_eq!(seen, total, "total={total}: coverage");
        }
    }

    #[test]
    fn v1_roundtrip_through_reassembly() {
        let id = Id {
            pri: 2,
            flags: flags::CRC32,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        };
        for total in [0usize, 1, 2, 3, 8, 9, 100, 200] {
            let payload: heapless_vec::Vec8<u8> = (0..total)
                .map(|i| (i.wrapping_mul(5) & 0xff) as u8)
                .collect();
            let mut r = V1Reassembler::new();
            let mut out = [0u8; 256];
            let mut got = None;
            for f in V1Fragmenter::new(hdr(&id), 1, 8, 9, payload.as_slice()) {
                if let Some(decoded) = r.push(f.id, f.data(), &mut out).unwrap() {
                    got = Some(decoded);
                }
            }
            let decoded = got.unwrap_or_else(|| panic!("total={total} never completed"));
            assert_eq!(decoded, id, "total={total}: header");
            assert_eq!(&out[..total], payload.as_slice(), "total={total}: payload");
        }
    }

    #[test]
    fn v1_continuation_without_a_begin_is_refused() {
        // A lost BEGIN must not be reassembled into a short packet with a garbage header.
        let mut r = V1Reassembler::new();
        let mut out = [0u8; 64];
        let id = v1_id(1, 8, TYPE_MORE, 0, 5);
        assert_eq!(
            r.push(id, &[1, 2, 3, 4], &mut out),
            Err(Error::NoTransferInProgress)
        );
    }

    #[test]
    fn v1_declared_length_larger_than_the_buffer_is_refused() {
        let mut r = V1Reassembler::new();
        let mut out = [0u8; 16];
        let mut data = [0u8; 8];
        data[4..6].copy_from_slice(&1000u16.to_be_bytes());
        assert_eq!(
            r.push(v1_id(1, 8, TYPE_BEGIN, 0, 1), &data, &mut out),
            Err(Error::BufferTooSmall { needed: 1000 })
        );
    }

    #[test]
    fn v1_short_begin_frame_is_refused() {
        let mut r = V1Reassembler::new();
        let mut out = [0u8; 64];
        assert_eq!(
            r.push(v1_id(1, 8, TYPE_BEGIN, 0, 1), &[0, 0, 0], &mut out),
            Err(Error::Truncated)
        );
    }

    #[test]
    fn v2_begin_frame_carries_the_header_extension() {
        let id = Id {
            pri: 2,
            flags: 0x10,
            src: 1000,
            dst: 2000,
            dport: 20,
            sport: 10,
        };
        let frag = V2Fragmenter::new(id, 5, 0, &[]);
        let ext = frag.header_extension();
        let raw = u32::from_be_bytes(ext);
        assert_eq!((raw >> V2_SRC_OFFSET) & V2_SRC_MASK, 1000);
        assert_eq!((raw >> V2_DPORT_OFFSET) & V2_DPORT_MASK, 20);
        assert_eq!((raw >> V2_SPORT_OFFSET) & V2_SPORT_MASK, 10);
        assert_eq!((raw >> V2_FLAGS_OFFSET) & V2_FLAGS_MASK, 0x10);
    }

    #[test]
    fn v2_sets_begin_and_end_correctly() {
        let id = Id {
            pri: 1,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        };
        // Fits in the first frame: begin and end both set.
        let f: Frame = V2Fragmenter::new(id, 5, 0, &[1, 2]).next().unwrap();
        assert_eq!((f.id >> V2_BEGIN_OFFSET) & 1, 1);
        assert_eq!((f.id >> V2_END_OFFSET) & 1, 1);

        // Needs two frames: end only on the last.
        let frames: heapless_vec::Vec8<Frame> = V2Fragmenter::new(id, 5, 0, &[0u8; 20]).collect();
        assert!(frames.len() > 1);
        for i in 0..frames.len() {
            let f = frames.get(i);
            let last = i == frames.len() - 1;
            assert_eq!((f.id >> V2_END_OFFSET) & 1, last as u32, "frame {i}");
            assert_eq!((f.id >> V2_BEGIN_OFFSET) & 1, (i == 0) as u32, "frame {i}");
        }
    }

    #[test]
    fn v2_fragment_counter_is_three_bits_and_wraps() {
        // 8 * 8 = 64 payload bytes after the first frame's 4 => fc must wrap.
        let id = Id::default();
        let payload = [0u8; 100];
        let frames: heapless_vec::Vec8<Frame> = V2Fragmenter::new(id, 1, 0, &payload).collect();
        let mut expected_fc = 1u32;
        for i in 1..frames.len() {
            let fc = (frames.get(i).id >> V2_FC_OFFSET) & V2_FC_MASK;
            assert_eq!(fc, expected_fc & V2_FC_MASK, "frame {i}");
            expected_fc += 1;
        }
        assert!(expected_fc > 8, "test did not actually reach a wrap");
    }

    #[test]
    fn v2_fragmentation_covers_the_payload_exactly() {
        let id = Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        };
        for total in [0usize, 1, 4, 5, 12, 13, 100] {
            let payload: heapless_vec::Vec8<u8> = (0..total).map(|i| (i & 0xff) as u8).collect();
            let frames: heapless_vec::Vec8<Frame> =
                V2Fragmenter::new(id, 5, 0, payload.as_slice()).collect();
            let mut seen = 0usize;
            for i in 0..frames.len() {
                let f = frames.get(i);
                seen += if i == 0 {
                    f.dlc() as usize - V2_EXT_SIZE
                } else {
                    f.dlc() as usize
                };
            }
            assert_eq!(seen, total, "total={total}");
        }
    }

    #[test]
    fn v2_roundtrip_through_reassembly() {
        let id = Id {
            pri: 2,
            flags: 0x10,
            src: 1000,
            dst: 2000,
            dport: 20,
            sport: 10,
        };
        for total in [0usize, 1, 4, 5, 12, 13, 100, 250] {
            let payload: heapless_vec::Vec8<u8> = (0..total)
                .map(|i| (i.wrapping_mul(3) & 0xff) as u8)
                .collect();
            let mut r = V2Reassembler::new();
            let mut out = [0u8; 300];
            let mut done = None;
            for f in V2Fragmenter::new(id, 5, 1, payload.as_slice()) {
                done = r.push(f.id, f.data(), &mut out).unwrap();
            }
            if total == 0 {
                // A zero-length packet is one frame carrying only the header extension.
                let (got, len) = done.expect("even an empty packet completes");
                assert_eq!(got, id);
                assert_eq!(len, 0);
                continue;
            }
            let (got, len) = done.unwrap_or_else(|| panic!("total={total} never completed"));
            assert_eq!(got, id, "total={total}: header");
            assert_eq!(len, total, "total={total}: length");
            assert_eq!(&out[..total], payload.as_slice(), "total={total}: payload");
        }
    }

    #[test]
    fn v2_continuation_without_a_begin_is_refused() {
        let mut r = V2Reassembler::new();
        let mut out = [0u8; 64];
        // fc=1, no begin bit
        let id = (1u32 << V2_FC_OFFSET) | (0 << V2_BEGIN_OFFSET);
        assert_eq!(
            r.push(id, &[1, 2, 3, 4], &mut out),
            Err(Error::NoTransferInProgress)
        );
    }

    #[test]
    fn v2_detects_a_lost_fragment_by_its_counter() {
        let id = Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        };
        let payload = [0u8; 60];
        let frames: heapless_vec::Vec8<Frame> = V2Fragmenter::new(id, 5, 0, &payload).collect();
        assert!(frames.len() >= 3, "need at least three frames to skip one");

        let mut r = V2Reassembler::new();
        let mut out = [0u8; 100];
        r.push(frames.get(0).id, frames.get(0).data(), &mut out)
            .unwrap();
        // skip frame 1, feed frame 2
        let f2 = frames.get(2);
        assert!(
            matches!(
                r.push(f2.id, f2.data(), &mut out),
                Err(Error::UnexpectedOffset { .. })
            ),
            "a gap in the 3-bit fragment counter must be caught"
        );
    }

    #[test]
    fn v2_short_begin_frame_is_refused() {
        let mut r = V2Reassembler::new();
        let mut out = [0u8; 64];
        let id = 1u32 << V2_BEGIN_OFFSET;
        assert_eq!(r.push(id, &[0, 0], &mut out), Err(Error::Truncated));
    }

    #[test]
    fn v2_reports_an_output_buffer_that_is_too_small() {
        let id = Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        };
        let payload = [0u8; 100];
        let mut r = V2Reassembler::new();
        let mut tiny = [0u8; 8];
        let mut err = None;
        for f in V2Fragmenter::new(id, 5, 0, &payload) {
            if let Err(e) = r.push(f.id, f.data(), &mut tiny) {
                err = Some(e);
                break;
            }
        }
        assert!(matches!(err, Some(Error::BufferTooSmall { .. })));
    }

    #[test]
    fn interleaved_transfers_both_survive() {
        // The whole reason the pool exists: on a shared bus, fragments from different
        // senders arrive interleaved. A single reassembler drops both.
        let a = Id {
            pri: 2,
            flags: 0,
            src: 1,
            dst: 8,
            dport: 20,
            sport: 10,
        };
        let b = Id {
            pri: 2,
            flags: 0,
            src: 2,
            dst: 9,
            dport: 21,
            sport: 11,
        };
        let pa = [0xAAu8; 40];
        let pb = [0xBBu8; 40];

        let fa: heapless_vec::Vec8<Frame> = V2Fragmenter::new(a, 5, 0, &pa).collect();
        let fb: heapless_vec::Vec8<Frame> = V2Fragmenter::new(b, 6, 1, &pb).collect();
        assert!(fa.len() > 1 && fb.len() > 1);

        let mut pool: Pbufs<V2Reassembler, 4> = Pbufs::new();
        let mut oa = [0u8; 64];
        let mut ob = [0u8; 64];
        let (mut da, mut db) = (None, None);

        for i in 0..core::cmp::max(fa.len(), fb.len()) {
            if i < fa.len() {
                let f = fa.get(i);
                let r = pool.get_or_create(f.id & V2_CONN_MASK, 0).unwrap();
                if let Some(d) = r.push(f.id, f.data(), &mut oa).unwrap() {
                    da = Some(d);
                    pool.release(f.id & V2_CONN_MASK);
                }
            }
            if i < fb.len() {
                let f = fb.get(i);
                let r = pool.get_or_create(f.id & V2_CONN_MASK, 0).unwrap();
                if let Some(d) = r.push(f.id, f.data(), &mut ob).unwrap() {
                    db = Some(d);
                    pool.release(f.id & V2_CONN_MASK);
                }
            }
        }

        assert_eq!(da.map(|(i, _)| i), Some(a), "transfer A must complete");
        assert_eq!(db.map(|(i, _)| i), Some(b), "transfer B must complete");
        assert_eq!(&oa[..40], &pa[..]);
        assert_eq!(&ob[..40], &pb[..]);
        assert!(pool.is_empty(), "both released");
    }

    #[test]
    fn a_full_pool_refuses_rather_than_evicting_a_transfer_in_progress() {
        let mut pool: Pbufs<V2Reassembler, 2> = Pbufs::new();
        assert!(pool.get_or_create(1, 0).is_some());
        assert!(pool.get_or_create(2, 0).is_some());
        assert!(
            pool.get_or_create(3, 0).is_none(),
            "evicting would corrupt a transfer in progress"
        );
        // an existing key still resolves
        assert!(pool.get_or_create(1, 0).is_some());
    }

    #[test]
    fn abandoned_transfers_are_expired() {
        // A sender that starts a transfer and stops would otherwise hold a slot forever.
        let mut pool: Pbufs<V2Reassembler, 2> = Pbufs::new();
        pool.get_or_create(1, 0).unwrap();
        pool.get_or_create(2, 5_000).unwrap();
        assert_eq!(pool.expire(6_000, 3_000), 1, "only the stale one");
        assert_eq!(pool.len(), 1);
        assert!(
            pool.get_or_create(3, 6_000).is_some(),
            "the slot is reusable"
        );
    }

    #[test]
    fn pool_expiry_survives_the_clock_wrap() {
        let mut pool: Pbufs<V2Reassembler, 2> = Pbufs::new();
        let t = u32::MAX - 100;
        pool.get_or_create(1, t).unwrap();
        assert_eq!(
            pool.expire(t.wrapping_add(50), 3_000),
            0,
            "must not expire merely because the clock wrapped"
        );
    }

    #[test]
    fn all_identifiers_fit_29_bits() {
        let id = Id {
            pri: 3,
            flags: 0x3f,
            src: 16383,
            dst: 16383,
            dport: 63,
            sport: 63,
        };
        for f in V2Fragmenter::new(id, 63, 3, &[0u8; 64]) {
            assert!(f.id < (1 << 29), "CFP2 id overflowed: {:#x}", f.id);
        }
        let v1 = Id {
            pri: 3,
            flags: 0xff,
            src: 31,
            dst: 31,
            dport: 63,
            sport: 63,
        };
        for f in V1Fragmenter::new(hdr(&v1), 31, 31, 1023, &[0u8; 64]) {
            assert!(f.id < (1 << 29), "CFP1 id overflowed: {:#x}", f.id);
        }
    }
}
