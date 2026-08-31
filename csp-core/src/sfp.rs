//! SFP — the Small Fragmentation Protocol, which carries payloads larger than one packet.
//!
//! An SFP fragment is an ordinary CSP packet whose header has [`flags::FRAG`] set and
//! whose payload is followed by an 8-byte trailer:
//!
//! ```text
//! [ payload bytes ][ u32 offset ][ u32 total ]   both big-endian
//! ```
//!
//! Note the trailer goes **after** the payload, not before it — `csp_sfp_header_add`
//! writes at `&packet->data[packet->length]` and then grows `length`.
//!
//! # This flag is what lets one port accept either shape
//!
//! Because `FRAG` lives in the *packet* header, a receiver can tell a whole datagram from
//! the first fragment of a stream by looking at one bit, without the sender having
//! declared anything in advance. That is what makes `Handler::Any` possible.
//!
//! The C gets this half right and then throws it away: `csp_sfp_header_remove` returns
//! NULL the moment `FRAG` is clear, and its caller frees the packet — so a plain datagram
//! delivered to a stream handler is **destroyed**, and the caller sees a misleading
//! `CSP_ERR_SFP`. Here, [`Fragment::parse`] returns [`NotAFragment`](crate::Error) and
//! leaves the payload untouched for the caller to handle as a datagram.

use crate::{Error, Result};

/// Bytes of trailer each fragment carries.
pub const HEADER_LEN: usize = 8;

const RDP_HEADER_LEN: usize = 5;
const CRC32_LEN: usize = 4;
const HMAC_LEN: usize = 4;

/// Largest fragment payload that still fits a `buffer_size` packet with `options` in use.
///
/// `options` is a mask of [`security::opts`](crate::security::opts) — the same bits the C
/// calls `CSP_SO_*`, and **not** the packet header [`flags`](crate::flags), which use
/// different numbers for the same three features.
///
/// Every protocol that appends a trailer competes for the same buffer, and libcsp does no
/// bounds check when appending — this accounting is the only thing keeping the writes in
/// range. Get it wrong and the C overruns the packet.
pub const fn max_mtu(buffer_size: usize, options: u32) -> usize {
    use crate::security::opts;

    let mut overhead = HEADER_LEN;
    if options & opts::RDP_REQ != 0 {
        overhead += RDP_HEADER_LEN;
    }
    if options & opts::CRC32_REQ != 0 {
        overhead += CRC32_LEN;
    }
    if options & opts::HMAC_REQ != 0 {
        overhead += HMAC_LEN;
    }
    buffer_size.saturating_sub(overhead)
}

/// A parsed fragment: where it sits in the reassembled message, and its payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fragment<'a> {
    /// Byte offset of this fragment within the whole message.
    pub offset: u32,
    /// Total size of the whole message.
    pub total: u32,
    /// This fragment's slice of it.
    pub payload: &'a [u8],
}

impl<'a> Fragment<'a> {
    /// Parse a fragment out of a packet payload.
    ///
    /// `is_frag` is the [`flags::FRAG`](crate::flags::FRAG) bit from the packet header.
    /// When it is clear this returns [`Error::NotAFragment`] **without consuming
    /// anything**, so the caller can deliver the same bytes as a datagram.
    pub fn parse(is_frag: bool, data: &'a [u8]) -> Result<Fragment<'a>> {
        if !is_frag {
            return Err(Error::NotAFragment);
        }
        if data.len() < HEADER_LEN {
            return Err(Error::Truncated);
        }
        let split = data.len() - HEADER_LEN;
        let (payload, trailer) = data.split_at(split);
        let offset = u32::from_be_bytes([trailer[0], trailer[1], trailer[2], trailer[3]]);
        let total = u32::from_be_bytes([trailer[4], trailer[5], trailer[6], trailer[7]]);

        // The C checks this too -- an offset past the end is how a malformed stream
        // would otherwise walk off the reassembly buffer.
        if offset > total {
            return Err(Error::OffsetBeyondTotal { offset, total });
        }
        Ok(Fragment {
            offset,
            total,
            payload,
        })
    }

    /// Write `payload` followed by the trailer into `out`, returning bytes written.
    pub fn encode(offset: u32, total: u32, payload: &[u8], out: &mut [u8]) -> Result<usize> {
        let needed = payload.len() + HEADER_LEN;
        if out.len() < needed {
            return Err(Error::BufferTooSmall { needed });
        }
        out[..payload.len()].copy_from_slice(payload);
        out[payload.len()..payload.len() + 4].copy_from_slice(&offset.to_be_bytes());
        out[payload.len() + 4..needed].copy_from_slice(&total.to_be_bytes());
        Ok(needed)
    }

    /// True if this fragment completes the message.
    pub const fn is_last(&self) -> bool {
        self.offset as usize + self.payload.len() >= self.total as usize
    }
}

/// Splits a message into fragments of at most `mtu` payload bytes each.
pub struct Fragmenter<'a> {
    data: &'a [u8],
    mtu: usize,
    offset: usize,
}

impl<'a> Fragmenter<'a> {
    /// Create a fragmenter. `mtu` is the payload budget per fragment, i.e. the value from
    /// [`max_mtu`].
    pub fn new(data: &'a [u8], mtu: usize) -> Result<Self> {
        if mtu == 0 {
            return Err(Error::ZeroMtu);
        }
        Ok(Fragmenter {
            data,
            mtu,
            offset: 0,
        })
    }

    /// Number of fragments this message will produce.
    pub const fn fragment_count(&self) -> usize {
        if self.data.is_empty() {
            0
        } else {
            self.data.len().div_ceil(self.mtu)
        }
    }
}

impl<'a> Iterator for Fragmenter<'a> {
    /// `(offset, total, payload)` — feed straight to [`Fragment::encode`].
    type Item = (u32, u32, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }
        let take = core::cmp::min(self.mtu, self.data.len() - self.offset);
        let chunk = &self.data[self.offset..self.offset + take];
        let off = self.offset as u32;
        self.offset += take;
        Some((off, self.data.len() as u32, chunk))
    }
}

/// Reassembles fragments into a caller-supplied buffer.
///
/// Rejects out-of-order and inconsistent fragments rather than trying to be clever: SFP
/// runs over an ordered transport, so a gap means loss, not reordering.
#[derive(Debug, Clone, Copy)]
pub struct Reassembler {
    expected: u32,
    total: Option<u32>,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    /// Start a new reassembly.
    pub const fn new() -> Self {
        Reassembler {
            expected: 0,
            total: None,
        }
    }

    /// Total message size, once the first fragment has been seen.
    pub const fn total(&self) -> Option<u32> {
        self.total
    }

    /// Bytes accepted so far.
    pub const fn received(&self) -> u32 {
        self.expected
    }

    /// True once every byte has been accepted.
    pub const fn is_complete(&self) -> bool {
        match self.total {
            Some(t) => self.expected >= t,
            None => false,
        }
    }

    /// Accept a fragment, copying its payload into `out` at the right offset.
    ///
    /// Returns `true` when the message is complete.
    pub fn push(&mut self, frag: &Fragment<'_>, out: &mut [u8]) -> Result<bool> {
        match self.total {
            None => {
                if frag.total == 0 {
                    // The C rejects this too: a zero-length transfer carries no data but
                    // would otherwise look complete on arrival.
                    return Err(Error::ZeroTotal);
                }
                self.total = Some(frag.total);
            }
            Some(t) if t != frag.total => {
                return Err(Error::InconsistentTotal {
                    expected: t,
                    got: frag.total,
                })
            }
            Some(_) => {}
        }
        if frag.offset != self.expected {
            return Err(Error::UnexpectedOffset {
                expected: self.expected,
                got: frag.offset,
            });
        }
        if frag.payload.is_empty() {
            return Err(Error::EmptyFragment);
        }
        let end = frag.offset as usize + frag.payload.len();
        if end > frag.total as usize {
            return Err(Error::OffsetBeyondTotal {
                offset: frag.offset,
                total: frag.total,
            });
        }
        if end > out.len() {
            return Err(Error::BufferTooSmall { needed: end });
        }
        out[frag.offset as usize..end].copy_from_slice(frag.payload);
        self.expected = end as u32;
        Ok(self.is_complete())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sfp_encode_refuses_a_short_buffer_and_is_last_and_default() {
        assert!(matches!(
            Fragment::encode(0, 100, b"data", &mut [0u8; HEADER_LEN + 3]),
            Err(Error::BufferTooSmall { .. })
        ));
        let mid = Fragment {
            offset: 0,
            total: 100,
            payload: b"x",
        };
        assert!(!mid.is_last());
        let last = Fragment {
            offset: 96,
            total: 100,
            payload: &[0u8; 4],
        };
        assert!(last.is_last());
        let _ = Reassembler::default();
    }

    use crate::security::opts;

    /// `max_mtu` charges four bytes for CRC32 and four for HMAC, so swapping the two
    /// constants gives the same answer for every input and no MTU test can see it. This
    /// pins the numbers themselves against `csp_types.h`.
    #[test]
    fn option_bits_match_csp_so() {
        assert_eq!(opts::RDP_REQ, 0x0001, "CSP_SO_RDPREQ");
        assert_eq!(opts::HMAC_REQ, 0x0004, "CSP_SO_HMACREQ");
        assert_eq!(opts::CRC32_REQ, 0x0040, "CSP_SO_CRC32REQ");
    }

    #[test]
    fn max_mtu_matches_the_c() {
        // Values from `csp_sfp_opts_max_mtu` with CSP_BUFFER_SIZE=256; also recorded by
        // `sfp::the_fragment_mtu_for_each_option_set` and compared on every corpus run.
        assert_eq!(max_mtu(256, 0), 248);
        assert_eq!(max_mtu(256, opts::RDP_REQ), 243);
        assert_eq!(max_mtu(256, opts::CRC32_REQ), 244);
        assert_eq!(max_mtu(256, opts::HMAC_REQ), 244);
        assert_eq!(max_mtu(256, opts::RDP_REQ | opts::HMAC_REQ), 239);
        assert_eq!(
            max_mtu(256, opts::RDP_REQ | opts::CRC32_REQ | opts::HMAC_REQ),
            235
        );
    }

    #[test]
    fn max_mtu_saturates_instead_of_underflowing() {
        // A tiny buffer must report 0, not wrap to a huge number and authorise a write
        // far past the end.
        assert_eq!(max_mtu(8, 0), 0);
        assert_eq!(
            max_mtu(4, opts::RDP_REQ | opts::CRC32_REQ | opts::HMAC_REQ),
            0
        );
    }

    #[test]
    fn trailer_goes_after_the_payload() {
        let mut out = [0u8; 32];
        let n = Fragment::encode(0, 1, &[0xAA], &mut out).unwrap();
        assert_eq!(n, 9);
        assert_eq!(&out[..n], &[0xAA, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn encode_parse_roundtrip() {
        let payload = b"fragment payload";
        let mut out = [0u8; 64];
        let n = Fragment::encode(16, 100, payload, &mut out).unwrap();
        let f = Fragment::parse(true, &out[..n]).unwrap();
        assert_eq!(f.offset, 16);
        assert_eq!(f.total, 100);
        assert_eq!(f.payload, payload);
    }

    #[test]
    fn a_plain_datagram_is_reported_not_destroyed() {
        // The C frees the packet here and returns a misleading CSP_ERR_SFP.
        let data = b"an ordinary datagram";
        assert_eq!(Fragment::parse(false, data), Err(Error::NotAFragment));
        // and the caller still has its bytes
        assert_eq!(data, b"an ordinary datagram");
    }

    #[test]
    fn truncated_fragment_is_refused() {
        assert_eq!(Fragment::parse(true, &[0u8; 7]), Err(Error::Truncated));
    }

    #[test]
    fn offset_past_total_is_refused() {
        let mut out = [0u8; 32];
        let n = Fragment::encode(200, 100, &[1, 2, 3], &mut out).unwrap();
        assert_eq!(
            Fragment::parse(true, &out[..n]),
            Err(Error::OffsetBeyondTotal {
                offset: 200,
                total: 100
            })
        );
    }

    #[test]
    fn fragmenter_covers_the_message_exactly() {
        let data: [u8; 250] = core::array::from_fn(|i| (i * 3) as u8);
        for mtu in [1usize, 7, 32, 100, 249, 250, 251, 1000] {
            let f = Fragmenter::new(&data, mtu).unwrap();
            let expected = f.fragment_count();
            let mut seen = 0usize;
            let mut count = 0usize;
            for (off, total, chunk) in Fragmenter::new(&data, mtu).unwrap() {
                assert_eq!(off as usize, seen, "mtu={mtu}");
                assert_eq!(total as usize, data.len());
                assert!(chunk.len() <= mtu);
                assert!(!chunk.is_empty());
                seen += chunk.len();
                count += 1;
            }
            assert_eq!(seen, data.len(), "mtu={mtu} did not cover the message");
            assert_eq!(count, expected, "mtu={mtu} fragment_count disagrees");
        }
    }

    #[test]
    fn zero_mtu_is_refused_rather_than_looping_forever() {
        assert!(Fragmenter::new(b"x", 0).is_err());
    }

    #[test]
    fn full_roundtrip_through_reassembly() {
        let data: [u8; 500] = core::array::from_fn(|i| (i * 7) as u8);
        for mtu in [1usize, 13, 64, 248, 499, 500, 501] {
            let mut r = Reassembler::new();
            let mut out = [0u8; 500];
            let mut done = false;
            for (off, total, chunk) in Fragmenter::new(&data, mtu).unwrap() {
                let mut enc = [0u8; 600];
                let n = Fragment::encode(off, total, chunk, &mut enc).unwrap();
                let f = Fragment::parse(true, &enc[..n]).unwrap();
                done = r.push(&f, &mut out).unwrap();
            }
            assert!(done, "mtu={mtu} never completed");
            assert_eq!(out, data, "mtu={mtu} reassembled wrong");
            assert_eq!(r.total(), Some(500));
        }
    }

    #[test]
    fn out_of_order_fragments_are_refused() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 64];
        let f2 = Fragment {
            offset: 8,
            total: 16,
            payload: &[0u8; 8],
        };
        // Second fragment first: SFP runs over an ordered transport, so this is loss.
        // The error says exactly which byte was expected, so a caller can log the gap.
        assert_eq!(
            r.push(&f2, &mut out),
            Err(Error::UnexpectedOffset {
                expected: 0,
                got: 8
            })
        );
    }

    #[test]
    fn inconsistent_total_between_fragments_is_refused() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 64];
        let a = Fragment {
            offset: 0,
            total: 16,
            payload: &[0u8; 8],
        };
        let b = Fragment {
            offset: 8,
            total: 99,
            payload: &[0u8; 8],
        };
        assert!(!r.push(&a, &mut out).unwrap());
        assert_eq!(
            r.push(&b, &mut out),
            Err(Error::InconsistentTotal {
                expected: 16,
                got: 99
            })
        );
    }

    #[test]
    fn zero_total_is_refused() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 8];
        let f = Fragment {
            offset: 0,
            total: 0,
            payload: &[1],
        };
        assert_eq!(r.push(&f, &mut out), Err(Error::ZeroTotal));
    }

    #[test]
    fn a_short_output_buffer_is_reported_not_overrun() {
        let mut r = Reassembler::new();
        let mut out = [0u8; 4];
        let f = Fragment {
            offset: 0,
            total: 16,
            payload: &[0u8; 8],
        };
        assert_eq!(
            r.push(&f, &mut out),
            Err(Error::BufferTooSmall { needed: 8 })
        );
    }
}
