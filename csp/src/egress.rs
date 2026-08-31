//! What every packet this node originates has appended before it reaches a wire.
//!
//! `csp_send_direct_iface` appends the HMAC and then the CRC32 to any packet with the
//! matching flag, guarded by `if (from_me)` (`csp_io.c:249-271`) — so forwarded traffic
//! passes through untouched and only what this node originated is protected. Both trailers
//! deliberately exclude the header; libcsp says why: backwards compatibility with csp1.x.
//!
//! This lived nowhere before. `connect` set the flags and `reply_to` copied them, and the
//! bytes were never appended, so every packet the port sent with `CSP_FCRC32` or `CSP_FHMAC`
//! was a packet a real libcsp peer verified, failed and dropped inside its own router —
//! before any application saw it. libcsp's own CMP client always asks with `CSP_O_CRC32`
//! (`csp_services.c:218`), so **no stock ground station could read this node's IDENT,
//! IF_STATS, CLOCK, PEEK or ROUTE_SET at all**, and it looked like a timeout rather than an
//! error. `difftest/tests/node_cmp_if_stats.rs` is the test that found it.

use crate::pool::Packet;
use csp_core::{flags, Error, Result};

/// Append the trailers `flags` promises, in the order `csp_send_direct_iface` appends them.
///
/// `key` is the node's HMAC key; `Err` when a MAC was asked for and there is none, or when
/// the buffer cannot hold the trailer. The C treats both as `tx_err`: the packet is freed
/// and `tx_error` counted, never sent claiming a protection it does not carry.
pub(crate) fn protect<const B: usize, const SZ: usize>(
    packet: &mut Packet<'_, B, SZ>,
    flags: u8,
    key: Option<&[u8]>,
) -> Result<()> {
    if flags & (flags::HMAC | flags::CRC32) == 0 {
        return Ok(());
    }
    // `with_payload_mut` is handed the whole buffer and returns the new length, so the
    // current one has to be read first.
    let len = packet.with_payload(|p| p.len());
    packet.with_payload_mut(|buf| {
        let mut n = len;
        #[cfg(feature = "hmac")]
        if flags & flags::HMAC != 0 {
            let Some(k) = key else {
                return (len, Err(Error::EmptyKey));
            };
            let mac = match csp_core::hmac::mac_over(
                k,
                &[],
                &buf[..n],
                csp_core::crc32::Coverage::PayloadOnly,
            ) {
                Ok(m) => m,
                Err(e) => return (len, Err(e)),
            };
            if n + mac.len() > buf.len() {
                return (
                    len,
                    Err(Error::BufferTooSmall {
                        needed: n + mac.len(),
                    }),
                );
            }
            buf[n..n + mac.len()].copy_from_slice(&mac);
            n += mac.len();
        }
        // `csp_io.c:259-260`: a build without HMAC support refuses the send rather than
        // emitting a packet that claims a MAC it cannot produce.
        #[cfg(not(feature = "hmac"))]
        if flags & flags::HMAC != 0 {
            let _ = key;
            return (
                len,
                Err(Error::Unsupported {
                    feature: csp_core::Feature::Hmac,
                }),
            );
        }
        if flags & flags::CRC32 != 0 {
            let sum = csp_core::crc32::checksum(&buf[..n]).to_be_bytes();
            if n + sum.len() > buf.len() {
                return (
                    len,
                    Err(Error::BufferTooSmall {
                        needed: n + sum.len(),
                    }),
                );
            }
            buf[n..n + sum.len()].copy_from_slice(&sum);
            n += sum.len();
        }
        (n, Ok(()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::{Pool, PADDING};
    use csp_core::flags;

    /// A pool of one slot, sized so a full payload leaves no room for a trailer.
    const SZ: usize = PADDING + 20;
    const CAP: usize = SZ - PADDING;

    fn full_packet(pool: &Pool<1, SZ>) -> Packet<'_, 1, SZ> {
        let mut p = pool.acquire(0).expect("a slot");
        p.set_payload(&[0xABu8; CAP]).expect("a full payload");
        p
    }

    #[test]
    fn a_crc32_trailer_that_will_not_fit_is_refused_cleanly() {
        let pool = Pool::<1, SZ>::new();
        let mut p = full_packet(&pool);
        // The payload already fills the buffer; the four-byte CRC cannot be appended.
        match protect(&mut p, flags::CRC32, None) {
            Err(Error::BufferTooSmall { needed }) => {
                assert_eq!(
                    needed,
                    CAP + csp_core::crc32::CRC32_LEN,
                    "reports the real need"
                );
            }
            other => panic!("a full buffer must refuse the CRC, got {other:?}"),
        }
        // The payload is untouched: a refused protect must not corrupt what it could not extend.
        assert!(p.with_payload(|b| b == [0xAB; CAP]), "payload untouched");
    }

    #[cfg(feature = "hmac")]
    #[test]
    fn an_hmac_trailer_that_will_not_fit_is_refused_cleanly() {
        let pool = Pool::<1, SZ>::new();
        let mut p = full_packet(&pool);
        let key = [0x11u8; 16];
        match protect(&mut p, flags::HMAC, Some(&key)) {
            Err(Error::BufferTooSmall { needed }) => {
                assert!(
                    needed > CAP,
                    "the MAC pushes the need past the buffer: {needed}"
                );
            }
            other => panic!("a full buffer must refuse the MAC, got {other:?}"),
        }
        assert!(p.with_payload(|b| b == [0xAB; CAP]), "payload untouched");
    }

    #[test]
    fn no_protection_flags_is_a_no_op() {
        let pool = Pool::<1, SZ>::new();
        let mut p = full_packet(&pool);
        assert!(
            protect(&mut p, 0, None).is_ok(),
            "nothing to append, nothing refused"
        );
        assert!(p.with_payload(|b| b.len() == CAP), "payload unchanged");
    }
}
