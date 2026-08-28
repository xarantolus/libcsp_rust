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
