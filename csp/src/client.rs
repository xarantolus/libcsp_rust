//! Issuing the built-in service requests.
//!
//! [`service`](crate::service) answers them; this builds them. The two halves are
//! separate because a flight node is usually both — it answers pings from the ground and
//! sends its own to the payload.
//!
//! Every function here builds a **request payload** and interprets a **reply payload**.
//! Sending is the caller's, via [`Node::send`](crate::Node::send), for the same reason the
//! rest of the crate works that way: it keeps the transport out of the protocol.

use csp_core::{ports, Error, Result};

#[cfg(feature = "cmp")]
use csp_core::cmp;

/// A request to send: which port, and what payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    /// Destination port.
    pub port: u8,
    /// Payload bytes.
    pub payload: &'a [u8],
}

/// Build a ping.
///
/// The payload is echoed back verbatim, so its content is the check: a ping whose reply
/// differs tells you the path corrupts data, which a zero-length ping cannot.
pub fn ping(payload: &[u8]) -> Request<'_> {
    Request {
        port: ports::PING,
        payload,
    }
}

/// Verify a ping reply against what was sent.
///
/// The C's `csp_ping` gets this half right and half wrong. It **does** verify the content
/// — it fills the request with `i % 256` and checks every byte of the reply against that
/// pattern. What it never checks is the reply's **length**: the loop runs to `size`, the
/// size that was *requested*, and indexes `packet->data[i]` regardless of
/// `packet->length`. A short reply is therefore compared against stale bytes left in the
/// pooled buffer by whatever used it last. Usually those fail the pattern and the ping
/// correctly reports failure, but the comparison is reading data that is not part of the
/// reply.
///
/// This checks the length first, then the content.
pub fn check_ping(sent: &[u8], reply: &[u8]) -> Result<()> {
    if reply.len() != sent.len() {
        return Err(Error::LengthExceedsMaximum {
            got: reply.len(),
            max: sent.len(),
        });
    }
    if reply != sent {
        return Err(Error::BadChecksum);
    }
    Ok(())
}

/// The single byte `csp_ping_noreply` sends.
pub const PING_NOREPLY_PAYLOAD: [u8; 1] = [0x55];

/// Build a fire-and-forget ping.
///
/// `csp_ping_noreply`: one 0x55 byte to the ping port, with no reply expected and no
/// connection kept open. Used to poke a node whose reply path may not work — after a
/// radio reconfiguration, say — where the useful signal is whether the *node* reacts, not
/// whether the packet comes back.
///
/// The C opens the connection with `CSP_O_CRC32` while `csp_ping` takes its options from
/// the caller, so the no-reply variant is the more strongly protected of the two.
pub const fn ping_noreply() -> Request<'static> {
    Request {
        port: ports::PING,
        payload: &PING_NOREPLY_PAYLOAD,
    }
}

/// Build a request for free memory.
pub const fn memfree() -> Request<'static> {
    Request {
        port: ports::MEMFREE,
        payload: &[],
    }
}

/// Build a request for free packet buffers.
pub const fn buf_free() -> Request<'static> {
    Request {
        port: ports::BUF_FREE,
        payload: &[],
    }
}

/// Build a request for uptime in seconds.
pub const fn uptime() -> Request<'static> {
    Request {
        port: ports::UPTIME,
        payload: &[],
    }
}

/// Build a request for the process list.
pub const fn ps() -> Request<'static> {
    Request {
        port: ports::PS,
        payload: &[],
    }
}

/// Decode a `u32` reply — memfree, buf_free and uptime all use this shape.
pub fn decode_u32(reply: &[u8]) -> Result<u32> {
    if reply.len() < 4 {
        return Err(Error::Truncated);
    }
    Ok(u32::from_be_bytes([reply[0], reply[1], reply[2], reply[3]]))
}

/// The reboot magic word, big-endian, ready to send to [`ports::REBOOT`].
pub const REBOOT_PAYLOAD: [u8; 4] = crate::service::REBOOT_MAGIC.to_be_bytes();
/// The shutdown magic word.
pub const SHUTDOWN_PAYLOAD: [u8; 4] = crate::service::SHUTDOWN_MAGIC.to_be_bytes();

/// Build a reboot request.
///
/// There is no reply — the node reboots. A caller waiting for one waits forever.
pub const fn reboot() -> Request<'static> {
    Request {
        port: ports::REBOOT,
        payload: &REBOOT_PAYLOAD,
    }
}

/// Build a shutdown request.
pub const fn shutdown() -> Request<'static> {
    Request {
        port: ports::REBOOT,
        payload: &SHUTDOWN_PAYLOAD,
    }
}

/// Build a CMP request into `out`, returning its length.
///
/// The reply is decoded with the matching type in [`csp_core::cmp`].
///
/// **The request is padded to [`cmp::request_len`] for the code**, which is usually the
/// size of the whole *reply*, because the node writes its answer back into the buffer the
/// request arrived in and refuses to start if that buffer is too small. A request shorter
/// than that is discarded by a real node **with no reply and no error** — the caller just
/// waits out its timeout.
///
/// This used to emit `2 + body.len()`, so `cmp_request(code::IDENT, &[], …)` produced two
/// bytes that no libcsp node would ever answer. The padding is zeroed, matching what the
/// C's own clients send: `csp_cmp_ident` passes `sizeof(struct csp_cmp_ident_msg)`.
#[cfg(feature = "cmp")]
pub fn cmp_request(code: u8, body: &[u8], out: &mut [u8]) -> Result<usize> {
    let supplied = cmp::Header::LEN + body.len();
    let needed = if supplied > cmp::request_len(code) {
        supplied
    } else {
        cmp::request_len(code)
    };
    if out.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }
    out[0] = cmp::REQUEST;
    out[1] = code;
    out[cmp::Header::LEN..supplied].copy_from_slice(body);
    out[supplied..needed].fill(0);
    Ok(needed)
}

/// Check that a CMP reply answers the request that was sent.
///
/// The C does not do this: `csp_cmp` returns whatever came back on the connection, so a
/// reply to an *earlier* request on the same connection is accepted as the answer to this
/// one — and the caller then reads it as the wrong message type.
#[cfg(feature = "cmp")]
pub fn check_cmp_reply(sent_code: u8, reply: &[u8]) -> Result<cmp::Header> {
    let h = cmp::Header::decode(reply)?;
    if !h.is_reply() {
        return Err(Error::NotAReply { got: h.kind });
    }
    if h.code != sent_code {
        return Err(Error::IdentMismatch {
            expected: sent_code as u16,
            got: h.code as u16,
        });
    }
    Ok(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_target_the_right_ports() {
        assert_eq!(ping(b"x").port, ports::PING);
        assert_eq!(memfree().port, ports::MEMFREE);
        assert_eq!(buf_free().port, ports::BUF_FREE);
        assert_eq!(uptime().port, ports::UPTIME);
        assert_eq!(ps().port, ports::PS);
        assert_eq!(reboot().port, ports::REBOOT);
        assert_eq!(shutdown().port, ports::REBOOT);
    }

    #[test]
    fn reboot_and_shutdown_differ_only_in_the_magic() {
        assert_ne!(reboot().payload, shutdown().payload);
        assert_eq!(
            reboot().payload,
            &crate::service::REBOOT_MAGIC.to_be_bytes()
        );
        assert_eq!(
            shutdown().payload,
            &crate::service::SHUTDOWN_MAGIC.to_be_bytes()
        );
    }

    #[test]
    fn the_reboot_request_is_exactly_what_the_server_accepts() {
        // The two halves must agree, or a reboot silently does nothing.
        use crate::service::Request as SvcRequest;
        let r = reboot();
        assert_eq!(
            SvcRequest::decode(r.port, r.payload).unwrap(),
            SvcRequest::Reboot
        );
        let s = shutdown();
        assert_eq!(
            SvcRequest::decode(s.port, s.payload).unwrap(),
            SvcRequest::Shutdown
        );
    }

    #[test]
    fn a_ping_reply_must_match_byte_for_byte() {
        // The C verifies content but never checks the reply's length -- its loop runs to
        // the REQUESTED size and reads past packet->length into stale buffer bytes.
        let sent = b"abcdefgh";
        assert!(check_ping(sent, b"abcdefgh").is_ok());
        assert_eq!(check_ping(sent, b"abcdefgX"), Err(Error::BadChecksum));
        assert!(
            matches!(
                check_ping(sent, b"abc"),
                Err(Error::LengthExceedsMaximum { .. })
            ),
            "a short reply is a different failure from a corrupted one"
        );
    }

    #[test]
    fn a_short_reply_is_refused_rather_than_compared_against_stale_bytes() {
        // This is the C's actual defect: its loop runs to the requested size and indexes
        // packet->data[i] without consulting packet->length, so a truncated reply is
        // compared against whatever the previous user of that pooled buffer left behind.
        let sent = [0u8, 1, 2, 3, 4, 5, 6, 7];
        // A truncated but otherwise correct prefix must still be refused.
        assert!(matches!(
            check_ping(&sent, &sent[..4]),
            Err(Error::LengthExceedsMaximum { got: 4, max: 8 })
        ));
        // And a longer-than-expected reply is refused too.
        let long = [0u8, 1, 2, 3, 4, 5, 6, 7, 8];
        assert!(check_ping(&sent, &long).is_err());
    }

    #[test]
    fn a_no_reply_ping_is_one_byte_to_the_ping_port() {
        // csp_ping_noreply: poke the node, do not wait. Useful when the reply path may
        // not work -- after a radio reconfiguration -- and the signal is whether the node
        // reacts at all.
        let r = ping_noreply();
        assert_eq!(r.port, ports::PING);
        assert_eq!(r.payload, &[0x55]);
    }

    #[test]
    fn a_no_reply_ping_is_still_a_ping_the_server_answers() {
        // It expects no reply, but it is not a different message: a node that does answer
        // must produce a valid echo, or the two halves have drifted apart.
        use crate::service::{respond, NodeStatus, Request as SvcRequest};
        let r = ping_noreply();
        let svc = SvcRequest::decode(r.port, r.payload).unwrap();
        let mut out = [0u8; 8];
        let n = respond(svc, r.payload, &NodeStatus::default(), &mut out)
            .unwrap()
            .unwrap();
        assert!(check_ping(r.payload, &out[..n]).is_ok());
    }

    #[test]
    fn an_empty_ping_still_round_trips() {
        assert!(check_ping(b"", b"").is_ok());
    }

    #[test]
    fn u32_replies_decode_big_endian() {
        assert_eq!(decode_u32(&[0x01, 0x02, 0x03, 0x04]).unwrap(), 0x0102_0304);
        assert_eq!(decode_u32(&[0, 0, 0, 0]).unwrap(), 0);
    }

    #[test]
    fn a_short_u32_reply_is_refused_rather_than_padded() {
        assert_eq!(decode_u32(&[1, 2, 3]), Err(Error::Truncated));
        assert_eq!(decode_u32(&[]), Err(Error::Truncated));
    }

    #[test]
    fn a_client_request_round_trips_through_the_server() {
        // End to end: what the client builds, the server answers, the client decodes.
        use crate::service::{respond, NodeStatus, Request as SvcRequest};
        let status = NodeStatus {
            mem_free: 4096,
            buf_free: 12,
            uptime_s: 3600,
        };
        for (req, expected) in [(uptime(), 3600u32), (memfree(), 4096), (buf_free(), 12)] {
            let svc = SvcRequest::decode(req.port, req.payload).unwrap();
            let mut out = [0u8; 16];
            let n = respond(svc, req.payload, &status, &mut out)
                .unwrap()
                .unwrap();
            assert_eq!(decode_u32(&out[..n]).unwrap(), expected);
        }
    }

    #[test]
    fn a_ping_round_trips_through_the_server() {
        use crate::service::{respond, NodeStatus, Request as SvcRequest};
        let payload = b"round trip check";
        let req = ping(payload);
        let svc = SvcRequest::decode(req.port, req.payload).unwrap();
        let mut out = [0u8; 64];
        let n = respond(svc, req.payload, &NodeStatus::default(), &mut out)
            .unwrap()
            .unwrap();
        assert!(check_ping(payload, &out[..n]).is_ok());
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn a_cmp_request_carries_the_request_marker() {
        let mut out = [0u8; 128];
        let n = cmp_request(cmp::code::IDENT, &[], &mut out).unwrap();
        let h = cmp::Header::decode(&out[..n]).unwrap();
        assert_eq!(h.kind, cmp::REQUEST);
        assert!(!h.is_reply());
        assert_eq!(h.code, cmp::code::IDENT);
    }

    /// A request has to be big enough to hold the reply the node will write back into it,
    /// or a real node discards it without answering. This test previously asserted
    /// `n == 2` for an `IDENT` request — the length libcsp is guaranteed *not* to answer.
    /// Measured in `ctest/suite_cmp.c`.
    #[cfg(feature = "cmp")]
    #[test]
    fn a_cmp_request_is_padded_to_what_the_node_will_answer() {
        let mut out = [0u8; 128];

        let n = cmp_request(cmp::code::IDENT, &[], &mut out).unwrap();
        assert_eq!(n, cmp::Ident::LEN, "IDENT needs room for the whole reply");
        assert!(out[2..n].iter().all(|&b| b == 0), "padding must be zeroed");

        let n = cmp_request(cmp::code::CLOCK, &[], &mut out).unwrap();
        assert_eq!(n, cmp::Timestamp::LEN);

        // IF_STATS is the one code whose handler stops checking at the interface name.
        let n = cmp_request(cmp::code::IF_STATS, &[], &mut out).unwrap();
        assert_eq!(n, cmp::IfStatsMsg::REQUEST_LEN);

        // A body longer than the minimum is not truncated to it.
        let n = cmp_request(cmp::code::POKE, &[0xAA; 40], &mut out).unwrap();
        assert_eq!(n, cmp::Header::LEN + 40);

        // An unknown code has no handler, so there is nothing to pad for.
        let n = cmp_request(200, &[], &mut out).unwrap();
        assert_eq!(n, cmp::Header::LEN);
    }

    /// The buffer-too-small error has to report the padded size, or a caller that retries
    /// with exactly `needed` fails again.
    #[cfg(feature = "cmp")]
    #[test]
    fn a_short_buffer_reports_the_padded_size() {
        let mut out = [0u8; 8];
        assert_eq!(
            cmp_request(cmp::code::IDENT, &[], &mut out),
            Err(Error::BufferTooSmall {
                needed: cmp::Ident::LEN
            })
        );
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn a_cmp_reply_for_a_different_request_is_refused() {
        // csp_cmp returns whatever came back on the connection, so a reply to an EARLIER
        // request is accepted as the answer to this one and read as the wrong type.
        let mut reply = [0u8; 8];
        reply[0] = cmp::REPLY;
        reply[1] = cmp::code::CLOCK;
        assert!(matches!(
            check_cmp_reply(cmp::code::IDENT, &reply),
            Err(Error::IdentMismatch { .. })
        ));
        assert!(check_cmp_reply(cmp::code::CLOCK, &reply).is_ok());
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn a_request_echoed_back_is_not_a_reply() {
        let mut echoed = [0u8; 8];
        echoed[0] = cmp::REQUEST;
        echoed[1] = cmp::code::IDENT;
        assert_eq!(
            check_cmp_reply(cmp::code::IDENT, &echoed),
            Err(Error::NotAReply { got: cmp::REQUEST }),
            "a request where a reply was expected is its own failure, not a code mismatch"
        );
    }

    #[cfg(feature = "cmp")]
    #[test]
    fn a_truncated_cmp_reply_is_refused() {
        assert_eq!(
            check_cmp_reply(cmp::code::IDENT, &[0xff]),
            Err(Error::Truncated)
        );
    }
}
