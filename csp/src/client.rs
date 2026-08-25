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
/// The C's `csp_ping` compares only the *length*, so a path that corrupts every byte but
/// preserves the length passes.
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
#[cfg(feature = "cmp")]
pub fn cmp_request(code: u8, body: &[u8], out: &mut [u8]) -> Result<usize> {
    let needed = cmp::Header::LEN + body.len();
    if out.len() < needed {
        return Err(Error::BufferTooSmall { needed });
    }
    out[0] = cmp::REQUEST;
    out[1] = code;
    out[cmp::Header::LEN..needed].copy_from_slice(body);
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
        assert_eq!(reboot().payload, &crate::service::REBOOT_MAGIC.to_be_bytes());
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
        // csp_ping compares only the LENGTH, so a path that corrupts every byte while
        // preserving the length passes.
        let sent = b"abcdefgh";
        assert!(check_ping(sent, b"abcdefgh").is_ok());
        assert_eq!(check_ping(sent, b"abcdefgX"), Err(Error::BadChecksum));
        assert!(
            matches!(check_ping(sent, b"abc"), Err(Error::LengthExceedsMaximum { .. })),
            "a short reply is a different failure from a corrupted one"
        );
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
        for (req, expected) in [
            (uptime(), 3600u32),
            (memfree(), 4096),
            (buf_free(), 12),
        ] {
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
        let mut out = [0u8; 32];
        let n = cmp_request(cmp::code::IDENT, &[], &mut out).unwrap();
        assert_eq!(n, 2);
        let h = cmp::Header::decode(&out[..n]).unwrap();
        assert_eq!(h.kind, cmp::REQUEST);
        assert!(!h.is_reply());
        assert_eq!(h.code, cmp::code::IDENT);
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
        assert_eq!(check_cmp_reply(cmp::code::IDENT, &[0xff]), Err(Error::Truncated));
    }
}
