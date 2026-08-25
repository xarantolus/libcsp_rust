//! The built-in service ports.
//!
//! Ping, uptime, free memory, free buffers, reboot — plus CMP on port 0. These are what
//! answers a spacecraft when nothing else will, so they are also the ones that must never
//! misbehave on a malformed request.
//!
//! # The reboot handler reads past the packet
//!
//! `csp_service_handler`'s `CSP_REBOOT` case is:
//!
//! ```c
//! uint32_t magic_word;
//! memcpy(&magic_word, packet->data, sizeof(magic_word));
//! ```
//!
//! **No length check.** A one-byte packet sent to port 4 makes the C read four bytes from
//! a payload that has one, so the comparison against the reboot magic is made partly
//! against whatever the previous user of that buffer left behind. Buffers are pooled and
//! reused, so those bytes are attacker-influenced in the ordinary case.
//!
//! It is not a remote reboot primitive — matching a 32-bit magic by accident is unlikely —
//! but it is an out-of-bounds read on the one port whose whole job is recovery, reachable
//! by anyone who can send a packet. [`Request::decode`] requires the four bytes.

use csp_core::{ports, Error, Result};

/// Reboot magic word.
pub const REBOOT_MAGIC: u32 = 0x8007_8007;
/// Shutdown magic word.
pub const SHUTDOWN_MAGIC: u32 = 0xD1E5_529A;

/// What a service request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Request {
    /// Echo the payload unchanged.
    Ping,
    /// Report free memory, in bytes.
    MemFree,
    /// Report free packet buffers.
    BufFree,
    /// Report uptime, in seconds.
    Uptime,
    /// Report the process list.
    Ps,
    /// Reboot the node.
    Reboot,
    /// Power down the node.
    Shutdown,
    /// A CMP message; the payload is handed to [`csp_core::cmp`].
    Cmp,
}

impl Request {
    /// Classify a request by port and payload.
    ///
    /// Returns [`Error::FieldOutOfRange`] for a port with no built-in service, so the
    /// caller can fall through to its own handlers rather than guessing.
    pub fn decode(port: u8, payload: &[u8]) -> Result<Request> {
        match port {
            ports::CMP => Ok(Request::Cmp),
            ports::PING => Ok(Request::Ping),
            ports::PS => Ok(Request::Ps),
            ports::MEMFREE => Ok(Request::MemFree),
            ports::BUF_FREE => Ok(Request::BufFree),
            ports::UPTIME => Ok(Request::Uptime),
            ports::REBOOT => {
                // The length check the C does not do.
                if payload.len() < 4 {
                    return Err(Error::Truncated);
                }
                let magic = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
                match magic {
                    REBOOT_MAGIC => Ok(Request::Reboot),
                    SHUTDOWN_MAGIC => Ok(Request::Shutdown),
                    // A wrong magic is not an error to report back — answering would tell
                    // an unauthenticated prober that the port exists. The C also stays
                    // silent here.
                    _ => Err(Error::BadChecksum),
                }
            }
            _ => Err(Error::FieldOutOfRange {
                field: csp_core::Field::DestinationPort,
            }),
        }
    }

    /// True if this request produces a reply.
    ///
    /// Reboot and shutdown do not: there would be nothing left to send it.
    pub const fn has_reply(&self) -> bool {
        !matches!(self, Request::Reboot | Request::Shutdown)
    }
}

/// What a node knows about itself, for the services that report it.
///
/// Supplied by the caller rather than read from hooks that resolve to `__weak` symbols —
/// libcsp has **two** `__weak` definitions of `csp_input_hook` in one library, so which
/// implementation runs is link-order dependent.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeStatus {
    /// Free memory in bytes.
    pub mem_free: u32,
    /// Free packet buffers.
    pub buf_free: u32,
    /// Uptime in seconds.
    pub uptime_s: u32,
}

/// Encode a `u32` reply, as the C's `set_u32_reply` does: four big-endian bytes.
pub fn encode_u32_reply(value: u32, out: &mut [u8]) -> Result<usize> {
    if out.len() < 4 {
        return Err(Error::BufferTooSmall { needed: 4 });
    }
    out[..4].copy_from_slice(&value.to_be_bytes());
    Ok(4)
}

/// Build the reply to a request, returning its length.
///
/// `request` is the incoming payload; for [`Request::Ping`] it is echoed unchanged.
/// Returns `Ok(None)` for requests that produce no reply.
pub fn respond(
    req: Request,
    request_payload: &[u8],
    status: &NodeStatus,
    out: &mut [u8],
) -> Result<Option<usize>> {
    match req {
        Request::Ping => {
            // Echo verbatim. A ping is how you find out whether the packet path works at
            // all, so it must not reinterpret the payload.
            if out.len() < request_payload.len() {
                return Err(Error::BufferTooSmall {
                    needed: request_payload.len(),
                });
            }
            out[..request_payload.len()].copy_from_slice(request_payload);
            Ok(Some(request_payload.len()))
        }
        Request::MemFree => Ok(Some(encode_u32_reply(status.mem_free, out)?)),
        Request::BufFree => Ok(Some(encode_u32_reply(status.buf_free, out)?)),
        Request::Uptime => Ok(Some(encode_u32_reply(status.uptime_s, out)?)),
        Request::Ps => Ok(Some(0)),
        Request::Reboot | Request::Shutdown => Ok(None),
        Request::Cmp => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> NodeStatus {
        NodeStatus {
            mem_free: 4096,
            buf_free: 12,
            uptime_s: 3600,
        }
    }

    #[test]
    fn ports_map_to_their_services() {
        assert_eq!(Request::decode(ports::PING, b"").unwrap(), Request::Ping);
        assert_eq!(Request::decode(ports::CMP, b"").unwrap(), Request::Cmp);
        assert_eq!(Request::decode(ports::PS, b"").unwrap(), Request::Ps);
        assert_eq!(
            Request::decode(ports::MEMFREE, b"").unwrap(),
            Request::MemFree
        );
        assert_eq!(
            Request::decode(ports::BUF_FREE, b"").unwrap(),
            Request::BufFree
        );
        assert_eq!(
            Request::decode(ports::UPTIME, b"").unwrap(),
            Request::Uptime
        );
    }

    #[test]
    fn an_unserviced_port_says_so_rather_than_guessing() {
        assert!(matches!(
            Request::decode(39, b""),
            Err(Error::FieldOutOfRange { .. })
        ));
    }

    #[test]
    fn a_short_reboot_request_is_refused_instead_of_reading_past_the_payload() {
        // The C memcpys 4 bytes unconditionally, so a 1-byte packet compares against
        // whatever the previous user of that pooled buffer left behind.
        for len in 0..4usize {
            let payload = [0x80u8; 4];
            assert_eq!(
                Request::decode(ports::REBOOT, &payload[..len]),
                Err(Error::Truncated),
                "a {len}-byte reboot request must be refused"
            );
        }
    }

    #[test]
    fn the_reboot_magic_must_match_exactly() {
        assert_eq!(
            Request::decode(ports::REBOOT, &REBOOT_MAGIC.to_be_bytes()).unwrap(),
            Request::Reboot
        );
        assert_eq!(
            Request::decode(ports::REBOOT, &SHUTDOWN_MAGIC.to_be_bytes()).unwrap(),
            Request::Shutdown
        );
        // one bit off
        let mut wrong = REBOOT_MAGIC.to_be_bytes();
        wrong[3] ^= 0x01;
        assert_eq!(
            Request::decode(ports::REBOOT, &wrong),
            Err(Error::BadChecksum)
        );
    }

    #[test]
    fn a_longer_reboot_request_still_reads_only_the_magic() {
        let mut payload = [0u8; 32];
        payload[..4].copy_from_slice(&REBOOT_MAGIC.to_be_bytes());
        assert_eq!(
            Request::decode(ports::REBOOT, &payload).unwrap(),
            Request::Reboot
        );
    }

    #[test]
    fn reboot_and_shutdown_produce_no_reply() {
        // There would be nothing left to send it with.
        assert!(!Request::Reboot.has_reply());
        assert!(!Request::Shutdown.has_reply());
        let mut out = [0u8; 16];
        assert_eq!(
            respond(Request::Reboot, b"", &status(), &mut out).unwrap(),
            None
        );
    }

    #[test]
    fn ping_echoes_the_payload_verbatim() {
        // A ping is how you find out whether the packet path works at all, so it must not
        // reinterpret what it was sent.
        let mut out = [0u8; 64];
        for payload in [&b""[..], b"x", b"\x00\xff\x00\xff", &[0xAA; 40]] {
            let n = respond(Request::Ping, payload, &status(), &mut out)
                .unwrap()
                .unwrap();
            assert_eq!(&out[..n], payload);
        }
    }

    #[test]
    fn ping_reports_a_short_buffer_rather_than_truncating() {
        let mut out = [0u8; 4];
        assert_eq!(
            respond(Request::Ping, &[0u8; 40], &status(), &mut out),
            Err(Error::BufferTooSmall { needed: 40 })
        );
    }

    #[test]
    fn u32_replies_are_big_endian() {
        let mut out = [0u8; 8];
        for (req, expected) in [
            (Request::MemFree, 4096u32),
            (Request::BufFree, 12),
            (Request::Uptime, 3600),
        ] {
            let n = respond(req, b"", &status(), &mut out).unwrap().unwrap();
            assert_eq!(n, 4);
            assert_eq!(&out[..4], &expected.to_be_bytes(), "{req:?}");
        }
    }

    #[test]
    fn a_short_reply_buffer_is_reported() {
        let mut out = [0u8; 3];
        assert_eq!(
            respond(Request::Uptime, b"", &status(), &mut out),
            Err(Error::BufferTooSmall { needed: 4 })
        );
    }

    #[test]
    fn arbitrary_requests_never_panic() {
        let status = status();
        let mut out = [0u8; 64];
        let mut x: u32 = 0x5E12_0001;
        let mut payload = [0u8; 40];
        for _ in 0..50_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            let port = x as u8;
            let n = (x as usize) % payload.len();
            for (i, b) in payload.iter_mut().enumerate() {
                *b = (x >> (i % 24)) as u8;
            }
            if let Ok(req) = Request::decode(port, &payload[..n]) {
                let _ = respond(req, &payload[..n], &status, &mut out);
            }
        }
    }
}
