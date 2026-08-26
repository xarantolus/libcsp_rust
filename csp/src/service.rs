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

#[cfg(feature = "cmp")]
use crate::hooks::Hooks;
#[cfg(feature = "cmp")]
use csp_core::cmp::{self, Header, Ident, IfStatsMsg, Query, RouteSetV1, RouteSetV2};
#[cfg(feature = "cmp")]
use csp_core::Version;
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
pub struct NodeStatus<'a> {
    /// Free memory in bytes.
    pub mem_free: u32,
    /// Free packet buffers.
    pub buf_free: u32,
    /// Uptime in seconds.
    pub uptime_s: u32,
    /// Process list, as `csp_ps_hook` would have filled it.
    ///
    /// Empty means "cannot answer", which the C treats as a discard rather than as an
    /// empty reply -- `csp_service_handler` does `if (packet->length == 0) goto discard`.
    /// A zero-length reply and no reply look the same to a peer only if it never times
    /// out; to one that does, an empty packet is a node claiming to have no processes.
    pub ps: &'a [u8],
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
    status: &NodeStatus<'_>,
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
        Request::Ps => {
            if status.ps.is_empty() {
                return Ok(None);
            }
            if out.len() < status.ps.len() {
                return Err(Error::BufferTooSmall {
                    needed: status.ps.len(),
                });
            }
            out[..status.ps.len()].copy_from_slice(status.ps);
            Ok(Some(status.ps.len()))
        }
        Request::Reboot | Request::Shutdown => Ok(None),
        Request::Cmp => Ok(None),
    }
}

#[cfg(feature = "cmp")]
/// What a node calls itself, for CMP `IDENT`.
///
/// The C reads `csp_conf.{hostname,model,revision}` and splices `__DATE__`/`__TIME__` in at
/// compile time. Both are supplied here instead: a build timestamp baked into the binary is
/// exactly the kind of thing that makes a build unreproducible, and an application that
/// wants one can pass it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Identity<'a> {
    /// Node hostname.
    pub hostname: &'a str,
    /// Hardware model.
    pub model: &'a str,
    /// Software revision.
    pub revision: &'a str,
    /// Build date, or empty.
    pub date: &'a str,
    /// Build time, or empty.
    pub time: &'a str,
}

#[cfg(feature = "cmp")]
/// Build the reply to a CMP request, returning its length.
///
/// This is `csp_cmp_handler` plus the reply-or-discard decision `csp_service_handler` makes
/// around it. `Ok(None)` means **send nothing** — the C's `goto discard`, which is how it
/// answers every refusal: an unknown interface, a route it would not install, a clock it
/// could not set, a memory window the application does not expose. None of them get an
/// error reply, so a peer cannot distinguish "refused" from "not listening" without a
/// timeout, and this port keeps that property rather than volunteering the difference.
///
/// `version` decides the netmask for the v1 route form, which the C takes from
/// `csp_id_get_host_bits()` rather than from the request.
pub fn respond_cmp<const B: usize, const SZ: usize, H: Hooks<B, SZ>>(
    query: Query<'_>,
    identity: &Identity<'_>,
    version: Version,
    hooks: &mut H,
    out: &mut [u8],
) -> Result<Option<usize>> {
    match query {
        Query::Ident => {
            let msg = Ident {
                hostname: identity.hostname,
                model: identity.model,
                revision: identity.revision,
                date: identity.date,
                time: identity.time,
            };
            Ok(Some(msg.encode(reply_header(cmp::code::IDENT), out)?))
        }

        Query::IfStats { interface } => match hooks.if_stats(interface) {
            Some(stats) => {
                let msg = IfStatsMsg { interface, stats };
                Ok(Some(msg.encode(reply_header(cmp::code::IF_STATS), out)?))
            }
            None => Ok(None),
        },

        Query::Clock { set } => {
            // The C sets only when tv_sec is non-zero, then reads back regardless -- but
            // returns the *set* result, so a refused set discards the reply it just built.
            // A peer that asked to set the clock and got silence learns the set failed;
            // one that got a timestamp back would read it as confirmation.
            if let Some(t) = set {
                if !hooks.set_clock(t.into()) {
                    return Ok(None);
                }
            }
            let now: cmp::Timestamp = hooks.clock().into();
            Ok(Some(now.encode(reply_header(cmp::code::CLOCK), out)?))
        }

        Query::RouteSetV1(r) => {
            let netmask = version.host_bits() as u16;
            if !hooks.route_set(
                r.dest_node as u16,
                netmask,
                r.interface,
                r.next_hop_via as u16,
            ) {
                return Ok(None);
            }
            let msg = RouteSetV1 { ..r };
            Ok(Some(
                msg.encode(reply_header(cmp::code::ROUTE_SET_V1), out)?,
            ))
        }

        Query::RouteSet(r) => {
            if !hooks.route_set(r.dest_node, r.netmask, r.interface, r.next_hop_via) {
                return Ok(None);
            }
            let msg = RouteSetV2 { ..r };
            Ok(Some(
                msg.encode(reply_header(cmp::code::ROUTE_SET_V2), out)?,
            ))
        }

        Query::Peek { addr, len, wide } => {
            let code = if wide {
                cmp::code::PEEK_V2
            } else {
                cmp::code::PEEK
            };
            let mut buf = [0u8; cmp::len::PEEK_MAX];
            let n = len as usize;
            if n > buf.len() {
                return Err(Error::LengthExceedsMaximum {
                    got: n,
                    max: buf.len(),
                });
            }
            if hooks.mem_read(addr, &mut buf[..n]).is_err() {
                return Ok(None);
            }
            encode_peek(code, addr, &buf[..n], wide, out).map(Some)
        }

        Query::Poke { addr, data, wide } => {
            if hooks.mem_write(addr, data).is_err() {
                return Ok(None);
            }
            let code = if wide {
                cmp::code::POKE_V2
            } else {
                cmp::code::POKE
            };
            encode_peek(code, addr, data, wide, out).map(Some)
        }
    }
}

#[cfg(feature = "cmp")]
/// Every CMP reply carries the request's code with the type flipped to `REPLY`, which is
/// `csp_cmp_dispatch.c`'s single `cmp->type = CSP_CMP_REPLY` after a successful handler.
const fn reply_header(code: u8) -> Header {
    Header {
        kind: cmp::REPLY,
        code,
    }
}

#[cfg(feature = "cmp")]
fn encode_peek(code: u8, addr: u64, data: &[u8], wide: bool, out: &mut [u8]) -> Result<usize> {
    let h = reply_header(code);
    if wide {
        cmp::PeekV2 {
            vaddr: addr,
            len: data.len() as u8,
            data,
        }
        .encode(h, out)
    } else {
        cmp::Peek {
            addr: addr as u32,
            len: data.len() as u8,
            data,
        }
        .encode(h, out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `csp_service_handler` discards a PS reply of zero length rather than sending an
    /// empty packet. The port replied with `Some(0)` -- a zero-length reply -- which a
    /// peer reads as "this node is running no processes" rather than as "this node cannot
    /// tell you".
    #[test]
    fn a_node_that_cannot_list_its_processes_says_nothing() {
        let mut out = [0u8; 64];
        let silent = NodeStatus {
            ps: b"",
            ..status()
        };
        assert_eq!(respond(Request::Ps, b"", &silent, &mut out).unwrap(), None);

        let n = respond(Request::Ps, b"", &status(), &mut out)
            .unwrap()
            .expect("a node with a process list answers");
        assert_eq!(&out[..n], b"init");
    }

    fn status() -> NodeStatus<'static> {
        NodeStatus {
            ps: b"init",
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
        let mut answered = 0u32;
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
                answered += 1;
                let _ = respond(req, &payload[..n], &status, &mut out);
            }
        }
        // Measured at 1139 of 50 000: a random u8 port is a valid service port about 2 %
        // of the time. Without this assertion a stricter `Request::decode` could take it
        // to zero and the test would still pass, having exercised nothing -- which is
        // exactly how a KISS fuzz test here once ran against no input at all.
        assert!(
            answered > 500,
            "only {answered} of 50000 random requests were answered -- the generator is \
             no longer reaching `respond`"
        );
    }
}
