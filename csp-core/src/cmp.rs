//! CMP — the CSP Management Protocol, on port 0.
//!
//! **Both directions.** The C ships request builders (`csp_cmp_ident`, `csp_cmp_clock`, …)
//! and server-side handlers, but no decoder — so anything that wants to *read* CMP off the
//! wire has to reimplement the format. In this repository the packet sniffer does exactly
//! that, hand-rolling every message type and both magic constants.
//!
//! Every multi-byte field is big-endian. The C structs are `__attribute__((packed))`, so
//! offsets are exact and several `u32`s are unaligned — which is precisely why a Rust port
//! cannot reuse the struct layout and has to serialise field by field.

use crate::{Error, Result};

/// Message is a request.
pub const REQUEST: u8 = 0x00;
/// Message is a reply.
pub const REPLY: u8 = 0xFF;

/// CMP operation codes.
pub mod code {
    /// Identify: hostname, model, revision, build date and time.
    pub const IDENT: u8 = 1;
    /// Install a route, CSP v1 form.
    pub const ROUTE_SET_V1: u8 = 2;
    /// Interface counters.
    pub const IF_STATS: u8 = 3;
    /// Read memory.
    pub const PEEK: u8 = 4;
    /// Write memory.
    pub const POKE: u8 = 5;
    /// Get or set the realtime clock.
    pub const CLOCK: u8 = 6;
    /// Install a route, CSP v2 form.
    pub const ROUTE_SET_V2: u8 = 7;
    /// Read memory, 64-bit address.
    pub const PEEK_V2: u8 = 8;
    /// Write memory, 64-bit address.
    pub const POKE_V2: u8 = 9;
}

/// Field widths, fixed by the wire format.
pub mod len {
    /// Hostname field.
    pub const HOSTNAME: usize = 20;
    /// Model field.
    pub const MODEL: usize = 30;
    /// Revision field.
    pub const REVISION: usize = 20;
    /// Build date field.
    pub const DATE: usize = 12;
    /// Build time field.
    pub const TIME: usize = 9;
    /// Interface name field.
    pub const IFACE: usize = 11;
    /// Largest peek/poke payload, 32-bit address form.
    pub const PEEK_MAX: usize = 200;
    /// Largest peek/poke payload, 64-bit address form.
    pub const PEEK_V2_MAX: usize = 196;
}

/// The two-byte header every CMP message starts with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// [`REQUEST`] or [`REPLY`].
    pub kind: u8,
    /// One of [`code`].
    pub code: u8,
}

impl Header {
    /// Size of the header on the wire.
    pub const LEN: usize = 2;

    /// Decode the header from the front of a CMP payload.
    pub fn decode(data: &[u8]) -> Result<Header> {
        if data.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Header {
            kind: data[0],
            code: data[1],
        })
    }

    /// True if this is a reply.
    pub const fn is_reply(&self) -> bool {
        self.kind == REPLY
    }
}

/// Copy a fixed-width, NUL-padded C string field out of `src`, returning it as `&str`
/// truncated at the first NUL.
fn c_str(src: &[u8]) -> &str {
    let end = src.iter().position(|&b| b == 0).unwrap_or(src.len());
    // CMP string fields are ASCII on the wire; anything else is a malformed peer, and
    // losing the tail is better than refusing the whole message.
    core::str::from_utf8(&src[..end]).unwrap_or("")
}

fn put_str(dst: &mut [u8], s: &str) {
    let n = core::cmp::min(dst.len(), s.len());
    dst[..n].copy_from_slice(&s.as_bytes()[..n]);
    for b in dst[n..].iter_mut() {
        *b = 0;
    }
}

fn be32(d: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}

/// `IDENT` reply payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ident<'a> {
    /// Node hostname.
    pub hostname: &'a str,
    /// Hardware model.
    pub model: &'a str,
    /// Software revision.
    pub revision: &'a str,
    /// Build date.
    pub date: &'a str,
    /// Build time.
    pub time: &'a str,
}

impl<'a> Ident<'a> {
    /// Encoded size.
    pub const LEN: usize =
        Header::LEN + len::HOSTNAME + len::MODEL + len::REVISION + len::DATE + len::TIME;

    /// Decode an `IDENT` message.
    pub fn decode(data: &'a [u8]) -> Result<Ident<'a>> {
        if data.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        let mut o = Header::LEN;
        let hostname = c_str(&data[o..o + len::HOSTNAME]);
        o += len::HOSTNAME;
        let model = c_str(&data[o..o + len::MODEL]);
        o += len::MODEL;
        let revision = c_str(&data[o..o + len::REVISION]);
        o += len::REVISION;
        let date = c_str(&data[o..o + len::DATE]);
        o += len::DATE;
        let time = c_str(&data[o..o + len::TIME]);
        Ok(Ident {
            hostname,
            model,
            revision,
            date,
            time,
        })
    }

    /// Encode an `IDENT` message with the given header.
    pub fn encode(&self, h: Header, out: &mut [u8]) -> Result<usize> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall { needed: Self::LEN });
        }
        out[0] = h.kind;
        out[1] = h.code;
        let mut o = Header::LEN;
        put_str(&mut out[o..o + len::HOSTNAME], self.hostname);
        o += len::HOSTNAME;
        put_str(&mut out[o..o + len::MODEL], self.model);
        o += len::MODEL;
        put_str(&mut out[o..o + len::REVISION], self.revision);
        o += len::REVISION;
        put_str(&mut out[o..o + len::DATE], self.date);
        o += len::DATE;
        put_str(&mut out[o..o + len::TIME], self.time);
        Ok(Self::LEN)
    }
}

/// `IF_STATS` reply payload — the ten interface counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(missing_docs)]
pub struct IfStats {
    pub tx: u32,
    pub rx: u32,
    pub tx_error: u32,
    pub rx_error: u32,
    pub drop: u32,
    pub autherr: u32,
    pub frame: u32,
    pub txbytes: u32,
    pub rxbytes: u32,
    pub irq: u32,
}

/// `IF_STATS` message: an interface name plus, in a reply, its counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IfStatsMsg<'a> {
    /// Interface name.
    pub interface: &'a str,
    /// Counters. Meaningless in a request.
    pub stats: IfStats,
}

impl<'a> IfStatsMsg<'a> {
    /// Encoded size of a full reply.
    pub const LEN: usize = Header::LEN + len::IFACE + 10 * 4;
    /// Encoded size of a request: the C validates only up to the counters.
    pub const REQUEST_LEN: usize = Header::LEN + len::IFACE;

    /// Decode. A short message carrying only the interface name is accepted as a request.
    pub fn decode(data: &'a [u8]) -> Result<IfStatsMsg<'a>> {
        if data.len() < Self::REQUEST_LEN {
            return Err(Error::Truncated);
        }
        let interface = c_str(&data[Header::LEN..Header::LEN + len::IFACE]);
        if data.len() < Self::LEN {
            return Ok(IfStatsMsg {
                interface,
                stats: IfStats::default(),
            });
        }
        let o = Header::LEN + len::IFACE;
        Ok(IfStatsMsg {
            interface,
            stats: IfStats {
                tx: be32(data, o),
                rx: be32(data, o + 4),
                tx_error: be32(data, o + 8),
                rx_error: be32(data, o + 12),
                drop: be32(data, o + 16),
                autherr: be32(data, o + 20),
                frame: be32(data, o + 24),
                txbytes: be32(data, o + 28),
                rxbytes: be32(data, o + 32),
                irq: be32(data, o + 36),
            },
        })
    }

    /// Encode a full reply.
    pub fn encode(&self, h: Header, out: &mut [u8]) -> Result<usize> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall { needed: Self::LEN });
        }
        out[0] = h.kind;
        out[1] = h.code;
        put_str(&mut out[Header::LEN..Header::LEN + len::IFACE], self.interface);
        let o = Header::LEN + len::IFACE;
        for (i, v) in [
            self.stats.tx,
            self.stats.rx,
            self.stats.tx_error,
            self.stats.rx_error,
            self.stats.drop,
            self.stats.autherr,
            self.stats.frame,
            self.stats.txbytes,
            self.stats.rxbytes,
            self.stats.irq,
        ]
        .iter()
        .enumerate()
        {
            out[o + i * 4..o + i * 4 + 4].copy_from_slice(&v.to_be_bytes());
        }
        Ok(Self::LEN)
    }
}

/// `CLOCK` message payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Timestamp {
    /// Seconds since the epoch.
    pub tv_sec: u32,
    /// Nanoseconds within the second.
    pub tv_nsec: u32,
}

impl Timestamp {
    /// Encoded size of a `CLOCK` message.
    pub const LEN: usize = Header::LEN + 8;

    /// Decode a `CLOCK` message.
    pub fn decode(data: &[u8]) -> Result<Timestamp> {
        if data.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        Ok(Timestamp {
            tv_sec: be32(data, Header::LEN),
            tv_nsec: be32(data, Header::LEN + 4),
        })
    }

    /// Encode a `CLOCK` message.
    pub fn encode(&self, h: Header, out: &mut [u8]) -> Result<usize> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall { needed: Self::LEN });
        }
        out[0] = h.kind;
        out[1] = h.code;
        out[Header::LEN..Header::LEN + 4].copy_from_slice(&self.tv_sec.to_be_bytes());
        out[Header::LEN + 4..Self::LEN].copy_from_slice(&self.tv_nsec.to_be_bytes());
        Ok(Self::LEN)
    }

    /// A `tv_sec` of zero means "do not set, just report", per `csp_cmp_clock_handler`.
    pub const fn is_query(&self) -> bool {
        self.tv_sec == 0
    }
}

/// `ROUTE_SET_V2` message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteSetV2<'a> {
    /// Destination network.
    pub dest_node: u16,
    /// Next hop.
    pub next_hop_via: u16,
    /// Prefix length.
    pub netmask: u16,
    /// Interface name.
    pub interface: &'a str,
}

impl<'a> RouteSetV2<'a> {
    /// Encoded size.
    pub const LEN: usize = Header::LEN + 6 + len::IFACE;

    /// Decode.
    pub fn decode(data: &'a [u8]) -> Result<RouteSetV2<'a>> {
        if data.len() < Self::LEN {
            return Err(Error::Truncated);
        }
        let o = Header::LEN;
        Ok(RouteSetV2 {
            dest_node: u16::from_be_bytes([data[o], data[o + 1]]),
            next_hop_via: u16::from_be_bytes([data[o + 2], data[o + 3]]),
            netmask: u16::from_be_bytes([data[o + 4], data[o + 5]]),
            interface: c_str(&data[o + 6..o + 6 + len::IFACE]),
        })
    }

    /// Encode.
    pub fn encode(&self, h: Header, out: &mut [u8]) -> Result<usize> {
        if out.len() < Self::LEN {
            return Err(Error::BufferTooSmall { needed: Self::LEN });
        }
        out[0] = h.kind;
        out[1] = h.code;
        let o = Header::LEN;
        out[o..o + 2].copy_from_slice(&self.dest_node.to_be_bytes());
        out[o + 2..o + 4].copy_from_slice(&self.next_hop_via.to_be_bytes());
        out[o + 4..o + 6].copy_from_slice(&self.netmask.to_be_bytes());
        put_str(&mut out[o + 6..o + 6 + len::IFACE], self.interface);
        Ok(Self::LEN)
    }
}

/// `PEEK`/`POKE` message with a 32-bit address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peek<'a> {
    /// Target address.
    pub addr: u32,
    /// Number of bytes.
    pub len: u8,
    /// Payload — empty in a `PEEK` request, populated in its reply and in a `POKE`.
    pub data: &'a [u8],
}

impl<'a> Peek<'a> {
    /// Size of the fixed part.
    pub const HEADER_LEN: usize = Header::LEN + 4 + 1;

    /// Decode.
    ///
    /// The declared `len` is checked against the bytes actually present — the C trusts it
    /// and copies, which is how a short frame with a large `len` reads past the packet.
    pub fn decode(data: &'a [u8]) -> Result<Peek<'a>> {
        if data.len() < Self::HEADER_LEN {
            return Err(Error::Truncated);
        }
        let declared = data[Header::LEN + 4];
        if declared as usize > len::PEEK_MAX {
            return Err(Error::LengthExceedsMaximum {
                got: declared as usize,
                max: len::PEEK_MAX,
            });
        }
        let body = &data[Self::HEADER_LEN..];
        // A PEEK request carries no body; a reply or POKE must carry all of it.
        if !body.is_empty() && body.len() < declared as usize {
            return Err(Error::Truncated);
        }
        let n = core::cmp::min(declared as usize, body.len());
        Ok(Peek {
            addr: be32(data, Header::LEN),
            len: declared,
            data: &body[..n],
        })
    }

    /// Encode.
    pub fn encode(&self, h: Header, out: &mut [u8]) -> Result<usize> {
        let needed = Self::HEADER_LEN + self.data.len();
        if out.len() < needed {
            return Err(Error::BufferTooSmall { needed });
        }
        if self.data.len() > len::PEEK_MAX {
            return Err(Error::LengthExceedsMaximum {
                got: self.data.len(),
                max: len::PEEK_MAX,
            });
        }
        out[0] = h.kind;
        out[1] = h.code;
        out[Header::LEN..Header::LEN + 4].copy_from_slice(&self.addr.to_be_bytes());
        out[Header::LEN + 4] = self.len;
        out[Self::HEADER_LEN..needed].copy_from_slice(self.data);
        Ok(needed)
    }
}

/// `PEEK_V2`/`POKE_V2` message with a 64-bit address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeekV2<'a> {
    /// Target address.
    pub vaddr: u64,
    /// Number of bytes.
    pub len: u8,
    /// Payload.
    pub data: &'a [u8],
}

impl<'a> PeekV2<'a> {
    /// Size of the fixed part.
    pub const HEADER_LEN: usize = Header::LEN + 8 + 1;

    /// Decode.
    pub fn decode(data: &'a [u8]) -> Result<PeekV2<'a>> {
        if data.len() < Self::HEADER_LEN {
            return Err(Error::Truncated);
        }
        let declared = data[Header::LEN + 8];
        if declared as usize > len::PEEK_V2_MAX {
            return Err(Error::LengthExceedsMaximum {
                got: declared as usize,
                max: len::PEEK_V2_MAX,
            });
        }
        let mut v = [0u8; 8];
        v.copy_from_slice(&data[Header::LEN..Header::LEN + 8]);
        let body = &data[Self::HEADER_LEN..];
        if !body.is_empty() && body.len() < declared as usize {
            return Err(Error::Truncated);
        }
        let n = core::cmp::min(declared as usize, body.len());
        Ok(PeekV2 {
            vaddr: u64::from_be_bytes(v),
            len: declared,
            data: &body[..n],
        })
    }

    /// Encode.
    pub fn encode(&self, h: Header, out: &mut [u8]) -> Result<usize> {
        let needed = Self::HEADER_LEN + self.data.len();
        if out.len() < needed {
            return Err(Error::BufferTooSmall { needed });
        }
        if self.data.len() > len::PEEK_V2_MAX {
            return Err(Error::LengthExceedsMaximum {
                got: self.data.len(),
                max: len::PEEK_V2_MAX,
            });
        }
        out[0] = h.kind;
        out[1] = h.code;
        out[Header::LEN..Header::LEN + 8].copy_from_slice(&self.vaddr.to_be_bytes());
        out[Header::LEN + 8] = self.len;
        out[Self::HEADER_LEN..needed].copy_from_slice(self.data);
        Ok(needed)
    }
}

/// What a CMP request asks the node to do.
///
/// The C dispatches inside `csp_cmp_dispatch.c` and each handler mutates the packet in
/// place into its own reply — so a handler that returns early leaves a half-built reply in
/// the buffer, and the caller cannot tell it apart from a real one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Query<'a> {
    /// Identify yourself.
    Ident,
    /// Report counters for this interface.
    IfStats {
        /// Interface name.
        interface: &'a str,
    },
    /// Read or set the clock. `None` in `set` means "report only".
    Clock {
        /// The time to set, or `None` to only report.
        set: Option<Timestamp>,
    },
    /// Install a route.
    RouteSet(RouteSetV2<'a>),
    /// Read memory.
    Peek {
        /// Address.
        addr: u64,
        /// Bytes requested.
        len: u8,
        /// True when the 64-bit address form was used.
        wide: bool,
    },
    /// Write memory.
    Poke {
        /// Address.
        addr: u64,
        /// Bytes to write.
        data: &'a [u8],
        /// True when the 64-bit address form was used.
        wide: bool,
    },
}

/// Classify an incoming CMP request.
///
/// Returns [`Error::NotAReply`] inverted — that is, refuses a message marked as a *reply*,
/// because answering one turns two nodes into a loop.
pub fn parse_request(data: &[u8]) -> Result<Query<'_>> {
    let h = Header::decode(data)?;
    if h.is_reply() {
        return Err(Error::NotAReply { got: h.kind });
    }
    match h.code {
        code::IDENT => Ok(Query::Ident),
        code::IF_STATS => Ok(Query::IfStats {
            interface: IfStatsMsg::decode(data)?.interface,
        }),
        code::CLOCK => {
            let t = Timestamp::decode(data)?;
            Ok(Query::Clock {
                set: if t.is_query() { None } else { Some(t) },
            })
        }
        code::ROUTE_SET_V2 => Ok(Query::RouteSet(RouteSetV2::decode(data)?)),
        code::PEEK => {
            let p = Peek::decode(data)?;
            Ok(Query::Peek {
                addr: p.addr as u64,
                len: p.len,
                wide: false,
            })
        }
        code::PEEK_V2 => {
            let p = PeekV2::decode(data)?;
            Ok(Query::Peek {
                addr: p.vaddr,
                len: p.len,
                wide: true,
            })
        }
        code::POKE => {
            let p = Peek::decode(data)?;
            Ok(Query::Poke {
                addr: p.addr as u64,
                data: p.data,
                wide: false,
            })
        }
        code::POKE_V2 => {
            let p = PeekV2::decode(data)?;
            Ok(Query::Poke {
                addr: p.vaddr,
                data: p.data,
                wide: true,
            })
        }
        other => Err(Error::LengthExceedsMaximum {
            got: other as usize,
            max: code::POKE_V2 as usize,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_sizes_match_the_packed_c_structs() {
        // Computed from the __attribute__((packed)) declarations in csp_cmp.h.
        assert_eq!(Header::LEN, 2);
        assert_eq!(Ident::LEN, 2 + 20 + 30 + 20 + 12 + 9);
        assert_eq!(Ident::LEN, 93);
        assert_eq!(IfStatsMsg::LEN, 2 + 11 + 40);
        assert_eq!(IfStatsMsg::LEN, 53);
        assert_eq!(RouteSetV2::LEN, 2 + 6 + 11);
        assert_eq!(RouteSetV2::LEN, 19);
        assert_eq!(Timestamp::LEN, 10);
        assert_eq!(Peek::HEADER_LEN, 7);
        assert_eq!(PeekV2::HEADER_LEN, 11);
    }

    #[test]
    fn header_roundtrip() {
        let h = Header {
            kind: REPLY,
            code: code::IDENT,
        };
        let mut out = [0u8; 4];
        out[0] = h.kind;
        out[1] = h.code;
        assert_eq!(Header::decode(&out).unwrap(), h);
        assert!(h.is_reply());
        assert!(!Header {
            kind: REQUEST,
            code: code::IDENT
        }
        .is_reply());
    }

    #[test]
    fn ident_roundtrip() {
        let id = Ident {
            hostname: "move-iiia-cdh",
            model: "CubeSat-3U",
            revision: "v1.2.3",
            date: "Aug 25 2026",
            time: "12:00:00",
        };
        let h = Header {
            kind: REPLY,
            code: code::IDENT,
        };
        let mut out = [0u8; 128];
        let n = id.encode(h, &mut out).unwrap();
        assert_eq!(n, Ident::LEN);
        assert_eq!(Ident::decode(&out[..n]).unwrap(), id);
        assert_eq!(Header::decode(&out).unwrap(), h);
    }

    #[test]
    fn ident_fields_that_fill_their_slot_have_no_nul() {
        // A hostname of exactly 20 bytes leaves no terminator; the reader must stop at
        // the field boundary rather than running into `model`.
        let id = Ident {
            hostname: "12345678901234567890", // exactly HOSTNAME
            model: "m",
            revision: "r",
            date: "d",
            time: "t",
        };
        let mut out = [0u8; 128];
        let n = id.encode(Header { kind: REPLY, code: code::IDENT }, &mut out).unwrap();
        let got = Ident::decode(&out[..n]).unwrap();
        assert_eq!(got.hostname, "12345678901234567890");
        assert_eq!(got.model, "m");
    }

    #[test]
    fn overlong_ident_fields_are_truncated_not_overflowed() {
        let id = Ident {
            hostname: "this hostname is far longer than twenty bytes",
            model: "m",
            revision: "r",
            date: "d",
            time: "t",
        };
        let mut out = [0u8; 128];
        let n = id.encode(Header { kind: REPLY, code: code::IDENT }, &mut out).unwrap();
        assert_eq!(n, Ident::LEN);
        let got = Ident::decode(&out[..n]).unwrap();
        assert_eq!(got.hostname.len(), len::HOSTNAME);
        assert_eq!(got.model, "m", "the next field must not be clobbered");
    }

    #[test]
    fn if_stats_roundtrip_big_endian() {
        let msg = IfStatsMsg {
            interface: "CAN1",
            stats: IfStats {
                tx: 0x0102_0304,
                rx: 2,
                tx_error: 3,
                rx_error: 4,
                drop: 5,
                autherr: 6,
                frame: 7,
                txbytes: 8,
                rxbytes: 9,
                irq: 10,
            },
        };
        let mut out = [0u8; 64];
        let n = msg
            .encode(Header { kind: REPLY, code: code::IF_STATS }, &mut out)
            .unwrap();
        assert_eq!(n, IfStatsMsg::LEN);
        // network byte order, and unaligned: tx starts at offset 13
        assert_eq!(&out[13..17], &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(IfStatsMsg::decode(&out[..n]).unwrap(), msg);
    }

    #[test]
    fn if_stats_request_carries_only_the_name() {
        let mut out = [0u8; 64];
        out[0] = REQUEST;
        out[1] = code::IF_STATS;
        put_str(&mut out[2..13], "CAN1");
        let msg = IfStatsMsg::decode(&out[..IfStatsMsg::REQUEST_LEN]).unwrap();
        assert_eq!(msg.interface, "CAN1");
        assert_eq!(msg.stats, IfStats::default());
    }

    #[test]
    fn clock_roundtrip_and_query_semantics() {
        let ts = Timestamp {
            tv_sec: 1_700_000_000,
            tv_nsec: 123_456_789,
        };
        let mut out = [0u8; 16];
        let n = ts
            .encode(Header { kind: REQUEST, code: code::CLOCK }, &mut out)
            .unwrap();
        assert_eq!(n, Timestamp::LEN);
        assert_eq!(&out[2..6], &1_700_000_000u32.to_be_bytes());
        assert_eq!(Timestamp::decode(&out[..n]).unwrap(), ts);
        assert!(!ts.is_query());
        assert!(Timestamp::default().is_query(), "tv_sec 0 means read-only");
    }

    #[test]
    fn route_set_v2_roundtrip() {
        let r = RouteSetV2 {
            dest_node: 1000,
            next_hop_via: 2000,
            netmask: 14,
            interface: "CAN1",
        };
        let mut out = [0u8; 32];
        let n = r
            .encode(Header { kind: REQUEST, code: code::ROUTE_SET_V2 }, &mut out)
            .unwrap();
        assert_eq!(RouteSetV2::decode(&out[..n]).unwrap(), r);
    }

    #[test]
    fn peek_request_has_no_body() {
        let p = Peek {
            addr: 0x2000_0000,
            len: 16,
            data: &[],
        };
        let mut out = [0u8; 32];
        let n = p
            .encode(Header { kind: REQUEST, code: code::PEEK }, &mut out)
            .unwrap();
        assert_eq!(n, Peek::HEADER_LEN);
        let got = Peek::decode(&out[..n]).unwrap();
        assert_eq!(got.addr, 0x2000_0000);
        assert_eq!(got.len, 16);
        assert!(got.data.is_empty());
    }

    #[test]
    fn peek_reply_carries_the_bytes() {
        let payload = [0xAAu8; 16];
        let p = Peek {
            addr: 0x2000_0000,
            len: 16,
            data: &payload,
        };
        let mut out = [0u8; 64];
        let n = p
            .encode(Header { kind: REPLY, code: code::PEEK }, &mut out)
            .unwrap();
        assert_eq!(n, Peek::HEADER_LEN + 16);
        assert_eq!(Peek::decode(&out[..n]).unwrap(), p);
    }

    #[test]
    fn a_declared_length_longer_than_the_frame_is_refused() {
        // The C trusts `len` and memcpys it, which reads past the packet.
        let mut buf = [0u8; 16];
        buf[0] = REPLY;
        buf[1] = code::PEEK;
        buf[Header::LEN + 4] = 200; // claims 200 bytes
        // only 9 bytes of body present
        assert_eq!(Peek::decode(&buf[..Peek::HEADER_LEN + 9]), Err(Error::Truncated));
    }

    #[test]
    fn a_declared_length_beyond_the_protocol_maximum_is_refused() {
        let mut buf = [0u8; 8];
        buf[Header::LEN + 4] = 255; // > PEEK_MAX (200)
        assert_eq!(
            Peek::decode(&buf),
            Err(Error::LengthExceedsMaximum { got: 255, max: 200 })
        );

        let mut b2 = [0u8; 12];
        b2[Header::LEN + 8] = 255; // > PEEK_V2_MAX (196)
        assert_eq!(
            PeekV2::decode(&b2),
            Err(Error::LengthExceedsMaximum { got: 255, max: 196 })
        );
    }

    #[test]
    fn peek_v2_roundtrip_64_bit_address() {
        let payload = [1u8, 2, 3, 4];
        let p = PeekV2 {
            vaddr: 0x0000_8000_1234_5678,
            len: 4,
            data: &payload,
        };
        let mut out = [0u8; 32];
        let n = p
            .encode(Header { kind: REPLY, code: code::PEEK_V2 }, &mut out)
            .unwrap();
        assert_eq!(&out[2..10], &0x0000_8000_1234_5678u64.to_be_bytes());
        assert_eq!(PeekV2::decode(&out[..n]).unwrap(), p);
    }

    #[test]
    fn truncated_messages_are_refused_across_the_board() {
        assert_eq!(Header::decode(&[1]), Err(Error::Truncated));
        assert_eq!(Ident::decode(&[0u8; 92]), Err(Error::Truncated));
        assert_eq!(Timestamp::decode(&[0u8; 9]), Err(Error::Truncated));
        assert_eq!(RouteSetV2::decode(&[0u8; 18]), Err(Error::Truncated));
        assert_eq!(IfStatsMsg::decode(&[0u8; 12]), Err(Error::Truncated));
        assert_eq!(Peek::decode(&[0u8; 6]), Err(Error::Truncated));
        assert_eq!(PeekV2::decode(&[0u8; 10]), Err(Error::Truncated));
    }

    // --- request dispatch ---

    fn req(code: u8, body: &[u8], out: &mut [u8]) -> usize {
        out[0] = REQUEST;
        out[1] = code;
        out[Header::LEN..Header::LEN + body.len()].copy_from_slice(body);
        Header::LEN + body.len()
    }

    #[test]
    fn every_message_type_dispatches_to_its_query() {
        let mut buf = [0u8; 128];

        let n = req(code::IDENT, &[], &mut buf);
        assert_eq!(parse_request(&buf[..n]).unwrap(), Query::Ident);

        let mut stats = [0u8; 64];
        let n = IfStatsMsg { interface: "CAN1", stats: IfStats::default() }
            .encode(Header { kind: REQUEST, code: code::IF_STATS }, &mut stats)
            .unwrap();
        assert_eq!(
            parse_request(&stats[..n]).unwrap(),
            Query::IfStats { interface: "CAN1" }
        );

        let ts = Timestamp { tv_sec: 1_700_000_000, tv_nsec: 5 };
        let n = ts
            .encode(Header { kind: REQUEST, code: code::CLOCK }, &mut buf)
            .unwrap();
        assert_eq!(parse_request(&buf[..n]).unwrap(), Query::Clock { set: Some(ts) });
    }

    #[test]
    fn a_zero_clock_is_a_read_not_a_set_to_the_epoch() {
        // csp_cmp_clock_handler treats tv_sec == 0 as "report only". Getting this wrong
        // sets a spacecraft's clock to 1970 whenever anyone asks it the time.
        let mut buf = [0u8; 32];
        let n = Timestamp::default()
            .encode(Header { kind: REQUEST, code: code::CLOCK }, &mut buf)
            .unwrap();
        assert_eq!(parse_request(&buf[..n]).unwrap(), Query::Clock { set: None });
    }

    #[test]
    fn peek_and_poke_report_which_address_width_was_used() {
        let mut buf = [0u8; 64];
        let n = Peek { addr: 0x2000_0000, len: 8, data: &[] }
            .encode(Header { kind: REQUEST, code: code::PEEK }, &mut buf)
            .unwrap();
        assert_eq!(
            parse_request(&buf[..n]).unwrap(),
            Query::Peek { addr: 0x2000_0000, len: 8, wide: false }
        );

        let n = PeekV2 { vaddr: 0x8000_1234_5678, len: 8, data: &[] }
            .encode(Header { kind: REQUEST, code: code::PEEK_V2 }, &mut buf)
            .unwrap();
        assert_eq!(
            parse_request(&buf[..n]).unwrap(),
            Query::Peek { addr: 0x8000_1234_5678, len: 8, wide: true }
        );
    }

    #[test]
    fn a_message_marked_as_a_reply_is_not_answered() {
        // Answering a reply turns two nodes into a loop.
        let mut buf = [0u8; 32];
        buf[0] = REPLY;
        buf[1] = code::IDENT;
        assert_eq!(
            parse_request(&buf[..2]),
            Err(Error::NotAReply { got: REPLY })
        );
    }

    #[test]
    fn an_unknown_code_is_refused_rather_than_guessed() {
        let mut buf = [0u8; 32];
        let n = req(200, &[], &mut buf);
        assert!(parse_request(&buf[..n]).is_err());
    }

    #[test]
    fn a_truncated_request_is_refused_per_type() {
        // Each type has its own minimum; a short IF_STATS must not be read as an IDENT.
        let mut buf = [0u8; 32];
        buf[0] = REQUEST;
        buf[1] = code::IF_STATS;
        assert_eq!(parse_request(&buf[..4]), Err(Error::Truncated));
        buf[1] = code::CLOCK;
        assert_eq!(parse_request(&buf[..6]), Err(Error::Truncated));
    }

    #[test]
    fn dispatching_arbitrary_bytes_never_panics() {
        let mut buf = [0u8; 128];
        let mut x: u32 = 0xC0DE_0001;
        for _ in 0..40_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (x >> (i % 24)) as u8;
            }
            for n in [0usize, 2, 7, 11, 19, 53, 93, 128] {
                let _ = parse_request(&buf[..n]);
            }
        }
    }

    #[test]
    fn decoding_arbitrary_bytes_never_panics() {
        let mut buf = [0u8; 128];
        let mut x: u32 = 0xC0FF_EE00;
        for _ in 0..20_000 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (x >> (i % 24)) as u8;
            }
            for n in [0usize, 2, 7, 11, 19, 53, 93, 128] {
                let d = &buf[..n];
                let _ = Header::decode(d);
                let _ = Ident::decode(d);
                let _ = IfStatsMsg::decode(d);
                let _ = Timestamp::decode(d);
                let _ = RouteSetV2::decode(d);
                let _ = Peek::decode(d);
                let _ = PeekV2::decode(d);
            }
        }
    }
}
