//! # csp-core — the Cubesat Space Protocol, as pure functions
//!
//! Wire-format codecs and protocol state machines with **no I/O, no timing source, no
//! allocation and no global state**. Everything here is a function from bytes to bytes or
//! a state machine you step yourself, which is what makes it testable without a scheduler
//! and usable from an interrupt handler.
//!
//! The node layer (buffer pool, connections, routing, the router loop) lives in the `csp`
//! crate and is built on top of this one.
//!
//! ## What "no global state" buys
//!
//! The C library keeps its configuration in a global `csp_conf`, and reads
//! `csp_conf.version` on every packet. That has a sharp edge: the version is baked into
//! the routing and broadcast maths at `csp_init()` time, so changing it afterwards
//! silently misroutes every packet — measured as one leaked buffer per fragment until the
//! pool empties. Nothing in the C API marks the field as init-only.
//!
//! Here, [`Version`] is a parameter to the functions that need it, so there is nothing to
//! mutate and nothing to get out of step.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod crc32;
pub mod id;

#[cfg(feature = "sha1")]
pub mod sha1;

#[cfg(feature = "hmac")]
pub mod hmac;

#[cfg(feature = "if-kiss")]
pub mod kiss;

#[cfg(feature = "sfp")]
pub mod sfp;

#[cfg(feature = "if-can")]
pub mod cfp;

#[cfg(feature = "rtable")]
pub mod rtable;

#[cfg(feature = "cmp")]
pub mod cmp;

#[cfg(feature = "rdp")]
pub mod rdp;

#[cfg(feature = "if-eth")]
pub mod eth;

pub use id::{Id, Version};

/// Errors returned by the pure codecs.
///
/// **Every variant carries enough to act on.** libcsp returns `CSP_ERR_INVAL` (-2) or
/// `CSP_ERR_SFP` (-103) for a dozen unrelated causes, which is why the flight code has
/// comments guessing at what a return code meant. A caller here can always tell three
/// things apart:
///
/// - *the peer sent nonsense* — [`Error::Truncated`], [`Error::BadChecksum`],
///   [`Error::UnexpectedOffset`], [`Error::InconsistentTotal`], …
/// - *I called this wrong* — [`Error::FieldOutOfRange`], [`Error::ZeroMtu`],
///   [`Error::TableFull`]
/// - *nothing is wrong, retry differently* — [`Error::BufferTooSmall`] carries the size,
///   [`Error::NotAFragment`] means "deliver this as a datagram instead"
///
/// There is no catch-all variant, on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The output buffer was too small for the encoded form.
    ///
    /// Carries the number of bytes that would have been needed, so a caller can retry
    /// with the right size rather than guessing.
    BufferTooSmall {
        /// Bytes required.
        needed: usize,
    },
    /// The input ended before a complete item could be decoded.
    Truncated,
    /// A field does not fit the wire format it is being encoded into.
    ///
    /// The C silently shifts an oversized value into the neighbouring field — encoding a
    /// 14-bit address into a CSP v1 header corrupts the source address rather than
    /// failing. This is that bug, refused.
    FieldOutOfRange {
        /// Which field.
        field: Field,
    },
    /// A checksum or authentication tag did not match.
    BadChecksum,
    /// The routing table is full.
    ///
    /// The C overwrites its last entry and returns success, so a node that installs one
    /// route too many gets a wrong routing table with nothing reported.
    TableFull,
    /// The packet is a plain datagram, not an SFP fragment.
    ///
    /// Not a failure: the caller asked the wrong question. The bytes are untouched and
    /// can be delivered as a datagram. The C frees the packet here and reports a generic
    /// SFP error, destroying data that was perfectly valid.
    NotAFragment,

    // --- reassembly: a fragment that does not fit the transfer in progress ---
    /// A fragment arrived at an offset other than the next expected one.
    ///
    /// SFP and CFP both run over ordered transports, so a gap is loss, not reordering.
    UnexpectedOffset {
        /// Offset the reassembler was waiting for.
        expected: u32,
        /// Offset the fragment claimed.
        got: u32,
    },
    /// Two fragments of the same transfer disagreed about its total size.
    InconsistentTotal {
        /// Size the first fragment declared.
        expected: u32,
        /// Size this fragment declared.
        got: u32,
    },
    /// A fragment's offset lies past the declared total size.
    OffsetBeyondTotal {
        /// The fragment's offset.
        offset: u32,
        /// The declared total.
        total: u32,
    },
    /// A fragment carried no payload, so reassembly could never progress.
    EmptyFragment,
    /// A transfer declared a total size of zero, which carries no data but would look
    /// complete on arrival.
    ZeroTotal,
    /// A continuation frame arrived with no transfer in progress — the opening frame was
    /// lost. Reassembling anyway would produce a short packet with a garbage header.
    NoTransferInProgress,
    /// A continuation frame belongs to a different transfer than the one in progress.
    IdentMismatch {
        /// Identifier of the transfer in progress.
        expected: u16,
        /// Identifier the frame carried.
        got: u16,
    },

    // --- caller mistakes ---
    /// An MTU of zero was supplied, which would fragment forever.
    ZeroMtu,
    /// An empty authentication key was supplied.
    ///
    /// The C returns `CSP_ERR_INVAL` here *without touching the output buffer*, so a
    /// caller that ignores the return value authenticates over uninitialised stack.
    EmptyKey,
    /// A declared or supplied length exceeds what the wire format allows.
    LengthExceedsMaximum {
        /// The length asked for.
        got: usize,
        /// The largest the format permits.
        max: usize,
    },
    /// A management-protocol message that should have been a reply was not.
    ///
    /// Distinct from a code mismatch: this one says the peer sent a *request* where an
    /// answer was expected, which usually means a loop or a crossed connection.
    NotAReply {
        /// The message kind byte that was seen.
        got: u8,
    },
    /// An Ethernet frame did not carry the CSP ethertype.
    UnexpectedEtherType {
        /// The ethertype seen.
        got: u16,
    },
    /// A route entry could not be parsed.
    InvalidRoute {
        /// Which part of the entry was wrong.
        reason: RouteError,
    },
}

/// Identifies the field in [`Error::FieldOutOfRange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum Field {
    Priority,
    Source,
    Destination,
    SourcePort,
    DestinationPort,
    Flags,
}

/// Why a route entry failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteError {
    /// The address was not a number.
    BadAddress,
    /// The netmask was not a number.
    BadNetmask,
    /// The via address was not a number.
    BadVia,
    /// No interface name followed the address.
    MissingInterface,
    /// More fields followed the via address than the format allows.
    TrailingGarbage,
}

/// Result alias for this crate.
pub type Result<T> = core::result::Result<T, Error>;

/// Packet header flags. These live in the low bits of [`Id::flags`].
pub mod flags {
    /// Use CRC32 checksum.
    pub const CRC32: u8 = 0x01;
    /// Use RDP (reliable datagram protocol).
    pub const RDP: u8 = 0x02;
    /// Use HMAC verification.
    pub const HMAC: u8 = 0x08;
    /// Payload is an SFP fragment.
    ///
    /// This is the flag that lets a port decide, per packet, whether it was handed a
    /// whole datagram or the first fragment of a stream.
    pub const FRAG: u8 = 0x10;
}

/// Well-known service ports handled by the built-in service handler.
pub mod ports {
    /// CSP management protocol.
    pub const CMP: u8 = 0;
    /// Echo.
    pub const PING: u8 = 1;
    /// Process list.
    pub const PS: u8 = 2;
    /// Free memory in bytes.
    pub const MEMFREE: u8 = 3;
    /// Reboot / shutdown, guarded by a magic word.
    pub const REBOOT: u8 = 4;
    /// Free packet buffers.
    pub const BUF_FREE: u8 = 5;
    /// Uptime in seconds.
    pub const UPTIME: u8 = 6;
    /// Bind to any port.
    pub const ANY: u8 = 255;
}
