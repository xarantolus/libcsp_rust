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
pub mod security;

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

#[cfg(feature = "if-i2c")]
pub mod i2c;

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
    /// An RDP connection cannot take another packet yet.
    ///
    /// `snd_nxt` has reached `snd_una + window_size - 1` and the peer has not acknowledged
    /// anything since. `csp_rdp_send` blocks on a semaphore here; a sans-io node has
    /// nowhere to block, so the caller drains `work` and retries.
    ///
    /// Distinct from the failures around it because it is *temporary*: the same packet on
    /// the same connection succeeds once an acknowledgement arrives. This used to be
    /// returned for a **closed** connection as well — where retrying never succeeds, and
    /// the caller needs to reconnect. The C separates them: `csp_rdp_send` returns
    /// `CSP_ERR_RESET` when the state is not open and blocks only for the window.
    SendWindowFull,
    /// The connection is gone: the peer reset it, or it timed out.
    ///
    /// `csp_rdp_send` (`csp_rdp.c:863`) reports `CSP_ERR_RESET` for exactly this. Unlike
    /// [`Error::SendWindowFull`] it is permanent — the caller has to open a new connection,
    /// and a caller that treats it as back-pressure retries forever against a dead peer.
    ConnectionReset,
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
    /// An interface with this name is already registered.
    ///
    /// `csp_iflist_add` returns `void` and silently keeps the first, so the second
    /// interface is simply absent. Two interfaces with one name would also make CMP
    /// `IF_STATS` ambiguous and the route text format unresolvable.
    DuplicateName {
        /// The name that was already taken.
        name: &'static str,
    },
    /// No interface is registered at this index.
    NoSuchInterface {
        /// The index that was asked for.
        index: u8,
    },
    /// The node refused to read or write this address.
    ///
    /// CMP `PEEK`/`POKE` name an address on the wire. libcsp's default
    /// `csp_cmp_memcpy` is a bare `memcpy` with no validation, so a node built with CMP
    /// answers a peek from any address and a poke to any address. Refusing is the default
    /// here, and a node that wants to serve them says which addresses are allowed.
    AddressRefused {
        /// The address that was asked for.
        addr: u64,
    },
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
    /// A packet with this sequence number is already buffered.
    ///
    /// Not a failure of the peer: retransmission is how RDP recovers, so the same
    /// sequence number arriving twice is expected. It means "drop this copy".
    DuplicateSequence {
        /// The sequence number already held.
        seq: u16,
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
    /// Nothing knows how to reach this address.
    ///
    /// Distinct from the ordinary send path, which hands the packet back as
    /// `Outbound::NoRoute` so the caller can reuse the buffer. This is for the calls with
    /// no packet to give back — opening an RDP connection, where the `SYN` the node built
    /// for itself cannot leave.
    Unroutable {
        /// The address that could not be reached.
        dst: u16,
    },
    /// A protection this build does not implement was asked for.
    ///
    /// Refusing is the safe answer: the alternative is to set the feature's bit in the
    /// header and not perform it, which tells the peer to parse bytes that are not there.
    /// The C sets `CSP_DBG_ERR_UNSUPPORTED` on a global and returns a null connection,
    /// which is the same decision reported somewhere easier to miss.
    Unsupported {
        /// Which protection.
        feature: Feature,
    },
}

/// A connection protection, for [`Error::Unsupported`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Reliable datagram protocol.
    Rdp,
    /// HMAC authentication.
    Hmac,
    /// CRC-32C checksum.
    Crc32,
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
