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

pub use id::{Id, Version};

/// Errors returned by the pure codecs.
///
/// Deliberately small and non-exhaustive-free: every variant is something a caller can
/// act on, and there is no catch-all "other".
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
    /// A checksum did not match.
    BadChecksum,
    /// The frame is structurally invalid (bad framing, impossible length, bad offset).
    Malformed,
    /// The packet is a plain datagram, not an SFP fragment.
    ///
    /// Distinct from [`Error::Malformed`] on purpose: nothing is wrong, the caller just
    /// asked the wrong question. Its bytes are untouched and can be delivered as a
    /// datagram. The C frees the packet in this case and reports a generic SFP error.
    NotAFragment,
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
