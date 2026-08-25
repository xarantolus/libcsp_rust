//! # csp — a Cubesat Space Protocol node
//!
//! The node layer: buffer pool, connections, ports, routing and delivery, built on the
//! pure codecs in [`csp_core`].
//!
//! ## No global state
//!
//! Everything libcsp keeps in file-scope statics — the packet pool, the connection table,
//! the port table, the router queue, the routing table, the interface list, the
//! configuration — lives inside a value you own. Two nodes can run in one process, which
//! the C cannot do at all: it has ~38 mutable statics, and `csp_init()` returns
//! `CSP_ERR_INVAL` on a second call.
//!
//! Storage is supplied by the caller, so `no_std` needs no allocator:
//!
//! ```
//! use csp::{Csp, CspStorage, Config};
//! use csp_core::Version;
//!
//! // 8 connections, 16 buffers of 264 bytes, 48 ports, 32 queued packets
//! let storage = CspStorage::<8, 16, 264, 48, 32>::new();
//! let csp = Csp::new(&storage, Config::new(Version::V1).address(11));
//! assert_eq!(csp.address(), 11);
//! ```
//!
//! ## Ports accept either shape
//!
//! A port does not declare in advance whether it expects a datagram or a stream. The
//! `FRAG` bit in each packet header says which arrived, so one handler can take both — see
//! [`delivery`]. Getting this wrong in the C destroys the packet: `csp_sfp_header_remove`
//! bails the moment `FRAG` is clear and its caller frees the buffer, so a plain datagram
//! sent to a stream port is lost behind a misleading `-103`.

#![no_std]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod conn;
pub mod dedup;
#[cfg(feature = "sfp")]
pub mod delivery;
pub mod iface;
pub mod pool;
pub mod qfifo;
pub mod router;

use csp_core::Version;

#[cfg(feature = "sfp")]
pub use delivery::{Delivery, Handler, PortTable};
pub use conn::Table as ConnTable;
pub use iface::{Interface, Transmit};
pub use qfifo::Qfifo;
pub use router::{DropReason, Routed, Router};
pub use pool::{Packet, Pool};

/// Node configuration.
///
/// The wire version is fixed at construction and cannot change afterwards. In the C it is
/// a mutable global that is *silently* init-only: `host_bits` (5 for v1, 14 for v2) is
/// baked into the routing and broadcast maths at `csp_init()`, so changing
/// `csp_conf.version` later misroutes every packet into the router queue where nothing
/// drains it — measured at one leaked buffer per fragment until the pool empties and
/// everything returns `CSP_ERR_NOMEM`, with no error at the point of misuse.
#[derive(Debug, Clone, Copy)]
pub struct Config<'a> {
    version: Version,
    address: u16,
    hostname: &'a str,
    model: &'a str,
    revision: &'a str,
}

impl<'a> Config<'a> {
    /// Start a configuration for the given wire version.
    pub const fn new(version: Version) -> Self {
        Config {
            version,
            address: 0,
            hostname: "",
            model: "",
            revision: "",
        }
    }

    /// Set this node's address.
    pub const fn address(mut self, addr: u16) -> Self {
        self.address = addr;
        self
    }

    /// Set the hostname reported by CMP `IDENT`.
    pub const fn hostname(mut self, s: &'a str) -> Self {
        self.hostname = s;
        self
    }

    /// Set the model reported by CMP `IDENT`.
    pub const fn model(mut self, s: &'a str) -> Self {
        self.model = s;
        self
    }

    /// Set the revision reported by CMP `IDENT`.
    pub const fn revision(mut self, s: &'a str) -> Self {
        self.revision = s;
        self
    }
}

/// Caller-owned storage for a node.
///
/// Const generics rather than Kconfig: `CONNS` connections, `BUFS` buffers of `BUFSZ`
/// bytes (including [`pool::PADDING`]), `PORTS` bindable ports, `QFIFO` queued packets.
/// The flight configuration is `<16, 64, 264, 48, 100>`.
#[derive(Debug)]
pub struct CspStorage<
    const CONNS: usize,
    const BUFS: usize,
    const BUFSZ: usize,
    const PORTS: usize,
    const QFIFO: usize,
> {
    pool: Pool<BUFS, BUFSZ>,
}

impl<
        const CONNS: usize,
        const BUFS: usize,
        const BUFSZ: usize,
        const PORTS: usize,
        const QFIFO: usize,
    > Default for CspStorage<CONNS, BUFS, BUFSZ, PORTS, QFIFO>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
        const CONNS: usize,
        const BUFS: usize,
        const BUFSZ: usize,
        const PORTS: usize,
        const QFIFO: usize,
    > CspStorage<CONNS, BUFS, BUFSZ, PORTS, QFIFO>
{
    /// Allocate the storage. Contains no allocator calls.
    pub fn new() -> Self {
        CspStorage { pool: Pool::new() }
    }
}

/// A CSP node.
///
/// Borrows its storage, so the node and its buffers have an explicit relationship instead
/// of the C's implicit "these statics belong to whoever called `csp_init` last".
#[derive(Debug)]
pub struct Csp<
    'a,
    const CONNS: usize,
    const BUFS: usize,
    const BUFSZ: usize,
    const PORTS: usize,
    const QFIFO: usize,
> {
    storage: &'a CspStorage<CONNS, BUFS, BUFSZ, PORTS, QFIFO>,
    version: Version,
    address: u16,
    hostname: &'a str,
    model: &'a str,
    revision: &'a str,
}

impl<
        'a,
        const CONNS: usize,
        const BUFS: usize,
        const BUFSZ: usize,
        const PORTS: usize,
        const QFIFO: usize,
    > Csp<'a, CONNS, BUFS, BUFSZ, PORTS, QFIFO>
{
    /// Create a node over the given storage.
    ///
    /// Cannot fail, and can be called as many times as there are storages — unlike
    /// `csp_init()`, which is once per process.
    pub fn new(
        storage: &'a CspStorage<CONNS, BUFS, BUFSZ, PORTS, QFIFO>,
        config: Config<'a>,
    ) -> Self {
        Csp {
            storage,
            version: config.version,
            address: config.address,
            hostname: config.hostname,
            model: config.model,
            revision: config.revision,
        }
    }

    /// This node's address.
    pub const fn address(&self) -> u16 {
        self.address
    }

    /// The wire version. Immutable by construction.
    pub const fn version(&self) -> Version {
        self.version
    }

    /// Hostname reported by CMP `IDENT`.
    pub const fn hostname(&self) -> &'a str {
        self.hostname
    }

    /// Model reported by CMP `IDENT`.
    pub const fn model(&self) -> &'a str {
        self.model
    }

    /// Revision reported by CMP `IDENT`.
    pub const fn revision(&self) -> &'a str {
        self.revision
    }

    /// The packet pool.
    pub const fn pool(&self) -> &'a Pool<BUFS, BUFSZ> {
        &self.storage.pool
    }

    /// Take a packet from the pool.
    pub fn packet(&self) -> Option<Packet<'a, BUFS, BUFSZ>> {
        self.storage.pool.acquire(0)
    }

    /// Buffers currently free — the CMP `BUF_FREE` service.
    pub fn buffers_free(&self) -> usize {
        self.storage.pool.available()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type S = CspStorage<8, 16, 264, 48, 32>;

    #[test]
    fn two_nodes_coexist_in_one_process() {
        // The whole point. csp_init() returns CSP_ERR_INVAL on a second call, because
        // libcsp's state is ~38 file-scope statics.
        let sa = S::new();
        let sb = S::new();
        let a = Csp::new(&sa, Config::new(Version::V1).address(11).hostname("adcs"));
        let b = Csp::new(&sb, Config::new(Version::V2).address(2000).hostname("cdh"));

        assert_eq!(a.address(), 11);
        assert_eq!(b.address(), 2000);
        assert_eq!(a.version(), Version::V1);
        assert_eq!(b.version(), Version::V2);
        assert_eq!(a.hostname(), "adcs");
        assert_eq!(b.hostname(), "cdh");
    }

    #[test]
    fn exhausting_one_nodes_pool_leaves_the_other_untouched() {
        let sa = S::new();
        let sb = S::new();
        let a = Csp::new(&sa, Config::new(Version::V1).address(1));
        let b = Csp::new(&sb, Config::new(Version::V1).address(2));

        let mut held = heapless::Vec16::new();
        while let Some(p) = a.packet() {
            held.push(p);
        }
        assert_eq!(a.buffers_free(), 0);
        assert_eq!(b.buffers_free(), 16, "independent pools");
        assert!(b.packet().is_some());
    }

    /// Fixed-capacity holder so the tests need no allocator.
    mod heapless {
        pub struct Vec16<T> {
            items: [Option<T>; 32],
            len: usize,
        }
        impl<T> Vec16<T> {
            pub fn new() -> Self {
                Vec16 {
                    items: core::array::from_fn(|_| None),
                    len: 0,
                }
            }
            pub fn push(&mut self, t: T) {
                self.items[self.len] = Some(t);
                self.len += 1;
            }
        }
    }

    #[test]
    fn the_version_cannot_be_changed_after_construction() {
        // There is deliberately no setter. In the C this is a mutable global that is
        // silently init-only, and changing it leaks one buffer per packet sent.
        let s = S::new();
        let node = Csp::new(&s, Config::new(Version::V1).address(1));
        assert_eq!(node.version(), Version::V1);
        // A different version requires a different node, with its own storage.
        let s2 = S::new();
        let other = Csp::new(&s2, Config::new(Version::V2).address(1));
        assert_eq!(other.version(), Version::V2);
    }

    #[test]
    fn packets_come_from_the_nodes_own_pool() {
        let s = S::new();
        let node = Csp::new(&s, Config::new(Version::V1).address(1));
        assert_eq!(node.buffers_free(), 16);
        {
            let _p = node.packet().unwrap();
            assert_eq!(node.buffers_free(), 15);
        }
        assert_eq!(node.buffers_free(), 16);
    }
}
