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
//! use csp::{Config, CspStorage, Node};
//! use csp_core::Version;
//!
//! // 8 connections, 16 buffers of 264 bytes, 48 ports, 32 queued packets, 4 interfaces
//! let storage = CspStorage::<8, 16, 264, 48, 32>::new();
//! let mut node: Node<8, 16, 264, 48, 32, 4> = Node::new(
//!     &storage,
//!     Config::new(Version::V1).address(11).hostname("adcs"),
//! );
//!
//! node.bind(12)?;
//! let mut packet = node.packet().expect("the pool is empty");
//! packet.set_payload(b"hello")?;
//! // pri, dst, dport, sport, flags -- the outbound is handed to an interface to send.
//! let outbound = node.sendto(2, 2, 12, 40, 0, packet)?;
//!
//! // The identity a CMP `IDENT` request is answered with. `node.identity()` bundles the
//! // three for `service::respond_cmp`; it needs the `cmp` feature, this accessor does not.
//! assert_eq!(node.hostname(), "adcs");
//! # Ok::<(), csp_core::Error>(())
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

pub mod client;
pub mod conn;
pub mod dedup;
#[cfg(feature = "sfp")]
pub mod delivery;
mod egress;
pub mod hooks;
pub mod iface;
pub mod iflist;
pub mod node;
pub mod pool;
pub mod qfifo;
pub mod route_policy;
pub mod router;
pub mod service;

use csp_core::Version;

pub use conn::{Kind as ConnKind, Table as ConnTable};
#[cfg(feature = "sfp")]
pub use delivery::{Delivery, Handler, PortTable};
pub use hooks::{Hooks, NoHooks, PowerAction, Timestamp};
pub use iface::{Interface, Sent, Transmit};
pub use iflist::IfList;
pub use node::{Node, Outbound, Unroutable};
pub use pool::{Packet, Pool};
pub use qfifo::Qfifo;
pub use router::{Bridged, DropReason, Routed, Router};
pub use service::{NodeStatus, Request};

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
    pub(crate) hostname: &'a str,
    pub(crate) model: &'a str,
    pub(crate) revision: &'a str,
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

    /// Set this node's address: what it answers to on loopback, and what it recognises as
    /// itself alongside every interface address and alias.
    ///
    /// It is **not** what outgoing packets are sourced from. libcsp has no node address: a
    /// packet a node originates is sourced from the address of the interface it leaves by,
    /// chosen by routing (`csp_conn.c:259`, `csp_io.c:119`). A node with one interface at
    /// this address sees no difference; a node with a CAN link and a radio link answers on
    /// each as that link.
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

    /// The wire version.
    pub const fn version(&self) -> Version {
        self.version
    }

    /// The node address.
    pub const fn addr(&self) -> u16 {
        self.address
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

    /// The packet pool.
    pub const fn pool_ref(&self) -> &Pool<BUFS, BUFSZ> {
        &self.pool
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::node::Node;

    type S = CspStorage<8, 16, 264, 48, 32>;
    type N<'a> = Node<'a, 8, 16, 264, 48, 32, 4>;

    #[test]
    fn two_nodes_coexist_in_one_process() {
        // The whole point. csp_init() returns CSP_ERR_INVAL on a second call, because
        // libcsp's state is ~38 file-scope statics.
        let sa = S::new();
        let sb = S::new();
        let a = N::new(&sa, Config::new(Version::V1).address(11).hostname("adcs"));
        let b = N::new(&sb, Config::new(Version::V2).address(2000).hostname("cdh"));

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
        let a = N::new(&sa, Config::new(Version::V1).address(1));
        let b = N::new(&sb, Config::new(Version::V1).address(2));

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
        let node = N::new(&s, Config::new(Version::V1).address(1));
        assert_eq!(node.version(), Version::V1);
        // A different version requires a different node, with its own storage.
        let s2 = S::new();
        let other = N::new(&s2, Config::new(Version::V2).address(1));
        assert_eq!(other.version(), Version::V2);
    }

    #[test]
    fn packets_come_from_the_nodes_own_pool() {
        let s = S::new();
        let node = N::new(&s, Config::new(Version::V1).address(1));
        assert_eq!(node.buffers_free(), 16);
        {
            let _p = node.packet().unwrap();
            assert_eq!(node.buffers_free(), 15);
        }
        assert_eq!(node.buffers_free(), 16);
    }
}
