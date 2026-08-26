//! Where a packet goes: `csp_send_direct`'s destination policy, in one place.
//!
//! This existed twice — once in [`Node::resolve`](crate::Node::resolve) for packets the
//! application sends, once in `Router::forward` for packets passing through. They are the
//! same C function, and keeping two of it cost two defects before this module existed:
//!
//! - `resolve` had **no local-subnet stage**, so a send to a directly attached address
//!   fell through to the default interfaces — out the wrong link, or nowhere;
//! - `resolve`'s split horizon was only the identity half of `is_same_subnet`, so it
//!   relayed a packet back onto the wire it came from by way of a second link on the same
//!   subnet — the loop split horizon exists to stop.
//!
//! Both were found by the C oracle, months apart, and neither could have been found by
//! reading one copy. There is now one copy.

use crate::iflist::IfList;
use csp_core::Version;

/// The routing table, or a stand-in for it when `rtable` is compiled out.
///
/// A stand-in rather than a second copy of the policy behind a `cfg`: the subnet and
/// default stages exist either way, and gating the whole function meant writing it twice.
/// The stub's `find_all` returns nothing, so stage 2 is skipped exactly as it should be.
#[cfg(feature = "rtable")]
pub use csp_core::rtable;

/// Stand-in for `csp_core::rtable` when the routing table is compiled out.
#[cfg(not(feature = "rtable"))]
pub mod rtable {
    /// No next hop.
    pub const NO_VIA: u16 = 0xFFFF;

    /// A route, for signature compatibility. Never constructed without the feature.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Route {
        /// Destination network.
        pub address: u16,
        /// Prefix length.
        pub netmask: u16,
        /// Interface index.
        pub iface: u8,
        /// Next hop.
        pub via: u16,
    }

    /// An empty routing table.
    #[derive(Debug)]
    pub struct Table<const N: usize>;

    impl<const N: usize> Table<N> {
        /// Create one. The version is irrelevant with nothing to store.
        pub const fn new(_version: csp_core::Version) -> Self {
            Table
        }
        /// Always finds nothing, so the policy falls through to the defaults.
        pub fn find_all<'r>(&'r self, _addr: u16, _out: &mut [&'r Route]) -> usize {
            0
        }
    }
}

/// No next hop: address the frame to the destination itself.
pub const NO_VIA: u16 = rtable::NO_VIA;

/// One place a packet goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    /// Interface index.
    pub iface: u8,
    /// Next hop, or [`NO_VIA`].
    pub via: u16,
    /// The destination the frame carries, which differs from the one asked for when
    /// `convert_broadcast` rewrites a routed broadcast to the local one.
    pub dst: u16,
}

/// What the policy decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// This many hops were written to `out`. Never zero.
    Hops(usize),
    /// A stage matched, but split horizon left nothing usable.
    ///
    /// Not the same as no route: the C returns as soon as its `local_found` or
    /// `route_found` is set, so a matched-but-vetoed stage drops the packet rather than
    /// falling through to the next one.
    SplitHorizon,
    /// Nothing matched at any stage.
    NoRoute,
}

/// True if sending on `candidate` would put the frame back on the wire it arrived from.
///
/// `is_same_subnet` (`csp_io.c:93`) is **two** clauses, and the second is the one that
/// matters: two links on the same subnet are two ways onto the same wire, so relaying
/// between them loops. An identity-only check misses that entirely.
pub fn is_same_subnet<const N: usize, const A: usize>(
    ifaces: &IfList<N, A>,
    candidate: u8,
    ingress: u8,
) -> bool {
    if candidate == ingress {
        return true;
    }
    match ifaces.get(candidate) {
        Some(e) => ifaces.is_within_subnet(e.addr, ingress),
        None => false,
    }
}

/// Every interface a packet for `dst` should go out on, in `csp_send_direct`'s order.
///
/// Three stages — an interface whose subnet owns the destination, then the routing table,
/// then the defaults — and each that matches anything is **terminal**, even if split
/// horizon leaves it empty.
///
/// `ingress` is `None` for locally originated traffic and `Some(iface)` when forwarding.
/// `out` bounds the fan-out; destinations past its end are dropped, and the caller is told
/// how many were written.
pub fn destinations<const N: usize, const A: usize, const R: usize>(
    ifaces: &IfList<N, A>,
    routes: &rtable::Table<R>,
    version: Version,
    dst: u16,
    ingress: Option<u8>,
    out: &mut [Hop],
) -> Outcome {
    let mut n = 0usize;
    let mut push = |h: Hop, n: &mut usize| {
        if *n < out.len() {
            out[*n] = h;
            *n += 1;
        }
    };
    let vetoed = |idx: u8| ingress.is_some_and(|i| is_same_subnet(ifaces, idx, i));

    // 1. A local subnet owns the destination.
    //
    // `convert_broadcast` rides along here and only here: a routed (L3) broadcast becomes
    // the local (L2) one as it reaches the interface. The rewrite is sticky across the
    // fan-out because `csp_send_direct` keeps one `idout_copy` for the whole loop and only
    // ever writes to it — measured, not inferred.
    let mut out_dst = dst;
    let mut local_found = false;
    for idx in ifaces.indices() {
        if !ifaces.is_within_subnet(dst, idx) {
            continue;
        }
        local_found = true;
        if vetoed(idx) {
            continue;
        }
        if ifaces.is_broadcast_for(dst, idx) {
            out_dst = version.max_node_id();
        }
        push(
            Hop {
                iface: idx,
                via: NO_VIA,
                dst: out_dst,
            },
            &mut n,
        );
    }
    if local_found {
        return finish(n);
    }

    // 2. The routing table: every entry tied for the longest prefix.
    {
        let placeholder = rtable::Route {
            address: 0,
            netmask: 0,
            iface: 0,
            via: NO_VIA,
        };
        let mut found = [&placeholder; 4];
        let matched = routes.find_all(dst, &mut found);
        for r in found.iter().take(matched) {
            if vetoed(r.iface) {
                continue;
            }
            push(
                Hop {
                    iface: r.iface,
                    via: r.via,
                    dst,
                },
                &mut n,
            );
        }
        if matched > 0 {
            return finish(n);
        }
    }

    // 3. Every interface marked as a default.
    for idx in ifaces.indices() {
        let Some(e) = ifaces.get(idx) else { continue };
        if !e.is_default || vetoed(idx) {
            continue;
        }
        push(
            Hop {
                iface: idx,
                via: NO_VIA,
                dst,
            },
            &mut n,
        );
    }
    if n > 0 {
        Outcome::Hops(n)
    } else if ingress.is_some()
        && ifaces
            .indices()
            .any(|i| ifaces.get(i).is_some_and(|e| e.is_default))
    {
        // Defaults existed but were all vetoed.
        Outcome::SplitHorizon
    } else {
        Outcome::NoRoute
    }
}

const fn finish(n: usize) -> Outcome {
    if n > 0 {
        Outcome::Hops(n)
    } else {
        Outcome::SplitHorizon
    }
}
