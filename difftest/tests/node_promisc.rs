//! The promiscuous tap, compared between a real C node and the port.
//!
//! # Why this is a separate binary and not a loop
//!
//! `csp_conf.version` is init-only. Changing it after `csp_init()` silently misroutes
//! every packet (SCOPE.md deviation 18 — measured as one leaked buffer per fragment until
//! the pool empties). So one process gets one C node at one wire version. Cargo gives each
//! integration-test file its own binary, which is exactly the process isolation needed —
//! the same trick the golden-vector oracle uses.
//!
//! Without this file, v2 has never been through a node at all: every node-level test in
//! `diff.rs` pins `Version::V1`, and the `versions()` loops there are all codec-level.
//! v2 headers were verified; v2 *routing and delivery* were not.
//!
//! # The topology has to be recomputed, not copied
//!
//! v1 has 5 host bits and v2 has 14, so a netmask is not portable between them. The two
//! interfaces must land in different subnets or split horizon vetoes forwarding:
//!
//! | | netmask | mask | ingress 9 | egress 20 | forwardable dst |
//! |---|---|---|---|---|---|
//! | v1 | 2 | `0b11000` | subnet 8 | subnet 16 | 18 |
//! | v2 | 12 | `0x3FFC` | subnet 8 | subnet 20 | 21 |
//!
//! Reusing v1's netmask of 2 under v2 gives `((1<<2)-1) << (14-2)` = `0x3000`, and both 9
//! and 20 mask to subnet 0 — one subnet, no forwarding, and a test that passes by
//! asserting nothing happened.

use csp::dedup::DedupMode;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
/// See the table above: 12 network bits of 14 puts 9 and 20 in different subnets.
const NETMASK: u16 = 12;
/// A third subnet, so a route can point somewhere local-subnet would not choose.
const THIRD_ADDR: u16 = 40;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn framed(id: Id, payload: &[u8]) -> Vec<u8> {
    let hdr = 6; // v2
    let mut v = vec![0u8; hdr + payload.len()];
    id.encode(VERSION, &mut v).expect("id fits v2");
    v[hdr..].copy_from_slice(payload);
    v
}

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, NODE_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );
    assert_eq!(c_node_bind(10), 0, "bind port 10");
}

/// What the tap sees, and where it sits in the path.
///
/// `csp_promisc_add` is at `csp_route.c:252` — **after** the deduplication check and
/// **before** the `is_to_me` branch. Two orderings follow, and a port can get either wrong
/// while every individual piece works:
///
/// - a packet being **forwarded** is tapped, not just one addressed to this node;
/// - a packet **deduplication already suppressed** is *not* tapped.
///
/// Both are asserted here against the C rather than against a reading of it. The tap must
/// also not change what the application receives, which is the property that makes it a
/// diagnostic tool rather than a second delivery path.
#[test]
fn the_promiscuous_tap_matches_the_c() {
    let _g = lock();
    setup();
    assert_eq!(c_node_promisc_enable(), 0, "the C's tap comes up");
    c_node_set_dedup(0);

    let to_me = framed(
        Id {
            pri: 2,
            flags: 0,
            src: 4000,
            dst: NODE_ADDR,
            dport: 10,
            sport: 40,
        },
        b"mine",
    );
    // 21 is in the egress subnet and is not an address any interface owns, so it is
    // forwarded rather than delivered.
    let onward = framed(
        Id {
            pri: 2,
            flags: 0,
            src: 4000,
            dst: 21,
            dport: 10,
            sport: 41,
        },
        b"onward",
    );

    // --- both shapes are tapped, and delivery is unchanged ---
    let c_mine = c_node_exchange(&to_me, &[10]);
    let c_fwd = c_node_exchange(&onward, &[10]);
    let c_tapped = c_node_promisc_drain();
    let r = rust_promisc_exchange(&[&to_me, &onward], DedupMode::Off);

    assert_eq!(
        c_mine.delivered.len(),
        1,
        "the C still delivers what is ours"
    );
    assert_eq!(c_fwd.tx.len(), 1, "and still forwards what is not");
    assert_eq!(
        r.delivered, 1,
        "the tap must not change what the application receives"
    );
    assert_eq!(r.forwarded, 1, "nor what leaves on the wire");

    let c_dsts: Vec<u16> = c_tapped.iter().map(|(d, _)| *d).collect();
    assert_eq!(
        c_dsts,
        vec![NODE_ADDR, 21],
        "the C taps traffic for this node *and* traffic it is forwarding"
    );
    assert_eq!(
        r.tapped, c_dsts,
        "and so must the port -- a tap placed after the `is_to_me` branch would miss \
         everything being forwarded, which is most of what a router sees"
    );

    // --- a deduplicated frame is not tapped ---
    c_node_set_dedup(2);
    let dup = framed(
        Id {
            pri: 2,
            flags: 0,
            src: 4000,
            dst: NODE_ADDR,
            dport: 10,
            sport: 42,
        },
        b"dup",
    );
    c_node_exchange(&dup, &[10]);
    c_node_exchange(&dup, &[10]);
    let c_dup_tapped = c_node_promisc_drain().len();
    let r_dup = rust_promisc_exchange(&[&dup, &dup], DedupMode::Incoming);

    assert_eq!(
        c_dup_tapped, 1,
        "the C taps the frame once: `csp_promisc_add` is below the dedup check, so the \
         suppressed copy never reaches it"
    );
    assert_eq!(
        r_dup.tapped.len(),
        c_dup_tapped,
        "the port must place its tap on the same side of deduplication -- a tap above it \
         would report traffic the node then discarded"
    );

    c_node_set_dedup(0);
}

#[derive(Debug, Default)]
struct PromiscOutcome {
    delivered: usize,
    forwarded: usize,
    tapped: Vec<u16>,
}

/// Feed frames to a fresh port node with the tap on, and report what each side saw.
fn rust_promisc_exchange(frames: &[&Vec<u8>], mode: DedupMode) -> PromiscOutcome {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces
        .add("INGRESS", NODE_ADDR, NETMASK, false)
        .unwrap();
    node.ifaces
        .add("EGRESS", EGRESS_ADDR, NETMASK, true)
        .unwrap();
    node.bind(10).unwrap();
    node.router.dedup_mode = mode;
    node.router.set_promisc(true);

    let mut out = PromiscOutcome::default();
    for f in frames {
        let Some(mut p) = node.packet() else { break };
        if p.set_frame(VERSION, f).is_err() {
            break;
        }
        node.router.receive(p, 0);
        loop {
            match node.work(0) {
                Routed::Delivered { conn, .. } => {
                    while let Ok(Some(pkt)) = node.read(conn) {
                        out.delivered += 1;
                        drop(pkt);
                    }
                }
                Routed::Forwarded { packet, .. } => {
                    out.forwarded += 1;
                    drop(node.take_forwarded(packet));
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
        while let Some(tapped) = node.router.promisc_read(node.pool()) {
            out.tapped.push(tapped.id().dst);
            drop(tapped);
        }
    }
    out
}
