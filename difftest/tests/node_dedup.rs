//! Deduplication, compared between a real C node and the port.
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

/// The same frame twice: both stacks must deliver it once, and neither by accident.
///
/// `csp_dedup_is_duplicate` keys on a CRC32 over the **framed** bytes — after
/// `csp_id_prepend`, so the header is part of the key — with a 16-entry ring and a 100 ms
/// window. The port's `Dedup` claims the same key, count and window. That is a reading of
/// two implementations; this is the comparison.
///
/// Both stacks default to `CSP_DEDUP_OFF`, so the first case here is the default: a
/// duplicate is delivered **twice** by both. Only then is dedup switched on, which is the
/// arrangement that makes a difference visible rather than assumed — a port that silently
/// deduplicated by default would look identical to one that did not, in any test that never
/// checked the off case.
#[test]
fn deduplication_matches_the_c_both_off_and_on() {
    let _g = lock();
    setup();

    let id = Id {
        pri: 2,
        flags: 0,
        src: 4000,
        dst: NODE_ADDR,
        dport: 10,
        sport: 40,
    };
    // Every case uses frames never seen before. The C's dedup ring is process-global and
    // 16 entries deep with a 100 ms window, and these cases run microseconds apart -- so a
    // frame reused between cases is still in the ring and the C suppresses it for reasons
    // that have nothing to do with what the case is testing. The port gets a fresh node per
    // call, so reusing frames would also compare a warm ring against a cold one.
    let mk = |tag: &[u8], sport: u8| framed(Id { sport, ..id }, tag);

    // --- off: the default on both sides ---
    c_node_set_dedup(0);
    let off = mk(b"case-off", 40);
    let c_off = {
        let a = c_node_exchange(&off, &[10]).delivered.len();
        let b = c_node_exchange(&off, &[10]).delivered.len();
        a + b
    };
    let r_off = rust_dedup_exchange(&[&off, &off], DedupMode::Off);
    assert_eq!(
        c_off, 2,
        "with dedup off the C delivers the same frame both times"
    );
    assert_eq!(
        r_off, c_off,
        "the port must match the C's default -- a port that deduplicated anyway would \
         silently swallow a ground station's retransmitted command"
    );

    // --- on: incoming traffic, which is what `dst == us` is ---
    c_node_set_dedup(2);
    let on = mk(b"case-on", 41);
    let c_on = {
        let a = c_node_exchange(&on, &[10]).delivered.len();
        let b = c_node_exchange(&on, &[10]).delivered.len();
        a + b
    };
    let r_on = rust_dedup_exchange(&[&on, &on], DedupMode::Incoming);
    assert_eq!(c_on, 1, "with dedup on the C delivers it once");
    assert_eq!(r_on, c_on, "and so must the port");

    // --- and not by suppressing everything ---
    let one = mk(b"case-distinct", 42);
    let two = mk(b"case-distinct", 43);
    let c_distinct = {
        let a = c_node_exchange(&one, &[10]).delivered.len();
        let b = c_node_exchange(&two, &[10]).delivered.len();
        a + b
    };
    let r_distinct = rust_dedup_exchange(&[&one, &two], DedupMode::Incoming);
    assert_eq!(
        c_distinct, 2,
        "two frames differing only in source port are not duplicates for the C"
    );
    assert_eq!(
        r_distinct, c_distinct,
        "nor for the port -- a key that ignored the header would collapse these into one"
    );

    c_node_set_dedup(0);
}

/// Feed frames to a fresh port node with `mode` set, and count what the application reads.
fn rust_dedup_exchange(frames: &[&Vec<u8>], mode: DedupMode) -> usize {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces
        .add("INGRESS", NODE_ADDR, NETMASK, true)
        .unwrap();
    node.bind(10).unwrap();
    node.router.dedup_mode = mode;

    let mut delivered = 0;
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
                        delivered += 1;
                        drop(pkt);
                    }
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
    }
    delivered
}
