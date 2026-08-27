//! The transparent bridge, compared against a real `csp_bridge_work`.
//!
//! # Why this file exists
//!
//! `csp_bridge.c` was in **neither** build — not difftest's source list, not `ctest`'s — so
//! the C bridge had never been compiled in this project, let alone run. `Router::bridge_work`
//! was a reading of it, and its only tests lived inside `router.rs` and asserted
//! `Bridged::Forward { iface: 2 }`.
//!
//! That is the forwarding bug's exact shape, and it was the forwarding bug: `Bridged::Forward`
//! carried an interface index and no pool slot, so `bridge_work` popped the packet from the
//! queue, reported where it should go, and dropped it on the way out of the function. A node
//! running the bridge forwarded **nothing**, and every test passed.
//!
//! # The bridge is not the router with a different destination
//!
//! `csp_bridge_work` consults no routing table, applies no split horizon, rewrites no
//! address, and never delivers locally — a frame addressed to the bridge's own interface
//! address is forwarded like any other. It also deduplicates *unconditionally*
//! (`csp_bridge.c:45` calls `csp_dedup_is_duplicate` without consulting `csp_conf.dedup`),
//! because a bridge is exactly where a frame can loop.

use csp::router::{Bridged, DropReason};
use csp::{Config, CspStorage, Node};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
/// Side A of the bridge, and the C node's own interface address.
const A_ADDR: u16 = 9;
/// Side B.
const B_ADDR: u16 = 20;
/// An interface that is neither side.
const C_ADDR: u16 = 40;
const NETMASK: u16 = 12;
const HDR: usize = 6;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn framed(dst: u16, sport: u8, body: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: 4000,
        dst,
        dport: 10,
        sport,
    };
    let mut v = vec![0u8; HDR + body.len()];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(body);
    v
}

/// The port's bridge, driven the way an application would: one step, then take the packet.
///
/// Returns the interface name the frame would leave by and the framed bytes handed over —
/// the same two things the C's capture nexthop records, so the two are comparable.
fn port_bridge_step(ingress: u8, frame: &[u8]) -> Option<(String, Vec<u8>)> {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(A_ADDR));
    node.ifaces.add("INGRESS", A_ADDR, NETMASK, false).unwrap();
    node.ifaces.add("EGRESS", B_ADDR, NETMASK, false).unwrap();
    node.ifaces.add("ROUTED", C_ADDR, NETMASK, false).unwrap();

    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, frame).expect("frame");
    node.router.receive(p, ingress);

    match node.router.bridge_work(node.pool(), 0, 1, 0) {
        Bridged::Forward { iface, packet } => {
            let pkt = node
                .take_forwarded(packet)
                .expect("Forward must hand over a packet the caller can send");
            let bytes = pkt.with_frame(|f| f.to_vec());
            let name = node
                .ifaces
                .get(iface)
                .expect("a named interface")
                .name
                .to_owned();
            Some((name, bytes))
        }
        _ => None,
    }
}

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, A_ADDR, NETMASK, B_ADDR, C_ADDR),
        "C node came up at v2"
    );
    c_bridge_set(0, 1);
    // Off, so the deduplication below is the bridge's own and not the router's setting.
    c_node_set_dedup(0);
}

/// A frame in on one side leaves on the other, byte for byte.
///
/// The bytes matter as much as the interface: a bridge that rewrote the header would still
/// name the right interface, and a bridge that dropped the packet — which this one did —
/// names the right interface too.
#[test]
fn each_side_reaches_the_other_carrying_what_arrived() {
    let _g = lock();
    setup();

    let f = framed(77, 40, b"a to b");
    let c = c_bridge_step(0, &f);
    let r = port_bridge_step(0, &f);
    assert_eq!(c.len(), 1, "the C forwards a frame arriving on side A");
    assert_eq!(c[0].0, "EGRESS", "out the opposing interface");
    assert_eq!(c[0].1, f, "unchanged — a bridge rewrites nothing");
    let r = r.expect("the port must forward it too, not merely name an interface");
    assert_eq!(
        (r.0.as_str(), &r.1),
        ("EGRESS", &c[0].1),
        "the port must put the same bytes on the same wire"
    );

    let f = framed(78, 41, b"b to a");
    let c = c_bridge_step(1, &f);
    let r = port_bridge_step(1, &f).expect("and in the other direction");
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].0, "INGRESS");
    assert_eq!(c[0].1, f);
    assert_eq!((r.0.as_str(), &r.1), ("INGRESS", &c[0].1));
}

/// A bridge deduplicates whatever the node's deduplication setting says.
///
/// `csp_conf.dedup` is off for the whole of this file. The C still drops the second copy —
/// `csp_bridge.c` does not consult the flag — because a bridge that does not deduplicate
/// loops a frame between its two interfaces until something gives out.
#[test]
fn a_repeated_frame_is_dropped_by_both_even_with_deduplication_off() {
    let _g = lock();
    setup();

    let f = framed(79, 42, b"looping");
    assert_eq!(
        c_bridge_step(0, &f).len(),
        1,
        "the first copy crosses the C's bridge"
    );
    assert_eq!(
        c_bridge_step(0, &f).len(),
        0,
        "and the second does not, though csp_conf.dedup is off"
    );

    // The port sees both copies on one node, since dedup is per-node state.
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(A_ADDR));
    node.ifaces.add("INGRESS", A_ADDR, NETMASK, false).unwrap();
    node.ifaces.add("EGRESS", B_ADDR, NETMASK, false).unwrap();
    assert_eq!(node.router.dedup_mode, csp::dedup::DedupMode::Off);

    let mut outcomes = Vec::new();
    for _ in 0..2 {
        let mut p = node.packet().expect("pool");
        p.set_frame(VERSION, &f).unwrap();
        node.router.receive(p, 0);
        match node.router.bridge_work(node.pool(), 0, 1, 0) {
            Bridged::Forward { packet, .. } => {
                drop(node.take_forwarded(packet));
                outcomes.push("forward");
            }
            Bridged::Dropped(DropReason::Duplicate) => outcomes.push("duplicate"),
            other => panic!("unexpected: {other:?}"),
        }
    }
    assert_eq!(
        outcomes,
        vec!["forward", "duplicate"],
        "the port must drop the second copy too — with deduplication off, which is the \
         default, a bridge that honours the flag loops"
    );

    // A control: a frame that is not a repeat still crosses, so the case above is not
    // passing because the bridge stopped forwarding altogether.
    let g = framed(79, 43, b"looping");
    assert_eq!(
        c_bridge_step(0, &g).len(),
        1,
        "a distinct frame still crosses"
    );
    assert!(port_bridge_step(0, &g).is_some(), "for the port as well");
}

/// A frame for the bridge's own interface address is forwarded, not delivered.
///
/// The bridge never asks "is this for me" — there is no `csp_iflist_get_by_addr` call in
/// `csp_bridge_work`. A node bridging two links is a wire, not a host.
#[test]
fn a_frame_addressed_to_the_bridge_itself_is_still_forwarded() {
    let _g = lock();
    setup();

    let f = framed(A_ADDR, 44, b"mine");
    let c = c_bridge_step(0, &f);
    assert_eq!(c.len(), 1, "the C forwards it rather than delivering it");
    assert_eq!(c[0].0, "EGRESS");
    let r = port_bridge_step(0, &f).expect("and so must the port");
    assert_eq!((r.0.as_str(), &r.1), ("EGRESS", &c[0].1));
}

/// A broadcast crosses the bridge unchanged — no fan-out, no rewrite.
#[test]
fn a_broadcast_crosses_the_bridge_as_one_frame() {
    let _g = lock();
    setup();

    let f = framed(0x3FFF, 45, b"bcast");
    let c = c_bridge_step(0, &f);
    assert_eq!(c.len(), 1, "one frame, not one per interface");
    assert_eq!(c[0].1, f, "and the destination is not rewritten");
    let r = port_bridge_step(0, &f).expect("the port forwards it too");
    assert_eq!((r.0.as_str(), &r.1), ("EGRESS", &c[0].1));
}

/// **Deliberate divergence.** A frame from an interface that is neither side of the bridge.
///
/// `csp_bridge.c:60` is `if (input.iface == bif_a) destif = bif_b; else destif = bif_a;` —
/// there is no third branch, so a frame from an unrelated interface is injected into side A
/// as though it had arrived from side B. Measured here, not inferred: the C emits it on
/// INGRESS.
///
/// The port refuses instead. A bridge is a two-port device; forwarding a third network's
/// traffic into one of them is how traffic crosses between networks that were never
/// bridged. This test asserts the **difference**, so a change back toward the C fails
/// rather than passing quietly.
#[test]
fn a_frame_from_neither_side_is_injected_into_side_a_by_the_c_and_refused_by_the_port() {
    let _g = lock();
    setup();

    let f = framed(81, 46, b"from elsewhere");

    let c = c_bridge_step(2, &f);
    assert_eq!(
        c.len(),
        1,
        "the C forwards it — its `else` has no third branch"
    );
    assert_eq!(
        c[0].0, "INGRESS",
        "into side A, as though it had come from side B"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(A_ADDR));
    node.ifaces.add("INGRESS", A_ADDR, NETMASK, false).unwrap();
    node.ifaces.add("EGRESS", B_ADDR, NETMASK, false).unwrap();
    node.ifaces.add("ROUTED", C_ADDR, NETMASK, false).unwrap();
    let before = node.buffers_free();

    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &f).unwrap();
    node.router.receive(p, 2);
    assert_eq!(
        node.router.bridge_work(node.pool(), 0, 1, 0),
        Bridged::Dropped(DropReason::NoRoute),
        "the port refuses a frame from neither side"
    );
    assert_eq!(
        node.buffers_free(),
        before,
        "and refusing must not cost a buffer"
    );
}
