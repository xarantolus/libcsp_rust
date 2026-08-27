//! Address aliases — a second address the node answers to — against a real C node.
//!
//! # Nothing had ever named one
//!
//! Measured on this branch: no `ctest` suite mentions an alias, no corpus record does, no
//! differential test does. `csp_route.c:236` nevertheless folds
//! `csp_addr_is_alias(packet->id.dst)` into the is-it-for-me decision, alongside "any
//! interface's address" and "the ingress interface's broadcast", and `csp/src/router.rs:473`
//! says the port does the same through `IfList::find_by_addr`. That was a reading of
//! `csp_iflist.c` deciding whether a command sent to a node's second address is **delivered
//! or forwarded back out onto the wire** — the same either/or the forwarding bug got wrong.
//!
//! # What is compared
//!
//! What the application receives and what leaves on the wire, for the same frame, with and
//! without the alias registered. The "without" half is what makes the "with" half mean
//! anything: an address the node does not answer to must be forwarded, so a test that only
//! checked the alias case would pass on a node that delivered everything.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;
const NETMASK: u16 = 12;
const PORT: u8 = 10;
const HDR: usize = 6;

/// The node's second address. In the same subnet as neither interface, so nothing but the
/// alias can make it local — otherwise the subnet rule would decide and the alias would
/// never be consulted.
const ALIAS_ADDR: u16 = 4001;
/// A third address the node answers to on no interface and by no alias.
const STRANGER: u16 = 4002;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn framed(dst: u16, sport: u8) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: 4000,
        dst,
        dport: PORT,
        sport,
    };
    let mut v = vec![0u8; HDR + 4];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(b"cmd!");
    v
}

/// Deliver `frame` to a port node, optionally with `ALIAS_ADDR` registered.
///
/// Returns (payloads the application got, frames that left on the wire).
fn port_outcome(frame: &[u8], with_alias: bool) -> (Vec<Vec<u8>>, usize) {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces
        .add("INGRESS", NODE_ADDR, NETMASK, false)
        .unwrap();
    node.ifaces
        .add("EGRESS", EGRESS_ADDR, NETMASK, true)
        .unwrap();
    if with_alias {
        node.ifaces.add_alias(ALIAS_ADDR, 0).unwrap();
    }
    node.bind(PORT).unwrap();

    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, frame).expect("frame");
    node.router.receive(p, 0);

    let (mut got, mut left) = (Vec::new(), 0);
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    got.push(pkt.with_payload(<[u8]>::to_vec));
                    drop(pkt);
                }
            }
            Routed::Forwarded { packet, .. } => {
                drop(node.take_forwarded(packet));
                left += 1;
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    (got, left)
}

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, NODE_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );
    assert_eq!(c_node_bind(PORT), 0, "bind port {PORT}");
}

/// Before the alias exists, both stacks forward a packet addressed to it.
///
/// This runs first on purpose: the C's alias list is global and has no remove, so once
/// `ALIAS_ADDR` is registered in this process it stays. Asking the "not an alias" question
/// afterwards would be asking it of a node that has one.
#[test]
fn an_address_that_is_not_an_alias_is_not_ours() {
    let _g = lock();
    setup();
    assert!(
        !c_node_is_alias(STRANGER),
        "STRANGER must not be an alias — if it were, this test proves nothing"
    );

    let frame = framed(STRANGER, 40);
    let c = c_node_exchange(&frame, &[PORT]);
    assert_eq!(
        c.delivered.len(),
        0,
        "the C does not deliver a packet for an address it does not answer to"
    );
    assert_eq!(c.tx.len(), 1, "it forwards it instead");

    let (got, left) = port_outcome(&frame, false);
    assert_eq!(got.len(), 0, "nor does the port deliver it");
    assert_eq!(left, 1, "and it forwards it too");
}

/// With the alias registered, both stacks deliver to the bound port instead of forwarding.
#[test]
fn a_packet_for_a_registered_alias_is_delivered_by_both() {
    let _g = lock();
    setup();

    // Before: not an alias, so it is forwarded. Establishing the baseline in the same
    // process is what distinguishes "the alias worked" from "this address was always local".
    let frame = framed(ALIAS_ADDR, 41);
    let before = c_node_exchange(&frame, &[PORT]);
    assert_eq!(
        before.delivered.len(),
        0,
        "not local before the alias exists"
    );
    assert_eq!(before.tx.len(), 1, "forwarded before the alias exists");

    assert!(c_node_add_alias(ALIAS_ADDR, 0), "register it on INGRESS");
    assert!(c_node_is_alias(ALIAS_ADDR), "libcsp now answers to it");

    let after = c_node_exchange(&framed(ALIAS_ADDR, 42), &[PORT]);
    assert_eq!(
        after.delivered.len(),
        1,
        "the C delivers a packet for its alias"
    );
    assert_eq!(after.delivered[0].payload, b"cmd!");
    assert_eq!(after.tx.len(), 0, "and does not also forward it");

    let (got, left) = port_outcome(&framed(ALIAS_ADDR, 42), true);
    assert_eq!(got.len(), 1, "and so must the port");
    assert_eq!(got[0], b"cmd!", "with the payload intact");
    assert_eq!(left, 0, "and it must not forward it as well");

    // And the alias makes exactly *one* address local, not everything: a `for_us` that
    // said yes to anything once an alias existed would satisfy every assertion above.
    //
    // This lives here rather than in a test of its own because the C's alias list is global
    // with no remove, so a separate test registering `ALIAS_ADDR` would break this one's
    // "before" half depending on which acquired the lock first — the tests passed three
    // runs in a row on scheduling luck. One experiment, one test.
    let stranger = framed(STRANGER, 43);
    let c = c_node_exchange(&stranger, &[PORT]);
    assert_eq!(
        c.delivered.len(),
        0,
        "the C still forwards an unrelated address once an alias exists"
    );
    assert_eq!(c.tx.len(), 1);
    let (got, left) = port_outcome(&stranger, true);
    assert_eq!(got.len(), 0, "and so does the port");
    assert_eq!(left, 1);
}
