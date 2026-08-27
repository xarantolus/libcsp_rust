//! `csp_send_prio` — what it leaves behind on the connection — against a real C node.
//!
//! # A divergence that was written down but never measured
//!
//! `csp_io.c:322` is two lines:
//!
//! ```c
//! void csp_send_prio(uint8_t prio, csp_conn_t * conn, csp_packet_t * packet) {
//!     conn->idout.pri = prio;
//!     csp_send(conn, packet);
//! }
//! ```
//!
//! The write is to the **connection**, not the packet. So a caller raising the priority of
//! one urgent frame raises every frame it sends on that connection afterwards, for the life
//! of the connection, and nothing says so.
//!
//! `csp/src/node.rs` said exactly that in a doc comment and `send_prio` applies the override
//! to one packet only. But measured on this branch: `csp_send_prio` appeared nowhere in
//! `difftest/`, `ctest/` or `corpus/`, `SCOPE.md` did not list the divergence, and the only
//! test was a unit test asserting the port's own half. The claim about libcsp came from
//! reading libcsp — the shape that has been wrong twice here.
//!
//! It is not wrong this time. Measured, one connection, three sends:
//!
//! | | plain | `send_prio(0)` | plain again |
//! |---|---|---|---|
//! | C | 2 | 0 | **0** |
//! | port | 2 | 0 | **2** |
//!
//! # Which behaviour the port keeps, and why the test asserts the difference
//!
//! The port's. A call named "send this one at high priority" that permanently reclassifies
//! a connection is a trap, and on a CAN bus priority is arbitration order — every later
//! frame would win the bus against traffic it should have yielded to. Someone porting C
//! that leans on the stickiness needs to know, which is what SCOPE.md 32 is for.
//!
//! So this asserts the **divergence**: if the port is ever "fixed" toward the C, the third
//! frame's priority changes and the test fails.

use csp::{Config, CspStorage, Node, Outbound};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 20;
const NETMASK: u16 = 12;
const PORT: u8 = 10;

/// The priority a connection is opened with, in both stacks.
const NORMAL: u8 = 2;
/// The override asked for, chosen at the far end of the range so a frame carrying it cannot
/// be confused with one that kept the default.
const URGENT: u8 = 0;

fn pri_of(frame: &[u8]) -> u8 {
    Id::decode(VERSION, frame)
        .expect("a frame the C emitted must decode")
        .pri
}

/// The priorities the C puts on the wire for: plain, `send_prio(URGENT)`, plain again.
fn c_priorities() -> [u8; 3] {
    let one = c_node_client_send(R_ADDR, PORT, b"one");
    let two = c_node_client_send_prio(URGENT, R_ADDR, PORT, b"two");
    let three = c_node_client_send(R_ADDR, PORT, b"three");
    for (n, f) in [&one, &two, &three].into_iter().enumerate() {
        assert_eq!(f.len(), 1, "the C must emit exactly one frame for send {n}");
    }
    [pri_of(&one[0]), pri_of(&two[0]), pri_of(&three[0])]
}

/// The same three sends on a port node, on one connection.
fn port_priorities() -> [u8; 3] {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: Node<'_, 8, 24, 300, 64, 8, 8> =
        Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("OUT", R_ADDR, NETMASK, true).unwrap();
    let conn = node.connect(NORMAL, C_ADDR, PORT, 0, 0).unwrap();

    // The priority the frame actually leaves with, off the packet the node hands back --
    // not the connection's field. What a peer sees is the whole question.
    fn on_the_wire(out: Outbound<'_, 24, 300>) -> u8 {
        let p = out.into_packet();
        let pri = p.id().pri;
        drop(p);
        pri
    }

    let mut send = |body: &[u8], prio: Option<u8>| -> u8 {
        let mut p = node.packet().expect("pool");
        p.set_payload(body).expect("payload");
        let out = match prio {
            Some(pri) => node.send_prio(conn, pri, p, 0),
            None => node.send(conn, p, 0),
        };
        on_the_wire(out.expect("the node must route it"))
    };
    [
        send(b"one", None),
        send(b"two", Some(URGENT)),
        send(b"three", None),
    ]
}

/// The override sticks to the connection in the C and to the packet here.
///
/// The first two frames are what makes the third mean anything: both stacks must agree that
/// a plain send carries the connection's priority and that the override reaches the wire at
/// all. Without them, "the third frame is 2" is satisfied by a `send_prio` that does nothing.
#[test]
fn send_prio_changes_one_packet_here_and_the_whole_connection_in_the_c() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, R_ADDR, 40),
        "C node came up at v2"
    );

    let c = c_priorities();
    let port = port_priorities();

    assert_eq!(
        c[0], NORMAL,
        "a plain send carries the connection's priority (C)"
    );
    assert_eq!(port[0], NORMAL, "and here");
    assert_eq!(c[1], URGENT, "the override reaches the wire (C)");
    assert_eq!(port[1], URGENT, "and here");

    // The divergence, asserted as one. `assert_ne` alone would pass if the port started
    // emitting anything at all that was not 0, so both sides are pinned to their value.
    assert_ne!(
        c[2], port[2],
        "this is a deliberate divergence (SCOPE.md 32); if it has gone, one of them moved"
    );
    assert_eq!(
        c[2], URGENT,
        "the C's next plain send inherits the raised priority -- conn->idout.pri was written"
    );
    assert_eq!(
        port[2], NORMAL,
        "the port's override applied to that packet and nothing after it"
    );
}
