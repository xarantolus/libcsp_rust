//! A real C peer's frames arriving out of order.
//!
//! # Why this is a third binary
//!
//! An RDP connection leaves durable state on the C node — a connection in `OPEN` or
//! `CLOSE_WAIT`, packets queued on it, buffers held — and libcsp has no per-test reset
//! (its own suite forks instead; `SCOPE.md` deviation 2). Sharing a process with
//! `node_v2.rs` made them interfere, and so did sharing one with each other: measured,
//! ten buffers stayed held after a burst even with every connection closed and libcsp's
//! global RDP queues flushed, so the third test in a binary started with a third of the
//! pool gone and failed depending on which order the threads ran in.
//!
//! So **one scenario per binary**. Cargo gives each integration-test file its own process,
//! which is the only reliable reset available — the same reason `node_v2.rs` is separate
//! from `diff.rs`.
//!
//! The C node here answers a `SYN` straight from its router, with no application involved:
//! the harness has always built with `CSP_USE_RDP=ON`.
//!
//! # What reordering makes observable
//!
//! `csp_rdp.c:723` stores an out-of-sequence packet with `csp_rdp_rx_queue_add` and walks
//! the queue once the hole is filled; `csp-core::rdp::RxQueue` and `Action::Hold` are the
//! port's equivalent. Both are covered at the libcheck level with hand-built frames. What
//! nothing had asked is whether the port reorders **a real peer's** frames — libcsp
//! sequences them, and the two only agree if the port reads that sequencing the same way.
//!
//! The reordering is done here, by handing the port the second frame first. That is what a
//! network does; neither stack has to cooperate.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, NODE_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );
}

/// Everything the node wants to put on the wire, framed and ready to inject.
fn drain(node: &mut TestNode, now: u32) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        match node.work(now) {
            Routed::Respond { packet, .. } => {
                let mut p = node.take_forwarded(packet).expect("slot");
                p.prepend_header(VERSION).unwrap();
                out.push(p.with_frame(|f| f.to_vec()));
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    out
}
/// Two messages from a real C peer, delivered to the port in the wrong order.
///
/// The application must see them **in order** and complete. A port that dropped the
/// overtaking frame would deliver one message and leave the peer to retransmit the other;
/// a port that delivered them as they arrived would hand the application a reordered stream
/// and call it reliable.
#[test]
fn a_real_peers_frames_are_reordered_before_the_application_sees_them() {
    const RDP_PORT: u8 = 12;

    let _g = lock();
    setup();
    assert_eq!(c_node_bind(RDP_PORT), 0, "bind this test's own port");

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();

    let conn = node
        .connect(
            2,
            NODE_ADDR,
            RDP_PORT,
            csp_core::security::opts::RDP_REQ,
            1000,
        )
        .expect("rdp connect");
    let syn = drain(&mut node, 1000);
    let answer = c_node_exchange(&syn[0], &[]);
    assert_eq!(answer.tx.len(), 1, "the C answers the SYN");
    let mut inject = node.packet().expect("pool");
    inject
        .set_frame(VERSION, &answer.tx[0])
        .expect("the C's frame");
    node.router.receive(inject, 0);
    for f in drain(&mut node, 1100) {
        c_node_exchange(&f, &[]);
    }
    assert!(node.is_rdp_open(conn), "handshake completes");

    // One send so the C's application takes the connection and can originate on it.
    let mut first = node.packet().expect("pool");
    first.set_payload(b"open").unwrap();
    let opener = match node.send(conn, first, 1150) {
        Ok(Outbound::Transmit { mut packet, .. }) => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("send on an open connection: {other:?}"),
    };
    for reply in &c_node_exchange(&opener, &[]).tx {
        let mut back = node.packet().expect("pool");
        if back.set_frame(VERSION, reply).is_ok() {
            node.router.receive(back, 0);
        }
    }
    for f in drain(&mut node, 1150) {
        c_node_exchange(&f, &[]);
    }

    // The C sends two messages, in order, as libcsp sequences them.
    let a = c_node_send_on(RDP_PORT, b"first");
    assert_eq!(a.len(), 1, "the C put the first message on the wire");
    let b = c_node_send_on(RDP_PORT, b"second");
    assert_eq!(b.len(), 1, "the C put the second message on the wire");

    // They reach the port the other way round.
    let mut all: Vec<Vec<u8>> = Vec::new();
    for frame in [&b[0], &a[0]] {
        let mut p = node.packet().expect("pool");
        p.set_frame(VERSION, frame).expect("the C's frame");
        node.router.receive(p, 0);
        loop {
            match node.work(1300) {
                Routed::Respond { packet, .. } => {
                    let mut r = node.take_forwarded(packet).expect("slot");
                    r.prepend_header(VERSION).unwrap();
                    let f = r.with_frame(|x| x.to_vec());
                    drop(r);
                    c_node_exchange(&f, &[]);
                }
                Routed::Delivered { .. } | Routed::Idle => break,
                _ => continue,
            }
        }
        // Read the connection itself rather than waiting for a `Delivered` event: a frame
        // the port held and released later arrives without a fresh event, and collecting
        // only on the event reported an empty application queue while the data sat on the
        // connection.
        while let Ok(Some(pkt)) = node.read(conn) {
            all.push(pkt.with_payload(|d| d.to_vec()));
            drop(pkt);
        }
    }
    while let Ok(Some(pkt)) = node.read(conn) {
        all.push(pkt.with_payload(|d| d.to_vec()));
        drop(pkt);
    }

    c_node_release(RDP_PORT);

    assert_eq!(
        all.len(),
        2,
        "both messages must reach the application -- got {:?}",
        all.iter()
            .map(|v| String::from_utf8_lossy(v).to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(all[0], b"first", "the overtaken message is delivered first");
    assert_eq!(
        all[1], b"second",
        "and the one that overtook it comes after"
    );
}
