//! Sustained RDP traffic, and a reset reported as a reset.
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
/// Sustained traffic over an RDP connection, and what a reset from the peer looks like.
///
/// Two things nothing had exercised. The first is more than one data packet: if the peer's
/// acknowledgements were not consumed the send window would never reopen, and a connection
/// that carries four packets and then wedges for ever looks fine in any test that sends one.
///
/// The second is the refusal itself. `csp_rdp_send` (`csp_rdp.c:863`) returns
/// `CSP_ERR_RESET` when the connection is not open and *blocks* when the window is full —
/// two different things. The port returned `Error::SendWindowFull` for both, and its own
/// documentation called that condition "temporary", which is false for half the cases it
/// covered. An application would retry for ever against a peer that had hung up.
#[test]
fn an_rdp_connection_sustains_traffic_and_reports_a_reset_as_a_reset() {
    // A port of its own. The C node is process-global and has no per-test reset (libcsp's
    // own suite forks instead), so two tests sharing a destination port leave the second
    // one talking to a connection the first opened — which showed up as the C ignoring a
    // perfectly good SYN.
    const RDP_PORT: u8 = 11;
    const BURST: usize = 10;

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
    assert_eq!(answer.tx.len(), 1, "the C answers this test's SYN");
    let mut inject = node.packet().expect("pool");
    inject
        .set_frame(VERSION, &answer.tx[0])
        .expect("the C's frame");
    node.router.receive(inject, 0);
    for f in drain(&mut node, 1100) {
        c_node_exchange(&f, &[]);
    }
    assert!(node.is_rdp_open(conn), "handshake completes");

    // A burst several times the window of 4. Each frame goes to the C; whatever the C says
    // back comes to us. If its acknowledgements were dropped the window would shut after
    // four and never reopen.
    for i in 0..BURST {
        let mut d = node.packet().expect("pool");
        d.set_payload(format!("msg{i}").as_bytes()).unwrap();
        let now = 1200 + i as u32 * 10;
        let frame = match node.send(conn, d, now) {
            Ok(Outbound::Transmit { mut packet, .. }) => {
                packet.prepend_header(VERSION).unwrap();
                packet.with_frame(|f| f.to_vec())
            }
            other => panic!("send {i} of {BURST} on an open connection: {other:?}"),
        };
        let got = c_node_exchange(&frame, &[]);
        for reply in &got.tx {
            let mut back = node.packet().expect("pool");
            if back.set_frame(VERSION, reply).is_ok() {
                node.router.receive(back, 0);
            }
        }
        for f in drain(&mut node, now) {
            c_node_exchange(&f, &[]);
        }
    }
    assert!(
        node.is_rdp_open(conn),
        "the connection survives a burst well past one window"
    );

    // Now let the C's application read and close, which is how libcsp resets a peer.
    let mut d = node.packet().expect("pool");
    d.set_payload(b"last").unwrap();
    let frame = match node.send(conn, d, 1400) {
        Ok(Outbound::Transmit { mut packet, .. }) => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("still open: {other:?}"),
    };
    // Watching the port makes the shim accept, read and `csp_close` — the C sends an RST.
    let closed = c_node_exchange(&frame, &[RDP_PORT]);
    assert_eq!(
        closed.delivered.len(),
        1,
        "the C's application reads the message before closing"
    );
    for reply in &closed.tx {
        let mut back = node.packet().expect("pool");
        if back.set_frame(VERSION, reply).is_ok() {
            node.router.receive(back, 0);
        }
    }
    while !matches!(node.work(1500), Routed::Idle) {}

    // The next send must say the connection is gone, not that it is momentarily busy.
    let mut d = node.packet().expect("pool");
    d.set_payload(b"after-reset").unwrap();
    assert_eq!(
        node.send(conn, d, 1600).err(),
        Some(csp_core::Error::ConnectionReset),
        "a peer that reset us is permanent; reporting back-pressure makes the caller retry \
         for ever"
    );
}
