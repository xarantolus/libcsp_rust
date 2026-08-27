//! Closing an RDP connection that still has data in flight.
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
//! # Why this case
//!
//! An RDP sender keeps a copy of every unacknowledged packet so it can retransmit it. Close
//! the connection before those are acknowledged and the copies have to be released, or a
//! node leaks one buffer per packet in flight — permanently, since a closed connection is
//! never coming back to free them. libcsp PR #3's fourth item is exactly this, and
//! `SCOPE.md` claimed it had no counterpart here on the grounds that the port had no live
//! transmit queue. It has had one for some time; the claim was stale, and nothing had ever
//! checked the behaviour it was excusing.

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
/// Both stacks must return every buffer held for retransmission when the connection closes.
///
/// The data is deliberately never acknowledged: each side is made to hold several packets
/// in flight, and then the connection is closed underneath them. What is compared is the
/// pool before and after — the only thing that distinguishes a connection that cleaned up
/// from one that quietly kept its buffers.
#[test]
fn closing_a_connection_with_data_in_flight_leaks_nothing() {
    const RDP_PORT: u8 = 11;
    /// Under the window of 4, so every one is sent and none is acknowledged.
    const IN_FLIGHT: usize = 3;

    let _g = lock();
    setup();
    assert_eq!(c_node_bind(RDP_PORT), 0, "bind this test's own port");

    // --- the port's side: send, never deliver, then close ---
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();

    let before = node.pool().available();

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

    // Send, and drop the frames on the floor. Nothing is acknowledged, so the port keeps a
    // copy of each for retransmission.
    for i in 0..IN_FLIGHT {
        let mut d = node.packet().expect("pool");
        d.set_payload(format!("inflight{i}").as_bytes()).unwrap();
        match node.send(conn, d, 1200 + i as u32) {
            Ok(Outbound::Transmit { packet, .. }) => drop(packet),
            other => panic!("send {i} on an open connection: {other:?}"),
        }
    }
    assert!(
        node.pool().available() < before,
        "the port is holding something for retransmission; if the pool is already back to \
         {before} then nothing was retained and this case tests nothing"
    );

    node.close(conn).expect("close");
    // A close can queue a reset for the peer; drain it so the comparison is of what the
    // connection released, not of a frame still waiting to be handed to a driver.
    for f in drain(&mut node, 1300) {
        c_node_exchange(&f, &[]);
    }
    assert_eq!(
        node.pool().available(),
        before,
        "closing a connection with {IN_FLIGHT} packets in flight must return every buffer \
         -- what is retained here is retained for good, because the connection is gone"
    );

    // --- the C's side, the same shape ---
    let c_before = c_node_buf_free();
    let mut c_node2: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 2));
    c_node2
        .ifaces
        .add("test", NODE_ADDR + 2, NETMASK, true)
        .unwrap();
    let c_conn = c_node2
        .connect(
            2,
            NODE_ADDR,
            RDP_PORT,
            csp_core::security::opts::RDP_REQ,
            2000,
        )
        .expect("rdp connect");
    let syn2 = drain(&mut c_node2, 2000);
    let answer2 = c_node_exchange(&syn2[0], &[]);
    assert_eq!(answer2.tx.len(), 1, "the C answers the second SYN");
    let mut inject2 = c_node2.packet().expect("pool");
    inject2.set_frame(VERSION, &answer2.tx[0]).unwrap();
    c_node2.router.receive(inject2, 0);
    for f in drain(&mut c_node2, 2100) {
        c_node_exchange(&f, &[]);
    }
    assert!(c_node2.is_rdp_open(c_conn), "second handshake completes");

    // One send so the C's application takes the connection, then the C originates and we
    // never acknowledge any of it.
    let mut opener = c_node2.packet().expect("pool");
    opener.set_payload(b"open").unwrap();
    if let Ok(Outbound::Transmit { mut packet, .. }) = c_node2.send(c_conn, opener, 2150) {
        packet.prepend_header(VERSION).unwrap();
        let f = packet.with_frame(|x| x.to_vec());
        drop(packet);
        c_node_exchange(&f, &[]);
    }
    for i in 0..IN_FLIGHT {
        let sent = c_node_send_on(RDP_PORT, format!("c-inflight{i}").as_bytes());
        assert_eq!(sent.len(), 1, "the C put message {i} on the wire");
        // deliberately not fed back to the port: nothing acknowledges it
    }
    assert!(
        c_node_buf_free() < c_before,
        "the C is holding something for retransmission"
    );

    // `csp_conn_close` returns early while the RDP close handshake is outstanding
    // (`csp_conn.c:230`), *before* the receive-queue flush and `csp_rdp_queue_flush` — so
    // the C still holds everything at this point. That is deferral, not a leak, and the
    // difference is worth measuring rather than glossing.
    let closing = c_node_release(RDP_PORT);
    assert!(
        c_node_buf_free() < c_before,
        "the C has not released yet: its close is a handshake, not an immediate teardown"
    );

    // The close does put a frame on the wire -- `ACK|RST`, the upper nibble being
    // `csp_rdp_incr` which the receiver masks off -- so the peer is told.
    assert_eq!(closing.len(), 1, "the C's close resets the peer");
    for f in &closing {
        let mut p = c_node2.packet().expect("pool");
        if p.set_frame(VERSION, f).is_ok() {
            c_node2.router.receive(p, 0);
        }
    }
    for f in drain(&mut c_node2, 2300) {
        c_node_exchange(&f, &[]);
    }

    // **Deliberately not asserted: that the C gets its buffers back here.** It does not,
    // within this exchange, and I have not established whether its connection timeout would
    // eventually free them -- driving that needs real time, since the harness omits
    // `csp_time.c` only for the *virtual* clock in `ctest/`, not here. Asserting either
    // "the C releases them" or "the C leaks them" would be a number without its condition.
    // What is measured is the deferral itself, and its mechanism is not in doubt.
    assert!(
        c_node_buf_free() < c_before,
        "the C's teardown is deferred, not immediate"
    );
}
