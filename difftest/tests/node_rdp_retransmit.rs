//! Retransmission after loss, against a real C peer.
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
//! # What loss makes observable
//!
//! Retransmission has only ever been driven at the libcheck level, where the give-up case
//! is a recorded divergence. What no test has asked is whether the frame the port
//! retransmits is one a **real C peer accepts** — the retransmitted copy carries the
//! original sequence number and a *refreshed* acknowledgement, and an earlier bug in that
//! refresh wrote the ack past the trailer and stretched the packet to the whole buffer.
//! Nothing on this side would notice; only the peer would.
//!
//! Loss is modelled by simply not handing a frame to the C. That is what loss is.

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

/// A data packet is lost; the retransmission is what reaches the peer.
///
/// The port sends, the frame never reaches the C, the clock passes `packet_timeout`, and the
/// port retransmits. The retransmitted frame is the one delivered — and the C's application
/// has to receive the payload **exactly once**, with the trailer stripped, as though nothing
/// had been lost.
#[test]
fn a_lost_packet_is_retransmitted_in_a_form_the_c_accepts() {
    use csp_core::rdp;

    const RDP_PORT: u8 = 10;
    /// `SynOptions::default()` — the C's compiled-in value, and what our SYN proposed.
    const PACKET_TIMEOUT_MS: u32 = 1000;

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

    // Send, and throw the frame away. The peer never sees it.
    let mut d = node.packet().expect("pool");
    d.set_payload(b"lost-then-found").unwrap();
    let lost = match node.send(conn, d, 1200) {
        Ok(Outbound::Transmit { mut packet, .. }) => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("send on an open connection: {other:?}"),
    };
    let original = {
        let mut p = node.packet().expect("pool");
        p.set_frame(VERSION, &lost).unwrap();
        let h = p.with_payload(|b| rdp::Header::decode(b).expect("an RDP trailer"));
        drop(p);
        h
    };

    // Nothing acknowledges it, so after the packet timeout the port should send it again.
    let mut resent = Vec::new();
    for step in 1..=4u32 {
        node.tick(1200 + step * PACKET_TIMEOUT_MS, 10_000);
        resent.extend(drain(&mut node, 1200 + step * PACKET_TIMEOUT_MS));
        if !resent.is_empty() {
            break;
        }
    }
    assert!(
        !resent.is_empty(),
        "an unacknowledged packet must be retransmitted; nothing came back after four \
         packet timeouts, so the peer would wait for data that was never resent"
    );

    // Same sequence number, or the peer treats it as new data and the original stays missing.
    let again = {
        let mut p = node.packet().expect("pool");
        p.set_frame(VERSION, &resent[0]).expect("our own frame");
        let h = p.with_payload(|b| rdp::Header::decode(b).expect("an RDP trailer"));
        drop(p);
        h
    };
    assert_eq!(
        again.seq_nr, original.seq_nr,
        "a retransmission repeats the sequence number it is retransmitting"
    );

    // And the peer accepts it: the payload reaches the C's application once, intact.
    let got = c_node_exchange(&resent[0], &[RDP_PORT]);
    assert_eq!(
        got.delivered.len(),
        1,
        "the C's application receives the retransmitted packet"
    );
    assert_eq!(
        got.delivered[0].payload, b"lost-then-found",
        "with the RDP trailer removed and the body intact"
    );
}
