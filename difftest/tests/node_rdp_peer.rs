//! A real C peer originating data on an RDP connection.
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
/// The other direction: a real C peer **originates** data on the connection.
///
/// Everything else here has the port sending and the C receiving. This has the C call
/// `csp_send` on the connection it accepted, so the bytes are sequenced and held for
/// retransmission by `csp_rdp_send` itself. The port has to recognise them as in-sequence
/// data, hand the payload up with the trailer removed, and acknowledge them — and if it
/// does not acknowledge, the C's send window closes after four and never reopens.
#[test]
fn a_real_c_peer_can_send_us_data_over_rdp() {
    const RDP_PORT: u8 = 12;
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

    // The port has to send once so the C's side finishes accepting the connection; the
    // C cannot originate on a connection its application has not taken yet.
    let mut first = node.packet().expect("pool");
    first.set_payload(b"hello").unwrap();
    let opener = match node.send(conn, first, 1150) {
        Ok(Outbound::Transmit { mut packet, .. }) => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("send on an open connection: {other:?}"),
    };
    let acked = c_node_exchange(&opener, &[]);
    for reply in &acked.tx {
        let mut back = node.packet().expect("pool");
        if back.set_frame(VERSION, reply).is_ok() {
            node.router.receive(back, 0);
        }
    }
    for f in drain(&mut node, 1150) {
        c_node_exchange(&f, &[]);
    }

    // Now the C speaks, repeatedly. More than one window, so a port that never
    // acknowledges runs the C out of window and the later messages never arrive.
    let mut received: Vec<Vec<u8>> = Vec::new();
    for i in 0..BURST {
        let body = format!("from-c-{i}");
        let frames = c_node_send_on(RDP_PORT, body.as_bytes());
        assert_eq!(
            frames.len(),
            1,
            "the C put message {i} of {BURST} on the wire -- if this is 0 its send window \
             never reopened, which means the port stopped acknowledging"
        );

        let mut p = node.packet().expect("pool");
        p.set_frame(VERSION, &frames[0]).expect("the C's frame");
        node.router.receive(p, 0);

        let now = 1200 + i as u32 * 10;
        loop {
            match node.work(now) {
                Routed::Delivered { conn: c, .. } => {
                    while let Ok(Some(pkt)) = node.read(c) {
                        received.push(pkt.with_payload(|d| d.to_vec()));
                        drop(pkt);
                    }
                }
                Routed::Respond { packet, .. } => {
                    let mut r = node.take_forwarded(packet).expect("slot");
                    r.prepend_header(VERSION).unwrap();
                    let f = r.with_frame(|x| x.to_vec());
                    drop(r);
                    c_node_exchange(&f, &[]);
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
    }

    c_node_release(RDP_PORT);

    assert_eq!(
        received.len(),
        BURST,
        "every message the C sent reaches the application"
    );
    for (i, got) in received.iter().enumerate() {
        assert_eq!(
            got,
            format!("from-c-{i}").as_bytes(),
            "message {i} arrives intact and with the RDP trailer removed"
        );
    }
}
