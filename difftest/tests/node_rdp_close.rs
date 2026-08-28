//! What a real C peer sees when the **port** closes an RDP connection.
//!
//! The other direction is measured (`node_rdp_peer.rs`, `node_rdp_reset.rs`): the C closes,
//! sends `ACK|RST`, and the port answers so the C's close completes. This is the port
//! closing. `csp_close` on an RDP connection sends `ACK|RST` and holds the slot until the
//! peer answers or the connection times out (`csp_rdp_close_internal`, `csp_rdp.c:936`);
//! the peer, on an in-sequence RST, answers `ACK|RST` and — with `CSP_USE_RDP_FAST_CLOSE`,
//! which `csp_rdp.c:32` defines to 1 — frees its side at once.
//!
//! Measured here: after the port closes, how many frames it puts on the wire, and whether
//! the C peer's connection is still open afterwards.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;
const RDP_PORT: u8 = 10;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

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

fn inject(node: &mut TestNode, frame: &[u8]) {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, frame).expect("the C's frame");
    node.router.receive(p, 0);
}

#[test]
fn closing_an_rdp_connection_tells_the_c_peer_and_frees_its_side() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        NODE_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));
    assert_eq!(c_node_bind(RDP_PORT), 0);
    let open_before = c_node_open_conns();

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
    inject(&mut node, &answer.tx[0]);
    for f in drain(&mut node, 1100) {
        c_node_exchange(&f, &[]);
    }
    assert!(node.is_rdp_open(conn), "handshake completes");

    // One acknowledged exchange, so both sides are established and in sequence.
    let mut d = node.packet().expect("pool");
    d.set_payload(b"hello").unwrap();
    let frame = match node.send(conn, d, 1200).expect("send") {
        Outbound::Transmit { mut packet, .. } => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("{other:?}"),
    };
    // Not watched: watching a port makes the harness accept, read and `csp_close`, and the
    // C would be the one closing. The data stays queued; with delayed acks the C's
    // acknowledgement waits for its timer, and nothing here depends on it.
    let got = c_node_exchange(&frame, &[]);
    for f in &got.tx {
        inject(&mut node, f);
    }
    let _ = drain(&mut node, 1300);
    assert!(node.is_rdp_open(conn), "still open after the exchange");
    assert_eq!(
        c_node_open_conns(),
        open_before + 1,
        "the C holds one connection for us"
    );

    // The port closes.
    node.close(conn, 1400).expect("close");
    assert!(
        node.router.conns.is_live(conn),
        "csp_close returns while the handshake is outstanding; the slot is held until the \
         peer answers or CLOSE_WAIT times out"
    );
    assert!(
        !node.conn_is_active(conn, 1400),
        "but csp_conn_is_active already says no in CLOSE_WAIT"
    );
    let on_close = drain(&mut node, 1400);
    assert_eq!(
        on_close.len(),
        1,
        "csp_close sends exactly one ACK|RST; a close that sends nothing leaves the peer \
         holding the connection until its own timeout"
    );
    let reply = c_node_exchange(&on_close[0], &[]);
    assert_eq!(
        reply.tx.len(),
        1,
        "the C answers an in-sequence RST with ACK|RST"
    );
    // `discard_close` (`csp_rdp.c:780`): the connection was announced to the socket at the
    // handshake, so `dest_socket` is NULL and the C closes it with PROTOCOL|TIMEOUT only --
    // `csp_rdp_close` returns AGAIN until userspace closes too. It wakes the reader with a
    // NULL packet instead. So the C still holds the slot here.
    assert_eq!(
        c_node_open_conns(),
        open_before + 1,
        "the C keeps an announced connection until its application closes it"
    );
    // The application accepts, reads the NULL and closes: now it is freed.
    assert_eq!(
        c_node_accept_count(RDP_PORT),
        1,
        "the connection was announced to the socket"
    );
    assert_eq!(
        c_node_open_conns(),
        open_before,
        "and userspace closing it frees the slot"
    );

    // Our side completes on the peer's answer.
    inject(&mut node, &reply.tx[0]);
    let _ = drain(&mut node, 1500);
    assert!(
        !node.router.conns.is_live(conn),
        "the peer's ACK|RST completes the port's close and releases the slot"
    );
}
