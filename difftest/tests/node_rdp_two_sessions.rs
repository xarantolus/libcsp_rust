//! Two RDP connections from the port to the same C node, interleaved — and the case that
//! found a buffer leak: several unacknowledged packets on one connection retransmitted in
//! a single sweep.
//!
//! A flight node holds several RDP connections at once (a file transfer and a telemetry
//! stream, say); the C keeps them apart by `(src, dst, sport, dport)`. Here both send turn
//! and turn about, B's second packet is never delivered, and B is left with **four**
//! unacknowledged packets (the opening datagram and three more) when its retransmission
//! timer fires — more than the router's fan-out queue (`MAX_FANOUT`) holds at once. The
//! copies past that bound had their pool slot taken by `into_index()` before the capacity
//! check and were then dropped on the floor: one leaked buffer per overflow, and the pool
//! never got it back. `push_pending_owned` now hands the whole packet over and drops it —
//! freeing the slot — when the queue is full, and the retransmission retries next sweep.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::security::opts;
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;
const PORT_A: u8 = 10;
const PORT_B: u8 = 11;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;
/// (connection, delivered payload).
type Delivery = (csp::conn::Handle, Vec<u8>);

/// Frames out, and (connection, payload) of everything delivered.
fn drain(node: &mut TestNode, now: u32) -> (Vec<Vec<u8>>, Vec<Delivery>) {
    let mut out = Vec::new();
    let mut delivered = Vec::new();
    loop {
        match node.work(now) {
            Routed::Respond { packet, .. } => {
                let mut p = node.take_forwarded(packet).expect("slot");
                p.prepend_header(VERSION).unwrap();
                out.push(p.with_frame(|f| f.to_vec()));
            }
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    delivered.push((conn, pkt.with_payload(|d| d.to_vec())));
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    (out, delivered)
}

fn inject(node: &mut TestNode, frame: &[u8]) {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, frame).expect("frame");
    node.router.receive(p, 0);
}

/// Port frames to the C and the C's answers back until quiet; returns what was delivered.
fn settle(node: &mut TestNode, now: u32) -> Vec<Delivery> {
    let mut delivered = Vec::new();
    for _ in 0..16 {
        let (out, d) = drain(node, now);
        delivered.extend(d);
        if out.is_empty() {
            break;
        }
        for f in &out {
            for r in &c_node_exchange(f, &[]).tx {
                inject(node, r);
            }
        }
    }
    delivered
}

fn send(node: &mut TestNode, conn: csp::conn::Handle, body: &[u8], now: u32) -> Vec<u8> {
    let mut p = node.packet().expect("pool");
    p.set_payload(body).unwrap();
    match node.send(conn, p, now).expect("send") {
        Outbound::Transmit { mut packet, .. } => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("{other:?}"),
    }
}

fn open(node: &mut TestNode, port: u8, now: u32) -> csp::conn::Handle {
    let conn = node
        .connect(2, NODE_ADDR, port, opts::RDP_REQ | opts::CRC32_REQ, now)
        .expect("connect");
    settle(node, now);
    assert!(node.is_rdp_open(conn), "session on port {port} opens");
    // One datagram so the C's application accepts and holds the connection. Left
    // unacknowledged deliberately: it is the fourth of B's outstanding packets later.
    let f = send(node, conn, b"open", now);
    for r in &c_node_exchange(&f, &[]).tx {
        inject(node, r);
    }
    let _ = drain(node, now);
    assert_eq!(c_node_read_held(port), 1);
    conn
}

#[test]
fn two_interleaved_sessions_stay_apart_and_a_multi_packet_retransmit_leaks_nothing() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        NODE_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));
    assert_eq!(c_node_bind(PORT_A), 0);
    assert_eq!(c_node_bind(PORT_B), 0);

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();
    let free_at_start = node.pool().available();

    let a = open(&mut node, PORT_A, 1000);
    let b = open(&mut node, PORT_B, 1100);
    assert_ne!(a, b);
    assert_eq!(c_node_open_conns(), 2, "the C holds both");

    // Turn and turn about; B's second data packet is never delivered. A's traffic is
    // acknowledged as it goes (its replies drive the C's acks); B's is left outstanding.
    let mut now = 1200u32;
    for i in 0..3u8 {
        for (conn, tag, port) in [(a, b'A', PORT_A), (b, b'B', PORT_B)] {
            let f = send(&mut node, conn, &[tag, i], now);
            if !(port == PORT_B && i == 1) {
                for r in &c_node_exchange(&f, &[]).tx {
                    inject(&mut node, r);
                }
            }
            settle(&mut node, now);
            now += 10;
        }
    }
    assert_eq!(c_node_read_held(PORT_A), 3, "A is complete");
    assert_eq!(c_node_read_held(PORT_B), 1, "B is stuck behind its gap");

    // B's timer retransmits all four of its outstanding packets at once — past MAX_FANOUT.
    now += 1001;
    node.tick(now, u32::MAX);
    settle(&mut node, now);
    assert_eq!(
        c_node_read_held(PORT_B),
        2,
        "B's gap is filled and the rest released"
    );
    assert_eq!(c_node_read_held(PORT_A), 0, "nothing was re-sent on A");

    // The C answers on both; each reply must land on its own connection.
    let mut frames = c_node_send_on(PORT_B, b"for B");
    frames.extend(c_node_send_on(PORT_A, b"for A"));
    assert_eq!(frames.len(), 2, "one frame per reply");
    for f in &frames {
        inject(&mut node, f);
    }
    let mut got = settle(&mut node, now);
    got.sort_by(|x, y| x.1.cmp(&y.1));
    assert_eq!(got, vec![(a, b"for A".to_vec()), (b, b"for B".to_vec())]);

    // Flush the C's delayed acknowledgements so nothing stays outstanding on either side,
    // then close both and let the CLOSE_WAIT timers release the slots.
    for _ in 0..8 {
        c_clock_advance(300);
        c_node_pump();
        for f in &c_node_tx_take() {
            inject(&mut node, f);
        }
        settle(&mut node, now);
        node.tick(now + 1, u32::MAX);
        settle(&mut node, now);
    }
    node.close(a, now).expect("close a");
    settle(&mut node, now);
    node.close(b, now).expect("close b");
    settle(&mut node, now);
    now += 20_001;
    node.tick(now, u32::MAX);
    let _ = c_node_release(PORT_A);
    let _ = c_node_release(PORT_B);
    assert_eq!(
        node.pool().available(),
        free_at_start,
        "every buffer back: the multi-packet retransmit must not leak the copies past MAX_FANOUT"
    );
}
