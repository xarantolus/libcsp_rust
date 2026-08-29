//! Minimal: one RDP connection, a whole data packet never delivered, repaired by the
//! port's retransmission timer, then acknowledged and closed. Checks the pool returns to
//! its starting count -- isolating whether the retransmit-of-a-lost-packet path leaks.

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
const PORT: u8 = 10;

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
    p.set_frame(VERSION, frame).expect("frame");
    node.router.receive(p, 0);
}

fn settle(node: &mut TestNode, now: u32) {
    for _ in 0..8 {
        let out = drain(node, now);
        if out.is_empty() {
            break;
        }
        for f in &out {
            for r in &c_node_exchange(f, &[]).tx {
                inject(node, r);
            }
        }
    }
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

#[test]
fn a_retransmitted_lost_packet_leaves_no_buffer_behind() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        NODE_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));
    assert_eq!(c_node_bind(PORT), 0);

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();
    let free_at_start = node.pool().available();

    let conn = node
        .connect(2, NODE_ADDR, PORT, opts::RDP_REQ | opts::CRC32_REQ, 1000)
        .expect("connect");
    settle(&mut node, 1000);
    let syn_done = node.is_rdp_open(conn);
    assert!(syn_done);
    let _ = c_node_read_held(PORT);

    // Three data packets; the second is never delivered to the C.
    let mut now = 1100u32;
    for i in 0..3u8 {
        let f = send(&mut node, conn, &[b'X', i], now);
        if i != 1 {
            for r in &c_node_exchange(&f, &[]).tx {
                inject(&mut node, r);
            }
        }
        settle(&mut node, now);
        now += 10;
    }
    assert_eq!(c_node_read_held(PORT), 1, "only the packet before the gap");

    // Retransmit the lost one.
    now += 1001;
    node.tick(now, u32::MAX);
    settle(&mut node, now);
    assert_eq!(c_node_read_held(PORT), 2, "gap filled, both released");

    // Flush the C's delayed acks so nothing stays unacknowledged.
    for _ in 0..3 {
        c_clock_advance(300);
        c_node_pump();
        for f in &c_node_tx_take() {
            inject(&mut node, f);
        }
        settle(&mut node, now);
        node.tick(now + 1, u32::MAX);
        settle(&mut node, now);
    }

    node.close(conn, now).expect("close");
    settle(&mut node, now);
    now += 20_001;
    node.tick(now, u32::MAX);
    let _ = c_node_release(PORT);
    assert_eq!(
        node.pool().available(),
        free_at_start,
        "a retransmitted-then-acknowledged packet must leave no buffer held"
    );
}
