//! Both ends close the same RDP connection at once. The C's `case RDP_CLOSE_WAIT` answers a
//! reset with `ACK|RST`, so two closers look like they would trade resets forever; measured
//! against the real C to see what actually happens (`csp_rdp.c`).

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::rdp::{Header, HEADER_LEN};
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
    p.set_frame(VERSION, frame).expect("frame");
    node.router.receive(p, 0);
}

fn rdp_flags(frame: &[u8]) -> u8 {
    Header::decode(&frame[frame.len() - HEADER_LEN..])
        .expect("an rdp trailer")
        .flags
        & 0x0F
}

const ACK: u8 = csp_core::rdp::ACK;
const RST: u8 = csp_core::rdp::RST;

#[test]
fn a_simultaneous_close_ends_without_a_reset_storm() {
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
    let free_at_start = node.pool().available();

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
    inject(&mut node, &answer.tx[0]);
    for f in drain(&mut node, 1100) {
        c_node_exchange(&f, &[]);
    }
    assert!(node.is_rdp_open(conn));

    // One exchange, and the C's application takes the connection.
    let mut d = node.packet().expect("pool");
    d.set_payload(b"hello").unwrap();
    let frame = match node.send(conn, d, 1200).expect("send") {
        Outbound::Transmit { mut packet, .. } => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("{other:?}"),
    };
    for f in &c_node_exchange(&frame, &[]).tx {
        inject(&mut node, f);
    }
    let _ = drain(&mut node, 1300);
    assert_eq!(
        c_node_read_held(RDP_PORT),
        1,
        "the C's application holds the connection"
    );

    // Both close at the same instant.
    node.close(conn, 1400).expect("close");
    let from_port = drain(&mut node, 1400);
    assert_eq!(from_port.len(), 1);
    assert_eq!(
        rdp_flags(&from_port[0]),
        ACK | RST,
        "the port's close is ACK|RST"
    );
    let from_c = c_node_release(RDP_PORT);
    assert_eq!(from_c.len(), 1, "csp_close sends one frame");
    assert_eq!(rdp_flags(&from_c[0]), ACK | RST, "the C's close is ACK|RST");

    // Each reset reaches a peer already in CLOSE-WAIT.
    // Measured: the C's `csp_close` has already released its slot, so the port's reset
    // finds no connection and is answered with nothing -- not the CLOSE-WAIT `ACK|RST`
    // the state table promises for a connection still held.
    let c_reply = c_node_exchange(&from_port[0], &[]).tx;
    assert_eq!(
        c_reply.len(),
        0,
        "the C answers nothing to the port's reset after its own close: {:?}",
        c_reply.iter().map(|f| rdp_flags(f)).collect::<Vec<_>>()
    );
    assert_eq!(
        c_node_open_conns(),
        open_before,
        "the C's slot is already free"
    );
    inject(&mut node, &from_c[0]);
    let port_reply = drain(&mut node, 1400);
    assert_eq!(
        port_reply.len(),
        0,
        "the port, in CLOSE-WAIT, takes the C's reset as the end and answers nothing"
    );
    assert!(
        !node.router.conns.is_live(conn),
        "and releases its slot at once"
    );

    // Keep trading whatever comes back, and count how long it goes on.
    let mut to_port = c_reply;
    let mut to_c = port_reply;
    let mut rounds = 0;
    while rounds < 6 && (!to_port.is_empty() || !to_c.is_empty()) {
        let mut next_to_c = Vec::new();
        for f in &to_port {
            inject(&mut node, f);
        }
        next_to_c.extend(drain(&mut node, 1400 + rounds * 10));
        let mut next_to_port = Vec::new();
        for f in &to_c {
            next_to_port.extend(c_node_exchange(f, &[]).tx);
        }
        to_port = next_to_port;
        to_c = next_to_c;
        rounds += 1;
    }
    assert_eq!(
        rounds, 0,
        "nothing is left to trade: no reset storm on either side"
    );
    assert_eq!(node.pool().available(), free_at_start, "every buffer back");
}
