//! A whole session, the way a flight node runs one: RDP with CRC32, over CAN, against a
//! real C peer — through the real `csp_can_rx` and `csp_can2_tx` on the C side and the
//! port's CFP fragmenter and reassembly pool on the other, both directions, with one CAN
//! frame lost and two swapped on the way.
//!
//! Every piece has its own comparison: the CFP framing, the RDP handshake, the CRC32
//! trailer, retransmission, the close. None of them had run *together*. What this pins is
//! the interaction: a trailer inside a fragment inside a retransmission inside a session
//! that both ends then close cleanly.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::security::opts;
use csp_core::Version;
use difftest::harness::{CanLink, V2};
use difftest::*;

const VERSION: Version = Version::V2;
/// The C: node and CAN interface at 9, subnet /12 (8..=11).
const C_ADDR: u16 = 9;
/// The port, on the same subnet so the C routes its replies out over CAN.
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const PORT: u8 = 10;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;
/// Feed frames to the real `csp_can_rx`, run the C's router, and hand back what the C
/// put on the CAN bus in return.
fn to_c(frames: &[CanFrame]) -> Vec<CanFrame> {
    for f in frames {
        let _ = c_can_rx(f);
    }
    // The C's acknowledgements are delayed (its ack timer, 250 ms): let its clock run so
    // each pump can send them, as a real node's timer task would.
    c_clock_advance(300);
    c_node_pump();
    c_can_drain()
}

/// Everything the port wants on the wire, fragmented; and everything delivered to the app.
fn drain(node: &mut TestNode, link: &mut CanLink<V2>, now: u32) -> (Vec<CanFrame>, Vec<Vec<u8>>) {
    let mut frames = Vec::new();
    let mut delivered = Vec::new();
    loop {
        match node.work(now) {
            Routed::Respond { packet, .. } => {
                let p = node.take_forwarded(packet).expect("slot");
                let id = p.id();
                let payload = p.with_payload(|d| d.to_vec());
                frames.extend(link.fragment(id, &payload));
            }
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    delivered.push(pkt.with_payload(|d| d.to_vec()));
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    (frames, delivered)
}

/// One full exchange step: the port's pending frames go to the C, the C's answers come
/// back into the port, until both sides are quiet.
fn settle(node: &mut TestNode, link: &mut CanLink<V2>, now: u32) -> Vec<Vec<u8>> {
    let mut delivered = Vec::new();
    for _ in 0..8 {
        let (frames, d) = drain(node, link, now);
        delivered.extend(d);
        if frames.is_empty() {
            break;
        }
        let back = to_c(&frames);
        link.deliver(node, &back, 0, now);
    }
    delivered
}

const SECRET: &[u8] = b"a shared secret for the bus";

#[test]
fn an_rdp_session_over_can_survives_a_lost_and_a_swapped_frame_under_every_protection() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert!(c_can_init(C_ADDR, NETMASK));
    assert_eq!(c_node_bind(PORT), 0);
    assert_eq!(c_hmac_set_key(SECRET), 0);
    let _ = c_can_drain();

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("can", R_ADDR, NETMASK, true).unwrap();
    node.set_hmac_key(SECRET);
    let mut link: CanLink<V2> = CanLink::new(R_ADDR);

    // The three protections a flight link would ask for; a retransmission must carry each.
    for protection in [
        opts::CRC32_REQ,
        opts::HMAC_REQ,
        opts::CRC32_REQ | opts::HMAC_REQ,
    ] {
        session(&mut node, &mut link, protection);
    }
}

fn session(node: &mut TestNode, link: &mut CanLink<V2>, protection: u32) {
    let free_at_start = node.pool().available();

    // Handshake, protected: every frame carries an RDP trailer and the trailers asked for.
    let conn = node
        .connect(2, C_ADDR, PORT, opts::RDP_REQ | protection, 1000)
        .expect("connect");
    settle(node, link, 1000);
    assert!(
        node.is_rdp_open(conn),
        "handshake over CAN completes ({protection:#x})"
    );
    let _ = c_node_read_held(PORT); // the C's application takes the connection

    // Three data packets, big enough to span several CAN frames each.
    let bodies: Vec<Vec<u8>> = (0..3u8)
        .map(|i| (0..60u8).map(|j| i * 60 + j).collect())
        .collect();
    let mut now = 1100;
    for (i, body) in bodies.iter().enumerate() {
        let mut p = node.packet().expect("pool");
        p.set_payload(body).unwrap();
        let (id, payload) = match node.send(conn, p, now).expect("send") {
            Outbound::Transmit { packet, .. } => (packet.id(), packet.with_payload(|d| d.to_vec())),
            other => panic!("{other:?}"),
        };
        let mut frames = link.fragment(id, &payload);
        match i {
            // Lose the middle frame of the second packet.
            1 => {
                frames.remove(frames.len() / 2);
            }
            // Swap the two frames after the first of the third.
            2 => frames.swap(1, 2),
            _ => {}
        }
        let back = to_c(&frames);
        link.deliver(node, &back, 0, now);
        settle(node, link, now);
        now += 10;
    }
    assert_eq!(
        c_node_read_held(PORT),
        1,
        "only the intact packet arrived so far"
    );

    // The port's retransmission timer repairs the other two.
    now += 1001;
    node.tick(now, u32::MAX);
    settle(node, link, now);
    assert_eq!(
        c_node_read_held(PORT),
        2,
        "both damaged packets arrive on retransmission"
    );

    // The C answers on the same connection; the port delivers in order.
    let mut got = Vec::new();
    for reply in [b"reply one".as_slice(), b"reply two".as_slice()] {
        let _ = c_node_send_on(PORT, reply);
        let frames = c_can_drain();
        assert!(!frames.is_empty(), "the C's reply leaves over CAN");
        link.deliver(node, &frames, 0, now);
        got.extend(settle(node, link, now));
        now += 10;
    }
    assert_eq!(got, vec![b"reply one".to_vec(), b"reply two".to_vec()]);

    // Close from the port; the C answers and both sides release.
    node.close(conn, now).expect("close");
    settle(node, link, now);
    now += 20_001;
    node.tick(now, u32::MAX);
    let _ = c_node_release(PORT);
    assert_eq!(
        node.pool().available(),
        free_at_start,
        "every buffer back once the session is over"
    );
}

/// The other direction: the C opens the connection over CAN and sends; the port receives,
/// reassembles, delivers in order, and repairs a lost and a swapped frame through the C's
/// retransmissions.
#[test]
fn a_c_initiated_rdp_crc32_session_over_can_repairs_a_lost_and_a_swapped_frame() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert!(c_can_init(C_ADDR, NETMASK));
    let _ = c_can_drain();

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("can", R_ADDR, NETMASK, true).unwrap();
    node.bind(PORT).unwrap();
    let mut link: CanLink<V2> = CanLink::new(R_ADDR);
    let free_at_start = node.pool().available();

    // The C's csp_connect(RDP|CRC32) blocks on its own thread; its SYN leaves over CAN.
    let _ = c_rdp_connect_start_opts(R_ADDR, PORT, opts::CRC32_REQ);
    let syn = c_can_drain();
    assert!(!syn.is_empty(), "the SYN goes out over CAN");
    link.deliver(&mut node, &syn, 0, 1000);
    let mut now = 1000;
    settle(&mut node, &mut link, now);
    assert!(c_rdp_connect_join(), "csp_connect returned a connection");
    let conn = node.accept().expect("the port announced the connection");
    assert!(node.is_rdp_open(conn));

    // Three packets from the C, damaged on the way: the middle frame of the second lost,
    // two frames of the third swapped.
    let bodies: Vec<Vec<u8>> = (0..3u8)
        .map(|i| (0..60u8).map(|j| (i * 60 + j) ^ 0xA5).collect())
        .collect();
    let mut got = Vec::new();
    for (i, body) in bodies.iter().enumerate() {
        let _ = c_rdp_initiator_send(body);
        let mut frames = c_can_drain();
        assert!(frames.len() > 3, "several CAN frames for a 60-byte packet");
        match i {
            1 => {
                frames.remove(frames.len() / 2);
            }
            2 => frames.swap(1, 2),
            _ => {}
        }
        now += 10;
        link.deliver(&mut node, &frames, 0, now);
        got.extend(settle(&mut node, &mut link, now));
    }
    assert_eq!(
        got,
        vec![bodies[0].clone()],
        "only the intact packet so far"
    );

    // The C's retransmission timer repairs the rest: packet_timeout of its own clock.
    for _ in 0..6 {
        c_clock_advance(300);
        c_node_pump();
        let frames = c_can_drain();
        now += 300;
        link.deliver(&mut node, &frames, 0, now);
        got.extend(settle(&mut node, &mut link, now));
    }
    assert_eq!(
        got, bodies,
        "both damaged packets arrive by retransmission, in order"
    );

    // The C closes; the port answers its ACK|RST and everything is released.
    c_rdp_initiator_close();
    let frames = c_can_drain();
    link.deliver(&mut node, &frames, 0, now);
    settle(&mut node, &mut link, now);
    // The port answers and sits in CLOSE_WAIT until its timer releases the connection.
    now += 20_001;
    node.tick(now, u32::MAX);
    assert!(
        !node.router.conns.is_live(conn),
        "the C's close completed on the port"
    );
    assert_eq!(node.pool().available(), free_at_start, "every buffer back");
}
