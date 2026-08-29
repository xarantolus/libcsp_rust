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
use csp_core::{cfp, Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
/// The C: node and CAN interface at 9, subnet /12 (8..=11).
const C_ADDR: u16 = 9;
/// The port, on the same subnet so the C routes its replies out over CAN.
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const PORT: u8 = 10;
const HDR: usize = 6;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;
type Pool = cfp::Pbufs<cfp::V2Reassembler, 4>;

/// Cut one port packet into CAN frames, as the port's CAN driver would.
fn fragment(id: Id, payload: &[u8], sc: &mut u32) -> Vec<CanFrame> {
    let frames = cfp::V2Fragmenter::new(id, R_ADDR, *sc, payload)
        .map(|f| (f.id, f.data().to_vec()))
        .collect();
    *sc += 1;
    frames
}

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

/// Reassemble the C's CAN frames with the port's pool and deliver each packet to the node.
fn from_c(node: &mut TestNode, pool: &mut Pool, frames: &[CanFrame], now: u32) {
    let mut buf = [0u8; 512];
    for (id, data) in frames {
        let key = *id & cfp::V2_CONN_MASK;
        let re = pool.get_or_create(key, now).expect("a reassembly slot");
        match re.push(*id, data, &mut buf) {
            Ok(Some((hdr, n))) => {
                pool.release(key);
                let mut v = vec![0u8; HDR + n];
                hdr.encode(VERSION, &mut v).unwrap();
                v[HDR..].copy_from_slice(&buf[..n]);
                let mut p = node.packet().expect("pool");
                p.set_frame(VERSION, &v).unwrap();
                node.router.receive(p, 0);
            }
            Ok(None) => {}
            Err(e) => panic!("the port's reassembler refused a C frame: {e:?}"),
        }
    }
}

/// Everything the port wants on the wire, fragmented; and everything delivered to the app.
fn drain(node: &mut TestNode, now: u32, sc: &mut u32) -> (Vec<CanFrame>, Vec<Vec<u8>>) {
    let mut frames = Vec::new();
    let mut delivered = Vec::new();
    loop {
        match node.work(now) {
            Routed::Respond { packet, .. } => {
                let p = node.take_forwarded(packet).expect("slot");
                let id = p.id();
                let payload = p.with_payload(|d| d.to_vec());
                frames.extend(fragment(id, &payload, sc));
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
fn settle(node: &mut TestNode, pool: &mut Pool, now: u32, sc: &mut u32) -> Vec<Vec<u8>> {
    let mut delivered = Vec::new();
    for _ in 0..8 {
        let (frames, d) = drain(node, now, sc);
        delivered.extend(d);
        if frames.is_empty() {
            break;
        }
        let back = to_c(&frames);
        from_c(node, pool, &back, now);
    }
    delivered
}

#[test]
fn an_rdp_crc32_session_over_can_survives_a_lost_and_a_swapped_frame() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert!(c_can_init(C_ADDR, NETMASK));
    assert_eq!(c_node_bind(PORT), 0);
    let _ = c_can_drain();

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("can", R_ADDR, NETMASK, true).unwrap();
    let mut pool = Pool::new();
    let mut sc = 0u32;
    let free_at_start = node.pool().available();

    // Handshake, protected: every frame carries an RDP trailer and a CRC32.
    let conn = node
        .connect(2, C_ADDR, PORT, opts::RDP_REQ | opts::CRC32_REQ, 1000)
        .expect("connect");
    settle(&mut node, &mut pool, 1000, &mut sc);
    assert!(node.is_rdp_open(conn), "handshake over CAN completes");
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
        let mut frames = fragment(id, &payload, &mut sc);
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
        from_c(&mut node, &mut pool, &back, now);
        settle(&mut node, &mut pool, now, &mut sc);
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
    settle(&mut node, &mut pool, now, &mut sc);
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
        from_c(&mut node, &mut pool, &frames, now);
        got.extend(settle(&mut node, &mut pool, now, &mut sc));
        now += 10;
    }
    assert_eq!(got, vec![b"reply one".to_vec(), b"reply two".to_vec()]);

    // Close from the port; the C answers and both sides release.
    node.close(conn, now).expect("close");
    settle(&mut node, &mut pool, now, &mut sc);
    now += 20_001;
    node.tick(now, u32::MAX);
    let _ = c_node_release(PORT);
    assert_eq!(
        node.pool().available(),
        free_at_start,
        "every buffer back once the session is over"
    );
}
