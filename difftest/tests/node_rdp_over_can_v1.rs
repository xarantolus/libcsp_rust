//! `node_rdp_over_can.rs` under CSP v1, the wire format MOVE-IIIa flies. Same session, same
//! damage, every protection — only the framing changes, `harness::CanLink<V1>` in place of
//! `<V2>`. The payoff of the shared harness.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::security::opts;
use csp_core::Version;
use difftest::harness::{work_until_idle, CanLink, V1};
use difftest::*;

const VERSION: Version = Version::V1;
/// The proven v1 addresses from `node_can_v1.rs`: 5-bit hosts, subnet /3.
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 3;
const PORT: u8 = 10;
const SECRET: &[u8] = b"a shared secret for the bus";

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// Feed the port's CAN frames to the real `csp_can1_rx`, run the C's router, hand back what
/// the C put on the bus.
fn to_c(frames: &[CanFrame]) -> Vec<CanFrame> {
    for f in frames {
        let _ = c_can_rx(f);
    }
    c_clock_advance(300);
    c_node_pump();
    c_can_drain()
}

/// The port's pending frames, fragmented onto CAN; and everything delivered to the app.
fn drain(node: &mut TestNode, link: &mut CanLink<V1>, now: u32) -> (Vec<CanFrame>, Vec<Vec<u8>>) {
    let mut frames = Vec::new();
    let mut delivered = Vec::new();
    work_until_idle(node, now, |node, r| match r {
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
        _ => {}
    });
    (frames, delivered)
}

fn settle(node: &mut TestNode, link: &mut CanLink<V1>, now: u32) -> Vec<Vec<u8>> {
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

#[test]
fn a_v1_rdp_session_over_can_survives_a_lost_and_a_swapped_frame_under_every_protection() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 24, 16));
    assert!(c_can_init(C_ADDR, NETMASK));
    assert_eq!(c_node_bind(PORT), 0);
    assert_eq!(c_hmac_set_key(SECRET), 0);
    let _ = c_can_drain();

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("can", R_ADDR, NETMASK, true).unwrap();
    node.set_hmac_key(SECRET);
    let mut link: CanLink<V1> = CanLink::new(R_ADDR);

    for protection in [
        opts::CRC32_REQ,
        opts::HMAC_REQ,
        opts::CRC32_REQ | opts::HMAC_REQ,
    ] {
        session(&mut node, &mut link, protection);
    }
}

fn session(node: &mut TestNode, link: &mut CanLink<V1>, protection: u32) {
    let free_at_start = node.pool().available();

    let conn = node
        .connect(2, C_ADDR, PORT, opts::RDP_REQ | protection, 1000)
        .expect("connect");
    settle(node, link, 1000);
    assert!(
        node.is_rdp_open(conn),
        "handshake over v1 CAN completes ({protection:#x})"
    );
    let _ = c_node_read_held(PORT);

    let bodies: Vec<Vec<u8>> = (0..3u8)
        .map(|i| (0..60u8).map(|j| (i * 60 + j) ^ 0x5A).collect())
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
            1 => {
                frames.remove(frames.len() / 2);
            }
            2 => frames.swap(1, 2),
            _ => {}
        }
        let back = to_c(&frames);
        link.deliver(node, &back, 0, now);
        settle(node, link, now);
        now += 10;
    }
    assert_eq!(c_node_read_held(PORT), 1, "only the intact packet arrived");

    now += 1001;
    node.tick(now, u32::MAX);
    settle(node, link, now);
    assert_eq!(
        c_node_read_held(PORT),
        2,
        "both damaged packets arrive on retransmission"
    );

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

    node.close(conn, now).expect("close");
    settle(node, link, now);
    now += 20_001;
    node.tick(now, u32::MAX);
    let _ = c_node_release(PORT);
    assert_eq!(node.pool().available(), free_at_start, "every buffer back");
}
