//! An SFP file transfer over RDP over CAN under CSP v1, a frame lost and repaired. The v1
//! counterpart of `node_sfp_over_can.rs` (upload direction): the two trailers
//! (`[body][sfp][rdp]`, re-protected on retransmit) inside v1 CFP-1 framing, on
//! `harness::CanLink<V1>`.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::security::opts;
use csp_core::Version;
use difftest::harness::{work_until_idle, CanLink, V1};
use difftest::*;

const VERSION: Version = Version::V1;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10; // same /3 subnet as the C, so it can route replies back
const NETMASK: u16 = 3;
const PORT: u8 = 10;
const MTU: usize = 100;
const SECRET: &[u8] = b"a shared secret for the bus";

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn message() -> Vec<u8> {
    (0..290u16)
        .map(|i| (i as u8).wrapping_mul(7) ^ 0x2A)
        .collect()
}

fn to_c(frames: &[CanFrame]) -> Vec<CanFrame> {
    for f in frames {
        let _ = c_can_rx(f);
    }
    c_clock_advance(300);
    c_node_pump();
    c_can_drain()
}

/// The port's pending frames, fragmented onto v1 CAN.
fn drain(node: &mut TestNode, link: &mut CanLink<V1>, now: u32) -> Vec<CanFrame> {
    let mut frames = Vec::new();
    work_until_idle(node, now, |node, r| {
        if let Routed::Respond { packet, .. } = r {
            let p = node.take_forwarded(packet).expect("slot");
            let id = p.id();
            let payload = p.with_payload(|d| d.to_vec());
            frames.extend(link.fragment(id, &payload));
        }
    });
    frames
}

fn settle(node: &mut TestNode, link: &mut CanLink<V1>, now: u32) {
    for _ in 0..8 {
        let frames = drain(node, link, now);
        if frames.is_empty() {
            break;
        }
        let back = to_c(&frames);
        link.deliver(node, &back, 0, now);
    }
}

#[test]
fn a_file_uploads_over_rdp_over_v1_can_with_a_frame_lost() {
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
    let free_at_start = node.pool().available();

    let conn = node
        .connect(
            2,
            C_ADDR,
            PORT,
            opts::RDP_REQ | opts::CRC32_REQ | opts::HMAC_REQ,
            1000,
        )
        .expect("connect");
    settle(&mut node, &mut link, 1000);
    assert!(node.is_rdp_open(conn), "v1 handshake over CAN completes");
    let _ = c_node_read_held(PORT);

    let up = message();
    let mtu = node.conn_sfp_mtu(conn).expect("mtu").min(MTU);
    let mut now = 1100u32;
    let mut fragments = 0;
    for (i, (offset, total, chunk)) in csp_core::sfp::Fragmenter::new(&up, mtu)
        .unwrap()
        .enumerate()
    {
        let mut p = node.packet().expect("pool");
        p.set_payload(chunk).unwrap();
        let (id, payload) = match node.send_fragment(conn, p, offset, total, now) {
            Ok(Outbound::Transmit { packet, .. }) => {
                (packet.id(), packet.with_payload(|d| d.to_vec()))
            }
            other => panic!("fragment at {offset}: {other:?}"),
        };
        let mut frames = link.fragment(id, &payload);
        // Drop a CAN frame from the middle fragment.
        if i == 1 {
            frames.remove(frames.len() / 2);
        }
        let back = to_c(&frames);
        link.deliver(&mut node, &back, 0, now);
        settle(&mut node, &mut link, now);
        now += 10;
        fragments += 1;
    }
    assert!(
        fragments >= 3,
        "the stream spans several fragments: {fragments}"
    );

    // The port's timer repairs the damaged fragment; the C reassembles the file.
    now += 1001;
    node.tick(now, u32::MAX);
    settle(&mut node, &mut link, now);
    match c_node_sfp_recv(&[], PORT) {
        Ok(got) => assert_eq!(got, up, "the C reassembles the v1 upload after the repair"),
        Err(e) => panic!("csp_sfp_recv_fp refused the v1 upload: {e}"),
    }

    node.close(conn, now).expect("close");
    settle(&mut node, &mut link, now);
    now += 20_001;
    node.tick(now, u32::MAX);
    let _ = c_node_release(PORT);
    assert_eq!(node.pool().available(), free_at_start, "every buffer back");
}
