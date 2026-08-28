//! What the port puts on the wire when it gives up on a peer that never acknowledges.
//!
//! The C record `rdp: unacknowledged_data_is_retransmitted_then_given_up_on`, regenerated
//! with the kind of each frame: after `CSP_RDP_MAX_RETRANSMITS` sweeps that retransmitted,
//! `csp_rdp_check_timeouts` calls `csp_conn_close` (`csp_rdp.c:431`), which sends **one**
//! `ACK|RST` (`rst_frames: 1`) and moves to CLOSE_WAIT. The port used to close the slot
//! silently: the peer was never told.
//!
//! The record is `diverges` on the retransmission cadence, and measured the C keeps
//! retransmitting in CLOSE_WAIT for a while after the reset before its CLOSE_WAIT timeout
//! stops it (`last_frame_ms_after_send: 33750` against a reset at `13750`). That tail is a
//! quirk of the C's block ordering and is not reproduced: the port stops when it gives up,
//! which is also what the record's zero `frames_after_giving_up` describes.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const NETMASK: u16 = 12;
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

fn rdp_flags(frame: &[u8]) -> u8 {
    csp_core::rdp::Header::decode(&frame[6..])
        .map(|h| h.flags)
        .unwrap_or(0)
}

#[test]
fn giving_up_sends_one_reset_then_nothing() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, NODE_ADDR, NETMASK, 20, 40));
    assert_eq!(c_node_bind(RDP_PORT), 0);

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();
    // The C record's connection proposed a 20 s conn_timeout, so that giving up (eleven
    // retransmissions at 1250 ms) comes before the idle timeout does. Same here.
    node.set_rdp_options(csp_core::rdp::SynOptions {
        conn_timeout: 20_000,
        ..csp_core::rdp::SynOptions::default()
    });
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
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &answer.tx[0]).unwrap();
    node.router.receive(p, 0);
    for f in drain(&mut node, 1100) {
        c_node_exchange(&f, &[]);
    }
    assert!(node.is_rdp_open(conn));

    // One packet out, dropped on the floor: the peer never acknowledges.
    let mut d = node.packet().expect("pool");
    d.set_payload(b"hello").unwrap();
    match node.send(conn, d, 1200).expect("send") {
        Outbound::Transmit { packet, .. } => drop(packet),
        other => panic!("{other:?}"),
    }

    // Sweep every 250 ms, as the C record does, well past any give-up point.
    let opts = node.rdp_options();
    let mut frames: Vec<(u32, u8)> = Vec::new();
    let mut now = 1200;
    for _ in 0..1000 {
        now += 250;
        node.tick(now, u32::MAX);
        for f in drain(&mut node, now) {
            frames.push((now - 1200, rdp_flags(&f) & 0x0F));
        }
    }
    let resets: Vec<&(u32, u8)> = frames
        .iter()
        .filter(|(_, f)| f & csp_core::rdp::RST != 0)
        .collect();
    assert_eq!(
        resets.len(),
        1,
        "exactly one reset, as the C's record says: {frames:?}"
    );
    assert_eq!(
        resets[0].1,
        csp_core::rdp::ACK | csp_core::rdp::RST,
        "csp_conn_close's ACK|RST"
    );
    let retransmits_before = frames
        .iter()
        .filter(|(t, f)| *t <= resets[0].0 && f & csp_core::rdp::RST == 0)
        .count();
    assert_eq!(
        retransmits_before,
        csp_core::rdp::MAX_RETRANSMITS as usize + 1,
        "`++retransmits > MAX` gives up on the eleventh retransmitting sweep, which still \
         retransmits: {frames:?}"
    );
    assert_eq!(
        resets[0].0,
        (csp_core::rdp::MAX_RETRANSMITS + 1) * 1250,
        "at 1250 ms per retransmission (packet_timeout plus one 250 ms sweep), the C's \
         first_rst_ms_after_send"
    );
    assert!(
        frames
            .iter()
            .all(|(t, _)| *t <= resets[0].0 + opts.conn_timeout + 250),
        "nothing after the close completes: {frames:?}"
    );
    // The reset marks the connection as closing; the application sees it as inactive.
    assert!(!node.conn_is_active(conn, now));
}
