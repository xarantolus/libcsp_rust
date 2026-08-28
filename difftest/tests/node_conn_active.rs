//! `csp_conn_is_active`, and the idle timeout on an established RDP connection, against
//! the real C with its clock advanced.
//!
//! `csp_rdp_check_timeouts` has two connection timeouts. The first is guarded by
//! `dest_socket != NULL` and covers a handshake never announced to a socket; the second
//! (`csp_rdp.c:443`) is not guarded: an `RDP_OPEN` connection that has heard nothing for
//! `conn_timeout` is closed with `ACK|RST`. `conn->timestamp` is refreshed on every packet
//! received in `OPEN` (`csp_rdp.c:704`), so a connection that is talking never times out;
//! `csp_conn_is_active` (`csp_rdp.c:1005`) reports the same rule without closing anything.
//!
//! An earlier record concluded the C never reaps an established connection. It counted
//! frames in the C's answer after the idle, and the C's answer was a reset. The rows below
//! are on the C's own clock, moved with `c_clock_advance`.

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

fn inject(node: &mut TestNode, frame: &[u8]) {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, frame).expect("the C's frame");
    node.router.receive(p, 0);
}

fn rdp_flags(frame: &[u8]) -> u8 {
    csp_core::rdp::Header::decode(&frame[6..])
        .map(|h| h.flags)
        .unwrap_or(0)
}

/// Send one data packet from the port to the C at `now`, feeding the C's answers back.
fn talk(node: &mut TestNode, conn: csp::conn::Handle, now: u32) -> Vec<Vec<u8>> {
    let mut d = node.packet().expect("pool");
    d.set_payload(b"still here").unwrap();
    let frame = match node.send(conn, d, now).expect("send") {
        Outbound::Transmit { mut packet, .. } => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("{other:?}"),
    };
    let got = c_node_exchange(&frame, &[]);
    for f in &got.tx {
        inject(node, f);
    }
    let _ = drain(node, now + 1);
    got.tx
}

#[test]
fn an_established_connection_stays_active_while_talking_and_times_out_when_silent() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, NODE_ADDR, NETMASK, 20, 40));
    assert_eq!(c_node_bind(RDP_PORT), 0);
    c_clock_set(5_000);

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
    inject(&mut node, &answer.tx[0]);
    for f in drain(&mut node, 1100) {
        c_node_exchange(&f, &[]);
    }
    assert!(node.is_rdp_open(conn));
    // The C's application takes the connection and holds it. Its "held" packet is
    // delivered to the port and acknowledged, so nothing is left unacknowledged on the C's
    // side -- an unacknowledged packet would be retransmitted and, after ten tries, would
    // close the connection for a reason this test is not about.
    for f in c_node_send_on(RDP_PORT, b"held") {
        inject(&mut node, &f);
    }
    for f in drain(&mut node, 1150) {
        c_node_exchange(&f, &[]);
    }
    let timeout = csp_core::rdp::SynOptions::default().conn_timeout;

    // 1. Right after the handshake: active on both.
    assert_eq!(c_node_held_active(RDP_PORT), Some(true));
    assert!(node.conn_is_active(conn, 1150));

    // 2. Talking keeps it alive: almost the whole timeout passes, a packet crosses, and
    //    another almost-timeout later both still say yes -- the clock restarted.
    c_clock_advance(timeout - 1);
    let mut now = 1150 + timeout - 1;
    let answers = talk(&mut node, conn, now);
    assert!(
        answers
            .iter()
            .all(|f| rdp_flags(f) & csp_core::rdp::RST == 0),
        "the C acknowledges, it does not reset: {:?}",
        answers.iter().map(|f| rdp_flags(f)).collect::<Vec<_>>()
    );
    c_clock_advance(timeout - 1);
    now += timeout - 1;
    assert_eq!(
        c_node_held_active(RDP_PORT),
        Some(true),
        "C: the packet restarted its clock"
    );
    assert!(node.conn_is_active(conn, now), "port: the same");

    // 3. Silence past the timeout: inactive on both, and the C closes -- its next answer
    //    is a reset. The port's tick does the same, with the same frame.
    // Three, not two: `talk` drains one tick after the packet, so the port's last activity
    // sits one ms later than the C's timestamp.
    c_clock_advance(3);
    now += 3;
    assert_eq!(
        c_node_held_active(RDP_PORT),
        Some(false),
        "C: csp_rdp_conn_is_active says no"
    );
    assert!(
        !node.conn_is_active(conn, now),
        "port: the same rule, on the same clock"
    );
    node.tick(now, u32::MAX);
    let on_timeout = drain(&mut node, now);
    // Two frames: the timeout's reset, and a retransmission of the data packet the C has
    // not acknowledged yet (its acks are delayed). `csp_rdp_check_timeouts` produces the same
    // pair in one sweep, retransmission first; the port's tick emits the reset first.
    let resets: Vec<u8> = on_timeout
        .iter()
        .map(|f| rdp_flags(f) & 0x0F)
        .filter(|f| f & csp_core::rdp::RST != 0)
        .collect();
    assert_eq!(
        resets,
        vec![csp_core::rdp::ACK | csp_core::rdp::RST],
        "the port's timeout sends exactly one reset, csp_conn_close's ACK|RST"
    );
    let rst = on_timeout
        .iter()
        .find(|f| rdp_flags(f) & csp_core::rdp::RST != 0)
        .unwrap();
    let reply = c_node_exchange(rst, &[]);
    assert!(
        reply
            .tx
            .iter()
            .any(|f| rdp_flags(f) & csp_core::rdp::RST != 0),
        "the C, which timed the connection out on its own clock, answers with a reset"
    );
    let _ = c_node_release(RDP_PORT);
}
