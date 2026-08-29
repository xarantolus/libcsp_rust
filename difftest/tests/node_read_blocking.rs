//! `csp_read` with a timeout, with the reader on a thread of its own.
//!
//! Two things only a blocked thread can show. First, the plain case: `csp_read(conn, t)`
//! returns NULL after `t` when nothing arrives, and returns the packet early when the
//! router delivers one meanwhile. Second, the RDP raise: on an RDP connection a non-zero
//! timeout shorter than `conn_timeout` is silently raised to `conn_timeout`
//! (`csp_io.c:55`), so an application asking for 100 ms waits the connection timeout.
//!
//! The port's `Node::read` never blocks — it is the application's loop that waits — so the
//! raise has no counterpart there; that is recorded rather than reproduced.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::rdp::SynOptions;
use csp_core::Version;
use difftest::*;
use std::time::Duration;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;
const PLAIN_PORT: u8 = 10;
const RDP_PORT: u8 = 11;
/// Short, so the raise is visible in test time; the C's compiled-in value is 10 s.
const CONN_TIMEOUT_MS: u32 = 400;

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

fn send_frame(node: &mut TestNode, conn: csp::conn::Handle, body: &[u8], now: u32) -> Vec<u8> {
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
fn a_c_reader_waits_its_timeout_and_on_rdp_the_connection_timeout() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        NODE_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));
    assert_eq!(c_node_bind(PLAIN_PORT), 0);
    assert_eq!(c_node_bind(RDP_PORT), 0);

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();
    node.set_rdp_options(SynOptions {
        conn_timeout: CONN_TIMEOUT_MS,
        ..SynOptions::default()
    });

    // --- Plain connection, held by the C's application. ---
    let plain = node
        .connect(2, NODE_ADDR, PLAIN_PORT, 0, 1000)
        .expect("connect");
    let f = send_frame(&mut node, plain, b"hello", 1000);
    c_node_exchange(&f, &[]);
    assert_eq!(
        c_node_read_held(PLAIN_PORT),
        1,
        "the C's application holds the connection"
    );

    // Nothing arrives: the read returns NULL after its own timeout.
    assert!(c_read_start(PLAIN_PORT, 100));
    let (got, ms) = c_read_join();
    assert_eq!(got, None, "NULL when nothing arrived");
    assert!(
        (80..400).contains(&ms),
        "a plain read waits its own timeout: {ms} ms"
    );

    // Something arrives while blocked: the router (main thread) delivers and the read
    // returns it well before its timeout.
    assert!(c_read_start(PLAIN_PORT, 2000));
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(c_read_peek(), None, "still blocked");
    let f = send_frame(&mut node, plain, b"again", 1100);
    c_node_exchange(&f, &[]);
    let (got, ms) = c_read_join();
    assert_eq!(got, Some(5), "the delivered packet");
    assert!(ms < 1000, "returned on delivery, not on timeout: {ms} ms");

    // --- RDP connection, held by the C's application. ---
    let rdp = node
        .connect(
            2,
            NODE_ADDR,
            RDP_PORT,
            csp_core::security::opts::RDP_REQ,
            1200,
        )
        .expect("rdp connect");
    let syn = drain(&mut node, 1200);
    let answer = c_node_exchange(&syn[0], &[]);
    inject(&mut node, &answer.tx[0]);
    for f in drain(&mut node, 1300) {
        c_node_exchange(&f, &[]);
    }
    assert!(node.is_rdp_open(rdp));
    let f = send_frame(&mut node, rdp, b"hold me", 1400);
    for r in &c_node_exchange(&f, &[]).tx {
        inject(&mut node, r);
    }
    let _ = drain(&mut node, 1400);
    assert_eq!(
        c_node_read_held(RDP_PORT),
        1,
        "the C's application holds the RDP connection"
    );

    // The raise: a 100 ms read on an RDP connection waits conn_timeout (negotiated from
    // the port's SYN: 400 ms here).
    assert!(c_read_start(RDP_PORT, 100));
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        c_read_peek(),
        None,
        "still blocked past the 100 ms it asked for"
    );
    let (got, ms) = c_read_join();
    assert_eq!(got, None);
    assert!(
        (350..1500).contains(&ms),
        "csp_io.c:55 raised the 100 ms timeout to conn_timeout: {ms} ms"
    );

    // Delivery on RDP still returns early.
    assert!(c_read_start(RDP_PORT, 100));
    std::thread::sleep(Duration::from_millis(50));
    let f = send_frame(&mut node, rdp, b"data", 1500);
    for r in &c_node_exchange(&f, &[]).tx {
        inject(&mut node, r);
    }
    let (got, ms) = c_read_join();
    assert_eq!(got, Some(4));
    assert!(ms < 350, "returned on delivery: {ms} ms");

    // The port's read is a poll: nothing queued, nothing waited for.
    assert!(matches!(node.read(rdp), Ok(None)));

    let _ = c_node_release(PLAIN_PORT);
    let _ = c_node_release(RDP_PORT);
    let _ = node.close(plain, 1600);
    let _ = node.close(rdp, 1600);
}
