//! The C's send window, with the sender on a thread of its own.
//!
//! `csp_rdp_send` blocks in `csp_bin_sem_wait(&conn->rdp.tx_wait, conn_timeout)` while a
//! full window is unacknowledged (`csp_rdp.c:868-876`), and only the router task's
//! processing of an acknowledgement posts that semaphore. A single-threaded harness cannot
//! observe this — the call does not return — which is why "window-full blocking" was the
//! one RDP rule the sweep had left unmeasured. Here the C's application is a real thread,
//! the main thread is its router and the port peer, and the observation is a counter of
//! completed sends: it stops at the window and moves again on the port's acknowledgement.
//!
//! The port cannot block — it is sans-io — so the same condition surfaces as
//! `Error::SendWindowFull` from `Node::send`, asserted at the end for the mirror image.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::Version;
use difftest::*;
use std::time::{Duration, Instant};

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;
const RDP_PORT: u8 = 10;
/// The C's compiled-in window, which the port proposes as well.
const WINDOW: usize = 4;
const BURST: usize = 6;

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
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    drop(pkt);
                }
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

/// Wait (wall clock) until the burst counter reaches `n`, or give up after `limit`.
fn wait_sent(n: usize, limit: Duration) -> bool {
    let t0 = Instant::now();
    while c_burst_sent() < n {
        if t0.elapsed() > limit {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    true
}

#[test]
fn a_c_sender_blocks_at_the_window_until_the_port_acknowledges() {
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

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();
    assert_eq!(node.rdp_options().window_size as usize, WINDOW);

    // Handshake, and one datagram so the C's application accepts and holds the connection.
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
    let mut hello = node.packet().expect("pool");
    hello.set_payload(b"hold me").unwrap();
    let frame = match node.send(conn, hello, 1200).expect("send") {
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
    let _ = c_node_tx_take();

    // The C's application sends a burst of six on a window of four.
    assert!(c_burst_start(RDP_PORT, BURST, 50), "burst started");
    assert!(
        wait_sent(WINDOW, Duration::from_secs(2)),
        "a window's worth of sends complete without any acknowledgement"
    );
    // ... and then no more: the fifth is blocked inside csp_rdp_send.
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(
        c_burst_sent(),
        WINDOW,
        "the sender is blocked at the window while nothing is acknowledged"
    );

    // The port receives the four, acknowledges (its delayed-ack timer), and the main
    // thread runs the C's router on that acknowledgement -- which posts tx_wait.
    let frames = c_node_tx_take();
    assert_eq!(
        frames.len(),
        WINDOW,
        "exactly a window of data frames left the C"
    );
    let mut now = 1400u32;
    for f in &frames {
        inject(&mut node, f);
    }
    let _ = drain(&mut node, now);
    now += 300;
    node.tick(now, u32::MAX);
    let acks = drain(&mut node, now);
    assert!(!acks.is_empty(), "the port acknowledges what it received");
    for a in &acks {
        c_node_exchange(a, &[]);
    }
    assert!(
        wait_sent(BURST, Duration::from_secs(2)),
        "the acknowledgement releases the blocked sender and the burst completes"
    );
    let (sent, max_block_ms) = c_burst_join();
    assert_eq!(sent, BURST);
    assert!(
        max_block_ms >= 250,
        "the fifth send measurably waited for the acknowledgement: {max_block_ms} ms"
    );

    // The rest reaches the port too; acknowledge, so the C holds nothing unacknowledged.
    for f in &c_node_tx_take() {
        inject(&mut node, f);
    }
    let _ = drain(&mut node, now);
    now += 300;
    node.tick(now, u32::MAX);
    for a in &drain(&mut node, now) {
        c_node_exchange(a, &[]);
    }

    // The mirror image on the port: a window of sends is accepted and the next is refused
    // with SendWindowFull -- the sans-io shape of the same rule. First let the C's
    // delayed-ack timer run, so the port starts with nothing unacknowledged.
    c_clock_advance(300);
    c_node_pump();
    for f in &c_node_tx_take() {
        inject(&mut node, f);
    }
    let _ = drain(&mut node, now);
    for i in 0..WINDOW {
        let mut p = node.packet().expect("pool");
        p.set_payload(&[i as u8; 8]).unwrap();
        let r = node.send(conn, p, now);
        assert!(r.is_ok(), "send {i} within the window: {r:?}");
    }
    let mut p = node.packet().expect("pool");
    p.set_payload(b"one too many").unwrap();
    assert!(
        matches!(
            node.send(conn, p, now),
            Err(csp_core::Error::SendWindowFull)
        ),
        "the port refuses the send past the window instead of blocking"
    );

    let _ = c_node_release(RDP_PORT);
    let _ = node.close(conn, now);
}
