//! The promiscuous tap yields to real traffic when the pool runs low.
//!
//! # What the C does
//!
//! `csp_promisc_add` (`csp_promisc.c:59`) refuses to clone a packet for the tap when
//! `csp_buffer_remaining() <= CSP_PROMISC_BUFFER_RESERVE`, which is a quarter of the pool
//! (`csp_promisc.c:16`, `CSP_BUFFER_COUNT / 4`). The comment says why: *"Yield to real
//! traffic when the pool runs low."* The packet itself is still delivered; only the copy is
//! skipped, and `csp_dbg_conn_ovf` counts it.
//!
//! # Why it matters
//!
//! The tap is a diagnostic. A diagnostic that takes the last buffers is one that turns a
//! busy bus into a node that cannot receive — and the tap is enabled in exactly the
//! situation where someone is already debugging a busy bus. A port that clones down to
//! zero would have the tap starving the traffic it was switched on to watch.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;
const PEER: u16 = 30;
const PORT: u8 = 10;
const HDR: usize = 6;
/// The pinned C build's pool, `CSP_BUFFER_COUNT`.
const C_POOL: i32 = 15;
/// The port's pool in this test.
const R_POOL: usize = 8;

type TestNode<'a> = Node<'a, R_POOL, 24, 300, 64, 8, 8>;

fn framed(dst: u16, payload: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: PEER,
        dst,
        dport: PORT,
        sport: 40,
    };
    let mut v = vec![0u8; HDR + payload.len()];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(payload);
    v
}

#[test]
fn the_c_tap_skips_the_copy_when_a_quarter_of_the_pool_is_left() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        C_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));
    assert_eq!(c_node_bind(PORT), 0);
    assert_eq!(c_node_promisc_enable(), 0);
    let _ = c_node_promisc_drain();

    // Bring the pool down to exactly the reserve: `remaining <= COUNT / 4` refuses.
    let reserve = C_POOL / 4;
    let free = c_node_buf_free();
    assert!(free > reserve, "the pool starts above the reserve: {free}");
    c_buffers_hold(free - reserve);
    assert_eq!(c_node_buf_free(), reserve, "held down to the reserve");

    let out = c_node_exchange(&framed(C_ADDR, b"real traffic"), &[PORT]);
    c_buffers_release();

    assert_eq!(
        out.delivered.len(),
        1,
        "the packet itself is still delivered"
    );
    assert_eq!(out.delivered[0].payload, b"real traffic");
    assert_eq!(
        c_node_promisc_drain(),
        Vec::<(u16, Vec<u8>)>::new(),
        "but the tap gets no copy: csp_promisc_add yields when remaining <= COUNT/4"
    );
}

#[test]
fn the_port_tap_skips_the_copy_when_a_quarter_of_the_pool_is_left() {
    let _g = lock();
    let storage = CspStorage::<R_POOL, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(PORT).unwrap();
    node.router.set_promisc(true);

    // Same rule, same arithmetic: hold slots until `available() <= capacity / 4` once the
    // incoming packet has taken its own slot.
    let reserve = R_POOL / 4;
    let mut held = Vec::new();
    while node.pool().available() > reserve + 1 {
        held.push(node.packet().expect("pool"));
    }
    let mut p = node.packet().expect("the incoming packet's own slot");
    p.set_frame(VERSION, &framed(R_ADDR, b"real traffic"))
        .expect("frame");
    assert_eq!(node.pool().available(), reserve, "down to the reserve");
    node.router.receive(p, 0);

    let mut delivered = Vec::new();
    loop {
        match node.work(0) {
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
    drop(held);

    assert_eq!(
        delivered,
        vec![b"real traffic".to_vec()],
        "the packet itself is still delivered"
    );
    assert!(
        node.router.promisc_read(node.pool()).is_none(),
        "but the tap gets no copy: the port must yield to real traffic at the same reserve \
         the C does, or a diagnostic takes the last buffers on the bus it is watching"
    );
    assert_eq!(
        node.router.promisc_missed(),
        1,
        "and the skipped copy is counted"
    );
}
