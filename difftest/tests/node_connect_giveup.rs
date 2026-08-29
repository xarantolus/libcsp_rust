//! `csp_connect` giving up, with the initiator on a thread of its own.
//!
//! `csp_rdp_connect` sends a SYN and waits `conn_timeout` on `tx_wait`. The `retry` in
//! `csp_rdp.c:799` reads like a second attempt after a timeout; measured, it is not: a
//! timeout goes straight to `error`, and the retry is only for a semaphore released with
//! the state still SYN-SENT. Silence gets one SYN and one connection timeout. The port's
//! `connect` cannot wait, so its counterpart is the SYN-SENT timeout in `tick`.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::rdp::SynOptions;
use csp_core::Version;
use difftest::*;
use std::time::{Duration, Instant};

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const EGRESS_ADDR: u16 = 20;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;
const PORT: u8 = 10;
const CONN_TIMEOUT_MS: u32 = 300;

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
    csp_core::rdp::Header::decode(&frame[frame.len() - csp_core::rdp::HEADER_LEN..])
        .expect("an rdp trailer")
        .flags
        & 0x0F
}

#[test]
fn a_c_initiator_sends_one_syn_and_gives_up_after_conn_timeout_when_nobody_answers() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        NODE_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));
    let opts = SynOptions {
        conn_timeout: CONN_TIMEOUT_MS,
        ..SynOptions::default()
    };
    c_rdp_set_opt(&opts);

    // The port node exists but is never fed: the C talks to silence.
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.set_rdp_options(opts);

    let t0 = Instant::now();
    let first = c_rdp_connect_start_opts(R_ADDR, PORT, 0);
    assert_eq!(first.len(), 1, "one SYN to begin with");
    assert_eq!(rdp_flags(&first[0]), csp_core::rdp::SYN);
    let _ = c_node_tx_take();
    // Measured: the "retry" at `csp_rdp.c:840` is only taken when the semaphore *was*
    // released and the state is still SYN-SENT; a plain timeout goes straight to `error`.
    // Silence therefore gets one SYN and one connection timeout -- not two.
    std::thread::sleep(Duration::from_millis(CONN_TIMEOUT_MS as u64 / 2));
    assert!(
        c_node_tx_take().is_empty(),
        "no second SYN inside the timeout"
    );
    assert!(!c_rdp_connect_join(), "gives up");
    let ms = t0.elapsed().as_millis() as u32;
    assert!(
        (CONN_TIMEOUT_MS - 50..2 * CONN_TIMEOUT_MS + 200).contains(&ms),
        "one connection timeout, no retry: {ms} ms"
    );
    assert!(c_node_tx_take().is_empty(), "nothing after the single SYN");

    // The port's counterpart: a SYN-SENT connection that hears nothing is closed by its
    // tick once conn_timeout has passed, having sent one SYN -- the same shape.
    let conn = node
        .connect(2, NODE_ADDR, PORT, csp_core::security::opts::RDP_REQ, 1000)
        .expect("connect");
    assert_eq!(drain(&mut node, 1000).len(), 1);
    node.tick(1000 + CONN_TIMEOUT_MS / 2, u32::MAX);
    assert!(
        node.router.conns.is_live(conn),
        "still waiting inside conn_timeout"
    );
    let _ = drain(&mut node, 1000 + CONN_TIMEOUT_MS / 2);
    node.tick(1000 + CONN_TIMEOUT_MS + 1, u32::MAX);
    let _ = drain(&mut node, 1000 + CONN_TIMEOUT_MS + 1);
    assert!(!node.router.conns.is_live(conn), "closed by the timeout");
}
