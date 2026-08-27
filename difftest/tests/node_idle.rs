//! Idle connections — which ones a sweep may take — against a real C node.
//!
//! # libcsp expires nothing on idleness
//!
//! `csp_conn_check_timeouts` looks like a general reaper and is not: it enters its body only
//! for a connection carrying `CSP_FRDP` (`csp_conn.c:32`). A plain connection, client or
//! server, is closed by the application or not at all — no clock touches it.
//!
//! The port's `Table::expire_idle` swept **every** open connection past `conn_timeout_ms`.
//! For a connection this node's own application opened, that takes it out from under code
//! which is merely quiet between passes, and the reply it is waiting for is then refused as
//! `PortNotBound`. Measured before the fix:
//!
//! ```text
//! C:    after 1000 sweeps the reply is Some("repl")
//! port: tick closed 1 connection(s); routing the reply gave Dropped(PortNotBound)
//! ```
//!
//! This is the same defect already found and fixed once in the RDP path — SCOPE.md records
//! it as *"a connection that is merely quiet — a telemetry link between passes — was dropped
//! while the C kept answering on it"* — surviving in the plain path.
//!
//! # What the sweep keeps
//!
//! Server connections. Those are created by the router when a packet arrives for a bound
//! port, so a peer that sends one packet and walks away leaves a slot nothing will ever
//! close; the C leaks it and the port does not. That divergence is deliberate and is
//! asserted here as one, so removing the sweep entirely would fail too.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 20;
const NETMASK: u16 = 12;
/// The remote service a client connection talks to.
const PORT: u8 = 12;
/// A port the port-side node binds, so a peer can open a server connection to it.
const SERVED: u8 = 10;
const HDR: usize = 6;

const TIMEOUT_MS: u32 = 60_000;
/// Far enough past `TIMEOUT_MS` that nothing survives on a rounding argument.
const LATER_MS: u32 = TIMEOUT_MS * 10;

type TestNode<'a> = Node<'a, 8, 40, 300, 64, 16, 8>;

fn framed(src: u16, dst: u16, dport: u8, sport: u8, body: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src,
        dst,
        dport,
        sport,
    };
    let mut v = vec![0u8; HDR + body.len()];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(body);
    v
}

fn new_node(storage: &CspStorage<8, 40, 300, 64, 16>) -> TestNode<'_> {
    let mut node: TestNode = Node::new(storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("OUT", R_ADDR, NETMASK, true).unwrap();
    node
}

/// A quiet client connection still receives its reply, in both stacks.
///
/// The C half needs no clock: `csp_conn_check_timeouts` cannot close a plain connection
/// however many times it runs, because it never looks at one. Sweeping it a thousand times
/// is the strongest form of that statement the harness can make.
#[test]
fn a_quiet_client_connection_still_gets_its_reply() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, R_ADDR, 40),
        "C node came up at v2"
    );

    let frames = c_node_client_send(R_ADDR, PORT, b"req");
    assert_eq!(frames.len(), 1, "the C's request went out");
    let c_sport = Id::decode(VERSION, &frames[0]).expect("decodes").sport;
    for _ in 0..1000 {
        c_node_check_timeouts();
    }
    assert_eq!(
        c_node_client_recv(&framed(R_ADDR, C_ADDR, c_sport, PORT, b"repl")).as_deref(),
        Some(&b"repl"[..]),
        "a real node still delivers the reply after 1000 sweeps"
    );

    let storage = CspStorage::<8, 40, 300, 64, 16>::new();
    let mut node = new_node(&storage);
    let conn = node.connect(2, C_ADDR, PORT, 0, 0).expect("a slot");
    let mut p = node.packet().expect("pool");
    p.set_payload(b"req").expect("payload");
    let sport = node
        .send(conn, p, 0)
        .expect("routed")
        .into_packet()
        .id()
        .sport;

    assert_eq!(
        node.tick(LATER_MS, TIMEOUT_MS),
        0,
        "the tick must not take a connection the application opened and still holds"
    );

    let mut r = node.packet().expect("pool");
    r.set_frame(VERSION, &framed(C_ADDR, R_ADDR, sport, PORT, b"repl"))
        .expect("frame");
    node.router.receive(r, 0);
    while !matches!(node.work(LATER_MS), Routed::Idle) {}
    let got = node
        .read(conn)
        .expect("the connection is still live")
        .expect("and so is the reply");
    got.with_payload(|b| assert_eq!(b, b"repl", "with its bytes intact"));
}

/// A server connection nobody accepted **is** swept, and its buffer comes back.
///
/// The deliberate half, asserted as a divergence: libcsp keeps such a connection for ever.
/// Without this, removing the sweep altogether would satisfy the test above and leave a node
/// that any peer can exhaust by sending one packet per slot and stopping.
#[test]
fn a_server_connection_nobody_accepted_is_swept() {
    let _g = lock();
    let storage = CspStorage::<8, 40, 300, 64, 16>::new();
    let mut node = new_node(&storage);
    node.bind(SERVED).unwrap();

    let before = node.buffers_free();
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(4000, R_ADDR, SERVED, 40, b"hi"))
        .expect("frame");
    node.router.receive(p, 0);
    while !matches!(node.work(0), Routed::Idle) {}
    assert!(
        node.buffers_free() < before,
        "the unaccepted message is holding a buffer, or there is nothing to reclaim"
    );

    assert_eq!(
        node.tick(LATER_MS, TIMEOUT_MS),
        1,
        "a server connection nobody accepted is the sweep's job"
    );
    assert_eq!(
        node.buffers_free(),
        before,
        "and its queued packet comes back with it"
    );
}
