//! `csp_bind(socket, CSP_ANY)` — the catch-all — against a real C node.
//!
//! # It did not exist
//!
//! `csp_port.c` keeps the catch-all in a slot past the port array and reaches it from
//! `csp_port_get_socket` only when the packet's own port has no socket of its own. So a
//! node that binds `CSP_ANY` receives **every** port in range, and an explicit bind still
//! wins for the port it names.
//!
//! Measured on this branch before the change: `Router::bind` wrote into a `[bool; PORTS]`
//! and nothing else, `Node` had no catch-all of any kind, and `csp_bind` was recorded in
//! `ctest/tools/api_map.tsv` as plain `ported` with no note. Two comments in
//! `csp/src/router.rs` — on `endpoint_opts` and on the single accept queue — justify their
//! design with *"every consumer of the C binds `CSP_ANY`"*, which is the idiom the API
//! could not express. A firmware doing what those comments describe would have got a node
//! that delivered nothing.
//!
//! # What is compared
//!
//! Which port a delivery arrives for, and whether anything left on the wire, for the same
//! frame at every stage: before the catch-all exists, with it, with an explicit bind
//! alongside it, and after it is released. The "before" and "after" halves are what make
//! the middle mean anything — a node that delivered everything would satisfy the middle
//! alone.
//!
//! # `PORTS` is `CSP_PORT_MAX_BIND + 1`
//!
//! The C refuses a port above `CSP_PORT_MAX_BIND` in `csp_port_get_socket` *before* it
//! consults the catch-all, so such a packet is dropped however the node is bound. The
//! canonical build sets 16, so ports 0..=16 are deliverable and 17 is not. The node here is
//! therefore built with `PORTS` = 17 and the boundary is asserted from both sides — with
//! any other value the two stacks would disagree for a reason that is configuration rather
//! than behaviour.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;
const NETMASK: u16 = 12;
const HDR: usize = 6;

/// `CSP_PORT_MAX_BIND` in `build/canonical/include/csp/autoconfig.h`.
const MAX_BIND: u8 = 16;
/// One slot per deliverable port, 0..=`MAX_BIND`.
const PORTS: usize = MAX_BIND as usize + 1;

type TestNode<'a> = Node<'a, 8, 24, 300, PORTS, 8, 8>;

/// Ports below the ceiling: two ordinary ones and the ceiling itself.
const IN_RANGE: [u8; 3] = [10, 11, MAX_BIND];
/// Ports above it: the first one past, and two further out.
const OUT_OF_RANGE: [u8; 3] = [MAX_BIND + 1, 20, 63];
/// The one port that gets a bind of its own, to show precedence.
const SPECIFIC: u8 = 10;

fn framed(dport: u8, sport: u8) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: 4000,
        dst: NODE_ADDR,
        dport,
        sport,
    };
    let mut v = vec![0u8; HDR + 4];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(b"cmd!");
    v
}

/// What the C node does with `frame`: the ports it delivered for, and how many frames left.
///
/// Deliveries are collected from the catch-all socket *and* from every explicitly bound
/// port, because which socket a message lands on is exactly what the catch-all decides.
fn c_outcome(frame: &[u8], watch: &[u8]) -> (Vec<u8>, usize) {
    let ex = c_node_exchange(frame, watch);
    let mut ports: Vec<u8> = ex.delivered.iter().map(|d| d.dport).collect();
    for d in c_node_recv_any() {
        assert_eq!(
            d.payload, b"cmd!",
            "the catch-all must carry the body intact"
        );
        ports.push(d.dport);
    }
    ports.sort_unstable();
    (ports, ex.tx.len())
}

/// How the catch-all got to the state a stage is asking about.
///
/// `Released` is not the same experiment as `Never` and cannot be spelled as one: a node
/// that never bound the catch-all exercises no release path at all. Written as a single
/// `bool` first, the whole of `unbind_any` could be deleted and this file still passed.
#[derive(Clone, Copy, PartialEq)]
enum Catch {
    Never,
    Bound,
    Released,
}

/// The same question of a port node, built fresh so each stage is independent.
fn port_outcome(frame: &[u8], catch: Catch, specific: &[u8]) -> (Vec<u8>, usize) {
    let storage = CspStorage::<8, 24, 300, PORTS, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces
        .add("INGRESS", NODE_ADDR, NETMASK, false)
        .unwrap();
    node.ifaces
        .add("EGRESS", EGRESS_ADDR, NETMASK, true)
        .unwrap();
    if catch != Catch::Never {
        node.bind_any();
    }
    for &p in specific {
        node.bind(p).unwrap();
    }
    if catch == Catch::Released {
        node.unbind_any();
    }

    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, frame).expect("frame");
    node.router.receive(p, 0);

    let (mut ports, mut tx) = (Vec::new(), 0);
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    assert_eq!(
                        pkt.with_payload(<[u8]>::to_vec),
                        b"cmd!",
                        "the port must carry the body intact too"
                    );
                    ports.push(node.conn_dport(conn).expect("live connection"));
                    drop(pkt);
                }
            }
            Routed::Forwarded { packet, .. } => {
                drop(node.take_forwarded(packet));
                tx += 1;
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    ports.sort_unstable();
    (ports, tx)
}

/// Both stacks agree at every stage of binding, for ports on both sides of the ceiling.
///
/// One test, not five: libcsp's port table is process-global and `csp_bind` cannot be
/// undone for an ordinary port, so the stages have to run in this order in this process.
/// Splitting them would make each one's result depend on which acquired the lock first —
/// the mistake `node_alias.rs` made, where three green runs were scheduling luck.
#[test]
fn the_catch_all_delivers_exactly_what_a_real_node_delivers() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, NODE_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );

    // Stage 1 — nothing bound. Establishes that these ports are not delivered for some
    // other reason; without it every later assertion is satisfied by "delivers everything".
    for dport in IN_RANGE.into_iter().chain(OUT_OF_RANGE) {
        let frame = framed(dport, 40);
        assert_eq!(
            c_outcome(&frame, &[]),
            (vec![], 0),
            "with nothing bound the C neither delivers nor forwards port {dport}"
        );
        assert_eq!(
            port_outcome(&frame, Catch::Never, &[]),
            (vec![], 0),
            "and neither does the port"
        );
    }

    // Stage 2 — the catch-all alone.
    assert_eq!(c_node_bind_any(), 0, "csp_bind(CSP_ANY) succeeds");
    for dport in IN_RANGE {
        let frame = framed(dport, 41);
        assert_eq!(
            c_outcome(&frame, &[]),
            (vec![dport], 0),
            "the C's catch-all takes port {dport}, and does not also forward it"
        );
        assert_eq!(
            port_outcome(&frame, Catch::Bound, &[]),
            (vec![dport], 0),
            "and so must the port"
        );
    }
    // The ceiling holds even with the catch-all bound: dropped, not forwarded, by both.
    for dport in OUT_OF_RANGE {
        let frame = framed(dport, 42);
        assert_eq!(
            c_outcome(&frame, &[]),
            (vec![], 0),
            "port {dport} is above CSP_PORT_MAX_BIND, so the C drops it anyway"
        );
        assert_eq!(
            port_outcome(&frame, Catch::Bound, &[]),
            (vec![], 0),
            "as must the port"
        );
    }

    // Stage 3 — an explicit bind alongside the catch-all. The C reports this on the
    // port's own socket rather than the catch-all; here both are counted the same way, so
    // what is actually under test is that it is delivered once, not twice.
    assert_eq!(c_node_bind(SPECIFIC), 0, "bind port {SPECIFIC}");
    for dport in IN_RANGE {
        let frame = framed(dport, 43);
        assert_eq!(
            c_outcome(&frame, &[SPECIFIC]),
            (vec![dport], 0),
            "port {dport} arrives exactly once with both binds in place (C)"
        );
        assert_eq!(
            port_outcome(&frame, Catch::Bound, &[SPECIFIC]),
            (vec![dport], 0),
            "and exactly once for the port"
        );
    }

    // Stage 4 — release the catch-all. The explicit bind survives it; everything else
    // stops. This is the half that proves stage 2 was the catch-all's doing.
    c_node_unbind_any();
    for dport in IN_RANGE {
        let frame = framed(dport, 44);
        let want = if dport == SPECIFIC {
            vec![dport]
        } else {
            vec![]
        };
        assert_eq!(
            c_outcome(&frame, &[SPECIFIC]),
            (want.clone(), 0),
            "after csp_socket_close only port {SPECIFIC} is still served (C, port {dport})"
        );
        assert_eq!(
            port_outcome(&frame, Catch::Released, &[SPECIFIC]),
            (want, 0),
            "and the same for the port"
        );
    }

    // Stage 5 — releasing the catch-all, and what it leaves behind. A DELIBERATE
    // DIVERGENCE (SCOPE.md 31): the port returns the buffer, the C does not.
    //
    // `csp_socket_close` looks like it drains what the socket was holding: it dequeues
    // `socket->rx_queue` into a `csp_packet_t *` and frees each one (`csp_port.c:150`).
    // But for a connection-oriented socket that queue holds `csp_conn_t *` — that is what
    // `csp_route.c:194` enqueues and what `csp_accept` dequeues. So it hands a *connection*
    // to `csp_buffer_free`, whose `CONTAINER_OF` steps backwards off the front of the
    // connection object, fails its `skbf_addr` check and returns `CSP_DBG_ERR_CORRUPT_BUFFER`
    // (measured below, not read). The connection stays open and its queued packet stays
    // held: a message delivered to a port nobody serves any more, with nothing left to
    // release it.
    //
    // The message is deliberately left unread. Reading it first would return the buffer for
    // the ordinary reason and this whole stage would pass without touching the close path.
    const UNSERVED: u8 = 11;
    const CORRUPT_BUFFER: i32 = 1; // CSP_DBG_ERR_CORRUPT_BUFFER, csp_debug.h:35
    assert_eq!(c_node_bind_any(), 0, "the catch-all can be bound again");
    let c_before = c_node_buf_free();
    c_node_exchange(&framed(UNSERVED, 45), &[]);
    let c_held = c_node_buf_free();
    assert!(
        c_held < c_before,
        "the unread message must be holding a buffer for this stage to mean anything"
    );
    assert_eq!(
        c_node_unbind_any(),
        CORRUPT_BUFFER,
        "csp_socket_close passes a connection to csp_buffer_free"
    );
    assert_eq!(
        c_node_buf_free(),
        c_held,
        "so the C keeps holding the buffer after the socket is closed"
    );

    let storage = CspStorage::<8, 24, 300, PORTS, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces
        .add("INGRESS", NODE_ADDR, NETMASK, false)
        .unwrap();
    node.bind_any();
    let before = node.buffers_free();
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(UNSERVED, 45)).expect("frame");
    node.router.receive(p, 0);
    assert!(
        matches!(node.work(0), Routed::Delivered { .. }),
        "the port delivers it through the catch-all"
    );
    assert!(
        node.buffers_free() < before,
        "and is holding the buffer, unread"
    );
    assert_eq!(node.unbind_any(), 1, "one connection was the catch-all's");
    assert_eq!(
        node.buffers_free(),
        before,
        "the port returns it, which is the divergence"
    );
}

/// Releasing the catch-all returns **every** buffer, not one drain's worth.
///
/// `unbind_any` closes one port's receive queue at a time and stops as soon as its scratch
/// array cannot hold another whole one, expecting to be called again — the same contract
/// `unbind` has, and the same one `unbind` was written without, leaving connections open on
/// a port nothing served with a buffer each and nothing left to release them.
///
/// A pool of 24 cannot tell that loop apart from a single pass over a fixed 32-slot array,
/// so this node has 64 buffers and queues more than 32 packets across five catch-all ports.
/// Port-only by necessity: `csp_socket_close` frees nothing at all (SCOPE.md 31), so there
/// is no C behaviour here to compare against.
#[test]
fn releasing_the_catch_all_returns_every_buffer_not_one_drains_worth() {
    const BIG_BUFS: usize = 64;
    const SPREAD: [u8; 5] = [1, 2, 3, 4, 5];
    const EACH: u8 = 8; // one full receive queue per port

    let storage = CspStorage::<8, BIG_BUFS, 300, PORTS, 16>::new();
    let mut node: Node<'_, 8, BIG_BUFS, 300, PORTS, 16, 8> =
        Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces
        .add("INGRESS", NODE_ADDR, NETMASK, false)
        .unwrap();
    node.bind_any();

    let before = node.buffers_free();
    for dport in SPREAD {
        for _ in 0..EACH {
            let mut p = node.packet().expect("pool");
            p.set_frame(VERSION, &framed(dport, 40)).expect("frame");
            node.router.receive(p, 0);
            while !matches!(node.work(0), Routed::Idle) {}
        }
    }
    let held = before - node.buffers_free();
    assert!(
        held > 32,
        "more than one 32-slot pass must be waiting, or the loop is unfalsifiable: {held}"
    );

    assert_eq!(
        node.unbind_any(),
        SPREAD.len(),
        "one connection per catch-all port"
    );
    assert_eq!(
        node.buffers_free(),
        before,
        "every buffer comes back, not just the first pass"
    );
}
