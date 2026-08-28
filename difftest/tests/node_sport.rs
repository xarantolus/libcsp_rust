//! Ephemeral source ports — the thing `find` leans on — against a real C node.
//!
//! # The invariant, and where both stacks lean on it
//!
//! `csp_conn_find_existing` matches a **client** connection on the incoming destination
//! port alone, with the comment saying why: *"Outgoing connections are uniquely defined by
//! the source port, so only the incoming destination port must match"* (`csp_conn.c:110`).
//! `Table::find` does the same.
//!
//! That is only sound because the C's source port is a property of the **slot**, not of a
//! counter: `csp_conn_init` sets `conn->sport_outgoing = CSP_PORT_MAX_BIND + 1 + i` once
//! (`csp_conn.c:58`) and `csp_connect` copies it into the outgoing header. Two connections
//! open at the same time are different slots, so they cannot share a source port.
//!
//! # What the port did instead
//!
//! A rotating counter, which gives that guarantee only until it wraps. Measured before the
//! fix, one connection held open on 17 and the rest opened and closed:
//!
//! ```text
//! C, eight open at once:      [18, 19, 20, 21, 22, 23, 24, 17]   one per slot
//! C, slots 1/3/5 reopened:    [19, 21, 23]                       the same ports again
//! port, held connection:      17
//! port: connection 46 got sport 17, the same as the still-open one
//! ```
//!
//! Two live client connections then share a source port, and a reply for either is
//! delivered to whichever the scan reaches first — a reply to one request handed to the
//! code that made a different one. `Node::connect` now derives the port from the slot.
//!
//! # What is compared
//!
//! The source ports that reach the wire while several connections are open at once, and
//! then, on a node that has churned through more connections than there are ephemeral
//! ports, which connection's application receives a reply.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 20;
const NETMASK: u16 = 12;
/// The remote service. Deliberately not in the ephemeral range, so a source port can never
/// be mistaken for it.
const PORT: u8 = 12;
const HDR: usize = 6;

/// `CSP_CONN_MAX` in the canonical build, and the port node's `CONNS`.
const CONNS: usize = 8;

/// Ephemeral ports run from here to `max_port()`. 17 is `CSP_PORT_MAX_BIND + 1`.
const EPHEMERAL_FIRST: u8 = 17;

type TestNode<'a> = Node<'a, CONNS, 40, 300, 64, 16, 8>;

fn new_node(storage: &CspStorage<CONNS, 40, 300, 64, 16>) -> TestNode<'_> {
    let mut node: TestNode = Node::new(storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("OUT", R_ADDR, NETMASK, true).unwrap();
    node
}

/// The source port a port-side connection puts on the wire.
///
/// Read off the frame the node hands back, not off the connection: what a peer sees is what
/// makes two connections distinguishable. (`conn_sport` is the C's `csp_conn_sport`, which
/// returns `idin.sport` — the *remote* port. Reading it here reported the service port for
/// every connection, and the first version of this file did exactly that.)
fn wire_sport(node: &mut TestNode<'_>, conn: csp::conn::Handle) -> u8 {
    let mut p = node.packet().expect("pool");
    p.set_payload(b"x").expect("payload");
    let out = node.send(conn, p, 0).expect("routed");
    let packet = out.into_packet();
    let sport = packet.id().sport;
    drop(packet);
    sport
}

/// A reply addressed to `sport`, as a peer would send one back.
fn reply_to(sport: u8, body: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: C_ADDR,
        dst: R_ADDR,
        dport: sport,
        sport: PORT,
    };
    let mut v = vec![0u8; HDR + body.len()];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(body);
    v
}

/// Connections open at the same time never share a source port, in either stack.
///
/// The C cannot be made to break this — that is the point of comparing against it. Its
/// ports come back identical when a slot is reused, which is the same fact seen from the
/// other side: the port belongs to the slot.
#[test]
fn no_two_open_connections_share_a_source_port() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, R_ADDR, 40),
        "C node came up at v2"
    );

    let c_ports: Vec<i32> = (0..CONNS as i32)
        .map(|s| c_conn_open(s, R_ADDR, PORT))
        .collect();
    assert!(
        c_ports.iter().all(|&p| p >= EPHEMERAL_FIRST as i32),
        "every C source port is in the ephemeral range: {c_ports:?}"
    );
    let mut sorted = c_ports.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        CONNS,
        "all {CONNS} open at once, all distinct: {c_ports:?}"
    );

    // Reopening a slot gives its port back — the port is the slot's, not a counter's.
    for s in [1, 3, 5] {
        c_conn_close(s);
    }
    let again: Vec<i32> = [1, 3, 5]
        .iter()
        .map(|&s| c_conn_open(s, R_ADDR, PORT))
        .collect();
    assert_eq!(
        again,
        vec![c_ports[1], c_ports[3], c_ports[5]],
        "a reused slot brings its own source port back"
    );
    for s in 0..CONNS as i32 {
        c_conn_close(s);
    }

    let storage = CspStorage::<CONNS, 40, 300, 64, 16>::new();
    let mut node = new_node(&storage);
    let conns: Vec<_> = (0..CONNS)
        .map(|_| node.connect(2, C_ADDR, PORT, 0, 0).expect("a free slot"))
        .collect();
    let mut ports: Vec<u8> = conns.iter().map(|&c| wire_sport(&mut node, c)).collect();
    assert!(
        ports.iter().all(|&p| p >= EPHEMERAL_FIRST),
        "and the port's are in the ephemeral range too: {ports:?}"
    );
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), CONNS, "and all distinct");
}

/// After churning past the ephemeral range, a reply still reaches the connection that asked.
///
/// The churn is what the old rotating counter could not survive: `max_port() -
/// EPHEMERAL_FIRST + 1` connections is a full lap, after which it handed a live
/// connection's port to a new one. A slot-derived port cannot, because the held slot is
/// never free.
///
/// Port-only by necessity — libcsp offers no way to produce the collision, which is the
/// finding, and the test above is the C-side half of it.
#[test]
fn a_reply_reaches_the_connection_that_asked_after_a_full_lap_of_ports() {
    let _g = lock();
    let storage = CspStorage::<CONNS, 40, 300, 64, 16>::new();
    let mut node = new_node(&storage);

    let held = node.connect(2, C_ADDR, PORT, 0, 0).expect("a slot");
    let held_sport = wire_sport(&mut node, held);

    // One full lap of the ephemeral range, and then some.
    let lap = (VERSION.max_port() - EPHEMERAL_FIRST) as usize + 1;
    let mut reused = 0;
    for _ in 0..lap + 10 {
        let c = node.connect(2, C_ADDR, PORT, 0, 0).expect("a free slot");
        if wire_sport(&mut node, c) == held_sport {
            reused += 1;
        }
        node.close(c, 0).expect("close");
    }
    assert_eq!(
        reused,
        0,
        "no connection may take the source port of one that is still open ({} laps)",
        lap + 10
    );

    // And the consequence that matters: each reply reaches the connection that asked.
    //
    // Both directions, deliberately. `held` was allocated first, so a `find` that ignored
    // the port entirely and returned the first open connection would satisfy the `held`
    // half on scan order alone -- a control that replaced the port match with `true` passed
    // when only that half was asserted. The reply addressed to the *later* connection is
    // the one that can only arrive by matching.
    let latest = node.connect(2, C_ADDR, PORT, 0, 0).expect("a free slot");
    let latest_sport = wire_sport(&mut node, latest);
    assert_ne!(latest_sport, held_sport, "two live connections, two ports");

    for (target, other, sport, body) in [
        (latest, held, latest_sport, &b"late"[..]),
        (held, latest, held_sport, &b"held"[..]),
    ] {
        let mut p = node.packet().expect("pool");
        p.set_frame(VERSION, &reply_to(sport, body)).expect("frame");
        node.router.receive(p, 0);
        while !matches!(node.work(0), Routed::Idle) {}

        let got = node
            .read(target)
            .expect("the addressed connection is live")
            .expect("a reply addressed to a connection must reach it");
        got.with_payload(|b| assert_eq!(b, body, "and carry its own bytes"));
        drop(got);
        assert!(
            node.read(other).unwrap_or(None).is_none(),
            "and not the other connection"
        );
    }
}
