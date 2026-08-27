//! Connection-less sockets — `CSP_SO_CONN_LESS` — against a real C node.
//!
//! # The option had no counterpart
//!
//! `csp_route_deliver_conn_less` (`csp_route.c:132`) puts the **packet** straight on the
//! socket's queue. No connection is created and none is consulted, so a connection-less
//! server costs nothing from the connection pool however many peers write to it. That is
//! the whole reason the option exists: a telemetry sink with more senders than the node has
//! connections.
//!
//! Measured on this branch before the change. `Node::recvfrom` was `accept` + `read` +
//! `close` under the name `csp_recvfrom`, with a doc comment calling it "the connection-less
//! server pattern", and `ctest/tools/api_map.tsv` mapped `csp_recvfrom` and `csp_sendto` as
//! plain `ported`. Nothing anywhere — no corpus record, no suite, no differential test —
//! mentioned `CSP_SO_CONN_LESS`. The probe that started this file:
//!
//! ```text
//! C:    12 senders -> 12 received      port:  12 senders -> 8 received
//! C:    20 senders -> 13 received      port:  20 senders -> 8 received
//! ```
//!
//! The port stopped at `CONNS`. The C stopped when its buffer pool ran out — 13 with 15
//! free, never at a connection count, because it never took one.
//!
//! # What is compared
//!
//! How many messages a connection-less server receives from more distinct peers than the
//! node has connections, and which sender each one came from. Both stacks are given the
//! same number of connections and enough buffers that the pool is not the limit, so the
//! only thing that can cut the count short is the connection table.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const NETMASK: u16 = 12;
const HDR: usize = 6;

/// `CSP_CONN_MAX` in `build/canonical/include/csp/autoconfig.h`. The port node is built
/// with the same number, so "ran out of connections" means the same thing on both sides.
const CONNS: usize = 8;
/// More senders than there are connections — the case the option exists for. The whole
/// experiment rests on this being true, so it is checked where it cannot drift.
const SENDERS: usize = 12;
const _: () = assert!(SENDERS > CONNS);
/// `CSP_CONN_RXQUEUE_LEN`: the socket queue on the C, `RXQ` here. Must exceed `SENDERS`,
/// or the queue rather than the connection table would be what cuts the count short.
const RXQ: usize = 16;

/// What arrived, as (sender address, first payload byte) — one list per door.
type Doors = (Vec<(u16, u8)>, Vec<(u16, u8)>);

const CL_PORT: u8 = 10;
const ORDINARY_PORT: u8 = 11;

fn framed(dport: u8, src: u16, body: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src,
        dst: NODE_ADDR,
        dport,
        sport: 40,
    };
    let mut v = vec![0u8; HDR + body.len()];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(body);
    v
}

/// One byte per sender, so a received message names the peer that sent it.
fn body(i: usize) -> Vec<u8> {
    vec![i as u8; 4]
}

fn sender(i: usize) -> u16 {
    4000 + i as u16
}

/// Feed the C node one packet from each of `SENDERS` peers, **reading nothing until they
/// have all arrived**, then report what came back through each door: `csp_accept` +
/// `csp_read`, and `csp_recvfrom`.
///
/// Both doors, always. Reading only the door a case expects is how the first version of
/// this file reported the C receiving nothing on an ordinary port.
///
/// Nothing is read in between because that is the whole experiment. Draining after every
/// packet keeps at most one connection open and recycles it, so an ordinary port then takes
/// all twelve too — measured, after asserting the opposite. What a connection-less port
/// saves you is the connections held by peers you have not got to yet.
fn c_run(dport: u8) -> Doors {
    for i in 0..SENDERS {
        c_node_exchange(&framed(dport, sender(i), &body(i)), &[]);
    }
    let mut accepted: Vec<(u16, u8)> = c_node_drain(&[dport])
        .delivered
        .iter()
        .map(|d| (d.src, d.payload[0]))
        .collect();
    let mut received: Vec<(u16, u8)> = c_node_recvfrom()
        .into_iter()
        .map(|d| (d.src, d.payload[0]))
        .collect();
    accepted.sort_unstable();
    received.sort_unstable();
    (accepted, received)
}

/// The same of a port node, through the same two doors and with the same nothing read in
/// between.
fn port_run(dport: u8, conn_less: bool) -> Doors {
    let storage = CspStorage::<CONNS, 64, 300, 64, 16>::new();
    let mut node: Node<'_, CONNS, 64, 300, 64, 16, RXQ> =
        Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces.add("IN", NODE_ADDR, NETMASK, false).unwrap();
    if conn_less {
        node.bind_conn_less(dport).unwrap();
    } else {
        node.bind(dport).unwrap();
    }

    for i in 0..SENDERS {
        let mut p = node.packet().expect("pool");
        p.set_frame(VERSION, &framed(dport, sender(i), &body(i)))
            .expect("frame");
        node.router.receive(p, 0);
        while !matches!(node.work(0), Routed::Idle) {}
    }

    let (mut accepted, mut received) = (Vec::new(), Vec::new());
    while let Some(conn) = node.accept() {
        while let Ok(Some(pkt)) = node.read(conn) {
            accepted.push((pkt.id().src, pkt.with_payload(|b| b[0])));
            drop(pkt);
        }
        let _ = node.close(conn);
    }
    while let Ok(Some(pkt)) = node.recvfrom() {
        received.push((pkt.id().src, pkt.with_payload(|b| b[0])));
        drop(pkt);
    }
    accepted.sort_unstable();
    received.sort_unstable();
    (accepted, received)
}

/// A connection-less port takes every peer; an ordinary one runs out of connections.
///
/// One test, not two: libcsp's port table is process-global, so a second `#[test]` in this
/// binary would be asking its question of a node the first one had already bound and filled.
/// Written as two, the ordinary-port case saw eight connections left over from the
/// conn-less case and read them as its own result.
#[test]
fn a_connection_less_port_takes_more_peers_than_the_node_has_connections() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, NODE_ADDR, NETMASK, 20, 40),
        "C node came up at v2"
    );
    assert_eq!(
        c_node_bind_conn_less(CL_PORT),
        0,
        "csp_bind with CSP_SO_CONN_LESS"
    );
    assert_eq!(c_node_bind(ORDINARY_PORT), 0, "and an ordinary port");

    let want: Vec<(u16, u8)> = (0..SENDERS).map(|i| (sender(i), i as u8)).collect();

    // The connection-less port: every peer arrives, through `recvfrom` and only through it.
    let (accepted, received) = c_run(CL_PORT);
    assert_eq!(
        received, want,
        "a real node takes all {SENDERS} without spending a connection"
    );
    assert_eq!(
        accepted,
        vec![],
        "and offers none of them to csp_accept -- the socket is the endpoint"
    );
    let (accepted, received) = port_run(CL_PORT, true);
    assert_eq!(
        received, want,
        "and so must the port, from the same {CONNS} connections"
    );
    assert_eq!(accepted, vec![], "and offer none of them to accept either");

    // The control, and the reason the numbers above mean anything: the *same* traffic to an
    // ordinary port does run out of connections, on both stacks. Without it the whole test
    // is satisfied by a node with a bigger connection table.
    //
    // `CONN_MAX` on the C and `CONNS` here are the same number, so both stop at the same
    // place; what matters is that both stop, and that neither did on the port above.
    let (accepted, received) = c_run(ORDINARY_PORT);
    assert_eq!(
        accepted.len(),
        CONNS,
        "the C runs out of connections on an ordinary port: {accepted:?}"
    );
    assert_eq!(
        received,
        vec![],
        "and csp_recvfrom says nothing about an ordinary port"
    );
    let (accepted, received) = port_run(ORDINARY_PORT, false);
    assert_eq!(accepted.len(), CONNS, "and so does the port");
    assert_eq!(received, vec![], "nor does the port's recvfrom");
}
