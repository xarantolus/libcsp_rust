//! Connection-table exhaustion and reuse, compared between a real C node and the port.
//!
//! # The two nodes have to be sized the same
//!
//! The C builds with `CSP_CONN_MAX = 8` and `CSP_BUFFER_COUNT = 15`. The port's node in the
//! other files here carries 8 connections but **24** buffers, and each accepted connection
//! holds its packet until the application reads it — so with 24 buffers the port runs out
//! of *connections* where the C runs out of *buffers*. Comparing "how many peers were
//! accepted" across those two is comparing two different experiments, and would have shown
//! a difference that is entirely the harness's.
//!
//! So this file's node is `<8, 15, ...>`: the same connection count and the same pool as
//! the C it is being compared against.
//!
//! # Why this is a separate binary and not a loop
//!
//! `csp_conf.version` is init-only. Changing it after `csp_init()` silently misroutes
//! every packet (SCOPE.md deviation 18 — measured as one leaked buffer per fragment until
//! the pool empties). So one process gets one C node at one wire version. Cargo gives each
//! integration-test file its own binary, which is exactly the process isolation needed —
//! the same trick the golden-vector oracle uses.
//!
//! Without this file, v2 has never been through a node at all: every node-level test in
//! `diff.rs` pins `Version::V1`, and the `versions()` loops there are all codec-level.
//! v2 headers were verified; v2 *routing and delivery* were not.
//!
//! # The topology has to be recomputed, not copied
//!
//! v1 has 5 host bits and v2 has 14, so a netmask is not portable between them. The two
//! interfaces must land in different subnets or split horizon vetoes forwarding:
//!
//! | | netmask | mask | ingress 9 | egress 20 | forwardable dst |
//! |---|---|---|---|---|---|
//! | v1 | 2 | `0b11000` | subnet 8 | subnet 16 | 18 |
//! | v2 | 12 | `0x3FFC` | subnet 8 | subnet 20 | 21 |
//!
//! Reusing v1's netmask of 2 under v2 gives `((1<<2)-1) << (14-2)` = `0x3000`, and both 9
//! and 20 mask to subnet 0 — one subnet, no forwarding, and a test that passes by
//! asserting nothing happened.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
/// See the table above: 12 network bits of 14 puts 9 and 20 in different subnets.
const NETMASK: u16 = 12;
/// A third subnet, so a route can point somewhere local-subnet would not choose.
const THIRD_ADDR: u16 = 40;

type TestNode<'a> = Node<'a, 8, 15, 300, 64, 8, 8>;

fn framed(id: Id, payload: &[u8]) -> Vec<u8> {
    let hdr = 6; // v2
    let mut v = vec![0u8; hdr + payload.len()];
    id.encode(VERSION, &mut v).expect("id fits v2");
    v[hdr..].copy_from_slice(payload);
    v
}

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, NODE_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );
    assert_eq!(c_node_bind(10), 0, "bind port 10");
}

/// More peers than the node has slots, three times over.
///
/// `csp_route_deliver_connection` frees the packet when `csp_conn_new` returns NULL, so
/// running out costs nothing permanent — and a closed connection is reusable, without which
/// the table is a one-shot resource and a node stops answering new peers after
/// `CSP_CONN_MAX` of them have ever connected. That looks exactly like a leak and is not
/// one, which is why both are asserted here rather than just the first.
#[test]
fn running_out_of_connections_and_reusing_them_matches_the_c() {
    const ROUNDS: usize = 3;
    /// Comfortably more than `CSP_CONN_MAX`, and more than the pool can hold at once.
    const PEERS: u8 = 20;

    let _g = lock();
    setup();
    c_node_set_dedup(0);

    let frames: Vec<Vec<u8>> = (0..PEERS)
        .map(|i| {
            framed(
                Id {
                    pri: 2,
                    flags: 0,
                    src: 4000,
                    dst: NODE_ADDR,
                    dport: 10,
                    sport: 40 + i,
                },
                b"hi",
            )
        })
        .collect();

    let before = c_node_buf_free();
    let mut c_rounds = Vec::new();
    for _ in 0..ROUNDS {
        for f in &frames {
            c_node_exchange(f, &[]);
        }
        c_rounds.push(c_node_accept_count(10) as usize);
    }
    let c_lost = before - c_node_buf_free();

    let r = rust_conn_exchange(&frames, ROUNDS);

    assert!(
        c_rounds[0] > 0,
        "the C accepts some peers; if this is 0 the case never filled anything"
    );
    assert!(
        (c_rounds[0] as u8) < PEERS,
        "and refuses the rest -- with {PEERS} peers offered it accepted {}, so the table \
         never actually ran out and the case proves nothing",
        c_rounds[0]
    );
    assert_eq!(
        r.rounds, c_rounds,
        "the port must accept the same number of peers per round as the C, given the same \
         connection count and the same buffer pool"
    );

    // Refusing the surplus costs nothing permanent, on either side.
    assert_eq!(c_lost, 0, "the C gets every buffer back");
    assert_eq!(r.buffers_lost, 0, "and so does the port");

    // And the last round is as productive as the first: closed slots come back.
    assert_eq!(
        c_rounds[ROUNDS - 1],
        c_rounds[0],
        "the C's table is reusable"
    );
    assert_eq!(
        r.rounds[ROUNDS - 1],
        r.rounds[0],
        "and so is the port's -- a table that did not recycle would leave the node unable \
         to answer any new peer after the first round, which looks like a leak but is not"
    );
}

#[derive(Debug, Default)]
struct ConnOutcome {
    rounds: Vec<usize>,
    buffers_lost: i32,
}

/// The same offer/drain cycle against a fresh port node sized like the C.
fn rust_conn_exchange(frames: &[Vec<u8>], rounds: usize) -> ConnOutcome {
    let storage = CspStorage::<8, 15, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces
        .add("INGRESS", NODE_ADDR, NETMASK, true)
        .unwrap();
    node.bind(10).unwrap();

    let before = node.pool().available() as i32;
    let mut out = ConnOutcome::default();
    for _ in 0..rounds {
        let mut accepted = 0usize;
        for f in frames {
            let Some(mut p) = node.packet() else { break };
            if p.set_frame(VERSION, f).is_err() {
                break;
            }
            node.router.receive(p, 0);
            while !matches!(node.work(0), Routed::Idle) {}
        }
        // Take every connection the application is offered, draining each.
        while let Some(conn) = node.accept() {
            while let Ok(Some(pkt)) = node.read(conn) {
                drop(pkt);
            }
            let _ = node.close(conn);
            accepted += 1;
        }
        out.rounds.push(accepted);
    }
    out.buffers_lost = before - node.pool().available() as i32;
    out
}
