//! A reply is checked against the **connection's** policy, not the node's.
//!
//! # What the C does
//!
//! `csp_connect` stores the caller's options on the connection (`csp_conn.c:320`), and
//! when a reply arrives `csp_route_deliver` resolves the endpoint — the existing connection
//! first, the bound socket otherwise — and checks the packet against *that* endpoint's
//! options: `uint32_t opts = conn ? conn->opts : socket->opts` (`csp_route.c:288`). A
//! connection opened with `CSP_O_CRC32` therefore refuses an unchecksummed reply, while one
//! opened with `0` on the same node takes it. Nothing node-wide is consulted.
//!
//! # Why it matters
//!
//! A flight node is a client too: it asks the payload for its status and the radio for its
//! counters, and the port lets the caller ask for a checksum per connection exactly as
//! `csp_connect` does. If the reply is then checked against a node-wide policy instead, a
//! protection the caller asked for and the peer omitted is silently not enforced — the
//! request went out flagged, the answer came back bare, and the application reads it as
//! verified. That is the same shape as the outgoing half `egress.rs` fixed: a flag set and
//! nothing behind it.
//!
//! # What is measured
//!
//! Both stacks, three cases each, the reply being a real ping echo from the other stack:
//!
//! | connection opened with | reply carries | C (`csp_transaction_persistent`) | port |
//! |---|---|---|---|
//! | `CRC32_REQ` | a checksum | accepted, checksum stripped | must match |
//! | `CRC32_REQ` | nothing | **refused**, `rx_error` | must match |
//! | `0` | nothing | accepted | must match |
//!
//! The middle row is the one a node-wide policy gets wrong in one direction or the other:
//! with the node's policy at `0` the bare reply is accepted; set to `CRC32_REQ` it would
//! refuse the third row too.

use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::security::opts;
use csp_core::{flags, Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;
const HDR: usize = 6;

const PING: &[u8] = b"policy is per connection";

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn fresh<'a>(storage: &'a CspStorage<8, 24, 300, 64, 8>) -> TestNode<'a> {
    let mut node: TestNode = Node::new(storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node
}

/// Open a connection to the C node's ping service under `conn_opts`, send `PING`, and
/// return the frame the port put on the wire.
fn port_ping(node: &mut TestNode, conn_opts: u32) -> (csp::conn::Handle, Vec<u8>) {
    let conn = node
        .connect(2, C_ADDR, csp_core::ports::PING, conn_opts, 0)
        .expect("connect");
    let mut req = node.packet().expect("pool");
    req.set_payload(PING).unwrap();
    let mut pkt = match node.send(conn, req, 0).expect("send") {
        Outbound::Transmit { packet, .. } => packet,
        other => panic!("must route: {other:?}"),
    };
    pkt.prepend_header(VERSION).unwrap();
    (conn, pkt.with_frame(|f| f.to_vec()))
}

/// The same reply with the CRC32 flag cleared and the checksum removed — what a peer that
/// ignores the request's flags, or an attacker, would send.
fn stripped(frame: &[u8]) -> Vec<u8> {
    let mut id = Id::decode(VERSION, &frame[..HDR]).expect("the C's header");
    assert!(id.has_flag(flags::CRC32), "the C echoed the checksum flag");
    id.flags &= !flags::CRC32;
    let mut out = vec![0u8; HDR];
    id.encode(VERSION, &mut out).unwrap();
    out.extend_from_slice(&frame[HDR..frame.len() - 4]);
    out
}

/// Feed one frame to the port and report what happened to it.
fn feed(node: &mut TestNode, frame: &[u8]) -> (Vec<Vec<u8>>, Vec<String>) {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, frame).expect("frame");
    node.router.receive(p, 0);
    let mut delivered = Vec::new();
    let mut dropped = Vec::new();
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    delivered.push(pkt.with_payload(|d| d.to_vec()));
                    drop(pkt);
                }
            }
            Routed::Dropped(reason) => dropped.push(format!("{reason:?}")),
            Routed::Idle => break,
            _ => continue,
        }
    }
    (delivered, dropped)
}

#[test]
fn the_c_checks_a_reply_against_the_connection_it_arrived_on() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        C_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));

    let (ret, got) = c_client_transaction_opts(
        R_ADDR,
        csp_core::ports::PING,
        opts::CRC32_REQ,
        flags::CRC32,
        PING,
        -1,
    );
    assert_eq!(
        ret,
        PING.len() as i32,
        "a checksummed reply on a CRC32 connection is accepted"
    );
    assert_eq!(got, PING, "and handed over with the checksum stripped");

    let (ret, _) =
        c_client_transaction_opts(R_ADDR, csp_core::ports::PING, opts::CRC32_REQ, 0, PING, -1);
    assert_eq!(
        ret, 0,
        "a bare reply on a CRC32 connection is refused by the C's router before the \
         transaction sees it (csp_route.c:288 with conn->opts)"
    );

    let (ret, got) = c_client_transaction_opts(R_ADDR, csp_core::ports::PING, 0, 0, PING, -1);
    assert_eq!(
        ret,
        PING.len() as i32,
        "a bare reply on a plain connection is accepted"
    );
    assert_eq!(got, PING);
}

#[test]
fn the_port_checks_a_reply_against_the_connection_it_arrived_on() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        C_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));
    assert_eq!(
        c_node_bind(csp_core::ports::PING),
        0,
        "bind the C's ping service"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    assert_eq!(
        node.router.endpoint_opts, 0,
        "no node-wide policy: the connection's is what counts"
    );

    // 1. CRC32 connection, checksummed reply from a real C node: accepted and stripped.
    let (_conn, req) = port_ping(&mut node, opts::CRC32_REQ);
    let replies = c_node_serve(&req, csp_core::ports::PING);
    assert_eq!(replies.len(), 1, "the C answers the checksummed ping");
    let (delivered, dropped) = feed(&mut node, &replies[0]);
    assert_eq!(dropped, Vec::<String>::new());
    assert_eq!(
        delivered,
        vec![PING.to_vec()],
        "the echo, checksum verified and stripped"
    );

    // 2. The same connection, the same reply without its checksum: refused, as the C does.
    let (_conn, req) = port_ping(&mut node, opts::CRC32_REQ);
    let replies = c_node_serve(&req, csp_core::ports::PING);
    let bare = stripped(&replies[0]);
    let rx_error_before = node.router.counters.rx_error;
    let (delivered, dropped) = feed(&mut node, &bare);
    assert_eq!(
        delivered,
        Vec::<Vec<u8>>::new(),
        "a bare reply on a connection that asked for a checksum must not reach the \
         application: the request went out flagged and the answer came back unprotected"
    );
    assert_eq!(dropped.len(), 1, "one refusal");
    assert!(
        dropped[0].contains("ChecksumRequired"),
        "refused for the right reason: {}",
        dropped[0]
    );
    assert_eq!(
        node.router.counters.rx_error,
        rx_error_before + 1,
        "counted as rx_error, where the C's csp_route_security_check counts it"
    );

    // 3. A plain connection on the same node takes the same bare reply.
    let (_conn, req) = port_ping(&mut node, 0);
    let replies = c_node_serve(&req, csp_core::ports::PING);
    assert!(
        !Id::decode(VERSION, &replies[0][..HDR])
            .unwrap()
            .has_flag(flags::CRC32),
        "a plain request draws a plain echo"
    );
    let (delivered, dropped) = feed(&mut node, &replies[0]);
    assert_eq!(dropped, Vec::<String>::new());
    assert_eq!(
        delivered,
        vec![PING.to_vec()],
        "no policy on this connection, so it is delivered"
    );
}
