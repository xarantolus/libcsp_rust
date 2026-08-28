//! What `csp_socket_close` does to a connection the application already holds.
//!
//! `csp_socket_close` (`csp_port.c:138`) unbinds the port and empties the socket's queue
//! of connections not yet accepted. It does **not** touch a connection the application has
//! accepted: that one stays open, and a packet for it is still delivered, because
//! `csp_route_deliver` finds the existing connection before it asks for a socket
//! (`csp_route.c:279-289`). Only new peers are refused.
//!
//! The port's `unbind` closed every server connection on the port, accepted or not.
//! Measured here on both sides.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const PEER: u16 = 30;
const PORT: u8 = 10;
const HDR: usize = 6;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn framed(dst: u16, sport: u8, payload: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: PEER,
        dst,
        dport: PORT,
        sport,
    };
    let mut v = vec![0u8; HDR + payload.len()];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(payload);
    v
}

#[test]
fn the_c_keeps_an_accepted_connection_across_socket_close() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert_eq!(c_node_bind(PORT), 0);
    let before = c_node_open_conns();

    // A peer opens a connection; the application accepts and holds it (`shim_node_send_on`
    // accepts on first use and keeps the connection).
    let first = c_node_exchange(&framed(C_ADDR, 40, b"first"), &[]);
    assert_eq!(first.delivered.len(), 0, "not read yet, only queued");
    assert_eq!(c_node_open_conns(), before + 1);
    let _ = c_node_send_on(PORT, b"taken");
    assert_eq!(c_node_open_conns(), before + 1, "accepted and held");

    assert_eq!(c_node_unbind(PORT), 0, "csp_socket_close");
    assert_eq!(
        c_node_open_conns(),
        before + 1,
        "the held connection survives the socket"
    );

    // A packet on that connection is still delivered to it...
    let more = c_node_exchange(&framed(C_ADDR, 40, b"more"), &[]);
    assert_eq!(more.tx.len(), 0);
    // ...which `send_on` shows by draining it before sending; a new peer is refused.
    let new_peer = c_node_exchange(&framed(C_ADDR, 41, b"new"), &[]);
    assert_eq!(new_peer.delivered.len(), 0);
    assert_eq!(
        c_node_open_conns(),
        before + 1,
        "no connection is created for a closed port"
    );
    let _ = c_node_release(PORT);
}

#[test]
fn the_port_keeps_an_accepted_connection_across_unbind() {
    let _g = lock();
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(PORT).unwrap();

    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(R_ADDR, 40, b"first")).unwrap();
    node.router.receive(p, 0);
    let mut accepted = None;
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => accepted = Some(conn),
            Routed::Idle => break,
            _ => continue,
        }
    }
    let conn = accepted.expect("delivered");
    assert!(node.accept().is_some(), "the application accepts it");
    let first = node.read(conn).unwrap().expect("first packet");
    first.with_payload(|d| assert_eq!(d, b"first"));
    drop(first);

    let closed = node.unbind(PORT);
    assert!(
        node.conn_is_active(conn),
        "csp_socket_close leaves an accepted connection alone; unbind closed {closed}"
    );

    // A packet on the held connection still arrives; a new peer is refused.
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(R_ADDR, 40, b"more")).unwrap();
    node.router.receive(p, 0);
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(R_ADDR, 41, b"new")).unwrap();
    node.router.receive(p, 0);
    let mut delivered = 0;
    let mut dropped = 0;
    loop {
        match node.work(0) {
            Routed::Delivered { .. } => delivered += 1,
            Routed::Dropped(_) => dropped += 1,
            Routed::Idle => break,
            _ => continue,
        }
    }
    assert_eq!(
        (delivered, dropped),
        (1, 1),
        "held connection served, new peer refused"
    );
    let more = node
        .read(conn)
        .unwrap()
        .expect("the packet on the held connection");
    more.with_payload(|d| assert_eq!(d, b"more"));
}
