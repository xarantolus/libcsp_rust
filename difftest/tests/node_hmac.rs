//! HMAC-authenticated traffic between the port and a real C node, both directions.
//!
//! The MAC itself was compared on random keys and messages (`diff.rs`), and the port's
//! router had its own tests for refusing a bad tag. What had never run was an **exchange**:
//! a C node with `csp_hmac_set_key`, the port with the same secret, a packet each way with
//! `CSP_O_HMAC`. That is where the CRC32 trailer defect lived — a flag set, verified by the
//! peer, and nothing behind it — and HMAC has the same two halves plus a key derivation
//! (`csp_hmac_set_key` stores SHA-1 of the material, `csp_hmac.c:115`) that both sides
//! must agree on, or every MAC fails with nothing to say why.

use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::security::opts;
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const HDR: usize = 6;
const SECRET: &[u8] = b"a shared secret, not a digest";
/// `CSP_O_HMAC` as the C's `csp_ping` takes it: `CSP_SO_HMACREQ`.
const O_HMAC: u8 = opts::HMAC_REQ as u8;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn fresh<'a>(storage: &'a CspStorage<8, 24, 300, 64, 8>) -> TestNode<'a> {
    let mut node: TestNode = Node::new(storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(csp_core::ports::PING).unwrap();
    node.set_hmac_key(SECRET);
    node
}

/// Serve one ping on the port; return the reply frames and what was delivered.
fn serve(node: &mut TestNode, request: &[u8]) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, Vec<String>) {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, request).expect("frame");
    node.router.receive(p, 0);
    let (mut replies, mut delivered, mut dropped) = (Vec::new(), Vec::new(), Vec::new());
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    delivered.push(pkt.with_payload(|d| d.to_vec()));
                    let mut reply = node.packet().expect("pool");
                    pkt.with_payload(|d| reply.set_payload(d).unwrap());
                    match node.reply_to(&pkt, reply) {
                        Ok(Outbound::Transmit { mut packet, .. }) => {
                            packet.prepend_header(VERSION).unwrap();
                            replies.push(packet.with_frame(|f| f.to_vec()));
                        }
                        other => panic!("{other:?}"),
                    }
                    drop(pkt);
                }
            }
            Routed::Dropped(r) => dropped.push(format!("{r:?}")),
            Routed::Idle => break,
            _ => continue,
        }
    }
    (replies, delivered, dropped)
}

#[test]
fn a_c_client_pings_the_port_with_hmac_and_reads_the_echo() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert_eq!(c_hmac_set_key(SECRET), 0, "csp_hmac_set_key");

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    node.router.endpoint_opts = opts::HMAC_REQ;

    // libcsp's own csp_ping with CSP_O_HMAC: the request carries a MAC, and the client
    // verifies the echo byte by byte.
    let req = c_service_start(
        CService::Ping {
            size: 8,
            opts: O_HMAC,
        },
        R_ADDR,
    );
    assert_eq!(req.len(), 1);
    assert!(
        Id::decode(VERSION, &req[0][..HDR])
            .unwrap()
            .has_flag(csp_core::flags::HMAC),
        "the request is flagged"
    );
    let (replies, delivered, dropped) = serve(&mut node, &req[0]);
    assert_eq!(
        dropped,
        Vec::<String>::new(),
        "the port verifies the C's MAC with the same derived key"
    );
    assert_eq!(delivered.len(), 1);
    assert_eq!(
        delivered[0].len(),
        8,
        "the MAC was stripped before delivery"
    );
    assert_eq!(replies.len(), 1);
    c_node_exchange(&replies[0], &[]);
    let (status, _) = c_service_join();
    assert!(
        status >= 0,
        "csp_ping must accept the port's echo: the reply carries a MAC the C verifies; \
         status {status}"
    );
}

#[test]
fn the_port_pings_the_c_with_hmac_and_reads_the_echo() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert_eq!(c_hmac_set_key(SECRET), 0);
    assert_eq!(c_node_bind(csp_core::ports::PING), 0);

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    let conn = node
        .connect(2, C_ADDR, csp_core::ports::PING, opts::HMAC_REQ, 0)
        .expect("connect");
    let mut p = node.packet().expect("pool");
    p.set_payload(b"authentic").unwrap();
    let frame = match node.send(conn, p, 0).expect("send") {
        Outbound::Transmit { mut packet, .. } => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("{other:?}"),
    };
    let replies = c_node_serve(&frame, csp_core::ports::PING);
    assert_eq!(
        replies.len(),
        1,
        "the C verified the port's MAC and answered; nothing means csp_hmac_verify refused it"
    );
    assert!(
        Id::decode(VERSION, &replies[0][..HDR])
            .unwrap()
            .has_flag(csp_core::flags::HMAC),
        "csp_sendto_reply(CSP_O_SAME) keeps the flag and send_direct appends the MAC"
    );
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &replies[0]).unwrap();
    node.router.receive(p, 0);
    let mut got = Vec::new();
    loop {
        match node.work(1) {
            Routed::Delivered { conn: c, .. } => {
                while let Ok(Some(pkt)) = node.read(c) {
                    got.push(pkt.with_payload(|d| d.to_vec()));
                    drop(pkt);
                }
            }
            Routed::Dropped(r) => panic!("the port refused the C's authenticated echo: {r:?}"),
            Routed::Idle => break,
            _ => continue,
        }
    }
    assert_eq!(got, vec![b"authentic".to_vec()], "verified and stripped");
}

#[test]
fn a_different_secret_is_refused_by_both() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert_eq!(c_node_bind(csp_core::ports::PING), 0);
    assert_eq!(c_hmac_set_key(b"the other secret"), 0);

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    node.router.endpoint_opts = opts::HMAC_REQ;

    // Port -> C: the C's csp_hmac_verify fails, the router drops it, nothing comes back.
    let conn = node
        .connect(2, C_ADDR, csp_core::ports::PING, opts::HMAC_REQ, 0)
        .expect("connect");
    let mut p = node.packet().expect("pool");
    p.set_payload(b"forged").unwrap();
    let frame = match node.send(conn, p, 0).expect("send") {
        Outbound::Transmit { mut packet, .. } => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("{other:?}"),
    };
    assert_eq!(
        c_node_serve(&frame, csp_core::ports::PING).len(),
        0,
        "the C answers nothing"
    );

    // C -> port: the same, and it is counted where IF_STATS reports it.
    let req = c_service_start(
        CService::Ping {
            size: 4,
            opts: O_HMAC,
        },
        R_ADDR,
    );
    let (replies, delivered, dropped) = serve(&mut node, &req[0]);
    assert_eq!(
        replies.len() + delivered.len(),
        0,
        "the port answers nothing"
    );
    assert_eq!(dropped.len(), 1);
    assert!(dropped[0].contains("BadAuthentication"), "{}", dropped[0]);
    assert_eq!(node.router.counters.auth_error, 1);
    let _ = c_service_join();
}
