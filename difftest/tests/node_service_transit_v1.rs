//! Service requests along the flight path under **CSP v1** (the flown wire format): the
//! ground station asks the C peer on the bus for a ping and its identity, through the port
//! as router, with CRC32 on the request. The v1 counterpart of `node_service_transit.rs`, on
//! the shared `harness::CanLink<V1>`.
//!
//! `node_rdp_transit.rs` carries a connection through the router; this carries the two
//! requests every ground pass starts with. The reply is served by the C's own
//! `csp_service_handler` and comes back through the router to the ground node's client
//! helpers, which check it the way `csp_ping` / `csp_cmp_ident` would.

use csp::node::Outbound;
use csp::{client, Config, CspStorage, Node, Routed};
use csp_core::security::opts;
use csp_core::{cmp, ports, Version};
use difftest::harness::{CanLink, V1};
use difftest::*;

const VERSION: Version = Version::V1;
const C_ADDR: u16 = 9;
const CDH_CAN: u16 = 10;
const CDH_KISS: u16 = 17;
const GROUND: u16 = 18;
const NETMASK: u16 = 2;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;
/// One request: ground → router → CAN → C, served; reply: C → CAN → router → ground.
/// Returns what the ground node's connection received.
#[allow(clippy::too_many_arguments)]
fn ask(
    ground: &mut TestNode,
    cdh: &mut TestNode,
    link: &mut CanLink<V1>,
    (can_if, kiss_if): (u8, u8),
    conn: csp::conn::Handle,
    body: &[u8],
    service_port: u8,
    now: u32,
) -> Vec<u8> {
    let mut p = ground.packet().expect("pool");
    p.set_payload(body).unwrap();
    let frame = match ground.send(conn, p, now).expect("send") {
        Outbound::Transmit { mut packet, .. } => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("{other:?}"),
    };
    let mut q = cdh.packet().expect("pool");
    q.set_frame(VERSION, &frame).unwrap();
    cdh.router.receive(q, kiss_if);
    let Routed::Forwarded { iface, packet, .. } = cdh.work(now) else {
        panic!("the router forwards the request");
    };
    assert_eq!(iface, can_if, "towards the bus");
    let p = cdh.take_forwarded(packet).expect("slot");
    let (id, payload) = (p.id(), p.with_payload(|d| d.to_vec()));
    drop(p);
    for f in link.fragment(id, &payload) {
        let _ = c_can_rx(&f);
    }
    assert_eq!(
        c_node_serve_pending(service_port),
        1,
        "the C serves exactly one request"
    );
    let back = c_can_drain();
    assert!(!back.is_empty(), "the reply leaves over CAN");
    link.deliver(cdh, &back, can_if, now);
    let Routed::Forwarded { iface, packet, .. } = cdh.work(now) else {
        panic!("the router forwards the reply");
    };
    assert_eq!(iface, kiss_if, "towards the ground");
    let mut p = cdh.take_forwarded(packet).expect("slot");
    p.prepend_header(VERSION).unwrap();
    let frame = p.with_frame(|f| f.to_vec());
    drop(p);
    assert!(matches!(cdh.work(now), Routed::Idle));
    let mut r = ground.packet().expect("pool");
    r.set_frame(VERSION, &frame).unwrap();
    ground.router.receive(r, 0);
    let mut reply = Vec::new();
    loop {
        match ground.work(now) {
            Routed::Delivered { conn: c, .. } => {
                assert_eq!(c, conn, "the reply lands on the asking connection");
                while let Ok(Some(pkt)) = ground.read(c) {
                    reply = pkt.with_payload(|d| d.to_vec());
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            other => panic!("{other:?}"),
        }
    }
    reply
}

#[test]
fn ping_and_ident_reach_the_v1_bus_peer_through_the_router_and_come_back() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 4, 28));
    assert!(c_can_init(C_ADDR, NETMASK));
    assert!(c_can_route(GROUND, NETMASK, CDH_CAN));
    assert_eq!(c_node_bind(ports::PING), 0);
    assert_eq!(c_node_bind(ports::CMP), 0);
    let _ = c_can_drain();

    let cdh_storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut cdh: TestNode = Node::new(&cdh_storage, Config::new(VERSION).address(CDH_CAN));
    let can_if = cdh.ifaces.add("can", CDH_CAN, NETMASK, true).unwrap();
    let kiss_if = cdh.ifaces.add("kiss", CDH_KISS, NETMASK, false).unwrap();
    let mut link: CanLink<V1> = CanLink::new(CDH_CAN);

    let g_storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut ground: TestNode = Node::new(&g_storage, Config::new(VERSION).address(GROUND));
    ground.ifaces.add("kiss", GROUND, NETMASK, true).unwrap();
    let g_free = ground.pool().available();
    let cdh_free = cdh.pool().available();

    // Ping, with a payload the C must echo byte for byte.
    let payload: Vec<u8> = (0..100u8).collect();
    let conn = ground
        .connect(2, C_ADDR, ports::PING, opts::CRC32_REQ, 1000)
        .expect("connect");
    let reply = ask(
        &mut ground,
        &mut cdh,
        &mut link,
        (can_if, kiss_if),
        conn,
        &payload,
        ports::PING,
        1000,
    );
    client::check_ping(&payload, &reply).expect("the C echoes the ping through the router");
    ground.close(conn, 1000).expect("close");

    // Identity.
    let conn = ground
        .connect(2, C_ADDR, ports::CMP, opts::CRC32_REQ, 1100)
        .expect("connect");
    let mut req = [0u8; 128];
    let n = client::cmp_request(cmp::code::IDENT, &[], &mut req).expect("request");
    let reply = ask(
        &mut ground,
        &mut cdh,
        &mut link,
        (can_if, kiss_if),
        conn,
        &req[..n],
        ports::CMP,
        1100,
    );
    let h = client::check_cmp_reply(cmp::code::IDENT, &reply).expect("an IDENT reply");
    let ident = cmp::Ident::decode(&reply).expect("a decodable ident");
    assert!(h.is_reply());
    assert_eq!(
        reply.len(),
        cmp::Ident::LEN,
        "sizeof(struct csp_cmp_ident_msg), intact"
    );
    // The shim sets no hostname; `date`/`time` are __DATE__/__TIME__ and always present.
    assert!(
        !ident.date.is_empty() && !ident.time.is_empty(),
        "the C's build stamp"
    );
    ground.close(conn, 1100).expect("close");

    assert_eq!(ground.pool().available(), g_free);
    assert_eq!(cdh.pool().available(), cdh_free);
}
