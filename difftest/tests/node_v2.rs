//! The same node behaviours as `diff.rs`, on CSP **v2**.
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
/// In the egress subnet (`21 & 0x3FFC == 20`), and not an address either interface owns.
const FORWARD_DST: u16 = 21;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn framed(id: Id, payload: &[u8]) -> Vec<u8> {
    let hdr = 6; // v2
    let mut v = vec![0u8; hdr + payload.len()];
    id.encode(VERSION, &mut v).expect("id fits v2");
    v[hdr..].copy_from_slice(payload);
    v
}

/// Drive a Rust node through one frame and report only what is observable.
fn rust_exchange(frame: &[u8], bind_ports: &[u8], routes: &[(u16, u16, u8, u16)]) -> NodeOutcome {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces
        .add("INGRESS", NODE_ADDR, NETMASK, false)
        .unwrap();
    node.ifaces
        .add("EGRESS", EGRESS_ADDR, NETMASK, true)
        .unwrap();
    for &p in bind_ports {
        node.bind(p).unwrap();
    }
    for &(a, m, i, v) in routes {
        node.route_set(a, m, i, v).unwrap();
    }

    let mut out = NodeOutcome::default();
    let Some(mut p) = node.packet() else {
        return out;
    };
    if p.set_frame(VERSION, frame).is_err() {
        return out;
    }
    node.router.receive(p, 0);

    for _ in 0..64 {
        match node.work(0) {
            Routed::Idle => break,
            Routed::Forwarded { packet, .. } => {
                if let Some(mut fwd) = node.take_forwarded(packet) {
                    if fwd.prepend_header(VERSION).is_ok() {
                        out.tx.push(fwd.with_frame(|f| f.to_vec()));
                    }
                }
            }
            _ => {}
        }
    }

    while let Some(conn) = node.accept() {
        let Ok(info) = node.conn_info(conn) else {
            break;
        };
        while let Ok(Some(pkt)) = node.read(conn) {
            out.delivered.push(Delivered {
                port: info.dport,
                src: info.src,
                dst: info.dst,
                dport: info.dport,
                sport: info.sport,
                payload: pkt.with_payload(|d| d.to_vec()),
            });
        }
        let _ = node.close(conn);
    }
    out
}

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, NODE_ADDR, NETMASK, EGRESS_ADDR),
        "C node came up at v2"
    );
    assert_eq!(c_node_bind(10), 0, "bind port 10");
}

/// v2 addresses are 14 bits, so the values that matter are the ones a v1 header could not
/// have carried at all.
#[test]
fn a_packet_for_a_bound_port_reaches_the_application_identically() {
    let _g = LOCK.lock().unwrap();
    setup();

    let mut rng = Rng(0x2_0001);
    let mut compared = 0u32;
    let mut wide = 0u32;

    for _ in 0..200 {
        // Deliberately biased past 31, which is every address a v1 header can express.
        let src = (rng.next() % 16384) as u16;
        if src == NODE_ADDR || src == EGRESS_ADDR {
            continue;
        }
        if src > 31 {
            wide += 1;
        }
        let sport = (rng.next() % 64) as u8;
        let len = (rng.next() % 24) as usize;
        let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let id = Id {
            pri: 2,
            flags: 0,
            src,
            dst: NODE_ADDR,
            dport: 10,
            sport,
        };
        let frame = framed(id, &payload);

        let c = c_node_exchange(&frame, &[10]);
        let r = rust_exchange(&frame, &[10], &[]);

        assert_eq!(
            c.delivered.len(),
            r.delivered.len(),
            "delivery count differs for {id:?}\n  C {:?}\n  R {:?}",
            c.delivered,
            r.delivered
        );
        if let (Some(cd), Some(rd)) = (c.delivered.first(), r.delivered.first()) {
            assert_eq!(cd.payload, rd.payload, "payload for {id:?}");
            assert_eq!(
                (cd.src, cd.dport, cd.sport),
                (rd.src, rd.dport, rd.sport),
                "connection endpoints for {id:?}"
            );
            compared += 1;
        }
    }
    assert!(compared > 150, "only {compared} deliveries compared");
    assert!(
        wide > 100,
        "only {wide} sources exceeded 31 -- this would pass on v1 and prove nothing"
    );
}

#[test]
fn a_packet_for_an_unbound_port_is_delivered_to_nobody() {
    let _g = LOCK.lock().unwrap();
    setup();

    let id = Id {
        pri: 2,
        flags: 0,
        src: 4000,
        dst: NODE_ADDR,
        dport: 11,
        sport: 40,
    };
    let frame = framed(id, b"nobody is listening");

    let c = c_node_exchange(&frame, &[10, 11]);
    let r = rust_exchange(&frame, &[10], &[]);

    assert!(c.delivered.is_empty(), "C delivered {:?}", c.delivered);
    assert!(r.delivered.is_empty(), "Rust delivered {:?}", r.delivered);
}

#[test]
fn a_packet_for_another_node_is_forwarded_onto_the_wire() {
    let _g = LOCK.lock().unwrap();
    setup();

    let id = Id {
        pri: 2,
        flags: 0,
        src: 4000,
        dst: FORWARD_DST,
        dport: 10,
        sport: 40,
    };
    let frame = framed(id, b"please forward me");

    let c = c_node_exchange(&frame, &[10]);
    let r = rust_exchange(&frame, &[10], &[(FORWARD_DST, 14, 1, 0xFFFF)]);

    assert!(c.delivered.is_empty(), "not for us");
    assert!(r.delivered.is_empty());
    assert_eq!(c.tx.len(), 1, "the C forwards it");
    assert_eq!(r.tx.len(), 1, "the port must forward it too");
    assert_eq!(
        c.tx[0], r.tx[0],
        "the forwarded frame must be byte-identical"
    );
    assert_eq!(c.tx[0], frame, "and unchanged from what arrived");
}

#[test]
fn no_path_through_the_node_leaks_a_buffer() {
    let _g = LOCK.lock().unwrap();
    setup();

    let before = c_node_buf_free();
    let mut rng = Rng(0x2_0002);

    for _ in 0..400 {
        let dst = match rng.next() % 4 {
            0 => NODE_ADDR,
            1 => FORWARD_DST,
            2 => 9000, // no route, no interface subnet
            _ => NODE_ADDR,
        };
        let dport = if rng.next() % 4 == 3 { 11 } else { 10 };
        let id = Id {
            pri: 2,
            flags: 0,
            src: 4000,
            dst,
            dport,
            sport: 40,
        };
        let len = (rng.next() % 20) as usize;
        let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let _ = c_node_exchange(&framed(id, &payload), &[10]);
    }

    assert_eq!(
        c_node_buf_free(),
        before,
        "the C node leaked {} buffers over 400 v2 exchanges",
        before - c_node_buf_free()
    );
}
