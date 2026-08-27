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

use csp::node::Outbound;
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
/// A third subnet, so a route can point somewhere local-subnet would not choose.
const THIRD_ADDR: u16 = 40;

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
    node.ifaces
        .add("ROUTED", THIRD_ADDR, NETMASK, false)
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
            Routed::Forwarded { iface, via, packet } => {
                if let Some(mut fwd) = node.take_forwarded(packet) {
                    if fwd.prepend_header(VERSION).is_ok() {
                        out.tx.push(fwd.with_frame(|f| f.to_vec()));
                        let name = node
                            .ifaces
                            .get(iface)
                            .map(|e| e.name.to_string())
                            .unwrap_or_else(|| format!("?{iface}"));
                        out.tx_via.push((name, via));
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
        c_node_init(VERSION, NODE_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );
    assert_eq!(c_node_bind(10), 0, "bind port 10");
}

/// v2 addresses are 14 bits, so the values that matter are the ones a v1 header could not
/// have carried at all.
#[test]
fn a_packet_for_a_bound_port_reaches_the_application_identically() {
    let _g = lock();
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
    let _g = lock();
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
    let _g = lock();
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
    assert_eq!(
        r.tx_via[0].0, c.tx_via[0].0,
        "and must leave by the same interface -- the bytes are identical whichever link \
         it goes out of, so comparing only the frame proves nothing about routing"
    );
}

#[test]
fn no_path_through_the_node_leaks_a_buffer() {
    let _g = lock();
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

    // --- and the port, over the same spread ---
    //
    // The half above asserts a property of libcsp. Named for "the node", it read as though
    // it covered both, and it was the whole of "buffer accounting at node level" for v2.
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    node.ifaces
        .add("INGRESS", NODE_ADDR, NETMASK, false)
        .unwrap();
    node.ifaces
        .add("EGRESS", EGRESS_ADDR, NETMASK, true)
        .unwrap();
    node.bind(10).unwrap();

    let free_before = node.buffers_free();
    let mut rng = Rng(0x2_0002);
    let (mut delivered, mut forwarded, mut dropped) = (0u32, 0u32, 0u32);

    for _ in 0..400 {
        let dst = match rng.next() % 4 {
            0 => NODE_ADDR,
            1 => FORWARD_DST,
            2 => 9000,
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

        let Some(mut p) = node.packet() else {
            panic!("the pool was empty after {delivered}/{forwarded}/{dropped}");
        };
        p.set_frame(VERSION, &framed(id, &payload)).unwrap();
        node.router.receive(p, 0);

        loop {
            match node.work(0) {
                Routed::Delivered { conn, .. } => {
                    delivered += 1;
                    while let Ok(Some(pkt)) = node.read(conn) {
                        drop(pkt);
                    }
                    let _ = node.close(conn);
                }
                Routed::Forwarded { packet, .. } => {
                    forwarded += 1;
                    drop(node.take_forwarded(packet));
                }
                Routed::Dropped(_) => dropped += 1,
                Routed::Idle => break,
                _ => continue,
            }
        }
    }

    assert_eq!(
        node.buffers_free(),
        free_before,
        "the port leaked {} buffers over 400 v2 exchanges",
        free_before - node.buffers_free()
    );
    // Each outcome must have been reached, or "no leak" is a claim about paths never taken.
    assert!(delivered > 0, "nothing was delivered");
    assert!(forwarded > 0, "nothing was forwarded");
    assert!(dropped > 0, "nothing was dropped");
}

/// The local-subnet-beats-routing-table precedence, on v2.
///
/// The v1 version of this is in `diff.rs`. Repeated here because the precedence depends on
/// subnet arithmetic and subnet arithmetic depends on host bits, which is the one thing
/// that differs between the versions — 5 bits against 14.
#[test]
fn a_local_subnet_beats_the_routing_table() {
    let _g = lock();
    setup();

    // FORWARD_DST is in EGRESS's subnet; point the routing table at ROUTED instead.
    assert_eq!(
        c_node_route(FORWARD_DST, 14, 2, 0xFFFF),
        0,
        "route installed"
    );

    let id = Id {
        pri: 2,
        flags: 0,
        src: 4000,
        dst: FORWARD_DST,
        dport: 10,
        sport: 40,
    };
    let frame = framed(id, b"which interface?");

    let c = c_node_exchange(&frame, &[10]);
    assert_eq!(c.tx.len(), 1);
    assert_eq!(
        c.tx_via[0].0, "EGRESS",
        "the C ignores the routing table when a local interface owns the subnet"
    );

    let r = rust_exchange(&frame, &[10], &[(FORWARD_DST, 14, 2, 0xFFFF)]);
    assert_eq!(r.tx.len(), 1);
    assert_eq!(c.tx[0], r.tx[0], "byte-identical");
    assert_eq!(r.tx_via[0].0, c.tx_via[0].0, "and the same interface");
}

/// The `is_to_me` conditions on v2, where the address space is 14 bits rather than 5.
///
/// Both parts are subnet arithmetic, which is the thing that differs between the versions,
/// so the v1 checks in `diff.rs` do not cover this.
#[test]
fn any_interface_address_and_both_broadcast_forms_are_ours() {
    let _g = lock();
    setup();

    // 1. The other interface's own address.
    let id = Id {
        pri: 2,
        flags: 0,
        src: 4000,
        dst: EGRESS_ADDR,
        dport: 10,
        sport: 40,
    };
    let c = c_node_exchange(&framed(id, b"for our other interface"), &[10]);
    let r = rust_exchange(&framed(id, b"for our other interface"), &[10], &[]);
    assert_eq!(c.delivered.len(), 1, "the C delivers it locally");
    assert_eq!(
        r.delivered.len(),
        1,
        "the port must too -- it sent {} frame(s) out",
        r.tx.len()
    );

    // 2. INGRESS is 9/12 of 14 host bits, so its subnet is 8..11 and its broadcast is 11.
    //    And the global broadcast is max_node_id() = 16383.
    for (dst, what) in [
        (11u16, "the ingress subnet broadcast"),
        (16383, "the global broadcast"),
    ] {
        let id = Id {
            pri: 2,
            flags: 0,
            src: 4000,
            dst,
            dport: 10,
            sport: 40,
        };
        let frame = framed(id, b"broadcast");
        let c = c_node_exchange(&frame, &[10]);
        let r = rust_exchange(&frame, &[10], &[]);
        assert_eq!(c.delivered.len(), 1, "the C delivers {what} (dst {dst})");
        assert_eq!(
            r.delivered.len(),
            1,
            "the port must deliver {what} (dst {dst}) -- it sent {} frame(s) out",
            r.tx.len()
        );
    }
}

/// The port as a **client**, against a real C node that answers.
///
/// Every other node-level test here drives the server direction: a frame goes in, and a
/// delivery or a forward comes out. None of them had a C node reply to something the port
/// had sent — which is exactly how the port shipped with `deliver_local` refusing every
/// reply to every connection it opened, because a reply arrives on the ephemeral source
/// port `connect` chose and nothing binds that.
///
/// The reply here is produced by libcsp itself: `csp_service_handler` echoes a `CSP_PING`
/// and `csp_sendto_reply` puts it on the wire. Nothing in the harness composes it.
#[test]
fn a_reply_from_a_real_c_node_reaches_the_connection_that_asked() {
    const CSP_PING: u8 = 1;

    let _g = lock();
    setup();
    assert_eq!(c_node_bind(CSP_PING), 0, "bind the ping service");

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();

    // The port opens the connection and sends the request.
    let conn = node
        .connect(2, NODE_ADDR, CSP_PING, 0, 1000)
        .expect("connect to the C node");
    let mut req = node.packet().expect("pool");
    req.set_payload(b"round-trip").unwrap();
    let out = node.send(conn, req, 1000).expect("send");
    // `send` decides where the packet goes; it does not frame it. The header is prepended
    // by whoever transmits, so a test that skipped this read an empty frame and blamed the
    // C node for not answering.
    let (iface, mut pkt) = match out {
        Outbound::Transmit { iface, packet, .. } => (iface, packet),
        other => panic!("the C node is on our own subnet, so this must route: {other:?}"),
    };
    let _ = iface;
    pkt.prepend_header(VERSION).expect("prepend");
    let request_frame = pkt.with_frame(|f| f.to_vec());

    // A real C node receives it, its service handler answers, and the reply is whatever
    // libcsp put on the wire.
    let replies = c_node_serve(&request_frame, CSP_PING);
    assert_eq!(
        replies.len(),
        1,
        "the C node answers a ping with exactly one frame"
    );

    // Feed that reply back and read it off the connection the port opened.
    let mut inject = node.packet().expect("pool");
    inject
        .set_frame(VERSION, &replies[0])
        .expect("the C's own frame");
    node.router.receive(inject, 0);

    let mut got = Vec::new();
    loop {
        match node.work(1100) {
            Routed::Delivered { conn: c, .. } => {
                while let Ok(Some(p)) = node.read(c) {
                    got.push(p.with_payload(|d| d.to_vec()));
                    drop(p);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }

    assert_eq!(
        got.len(),
        1,
        "the reply must reach the connection that asked for it"
    );
    assert_eq!(
        got[0], b"round-trip",
        "a ping is echoed verbatim, so the body must come back unchanged"
    );
}

/// The CMP client against a real C CMP server.
///
/// `client::cmp_request` builds the request and `client::check_cmp_reply` validates the
/// answer, and until `c_node_serve` existed neither had ever seen a reply libcsp actually
/// produced — both halves were only ever tested against bytes this repository composed.
/// `csp_cmp_handler` is what answers here.
#[test]
fn the_cmp_client_understands_what_a_real_c_node_answers() {
    use csp_core::cmp;

    const CSP_CMP: u8 = 0;

    let _g = lock();
    setup();
    assert_eq!(c_node_bind(CSP_CMP), 0, "bind the CMP service");

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();

    let conn = node
        .connect(2, NODE_ADDR, CSP_CMP, 0, 1000)
        .expect("connect to the C node");

    let mut body = [0u8; 128];
    let n = csp::client::cmp_request(cmp::code::IDENT, &[], &mut body).expect("build IDENT");

    let mut req = node.packet().expect("pool");
    req.set_payload(&body[..n]).unwrap();
    let out = node.send(conn, req, 1000).expect("send");
    let mut pkt = match out {
        Outbound::Transmit { packet, .. } => packet,
        other => panic!("must route: {other:?}"),
    };
    pkt.prepend_header(VERSION).expect("prepend");
    let request_frame = pkt.with_frame(|f| f.to_vec());

    let replies = c_node_serve(&request_frame, CSP_CMP);
    assert_eq!(replies.len(), 1, "the C node answers an IDENT");

    let mut inject = node.packet().expect("pool");
    inject
        .set_frame(VERSION, &replies[0])
        .expect("the C's frame");
    node.router.receive(inject, 0);

    let mut got = Vec::new();
    loop {
        match node.work(1100) {
            Routed::Delivered { conn: c, .. } => {
                while let Ok(Some(p)) = node.read(c) {
                    got.push(p.with_payload(|d| d.to_vec()));
                    drop(p);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    assert_eq!(got.len(), 1, "the IDENT reply reaches the connection");

    // The client's own validator, on bytes libcsp produced rather than bytes we wrote.
    let hdr = csp::client::check_cmp_reply(cmp::code::IDENT, &got[0])
        .expect("the client accepts a real C node's IDENT reply");
    assert_eq!(hdr.code, cmp::code::IDENT);

    // And the fields line up with the C's `struct csp_cmp_ident_msg`. `Ident::decode`
    // takes the whole message, header included -- `Ident::LEN` counts those two bytes.
    let parsed = cmp::Ident::decode(&got[0]).expect("the reply parses as an IDENT");
    assert_eq!(
        got[0].len(),
        cmp::Ident::LEN,
        "the C's reply is exactly sizeof(struct csp_cmp_ident_msg)"
    );
    // The shim node sets no hostname, so the identity strings are empty -- but `date` and
    // `time` come from __DATE__/__TIME__ and are always populated. They are the last two
    // fields, so reading them proves every preceding field width matches the C's struct:
    // one byte of drift anywhere earlier and these would be garbage.
    assert!(
        parsed.date.len() >= 6 && parsed.time.contains(':'),
        "date {:?} / time {:?} came out misaligned, so a field width disagrees with the C",
        parsed.date,
        parsed.time
    );
}
