//! The flight topology: a ground node, the port as the CDH router in the middle, and a
//! real C peer on the CAN bus — an RDP session with HMAC and CRC32 *in transit* through
//! the router, with CAN frames lost and swapped on the far leg.
//!
//! The router holds no key and must not need one: a C router forwards a packet for another
//! node untouched, trailers and all (`csp_route_work` checks security only for packets it
//! delivers to itself). The two endpoints run the port's node code on one side and libcsp on
//! the other; the packet passes through `Router::forward` between them.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::security::opts;
use csp_core::{cfp, Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
/// The C, on the bus: 9 in 8..=11.
const C_ADDR: u16 = 9;
/// The router's bus side, 10, and its ground side, 16 in 16..=19.
const CDH_CAN: u16 = 10;
const CDH_KISS: u16 = 16;
/// The ground station, beyond the bus subnet.
const GROUND: u16 = 17;
const NETMASK: u16 = 12;
const PORT: u8 = 10;
const HDR: usize = 6;
const SECRET: &[u8] = b"a shared secret for the bus";

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;
type Pool = cfp::Pbufs<cfp::V2Reassembler, 4>;

fn fragment(id: Id, payload: &[u8], sc: &mut u32) -> Vec<CanFrame> {
    let frames = cfp::V2Fragmenter::new(id, CDH_CAN, *sc, payload)
        .map(|f| (f.id, f.data().to_vec()))
        .collect();
    *sc += 1;
    frames
}

fn to_c(frames: &[CanFrame]) -> Vec<CanFrame> {
    for f in frames {
        let _ = c_can_rx(f);
    }
    c_clock_advance(300);
    c_node_pump();
    c_can_drain()
}

/// The router's CAN driver: reassemble the C's frames and hand each packet to the router.
fn can_to_router(cdh: &mut TestNode, pool: &mut Pool, frames: &[CanFrame], now: u32, can_if: u8) {
    let mut buf = [0u8; 512];
    pool.expire(now, 1000);
    for (id, data) in frames {
        let key = *id & cfp::V2_CONN_MASK;
        let Some(re) = pool.get_or_create(key, now) else {
            continue;
        };
        match re.push(*id, data, &mut buf) {
            Ok(Some((hdr, n))) => {
                pool.release(key);
                let mut v = vec![0u8; HDR + n];
                hdr.encode(VERSION, &mut v).unwrap();
                v[HDR..].copy_from_slice(&buf[..n]);
                let mut p = cdh.packet().expect("pool");
                p.set_frame(VERSION, &v).unwrap();
                cdh.router.receive(p, can_if);
            }
            Ok(None) => {}
            Err(_) => pool.release(key),
        }
    }
}

struct Links {
    can_if: u8,
    kiss_if: u8,
    sc: u32,
    /// Damage to apply to the next packets the router puts on CAN: index -> lose or swap.
    damage: Vec<(usize, bool)>,
    can_packets: usize,
    to_ground: Vec<Vec<u8>>,
}

/// Run the router: whatever it forwards goes to the bus (as CAN frames, through the C) or
/// to the ground (as frames handed to the ground node).
fn run_router(cdh: &mut TestNode, pool: &mut Pool, links: &mut Links, now: u32) {
    loop {
        match cdh.work(now) {
            Routed::Forwarded { iface, packet, .. } => {
                let p = cdh.take_forwarded(packet).expect("slot");
                if iface == links.can_if {
                    let id = p.id();
                    let payload = p.with_payload(|d| d.to_vec());
                    drop(p);
                    let mut frames = fragment(id, &payload, &mut links.sc);
                    let n = links.can_packets;
                    links.can_packets += 1;
                    if let Some(&(_, lose)) = links.damage.iter().find(|(i, _)| *i == n) {
                        if lose {
                            frames.remove(frames.len() / 2);
                        } else {
                            frames.swap(1, 2);
                        }
                    }
                    let back = to_c(&frames);
                    can_to_router(cdh, pool, &back, now, links.can_if);
                } else {
                    let mut p = p;
                    p.prepend_header(VERSION).unwrap();
                    links.to_ground.push(p.with_frame(|f| f.to_vec()));
                }
            }
            Routed::Idle => break,
            other => panic!("the router must only forward: {other:?}"),
        }
    }
}

/// Everything the ground node wants on the wire goes into the router; everything the
/// router sends back is received by the ground; until both are quiet.
fn settle(
    ground: &mut TestNode,
    cdh: &mut TestNode,
    pool: &mut Pool,
    links: &mut Links,
    now: u32,
) -> Vec<Vec<u8>> {
    let mut delivered = Vec::new();
    for _ in 0..12 {
        let mut sent = 0;
        loop {
            match ground.work(now) {
                Routed::Respond { packet, .. } => {
                    let mut p = ground.take_forwarded(packet).expect("slot");
                    p.prepend_header(VERSION).unwrap();
                    let frame = p.with_frame(|f| f.to_vec());
                    drop(p);
                    let mut q = cdh.packet().expect("pool");
                    q.set_frame(VERSION, &frame).unwrap();
                    cdh.router.receive(q, links.kiss_if);
                    sent += 1;
                }
                Routed::Delivered { conn, .. } => {
                    while let Ok(Some(pkt)) = ground.read(conn) {
                        delivered.push(pkt.with_payload(|d| d.to_vec()));
                        drop(pkt);
                    }
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
        run_router(cdh, pool, links, now);
        let back = core::mem::take(&mut links.to_ground);
        for f in &back {
            let mut p = ground.packet().expect("pool");
            p.set_frame(VERSION, f).unwrap();
            ground.router.receive(p, 0);
        }
        if sent == 0 && back.is_empty() {
            break;
        }
    }
    delivered
}

#[test]
fn a_protected_rdp_session_transits_the_router_untouched_and_survives_can_loss() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert!(c_can_init(C_ADDR, NETMASK));
    assert!(
        c_can_route(CDH_KISS, NETMASK, CDH_CAN),
        "the C reaches the ground via CDH"
    );
    assert_eq!(c_node_bind(PORT), 0);
    assert_eq!(c_hmac_set_key(SECRET), 0);
    let _ = c_can_drain();

    // The router: two interfaces, no application, no key.
    let cdh_storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut cdh: TestNode = Node::new(&cdh_storage, Config::new(VERSION).address(CDH_CAN));
    let can_if = cdh.ifaces.add("can", CDH_CAN, NETMASK, true).unwrap();
    let kiss_if = cdh.ifaces.add("kiss", CDH_KISS, NETMASK, false).unwrap();
    let mut pool = Pool::new();

    // The ground station: one link, the router is its default route.
    let g_storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut ground: TestNode = Node::new(&g_storage, Config::new(VERSION).address(GROUND));
    ground.ifaces.add("kiss", GROUND, NETMASK, true).unwrap();
    ground.set_hmac_key(SECRET);

    let mut links = Links {
        can_if,
        kiss_if,
        sc: 0,
        damage: Vec::new(),
        can_packets: 0,
        to_ground: Vec::new(),
    };
    let g_free = ground.pool().available();
    let cdh_free = cdh.pool().available();

    let conn = ground
        .connect(
            2,
            C_ADDR,
            PORT,
            opts::RDP_REQ | opts::CRC32_REQ | opts::HMAC_REQ,
            1000,
        )
        .expect("connect");
    settle(&mut ground, &mut cdh, &mut pool, &mut links, 1000);
    assert!(
        ground.is_rdp_open(conn),
        "the handshake completes through a router that holds no key"
    );
    let _ = c_node_read_held(PORT);
    let handshake_packets = links.can_packets;

    // Three packets; the second loses a CAN frame on the bus leg, the third has two swapped.
    links.damage = vec![
        (handshake_packets + 1, true),
        (handshake_packets + 2, false),
    ];
    let bodies: Vec<Vec<u8>> = (0..3u8)
        .map(|i| (0..60u8).map(|j| (i * 60 + j) ^ 0x5A).collect())
        .collect();
    let mut now = 1100u32;
    for body in &bodies {
        let mut p = ground.packet().expect("pool");
        p.set_payload(body).unwrap();
        match ground.send(conn, p, now).expect("send") {
            Outbound::Transmit { mut packet, .. } => {
                packet.prepend_header(VERSION).unwrap();
                let frame = packet.with_frame(|f| f.to_vec());
                drop(packet);
                let mut q = cdh.packet().expect("pool");
                q.set_frame(VERSION, &frame).unwrap();
                cdh.router.receive(q, kiss_if);
            }
            other => panic!("{other:?}"),
        }
        run_router(&mut cdh, &mut pool, &mut links, now);
        settle(&mut ground, &mut cdh, &mut pool, &mut links, now);
        now += 10;
    }
    assert_eq!(
        c_node_read_held(PORT),
        1,
        "only the intact packet has arrived"
    );

    // The ground's timer repairs the other two; the router forwards the retransmissions.
    now += 1001;
    ground.tick(now, u32::MAX);
    settle(&mut ground, &mut cdh, &mut pool, &mut links, now);
    assert_eq!(
        c_node_read_held(PORT),
        2,
        "both damaged packets arrive by retransmission"
    );

    // The C answers; the replies transit the router the other way.
    let mut got = Vec::new();
    for reply in [b"reply one".as_slice(), b"reply two".as_slice()] {
        let _ = c_node_send_on(PORT, reply);
        let frames = c_can_drain();
        assert!(
            !frames.is_empty(),
            "the C's reply leaves over CAN towards the router"
        );
        can_to_router(&mut cdh, &mut pool, &frames, now, can_if);
        got.extend(settle(&mut ground, &mut cdh, &mut pool, &mut links, now));
        now += 10;
    }
    assert_eq!(got, vec![b"reply one".to_vec(), b"reply two".to_vec()]);

    // Close from the ground; the C answers through the router.
    ground.close(conn, now).expect("close");
    settle(&mut ground, &mut cdh, &mut pool, &mut links, now);
    now += 20_001;
    ground.tick(now, u32::MAX);
    let _ = c_node_release(PORT);
    assert!(!ground.router.conns.is_live(conn), "the close completes");
    assert_eq!(
        ground.pool().available(),
        g_free,
        "the ground holds nothing"
    );
    assert_eq!(cdh.pool().available(), cdh_free, "the router holds nothing");
}
