//! The flight topology again (`node_rdp_transit.rs`), with the loss on the **ground leg**:
//! a frame from the ground never reaches the router, and a reply the router hands towards
//! the ground is lost. The ground's timer repairs the first through the router; the C's
//! timer repairs the second, with the retransmission crossing the router a second time.
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
    /// Lose the n-th frame the router hands towards the ground (counted from 0).
    drop_to_ground: Option<usize>,
    ground_frames: usize,
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
        let mut back = core::mem::take(&mut links.to_ground);
        let mut kept = Vec::new();
        for f in back.drain(..) {
            let n = links.ground_frames;
            links.ground_frames += 1;
            if links.drop_to_ground == Some(n) {
                links.drop_to_ground = None;
                continue;
            }
            kept.push(f);
        }
        let back = kept;
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
fn a_transit_session_repairs_a_loss_on_the_ground_leg_in_both_directions() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert!(c_can_init(C_ADDR, NETMASK));
    assert!(c_can_route(CDH_KISS, NETMASK, CDH_CAN));
    assert_eq!(c_node_bind(PORT), 0);
    assert_eq!(c_hmac_set_key(SECRET), 0);
    let _ = c_can_drain();

    let cdh_storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut cdh: TestNode = Node::new(&cdh_storage, Config::new(VERSION).address(CDH_CAN));
    let can_if = cdh.ifaces.add("can", CDH_CAN, NETMASK, true).unwrap();
    let kiss_if = cdh.ifaces.add("kiss", CDH_KISS, NETMASK, false).unwrap();
    let mut pool = Pool::new();

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
        drop_to_ground: None,
        ground_frames: 0,
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
    assert!(ground.is_rdp_open(conn));
    let _ = c_node_read_held(PORT);

    // Uplink: the second packet's frame never reaches the router.
    let bodies: Vec<Vec<u8>> = (0..3u8)
        .map(|i| (0..60u8).map(|j| (i * 60 + j) ^ 0x3C).collect())
        .collect();
    let mut now = 1100u32;
    for (i, body) in bodies.iter().enumerate() {
        let mut p = ground.packet().expect("pool");
        p.set_payload(body).unwrap();
        match ground.send(conn, p, now).expect("send") {
            Outbound::Transmit { mut packet, .. } => {
                packet.prepend_header(VERSION).unwrap();
                let frame = packet.with_frame(|f| f.to_vec());
                drop(packet);
                if i != 1 {
                    let mut q = cdh.packet().expect("pool");
                    q.set_frame(VERSION, &frame).unwrap();
                    cdh.router.receive(q, kiss_if);
                }
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
        "the packet before the gap is readable"
    );
    now += 1001;
    ground.tick(now, u32::MAX);
    settle(&mut ground, &mut cdh, &mut pool, &mut links, now);
    assert_eq!(
        c_node_read_held(PORT),
        2,
        "the ground's retransmission crosses the router and fills the gap"
    );

    // Downlink: the router's first frame towards the ground is lost; the C's timer
    // retransmits and the copy crosses the router.
    links.drop_to_ground = Some(links.ground_frames);
    let mut got = Vec::new();
    for reply in [b"reply one".as_slice(), b"reply two".as_slice()] {
        let _ = c_node_send_on(PORT, reply);
        let frames = c_can_drain();
        assert!(!frames.is_empty());
        can_to_router(&mut cdh, &mut pool, &frames, now, can_if);
        got.extend(settle(&mut ground, &mut cdh, &mut pool, &mut links, now));
        now += 10;
    }
    assert!(links.drop_to_ground.is_none(), "the loss was applied");
    assert!(
        got.is_empty(),
        "nothing is readable behind the gap yet: {got:?}"
    );
    for _ in 0..6 {
        c_clock_advance(300);
        c_node_pump();
        let frames = c_can_drain();
        now += 300;
        can_to_router(&mut cdh, &mut pool, &frames, now, can_if);
        got.extend(settle(&mut ground, &mut cdh, &mut pool, &mut links, now));
        if got.len() == 2 {
            break;
        }
    }
    assert_eq!(
        got,
        vec![b"reply one".to_vec(), b"reply two".to_vec()],
        "the C's retransmission crosses the router and both replies arrive in order"
    );

    ground.close(conn, now).expect("close");
    settle(&mut ground, &mut cdh, &mut pool, &mut links, now);
    now += 20_001;
    ground.tick(now, u32::MAX);
    let _ = c_node_release(PORT);
    assert!(!ground.router.conns.is_live(conn));
    assert_eq!(ground.pool().available(), g_free);
    assert_eq!(cdh.pool().available(), cdh_free);
}
