//! A file transfer the way a flight node does one: SFP over RDP with HMAC and CRC32,
//! over CAN, against a real C peer, in both directions, with CAN frames lost and swapped
//! on the way.
//!
//! `node_rdp_over_can.rs` pins the session; `node_sfp_rdp*.rs` pin the two trailers on a
//! clean wire. This puts the stream *inside* the session: a fragment that is retransmitted
//! must carry its SFP trailer, its RDP trailer, its HMAC and its CRC, in that order, and
//! the reassembler at the far end must see the fragments in order after the repair.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::security::opts;
use csp_core::{cfp, Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const PORT: u8 = 10;
const HDR: usize = 6;
/// Fragment budget: three fragments fit the C's default RDP window of four, so a
/// `csp_sfp_send` on the C never blocks on a window it has no router thread to open.
const MTU: usize = 100;
const SECRET: &[u8] = b"a shared secret for the bus";

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;
type Pool = cfp::Pbufs<cfp::V2Reassembler, 4>;

fn message(seed: u8) -> Vec<u8> {
    (0..290u16)
        .map(|i| (i as u8).wrapping_mul(7) ^ seed)
        .collect()
}

fn fragment(id: Id, payload: &[u8], sc: &mut u32) -> Vec<CanFrame> {
    let frames = cfp::V2Fragmenter::new(id, R_ADDR, *sc, payload)
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

fn from_c(node: &mut TestNode, pool: &mut Pool, frames: &[CanFrame], now: u32) {
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
                let mut p = node.packet().expect("pool");
                p.set_frame(VERSION, &v).unwrap();
                node.router.receive(p, 0);
            }
            Ok(None) => {}
            Err(_) => pool.release(key),
        }
    }
}

/// The port's pending frames, fragmented. Deliveries stay on the connection: the stream
/// reader below takes them off in order.
fn drain(node: &mut TestNode, now: u32, sc: &mut u32) -> Vec<CanFrame> {
    let mut frames = Vec::new();
    loop {
        match node.work(now) {
            Routed::Respond { packet, .. } => {
                let p = node.take_forwarded(packet).expect("slot");
                let id = p.id();
                let payload = p.with_payload(|d| d.to_vec());
                frames.extend(fragment(id, &payload, sc));
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    frames
}

fn settle(node: &mut TestNode, pool: &mut Pool, now: u32, sc: &mut u32) {
    for _ in 0..8 {
        let frames = drain(node, now, sc);
        if frames.is_empty() {
            break;
        }
        let back = to_c(&frames);
        from_c(node, pool, &back, now);
    }
}

#[test]
fn a_file_goes_both_ways_over_rdp_over_can_with_frames_lost_and_swapped() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert!(c_can_init(C_ADDR, NETMASK));
    assert_eq!(c_node_bind(PORT), 0);
    assert_eq!(c_hmac_set_key(SECRET), 0);
    let _ = c_can_drain();

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("can", R_ADDR, NETMASK, true).unwrap();
    node.set_hmac_key(SECRET);
    let mut pool = Pool::new();
    let mut sc = 0u32;
    let free_at_start = node.pool().available();

    let conn = node
        .connect(
            2,
            C_ADDR,
            PORT,
            opts::RDP_REQ | opts::CRC32_REQ | opts::HMAC_REQ,
            1000,
        )
        .expect("connect");
    settle(&mut node, &mut pool, 1000, &mut sc);
    assert!(node.is_rdp_open(conn), "handshake over CAN completes");
    let _ = c_node_read_held(PORT);

    // --- Upload: the port streams to the C. ---
    let up = message(0x11);
    let mtu = node.conn_sfp_mtu(conn).expect("mtu").min(MTU);
    let mut now = 1100u32;
    let mut fragments = 0;
    for (i, (offset, total, chunk)) in csp_core::sfp::Fragmenter::new(&up, mtu)
        .unwrap()
        .enumerate()
    {
        let mut p = node.packet().expect("pool");
        p.set_payload(chunk).unwrap();
        let (id, payload) = match node.send_fragment(conn, p, offset, total, now) {
            Ok(Outbound::Transmit { packet, .. }) => {
                (packet.id(), packet.with_payload(|d| d.to_vec()))
            }
            other => panic!("fragment at {offset}: {other:?}"),
        };
        let mut frames = fragment(id, &payload, &mut sc);
        match i {
            1 => {
                frames.remove(frames.len() / 2);
            }
            2 => frames.swap(1, 2),
            _ => {}
        }
        let back = to_c(&frames);
        from_c(&mut node, &mut pool, &back, now);
        settle(&mut node, &mut pool, now, &mut sc);
        now += 10;
        fragments += 1;
    }
    assert_eq!(fragments, 3, "the stream spans three fragments");

    // The port's timer repairs the two damaged fragments; then the C's application
    // reassembles what its connection holds.
    now += 1001;
    node.tick(now, u32::MAX);
    settle(&mut node, &mut pool, now, &mut sc);
    match c_node_sfp_recv(&[], PORT) {
        Ok(got) => assert_eq!(got, up, "the C reassembles the upload after the repair"),
        Err(e) => panic!("csp_sfp_recv_fp refused the upload: {e}"),
    }

    // --- Download: the C streams to the port over the same connection. ---
    let down = message(0x22);
    // Its fragments leave over CAN (the shim's own capture also counts them, per packet).
    c_node_sfp_send_on(PORT, &down, mtu as u32).expect("csp_sfp_send on the held conn");
    let over_can = c_can_drain();
    let mut frames = over_can;
    assert!(
        frames.len() > 6,
        "three fragments span many CAN frames: {}",
        frames.len()
    );
    // Lose a frame in the middle of the transfer.
    frames.remove(frames.len() / 2);
    from_c(&mut node, &mut pool, &frames, now);
    settle(&mut node, &mut pool, now, &mut sc);

    let first = node
        .read(conn)
        .expect("read")
        .expect("the first fragment is delivered");

    struct Src<'s, 'a> {
        node: &'s mut TestNode<'a>,
        pool: &'s mut Pool,
        sc: &'s mut u32,
        conn: csp::conn::Handle,
        now: u32,
        rounds: u32,
    }
    impl<'a> csp::delivery::PacketSource<'a, 24, 300> for Src<'_, 'a> {
        fn next_packet(&mut self, _timeout_ms: u32) -> Option<csp::Packet<'a, 24, 300>> {
            loop {
                if let Ok(Some(p)) = self.node.read(self.conn) {
                    return Some(p);
                }
                if self.rounds == 0 {
                    return None;
                }
                self.rounds -= 1;
                // The C's retransmission timer, from its own clock.
                c_clock_advance(300);
                c_node_pump();
                let frames = c_can_drain();
                self.now += 300;
                from_c(self.node, self.pool, &frames, self.now);
                settle(self.node, self.pool, self.now, self.sc);
            }
        }
    }
    let mut src = Src {
        node: &mut node,
        pool: &mut pool,
        sc: &mut sc,
        conn,
        now,
        rounds: 8,
    };
    match csp::delivery::Delivery::classify(first, &mut src) {
        csp::delivery::Delivery::Stream(mut st) => {
            let mut buf = [0u8; 512];
            let got = st
                .read_to_slice(2000, &mut buf)
                .expect("the port reassembles the download after the C's repair");
            assert_eq!(&buf[..got], &down[..]);
        }
        _ => panic!("the first delivered packet did not start a stream"),
    }
    assert!(
        src.rounds < 8,
        "the lost frame must have been repaired by the C's retransmission timer"
    );
    now = src.now;

    // Close from the port; the C answers and both sides release.
    node.close(conn, now).expect("close");
    settle(&mut node, &mut pool, now, &mut sc);
    now += 20_001;
    node.tick(now, u32::MAX);
    let _ = c_node_release(PORT);
    assert_eq!(node.pool().available(), free_at_start, "every buffer back");
}
