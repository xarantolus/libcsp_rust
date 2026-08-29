//! A whole session over the ground link: RDP with CRC32, over KISS with its own CRC, against
//! a real C peer — through the real `csp_kiss_rx` and `csp_kiss_tx` on a routed KISS
//! interface of the C node, and the port's KISS encoder and decoder on the other end. Both
//! directions, with one frame lost on the way and repaired by retransmission.
//!
//! KISS carries the whole CSP frame, and with `CSP_ENABLE_KISS_CRC` (the canonical build)
//! `csp_kiss_tx` appends a CRC32 over the payload before framing; `csp_kiss_rx` verifies it
//! and refuses a frame without one. That is a second checksum outside the CSP-level one the
//! connection asks for, and the port has to put both on and take both off.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::security::opts;
use csp_core::{crc32, kiss, Version};
use difftest::*;

const VERSION: Version = Version::V2;
/// The C node's address, and its KISS interface's: a subnet of its own (24..=27).
const C_ADDR: u16 = 9;
const C_KISS: u16 = 24;
/// The port, on the KISS subnet, so the C's replies leave over KISS.
const R_ADDR: u16 = 25;
const NETMASK: u16 = 12;
const PORT: u8 = 10;
const HDR: usize = 6;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// The port's KISS frame for one packet: header, payload, KISS CRC over the payload.
fn kiss_frame(frame: &[u8]) -> Vec<u8> {
    let mut body = frame.to_vec();
    body.extend_from_slice(&crc32::checksum(&frame[HDR..]).to_be_bytes());
    let mut out = vec![0u8; kiss::max_encoded_len(body.len())];
    let n = kiss::encode(&body, &mut out).unwrap();
    out.truncate(n);
    out
}

/// Feed a byte stream to the real `csp_kiss_rx`, run the C's router, and hand back what the
/// C's KISS link transmitted in return.
fn to_c(bytes: &[u8]) -> Vec<u8> {
    c_kiss_node_rx(bytes);
    c_clock_advance(300);
    c_node_pump();
    c_kiss_node_drain()
}

/// Decode the C's byte stream with the port's decoder, verify and strip each frame's KISS
/// CRC, and deliver each packet to the node.
fn from_c(node: &mut TestNode, dec: &mut kiss::Decoder<512>, bytes: &[u8], now: u32) {
    for &b in bytes {
        if let Some(frame) = dec.push(b) {
            let payload = crc32::verify(&[], &frame[HDR..], crc32::Coverage::PayloadOnly)
                .expect("the C's KISS CRC over the payload");
            let mut v = frame[..HDR].to_vec();
            v.extend_from_slice(payload);
            let mut p = node.packet().expect("pool");
            p.set_frame(VERSION, &v).unwrap();
            node.router.receive(p, 0);
        }
    }
    let _ = now;
}

fn drain(node: &mut TestNode, now: u32) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut frames = Vec::new();
    let mut delivered = Vec::new();
    loop {
        match node.work(now) {
            Routed::Respond { packet, .. } => {
                let mut p = node.take_forwarded(packet).expect("slot");
                p.prepend_header(VERSION).unwrap();
                frames.push(p.with_frame(kiss_frame));
            }
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    delivered.push(pkt.with_payload(|d| d.to_vec()));
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    (frames, delivered)
}

fn settle(node: &mut TestNode, dec: &mut kiss::Decoder<512>, now: u32) -> Vec<Vec<u8>> {
    let mut delivered = Vec::new();
    for _ in 0..8 {
        let (frames, d) = drain(node, now);
        delivered.extend(d);
        if frames.is_empty() {
            break;
        }
        let bytes: Vec<u8> = frames.concat();
        let back = to_c(&bytes);
        from_c(node, dec, &back, now);
    }
    delivered
}

#[test]
fn an_rdp_crc32_session_over_kiss_survives_a_lost_frame_both_ways() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert!(c_kiss_node_init(C_KISS, NETMASK));
    assert_eq!(c_node_bind(PORT), 0);
    let _ = c_kiss_node_drain();

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("kiss", R_ADDR, NETMASK, true).unwrap();
    let mut dec = kiss::Decoder::<512>::new();
    let free_at_start = node.pool().available();

    let conn = node
        .connect(2, C_KISS, PORT, opts::RDP_REQ | opts::CRC32_REQ, 1000)
        .expect("connect");
    settle(&mut node, &mut dec, 1000);
    assert!(node.is_rdp_open(conn), "handshake over KISS completes");
    let _ = c_node_read_held(PORT);

    // Three packets; the second's KISS frame is lost on the wire.
    let bodies: Vec<Vec<u8>> = (0..3u8)
        .map(|i| (0..40u8).map(|j| 7 + i * 40 + j).collect())
        .collect();
    let mut now = 1100;
    for (i, body) in bodies.iter().enumerate() {
        let mut p = node.packet().expect("pool");
        p.set_payload(body).unwrap();
        let frame = match node.send(conn, p, now).expect("send") {
            Outbound::Transmit { mut packet, .. } => {
                packet.prepend_header(VERSION).unwrap();
                packet.with_frame(kiss_frame)
            }
            other => panic!("{other:?}"),
        };
        if i != 1 {
            let back = to_c(&frame);
            from_c(&mut node, &mut dec, &back, now);
        }
        settle(&mut node, &mut dec, now);
        now += 10;
    }
    // In order: the first is delivered; the third arrived but waits behind the gap.
    assert_eq!(
        c_node_read_held(PORT),
        1,
        "only the packet before the gap is readable"
    );
    now += 1001;
    node.tick(now, u32::MAX);
    settle(&mut node, &mut dec, now);
    assert_eq!(
        c_node_read_held(PORT),
        2,
        "the retransmission fills the gap and releases the packet held behind it"
    );

    // The C answers; one of its frames is lost too, and its own timer repairs it.
    let mut got = Vec::new();
    for (i, reply) in [b"reply one".as_slice(), b"reply two".as_slice()]
        .iter()
        .enumerate()
    {
        let _ = c_node_send_on(PORT, reply);
        let bytes = c_kiss_node_drain();
        assert!(!bytes.is_empty(), "the C's reply leaves over KISS");
        if i != 0 {
            from_c(&mut node, &mut dec, &bytes, now);
        }
        got.extend(settle(&mut node, &mut dec, now));
        now += 10;
    }
    for _ in 0..6 {
        c_clock_advance(300);
        c_node_pump();
        let bytes = c_kiss_node_drain();
        now += 300;
        from_c(&mut node, &mut dec, &bytes, now);
        got.extend(settle(&mut node, &mut dec, now));
    }
    assert_eq!(got, vec![b"reply one".to_vec(), b"reply two".to_vec()]);

    node.close(conn, now).expect("close");
    settle(&mut node, &mut dec, now);
    now += 20_001;
    node.tick(now, u32::MAX);
    let _ = c_node_release(PORT);
    assert_eq!(node.pool().available(), free_at_start, "every buffer back");
}
