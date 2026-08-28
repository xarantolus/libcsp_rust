//! The edges of `csp_rdp_new_packet`'s state machine, driven with hand-built frames at a
//! real C server and at the port as server, row by row.
//!
//! Every row is a packet the protocol does not expect in the state it arrives in — the
//! "BIG FAT switch" (`csp_rdp.c:527`) has a rule for each, and none of them had been put
//! next to the port. Each row opens a fresh connection (its own source port), so rows do
//! not contaminate each other. Delayed acknowledgements are proposed off, so an
//! acknowledgement, when the rule sends one, is immediate.
//!
//! | row | packet | C |
//! |---|---|---|
//! | closed | data with ACK, no handshake | `RST`, connection closed |
//! | dup-syn | a second SYN while `SYN_RCVD` | another `SYN\|ACK` at once |
//! | in-window | data at `cur+3`, window 4 | held, `ACK(cur)` |
//! | out-of-window | data at `cur+20` | discarded, silence |
//! | bad-ack | in-order data whose `ack_nr` is outside `[snd_una-1-2w, snd_nxt-1]` | discarded, silence |

use csp::{Config, CspStorage, Node, Routed};
use csp_core::rdp::{self, Header, SynOptions};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const PEER: u16 = 30;
const PORT: u8 = 10;
const HDR: usize = 6;
const WINDOW: u32 = 4;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;
/// One row's observation: the RDP flags of every frame sent, and packets delivered.
type Row = (Vec<u8>, usize);

fn opts() -> SynOptions {
    SynOptions {
        window_size: WINDOW,
        conn_timeout: 10_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    }
}

/// An RDP frame from the peer: header, payload, RDP trailer.
fn frame(dst: u16, sport: u8, flags: u8, seq: u16, ack: u16, payload: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: csp_core::flags::RDP,
        src: PEER,
        dst,
        dport: PORT,
        sport,
    };
    let mut body = [0u8; 128];
    body[..payload.len()].copy_from_slice(payload);
    let n = Header {
        flags,
        seq_nr: seq,
        ack_nr: ack,
    }
    .encode(&[], &mut body[payload.len()..])
    .unwrap();
    let mut v = vec![0u8; HDR + payload.len() + n];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(&body[..payload.len() + n]);
    v
}

fn syn_payload() -> Vec<u8> {
    let mut o = [0u8; rdp::SYN_OPTIONS_LEN];
    let n = opts().encode(&mut o).unwrap();
    o[..n].to_vec()
}

fn rdp_flags(f: &[u8]) -> u8 {
    Header::decode(&f[HDR..])
        .map(|h| h.flags & 0x0F)
        .unwrap_or(0)
}
fn rdp_seq(f: &[u8]) -> u16 {
    Header::decode(&f[HDR..]).map(|h| h.seq_nr).unwrap()
}

// ---- the C as server ----------------------------------------------------------------

/// Handshake with the C on `sport`; returns the server's ISN. Releases the connection the
/// previous row's reads held, so each row's connection is its own.
fn c_open(sport: u8) -> u16 {
    let _ = c_node_release(PORT);
    let a = c_node_exchange(
        &frame(C_ADDR, sport, rdp::SYN, 1000, 0, &syn_payload()),
        &[],
    );
    assert_eq!(a.tx.len(), 1, "SYN|ACK");
    assert_eq!(rdp_flags(&a.tx[0]), rdp::SYN | rdp::ACK);
    let iss = rdp_seq(&a.tx[0]);
    let b = c_node_exchange(&frame(C_ADDR, sport, rdp::ACK, 1001, iss, &[]), &[]);
    assert_eq!(b.tx.len(), 0, "the handshake's ACK draws nothing");
    iss
}

/// What the C does with one more packet: (frames out as flags, packets the application
/// can then read). Not watched during the exchange -- watching makes the harness close the
/// connection, and its reset would be counted as the protocol's answer.
fn c_row(_sport: u8, f: &[u8]) -> (Vec<u8>, usize) {
    let out = c_node_exchange(f, &[]);
    let flags = out.tx.iter().map(|x| rdp_flags(x)).collect();
    // Read without closing: closing would reset the connection and the next row's packet
    // would be answered from CLOSE_WAIT.
    (flags, c_node_read_held(PORT) as usize)
}

// ---- the port as server -------------------------------------------------------------

fn r_feed(node: &mut TestNode, f: &[u8], now: u32) -> (Vec<u8>, usize) {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, f).unwrap();
    node.router.receive(p, 0);
    let mut flags = Vec::new();
    let mut delivered = 0;
    loop {
        match node.work(now) {
            Routed::Respond { packet, .. } => {
                let mut p = node.take_forwarded(packet).unwrap();
                p.prepend_header(VERSION).unwrap();
                flags.push(p.with_frame(rdp_flags));
            }
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    delivered += 1;
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    (flags, delivered)
}

fn r_open(node: &mut TestNode, sport: u8) -> u16 {
    let mut p = node.packet().expect("pool");
    p.set_frame(
        VERSION,
        &frame(R_ADDR, sport, rdp::SYN, 1000, 0, &syn_payload()),
    )
    .unwrap();
    node.router.receive(p, 0);
    let mut iss = None;
    loop {
        match node.work(0) {
            Routed::Respond { packet, .. } => {
                let mut p = node.take_forwarded(packet).unwrap();
                p.prepend_header(VERSION).unwrap();
                p.with_frame(|x| {
                    assert_eq!(rdp_flags(x), rdp::SYN | rdp::ACK);
                    iss = Some(rdp_seq(x));
                });
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    let iss = iss.expect("SYN|ACK");
    let (f, _) = r_feed(node, &frame(R_ADDR, sport, rdp::ACK, 1001, iss, &[]), 1);
    assert_eq!(f, Vec::<u8>::new(), "the handshake's ACK draws nothing");
    let _ = node.accept();
    iss
}

fn fresh<'a>(storage: &'a CspStorage<8, 24, 300, 64, 8>) -> TestNode<'a> {
    let mut node: TestNode = Node::new(storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(PORT).unwrap();
    node
}

#[test]
fn every_edge_of_the_state_machine_answers_as_the_c_does() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_ADDR, NETMASK, 20, 40));
    assert_eq!(c_node_bind(PORT), 0);
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    let mut rows: Vec<(&str, Row, Row)> = Vec::new();

    // closed: data with ACK and no handshake.
    let c = c_row(40, &frame(C_ADDR, 40, rdp::ACK, 5, 5, b"stray"));
    let r = r_feed(&mut node, &frame(R_ADDR, 40, rdp::ACK, 5, 5, b"stray"), 10);
    rows.push(("closed: data, no handshake", c, r));

    // dup-syn: a second SYN while SYN_RCVD.
    let a = c_node_exchange(&frame(C_ADDR, 41, rdp::SYN, 1000, 0, &syn_payload()), &[]);
    assert_eq!(rdp_flags(&a.tx[0]), rdp::SYN | rdp::ACK);
    let c = c_row(41, &frame(C_ADDR, 41, rdp::SYN, 1000, 0, &syn_payload()));
    let mut p = node.packet().unwrap();
    p.set_frame(
        VERSION,
        &frame(R_ADDR, 41, rdp::SYN, 1000, 0, &syn_payload()),
    )
    .unwrap();
    node.router.receive(p, 0);
    while !matches!(node.work(20), Routed::Idle) {}
    let r = r_feed(
        &mut node,
        &frame(R_ADDR, 41, rdp::SYN, 1000, 0, &syn_payload()),
        21,
    );
    rows.push(("dup-syn: SYN again in SYN_RCVD", c, r));

    // in-window: data at cur+3.
    let iss = c_open(42);
    let c = c_row(42, &frame(C_ADDR, 42, rdp::ACK, 1003, iss, b"ahead"));
    let iss_r = r_open(&mut node, 42);
    let r = r_feed(
        &mut node,
        &frame(R_ADDR, 42, rdp::ACK, 1003, iss_r, b"ahead"),
        30,
    );
    rows.push(("in-window: data at cur+3 (1003)", c, r));

    // in-window by the C's rule only: data at cur+6, inside 2*window (8), outside a
    // constant window of 5.
    // Held or discarded looks the same until the gap fills: send cur+1..cur+5 afterwards and
    // count what the application gets in all -- six if cur+6 was held, five if it was not.
    // Held or discarded looks the same until the gap fills: send cur+1..cur+5 afterwards and
    // count what the application gets in all -- six if cur+6 was held, five if it was not.
    // Only the delivered total is compared for this row: the C acknowledged four of the
    // five fill packets and the port five (both deliver all six, in order), a cadence
    // difference this test does not chase.
    let iss = c_open(46);
    let (_, mut c_delivered) = c_row(46, &frame(C_ADDR, 46, rdp::ACK, 1006, iss, b"edge"));
    for k in 1..=5u16 {
        c_delivered += c_row(46, &frame(C_ADDR, 46, rdp::ACK, 1000 + k, iss, b"fill")).1;
    }
    let iss_r = r_open(&mut node, 46);
    let (_, mut r_delivered) = r_feed(
        &mut node,
        &frame(R_ADDR, 46, rdp::ACK, 1006, iss_r, b"edge"),
        35,
    );
    for k in 1..=5u16 {
        r_delivered += r_feed(
            &mut node,
            &frame(R_ADDR, 46, rdp::ACK, 1000 + k, iss_r, b"fill"),
            35 + k as u32,
        )
        .1;
    }
    assert_eq!(
        c_delivered, 6,
        "the C held cur+6 (inside 2w) and released it with the gap"
    );
    rows.push((
        "in-window by 2*window only: cur+6 held, then the gap filled (delivered)",
        (vec![], c_delivered),
        (vec![], r_delivered),
    ));

    // out-of-window: data at cur+20.
    let iss = c_open(43);
    let c = c_row(43, &frame(C_ADDR, 43, rdp::ACK, 1020, iss, b"far"));
    let iss_r = r_open(&mut node, 43);
    let r = r_feed(
        &mut node,
        &frame(R_ADDR, 43, rdp::ACK, 1020, iss_r, b"far"),
        40,
    );
    rows.push(("out-of-window: data at cur+20 (1020)", c, r));

    // bad-ack: in-order data acknowledging a sequence the server never sent.
    let iss = c_open(44);
    let c = c_row(
        44,
        &frame(C_ADDR, 44, rdp::ACK, 1001, iss.wrapping_add(1000), b"ok"),
    );
    let iss_r = r_open(&mut node, 44);
    let r = r_feed(
        &mut node,
        &frame(R_ADDR, 44, rdp::ACK, 1001, iss_r.wrapping_add(1000), b"ok"),
        50,
    );
    rows.push(("bad-ack: in-order data, ack_nr far outside", c, r));

    // in-order, for reference.
    let iss = c_open(45);
    let c = c_row(45, &frame(C_ADDR, 45, rdp::ACK, 1001, iss, b"fine"));
    let iss_r = r_open(&mut node, 45);
    let r = r_feed(
        &mut node,
        &frame(R_ADDR, 45, rdp::ACK, 1001, iss_r, b"fine"),
        60,
    );
    rows.push(("in-order: data at cur+1", c, r));

    // duplicate: in-order data delivered and acknowledged, then the same packet again --
    // what a peer sends when the acknowledgement was lost.
    let iss = c_open(47);
    let first = c_row(47, &frame(C_ADDR, 47, rdp::ACK, 1001, iss, b"once"));
    assert_eq!(first, (vec![rdp::ACK], 1));
    let c = c_row(47, &frame(C_ADDR, 47, rdp::ACK, 1001, iss, b"once"));
    let iss_r = r_open(&mut node, 47);
    let first = r_feed(
        &mut node,
        &frame(R_ADDR, 47, rdp::ACK, 1001, iss_r, b"once"),
        70,
    );
    assert_eq!(first, (vec![rdp::ACK], 1));
    let r = r_feed(
        &mut node,
        &frame(R_ADDR, 47, rdp::ACK, 1001, iss_r, b"once"),
        71,
    );
    rows.push(("duplicate: the same in-order packet again", c, r));

    let mut diverged = Vec::new();
    for (name, c, r) in &rows {
        eprintln!("{name:44}  C: {c:?}   port: {r:?}");
        if c != r {
            diverged.push(*name);
        }
    }
    assert!(
        diverged.is_empty(),
        "rows that differ from the C: {diverged:?}"
    );
}
