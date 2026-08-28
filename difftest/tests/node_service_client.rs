//! **libcsp's own service clients**, waiting for a real reply from the port.
//!
//! # What was never driven
//!
//! `difftest`'s `shim_client_request` calls each of `csp_services.c`'s clients with a
//! **zero** timeout: the request reaches the wire and the client gives up immediately. So
//! `every_service_request_matches_what_the_cs_client_builds` compares the request bytes and
//! nothing else, and no libcsp service client had ever received and interpreted a reply the
//! port produced.
//!
//! That is the direction an operator is in. What each client demands of the reply:
//!
//! | client | requires | how failure reads on the ground |
//! |---|---|---|
//! | `csp_ping` | the echo, checked byte by byte against `i % 256` | returns `-1` |
//! | `csp_get_memfree` | exactly 4 bytes, then `be32toh` | `CSP_ERR_TIMEDOUT`, value `0` |
//! | `csp_get_buf_free` | the same | the same |
//! | `csp_get_uptime` | the same | the same |
//!
//! Every one of those failures is indistinguishable from a node that did not answer. A
//! reply of the wrong length, the wrong byte order, or without the checksum the `csp_get_*`
//! family always requests, would have been invisible to every test in this repository — the
//! same shape as the CRC32 defect `node_cmp_if_stats.rs` found one commit ago, which is why
//! this file drives the byte order rather than reading the encoder.
//!
//! # Why a thread
//!
//! `csp_transaction_persistent` and `csp_ping` both block in `csp_read`, so the client runs
//! on its own thread and this test turns the crank — the arrangement `node_rdp_responder.rs`
//! introduced.

use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
/// The C node, which asks.
const C_ADDR: u16 = 9;
/// The port, which answers.
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;

/// Numbers with no zero bytes and different in every position, so a byte-order slip or a
/// truncation cannot land on the right answer by accident. `0x01020304` would survive a
/// half-word swap looking plausible; these do not.
const MEM_FREE: u32 = 0x1234_5678;
const BUF_FREE: u32 = 0x0000_0013;
const UPTIME_S: u32 = 0x00BC_614E;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// Serve one request the way an application does: read it, build the reply, put it on a
/// wire. Returns the reply frames.
fn serve(node: &mut TestNode, request: &[u8]) -> Vec<Vec<u8>> {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, request)
        .expect("the C client's own frame");
    node.router.receive(p, 0);

    let status = csp::service::NodeStatus {
        mem_free: MEM_FREE,
        buf_free: BUF_FREE,
        uptime_s: UPTIME_S,
        ps: b"",
    };

    let mut replies = Vec::new();
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    let dport = pkt.id().dport;
                    let mut out = [0u8; 256];
                    let answered = pkt.with_payload(|body| {
                        let req = csp::service::Request::decode(dport, body).ok()?;
                        csp::service::respond(req, body, &status, &mut out)
                            .ok()
                            .flatten()
                    });
                    let Some(n) = answered else {
                        drop(pkt);
                        continue;
                    };
                    let mut reply = node.packet().expect("pool");
                    reply.set_payload(&out[..n]).unwrap();
                    match node.reply_to(&pkt, reply) {
                        Ok(Outbound::Transmit { mut packet, .. }) => {
                            packet.prepend_header(VERSION).unwrap();
                            replies.push(packet.with_frame(|f| f.to_vec()));
                        }
                        other => panic!("the reply did not reach a wire: {other:?}"),
                    }
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    replies
}

/// Run one client end to end and hand back what libcsp made of the answer.
fn round_trip(node: &mut TestNode, svc: CService) -> (i32, u32) {
    let request = c_service_start(svc, R_ADDR);
    assert_eq!(
        request.len(),
        1,
        "{svc:?}: libcsp's client puts exactly one request frame on the wire"
    );
    let replies = serve(node, &request[0]);
    assert_eq!(replies.len(), 1, "{svc:?}: one request, one reply");
    c_node_exchange(&replies[0], &[]);
    c_service_join()
}

#[test]
fn libcsps_own_service_clients_accept_what_the_port_answers() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(csp_core::ports::PING).unwrap();
    node.bind(csp_core::ports::MEMFREE).unwrap();
    node.bind(csp_core::ports::BUF_FREE).unwrap();
    node.bind(csp_core::ports::UPTIME).unwrap();

    // A ping long enough that the echo check has something to check: `csp_ping` fills the
    // payload with `i % 256` and compares every byte, so a one-byte ping passes even if the
    // reply were a fixed 0x00.
    let (status, _) = round_trip(&mut node, CService::Ping { size: 40, opts: 0 });
    assert!(
        status >= 0,
        "csp_ping must accept the port's echo -- -1 means the reply was missing, short, or \
         not the bytes it sent"
    );

    // The same again with the checksum a shell's `ping -c` asks for, which is the path the
    // CRC32 defect made undeliverable.
    let (status, _) = round_trip(
        &mut node,
        CService::Ping {
            size: 40,
            // `CSP_O_CRC32` is `CSP_SO_CRC32REQ`, 0x40 (`csp_types.h:85`). 0x04 is
            // `CSP_SO_HMACREQ`, which is a different question entirely.
            opts: 0x40,
        },
    );
    assert!(
        status >= 0,
        "csp_ping with CSP_O_CRC32 must round-trip: the reply carries the flag, so it needs \
         the checksum too"
    );

    // The three `csp_get_*` clients, each demanding four big-endian bytes and a checksum.
    for (svc, want) in [
        (CService::MemFree, MEM_FREE),
        (CService::BufFree, BUF_FREE),
        (CService::Uptime, UPTIME_S),
    ] {
        let (status, value) = round_trip(&mut node, svc);
        assert_eq!(
            status, 0,
            "{svc:?}: libcsp must report CSP_ERR_NONE -- -3 is CSP_ERR_TIMEDOUT, which is \
             what a reply of the wrong length or without the checksum looks like"
        );
        assert_eq!(
            value, want,
            "{svc:?}: and the number must survive be32toh, which is what catches a reply \
             written in the wrong byte order"
        );
    }
}
