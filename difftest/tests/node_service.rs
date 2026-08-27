//! The built-in services, compared between a real C node and the port.
//!
//! # Why this file exists
//!
//! `csp::service::respond` — ping, ps, memfree, buf_free, uptime, reboot — had **no
//! comparison against libcsp of any kind**. Not a corpus record (there is no
//! `suite_service.c`; the eleven suites are buffer, cmp, conn, dedup, eth, hmac, promisc,
//! queue, rdp, route, security, sfp), not a golden vector, not a differential test. Its only
//! callers anywhere are three `#[cfg(test)]` bodies in `client.rs`. So every claim about it
//! was a reading of `csp_service_handler.c`.
//!
//! Ping is how an operator finds out whether the link works at all, and reboot is the one
//! service that cannot be undone from the ground. Neither had ever been put next to the C.
//!
//! # What is compared, and on what
//!
//! Not every service is comparable the same way, and saying which is which is the point:
//!
//! | service | comparable directly? |
//! |---|---|
//! | PING | **yes, byte for byte** — a pure echo, no node state involved |
//! | PS | **yes, as reply-or-silence** — both decide by "is there anything to say" |
//! | REBOOT / SHUTDOWN | **yes** — for which payloads the guard opens |
//! | MEMFREE | only if both are *given* the same number; the C's comes from a hook, the port's from the caller |
//! | BUF_FREE, UPTIME | same — the C reports its own pool and clock, the port reports what the application passes. The shared claim is the **encoding**, so the port is fed the value the C reported. |
//!
//! # The reboot hook had to be defused first
//!
//! `arch/posix/csp_system.c` implements `csp_reboot_hook` as `sync();
//! reboot(LINUX_REBOOT_CMD_RESTART)`. It was in this build, so a test sending port 4 with
//! the right magic word would have rebooted the machine running it. `build.rs` now leaves
//! that file out and `shim.c` supplies recording hooks, the way `ctest/hooks.c` already did
//! and `difftest` had not.

use csp::service::{self, NodeStatus, Request};
use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const PEER: u16 = 4000;
const HDR: usize = 6;

/// The value both stacks are told to report for MEMFREE.
const MEMFREE: u32 = 0x0010_0000;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn framed(dst: u16, dport: u8, payload: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: PEER,
        dst,
        dport,
        sport: 40,
    };
    let mut v = vec![0u8; HDR + payload.len()];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(payload);
    v
}

/// Reply payloads a peer would see from the C node.
fn c_replies(dport: u8, payload: &[u8]) -> Vec<Vec<u8>> {
    c_node_serve(&framed(C_ADDR, dport, payload), dport)
        .into_iter()
        .map(|f| f[HDR.min(f.len())..].to_vec())
        .collect()
}

/// What the port's service does with the same request.
///
/// Drives the whole path a real deployment uses — router, bound port, the application's
/// `read`, `Request::decode`, `respond`, and `reply_to` onto a wire — so the reply payloads
/// are what a peer would actually receive, not what an encoder returned in memory.
struct PortResult {
    replies: Vec<Vec<u8>>,
    classified: Option<Request>,
}

fn port_replies(dport: u8, payload: &[u8], status: &NodeStatus<'_>) -> PortResult {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(dport).unwrap();

    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(R_ADDR, dport, payload))
        .expect("frame");
    node.router.receive(p, 0);

    let mut out = PortResult {
        replies: Vec::new(),
        classified: None,
    };
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    let mut buf = [0u8; 512];
                    let made = pkt.with_payload(|got| {
                        let req = Request::decode(dport, got).ok()?;
                        let n = service::respond(req, got, status, &mut buf).ok().flatten();
                        Some((req, n))
                    });
                    if let Some((req, n)) = made {
                        out.classified = Some(req);
                        if let Some(n) = n {
                            let mut reply = node.packet().expect("pool");
                            reply.set_payload(&buf[..n]).unwrap();
                            match node.reply_to(&pkt, reply) {
                                Ok(Outbound::Transmit { mut packet, .. }) => {
                                    packet.prepend_header(VERSION).unwrap();
                                    let f = packet.with_frame(|f| f.to_vec());
                                    out.replies.push(f[HDR..].to_vec());
                                }
                                other => panic!("a reply did not reach a wire: {other:?}"),
                            }
                        }
                    }
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    out
}

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, 20, 40),
        "C node came up at v2"
    );
    for p in 1..=6u8 {
        assert_eq!(c_node_bind(p), 0, "bind service port {p}");
    }
    c_service_hooks_reset();
    c_set_memfree(MEMFREE);
}

/// A ping must come back exactly as it went out — that is the whole contract.
///
/// Three shapes, because the interesting ones are at the ends: an empty ping (a peer
/// checking liveness with no payload) and a large one (the path's MTU behaviour).
#[test]
fn a_ping_is_echoed_byte_for_byte_by_both() {
    let _g = lock();
    setup();

    for body in [b"ping".to_vec(), Vec::new(), vec![0xAB; 200]] {
        let c = c_replies(csp_core::ports::PING, &body);
        let r = port_replies(csp_core::ports::PING, &body, &NodeStatus::default());

        assert_eq!(
            c.len(),
            1,
            "the C answers every ping, including a {}-byte one",
            body.len()
        );
        assert_eq!(c[0], body, "and answers it with the request verbatim");
        assert_eq!(
            r.replies,
            c,
            "the port must echo identically for a {}-byte ping -- an operator uses this to \
             decide whether the link works, so a reply that differs is a false negative",
            body.len()
        );
    }
}

/// A node with nothing to say about its processes says **nothing**, rather than saying
/// nothing at length.
///
/// `csp_service_handler` runs `csp_ps_hook` and then `if (packet->length == 0) goto
/// discard`. An empty reply and no reply differ to any peer that times out: one is a node
/// claiming to have no processes, the other is a node that did not answer.
#[test]
fn a_process_list_with_nothing_in_it_draws_no_reply_from_either() {
    let _g = lock();
    setup();
    c_set_ps_entries(0);

    let c = c_replies(csp_core::ports::PS, &[]);
    let r = port_replies(csp_core::ports::PS, &[], &NodeStatus::default());

    assert_eq!(c.len(), 0, "the C discards a PS it cannot fill");
    assert_eq!(
        r.replies.len(),
        0,
        "and the port must not answer with an empty packet"
    );

    // And when there *is* something, both answer.
    c_set_ps_entries(3);
    let c = c_replies(csp_core::ports::PS, &[]);
    let status = NodeStatus {
        ps: b"init\nrouter\napp\n",
        ..Default::default()
    };
    let r = port_replies(csp_core::ports::PS, &[], &status);
    assert_eq!(c.len(), 1, "the C answers when the hook filled the packet");
    assert_eq!(
        r.replies.len(),
        1,
        "and so does the port -- a control, so the case above is not passing because \
         nothing ever answers"
    );
}

/// The three counter services encode the same way: four big-endian bytes.
///
/// The *values* are not comparable — the C reports its own pool and its own clock — so each
/// stack is asked what it reports, and the port is then given that number. What is being
/// compared is the encoding, which is the part a ground station's decoder depends on.
#[test]
fn the_counter_services_encode_the_same_four_bytes() {
    let _g = lock();
    setup();

    // MEMFREE: both are given the same number outright.
    let c = c_replies(csp_core::ports::MEMFREE, &[]);
    assert_eq!(c.len(), 1);
    assert_eq!(
        c[0],
        MEMFREE.to_be_bytes(),
        "the C encodes memfree big-endian"
    );
    let status = NodeStatus {
        mem_free: MEMFREE,
        ..Default::default()
    };
    let r = port_replies(csp_core::ports::MEMFREE, &[], &status);
    assert_eq!(r.replies, c, "and so must the port, for the same number");

    // BUF_FREE and UPTIME: take the C's own answer and feed it to the port.
    for (port, name) in [
        (csp_core::ports::BUF_FREE, "buf_free"),
        (csp_core::ports::UPTIME, "uptime"),
    ] {
        let c = c_replies(port, &[]);
        assert_eq!(c.len(), 1, "the C answers {name}");
        assert_eq!(c[0].len(), 4, "{name} is four bytes");
        let v = u32::from_be_bytes([c[0][0], c[0][1], c[0][2], c[0][3]]);
        let status = NodeStatus {
            buf_free: v,
            uptime_s: v,
            ..Default::default()
        };
        let r = port_replies(port, &[], &status);
        assert_eq!(
            r.replies, c,
            "{name}: given the number the C reported, the port must put the same bytes \
             on the wire"
        );
    }
}

/// The magic word is the only thing standing between a stray packet and a dead satellite.
///
/// Safe to ask only because this build's reboot hook records instead of rebooting; the real
/// posix one calls `reboot(2)`.
#[test]
fn only_the_magic_word_opens_the_reboot_service() {
    let _g = lock();
    setup();

    // Wrong magic, and a request too short to hold one: nothing, from either.
    for body in [
        0xDEAD_BEEFu32.to_be_bytes().to_vec(),
        Vec::new(),
        vec![0x80, 0x07],
    ] {
        c_service_hooks_reset();
        let c = c_replies(csp_core::ports::REBOOT, &body);
        let (rebooted, shut) = c_service_rebooted();
        assert_eq!(c.len(), 0, "the C never replies on the reboot port");
        assert!(
            !rebooted && !shut,
            "a {}-byte payload that is not the magic word must not reboot the C",
            body.len()
        );

        let r = port_replies(csp_core::ports::REBOOT, &body, &NodeStatus::default());
        assert_eq!(r.replies.len(), 0, "nor does the port reply");
        assert_eq!(
            r.classified,
            None,
            "and the port must not tell its application to reboot for a {}-byte \
             non-magic payload",
            body.len()
        );
    }

    // The right words, on the other hand, are obeyed by both.
    c_service_hooks_reset();
    let c = c_replies(
        csp_core::ports::REBOOT,
        &service::REBOOT_MAGIC.to_be_bytes(),
    );
    let (rebooted, shut) = c_service_rebooted();
    assert_eq!(c.len(), 0, "a reboot is not acknowledged");
    assert!(rebooted && !shut, "the C reboots on 0x80078007");
    let r = port_replies(
        csp_core::ports::REBOOT,
        &service::REBOOT_MAGIC.to_be_bytes(),
        &NodeStatus::default(),
    );
    assert_eq!(r.replies.len(), 0, "nor does the port acknowledge it");
    assert_eq!(
        r.classified,
        Some(Request::Reboot),
        "the port tells its application to reboot for the same word the C reboots on"
    );

    c_service_hooks_reset();
    let c = c_replies(
        csp_core::ports::REBOOT,
        &service::SHUTDOWN_MAGIC.to_be_bytes(),
    );
    let (rebooted, shut) = c_service_rebooted();
    assert_eq!(c.len(), 0);
    assert!(
        shut && !rebooted,
        "the C shuts down on 0xD1E5529A, and does not confuse it with a reboot"
    );
    let r = port_replies(
        csp_core::ports::REBOOT,
        &service::SHUTDOWN_MAGIC.to_be_bytes(),
        &NodeStatus::default(),
    );
    assert_eq!(r.replies.len(), 0);
    assert_eq!(
        r.classified,
        Some(Request::Shutdown),
        "and the port distinguishes the two words the same way"
    );
}
