//! **libcsp's own `csp_cmp_clock`** setting and reading the port's clock.
//!
//! # Why this one
//!
//! Measured across the CMP codes the port serves: `IDENT` had a real C client
//! (`node_cmp_server.rs`, hand-rolled), `PEEK`/`POKE` v2 had one, `IF_STATS` gained libcsp's
//! actual client last commit. `CLOCK` had none, and it is the code where being wrong costs
//! the most. A lost packet is retried; a satellite whose clock was set wrong timestamps every
//! subsequent telemetry record, schedules every window and propagates every ephemeris from a
//! bad epoch — and nothing on the ground says so.
//!
//! # The behaviour that only a waiting client can see
//!
//! `csp_cmp_clock_handler` (`csp_cmp_clock.c:8`) sets only when `tv_sec` is non-zero, reads
//! back regardless, and then returns the **set** result — so a refused set builds a reply and
//! `csp_service_handler` discards it. The three cases and what a ground station sees:
//!
//! | request | the node | the client |
//! |---|---|---|
//! | `tv_sec != 0`, accepted | sets, then reports its clock | the new time |
//! | `tv_sec == 0` | does **not** set, reports its clock | the current time |
//! | `tv_sec != 0`, refused | sets nothing, sends nothing | `CSP_ERR_TIMEDOUT` |
//!
//! The third is the one that matters: silence is how an operator learns the set failed. A
//! node that answered anyway would be read as confirmation, and the clock would be believed.
//! None of that is visible to a client that does not wait for the reply, which is every
//! client in this harness before `node_service_client.rs`.
//!
//! `csp_cmp` sends with `CSP_O_CRC32` and demands a reply of exactly
//! `sizeof(struct csp_cmp_clock_msg)`, so this also exercises the trailer the previous commit
//! added.

use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::Version;
use difftest::*;
use std::cell::Cell;

const VERSION: Version = Version::V2;
/// The C node, which asks.
const C_ADDR: u16 = 9;
/// The port, which answers.
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;

/// What the node's clock reads before anything sets it. Distinct in every byte so a field
/// swap or a truncation cannot land on it.
const BOOT_SEC: u32 = 0x2A3B_4C5D;
const BOOT_NSEC: u32 = 0x0102_0304;
/// What ground asks for. `tv_nsec` differs from `tv_sec` in every byte too, so the two
/// cannot be transposed unnoticed — the failure that puts a satellite a year out.
const SET_SEC: u32 = 0x6612_3456;
const SET_NSEC: u32 = 0x1DCD_6500;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// The integrator's clock. Records what a set asked for, and can refuse.
struct Clock {
    now: Cell<(u32, u32)>,
    accept: bool,
    set_seen: Cell<Option<(u32, u32)>>,
}

impl csp::hooks::Hooks<24, 300> for Clock {
    // `csp::Timestamp` (the hook's) and `csp_core::cmp::Timestamp` (the wire's) are the
    // same two `u32`s, converted by an `Into` inside `respond_cmp` -- the same duplication
    // as `iface::Stats` against `cmp::IfStats`.
    fn clock(&self) -> csp::Timestamp {
        let (s, ns) = self.now.get();
        csp::Timestamp {
            tv_sec: s,
            tv_nsec: ns,
        }
    }

    fn set_clock(&mut self, t: csp::Timestamp) -> bool {
        self.set_seen.set(Some((t.tv_sec, t.tv_nsec)));
        if self.accept {
            self.now.set((t.tv_sec, t.tv_nsec));
        }
        self.accept
    }
}

/// Serve one CMP request and return the reply frames, which may be none.
fn serve(node: &mut TestNode, request: &[u8], hooks: &mut Clock) -> Vec<Vec<u8>> {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, request)
        .expect("the C client's own frame");
    node.router.receive(p, 0);

    let identity = node.identity();
    let mut replies = Vec::new();
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    let mut out = [0u8; 256];
                    let answered = pkt.with_payload(|body| {
                        let q = csp_core::cmp::parse_request(body).ok()?;
                        csp::service::respond_cmp(q, &identity, VERSION, hooks, &mut out)
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

#[test]
fn libcsps_own_clock_client_sets_and_reads_the_ports_clock() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(csp_core::ports::CMP).unwrap();

    let mut clock = Clock {
        now: Cell::new((BOOT_SEC, BOOT_NSEC)),
        accept: true,
        set_seen: Cell::new(None),
    };

    // 1. A read: `tv_sec == 0` must not set anything, and must report the node's clock.
    let req = c_cmp_clock_start(R_ADDR, 0, 0);
    assert_eq!(req.len(), 1, "one request frame");
    let replies = serve(&mut node, &req[0], &mut clock);
    assert_eq!(replies.len(), 1, "a read is always answered");
    c_node_exchange(&replies[0], &[]);
    let got = c_cmp_clock_join().expect("libcsp must accept the port's CLOCK reply");
    assert_eq!(
        got,
        (BOOT_SEC, BOOT_NSEC),
        "a read must report the node's clock, both fields, in the byte order be32toh expects"
    );
    assert_eq!(
        clock.set_seen.get(),
        None,
        "a tv_sec of zero is a read -- the C never calls csp_clock_set_time for it, so \
         neither may the port, or a status poll would reset the satellite's clock to zero"
    );

    // 2. A set that the node accepts.
    let req = c_cmp_clock_start(R_ADDR, SET_SEC, SET_NSEC);
    assert_eq!(req.len(), 1, "one request frame");
    let replies = serve(&mut node, &req[0], &mut clock);
    assert_eq!(replies.len(), 1, "an accepted set is answered");
    c_node_exchange(&replies[0], &[]);
    let got = c_cmp_clock_join().expect("libcsp must accept the reply to an accepted set");
    assert_eq!(
        clock.set_seen.get(),
        Some((SET_SEC, SET_NSEC)),
        "the node must be handed exactly what ground asked for -- the two fields differ in \
         every byte, so a transposition shows here and nowhere else"
    );
    assert_eq!(
        got,
        (SET_SEC, SET_NSEC),
        "and the reply reports the clock as it now reads"
    );

    // 3. A set the node refuses: no reply at all, which is how the operator learns.
    clock.accept = false;
    clock.set_seen.set(None);
    let req = c_cmp_clock_start(R_ADDR, SET_SEC + 1, 0);
    assert_eq!(req.len(), 1, "one request frame");
    let replies = serve(&mut node, &req[0], &mut clock);
    assert_eq!(
        replies.len(),
        0,
        "a refused set must send nothing: the C returns the set's error and \
         csp_service_handler discards the reply it had already built"
    );
    assert_eq!(
        clock.set_seen.get(),
        Some((SET_SEC + 1, 0)),
        "the node was still asked -- 'refused' has to mean the hook said no, not that the \
         request was never decoded"
    );
    assert_eq!(
        c_cmp_clock_join(),
        Err(-3),
        "libcsp must report CSP_ERR_TIMEDOUT. Anything else means ground would read a \
         failed clock set as confirmation"
    );
}
