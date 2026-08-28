//! **libcsp's own CMP client**, unmodified, asking the port for a link's counters.
//!
//! # What was never driven
//!
//! Measured this cycle: no `csp_cmp_*` client helper is called by either harness.
//! `node_cmp_server.rs` and `node_v2.rs` cover CMP in both directions, but both build the
//! request by filling libcsp's struct and send it with a hand-rolled client. libcsp's real
//! entry point — `csp_cmp_if_stats` and its siblings, all funnelling through `csp_cmp` →
//! `csp_transaction_w_opts` — had never executed. Three things live only on that path:
//!
//! | | where | what it means for the port |
//! |---|---|---|
//! | the request is sent with `CSP_O_CRC32` | `csp_services.c:218` | the port must verify a checksum on the way in **and put one back on the reply** |
//! | the reply's length is checked exactly | `csp_io.c:352` | one byte over or under and the client discards it |
//! | "no reply" becomes `CSP_ERR_TIMEDOUT` | `csp_services.c:219` | a dropped reply is indistinguishable from a dead node |
//!
//! The first is the one that bites. Ground reads `IF_STATS` to see whether a link is
//! carrying traffic or being probed — the per-interface `autherr` counter exists for exactly
//! that. If the port answered without echoing the checksum flag, the reply would be thrown
//! away by the *client's own router*, before any application saw it, and the operator would
//! read a timeout: the satellite looks dead on a link that is working.
//!
//! Nothing here has ever put a CRC32 on a CMP request, so nothing has ever checked that.
//!
//! # And `IF_STATS` itself
//!
//! Of the CMP codes the port serves, only `IDENT` (`node_cmp_server.rs`) and `PEEK`/`POKE`
//! v2 (`node_cmp_peek_v2.rs`) had a real C client accept the port's reply. `IF_STATS` is
//! served and had none.
//!
//! # Why a thread
//!
//! `csp_transaction_persistent` blocks in `csp_read` waiting for the reply, so `csp_cmp`
//! runs on its own thread and this test turns the crank — the same arrangement
//! `node_rdp_responder.rs` uses, and for the same reason.

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
/// The interface the question is about. Eleven bytes is `CSP_CMP_ROUTE_IFACE_LEN`.
const IFNAME: &str = "test";

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// The integrator's side of `IF_STATS`: the port is sans-io, so the node does not report
/// its own counters — the application does, through this hook. Here it hands back exactly
/// what `node.ifaces` holds, which is what a flight application would do.
struct Report {
    name: &'static str,
    stats: csp_core::cmp::IfStats,
}
impl csp::hooks::Hooks<24, 300> for Report {
    fn if_stats(&self, name: &str) -> Option<csp_core::cmp::IfStats> {
        (name == self.name).then_some(self.stats)
    }
}

/// `csp::iface::Stats` and `csp_core::cmp::IfStats` are the same ten `u32`s and there is no
/// conversion between them, so every integrator retypes this by hand — in an order where a
/// transposition is invisible. Written out once here rather than hidden in a helper.
fn as_cmp(s: &csp::iface::Stats) -> csp_core::cmp::IfStats {
    csp_core::cmp::IfStats {
        tx: s.tx,
        rx: s.rx,
        tx_error: s.tx_error,
        rx_error: s.rx_error,
        drop: s.drop,
        autherr: s.autherr,
        frame: s.frame,
        txbytes: s.txbytes,
        rxbytes: s.rxbytes,
        irq: s.irq,
    }
}

#[test]
fn libcsps_own_cmp_client_reads_the_ports_interface_counters() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add(IFNAME, R_ADDR, NETMASK, true).unwrap();
    node.bind(csp_core::ports::CMP).unwrap();

    // Leg 1: a real `csp_cmp_if_stats`, which sets CSP_O_CRC32 on the way out.
    let request = c_cmp_if_stats_start(R_ADDR, IFNAME);
    assert_eq!(
        request.len(),
        1,
        "libcsp's client puts exactly one request frame on the wire"
    );
    let req_id = csp_core::Id::decode(VERSION, &request[0]).expect("the C's own frame");
    assert_eq!(
        req_id.flags & csp_core::flags::CRC32,
        csp_core::flags::CRC32,
        "the guard on the whole scenario: `csp_cmp` sends with CSP_O_CRC32, and without \
         that flag this is the request `node_cmp_server.rs` already covers. flags {:#04x}",
        req_id.flags
    );

    // Leg 2: the port serves it. The request has to survive the checksum check on the way
    // in, and the reply has to carry one back out.
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &request[0])
        .expect("the C's own request frame");
    node.router.receive(p, 0);

    let identity = node.identity();
    let mut replies = Vec::new();
    let mut served = csp_core::cmp::IfStats::default();
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    // Snapshot the counters *now*, with the request already accounted for,
                    // and hand those to the hook. Copied out, so the borrow ends here.
                    served = node
                        .ifaces
                        .get(0)
                        .map(|e| as_cmp(&e.stats))
                        .unwrap_or_default();
                    let mut hooks = Report {
                        name: IFNAME,
                        stats: served,
                    };
                    let mut out = [0u8; 256];
                    let answered = pkt.with_payload(|got| {
                        let q = csp_core::cmp::parse_request(got).ok()?;
                        csp::service::respond_cmp(q, &identity, VERSION, &mut hooks, &mut out)
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
    assert_eq!(replies.len(), 1, "one request, one reply frame");

    // Leg 3: hand it to the C's router, which is what releases `csp_read`.
    c_node_exchange(&replies[0], &[]);

    // libcsp's own verdict. A `CSP_ERR_TIMEDOUT` here means the reply never survived the
    // client's router -- the failure an operator cannot tell from a dead satellite.
    let got = c_cmp_if_stats_join().unwrap_or_else(|e| {
        panic!(
            "libcsp's own CMP client refused the port's IF_STATS reply: error {e} \
             (-3 is CSP_ERR_TIMEDOUT: no reply reached the application)"
        )
    });

    assert_eq!(
        got.interface, IFNAME,
        "the reply must name the interface that was asked about"
    );
    // The counters the port served, read back the way the operator's tool reads them.
    // Comparing against what the node held rather than against a literal is what makes this
    // about the reply rather than about the traffic.
    assert_eq!(
        (
            got.tx,
            got.rx,
            got.tx_error,
            got.rx_error,
            got.drop,
            got.autherr,
            got.frame,
            got.txbytes,
            got.rxbytes,
            got.irq
        ),
        (
            served.tx,
            served.rx,
            served.tx_error,
            served.rx_error,
            served.drop,
            served.autherr,
            served.frame,
            served.txbytes,
            served.rxbytes,
            served.irq
        ),
        "every counter must survive the round trip in the order and byte order libcsp reads"
    );
    assert!(
        got.rx > 0,
        "the request itself arrived on this interface, so rx cannot be zero -- an \
         all-zero reply would satisfy the comparison above vacuously"
    );
}
