//! **libcsp's own `csp_cmp_route_set_v2`** rewriting the port's routing table.
//!
//! # Why this one
//!
//! Measured after the CLOCK work: of the nine CMP codes, IDENT had a hand-rolled C client,
//! IF_STATS and CLOCK libcsp's real one, PEEK_V2 a real `csp_transaction`. `ROUTE_SET_V2`
//! had no client at all — and it is the code by which ground rewrites a satellite's routing
//! table. A route set wrong strands every packet behind it; a route set right but *reported*
//! wrong makes ground retry, or move on believing it failed.
//!
//! # What a waiting client sees
//!
//! `csp_cmp_route_set_v2_handler` (`csp_cmp_route.c:32`) resolves the interface by name,
//! calls `csp_rtable_set`, and on success echoes the request back unchanged as the reply,
//! `sizeof(struct csp_cmp_route_set_v2_msg)` = 19 bytes. On any failure — unknown
//! interface, table refuses — it returns `CSP_ERR_INVAL` and `csp_service_handler` sends
//! nothing, so the client times out. The port routes through `Hooks::route_set`, which the
//! integrator implements against whatever table the node actually has.
//!
//! Every field here has a distinct byte pattern so a transposition of `dest_node` and
//! `next_hop_via` — the two `u16`s that sit side by side — shows in the hook and in the echo.

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

/// v2 addresses are 14 bits; all three below fit and differ in both bytes.
const DEST: u16 = 0x1234;
const VIA: u16 = 0x2B3C;
const PREFIX: u16 = 10;
/// Ten characters: the longest name `CSP_CMP_ROUTE_IFACE_LEN` (11, with NUL) carries.
const IFNAME: &str = "0123456789";
/// `sizeof(struct csp_cmp_route_set_v2_msg)`.
const ROUTE_SET_V2_LEN: usize = 19;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// The integrator's routing table. Records what it was asked, and can refuse.
struct Table {
    accept: bool,
    seen: Option<(u16, u16, String, u16)>,
}

impl csp::hooks::Hooks<24, 300> for Table {
    fn route_set(&mut self, dest: u16, netmask: u16, iface: &str, via: u16) -> bool {
        self.seen = Some((dest, netmask, iface.to_owned(), via));
        self.accept
    }
}

/// Serve one CMP request and return the reply frames, which may be none.
fn serve(node: &mut TestNode, request: &[u8], hooks: &mut Table) -> Vec<Vec<u8>> {
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

fn fresh<'a>(storage: &'a CspStorage<8, 24, 300, 64, 8>) -> TestNode<'a> {
    let mut node: TestNode = Node::new(storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(csp_core::ports::CMP).unwrap();
    node
}

#[test]
fn libcsps_own_route_set_client_rewrites_the_ports_table() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    let mut table = Table {
        accept: true,
        seen: None,
    };

    let req = c_cmp_route_set_v2_start(R_ADDR, DEST, PREFIX, VIA, IFNAME);
    assert_eq!(req.len(), 1, "one request frame");
    let replies = serve(&mut node, &req[0], &mut table);
    assert_eq!(replies.len(), 1, "an accepted route_set is answered");
    c_node_exchange(&replies[0], &[]);

    let got = c_cmp_route_set_v2_join().unwrap_or_else(|e| {
        panic!("libcsp refused the port's ROUTE_SET_V2 reply: {e} (CSP_ERR_TIMEDOUT is -3)")
    });
    assert_eq!(
        table.seen.as_deref_tuple(),
        Some((DEST, PREFIX, IFNAME, VIA)),
        "the table must be handed exactly what ground sent: destination, prefix length, \
         interface name, next hop -- dest and via sit side by side on the wire and \
         differ in every byte, so a transposition shows here"
    );
    assert_eq!(
        got,
        CRouteSet {
            dest: DEST,
            netmask: PREFIX,
            via: VIA,
            interface: IFNAME.to_owned(),
        },
        "and the reply echoes the request the C way: same fields, same order, the full \
         ten-character interface name"
    );
}

#[test]
fn a_refused_route_set_is_silence_not_a_reply() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(
        VERSION,
        C_ADDR,
        NETMASK,
        EGRESS_ADDR,
        THIRD_ADDR
    ));

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = fresh(&storage);
    let mut table = Table {
        accept: false,
        seen: None,
    };

    let req = c_cmp_route_set_v2_start(R_ADDR, DEST, PREFIX, VIA, "nosuch");
    assert_eq!(req.len(), 1, "one request frame");
    let replies = serve(&mut node, &req[0], &mut table);
    assert_eq!(
        replies.len(),
        0,
        "a refused route_set must send nothing: the C returns CSP_ERR_INVAL for an \
         unknown interface and csp_service_handler discards the reply"
    );
    assert!(
        table.seen.is_some(),
        "the table was still asked -- 'refused' has to mean the hook said no"
    );
    assert_eq!(
        c_cmp_route_set_v2_join(),
        Err(-3),
        "libcsp must report CSP_ERR_TIMEDOUT; anything else and ground would read a \
         route that was never installed as installed"
    );
}

/// `Option<(u16, u16, String, u16)>` compared against borrowed strings.
trait AsDerefTuple {
    fn as_deref_tuple(&self) -> Option<(u16, u16, &str, u16)>;
}

impl AsDerefTuple for Option<(u16, u16, String, u16)> {
    fn as_deref_tuple(&self) -> Option<(u16, u16, &str, u16)> {
        self.as_ref().map(|(a, b, c, d)| (*a, *b, c.as_str(), *d))
    }
}

#[allow(dead_code)]
const _: () = assert!(ROUTE_SET_V2_LEN == csp_core::cmp::RouteSetV2::LEN);
