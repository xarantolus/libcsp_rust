//! A real C client asks the port for its identity, and gets an answer it can parse.
//!
//! # What was and was not measured before
//!
//! CMP had node-level coverage in one direction only. `node_v2.rs`'s
//! `the_cmp_client_understands_what_a_real_c_node_answers` has the *port* ask and a real C
//! node answer. The reverse — a peer asking the port — was covered by a corpus record that
//! stops one step short of the wire:
//!
//! | | what it drives | where it stops |
//! |---|---|---|
//! | the served-by-a-real-node corpus record | a real `Router`, a bound port 0, the application's `read`, `respond_cmp` | records `replies`, `reply_len`, `reply_type`, `reply_code` — the encoder's bytes, in memory. **The reply is never sent.** |
//! | the other CMP records | `respond_cmp` as a function | never near a node |
//! | golden vectors, `suite_cmp.c` | the C's own encoder and dispatcher | say nothing about the port's reply path |
//!
//! So the reply bytes were compared against the C's, and the request path was driven, but
//! nothing ever put a CMP reply on a wire or had a peer accept one. That is the same gap as
//! the forwarding bug — every assertion about what the router *decided*, none about a frame
//! arriving — and the reply path is where the port has already shipped a silent drop once.
//!
//! Both halves here come from libcsp: the request is `struct csp_cmp_ident_msg` filled in by
//! the C, and the reply is parsed by casting to the same struct, which is what
//! `csp_cmp_ident` hands its caller.

use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
/// The C node, which asks.
const C_ADDR: u16 = 9;
/// The port, which answers.
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;
const EGRESS_ADDR: u16 = 20;

const HOSTNAME: &str = "move-iiia-cdh";
const MODEL: &str = "stm32l4";
const REVISION: &str = "v2.1.0";

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

struct NoHooks;
impl csp::hooks::Hooks<24, 300> for NoHooks {}

#[test]
fn a_real_c_client_gets_an_ident_reply_it_can_parse() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );

    // The request, as libcsp builds one.
    let body = c_cmp_ident_request();
    let request = c_node_client_send(R_ADDR, csp_core::ports::CMP, &body);
    assert_eq!(
        request.len(),
        1,
        "the C client puts exactly one request frame on the wire"
    );

    // The port, serving.
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(
        &storage,
        Config::new(VERSION)
            .address(R_ADDR)
            .hostname(HOSTNAME)
            .model(MODEL)
            .revision(REVISION),
    );
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(csp_core::ports::CMP).unwrap();

    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &request[0])
        .expect("the C's own request frame");
    node.router.receive(p, 0);

    let identity = node.identity();
    let mut replies = Vec::new();
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    let mut out = [0u8; 256];
                    let n = pkt.with_payload(|got| {
                        let q = csp_core::cmp::parse_request(got).ok()?;
                        csp::service::respond_cmp(q, &identity, VERSION, &mut NoHooks, &mut out)
                            .ok()
                            .flatten()
                    });
                    let Some(n) = n else {
                        drop(pkt);
                        continue;
                    };
                    // The step the corpus record never took: put it on the wire.
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

    // And the C client, receiving.
    let got = c_node_client_recv(&replies[0])
        .expect("the reply reaches the connection the C client is waiting on");
    let (hostname, model, revision) = c_cmp_parse_ident(&got).unwrap_or_else(|| {
        panic!(
            "libcsp's own struct did not recognise the port's IDENT reply ({} bytes)",
            got.len()
        )
    });

    assert_eq!(hostname, HOSTNAME);
    assert_eq!(model, MODEL);
    assert_eq!(revision, REVISION);

    c_node_client_close();
}
