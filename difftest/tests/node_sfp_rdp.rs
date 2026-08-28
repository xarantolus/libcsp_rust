//! A stream the port sends **over RDP**, reassembled by a real C node's application.
//!
//! The fourth cell of `{plain, SFP} x {no RDP, RDP}`, and the one with two trailers to get
//! right at once. `csp_rdp_send` appends its header at `data[length]` *after*
//! `csp_sfp_header_add` has already appended its own, so a fragment on an RDP connection is
//! `[body][sfp trailer][rdp trailer]` and the C strips them in the reverse order. Get the
//! order wrong and the C reads four bytes of the SFP offset as an RDP sequence number —
//! which is not a crash, just a connection that silently discards everything.
//!
//! This is the *sending* half only: it proves the port appends the two trailers in the order
//! a real C receiver expects. `node_sfp_rdp_in.rs` is the other direction — a real
//! `csp_sfp_send` on an RDP connection, which the port has to strip in reverse.
//!
//! `node_sfp.rs` covers the plain half and explains what was and was not measured before.
//! One scenario per binary, for the reason `node_rdp.rs` documents: an RDP connection leaves
//! durable state on the C node and libcsp has no per-test reset.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;
/// The C node's second interface. It must not be the peer's address: pointing it at the
/// peer gave the C two routes to the same place and it answered the SYN twice.
const EGRESS_ADDR: u16 = 20;
const PORT: u8 = 10;
/// The port's own address, one above the C node's, so both sit in the same subnet.
const R_ADDR: u16 = C_ADDR + 1;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// Long enough for three fragments at the MTU below, so offsets past the first are exercised.
const MESSAGE: &[u8] = b"a stream carried inside a reliable connection, long enough to need \
several fragments so the offsets matter";

fn drain(node: &mut TestNode, now: u32) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        match node.work(now) {
            Routed::Respond { packet, .. } => {
                let mut p = node.take_forwarded(packet).expect("slot");
                p.prepend_header(VERSION).unwrap();
                out.push(p.with_frame(|f| f.to_vec()));
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    out
}

#[test]
fn a_stream_over_rdp_is_reassembled_by_a_real_c_application() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );
    assert_eq!(c_node_bind(PORT), 0, "bind port {PORT}");

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();

    let conn = node
        .connect(2, C_ADDR, PORT, csp_core::security::opts::RDP_REQ, 1000)
        .expect("an RDP connect is accepted");

    // Legs 1-3 of the handshake, against the C's router. `node_rdp.rs` asserts the shape of
    // each; here they are only the prerequisite, so this checks the outcome and moves on.
    let syn = drain(&mut node, 1000);
    assert_eq!(syn.len(), 1, "connect puts one SYN on the wire");
    let answer = c_node_exchange(&syn[0], &[]);
    assert_eq!(answer.tx.len(), 1, "the C answers with SYN|ACK");
    let mut inject = node.packet().expect("pool");
    inject.set_frame(VERSION, &answer.tx[0]).expect("frame");
    node.router.receive(inject, 0);
    let third = drain(&mut node, 1100);
    assert_eq!(third.len(), 1, "the initiator sends the third leg");
    assert!(node.is_rdp_open(conn), "the connection is open");
    c_node_exchange(&third[0], &[]);

    // The stream. `conn_sfp_mtu` already subtracts the RDP header for an RDP connection, so
    // the fragment size below is a deliberately small fraction of it -- a one-fragment
    // stream would pass with the offset field ignored entirely.
    let mtu = node.conn_sfp_mtu(conn).expect("an mtu for this connection");
    assert!(
        mtu > 40,
        "the buffer leaves room for a real fragment: {mtu}"
    );

    let mut frames = Vec::new();
    let mut now = 1200;
    for (offset, total, chunk) in csp_core::sfp::Fragmenter::new(MESSAGE, 40).unwrap() {
        let mut p = node.packet().expect("pool");
        p.set_payload(chunk).unwrap();
        let mut sent = match node.send_fragment(conn, p, offset, total, now) {
            Ok(Outbound::Transmit { packet, .. }) => packet,
            other => panic!("fragment at {offset} did not reach a wire: {other:?}"),
        };
        sent.prepend_header(VERSION).unwrap();
        frames.push(sent.with_frame(|f| f.to_vec()));
        drop(sent);
        for extra in drain(&mut node, now) {
            frames.push(extra);
        }
        now += 10;
    }
    assert!(
        frames.len() >= 3,
        "the message must span several fragments: got {}",
        frames.len()
    );

    match c_node_sfp_recv(&frames, PORT) {
        Ok(got) => assert_eq!(
            got, MESSAGE,
            "a real C application must receive the stream carried over RDP intact"
        ),
        Err(code) => panic!(
            "csp_sfp_recv_fp refused a stream the port sent over RDP: error {code} \
             ({} frames offered)",
            frames.len()
        ),
    }
}
