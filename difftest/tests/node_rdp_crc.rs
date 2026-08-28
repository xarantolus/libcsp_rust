//! An RDP connection the port opens **with `CSP_O_CRC32`**, against a real C node.
//!
//! # Why this file exists
//!
//! `node_cmp_if_stats.rs` found that the port set `CSP_FCRC32` on a packet and never
//! appended the checksum, so a real libcsp peer's router verified, failed and dropped it.
//! The fix appends the trailer to everything this node originates, matching
//! `csp_send_direct_iface`'s `if (from_me)` block (`csp_io.c:249-271`).
//!
//! Originated traffic includes **RDP control**: `csp_rdp_send_cmp` goes through
//! `csp_send_direct` with `from_me` set like anything else, so a `SYN` on a checksummed
//! connection carries a checksum. That is a second code path in the port — the router's
//! `queue_rdp`, not the node's `route_from` — and fixing it without driving it would be the
//! same mistake in a new place.
//!
//! Here the handshake itself is the assertion. A `SYN` whose checksum is missing or wrong is
//! dropped by `csp_route_security_check` before the C's RDP machine ever sees it, so the C
//! answers nothing and the connection never opens — from the port's side, indistinguishable
//! from a peer that is not there.
//!
//! # Process isolation
//!
//! One scenario per binary, for the reason `node_rdp_peer.rs` documents.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const NETMASK: u16 = 12;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;
const PORT: u8 = 12;
const R_ADDR: u16 = C_ADDR + 1;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

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
fn a_checksummed_rdp_handshake_is_accepted_by_a_real_c_node() {
    use csp_core::security::opts;

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
        .connect(2, C_ADDR, PORT, opts::RDP_REQ | opts::CRC32_REQ, 1000)
        .expect("an RDP connect with a checksum is accepted");

    let syn = drain(&mut node, 1000);
    assert_eq!(syn.len(), 1, "connect puts one SYN on the wire");

    // The guard on the scenario: without the flag this is `node_rdp.rs` again.
    let syn_id = csp_core::Id::decode(VERSION, &syn[0]).expect("our own frame");
    assert_eq!(
        syn_id.flags & csp_core::flags::CRC32,
        csp_core::flags::CRC32,
        "the SYN must claim a checksum, or the C has nothing to verify. flags {:#04x}",
        syn_id.flags
    );
    // And the trailer must be there, not just the claim. A SYN is a fixed size, so the
    // length alone separates "checksummed" from "flagged and empty" — which is the exact
    // bug this file exists for.
    assert_eq!(
        syn[0].len(),
        6 + csp_core::rdp::HEADER_LEN + csp_core::rdp::SYN_OPTIONS_LEN + 4,
        "header + RDP header + option block + a four-byte checksum"
    );

    let answer = c_node_exchange(&syn[0], &[]);
    assert_eq!(
        answer.tx.len(),
        1,
        "a real C node must answer a checksummed SYN with SYN|ACK -- zero frames means \
         csp_route_security_check threw it away before RDP saw it"
    );

    let mut inject = node.packet().expect("pool");
    inject.set_frame(VERSION, &answer.tx[0]).expect("frame");
    node.router.receive(inject, 0);
    let third = drain(&mut node, 1100);
    assert_eq!(
        third.len(),
        1,
        "the initiator sends the handshake's final ACK"
    );
    // The third leg is built by a *different* function from the SYN -- `queue_rdp`, which
    // answers an incoming header, rather than `queue_rdp_from_tick`, which the connect
    // queues. Asserting its length is what separates the two: without it, mutating the
    // append out of `queue_rdp` alone changed nothing any test could see, because the C
    // opens the connection on the data packet that follows instead.
    assert_eq!(
        third[0].len(),
        6 + csp_core::rdp::HEADER_LEN + 4,
        "header + a bare RDP control header + a four-byte checksum"
    );
    for f in &third {
        c_node_exchange(f, &[]);
    }
    assert!(
        node.is_rdp_open(conn),
        "the handshake completes over a checksummed connection"
    );

    // And data on it survives the same round trip, through the other egress path: this one
    // goes out via `Node::send`, not the router's control queue.
    const BODY: &[u8] = b"checksummed payload";
    let mut p = node.packet().expect("pool");
    p.set_payload(BODY).unwrap();
    let frame = match node.send(conn, p, 1150) {
        Ok(Outbound::Transmit { mut packet, .. }) => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("send on an open connection: {other:?}"),
    };
    let got = c_node_exchange(&frame, &[PORT]);
    assert_eq!(
        got.delivered.len(),
        1,
        "the C's application must receive the datagram -- a bad checksum is dropped by its \
         router and never reaches the bound port"
    );
    assert_eq!(
        got.delivered[0].payload, BODY,
        "and with both the checksum and the RDP trailer stripped"
    );

    let _ = c_node_release(PORT);
}
