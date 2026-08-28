//! A **real libcsp opens an RDP connection to the port**, and the port answers it.
//!
//! # The direction that flies, and the only one never driven
//!
//! Measured across the seven RDP files in this directory: every one has the port call
//! `connect` and the C node answer from its router. `CSP_SO_RDPREQ` appears nowhere in the
//! harness. So the port's **responder** path — take a SYN off the wire from a real libcsp,
//! answer `SYN|ACK`, accept the third leg — had never been driven by a real initiator.
//!
//! That is the direction a satellite is in. Ground opens the connection; the flight node
//! answers. The port's `SYN|ACK` *fields* are compared against libcsp's, by the corpus record
//! `rdp::a_syn_is_answered_with_syn_ack` — but a field comparison cannot answer the question
//! an operator actually has, which is whether a stock libcsp **accepts** it and reports the
//! connection open. `csp_connect` returning `NULL` after a complete-looking exchange is what
//! a broken responder looks like from the ground, and nothing here could have seen it.
//!
//! # Why a thread
//!
//! `csp_rdp_connect` sends the SYN and then blocks on `tx_wait` until a router task releases
//! it (`csp_rdp.c:836`), retrying once and giving up after `conn_timeout`. This harness has
//! no router task, so `csp_connect` runs on its own thread and this test turns the crank —
//! the division of labour libcsp is written for. The verdict it reports on join is libcsp's
//! own, not something the harness computed.
//!
//! # What the controls showed, including one that could not bite
//!
//! Answering with `SYN` and no `ACK` makes libcsp refuse and `csp_connect` return `NULL` —
//! this file's central assertion. Leaving the RDP trailer on delivery puts five stray bytes
//! in the application's buffer. But acknowledging the **wrong sequence number** changes
//! nothing: libcsp's `SYN_SENT` arm takes any `SYN|ACK`, assigns
//! `snd_una = ack_nr + 1` and opens (`csp_rdp.c:596-606`), without ever comparing `ack_nr`
//! against the `snd_iss` it sent. So an end-to-end test cannot pin that field, and this one
//! does not pretend to; the corpus record `rdp::a_syn_is_answered_with_syn_ack` carries
//! `ack: 1000` and pins it by field comparison instead.
//!
//! # Process isolation
//!
//! One scenario per binary, for the reason `node_rdp_peer.rs` documents.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
/// The C node, which initiates.
const C_ADDR: u16 = 9;
/// The port, which answers.
const R_ADDR: u16 = 10;
const NETMASK: u16 = 12;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;
const PORT: u8 = 12;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// Everything the port wants to put on the wire, framed and ready to inject.
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

fn feed(node: &mut TestNode, frame: &[u8]) {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, frame).expect("a frame the C emitted");
    node.router.receive(p, 0);
}

#[test]
fn a_real_libcsp_opens_an_rdp_connection_to_the_port_and_gets_data_through() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
    node.bind(PORT).unwrap();

    // Leg 1: a real `csp_connect(..., CSP_SO_RDPREQ)`.
    let syn = c_rdp_connect_start(R_ADDR, PORT);
    assert_eq!(syn.len(), 1, "libcsp puts exactly one SYN on the wire");
    let syn_id = csp_core::Id::decode(VERSION, &syn[0]).expect("the C's own frame");
    assert_eq!(
        syn_id.flags & csp_core::flags::RDP,
        csp_core::flags::RDP,
        "the guard on the whole scenario: without CSP_SO_RDPREQ this is an ordinary \
         datagram and proves nothing about the responder path. flags {:#04x}",
        syn_id.flags
    );

    // Leg 2: the port answers.
    feed(&mut node, &syn[0]);
    let syn_ack = drain(&mut node, 1000);
    assert_eq!(
        syn_ack.len(),
        1,
        "the port must answer a real libcsp SYN with exactly one frame"
    );

    // Leg 3: libcsp reads the port's SYN|ACK and replies. `c_node_exchange` turns the C's
    // router, which is what releases the semaphore `csp_connect` is blocked on.
    let third = c_node_exchange(&syn_ack[0], &[]);
    assert_eq!(
        third.tx.len(),
        1,
        "a real libcsp must answer the port's SYN|ACK with the handshake's final ACK -- \
         zero frames here means it refused what the port sent"
    );
    feed(&mut node, &third.tx[0]);
    for f in drain(&mut node, 1100) {
        c_node_exchange(&f, &[]);
    }

    // libcsp's own verdict, which is the assertion this file exists for.
    assert!(
        c_rdp_connect_join(),
        "csp_connect must return an open connection -- a NULL here is what a satellite \
         that cannot be reached over RDP looks like from the ground"
    );

    // And the connection carries traffic: an application datagram from the real initiator,
    // delivered to the port's bound port with the RDP trailer removed. Without this the
    // handshake could complete onto a connection that transports nothing, which is the
    // shape of the `Router::forward` failure.
    const BODY: &[u8] = b"from a real initiator";
    let data = c_rdp_initiator_send(BODY);
    assert_eq!(data.len(), 1, "the C put its datagram on the wire");
    feed(&mut node, &data[0]);

    let mut got: Vec<Vec<u8>> = Vec::new();
    loop {
        match node.work(1200) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(p)) = node.read(conn) {
                    got.push(p.with_payload(|d| d.to_vec()));
                    drop(p);
                }
            }
            Routed::Respond { packet, .. } => {
                let mut r = node.take_forwarded(packet).expect("slot");
                r.prepend_header(VERSION).unwrap();
                let f = r.with_frame(|x| x.to_vec());
                drop(r);
                c_node_exchange(&f, &[]);
            }
            Routed::Idle => break,
            _ => continue,
        }
    }

    c_rdp_initiator_close();

    assert_eq!(got.len(), 1, "the datagram reaches the bound port");
    assert_eq!(
        got[0], BODY,
        "and arrives intact, with the RDP trailer stripped"
    );
}
