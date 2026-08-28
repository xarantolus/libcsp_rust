//! A stream a **real C node originates over RDP**, reassembled by the port.
//!
//! # The half of the fourth cell that was missing
//!
//! `{plain, SFP} x {no RDP, RDP}` has four cells, and by the last count all four had
//! node-level evidence. Measured this cycle: the RDP-SFP cell had it in **one direction
//! only**.
//!
//! | direction | plain | SFP |
//! |---|---|---|
//! | port sends, C receives | `diff.rs`, `node_v2.rs` | `node_sfp.rs`, `node_sfp_rdp.rs` |
//! | C sends, port receives | `diff.rs`, `node_rdp_peer.rs` | `node_sfp.rs` — **but over a plain connection** |
//!
//! `node_sfp.rs::the_port_reassembles_what_a_real_csp_sfp_send_fragments` drives
//! `csp_sfp_send`, but through `shim_sfp_send`, which opens the connection with
//! `csp_connect(..., 0)` — no RDP. So every fragment the port's reassembler had ever seen
//! from a real libcsp sender carried exactly **one** trailer.
//!
//! # Why that direction is not symmetry for its own sake
//!
//! `node_sfp_rdp.rs` states the rule: `csp_rdp_send` appends its header at `data[length]`
//! *after* `csp_sfp_header_add` has appended its own, so a fragment on an RDP connection is
//! `[body][sfp trailer][rdp trailer]` and the receiver strips them in the reverse order.
//! That file proves the port **appends** them in the right order — a C node strips them and
//! gets the message. Stripping is a different code path in the port: the router unwraps RDP,
//! `Delivery::classify` looks at the flags, and `Stream` reads the SFP trailer off what is
//! left. Nothing had ever driven it with two trailers on the wire.
//!
//! The failure mode is the one the other file names, pointed the other way: read the RDP
//! trailer as part of the SFP offset and there is no crash and no error — just a connection
//! that acknowledges every frame and delivers nothing. On a satellite that is a link the
//! telemetry says is healthy while no file ever arrives.
//!
//! # Process isolation
//!
//! One scenario per binary, for the reason `node_rdp_peer.rs` documents: an RDP connection
//! leaves durable state on the C node and libcsp has no per-test reset.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;
/// The C node's second interface. Not the peer's address: pointing it at the peer gives the
/// C two routes to the same place and it answers the SYN twice.
const EGRESS_ADDR: u16 = 20;
const PORT: u8 = 10;
const R_ADDR: u16 = C_ADDR + 1;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// Long enough to need several fragments at the MTU below, so the offset field is exercised.
/// A one-fragment stream reassembles correctly even if the offset is read out of the wrong
/// bytes entirely.
const MESSAGE: &[u8] = b"a stream a real libcsp sender cut up and pushed through its own \
reliable transport, long enough that the offsets have to be read from the right place";

/// Everything the node wants to put on the wire, framed and ready to inject.
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
fn a_stream_a_real_c_node_sends_over_rdp_is_reassembled_by_the_port() {
    /// A payload budget per fragment, small enough that `MESSAGE` spans several.
    const MTU: u32 = 40;

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

    // Legs 1-3 of the handshake. `node_rdp.rs` asserts the shape of each; here it is only
    // the prerequisite for having a real RDP connection to send a stream over.
    let conn = node
        .connect(2, C_ADDR, PORT, csp_core::security::opts::RDP_REQ, 1000)
        .expect("an RDP connect is accepted");
    let syn = drain(&mut node, 1000);
    assert_eq!(syn.len(), 1, "connect puts one SYN on the wire");
    let answer = c_node_exchange(&syn[0], &[]);
    assert_eq!(answer.tx.len(), 1, "the C answers with SYN|ACK");
    let mut inject = node.packet().expect("pool");
    inject.set_frame(VERSION, &answer.tx[0]).expect("frame");
    node.router.receive(inject, 0);
    for f in drain(&mut node, 1100) {
        c_node_exchange(&f, &[]);
    }
    assert!(node.is_rdp_open(conn), "the connection is open");

    // The C cannot originate on a connection its application has not accepted, and it only
    // accepts once something has been delivered on it.
    let mut hello = node.packet().expect("pool");
    hello.set_payload(b"open it").unwrap();
    let opener = match node.send(conn, hello, 1150) {
        Ok(Outbound::Transmit { mut packet, .. }) => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("send on an open connection: {other:?}"),
    };
    for reply in &c_node_exchange(&opener, &[]).tx {
        let mut back = node.packet().expect("pool");
        if back.set_frame(VERSION, reply).is_ok() {
            node.router.receive(back, 0);
        }
    }
    for f in drain(&mut node, 1150) {
        c_node_exchange(&f, &[]);
    }

    // Now libcsp cuts the message up and pushes it through its own RDP.
    let frames = c_node_sfp_send_on(PORT, MESSAGE, MTU)
        .unwrap_or_else(|e| panic!("csp_sfp_send refused the stream on the RDP connection: {e}"));
    assert!(
        frames.len() >= 3,
        "the message must span several fragments: got {}",
        frames.len()
    );
    // The guard on the whole scenario. Without this the test is `node_sfp.rs` again: if
    // `csp_sfp_send` had gone out on a plain connection the fragments would carry FRAG
    // alone, one trailer, and reassembling them would prove nothing new. Measured 0x12 on
    // every frame -- FRAG | RDP.
    for (i, f) in frames.iter().enumerate() {
        let id = csp_core::Id::decode(VERSION, f).expect("a frame the C emitted");
        assert_eq!(
            id.flags & (csp_core::flags::FRAG | csp_core::flags::RDP),
            csp_core::flags::FRAG | csp_core::flags::RDP,
            "fragment {i} must carry both trailers: flags {:#04x}",
            id.flags
        );
    }

    // Feed one frame, then let the port answer, and repeat — a receive loop, not a dump.
    // Pushing all of them in first overruns the connection's receive queue, which
    // `node_sfp.rs` records as the mistake that looked like a reassembly failure.
    let mut pending = frames.iter();
    let mut now = 1200u32;
    let mut feed = |node: &mut TestNode| -> bool {
        let Some(f) = pending.next() else {
            return false;
        };
        let mut p = node.packet().expect("pool");
        p.set_frame(VERSION, f).expect("a frame the C emitted");
        node.router.receive(p, 0);
        // Acknowledge, or the C's send window closes and the rest never arrives.
        for out in drain(node, now) {
            c_node_exchange(&out, &[]);
        }
        now += 10;
        true
    };
    feed(&mut node);

    let first = node
        .read(conn)
        .expect("read")
        .expect("the connection had no first fragment");

    struct ConnSource<'s, 'a, F: FnMut(&mut TestNode<'a>) -> bool> {
        node: &'s mut TestNode<'a>,
        conn: csp::conn::Handle,
        feed: F,
    }
    impl<'a, F: FnMut(&mut TestNode<'a>) -> bool> csp::delivery::PacketSource<'a, 24, 300>
        for ConnSource<'_, 'a, F>
    {
        fn next_packet(&mut self, _timeout_ms: u32) -> Option<csp::Packet<'a, 24, 300>> {
            loop {
                if let Ok(Some(p)) = self.node.read(self.conn) {
                    return Some(p);
                }
                if !(self.feed)(self.node) {
                    return None;
                }
            }
        }
    }

    let mut src = ConnSource {
        node: &mut node,
        conn,
        feed,
    };
    match csp::delivery::Delivery::classify(first, &mut src) {
        csp::delivery::Delivery::Stream(mut st) => {
            let mut buf = [0u8; 512];
            let got = st
                .read_to_slice(2000, &mut buf)
                .expect("the port must reassemble a stream a real C node sent over RDP");
            assert_eq!(
                &buf[..got],
                MESSAGE,
                "the application must get back exactly what the C application sent -- both \
                 trailers removed, in the right order"
            );
        }
        csp::delivery::Delivery::Datagram(_) => {
            panic!("the C's fragments must classify as a stream, not a datagram")
        }
    }

    let _ = c_node_release(PORT);
}
