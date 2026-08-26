//! The port as RDP initiator on CSP **v1**: handshake, then data.
//!
//! # Why this is a third binary
//!
//! An RDP connection leaves durable state on the C node — a connection in `OPEN` or
//! `CLOSE_WAIT`, packets queued on it, buffers held — and libcsp has no per-test reset
//! (its own suite forks instead; `SCOPE.md` deviation 2). Sharing a process with
//! `node_v2.rs` made them interfere, and so did sharing one with each other: measured,
//! ten buffers stayed held after a burst even with every connection closed and libcsp's
//! global RDP queues flushed, so the third test in a binary started with a third of the
//! pool gone and failed depending on which order the threads ran in.
//!
//! So **one scenario per binary**. Cargo gives each integration-test file its own process,
//! which is the only reliable reset available — the same reason `node_v2.rs` is separate
//! from `diff.rs`.
//!
//! The C node here answers a `SYN` straight from its router, with no application involved:
//! the harness has always built with `CSP_USE_RDP=ON`.
//!
//! # Why v1 needs its own run
//!
//! `csp_conf.version` is init-only, so one process gets one C node at one wire version —
//! and every node-level RDP test until now was v2. v1 is not a cosmetic difference here:
//! 5 address bits against 14, a 4-byte header against 6, and 6-bit ports. The RDP trailer
//! sits at the end of the payload either way, but everything around it moves. The last
//! version-shaped assumption I did not check — a comment claiming the C node spoke no RDP
//! — turned out to be false, so this is checked rather than reasoned about.
//!
//! The topology is recomputed, not copied: with 5 host bits and a netmask of 2 the mask is
//! `0b11000`, so 9 and 20 land in subnets 8 and 16, and the port's own address 10 shares
//! subnet 8 with the C node and reaches it directly.

use csp::node::Outbound;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::Version;
use difftest::*;

const VERSION: Version = Version::V1;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
const NETMASK: u16 = 2;
const THIRD_ADDR: u16 = 26;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, NODE_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v1"
    );
}

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

/// The port's RDP **initiator** against a real C peer: handshake, then data.
///
/// `csp_rdp.c` has been in this harness's build all along (`CSP_USE_RDP=ON`), so the C node
/// here answers a `SYN` from its router with no application involved. Nothing had ever sent
/// it one — a comment in `diff.rs` even claimed "the C node under test here speaks no RDP",
/// which was simply wrong.
///
/// Driving it found that the port never sent the handshake's third leg. `csp_rdp.c:610`
/// sends `ACK(seq = snd_nxt, ack = rcv_cur)` on `SYN_SENT` + `SYN|ACK`; the port returned
/// `Action::Opened` and put nothing on the wire, leaving the peer in `SYN_RCVD` to
/// retransmit and give up. It looked like it worked only because the initiator's first
/// *data* packet also carries `ACK` and drags the peer open — so a client that connected
/// and then waited for the server to speak first had its connection die under it.
#[test]
fn an_rdp_connection_over_v1_handshakes_then_carries_data() {
    use csp_core::rdp;

    const RDP_PORT: u8 = 10;
    let _g = lock();
    setup();
    assert_eq!(c_node_bind(RDP_PORT), 0, "bind this test's own port");

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR + 1));
    node.ifaces
        .add("test", NODE_ADDR + 1, NETMASK, true)
        .unwrap();

    // Whatever the node wants to put on the wire, framed and ready to inject.
    let conn = node
        .connect(
            2,
            NODE_ADDR,
            RDP_PORT,
            csp_core::security::opts::RDP_REQ,
            1000,
        )
        .expect("an RDP connect is accepted");

    // Leg 1: our SYN.
    let syn = drain(&mut node, 1000);
    assert_eq!(syn.len(), 1, "connect puts exactly one SYN on the wire");
    // Pin the wire shape, or this test would pass just as well at v2 and prove nothing
    // about v1. A v1 header is 4 bytes against v2's 6, so the same exchange differs by two
    // bytes per frame: 4 + 24 option bytes + a 5-byte RDP trailer.
    assert_eq!(
        syn[0].len(),
        Version::V1.header_size() + rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN,
        "the SYN must be framed as v1 -- at v2 this is two bytes longer"
    );
    assert_ne!(
        Version::V1.header_size(),
        Version::V2.header_size(),
        "if the two header sizes ever match, the assertion above stops distinguishing them"
    );

    // Leg 2: the real C node answers it, from its router, with no application involved.
    let answer = c_node_exchange(&syn[0], &[RDP_PORT]);
    assert_eq!(answer.tx.len(), 1, "the C answers a SYN with one frame");
    assert_eq!(
        answer.delivered.len(),
        0,
        "a handshake is not an application message"
    );

    let mut inject = node.packet().expect("pool");
    inject
        .set_frame(VERSION, &answer.tx[0])
        .expect("the C's frame");
    node.router.receive(inject, 0);

    // Leg 3: our ACK. This is what was missing.
    let third = drain(&mut node, 1100);
    assert!(
        node.is_rdp_open(conn),
        "the C's SYN|ACK opens the connection"
    );
    assert_eq!(
        third.len(),
        1,
        "the initiator must answer SYN|ACK with the handshake's third leg -- \
         without it the peer stays in SYN_RCVD and gives up"
    );

    // It has to be an ACK naming the sequence the C proposed, or the peer ignores it.
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &third[0]).expect("our own frame");
    let (flags, ack_nr) = p.with_payload(|d| {
        let h = rdp::Header::decode(d).expect("an RDP trailer");
        (h.flags, h.ack_nr)
    });
    drop(p);
    assert_eq!(flags, rdp::ACK, "the third leg is a bare ACK");
    let syn_ack_seq = {
        let mut q = node.packet().expect("pool");
        q.set_frame(VERSION, &answer.tx[0]).unwrap();
        let seq = q.with_payload(|d| rdp::Header::decode(d).unwrap().seq_nr);
        drop(q);
        seq
    };
    assert_eq!(
        ack_nr, syn_ack_seq,
        "the ACK must name the sequence the C's SYN|ACK carried"
    );

    // The C accepts it silently -- a peer that was still unsatisfied would answer.
    let settled = c_node_exchange(&third[0], &[]);
    assert_eq!(
        settled.tx.len(),
        0,
        "the third leg provokes no further frame from the C"
    );

    // And the connection carries data to the C's application, trailer stripped.
    let mut data = node.packet().expect("pool");
    data.set_payload(b"over-rdp").unwrap();
    let mut sent = match node.send(conn, data, 1200) {
        Ok(Outbound::Transmit { packet, .. }) => packet,
        other => panic!("send on an open RDP connection: {other:?}"),
    };
    sent.prepend_header(VERSION).unwrap();
    let frame = sent.with_frame(|f| f.to_vec());
    drop(sent);

    let got = c_node_exchange(&frame, &[RDP_PORT]);
    assert_eq!(got.delivered.len(), 1, "the C's application receives it");
    assert_eq!(
        got.delivered[0].payload, b"over-rdp",
        "and gets the payload with the RDP trailer removed"
    );
}
