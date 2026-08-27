//! A stream the port sends, reassembled by a real C node's application.
//!
//! # The cell of the delivery matrix nothing covered
//!
//! `{plain, SFP} x {no RDP, RDP}` has four cells. Three had node-level evidence: plain
//! datagrams both ways (`diff.rs`, `node_v2.rs`), and SFP *received* over RDP through a
//! real router into a bound port (corpus `rdp::a_multi_fragment_stream_reassembles_over_rdp`).
//!
//! The fourth — **fragments the port emits, accepted by a C node** — had none, in either
//! sub-cell. What looked like coverage was measured on something else:
//!
//! | claim | actually measured on |
//! |---|---|
//! | `ctest/suite_sfp.c`, 12 corpus records | `csp_sfp_recv_fp` called directly, with `make_packet` packets on a hand-opened connection: no wire, no routing, no bound port |
//! | `csp-core::sfp` unit tests | the port's own fragmenter and reassembler, against each other |
//! | `rdp::a_multi_fragment_stream_reassembles_over_rdp` | the C receiving frames the *C test* built |
//!
//! Each is a true statement about the SFP codec. None of them says a C peer accepts what
//! the port sends, which is the direction that failed silently before: `Router::forward`
//! satisfied every assertion about which interface it picked while destroying the packet.
//!
//! # Both directions, eventually
//!
//! The first version of this file drove only port-fragments-to-C-reassembles, and said it
//! covered the cell. It did not: `csp_sfp_send` — the decision a real libcsp sender makes
//! about how to cut a message up — appeared in this tree exactly once, in a comment in
//! `suite_rdp.c`, and had never executed. The port's reassembler had only ever seen
//! fragments the port or a `make_packet` helper built. `node_can.rs` covers CAN both ways;
//! this file did not, and the omission was invisible because the one direction present was
//! the harder-looking one.
//!
//! # Process isolation
//!
//! `csp_conf.version` is init-only (SCOPE.md 18), and this file's C node binds a port and
//! holds a connection across calls, so it gets its own binary like the RDP files do.

use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
/// The C node, which receives.
const C_ADDR: u16 = 9;
/// The port, which sends.
const R_ADDR: u16 = 20;
const NETMASK: u16 = 12;
const THIRD_ADDR: u16 = 40;
const PORT: u8 = 10;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, R_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );
    assert_eq!(c_node_bind(PORT), 0, "bind port {PORT}");
}

/// A message long enough to need more than one fragment at any sane MTU.
const MESSAGE: &[u8] = b"the quick brown fox jumps over the lazy dog, twice over, and then \
some more so that this does not fit in a single fragment at the mtu chosen below";

/// Fragment `MESSAGE` on a connection and collect the frames the port puts on the wire.
///
/// `mtu` is a payload budget per fragment, deliberately small so the transfer is several
/// fragments: a one-fragment stream would pass even if offset handling were broken.
fn rust_stream_frames(opts: u32, mtu: usize) -> Vec<Vec<u8>> {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
    node.ifaces.add("EGRESS", R_ADDR, NETMASK, true).unwrap();
    node.route_default(0).unwrap();

    let conn = node.connect(2, C_ADDR, PORT, opts, 0).unwrap();

    let mut frames = Vec::new();
    for (offset, total, chunk) in csp_core::sfp::Fragmenter::new(MESSAGE, mtu).unwrap() {
        let mut p = node.packet().unwrap();
        p.set_payload(chunk).unwrap();
        match node.send_fragment(conn, p, offset, total, 0).unwrap() {
            Outbound::Transmit { mut packet, .. } => {
                packet.prepend_header(VERSION).unwrap();
                frames.push(packet.with_frame(|f| f.to_vec()));
            }
            other => panic!("fragment at offset {offset} did not reach a wire: {other:?}"),
        }
        // Drain anything the send queued behind it (an RDP connection queues nothing here,
        // but the loop keeps the pool from filling up over several fragments).
        while !matches!(node.work(0), Routed::Idle) {}
    }
    frames
}

/// The whole point: bytes in one end, the same bytes out of a real C application.
///
/// Plain, no RDP. If the port sets `FRAG` on every fragment and lays the SFP trailer out
/// the way `csp_sfp_header_add` does, `csp_sfp_recv_fp` reassembles `MESSAGE` exactly. If
/// it does not, the C either refuses the transfer (`CSP_ERR_SFP`) or — worse and quieter —
/// delivers each fragment as a plain datagram with eight bytes of trailer stuck on the end,
/// and the application never learns the message was cut into pieces.
#[test]
fn a_stream_the_port_sends_is_reassembled_by_a_real_c_application() {
    let _g = lock();
    setup();

    let frames = rust_stream_frames(0, 40);
    assert!(
        frames.len() >= 3,
        "the message must span several fragments for this to test offsets: got {}",
        frames.len()
    );

    match c_node_sfp_recv(&frames, PORT) {
        Ok(got) => assert_eq!(
            got, MESSAGE,
            "a real C node's application must receive exactly what the port streamed"
        ),
        Err(code) => panic!(
            "csp_sfp_recv_fp refused the port's own fragments: error {code} \
             ({} frames offered)",
            frames.len()
        ),
    }
}

/// Every fragment must carry `FRAG`, or the C never treats the transfer as a stream at all.
///
/// Checked on the wire rather than through the C, because the failure is silent on the
/// C side: without `FRAG`, `csp_sfp_header_remove` returns NULL on the first packet and
/// `csp_sfp_recv_fp` frees it and reports `CSP_ERR_SFP` — indistinguishable from a corrupt
/// peer, and a plain `csp_read` would have handed the application the trailer as payload.
#[test]
fn every_fragment_leaves_the_port_marked_as_one() {
    let _g = lock();
    setup();

    for (i, f) in rust_stream_frames(0, 40).iter().enumerate() {
        let id = Id::decode(VERSION, f).expect("a frame the port emitted decodes");
        assert!(
            id.is_fragment(),
            "fragment {i} left without FRAG set; the C reads it as a datagram \
             and the SFP trailer becomes payload"
        );
    }
}

/// The other direction: a real `csp_sfp_send` cuts the message up, the port reassembles.
///
/// Driven through the port's whole receive path — router, bound port, `Delivery::classify`,
/// `Stream::read_to_slice` over a `PacketSource` — so what is compared is what the
/// application is handed, not what a codec returned.
///
/// The MTUs matter: 40 leaves a comfortable payload per frame, 8 is the smallest the C will
/// take here and produces thirteen frames for a hundred bytes, and both are checked at a
/// length that divides evenly and one that does not.
#[test]
fn the_port_reassembles_what_a_real_csp_sfp_send_fragments() {
    let _g = lock();
    setup();

    for (len, mtu) in [(5usize, 40u32), (10, 40), (100, 40), (100, 8), (200, 40)] {
        let payload: Vec<u8> = (0..len)
            .map(|i| (i as u8).wrapping_mul(3).wrapping_add(1))
            .collect();
        let frames = c_sfp_send(R_ADDR, PORT, &payload, mtu)
            .unwrap_or_else(|e| panic!("csp_sfp_send refused {len} bytes at mtu {mtu}: {e}"));
        assert!(!frames.is_empty(), "{len}@{mtu}: the C emitted nothing");

        let storage = CspStorage::<8, 24, 300, 64, 8>::new();
        let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
        node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
        node.bind(PORT).unwrap();

        // Feed one frame, then read what it produced, and repeat — which is what a sans-io
        // application does. Pushing all of them in first overruns the connection's receive
        // queue: at mtu 8 a hundred bytes is thirteen frames and the queue holds eight, and
        // the reassembly failed with `Truncated` for lack of the fragments that were
        // dropped. Enlarging the queue would have hidden that this test was not modelling a
        // receive loop.
        let mut pending = frames.iter();
        let mut feed = |node: &mut TestNode| -> bool {
            let Some(f) = pending.next() else {
                return false;
            };
            let mut p = node.packet().expect("pool");
            p.set_frame(VERSION, f).expect("a frame the C emitted");
            node.router.receive(p, 0);
            while !matches!(node.work(0), Routed::Idle) {}
            true
        };
        feed(&mut node);

        let conn = node
            .accept()
            .unwrap_or_else(|| panic!("{len}@{mtu}: nothing was delivered to the bound port"));
        let first = node
            .read(conn)
            .expect("read")
            .unwrap_or_else(|| panic!("{len}@{mtu}: the connection had no first fragment"));

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
                    // Nothing waiting: take delivery of the next frame off the wire. A real
                    // application blocks in its driver here; sans-io, it turns the crank.
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
        // Bound, so the `Delivery` is dropped before `storage` at the end of the iteration.
        let delivery = csp::delivery::Delivery::classify(first, &mut src);
        match delivery {
            csp::delivery::Delivery::Stream(mut st) => {
                let mut buf = [0u8; 512];
                let got = st
                    .read_to_slice(1000, &mut buf)
                    .unwrap_or_else(|e| panic!("{len}@{mtu}: reassembly failed: {e:?}"));
                assert_eq!(
                    &buf[..got],
                    &payload[..],
                    "{len}@{mtu}: the application must get back what the C sent"
                );
            }
            csp::delivery::Delivery::Datagram(_) => {
                panic!("{len}@{mtu}: the C's fragments must classify as a stream, not a datagram")
            }
        };
    }
}
