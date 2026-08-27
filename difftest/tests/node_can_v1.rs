//! CFP **v1** fragmentation and reassembly, against the real `csp_can1_rx` / `csp_can1_tx`.
//!
//! # Why a separate binary, and why this exists at all
//!
//! `csp_can_rx` dispatches on `csp_conf.version`, which is init-only (SCOPE.md deviation 18)
//! — so the v1 half of the interface is unreachable from the v2 file next door. Cargo gives
//! each integration-test file its own process, which is the reset.
//!
//! `node_can.rs` closed the gap that `csp_if_can.c` had never been compiled, and covered
//! **v2 only**. That left the v1 half exactly as it was: measured on this branch,
//! `csp_core::cfp::V1Reassembler` had **no caller anywhere outside its own module** — no
//! golden vector, no differential test, nothing. `V1Fragmenter` had one, in the golden-vector
//! generator. So v1 reassembly was a reading of `csp_can1_rx` and nothing else.
//!
//! # The two layouts are not variations on each other
//!
//! CFP 1 puts the whole 4-byte CSP header *and* a 2-byte total length in the first frame's
//! data, leaving two payload bytes; CFP 2 puts a 4-byte header extension there and leaves
//! four. CFP 1 counts down `remain` in the identifier and has no end bit; CFP 2 has begin and
//! end bits and a fragment counter. Nothing about v2 passing implies v1 does.

use csp_core::cfp;
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V1;
const C_ADDR: u16 = 9;
/// A different address: `csp_can1_tx` loops a self-addressed packet back without framing.
const R_ADDR: u16 = 20;
/// v1 has 5 host bits, so 3 network bits puts 9 and 20 in different subnets.
const NETMASK: u16 = 3;
const PORT: u8 = 10;

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, 24, 16),
        "C node came up at v1"
    );
    assert!(c_can_init(C_ADDR, NETMASK), "the CAN interface came up");
    assert_eq!(c_node_bind(PORT), 0, "bind port {PORT}");
}

fn body(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(11).wrapping_add(5))
        .collect()
}

/// Fragment with the port's CFP v1 fragmenter, addressed to the C node.
fn port_fragments(payload: &[u8], ident: u16) -> Vec<CanFrame> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: R_ADDR,
        dst: C_ADDR,
        dport: PORT,
        sport: 40,
    };
    let mut header = [0u8; 4];
    id.encode(VERSION, &mut header).expect("a v1 header");
    cfp::V1Fragmenter::new(header, R_ADDR, C_ADDR, ident, payload)
        .map(|f| (f.id, f.data().to_vec()))
        .collect()
}

/// The port cuts a v1 packet into CAN frames; a real `csp_can1_rx` puts it back together.
///
/// The lengths straddle CFP 1's own boundaries: the first frame carries header(4) +
/// length(2) + at most **two** payload bytes, and each later frame eight. So 2 and 3 are the
/// first-frame edge, 10 and 11 the second.
#[test]
fn a_real_csp_can1_rx_reassembles_what_the_port_fragments() {
    let _g = lock();
    setup();

    for (i, len) in [1usize, 2, 3, 10, 11, 100].into_iter().enumerate() {
        let payload = body(len);
        let frames = port_fragments(&payload, i as u16);
        assert!(!frames.is_empty(), "{len} bytes must produce a frame");

        for (n, f) in frames.iter().enumerate() {
            assert_eq!(
                c_can_rx(f),
                0,
                "libcsp refused frame {n} of {} for a {len}-byte payload",
                frames.len()
            );
        }

        let got = c_node_drain(&[PORT]);
        assert_eq!(
            got.delivered.len(),
            1,
            "a {len}-byte payload must arrive as exactly one message (frames: {})",
            frames.len()
        );
        let d = &got.delivered[0];
        assert_eq!(d.payload, payload, "carrying the bytes unchanged ({len})");
        assert_eq!((d.src, d.dst, d.dport, d.sport), (R_ADDR, C_ADDR, PORT, 40));
    }
}

/// A real `csp_can1_tx` cuts a packet up; the port's `V1Reassembler` puts it back together.
///
/// This is the direction that had nothing at all behind it.
#[test]
fn the_port_reassembles_what_a_real_csp_can1_tx_fragments() {
    let _g = lock();
    setup();

    for len in [1usize, 2, 3, 10, 11, 100] {
        let payload = body(len);
        let frames = c_can_send(R_ADDR, PORT, 40, &payload);
        assert!(
            !frames.is_empty(),
            "the C must emit frames for a {len}-byte payload"
        );

        let mut re = cfp::V1Reassembler::new();
        let mut out = [0u8; 512];
        let mut done = None;
        for (n, (id, data)) in frames.iter().enumerate() {
            match re.push(*id, data, &mut out) {
                Ok(Some(hdr)) => {
                    assert_eq!(
                        n,
                        frames.len() - 1,
                        "the port must not finish early: frame {n} of {}",
                        frames.len()
                    );
                    done = Some((hdr, re.received()));
                }
                Ok(None) => {}
                Err(e) => panic!("the port refused the C's frame {n} of a {len}-byte: {e:?}"),
            }
        }
        let (hdr, n) = done.unwrap_or_else(|| {
            panic!(
                "the port never completed a {len}-byte transfer the C sent in {} frame(s)",
                frames.len()
            )
        });
        assert_eq!(&out[..n], &payload[..], "payload for {len} bytes");
        assert_eq!(
            (hdr.src, hdr.dst, hdr.dport, hdr.sport),
            (C_ADDR, R_ADDR, PORT, 40),
            "and the CSP header the C packed into the first frame"
        );
    }
}

/// Two senders interleaved, distinguished **only** by the source field of the identifier.
///
/// `CFP_ID_CONN_MASK` for v1 is source, destination and the transfer identifier. Holding the
/// identifier equal is deliberate: giving the two transfers different identifiers as well
/// would let those keep the pbufs apart, and the source field would never be under test.
/// That is exactly the hole the v2 version of this test had until a control caught it.
#[test]
fn two_v1_senders_interleaved_do_not_contaminate_each_other() {
    let _g = lock();
    setup();

    let one = body(30);
    let two: Vec<u8> = body(30).iter().map(|b| !b).collect();

    let mk = |src: u16, payload: &[u8], ident: u16| -> Vec<CanFrame> {
        let id = Id {
            pri: 2,
            flags: 0,
            src,
            dst: C_ADDR,
            dport: PORT,
            sport: 40,
        };
        let mut header = [0u8; 4];
        id.encode(VERSION, &mut header).expect("a v1 header");
        cfp::V1Fragmenter::new(header, src, C_ADDR, ident, payload)
            .map(|f| (f.id, f.data().to_vec()))
            .collect()
    };
    const SAME_IDENT: u16 = 0;
    let a = mk(R_ADDR, &one, SAME_IDENT);
    let b = mk(R_ADDR + 1, &two, SAME_IDENT);
    assert!(a.len() > 2 && b.len() > 2, "both must span several frames");
    assert_ne!(a[0].0, b[0].0, "and differ only by the source field");

    let mut i = 0;
    loop {
        let mut any = false;
        if i < a.len() {
            assert_eq!(c_can_rx(&a[i]), 0, "sender A frame {i}");
            any = true;
        }
        if i < b.len() {
            assert_eq!(c_can_rx(&b[i]), 0, "sender B frame {i}");
            any = true;
        }
        if !any {
            break;
        }
        i += 1;
    }

    let got = c_node_drain(&[PORT]);
    assert_eq!(got.delivered.len(), 2, "both transfers complete");
    let mut payloads: Vec<&Vec<u8>> = got.delivered.iter().map(|d| &d.payload).collect();
    payloads.sort();
    let mut want = vec![&one, &two];
    want.sort();
    assert_eq!(payloads, want, "and neither picked up a byte of the other");
}
