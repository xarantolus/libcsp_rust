//! CAN fragmentation and reassembly, against the real `csp_if_can.c`.
//!
//! # What was compared before, and what was not
//!
//! Four differential tests already covered CFP: `cfp1_identifier_packing_agrees`,
//! `cfp1_identifier_parsing_agrees_for_arbitrary_identifiers`,
//! `cfp2_identifiers_from_the_fragmenter_agree_with_the_c` and
//! `cfp2_packing_agrees_bit_for_bit`. Every one of them compares the **CAN identifier's bit
//! layout**, and every one is measured against `shim.c` expanding the macros from
//! `csp_if_can.h` itself.
//!
//! `csp_if_can.c` and `csp_if_can_pbuf.c` were in **neither** build — not difftest's source
//! list, not `ctest`'s. So not one line of the interface had ever run: not `csp_can_rx`, not
//! the reassembly pool it keys by sender, not the fragmenter that decides how a packet is
//! cut into eight-byte frames. That is the same hole `csp_bridge.c` was in, and CAN is the
//! bus this port is meant to fly on.
//!
//! # What this measures
//!
//! Both directions, end to end, in terms of what an application receives:
//!
//! - the port fragments, a real `csp_can_rx` reassembles, and the C's application on a bound
//!   port gets the bytes back;
//! - a real `csp_can*_tx` fragments, the port's reassembler puts the packet together, and the
//!   payload matches.
//!
//! # Two things the probe turned up before any of this was written
//!
//! `csp_can_tx` is declared in `csp_if_can.h` and **defined nowhere** in this fork:
//! `csp_can_add_interface` installs the static `csp_can1_tx` or `csp_can2_tx` depending on
//! the wire version, so calling the documented entry point does not link. The shim goes
//! through `iface->nexthop`, which is what the router uses.
//!
//! And `csp_can2_tx` short-circuits a packet addressed to the interface's own address
//! straight into `csp_qfifo_write` — no CAN frames at all. Which is why the two nodes here
//! address each other rather than themselves.

use csp_core::cfp;
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
/// The C node's CAN interface, and its address.
const C_ADDR: u16 = 9;
/// The port's address — a different one, or `csp_can2_tx` loops back instead of framing.
const R_ADDR: u16 = 77;
const NETMASK: u16 = 12;
const PORT: u8 = 10;

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, 20, 40),
        "C node came up at v2"
    );
    assert!(c_can_init(C_ADDR, NETMASK), "the CAN interface came up");
    assert_eq!(c_node_bind(PORT), 0, "bind port {PORT}");
}

/// Fragment `payload` with the port's own CFP v2 fragmenter, addressed to the C node.
fn port_fragments(payload: &[u8], sender_count: u32) -> Vec<CanFrame> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: R_ADDR,
        dst: C_ADDR,
        dport: PORT,
        sport: 40,
    };
    cfp::V2Fragmenter::new(id, R_ADDR, sender_count, payload)
        .map(|f| (f.id, f.data().to_vec()))
        .collect()
}

/// A payload big enough to span several frames, with a recognisable pattern.
fn body(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
        .collect()
}

/// The port cuts a packet into CAN frames; a real `csp_can_rx` puts it back together.
///
/// The lengths straddle every boundary the C's framing has: the first frame carries a
/// four-byte header extension plus at most four payload bytes, and every later frame carries
/// eight. So 4, 5, 12 and 13 are the interesting sizes, and 200 is "many frames".
#[test]
fn a_real_csp_can_rx_reassembles_what_the_port_fragments() {
    let _g = lock();
    setup();

    for (i, len) in [1usize, 4, 5, 12, 13, 200].into_iter().enumerate() {
        let payload = body(len);
        let frames = port_fragments(&payload, i as u32);
        assert!(!frames.is_empty(), "{len} bytes must produce a frame");

        for (n, f) in frames.iter().enumerate() {
            let ret = c_can_rx(f);
            assert_eq!(
                ret,
                0,
                "libcsp refused frame {n} of {} for a {len}-byte payload",
                frames.len()
            );
        }

        let got = c_node_drain(&[PORT]);
        assert_eq!(
            got.delivered.len(),
            1,
            "a {len}-byte payload must arrive as exactly one message, not {} \
             (frames sent: {})",
            got.delivered.len(),
            frames.len()
        );
        let d = &got.delivered[0];
        assert_eq!(
            d.payload, payload,
            "and carry the bytes unchanged ({len} bytes)"
        );
        assert_eq!((d.src, d.dst, d.dport, d.sport), (R_ADDR, C_ADDR, PORT, 40));
    }
}

/// The C cuts a packet into CAN frames; the port's reassembler puts it back together.
#[test]
fn the_port_reassembles_what_a_real_csp_can_tx_fragments() {
    let _g = lock();
    setup();

    for len in [1usize, 4, 5, 12, 13, 200] {
        let payload = body(len);
        let frames = c_can_send(R_ADDR, PORT, 40, &payload);
        assert!(
            !frames.is_empty(),
            "the C must emit frames for a {len}-byte payload to another address"
        );

        let mut re = cfp::V2Reassembler::new();
        let mut out = [0u8; 512];
        let mut done = None;
        for (n, (id, data)) in frames.iter().enumerate() {
            match re.push(*id, data, &mut out) {
                // `push` returns the decoded header *and* the length: CFP 2 has no length
                // field, so the count is the only way to know how much of `out` is packet.
                Ok(Some((hdr, written))) => {
                    assert_eq!(
                        n,
                        frames.len() - 1,
                        "the port must not finish early: frame {n} of {}",
                        frames.len()
                    );
                    done = Some((hdr, written));
                }
                Ok(None) => {}
                Err(e) => panic!("the port refused the C's frame {n} of {len}-byte: {e:?}"),
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
            "and the header the C packed into the first frame"
        );
    }
}

/// Two senders interleaved: each transfer must come back whole and unmixed.
///
/// `csp_if_can_pbuf.c` keys a reassembly buffer by sender, which is the only reason two
/// nodes can talk to one at the same time — the case a bus has constantly and a
/// one-transfer-at-a-time test never sees.
#[test]
fn two_senders_interleaved_do_not_contaminate_each_other() {
    let _g = lock();
    setup();

    let one = body(30);
    let two: Vec<u8> = body(30).iter().map(|b| !b).collect();

    let mk = |src: u16, payload: &[u8], sc: u32| -> Vec<CanFrame> {
        let id = Id {
            pri: 2,
            flags: 0,
            src,
            dst: C_ADDR,
            dport: PORT,
            sport: 40,
        };
        cfp::V2Fragmenter::new(id, src, sc, payload)
            .map(|f| (f.id, f.data().to_vec()))
            .collect()
    };
    // The **same** sender count on purpose. `CFP2_ID_CONN_MASK` is
    // `dst | sender | prio | sc`, so giving the two transfers different counts as well
    // would let the count keep them apart and the sender field would never be under test —
    // measured: with different counts, zeroing the fragmenter's sender field passes this.
    const SAME_COUNT: u32 = 0;
    let a = mk(R_ADDR, &one, SAME_COUNT);
    let b = mk(R_ADDR + 1, &two, SAME_COUNT);
    assert!(a.len() > 2 && b.len() > 2, "both must span several frames");
    assert_ne!(
        a[0].0, b[0].0,
        "and the two must differ only by the sender field"
    );

    // Interleave them frame by frame, which is what a shared bus does.
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
    assert_eq!(
        payloads, want,
        "and neither has picked up a byte of the other"
    );
}
