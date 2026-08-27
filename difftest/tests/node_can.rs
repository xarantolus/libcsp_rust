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

    // And now the same frames through the port's own pool, which is the half this test
    // was missing: everything above proves the *C* separates two senders.
    assert_eq!(
        port_pool_reassembles(&a, &b),
        want.into_iter().cloned().collect::<Vec<_>>(),
        "the port's Pbufs must separate them too"
    );
}

/// Interleave two senders' frames through the port's `Pbufs`, and return what came out.
///
/// `cfp::Pbufs` is the counterpart of `csp_if_can_pbuf.c` — one reassembler per sender,
/// keyed by the connection bits of the identifier. Measured on this branch: it had **no user
/// anywhere outside `cfp.rs`**, so the port's concurrent reassembly had never been driven by
/// anything but its own unit tests, and the interleaving case above proved only that the C
/// separates two senders.
fn port_pool_reassembles(a: &[CanFrame], b: &[CanFrame]) -> Vec<Vec<u8>> {
    let mut pool: cfp::Pbufs<cfp::V2Reassembler, 4> = cfp::Pbufs::new();
    // One output buffer per sender. A reassembler writes each fragment at its own offset,
    // so a buffer allocated per *frame* keeps only the last one — which is what the first
    // version of this did, and it reported two payloads of trailing bytes and zeroes.
    let mut bufs = [[0u8; 512]; 2];
    let mut out = Vec::new();
    let mut i = 0;
    loop {
        let mut any = false;
        for (which, frames) in [a, b].into_iter().enumerate() {
            let Some((id, data)) = frames.get(i) else {
                continue;
            };
            any = true;
            let key = *id & cfp::V2_CONN_MASK;
            let buf = &mut bufs[which];
            let r = pool
                .get_or_create(key, 0)
                .expect("a slot for each of two senders");
            match r.push(*id, data, buf) {
                Ok(Some((_, n))) => {
                    out.push(buf[..n].to_vec());
                    pool.release(key);
                }
                Ok(None) => {}
                Err(e) => panic!("the port's pool refused a frame: {e:?}"),
            }
        }
        if !any {
            break;
        }
        i += 1;
    }
    out.sort();
    out
}

/// **Deliberate divergence.** A sender whose transfer is truncated, then retries.
///
/// Measured, not inferred — the first version of this test asserted that the C reclaims the
/// stalled buffer after `PBUF_TIMEOUT_MS`, and that is not what it does.
/// `csp_can_pbuf_cleanup` runs only from `csp_can_pbuf_new`, and `new` is reached only when
/// `csp_can_pbuf_find` returns NULL. A stalled buffer with the *same* identifier bits is
/// found, so cleanup never runs for it however long the sender waits:
///
/// | | retrying the same key after the timeout |
/// |---|---|
/// | C | first frame `CSP_ERR_NONE`, every later one `-2 CSP_ERR_INVAL`, nothing delivered |
/// | port | the repeated `begin` restarts the transfer; the payload arrives intact |
///
/// So in the C a single lost frame wedges that sender until some *other* sender allocates a
/// buffer and incidentally runs the sweep. On a quiet bus with one talker that is indefinite.
/// The port treats a `begin` as what it says it is and starts over.
///
/// This asserts the **difference**, so a change back toward the C fails rather than passing
/// quietly.
#[test]
fn a_truncated_transfer_wedges_the_c_and_the_port_recovers() {
    let _g = lock();
    setup();
    c_clock_set(100_000);

    let whole = body(30);
    let frames = port_fragments(&whole, 5);
    assert!(frames.len() > 2, "must span several frames");

    // --- the C: stall, wait past the timeout, retry the same key ---
    for f in &frames[..frames.len() - 1] {
        assert_eq!(c_can_rx(f), 0);
    }
    assert_eq!(
        c_node_drain(&[PORT]).delivered.len(),
        0,
        "an unfinished transfer delivers nothing"
    );

    c_clock_advance(2 * 1000);
    let again = port_fragments(&whole, 5);
    let rets: Vec<i32> = again.iter().map(c_can_rx).collect();
    assert_eq!(rets[0], 0, "the C takes the repeated begin frame");
    assert!(
        rets[1..].iter().all(|&r| r != 0),
        "and then refuses the rest: {rets:?}"
    );
    assert_eq!(
        c_node_drain(&[PORT]).delivered.len(),
        0,
        "the retry is lost — the timeout did not free the stalled buffer, because \
         csp_can_pbuf_cleanup only runs when a new buffer is allocated"
    );

    // A different sender does allocate, which runs the sweep — the C's only way out.
    let other = {
        let id = Id {
            pri: 2,
            flags: 0,
            src: R_ADDR + 1,
            dst: C_ADDR,
            dport: PORT,
            sport: 40,
        };
        cfp::V2Fragmenter::new(id, R_ADDR + 1, 6, &whole)
            .map(|f| (f.id, f.data().to_vec()))
            .collect::<Vec<_>>()
    };
    for f in &other {
        assert_eq!(c_can_rx(f), 0, "a different sender is unaffected");
    }
    assert_eq!(c_node_drain(&[PORT]).delivered.len(), 1);

    // --- the port: the same stall and the same retry ---
    let mut pool: cfp::Pbufs<cfp::V2Reassembler, 4> = cfp::Pbufs::new();
    let key = frames[0].0 & cfp::V2_CONN_MASK;
    let mut buf = [0u8; 512];
    for f in &frames[..frames.len() - 1] {
        let r = pool.get_or_create(key, 100_000).expect("slot");
        assert!(matches!(r.push(f.0, &f.1, &mut buf), Ok(None)));
    }
    let mut done = None;
    for f in &again {
        let r = pool.get_or_create(key, 102_000).expect("slot");
        match r.push(f.0, &f.1, &mut buf) {
            Ok(Some((_, n))) => done = Some(buf[..n].to_vec()),
            Ok(None) => {}
            Err(e) => panic!("the port refused a retried frame: {e:?}"),
        }
    }
    assert_eq!(
        done.as_deref(),
        Some(&whole[..]),
        "the port recovers from a truncated transfer on the retry, where the C does not"
    );
}

/// `Pbufs::expire` reclaims a transfer that has gone quiet, and only that one.
///
/// The port's sweep is explicit rather than a side effect of allocating, which is what lets
/// it happen at all on a bus with one talker. Asserted through what comes out: after the
/// sweep the stale slot is free, and a transfer still in flight is untouched.
#[test]
fn the_ports_sweep_reclaims_the_quiet_transfer_and_leaves_the_busy_one() {
    let stale = body(30);
    let busy = body(24);
    let a = port_fragments(&stale, 7);
    let b = {
        let id = Id {
            pri: 2,
            flags: 0,
            src: R_ADDR + 1,
            dst: C_ADDR,
            dport: PORT,
            sport: 40,
        };
        cfp::V2Fragmenter::new(id, R_ADDR + 1, 7, &busy)
            .map(|f| (f.id, f.data().to_vec()))
            .collect::<Vec<_>>()
    };
    let (ka, kb) = (a[0].0 & cfp::V2_CONN_MASK, b[0].0 & cfp::V2_CONN_MASK);
    assert_ne!(ka, kb);

    let mut pool: cfp::Pbufs<cfp::V2Reassembler, 4> = cfp::Pbufs::new();
    let mut bufs = [[0u8; 512]; 2];

    // A stalls at t=1000; B keeps going until t=1900.
    for f in &a[..a.len() - 1] {
        let r = pool.get_or_create(ka, 1_000).expect("slot");
        assert!(matches!(r.push(f.0, &f.1, &mut bufs[0]), Ok(None)));
    }
    for f in &b[..b.len() - 1] {
        let r = pool.get_or_create(kb, 1_900).expect("slot");
        assert!(matches!(r.push(f.0, &f.1, &mut bufs[1]), Ok(None)));
    }

    assert_eq!(
        pool.expire(2_100, 1_000),
        1,
        "only the transfer that has been quiet longer than the timeout"
    );

    // B finishes normally: the sweep did not disturb it.
    let last = b.last().unwrap();
    let r = pool.get_or_create(kb, 2_100).expect("slot");
    match r.push(last.0, &last.1, &mut bufs[1]) {
        Ok(Some((_, n))) => assert_eq!(&bufs[1][..n], &busy[..], "B completes intact"),
        other => panic!("B must complete: {other:?}"),
    }
}
