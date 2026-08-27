//! The two things `csp_if_i2c.c` does that no other interface does.
//!
//! # Why this file exists
//!
//! `if-i2c` is a **default-on feature in both crates that gated zero lines of code**, and
//! `api_map.tsv` claimed its three C functions were ported:
//!
//! ```text
//! csp_i2c_add_interface  ported  csp::iface::Interface::new
//! csp_i2c_rx             ported  csp::iface::Interface::note_rx
//! csp_i2c_tx             ported  csp::iface::Interface::send
//! ```
//!
//! Those are the *generic* interface methods. `csp_if_i2c.c` was in neither harness's build,
//! so nothing had ever checked the claim. Measured: most of the file genuinely is generic —
//! loopback when the destination is our own address, `csp_id_prepend` outbound,
//! `csp_id_strip` inbound, all of which `Interface::send` already did. Two things are not,
//! and the port had neither.
//!
//! - **The bus address is seven bits.** `csp_if_i2c.c:22` masks it, so a CSP address of 200
//!   is addressed as 72 and two nodes 128 apart collide on the bus with nothing reported.
//! - **A frame under four bytes is refused** and counted as a framing error, before
//!   `csp_id_strip` runs.
//!
//! Both are pure functions of the header, so they are `csp_core::i2c` rather than a driver.

use csp_core::i2c;
use difftest::*;

const NODE_ADDR: u16 = 9;

fn setup() {
    c_set_version(csp_core::Version::V2);
    assert!(c_node_init(csp_core::Version::V2, NODE_ADDR, 12, 20, 40));
    assert!(c_i2c_init(NODE_ADDR), "the I2C interface came up");
}

/// The bus address, for a next hop and without one, inside the seven-bit space and outside.
///
/// The out-of-range rows are the point: an address the C truncates and the port did not
/// would put every frame for that node somewhere else on the bus.
#[test]
fn the_bus_address_matches_what_csp_i2c_tx_picks() {
    let _g = lock();
    setup();

    // (dst, via) — `via` of NO_VIA means "no next hop".
    let cases = [
        (5u16, i2c::NO_VIA),
        (72, i2c::NO_VIA),
        (127, i2c::NO_VIA),
        // Above the seven-bit space: 200 & 0x7F == 72, colliding with the row above.
        (200, i2c::NO_VIA),
        (128, i2c::NO_VIA),
        (0x3FFF, i2c::NO_VIA),
        // A next hop wins over the destination, and is masked the same way.
        (200, 5),
        (5, 200),
        (11, 0x3FFF),
    ];

    for (dst, via) in cases {
        let c = c_i2c_bus_addr(dst, via)
            .unwrap_or_else(|| panic!("dst={dst} via={via}: csp_i2c_tx did not reach the driver"));
        assert_eq!(
            i2c::physical_addr(via, dst),
            c,
            "dst={dst} via={via}: the port must address the same device on the bus"
        );
        assert!(c <= 0x7F, "and the C's own answer is seven bits");
    }
}

/// A packet for our own address never reaches the bus at all.
///
/// `csp_i2c_tx` loops it back into the router before it computes an address. This is the one
/// case where "no bus address" is the correct answer, and it is what makes the rows above
/// mean something: a driver that was never called for *any* packet would satisfy them.
#[test]
fn a_packet_for_ourselves_never_reaches_the_driver() {
    let _g = lock();
    setup();

    assert_eq!(
        c_i2c_bus_addr(NODE_ADDR, i2c::NO_VIA),
        None,
        "the C loops a self-addressed packet back rather than sending it"
    );
    // And the control: some other address does reach the driver.
    assert!(
        c_i2c_bus_addr(NODE_ADDR + 1, i2c::NO_VIA).is_some(),
        "a packet for anyone else does reach it"
    );

    // The loopback test is on `id.dst`, *before* the next hop is consulted — so a packet
    // addressed to ourselves is looped back even when a route says to send it via someone
    // else. Found by writing this case with `dst == NODE_ADDR` by accident and having the
    // C refuse to reach the driver at all.
    assert_eq!(
        c_i2c_bus_addr(NODE_ADDR, 11),
        None,
        "a next hop does not override the loopback: csp_i2c_tx checks id.dst first"
    );
}

/// The receive guard is four bytes — which is not the size of a header.
///
/// `csp_i2c_rx` refuses `frame_length < sizeof(uint32_t)`. A v2 header is six, so a five-byte
/// frame passes the guard and is handed to `csp_id_strip`; the port reproduces the C's rule
/// rather than the one it presumably meant, because refusing more would drop frames a real
/// libcsp peer accepts.
#[test]
fn the_receive_guard_is_the_cs_four_bytes() {
    let _g = lock();
    setup();

    for len in [0usize, 1, 3, 4, 5, 6, 16] {
        let frame = vec![0x42u8; len];
        assert_eq!(
            i2c::accepts(len),
            c_i2c_accepts(&frame),
            "a {len}-byte frame: the port must accept exactly what csp_i2c_rx accepts"
        );
    }
}
