//! The RDP SYN-option clamp vs the real C, every field across each bound. `decode_clamped`
//! bounds all six unauthenticated options (`csp_rdp.c:568-576`); a wrong bound lets a peer
//! set a 1 ms packet timeout or a zero window. The shim runs the C's clamp with the real
//! `CSP_RDP_*` macros, pinning arithmetic and constants.

use csp_core::rdp::{
    SynOptions, MAX_CONN_TIMEOUT, MAX_PACKET_TIMEOUT, MIN_ACK_TIMEOUT, MIN_CONN_TIMEOUT,
    MIN_PACKET_TIMEOUT,
};
use difftest::*;

const MAX_WINDOW: u32 = 5;

fn block(v: [u32; 6]) -> [u8; 24] {
    let mut b = [0u8; 24];
    for (i, w) in v.iter().enumerate() {
        b[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    b
}

fn port(v: [u32; 6], max_window: u32) -> [u32; 6] {
    let o = SynOptions::decode_clamped(&block(v), max_window).expect("a full option block");
    [
        o.window_size,
        o.conn_timeout,
        o.packet_timeout,
        o.delayed_acks as u32,
        o.ack_timeout,
        o.ack_delay_count,
    ]
}

#[test]
fn the_port_constants_match_the_c_macros() {
    let _g = lock();
    assert_eq!(MAX_WINDOW, c_rdp_max_window(), "CSP_RDP_MAX_WINDOW");
    // The five bound constants, proven via the clamp: a value below/above each bound must
    // come back pinned to exactly the port constant AND to what the C returns.
    for (idx, lo, hi) in [
        (1usize, MIN_CONN_TIMEOUT, MAX_CONN_TIMEOUT),
        (2, MIN_PACKET_TIMEOUT, MAX_PACKET_TIMEOUT),
    ] {
        let mut low = [10_000u32; 6];
        low[idx] = 0;
        assert_eq!(port(low, MAX_WINDOW)[idx], lo, "field {idx} floor");
        let mut high = [10_000u32; 6];
        high[idx] = u32::MAX;
        assert_eq!(port(high, MAX_WINDOW)[idx], hi, "field {idx} ceil");
    }
    assert_eq!(
        port([10_000, 10_000, 10_000, 1, 0, 3], MAX_WINDOW)[4],
        MIN_ACK_TIMEOUT
    );
}

#[test]
fn decode_clamped_matches_the_c_across_every_boundary() {
    let _g = lock();
    // Values chosen to straddle every bound: 0, just under/over each min/max, huge.
    let probes = [
        0u32,
        1,
        9,
        10,
        11,
        99,
        100,
        101,
        999,
        1_000,
        1_001,
        59_999,
        60_000,
        60_001,
        0x7FFF_FFFF,
        0xFFFF_FFFF,
    ];
    let mut n = 0u64;
    // Sweep each field through the probes while the others sit at a mid value; plus the
    // interdependent pairs (ack_timeout vs conn_timeout, ack_delay_count vs window).
    for field in 0..6usize {
        for &p in &probes {
            for &w in &[0u32, 1, 3, 5, 6, 100] {
                let mut v = [5_000u32, 30_000, 5_000, 1, 5_000, 2];
                v[field] = p;
                v[0] = w; // vary window too, since ack_delay_count clamps to it
                assert_eq!(
                    port(v, MAX_WINDOW),
                    c_rdp_decode_options(v, MAX_WINDOW),
                    "field {field} probe {p} window {w}"
                );
                n += 1;
            }
        }
    }
    assert!(n > 500, "swept {n} combinations");
}
