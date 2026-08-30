//! The RDP sequence-comparison primitives against the real C, across the whole space.
//!
//! `seq_before` and `seq_between` decide every window, ack, and duplicate check in RDP, so a
//! one-point disagreement with the C is a latent divergence in all of them. `seq_before`
//! once differed from the C at exactly the antipode (`a - b == 0x8000`), where the C's
//! signed comparison says "before" and the port's `(b-a) < 0x8000` said "not" — 65536 points
//! of the 2^32 grid, unreachable behind the window range checks but wrong in the primitive.
//! This sweeps a dense grid plus every antipodal pair to keep them identical.

use csp_core::rdp::{seq_before, seq_between};
use difftest::*;

#[test]
fn seq_before_matches_the_c_everywhere_including_the_antipode() {
    let _g = lock();
    // Every antipodal pair -- the diagonal that used to differ.
    for a in 0u32..=0xFFFF {
        let b = (a + 0x8000) & 0xFFFF;
        assert_eq!(
            seq_before(a as u16, b as u16),
            c_rdp_seq_before(a as u16, b as u16),
            "antipode a={a:#06x} b={b:#06x}"
        );
    }
    // A dense grid over the rest of the space.
    for a in (0u32..=0xFFFF).step_by(211) {
        for b in (0u32..=0xFFFF).step_by(223) {
            assert_eq!(
                seq_before(a as u16, b as u16),
                c_rdp_seq_before(a as u16, b as u16),
                "seq_before a={a:#06x} b={b:#06x}"
            );
        }
    }
}

#[test]
fn seq_between_matches_the_c_across_the_space() {
    let _g = lock();
    for s in (0u32..=0xFFFF).step_by(151) {
        for start in (0u32..=0xFFFF).step_by(167) {
            for w in [0u32, 1, 2, 8, 0x7FFF, 0x8000, 0xFFFF] {
                let end = (start + w) & 0xFFFF;
                assert_eq!(
                    seq_between(s as u16, start as u16, end as u16),
                    c_rdp_seq_between(s as u16, start as u16, end as u16),
                    "seq_between s={s:#06x} start={start:#06x} end={end:#06x}"
                );
            }
        }
    }
}
