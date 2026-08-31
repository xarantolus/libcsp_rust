//! `seq_before` and `seq_between` against the real C across the whole 2^16 x 2^16 space —
//! they decide every RDP window, ack, and duplicate check, so a one-point disagreement is a
//! latent divergence. Sweeps a dense grid plus every antipodal pair (`a - b == 0x8000`, the
//! one point where a signed and an unsigned "before" can differ).

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
