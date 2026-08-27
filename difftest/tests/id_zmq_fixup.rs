//! `csp_id_*_fixup_cspv1` — the ZeroMQ hub's little-endian v1 header — measured, then scoped out.
//!
//! # A mapping that claimed the wrong codec
//!
//! `ctest/tools/api_map.tsv` had all three of `csp_id_prepend_fixup_cspv1`,
//! `csp_id_extract_fixup_cspv1` and `csp_id_strip_fixup_cspv1` as `ported` to
//! `csp_core::id::Id::encode` / `Id::decode`. They are not that codec.
//! `csp_id1_prepend(packet, true)` swaps `htobe32` for `htole32` (`csp_id.c:57`), so at v1
//! the four header bytes come out in the **host's** byte order rather than network order;
//! at v2 the fixup path is `csp_id2_prepend`, unchanged.
//!
//! Two of the three rows therefore recorded a function as covered by a Rust function that
//! does something different — the same shape as `csp_rtable_save` being mapped to a
//! one-route formatter, and the same shape as the very first false "the port is complete".
//!
//! # What it actually is, and why it is now out of scope
//!
//! The only caller anywhere in libcsp is `csp_if_zmqhub.c`, and the ZeroMQ hub is out of
//! scope by the agreed feature table — rows 30 and 31 of the same map already say so for the
//! hub's own halves of this feature. The three rows now say it too.
//!
//! This test exists so that "not the same codec" is a **measurement** rather than a reading
//! of the `#if`, and so that anyone who later wonders whether the port should speak the zmq
//! fixup can see exactly what it would have to produce.

use csp_core::{Id, Version};
use difftest::*;

fn sample() -> Id {
    Id {
        pri: 2,
        flags: 0x0C,
        src: 9,
        dst: 20,
        dport: 10,
        sport: 40,
    }
}

/// At v1 the fixup header is the ordinary one byte-reversed; at v2 they are identical.
#[test]
fn the_zmq_fixup_is_a_different_codec_at_v1_and_the_same_one_at_v2() {
    let _g = lock();
    let id = sample();

    c_set_version(Version::V1);
    let plain = c_id_encode(&id);
    let fixup = c_id_encode_fixup(&id);
    assert_eq!(plain.len(), 4, "a v1 header is four bytes");
    assert_eq!(fixup.len(), 4, "and so is the fixup's");
    assert_ne!(
        plain, fixup,
        "the fixup is not the ordinary v1 codec, which is what the api_map claimed"
    );
    let mut reversed = fixup.clone();
    reversed.reverse();
    assert_eq!(
        plain, reversed,
        "it is the same 32-bit word written the other way round -- htole32 for htobe32"
    );

    // The port's encoder is the network-order one, so it agrees with the plain path and not
    // with the fixup. That is the whole reason the mapping was wrong.
    let mut ours = [0u8; 4];
    let n = id.encode(Version::V1, &mut ours).expect("a v1 header");
    assert_eq!(&ours[..n], &plain[..], "the port speaks network order");
    assert_ne!(&ours[..n], &fixup[..], "and not the hub's");

    c_set_version(Version::V2);
    let plain = c_id_encode(&id);
    let fixup = c_id_encode_fixup(&id);
    assert_eq!(plain.len(), 6, "a v2 header is six bytes");
    assert_eq!(
        plain, fixup,
        "at v2 the fixup path is csp_id2_prepend unchanged, so there is nothing to diverge"
    );
    let mut ours = [0u8; 6];
    let n = id.encode(Version::V2, &mut ours).expect("a v2 header");
    assert_eq!(
        &ours[..n],
        &fixup[..],
        "and the port matches it, as it matches the plain path"
    );
}
