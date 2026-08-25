//! Differential tests: the same bytes through both implementations.
//!
//! Run with `cargo test -p difftest --release` for the full iteration counts.
//!
//! Every test is seeded and deterministic, so a failure reproduces from its seed.

use csp_core::{Id, Version};
use difftest::*;

const ITERS: u64 = if cfg!(debug_assertions) { 20_000 } else { 300_000 };

fn versions() -> [Version; 2] {
    [Version::V1, Version::V2]
}

/// Random ids that are *in range* for `v`, so both sides should agree exactly.
fn random_valid_id(rng: &mut Rng, v: Version) -> Id {
    Id {
        pri: rng.below(4) as u8,
        flags: (rng.next() as u8) & if v == Version::V1 { 0xff } else { 0x3f },
        src: rng.below(v.max_node_id() as u64 + 1) as u16,
        dst: rng.below(v.max_node_id() as u64 + 1) as u16,
        dport: rng.below(v.max_port() as u64 + 1) as u8,
        sport: rng.below(v.max_port() as u64 + 1) as u8,
    }
}

#[test]
fn version_parameters_agree() {
    let _g = LOCK.lock().unwrap();
    for v in versions() {
        c_set_version(v);
        assert_eq!(c_header_size(), v.header_size(), "{v:?} header size");
        assert_eq!(c_host_bits(), v.host_bits(), "{v:?} host bits");
        assert_eq!(c_max_nodeid() as u16, v.max_node_id(), "{v:?} max node id");
        assert_eq!(c_max_port() as u8, v.max_port(), "{v:?} max port");
    }
}

#[test]
fn header_encoding_agrees_for_every_in_range_id() {
    let _g = LOCK.lock().unwrap();
    let mut rng = Rng(0x1234_5678_9abc_def0);
    for v in versions() {
        c_set_version(v);
        for i in 0..ITERS {
            let id = random_valid_id(&mut rng, v);
            let mut ours = [0u8; 8];
            let n = id
                .encode(v, &mut ours)
                .unwrap_or_else(|e| panic!("iter {i}: rust refused {id:?}: {e:?}"));
            let theirs = c_id_encode(&id);
            assert_eq!(
                &ours[..n],
                &theirs[..],
                "iter {i}, {v:?}, id {id:?}\n  rust: {:02x?}\n  c:    {:02x?}",
                &ours[..n],
                theirs
            );
        }
    }
}

#[test]
fn header_decoding_agrees_for_arbitrary_bytes() {
    // Decoding must agree on *every* bit pattern, not just well-formed ones -- this is
    // what a hostile or corrupted frame looks like.
    let _g = LOCK.lock().unwrap();
    let mut rng = Rng(0xdead_beef_cafe_0001);
    for v in versions() {
        c_set_version(v);
        let n = v.header_size();
        for i in 0..ITERS {
            let mut buf = [0u8; 8];
            rng.fill(&mut buf[..n]);
            let ours = Id::decode(v, &buf[..n]).expect("decode must accept any bytes");
            let theirs = c_id_decode(&buf[..n]);
            assert_eq!(ours, theirs, "iter {i}, {v:?}, bytes {:02x?}", &buf[..n]);
        }
    }
}

#[test]
fn decode_encode_is_a_fixed_point_in_both() {
    // Whatever the C decodes out of arbitrary bytes must re-encode to the same bytes in
    // both implementations. This catches a masking difference the round-trip alone hides.
    let _g = LOCK.lock().unwrap();
    let mut rng = Rng(0x0bad_c0de_0000_0007);
    for v in versions() {
        c_set_version(v);
        let n = v.header_size();
        for i in 0..ITERS {
            let mut buf = [0u8; 8];
            rng.fill(&mut buf[..n]);
            let id = c_id_decode(&buf[..n]);

            let mut ours = [0u8; 8];
            let m = id.encode(v, &mut ours).unwrap_or_else(|e| {
                panic!("iter {i}: rust refused a C-decoded id {id:?}: {e:?}")
            });
            let theirs = c_id_encode(&id);
            assert_eq!(&ours[..m], &theirs[..], "iter {i}, {v:?}, id {id:?}");
        }
    }
}

#[test]
fn broadcast_detection_agrees() {
    let _g = LOCK.lock().unwrap();
    let mut rng = Rng(0xfeed_face_0000_002a);
    for v in versions() {
        c_set_version(v);
        for i in 0..ITERS {
            let addr = rng.next() as u16;
            let iface_addr = rng.next() as u16;
            // A netmask wider than the address space shifts out of range in the C; keep
            // to the legal domain.
            let netmask = rng.below(v.host_bits() as u64 + 1) as u16;
            assert_eq!(
                v.is_broadcast(addr, iface_addr, netmask),
                c_is_broadcast(addr, iface_addr, netmask),
                "iter {i}, {v:?}, addr={addr} iface={iface_addr}/{netmask}"
            );
        }
    }
}

#[test]
fn crc32_agrees_on_random_buffers() {
    let mut rng = Rng(0xc0ff_ee00_0000_0003);
    let mut buf = [0u8; 512];
    for i in 0..ITERS {
        let n = rng.below(buf.len() as u64 + 1) as usize;
        rng.fill(&mut buf[..n]);
        assert_eq!(
            csp_core::crc32::checksum(&buf[..n]),
            c_crc32(&buf[..n]),
            "iter {i}, len {n}"
        );
    }
}

#[test]
fn sha1_agrees_on_random_buffers() {
    // Lengths cluster around the 64-byte block and the 55/56 padding boundary, which is
    // where a hand-written SHA-1 goes wrong.
    let mut rng = Rng(0x5a17_0000_0000_0005u64);
    let mut buf = [0u8; 300];
    for i in 0..ITERS / 4 {
        let n = match rng.below(3) {
            0 => rng.below(70) as usize,
            1 => (55 + rng.below(20)) as usize,
            _ => rng.below(buf.len() as u64 + 1) as usize,
        };
        rng.fill(&mut buf[..n]);
        assert_eq!(
            csp_core::sha1::digest(&buf[..n]),
            c_sha1(&buf[..n]),
            "iter {i}, len {n}"
        );
    }
}

#[test]
fn hmac_agrees_on_random_keys_and_messages() {
    // Key lengths straddle the 64-byte block, where the key is hashed instead of padded.
    let mut rng = Rng(0x48ac_0000_0000_0009u64);
    let mut key = [0u8; 100];
    let mut msg = [0u8; 300];
    for i in 0..ITERS / 4 {
        let klen = match rng.below(3) {
            0 => rng.below(20) as usize,
            1 => (60 + rng.below(10)) as usize,
            _ => rng.below(key.len() as u64 + 1) as usize,
        };
        let mlen = rng.below(msg.len() as u64 + 1) as usize;
        rng.fill(&mut key[..klen]);
        rng.fill(&mut msg[..mlen]);

        let ours = csp_core::hmac::mac_full(&key[..klen], &msg[..mlen]);
        let theirs = c_hmac(&key[..klen], &msg[..mlen]);

        match (ours, theirs) {
            (Ok(a), Some(b)) => assert_eq!(a, b, "iter {i}, klen {klen}, mlen {mlen}"),
            (Err(_), None) => {
                // Both refused. The only refusal either side has is an empty key.
                assert_eq!(klen, 0, "iter {i}: refused a non-empty key");
            }
            (a, b) => panic!(
                "iter {i}: disagreed on acceptance, klen {klen}: rust {:?}, c {:?}",
                a.is_ok(),
                b.is_some()
            ),
        }
    }
}

// --- deliberate divergences: assert the difference, so a regression toward C fails ---

#[test]
fn rust_refuses_out_of_range_fields_where_the_c_corrupts_its_neighbour() {
    // SCOPE.md deviation 7. The C shifts an oversized value into the adjacent field and
    // produces a header that decodes as a *different, valid* packet.
    let _g = LOCK.lock().unwrap();
    c_set_version(Version::V1);

    let id = Id {
        pri: 0,
        flags: 0,
        src: 1,
        dst: 1000, // needs 14 bits; v1 has 5
        dport: 0,
        sport: 0,
    };

    let mut buf = [0u8; 8];
    assert!(
        id.encode(Version::V1, &mut buf).is_err(),
        "rust must refuse an address that does not fit"
    );

    let theirs = c_id_encode(&id);
    let round_tripped = c_id_decode(&theirs);
    assert_ne!(
        round_tripped, id,
        "the C should have corrupted this; if it round-trips, the premise changed"
    );
    // and specifically, the damage lands in a neighbouring field
    assert_ne!(
        round_tripped.src, id.src,
        "the overflow should have reached the source address"
    );
}

#[test]
fn rust_refuses_an_empty_hmac_key_and_the_c_leaves_the_buffer_untouched() {
    // SCOPE.md deviation: the C returns CSP_ERR_INVAL without writing, so a caller that
    // ignores the return value MACs over whatever was already in the buffer.
    assert!(csp_core::hmac::mac_full(b"", b"anything").is_err());
    assert!(
        c_hmac(b"", b"anything").is_none(),
        "the C must be refusing this too"
    );
}
