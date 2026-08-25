//! Differential tests: the same bytes through both implementations.
//!
//! Run with `cargo test -p difftest --release` for the full iteration counts.
//!
//! Every test is seeded and deterministic, so a failure reproduces from its seed.

use csp_core::{Id, Version};
use difftest::*;

const ITERS: u64 = if cfg!(debug_assertions) {
    20_000
} else {
    300_000
};

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
            let m = id
                .encode(v, &mut ours)
                .unwrap_or_else(|e| panic!("iter {i}: rust refused a C-decoded id {id:?}: {e:?}"));
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

#[test]
fn cfp1_identifier_packing_agrees() {
    use csp_core::cfp;
    let mut rng = Rng(0xCF71_0000_0000_000B);
    for i in 0..ITERS {
        // In-range values: the C's macros mask, so out-of-range inputs are silently
        // truncated on both sides and would not prove anything.
        let src = rng.below(32) as u16;
        let dst = rng.below(32) as u16;
        let kind = rng.below(2) as u32;
        let remain = rng.below(256) as u32;
        let ident = rng.below(1024) as u16;

        let ours = cfp::v1_id(src, dst, kind, remain, ident);
        let theirs = c_cfp1_make(src, dst, kind, remain, ident);
        assert_eq!(
            ours, theirs,
            "iter {i}: make({src},{dst},{kind},{remain},{ident}) {ours:#x} != {theirs:#x}"
        );
        assert!(
            ours < (1 << 29),
            "iter {i}: id must fit an extended CAN identifier"
        );
    }
}

#[test]
fn cfp1_identifier_parsing_agrees_for_arbitrary_identifiers() {
    use csp_core::cfp;
    let mut rng = Rng(0xCF72_0000_0000_000D);
    for i in 0..ITERS {
        // Any 29-bit pattern, including ones no sane sender would produce.
        let id = (rng.next() as u32) & ((1 << 29) - 1);
        let ours = cfp::v1_parse(id);
        let (src, dst, kind, remain, ident) = c_cfp1_parse(id);
        assert_eq!(
            (ours.src, ours.dst, ours.kind, ours.remain, ours.ident),
            (src, dst, kind, remain, ident),
            "iter {i}: parse({id:#x})"
        );
    }
}

// ---------------------------------------------------------------------------
// CFP 2 -- the CSP v2 CAN identifier
// ---------------------------------------------------------------------------

/// Every field the real fragmenter puts in a CAN id must read back the same through the
/// C's macros.
///
/// This runs the production path rather than comparing constants: an offset or mask typo
/// in `V2Fragmenter::base_id` would silently corrupt every v2 CAN frame the node sends,
/// and no round-trip test against our own reassembler would notice, because both sides
/// would be wrong in the same way.
#[test]
fn cfp2_identifiers_from_the_fragmenter_agree_with_the_c() {
    let mut rng = Rng(0xC2F2_0001);
    let mut checked = 0u32;

    for _ in 0..20_000 {
        let id = csp_core::Id {
            pri: (rng.next() % 4) as u8,
            flags: (rng.next() % 0x40) as u8,
            src: (rng.next() % 16384) as u16,
            dst: (rng.next() % 16384) as u16,
            dport: (rng.next() % 64) as u8,
            sport: (rng.next() % 64) as u8,
        };
        let sender = (rng.next() % 64) as u16;
        let sender_count = rng.next() as u32 % 4;
        let len = (rng.next() % 40) as usize;
        let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();

        let frames: Vec<_> =
            csp_core::cfp::V2Fragmenter::new(id, sender, sender_count, &payload).collect();
        assert!(
            !frames.is_empty(),
            "a fragmenter must emit at least one frame"
        );
        let last = frames.len() - 1;

        for (i, f) in frames.iter().enumerate() {
            let c = c_cfp2_parse(f.id);
            assert_eq!(c.pri, id.pri as u16, "priority, frame {i}");
            assert_eq!(c.dst, id.dst, "destination, frame {i}");
            assert_eq!(c.sender, sender, "sender, frame {i}");
            assert_eq!(c.sc, sender_count as u16, "sender count, frame {i}");
            assert_eq!(c.begin, u16::from(i == 0), "begin bit, frame {i}");
            assert_eq!(c.end, u16::from(i == last), "end bit, frame {i}");
            // The fragment counter wraps at 3 bits, which is the whole point of it.
            assert_eq!(c.fc, (i as u16) & 0x7, "fragment counter, frame {i}");
            checked += 1;
        }
    }
    assert!(checked > 20_000, "only {checked} frames compared");
}

/// And the packing direction: an identifier the C builds from the same fields is the same
/// number the fragmenter produced.
#[test]
fn cfp2_packing_agrees_bit_for_bit() {
    let mut rng = Rng(0xC2F2_0002);
    for _ in 0..200_000 {
        let f = Cfp2Fields {
            pri: (rng.next() % 4) as u16,
            dst: (rng.next() % 16384) as u16,
            sender: (rng.next() % 64) as u16,
            sc: (rng.next() % 4) as u16,
            fc: (rng.next() % 8) as u16,
            begin: (rng.next() % 2) as u16,
            end: (rng.next() % 2) as u16,
        };
        let packed = c_cfp2_make(f);
        assert_eq!(
            c_cfp2_parse(packed),
            f,
            "the C must round-trip its own layout"
        );
        assert_eq!(packed >> 29, 0, "a CAN id is 29 bits");
    }
}

// ---------------------------------------------------------------------------
// Route table -- the parser is a full rewrite, so this is the strongest test here
// ---------------------------------------------------------------------------

/// Interface names both sides know about.
const IFACES: [&str; 3] = ["CAN", "KISS", "LOOP"];

fn register_ifaces() {
    for (i, n) in IFACES.iter().enumerate() {
        c_add_iface(n, i as u16 + 1, 5);
    }
}

/// Build a random route-table entry that both sides should accept.
fn valid_entry(rng: &mut Rng, host_bits: u16, max_node: u16) -> String {
    let addr = (rng.next() % (max_node as u64 + 1)) as u16;
    let iface = IFACES[(rng.next() % IFACES.len() as u64) as usize];
    match rng.next() % 4 {
        0 => format!(
            "{addr}/{} {iface} {}",
            rng.next() % (host_bits as u64 + 1),
            rng.next() % 16
        ),
        1 => format!("{addr}/{} {iface}", rng.next() % (host_bits as u64 + 1)),
        2 => format!("{addr} {iface} {}", rng.next() % 16),
        _ => format!("{addr} {iface}"),
    }
}

/// A table both sides accept must route every address to the same interface and via.
///
/// The parser here is a rewrite -- no `sscanf`, no VLA -- so unlike the codecs there is no
/// shared structure to make the two agree by construction. If the longest-prefix rule or
/// the netmask default differs anywhere, a random table finds it.
#[test]
fn rtable_lookups_agree_for_tables_both_sides_accept() {
    let _g = LOCK.lock().unwrap();
    c_set_version(Version::V1);
    register_ifaces();

    let mut rng = Rng(0x2AB1_0001);
    let mut compared = 0u32;
    let mut accepted = 0u32;

    for _ in 0..2_000 {
        // Two or three entries, comfortably inside the C's 100-character limit.
        let n = 2 + (rng.next() % 2) as usize;
        let text: Vec<String> = (0..n).map(|_| valid_entry(&mut rng, 5, 31)).collect();
        let text = text.join(",");
        if text.len() >= 100 {
            continue; // the C truncates at 100; that case has its own test
        }

        let c_res = c_rtable_load(&text).expect("no interior NULs");
        let mut rust: Vec<(u16, u16, u8, u16)> = Vec::new();
        let rust_res = csp_core::rtable::parse(&text, |r| {
            rust.push((
                r.address,
                r.netmask.unwrap_or(5),
                IFACES.iter().position(|&n| n == r.iface).unwrap_or(255) as u8,
                r.via.unwrap_or(csp_core::rtable::NO_VIA),
            ));
            Ok(())
        });

        assert_eq!(
            c_res >= 0,
            rust_res.is_ok(),
            "acceptance must agree for {text:?} (C {c_res}, Rust {rust_res:?})"
        );
        if c_res < 0 {
            continue;
        }
        accepted += 1;
        assert_eq!(c_res as usize, rust.len(), "entry count for {text:?}");

        // Install the same entries in a Rust table and compare every lookup.
        let mut table: csp_core::rtable::Table<16> = csp_core::rtable::Table::new(Version::V1);
        for &(addr, mask, iface, via) in &rust {
            table.set(addr, mask, iface, via).unwrap();
        }
        for addr in 0u16..=31 {
            let c_route = c_rtable_lookup(addr);
            let r_route = table.find(addr);
            match (&c_route, r_route) {
                (None, None) => {}
                (Some(c), Some(r)) => {
                    assert_eq!(
                        c.iface,
                        IFACES[r.iface as usize],
                        "interface for {addr} in {text:?}"
                    );
                    assert_eq!(c.via, r.via, "via for {addr} in {text:?}");
                }
                _ => panic!("one side found a route for {addr} and the other did not: {text:?} -- C {c_route:?}, Rust {r_route:?}"),
            }
            compared += 1;
        }
    }
    assert!(accepted > 1_000, "only {accepted} tables were accepted");
    assert!(compared > 30_000, "only {compared} lookups compared");
}

/// A short token ends the C's parse, silently, and reports success.
///
/// `while (str && (strlen(str) > 1))` is the loop condition, not a skip: the first token
/// of one character or fewer terminates parsing, every entry after it is dropped, and
/// `csp_rtable_load` returns the count of what it managed before that -- a non-negative
/// number, which callers read as success. This port parses the later entries.
#[test]
fn a_one_character_entry_ends_the_cs_parse_and_it_reports_success() {
    let _g = LOCK.lock().unwrap();
    c_set_version(Version::V1);
    register_ifaces();

    let text = "1 CAN,2,3 KISS";
    let c_res = c_rtable_load(text).unwrap();
    assert_eq!(
        c_res, 1,
        "the C stopped at \"2\" and kept only the first entry"
    );
    assert!(c_res >= 0, "and reported success while dropping 3 KISS");
    assert!(
        c_rtable_lookup(3).is_none(),
        "the dropped entry is simply not there"
    );

    let mut seen = Vec::new();
    let n = csp_core::rtable::parse(text, |r| {
        seen.push((r.address, r.iface.to_string()));
        Ok(())
    })
    .expect("the port skips the short entry rather than stopping");
    assert_eq!(n, 2, "both real entries are parsed");
    assert_eq!(seen[1], (3, "KISS".to_string()));
}

/// The C truncates the whole table at 100 characters, and what that costs depends on
/// where the cut lands.
///
/// `strnlen(rtable, 100)` then a VLA of that size (`csp_rtable_stdio.c:17-20`). Two
/// outcomes, both bad in different ways:
///
/// - the cut lands **mid-entry**: the fragment fails to parse and the whole load is
///   rejected with `CSP_ERR_INVAL`, so a table that is entirely valid is refused for
///   being long;
/// - the cut lands **on a separator**: every surviving entry parses, the function returns
///   a positive count, and the dropped tail is never mentioned. The caller sees success
///   and a routing table missing routes.
///
/// The port parses the whole string either way.
#[test]
fn the_c_truncates_a_long_table_at_a_hundred_characters() {
    let _g = LOCK.lock().unwrap();
    c_set_version(Version::V1);
    register_ifaces();

    // Nine-character entries, so with separators every entry starts at a multiple of ten
    // and the 100-character cut falls exactly on the comma after the tenth.
    let aligned: Vec<String> = (0..15).map(|i| format!("{:02} CAN 11", i % 32)).collect();
    let aligned = aligned.join(",");
    assert_eq!(aligned.len(), 15 * 9 + 14);
    assert_eq!(&aligned[99..100], ",", "the cut must land on a separator");

    let c_res = c_rtable_load(&aligned).unwrap();
    let rust_n = csp_core::rtable::parse(&aligned, |_| Ok(())).unwrap();
    assert_eq!(rust_n, 15, "the port parses every entry");
    assert_eq!(c_res, 10, "the C kept the ten that fit");
    assert!(c_res > 0, "and reported success while dropping five routes");
    assert!(
        c_rtable_lookup(14).is_none(),
        "the fifteenth entry is simply not in the table"
    );

    // Seven-character entries put the cut inside an entry instead.
    let midway: Vec<String> = (0..20).map(|i| format!("{} CAN 1", i % 10)).collect();
    let midway = midway.join(",");
    assert!(midway.len() > 100);
    assert_ne!(&midway[99..100], ",", "this cut must land mid-entry");

    assert!(
        c_rtable_load(&midway).unwrap() < 0,
        "a mid-entry cut makes the C reject the whole table"
    );
    assert_eq!(
        csp_core::rtable::parse(&midway, |_| Ok(())).unwrap(),
        20,
        "and the port still parses all twenty"
    );
}

// ---------------------------------------------------------------------------
// KISS framing -- the real csp_kiss_rx state machine, byte for byte
// ---------------------------------------------------------------------------

/// A frame the port encodes must arrive at a C node as the same id and payload.
///
/// This is the direction interop depends on: our KISS output goes down a UART to a C
/// node, and what comes out the other side has to be the packet we sent.
///
/// Note what the C's KISS layer does beyond framing — it drops the TNC command byte and
/// runs `csp_id_strip`, so by the time the packet reaches the router the header is already
/// consumed. The port keeps those apart: `kiss::Decoder` de-escapes and `Id::decode`
/// parses, because a sans-io decoder that silently parsed headers could not be used for
/// anything else. Both must still agree on the bytes.
#[test]
fn kiss_frames_we_encode_arrive_intact_at_a_c_node() {
    let _g = LOCK.lock().unwrap();
    let mut rng = Rng(0x4155_0001);

    for version in versions() {
        c_set_version(version);
        let hdr = c_header_size();
        let mut checked = 0u32;

        for _ in 0..2_000 {
            let id = random_valid_id(&mut rng, version);
            // Bias hard toward the escape bytes: FEND and FESC are the whole protocol,
            // and a uniform random payload almost never contains either.
            let len = 1 + (rng.next() % 40) as usize;
            let payload: Vec<u8> = (0..len)
                .map(|_| match rng.next() % 4 {
                    0 => 0xC0, // FEND
                    1 => 0xDB, // FESC
                    2 => (rng.next() % 4) as u8 + 0xDC,
                    _ => rng.next() as u8,
                })
                .collect();

            // The body is the CSP frame: encoded header, payload, then the CRC32 the
            // C's KISS interface requires. CSP_ENABLE_KISS_CRC defaults ON, and a frame
            // without one is rejected with nothing but iface->frame++ to show for it.
            let crc = csp_core::crc32::checksum(&payload);
            let mut body = vec![0u8; hdr + payload.len() + 4];
            id.encode(version, &mut body).expect("header fits");
            body[hdr..hdr + payload.len()].copy_from_slice(&payload);
            body[hdr + payload.len()..].copy_from_slice(&crc.to_be_bytes());

            let mut framed = vec![0u8; csp_core::kiss::max_encoded_len(body.len())];
            let n = csp_core::kiss::encode(&body, &mut framed).expect("room was reserved");

            let c = c_kiss_decode(&framed[..n]);
            assert_eq!(
                c.frames, 1,
                "{version:?}: the C must see one frame for {id:?} (frame errors {})",
                c.frame_errors
            );
            assert_eq!(
                c.last.as_deref(),
                Some(&payload[..]),
                "{version:?}: payload must survive framing and escaping"
            );
            assert_eq!(
                c.id.as_deref(),
                Some(&body[..hdr]),
                "{version:?}: and the header the C parsed must be the one we sent"
            );
            checked += 1;
        }
        assert_eq!(checked, 2_000, "{version:?}");
    }
}

/// A corrupted frame must never reach the C's router carrying the wrong payload.
///
/// Random byte streams cannot test this decoder: `CSP_ENABLE_KISS_CRC` is ON by default,
/// so acceptance is gated on a valid CRC32 and arbitrary bytes are rejected essentially
/// always. Starting from a *valid* frame and corrupting one byte reaches the interesting
/// states — a flipped escape, a truncated body, a broken checksum — which is where a
/// framing decoder actually goes wrong.
///
/// The property is one-sided on purpose: the C may legitimately reject a frame the port
/// would hand on, because the port's decoder stops at de-escaping and leaves header and
/// CRC to the caller. What must never happen is the C accepting a frame and delivering a
/// payload that is not the one that was sent — on a live link that is a corrupted command
/// obeyed as if it were genuine.
#[test]
fn a_corrupted_kiss_frame_never_reaches_the_router_with_the_wrong_payload() {
    let _g = LOCK.lock().unwrap();
    c_set_version(Version::V1);
    let hdr = c_header_size();
    let mut rng = Rng(0x4155_0002);

    let mut accepted = 0u32;
    let mut rejected = 0u32;

    for _ in 0..5_000 {
        let id = random_valid_id(&mut rng, Version::V1);
        let len = 1 + (rng.next() % 30) as usize;
        let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let crc = csp_core::crc32::checksum(&payload);

        let mut body = vec![0u8; hdr + payload.len() + 4];
        id.encode(Version::V1, &mut body).unwrap();
        body[hdr..hdr + payload.len()].copy_from_slice(&payload);
        body[hdr + payload.len()..].copy_from_slice(&crc.to_be_bytes());

        let mut framed = vec![0u8; csp_core::kiss::max_encoded_len(body.len())];
        let n = csp_core::kiss::encode(&body, &mut framed).unwrap();
        let mut framed = framed[..n].to_vec();

        // Corrupt one byte -- including, deliberately, the delimiters.
        match rng.next() % 4 {
            0 => {
                let i = (rng.next() as usize) % framed.len();
                framed[i] ^= 1 << (rng.next() % 8);
            }
            1 => {
                let i = (rng.next() as usize) % framed.len();
                framed[i] = 0xC0; // a FEND where none belongs
            }
            2 => {
                let i = (rng.next() as usize) % framed.len();
                framed[i] = 0xDB; // a FESC where none belongs
            }
            _ => {
                framed.truncate(1 + (rng.next() as usize) % framed.len());
            }
        }

        let c = c_kiss_decode(&framed);
        if c.frames == 0 {
            rejected += 1;
            continue;
        }
        accepted += 1;
        // If it *was* accepted, the payload must be exactly what was sent -- a corruption
        // that survives the CRC has to be one that changed nothing that matters.
        assert_eq!(
            c.last.as_deref(),
            Some(&payload[..]),
            "the C accepted a corrupted frame and delivered a different payload"
        );
    }

    assert!(
        rejected > 1_000,
        "only {rejected} corruptions were rejected -- the CRC is not being exercised"
    );
    assert!(
        accepted > 0,
        "no corruption was survivable; the generator never hits a byte that does not matter"
    );
}

// ---------------------------------------------------------------------------
// Node level: a real C node and a real Rust node, same frames, same questions
//
// Everything above this line compares codecs -- bytes in, bytes out. That leaves the
// layer where the port actually had a missing behaviour (the default-interface routing
// fan-out) checked only against a careful reading of the C. These tests close that.
//
// The comparison is deliberately behavioural. Both sides are asked only what an
// application or a peer could observe: which port received what payload on a connection
// with which endpoints, and what frames went out. Neither side's queue depths,
// connection-table indices or refcounts are touched -- pinning those would be testing
// libcsp's implementation, and the port is entitled to differ there and does.
// ---------------------------------------------------------------------------

use csp::{Config, CspStorage, Node, Routed};

/// The node under test on the Rust side, sized like the C's defaults.
type NodeStorage = CspStorage<8, 24, 300, 64, 8>;
/// `RXQ` is the seventh parameter of `Node` and is not implied by the storage type.
type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

/// Address both nodes answer to. Fits CSP v1's 5 bits.
const NODE_ADDR: u16 = 9;
/// Address of the egress interface, in a different subnet from the ingress one.
const EGRESS_ADDR: u16 = 20;

/// Drive a Rust node with one frame and report the same observable outcome the C shim
/// reports, so the two can be compared directly.
fn rust_node_exchange(
    version: Version,
    frame: &[u8],
    bind_ports: &[u8],
    watch_ports: &[u8],
) -> NodeOutcome {
    rust_node_exchange_routed(version, frame, bind_ports, watch_ports, &[])
}

/// As above, with routing-table entries installed first: `(address, netmask, iface, via)`.
fn rust_node_exchange_routed(
    version: Version,
    frame: &[u8],
    bind_ports: &[u8],
    watch_ports: &[u8],
    routes: &[(u16, u16, u8, u16)],
) -> NodeOutcome {
    let storage = NodeStorage::new();
    let mut node: TestNode = Node::new(&storage, Config::new(version).address(NODE_ADDR));
    // Same topology as the C shim: ingress on 8..15, egress on 16..23, so a forwarded
    // packet has a different subnet to leave by and split horizon does not veto it.
    node.ifaces.add("INGRESS", NODE_ADDR, 2, false).unwrap();
    node.ifaces.add("EGRESS", EGRESS_ADDR, 2, true).unwrap();
    for &p in bind_ports {
        node.bind(p).unwrap();
    }
    for &(a, m, i, v) in routes {
        node.route_set(a, m, i, v).unwrap();
    }

    let mut out = NodeOutcome::default();

    // A driver hands the node a framed packet off the wire.
    let Some(mut p) = node.packet() else {
        return out;
    };
    if p.set_frame(version, frame).is_err() {
        return out; // malformed frame: the node never sees it, same as csp_id_strip failing
    }
    node.router.receive(p, 0);

    // Turn the crank to quiescence, capturing anything that goes back out.
    //
    // Forwarding is the part that matters here: the router hands back a pool index and the
    // caller is responsible for putting the frame on the wire. Doing that here is what
    // makes this an end-to-end test rather than an assertion about which interface index
    // the router picked -- and it is exactly what no unit test did, which is how a router
    // that forwarded nothing at all passed 451 of them.
    for _ in 0..64 {
        match node.work(0) {
            Routed::Idle => break,
            Routed::Delivered { .. } => {}
            Routed::Forwarded { packet, .. } => {
                if let Some(mut p) = node.take_forwarded(packet) {
                    if p.prepend_header(version).is_ok() {
                        out.tx.push(p.with_frame(|f| f.to_vec()));
                    }
                }
            }
            Routed::Dropped(_) => {}
        }
    }

    // What did the application get?
    for &port in watch_ports {
        while let Some(conn) = node.accept() {
            let info = match node.conn_info(conn) {
                Ok(i) => i,
                Err(_) => break,
            };
            while let Ok(Some(pkt)) = node.read(conn) {
                let payload = pkt.with_payload(|d| d.to_vec());
                out.delivered.push(Delivered {
                    port: info.dport,
                    src: info.src,
                    dst: info.dst,
                    dport: info.dport,
                    sport: info.sport,
                    payload,
                });
            }
            let _ = node.close(conn);
            let _ = port;
        }
    }
    out
}

/// Build a complete framed packet: encoded header followed by payload.
fn framed(version: Version, id: Id, payload: &[u8]) -> Vec<u8> {
    let hdr = match version {
        Version::V1 => 4,
        Version::V2 => 6,
    };
    let mut v = vec![0u8; hdr + payload.len()];
    id.encode(version, &mut v).expect("id fits the version");
    v[hdr..].copy_from_slice(payload);
    v
}

/// A packet addressed to this node, on a bound port, must reach the application on both
/// sides with the same endpoints and the same bytes.
///
/// This is the plainest thing a CSP node does and it was never checked against the C —
/// only against a reading of it.
#[test]
fn a_packet_for_a_bound_port_reaches_the_application_identically() {
    let _g = LOCK.lock().unwrap();
    let version = Version::V1;
    c_set_version(version);
    assert!(
        c_node_init(version, NODE_ADDR, 2, EGRESS_ADDR),
        "C node came up"
    );
    assert_eq!(c_node_bind(10), 0, "bind failed");

    let mut rng = Rng(0x0DE_0001);
    let mut compared = 0u32;

    for _ in 0..200 {
        let sport = (rng.next() % 32) as u8;
        let src = (rng.next() % 30) as u16;
        if src == NODE_ADDR {
            continue; // a packet from ourselves is a different case
        }
        let len = (rng.next() % 24) as usize;
        let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let id = Id {
            pri: 2,
            flags: 0,
            src,
            dst: NODE_ADDR,
            dport: 10,
            sport,
        };
        let frame = framed(version, id, &payload);

        let c = c_node_exchange(&frame, &[10]);
        let r = rust_node_exchange(version, &frame, &[10], &[10]);

        assert_eq!(
            c.delivered.len(),
            r.delivered.len(),
            "delivery count differs for {id:?}\n  C {:?}\n  R {:?}",
            c.delivered,
            r.delivered
        );
        if let (Some(cd), Some(rd)) = (c.delivered.first(), r.delivered.first()) {
            assert_eq!(cd.payload, rd.payload, "payload for {id:?}");
            assert_eq!(
                (cd.src, cd.dport, cd.sport),
                (rd.src, rd.dport, rd.sport),
                "connection endpoints for {id:?}"
            );
            compared += 1;
        }
    }
    assert!(
        compared > 150,
        "only {compared} deliveries actually compared"
    );
}

/// A packet for a port nobody bound must not reach any application, on either side.
#[test]
fn a_packet_for_an_unbound_port_is_delivered_to_nobody() {
    let _g = LOCK.lock().unwrap();
    let version = Version::V1;
    c_set_version(version);
    assert!(c_node_init(version, NODE_ADDR, 2, EGRESS_ADDR));
    assert_eq!(c_node_bind(10), 0, "bind failed");

    // Port 11 is never bound on either side.
    let id = Id {
        pri: 2,
        flags: 0,
        src: 3,
        dst: NODE_ADDR,
        dport: 11,
        sport: 4,
    };
    let frame = framed(version, id, b"nobody is listening");

    let c = c_node_exchange(&frame, &[10, 11]);
    let r = rust_node_exchange(version, &frame, &[10], &[10, 11]);

    assert!(c.delivered.is_empty(), "C delivered {:?}", c.delivered);
    assert!(r.delivered.is_empty(), "Rust delivered {:?}", r.delivered);
}

/// A packet addressed to somebody else must leave the node on the wire.
///
/// This is the whole job of a router, and it is the one thing the codec-level differential
/// tests structurally could not check. The C emits the frame on its default interface.
#[test]
fn a_packet_for_another_node_is_forwarded_onto_the_wire() {
    let _g = LOCK.lock().unwrap();
    let version = Version::V1;
    c_set_version(version);
    assert!(c_node_init(version, NODE_ADDR, 2, EGRESS_ADDR));
    assert_eq!(c_node_bind(10), 0);

    // Addressed to node 18: not us, not either interface's own address, but inside the
    // egress interface's subnet (16..23) so it has somewhere to go.
    let id = Id {
        pri: 2,
        flags: 0,
        src: 3,
        dst: 18,
        dport: 10,
        sport: 4,
    };
    let frame = framed(version, id, b"please forward me");

    let c = c_node_exchange(&frame, &[10]);
    // Interface 0 is the Rust node's only interface and its default route.
    let r = rust_node_exchange_routed(version, &frame, &[10], &[10], &[(18, 5, 1, 0xFFFF)]);

    assert!(
        c.delivered.is_empty(),
        "not addressed to us, so no local delivery"
    );
    assert!(r.delivered.is_empty());

    assert_eq!(c.tx.len(), 1, "the C forwards it onto the wire");
    assert_eq!(r.tx.len(), 1, "the port must forward it too");
    assert_eq!(
        c.tx[0], r.tx[0],
        "the forwarded frame must be byte-identical -- a router that forwards a \
         different packet than it received is worse than one that forwards none"
    );
    // And what went out is what came in: forwarding must not mutate the packet.
    assert_eq!(c.tx[0], frame, "the C forwards the frame unchanged");
}

/// Nothing leaks, whatever the node decides to do with a packet.
///
/// Delivery, forwarding and dropping all take a buffer out of the pool; each must put it
/// back. The C's own robustness suite exists to catch this, and a leak here would starve
/// the node in orbit long after the packet that caused it was forgotten.
#[test]
fn no_path_through_the_node_leaks_a_buffer() {
    let _g = LOCK.lock().unwrap();
    let version = Version::V1;
    c_set_version(version);
    assert!(c_node_init(version, NODE_ADDR, 2, EGRESS_ADDR));
    assert_eq!(c_node_bind(10), 0);

    let before = c_node_buf_free();
    let mut rng = Rng(0x0DE_0002);

    for _ in 0..400 {
        // A spread across every outcome: delivered, forwarded, dropped for no route,
        // dropped for an unbound port.
        let dst = match rng.next() % 4 {
            0 => NODE_ADDR, // to us, bound port
            1 => 18,        // forwardable, egress subnet
            2 => 2,         // no route, no interface subnet
            _ => NODE_ADDR, // to us, unbound port below
        };
        let dport = if rng.next() % 4 == 3 { 11 } else { 10 };
        let id = Id {
            pri: 2,
            flags: 0,
            src: 3,
            dst,
            dport,
            sport: 4,
        };
        let len = (rng.next() % 20) as usize;
        let payload: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let frame = framed(version, id, &payload);

        let _ = c_node_exchange(&frame, &[10]);
    }

    assert_eq!(
        c_node_buf_free(),
        before,
        "the C node leaked {} buffers over 400 exchanges",
        before - c_node_buf_free()
    );
}
