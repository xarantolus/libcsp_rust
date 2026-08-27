//! `csp_rtable_save` — the text a ground tool reads back off a node — against a real node.
//!
//! # Nothing had ever compared it
//!
//! `ctest/tools/api_map.tsv` mapped `csp_rtable_save` to `Table::format_route`, which
//! renders **one** route. Measured on this branch: `format_route` had no caller outside its
//! own unit tests, `csp_rtable_save` was called by neither harness, and nothing anywhere
//! joined routes into a table. So the comma separator, the whole-table behaviour and the
//! truncation rule had no counterpart at all, and the per-route text had never been put
//! beside the C's.
//!
//! # Two differences, both measured
//!
//! `csp_rtable_save_route` (`csp_rtable_stdio.c:91`) **omits the netmask when it equals the
//! host-bit width**, because that is a host route and the parser defaults to it. The port
//! always printed it. Which masks count as "host" depends on the wire version, which is why
//! `format_route` now takes one:
//!
//! ```text
//! v1 (5 host bits):  load "8/5 CAN"    -> save "8 CAN"
//!                    load "31/5 CAN 7" -> save "31 CAN 7"
//! v2 (14 host bits): load "8/5 CAN"    -> save "8/5 CAN"
//!                    load "8/14 CAN"   -> save "8 CAN"
//! both:              load "0/0 CAN"    -> save "0/0 CAN"
//! ```
//!
//! Both forms parse back to the same table, so this is not a routing bug — it is the text a
//! node reports about itself, which an operator diffs against the text they uploaded.
//!
//! The second: entries join with a bare comma, `8/5 CAN,9 KISS 3`. `Table::save` does that
//! and, where the C `snprintf`s into a fixed buffer and stops, refuses instead.

use csp_core::rtable::{parse, Table, NO_VIA};
use csp_core::{Error, Version};
use difftest::*;

/// A four-route table per version, built in both stacks from the same text.
///
/// One table for both versions does not exist: v1 has 5 host bits, so `20/14` is an invalid
/// netmask and `1000` an unrepresentable address there — the C refuses the whole string with
/// `-2`. Each version gets a table containing a host route, a subnet route, a next hop and
/// the default route, which is what the comparison needs.
const TABLES: [(Version, &str); 2] = [
    (Version::V1, "8/5 CAN, 20 KISS 3, 0/0 CAN, 31/3 KISS"),
    (Version::V2, "8/14 CAN, 20/5 KISS 3, 0/0 CAN, 1000/9 KISS"),
];

fn names(iface: u8) -> Option<&'static str> {
    match iface {
        0 => Some("CAN"),
        1 => Some("KISS"),
        _ => None,
    }
}

/// Build the port's table from `text`, mapping interface names onto indices.
fn port_table(text: &str, version: Version) -> Table<8> {
    let mut t = Table::<8>::new(version);
    parse(text, version, |p| {
        let iface = match p.iface {
            "CAN" => 0,
            "KISS" => 1,
            other => panic!("unexpected interface {other}"),
        };
        t.set(
            p.address,
            p.netmask.unwrap_or(version.host_bits() as u16),
            iface,
            p.via.unwrap_or(NO_VIA),
        )
        .expect("room");
        Ok(())
    })
    .expect("the text parses");
    t
}

/// The port writes the table libcsp writes, at both wire versions.
///
/// One test for both versions: `csp_rtable_save` reads `csp_id_get_host_bits()` off
/// `csp_conf.version`, which the shim sets directly here — no node is initialised, so this
/// is not the one-version-per-process rule that governs the node tests.
#[test]
fn the_table_saves_as_a_real_node_saves_it() {
    let _g = lock();
    c_add_iface("CAN", 0, 0);
    c_add_iface("KISS", 0, 0);

    for (version, table) in TABLES {
        c_set_version(version);
        assert_eq!(
            c_rtable_load(table),
            Some(4),
            "{version:?}: the C accepts all four routes"
        );
        let c_text = c_rtable_save().expect("the C saves it");

        let mut out = [0u8; 256];
        let n = port_table(table, version)
            .save(version, names, &mut out)
            .expect("room");
        let port_text = core::str::from_utf8(&out[..n]).expect("ascii");

        assert_eq!(
            port_text, c_text,
            "{version:?}: the port must write the text a real node writes"
        );
        // And not vacuously equal because both are empty.
        assert!(
            c_text.contains("CAN") && c_text.contains("KISS") && c_text.contains(','),
            "{version:?}: the saved text must actually describe the table: {c_text:?}"
        );
    }
}

/// The masks the C drops, route by route, at the version that makes each one a host route.
///
/// The table above holds both a `/5` and a `/14`, and each is a host route at a different
/// version — but a formatter that dropped *every* mask, or none, would still have to differ
/// from the C on one of the two rows. This pins which is which, and pins that zero is
/// nobody's host width.
#[test]
fn a_host_routes_mask_is_dropped_and_a_subnets_is_kept() {
    let _g = lock();
    c_add_iface("CAN", 0, 0);

    for (version, text, want) in [
        (Version::V1, "8/5 CAN", "8 CAN"),
        (Version::V1, "31/5 CAN 7", "31 CAN 7"),
        (Version::V1, "8/3 CAN", "8/3 CAN"),
        (Version::V2, "8/14 CAN", "8 CAN"),
        (Version::V2, "8/5 CAN", "8/5 CAN"),
        (Version::V1, "0/0 CAN", "0/0 CAN"),
        (Version::V2, "0/0 CAN", "0/0 CAN"),
    ] {
        c_set_version(version);
        assert_eq!(c_rtable_load(text), Some(1), "{version:?} {text}");
        assert_eq!(
            c_rtable_save().as_deref(),
            Some(want),
            "{version:?}: what a real node writes for {text}"
        );

        let mut out = [0u8; 64];
        let n = port_table(text, version)
            .save(version, names, &mut out)
            .expect("room");
        assert_eq!(
            core::str::from_utf8(&out[..n]).unwrap(),
            want,
            "{version:?}: and the port must write the same for {text}"
        );
    }
}

/// A table that does not fit is refused here and silently shortened by the C.
///
/// A DELIBERATE DIVERGENCE. `csp_rtable_save` returns `CSP_ERR_NOMEM`, but it has already
/// written every route that fitted and leaves that prefix in the buffer — so a caller that
/// ignores the return value, or logs the buffer regardless, reports a **valid table that is
/// not the node's**. Refusing gives the caller nothing to misread.
#[test]
fn a_table_too_large_to_save_is_refused_rather_than_shortened() {
    let _g = lock();
    let (version, table) = TABLES[1];
    let t = port_table(table, version);

    let mut full = [0u8; 256];
    let n = t.save(version, names, &mut full).expect("room");
    assert!(
        n > 12,
        "the whole table must need more than the tiny buffer below, or this proves nothing"
    );

    let mut tiny = [0u8; 12];
    assert!(
        matches!(
            t.save(version, names, &mut tiny),
            Err(Error::BufferTooSmall { .. })
        ),
        "a table that does not fit must be refused, not shortened to one that parses"
    );
}
