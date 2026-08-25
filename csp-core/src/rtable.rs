//! CIDR routing table and its text format.
//!
//! Fixed capacity, no allocation, longest-prefix-match. The table is a value the caller
//! owns rather than the C's `static csp_route_t rtable[CSP_RTABLE_SIZE]`.
//!
//! # Two things the C does quietly that this does not
//!
//! **A full table silently eats routes.** `csp_rtable_set_internal` does
//! `entry = &rtable[rtable_inptr++]` and then clamps `rtable_inptr` back to
//! `CSP_RTABLE_SIZE - 1`, so once the table fills, every subsequent route overwrites the
//! last slot and `csp_rtable_set` still returns `CSP_ERR_NONE`. A spacecraft that adds one
//! route too many gets a routing table that is wrong in a way nothing reports.
//! [`Table::set`] returns [`Error::TableFull`](crate::Error) instead.
//!
//! **The text parser truncates at 100 characters.** `strnlen(rtable, 100)` followed by a
//! `char rtable_copy[str_len + 1]` VLA means a longer route string is silently cut, very
//! likely mid-entry. [`parse`] has no length limit and no VLA.

use crate::{Error, Result, Version};

/// The `via` value meaning "deliver directly, no next hop".
pub const NO_VIA: u16 = 0xFFFF;

/// One routing table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// Network address.
    pub address: u16,
    /// Prefix length in bits.
    pub netmask: u16,
    /// Index of the interface to send on.
    ///
    /// An index rather than a pointer: the C stores `csp_iface_t *` and documents that the
    /// interface must outlive the table, which is a lifetime rule no compiler checks.
    pub iface: u8,
    /// Next hop, or [`NO_VIA`].
    pub via: u16,
}

/// Fixed-capacity routing table.
#[derive(Debug, Clone)]
pub struct Table<const N: usize> {
    entries: [Route; N],
    len: usize,
    version: Version,
}

impl<const N: usize> Table<N> {
    /// Create an empty table for the given wire version.
    ///
    /// The version fixes `host_bits`, which every mask computation depends on — hence it
    /// belongs to the table rather than to a global that can change underneath it.
    pub const fn new(version: Version) -> Self {
        Table {
            entries: [Route {
                address: 0,
                netmask: 0,
                iface: 0,
                via: NO_VIA,
            }; N],
            len: 0,
            version,
        }
    }

    /// Number of routes.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// True if no routes are installed.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// All installed routes.
    pub fn routes(&self) -> &[Route] {
        &self.entries[..self.len]
    }

    /// Remove every route.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Install or update a route.
    ///
    /// A netmask wider than the address space is clamped to `host_bits`, matching the C.
    /// Returns [`Error::TableFull`](crate::Error) rather than overwriting silently.
    pub fn set(&mut self, address: u16, netmask: u16, iface: u8, via: u16) -> Result<()> {
        let host_bits = self.version.host_bits() as u16;
        let netmask = if netmask > host_bits { host_bits } else { netmask };

        if address > self.version.max_node_id() {
            return Err(Error::FieldOutOfRange {
                field: crate::Field::Destination,
            });
        }

        // Updating an exact match in place is what the C does, and it keeps a repeated
        // set() from consuming the table.
        for e in self.entries[..self.len].iter_mut() {
            if e.address == address && e.netmask == netmask && e.iface == iface {
                e.via = via;
                return Ok(());
            }
        }
        if self.len >= N {
            return Err(Error::TableFull);
        }
        self.entries[self.len] = Route {
            address,
            netmask,
            iface,
            via,
        };
        self.len += 1;
        Ok(())
    }

    /// Longest-prefix-match lookup.
    ///
    /// On an equal-length tie the later entry wins, matching the C's `>=`.
    pub fn find(&self, addr: u16) -> Option<&Route> {
        let host_bits = self.version.host_bits() as u16;
        let mut best: Option<&Route> = None;
        let mut best_mask = 0u16;

        for e in self.entries[..self.len].iter() {
            let shift = host_bits.saturating_sub(e.netmask);
            let hostbits: u16 = (1u16 << shift) - 1;
            let netbits = !hostbits;
            if (e.address & netbits) == (addr & netbits) && e.netmask >= best_mask {
                best_mask = e.netmask;
                best = Some(e);
            }
        }
        best
    }
}

/// One parsed entry from the text format, before interface-name resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParsedRoute<'a> {
    /// Network address.
    pub address: u16,
    /// Prefix length. `None` means "use `host_bits`".
    pub netmask: Option<u16>,
    /// Interface name as written.
    pub iface: &'a str,
    /// Next hop, if given.
    pub via: Option<u16>,
}

/// Parse the route-table text format.
///
/// Accepts the same four shapes the C's four `sscanf` calls do, comma-separated:
///
/// ```text
/// "<addr>/<mask> <iface> <via>"
/// "<addr>/<mask> <iface>"
/// "<addr> <iface> <via>"
/// "<addr> <iface>"
/// ```
///
/// Written by hand: no `sscanf`, no VLA, no C-primitive shim, and no 100-character cliff.
/// The callback is invoked per entry so nothing needs allocating.
pub fn parse<'a, F>(text: &'a str, mut each: F) -> Result<usize>
where
    F: FnMut(ParsedRoute<'a>) -> Result<()>,
{
    let mut count = 0usize;
    for entry in text.split(',') {
        let entry = entry.trim();
        // The C skips tokens of length <= 1, which is how it tolerates trailing commas.
        if entry.len() <= 1 {
            continue;
        }

        let mut fields = entry.split_whitespace();
        let addr_field = fields.next().ok_or(Error::Malformed)?;
        let iface = fields.next().ok_or(Error::Malformed)?;
        let via = match fields.next() {
            Some(v) => Some(v.parse::<u16>().map_err(|_| Error::Malformed)?),
            None => None,
        };
        if fields.next().is_some() {
            return Err(Error::Malformed);
        }

        let (address, netmask) = match addr_field.split_once('/') {
            Some((a, m)) => (
                a.parse::<u16>().map_err(|_| Error::Malformed)?,
                Some(m.parse::<u16>().map_err(|_| Error::Malformed)?),
            ),
            None => (addr_field.parse::<u16>().map_err(|_| Error::Malformed)?, None),
        };

        each(ParsedRoute {
            address,
            netmask,
            iface,
            via,
        })?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> Table<4> {
        Table::new(Version::V1)
    }

    #[test]
    fn default_route_matches_everything() {
        let mut tb = t();
        tb.set(0, 0, 1, NO_VIA).unwrap();
        for addr in [0u16, 1, 8, 31] {
            assert_eq!(tb.find(addr).unwrap().iface, 1, "addr {addr}");
        }
    }

    #[test]
    fn longest_prefix_wins() {
        let mut tb = t();
        tb.set(0, 0, 1, NO_VIA).unwrap();
        tb.set(8, 5, 2, NO_VIA).unwrap();
        assert_eq!(tb.find(8).unwrap().iface, 2, "specific route must beat default");
        assert_eq!(tb.find(9).unwrap().iface, 1, "everything else takes the default");
    }

    #[test]
    fn later_entry_wins_an_equal_length_tie() {
        // Matches the C's `>=`.
        let mut tb = t();
        tb.set(8, 5, 1, NO_VIA).unwrap();
        tb.set(8, 5, 2, NO_VIA).unwrap();
        assert_eq!(tb.find(8).unwrap().iface, 2);
    }

    #[test]
    fn setting_the_same_route_twice_updates_in_place() {
        let mut tb = t();
        tb.set(8, 5, 1, NO_VIA).unwrap();
        tb.set(8, 5, 1, 12).unwrap();
        assert_eq!(tb.len(), 1, "must not consume a second slot");
        assert_eq!(tb.find(8).unwrap().via, 12);
    }

    #[test]
    fn a_full_table_reports_instead_of_eating_the_route() {
        // The C overwrites its last slot and still returns success.
        let mut tb = t();
        for i in 0..4u16 {
            tb.set(i, 5, i as u8, NO_VIA).unwrap();
        }
        assert_eq!(tb.len(), 4);
        assert_eq!(tb.set(9, 5, 9, NO_VIA), Err(Error::TableFull));
        // and nothing already installed was disturbed
        assert_eq!(tb.len(), 4);
        assert_eq!(tb.find(3).unwrap().iface, 3);
    }

    #[test]
    fn netmask_wider_than_the_address_space_is_clamped() {
        let mut tb = t();
        tb.set(8, 99, 1, NO_VIA).unwrap();
        assert_eq!(tb.routes()[0].netmask, Version::V1.host_bits() as u16);
    }

    #[test]
    fn address_outside_the_wire_version_is_refused() {
        let mut tb = t();
        assert!(tb.set(1000, 5, 1, NO_VIA).is_err(), "1000 does not fit 5 bits");
        let mut tb2: Table<4> = Table::new(Version::V2);
        assert!(tb2.set(1000, 14, 1, NO_VIA).is_ok());
    }

    #[test]
    fn no_match_returns_none() {
        let mut tb = t();
        tb.set(8, 5, 1, NO_VIA).unwrap();
        assert!(tb.find(9).is_none());
    }

    #[test]
    fn clear_empties_the_table() {
        let mut tb = t();
        tb.set(8, 5, 1, NO_VIA).unwrap();
        tb.clear();
        assert!(tb.is_empty());
        assert!(tb.find(8).is_none());
    }

    fn collect<'a>(s: &'a str) -> (usize, [Option<ParsedRoute<'a>>; 8]) {
        let mut out: [Option<ParsedRoute>; 8] = [None; 8];
        let mut n = 0;
        let count = parse(s, |r| {
            out[n] = Some(r);
            n += 1;
            Ok(())
        })
        .unwrap();
        (count, out)
    }

    #[test]
    fn parses_all_four_shapes_the_c_accepts() {
        let (n, r) = collect("0/0 CAN, 8/5 KISS 12, 9 CAN, 10 KISS 3");
        assert_eq!(n, 4);
        assert_eq!(
            r[0].unwrap(),
            ParsedRoute { address: 0, netmask: Some(0), iface: "CAN", via: None }
        );
        assert_eq!(
            r[1].unwrap(),
            ParsedRoute { address: 8, netmask: Some(5), iface: "KISS", via: Some(12) }
        );
        assert_eq!(
            r[2].unwrap(),
            ParsedRoute { address: 9, netmask: None, iface: "CAN", via: None }
        );
        assert_eq!(
            r[3].unwrap(),
            ParsedRoute { address: 10, netmask: None, iface: "KISS", via: Some(3) }
        );
    }

    #[test]
    fn parses_the_default_route_the_ground_station_uses() {
        // "0/0 CAN" is the only route string in the whole flight repository.
        let (n, r) = collect("0/0 CAN");
        assert_eq!(n, 1);
        assert_eq!(r[0].unwrap().address, 0);
        assert_eq!(r[0].unwrap().netmask, Some(0));
        assert_eq!(r[0].unwrap().iface, "CAN");
    }

    #[test]
    fn trailing_and_empty_entries_are_skipped() {
        let (n, _) = collect("0/0 CAN,");
        assert_eq!(n, 1);
        let (n, _) = collect("0/0 CAN, , 8 KISS");
        assert_eq!(n, 2);
    }

    #[test]
    fn a_long_route_string_is_not_truncated() {
        // The C's strnlen(rtable, 100) cuts this mid-entry and silently drops the tail.
        const LONG: &str = "0/5 IFACE0,1/5 IFACE1,2/5 IFACE2,3/5 IFACE3,4/5 IFACE4,\
5/5 IFACE5,6/5 IFACE6,7/5 IFACE7,8/5 IFACE8,9/5 IFACE9,\
10/5 IFACEA,11/5 IFACEB,12/5 IFACEC,13/5 IFACED,14/5 IFACEE";
        assert!(LONG.len() > 100, "test string must exceed the C's limit");
        let mut n = 0;
        parse(LONG, |_| {
            n += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(n, 15, "every entry must survive");
    }

    #[test]
    fn malformed_entries_are_refused_not_guessed() {
        for bad in ["notanumber CAN", "8/notamask CAN", "88", "8 CAN 1 extra", "8/5/6 CAN"] {
            assert!(
                parse(bad, |_| Ok(())).is_err(),
                "{bad:?} should not parse"
            );
        }
    }

    #[test]
    fn single_character_entries_are_skipped_like_the_c() {
        // strlen(str) > 1 in csp_rtable_stdio.c: a lone "8" is not an error, it is ignored.
        assert_eq!(parse("8", |_| Ok(())).unwrap(), 0);
        assert_eq!(parse("0/0 CAN,x", |_| Ok(())).unwrap(), 1);
    }

    #[test]
    fn parse_feeds_a_table_end_to_end() {
        let mut tb = t();
        parse("0/0 CAN, 8/5 CAN 12", |r| {
            let mask = r.netmask.unwrap_or(Version::V1.host_bits() as u16);
            tb.set(r.address, mask, 0, r.via.unwrap_or(NO_VIA))
        })
        .unwrap();
        assert_eq!(tb.len(), 2);
        assert_eq!(tb.find(8).unwrap().via, 12);
        assert_eq!(tb.find(20).unwrap().via, NO_VIA);
    }
}
