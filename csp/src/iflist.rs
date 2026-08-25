//! The interface registry.
//!
//! Holds each interface's identity — name, address, netmask, default flag, counters — and
//! answers the lookups routing and CMP need. The *drivers* stay with the caller; this
//! registry deals in indices, which is what [`Router`](crate::Router) and
//! [`Outbound`](crate::Outbound) hand back.
//!
//! The C keeps this as an intrusive linked list of caller-owned `csp_iface_t`s
//! (`static csp_iface_t * interfaces`), documented with "must remain valid as long as the
//! application is running" — a lifetime rule no compiler checks. Here the registry owns
//! its entries.
//!
//! # An out-of-range netmask shifts out of range in the C
//!
//! `csp_iflist_is_within_subnet` computes
//!
//! ```c
//! uint16_t netmask = ((1 << ifc->netmask) - 1) << (csp_id_get_host_bits() - ifc->netmask);
//! ```
//!
//! If `ifc->netmask` exceeds `host_bits` — 5 on CSP v1, and nothing validates the field on
//! assignment — then `host_bits - ifc->netmask` underflows as unsigned and the shift count
//! is enormous, which is undefined behaviour. [`IfList::add`] rejects the netmask up front.
//!
//! # The netmask trap that bit the flight code
//!
//! When an interface's netmask equals `host_bits`, the node's **own** address reads as a
//! subnet broadcast. The flight code carries a fifteen-line comment about this before
//! assigning `csp_if_lo.addr`, because self-addressed packets would otherwise go out on
//! the wire instead of looping back. [`IfList::is_broadcast_for`] makes the condition
//! askable rather than folklore.

use crate::iface::Stats;
use csp_core::{Error, Field, Result, Version};

/// Maximum length of an interface name, matching `CSP_IFLIST_NAME_MAX`.
pub const NAME_MAX: usize = 10;

/// One registered interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// Name, as used by CMP `IF_STATS` and the route-table text format.
    pub name: &'static str,
    /// This interface's address on its subnet.
    pub addr: u16,
    /// Prefix length. `0` means "no subnet", and such an interface is skipped by
    /// [`IfList::find_by_subnet`] — matching the C, which rejects `netmask == 0` there.
    pub netmask: u16,
    /// Whether this is a default-route target.
    pub is_default: bool,
    /// Counters.
    pub stats: Stats,
}

/// An additional receive address bound to an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alias {
    /// The extra address.
    pub addr: u16,
    /// Which interface it belongs to.
    pub iface: u8,
}

/// Fixed-capacity interface registry.
#[derive(Debug)]
pub struct IfList<const N: usize, const A: usize> {
    entries: [Option<Entry>; N],
    aliases: [Option<Alias>; A],
    version: Version,
}

impl<const N: usize, const A: usize> IfList<N, A> {
    /// Compile-time invariant: an index is a `u8`, so a registry larger than 256 has
    /// entries nothing can refer to.
    const SANITY: () = {
        assert!(N > 0, "a node needs at least one interface slot");
        assert!(N <= 256, "interfaces are addressed by u8");
    };

    /// An empty registry for the given wire version.
    ///
    /// The version fixes `host_bits`, which every subnet computation depends on.
    pub fn new(version: Version) -> Self {
        let () = Self::SANITY;
        IfList {
            entries: [None; N],
            aliases: [None; A],
            version,
        }
    }

    /// Interfaces registered.
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// True if nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Register an interface, returning its index.
    ///
    /// Rejects a name longer than [`NAME_MAX`], a duplicate name, an address outside the
    /// wire version, and a netmask wider than the address space — the last of which is the
    /// out-of-range shift described in the module docs.
    pub fn add(
        &mut self,
        name: &'static str,
        addr: u16,
        netmask: u16,
        is_default: bool,
    ) -> Result<u8> {
        if name.len() > NAME_MAX {
            return Err(Error::LengthExceedsMaximum {
                got: name.len(),
                max: NAME_MAX,
            });
        }
        if addr > self.version.max_node_id() {
            return Err(Error::FieldOutOfRange {
                field: Field::Source,
            });
        }
        if netmask > self.version.host_bits() as u16 {
            return Err(Error::FieldOutOfRange {
                field: Field::Destination,
            });
        }
        if self.find_by_name(name).is_some() {
            // Two interfaces with one name makes CMP IF_STATS ambiguous, and the route
            // text format unresolvable.
            return Err(Error::TableFull);
        }
        for (i, slot) in self.entries.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(Entry {
                    name,
                    addr,
                    netmask,
                    is_default,
                    stats: Stats::default(),
                });
                return Ok(i as u8);
            }
        }
        Err(Error::TableFull)
    }

    /// Remove an interface.
    pub fn remove(&mut self, index: u8) -> Result<()> {
        let i = index as usize;
        if i >= N || self.entries[i].is_none() {
            return Err(Error::NoTransferInProgress);
        }
        self.entries[i] = None;
        // Aliases pointing at it would otherwise resolve to a freed slot.
        for a in self.aliases.iter_mut() {
            if matches!(a, Some(al) if al.iface == index) {
                *a = None;
            }
        }
        Ok(())
    }

    /// Look up by index.
    pub fn get(&self, index: u8) -> Option<&Entry> {
        self.entries.get(index as usize)?.as_ref()
    }

    /// Mutable access, for counter updates.
    pub fn get_mut(&mut self, index: u8) -> Option<&mut Entry> {
        self.entries.get_mut(index as usize)?.as_mut()
    }

    /// Look up by name — what CMP `IF_STATS` and the route text format use.
    pub fn find_by_name(&self, name: &str) -> Option<u8> {
        self.entries.iter().enumerate().find_map(|(i, e)| {
            e.as_ref()
                .filter(|e| e.name == name)
                .map(|_| i as u8)
        })
    }

    /// Look up by exact address, including aliases.
    pub fn find_by_addr(&self, addr: u16) -> Option<u8> {
        if let Some(i) = self.entries.iter().enumerate().find_map(|(i, e)| {
            e.as_ref().filter(|e| e.addr == addr).map(|_| i as u8)
        }) {
            return Some(i);
        }
        self.aliases
            .iter()
            .flatten()
            .find(|a| a.addr == addr)
            .map(|a| a.iface)
    }

    /// Is `addr` inside this interface's subnet?
    ///
    /// `false` for a netmask of zero, matching the C's rejection in `get_by_subnet`.
    pub fn is_within_subnet(&self, addr: u16, index: u8) -> bool {
        let Some(e) = self.get(index) else {
            return false;
        };
        if e.netmask == 0 {
            return false;
        }
        let host_bits = self.version.host_bits() as u16;
        // `add` guarantees netmask <= host_bits, so this shift is in range. The C
        // computes the same expression with no such guarantee.
        let shift = host_bits - e.netmask;
        let netmask: u16 = ((1u16 << e.netmask) - 1) << shift;
        (e.addr & netmask) == (addr & netmask)
    }

    /// First interface whose subnet contains `addr`.
    pub fn find_by_subnet(&self, addr: u16) -> Option<u8> {
        (0..N as u8).find(|&i| self.is_within_subnet(addr, i))
    }

    /// First interface marked as a default-route target.
    pub fn find_default(&self) -> Option<u8> {
        self.entries.iter().enumerate().find_map(|(i, e)| {
            e.as_ref().filter(|e| e.is_default).map(|_| i as u8)
        })
    }

    /// Every registered index, in order.
    pub fn indices(&self) -> impl Iterator<Item = u8> + '_ {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.is_some())
            .map(|(i, _)| i as u8)
    }

    /// Bind an extra receive address to an interface.
    pub fn add_alias(&mut self, addr: u16, iface: u8) -> Result<()> {
        if self.get(iface).is_none() {
            return Err(Error::NoTransferInProgress);
        }
        if addr > self.version.max_node_id() {
            return Err(Error::FieldOutOfRange {
                field: Field::Source,
            });
        }
        for slot in self.aliases.iter_mut() {
            if slot.is_none() {
                *slot = Some(Alias { addr, iface });
                return Ok(());
            }
        }
        Err(Error::TableFull)
    }

    /// Is `addr` an alias of some interface?
    pub fn is_alias(&self, addr: u16) -> bool {
        self.aliases.iter().flatten().any(|a| a.addr == addr)
    }

    /// Would `addr` be a broadcast as seen from this interface?
    ///
    /// Worth asking explicitly: when `netmask == host_bits` this is true for the
    /// interface's **own** address, which is the trap the flight code documents at length
    /// before assigning the loopback address.
    pub fn is_broadcast_for(&self, addr: u16, index: u8) -> bool {
        match self.get(index) {
            Some(e) => self.version.is_broadcast(addr, e.addr, e.netmask),
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type L = IfList<4, 4>;

    fn list() -> L {
        IfList::new(Version::V1)
    }

    #[test]
    fn add_and_look_up_by_name() {
        let mut l = list();
        let can = l.add("CAN", 1, 5, true).unwrap();
        let kiss = l.add("KISS", 2, 5, false).unwrap();
        assert_ne!(can, kiss);
        assert_eq!(l.find_by_name("CAN"), Some(can));
        assert_eq!(l.find_by_name("KISS"), Some(kiss));
        assert_eq!(l.find_by_name("NOPE"), None);
        assert_eq!(l.len(), 2);
    }

    #[test]
    fn a_duplicate_name_is_refused() {
        // Two interfaces with one name makes CMP IF_STATS ambiguous and the route text
        // format unresolvable.
        let mut l = list();
        l.add("CAN", 1, 5, false).unwrap();
        assert_eq!(l.add("CAN", 2, 5, false), Err(Error::TableFull));
    }

    #[test]
    fn an_overlong_name_is_refused_with_the_limit() {
        let mut l = list();
        assert_eq!(
            l.add("ABCDEFGHIJK", 1, 5, false),
            Err(Error::LengthExceedsMaximum { got: 11, max: 10 })
        );
    }

    #[test]
    fn a_netmask_wider_than_the_address_space_is_refused() {
        // The C computes (host_bits - netmask) as unsigned; with netmask > host_bits that
        // underflows and the shift count is enormous -- undefined behaviour.
        let mut l = list();
        assert!(matches!(
            l.add("CAN", 1, 99, false),
            Err(Error::FieldOutOfRange { .. })
        ));
        // and the legal boundary is accepted
        assert!(l.add("CAN", 1, 5, false).is_ok());
    }

    #[test]
    fn an_address_outside_the_wire_version_is_refused() {
        let mut l = list();
        assert!(matches!(
            l.add("CAN", 1000, 5, false),
            Err(Error::FieldOutOfRange { .. })
        ));
        let mut l2: IfList<4, 4> = IfList::new(Version::V2);
        assert!(l2.add("CAN", 1000, 14, false).is_ok());
    }

    #[test]
    fn a_full_registry_reports_rather_than_overwriting() {
        let mut l = list();
        for i in 0..4u16 {
            l.add(
                ["A", "B", "C", "D"][i as usize],
                i,
                5,
                false,
            )
            .unwrap();
        }
        assert_eq!(l.add("E", 9, 5, false), Err(Error::TableFull));
    }

    #[test]
    fn subnet_matching() {
        // netmask 3 on a 5-bit address space: top 3 bits are the network.
        let mut l = list();
        let i = l.add("CAN", 0b01000, 3, false).unwrap();
        assert!(l.is_within_subnet(0b01000, i));
        assert!(l.is_within_subnet(0b01011, i), "same network, different host");
        assert!(!l.is_within_subnet(0b10000, i), "different network");
        assert_eq!(l.find_by_subnet(0b01011), Some(i));
        assert_eq!(l.find_by_subnet(0b10000), None);
    }

    #[test]
    fn a_zero_netmask_never_matches_a_subnet() {
        // The C rejects netmask == 0 in get_by_subnet; without that, an interface with no
        // subnet would match everything.
        let mut l = list();
        let i = l.add("CAN", 1, 0, false).unwrap();
        assert!(!l.is_within_subnet(1, i));
        assert!(!l.is_within_subnet(99, i));
        assert_eq!(l.find_by_subnet(1), None);
    }

    #[test]
    fn default_route_lookup() {
        let mut l = list();
        l.add("CAN", 1, 5, false).unwrap();
        let dfl = l.add("KISS", 2, 5, true).unwrap();
        assert_eq!(l.find_default(), Some(dfl));
    }

    #[test]
    fn no_default_is_none_not_a_guess() {
        let mut l = list();
        l.add("CAN", 1, 5, false).unwrap();
        assert_eq!(l.find_default(), None);
    }

    #[test]
    fn aliases_resolve_to_their_interface() {
        let mut l = list();
        let can = l.add("CAN", 1, 5, false).unwrap();
        l.add_alias(7, can).unwrap();
        assert!(l.is_alias(7));
        assert!(!l.is_alias(8));
        assert_eq!(l.find_by_addr(7), Some(can), "an alias resolves like an address");
        assert_eq!(l.find_by_addr(1), Some(can), "and so does the real address");
    }

    #[test]
    fn an_alias_on_a_missing_interface_is_refused() {
        let mut l = list();
        assert!(l.add_alias(7, 3).is_err());
    }

    #[test]
    fn removing_an_interface_removes_its_aliases() {
        // Otherwise the alias resolves to a freed slot.
        let mut l = list();
        let can = l.add("CAN", 1, 5, false).unwrap();
        l.add_alias(7, can).unwrap();
        l.remove(can).unwrap();
        assert!(!l.is_alias(7), "a dangling alias must not survive");
        assert_eq!(l.find_by_addr(7), None);
        assert_eq!(l.find_by_name("CAN"), None);
    }

    #[test]
    fn removing_an_unregistered_interface_reports() {
        let mut l = list();
        assert!(l.remove(2).is_err());
    }

    #[test]
    fn a_removed_slot_is_reused() {
        let mut l = list();
        let a = l.add("A", 1, 5, false).unwrap();
        l.remove(a).unwrap();
        let b = l.add("B", 2, 5, false).unwrap();
        assert_eq!(a, b, "the freed slot should be reused");
        assert_eq!(l.len(), 1);
    }

    #[test]
    fn indices_lists_only_registered_interfaces() {
        let mut l = list();
        let a = l.add("A", 1, 5, false).unwrap();
        let b = l.add("B", 2, 5, false).unwrap();
        l.remove(a).unwrap();
        let live: heapless::Vec8 = l.indices().collect();
        assert_eq!(live.as_slice(), &[b]);
    }

    mod heapless {
        pub struct Vec8 {
            items: [u8; 8],
            len: usize,
        }
        impl Vec8 {
            pub fn as_slice(&self) -> &[u8] {
                &self.items[..self.len]
            }
        }
        impl FromIterator<u8> for Vec8 {
            fn from_iter<I: IntoIterator<Item = u8>>(it: I) -> Self {
                let mut v = Vec8 { items: [0; 8], len: 0 };
                for i in it {
                    v.items[v.len] = i;
                    v.len += 1;
                }
                v
            }
        }
    }

    #[test]
    fn an_interface_whose_netmask_equals_host_bits_sees_its_own_address_as_broadcast() {
        // The trap the flight code documents in fifteen lines before assigning
        // csp_if_lo.addr: self-addressed packets would go out on the wire instead of
        // looping back.
        let mut l = list();
        let i = l.add("LOOP", 11, Version::V1.host_bits() as u16, false).unwrap();
        assert!(
            l.is_broadcast_for(11, i),
            "with netmask == host_bits the interface's own address reads as broadcast"
        );

        // With a narrower mask it does not.
        let mut l2 = list();
        let j = l2.add("CAN", 11, 0, false).unwrap();
        assert!(!l2.is_broadcast_for(11, j));
    }

    #[test]
    fn counters_are_per_interface() {
        let mut l = list();
        let a = l.add("A", 1, 5, false).unwrap();
        let b = l.add("B", 2, 5, false).unwrap();
        l.get_mut(a).unwrap().stats.tx = 5;
        assert_eq!(l.get(a).unwrap().stats.tx, 5);
        assert_eq!(l.get(b).unwrap().stats.tx, 0);
    }
}
