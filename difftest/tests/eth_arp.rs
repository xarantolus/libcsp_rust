//! The Ethernet ARP table — which MAC every outgoing frame is addressed to — against the C.
//!
//! # Nothing had ever called either function
//!
//! `csp_eth_arp_set_addr` and `csp_eth_arp_get_addr` were on the shortlist of `ported` C
//! functions neither harness calls, and `csp_if_eth.c` was in `ctest`'s build (for the EFP
//! reassembly suite) but not `difftest`'s. On the port side `ArpTable` had **no caller at
//! all** — not in `csp`, not in either harness. That is expected of a sans-io library, where
//! the driver owns the NIC and calls `lookup`/`learn` itself, but it meant the semantics had
//! never been put beside the C's.
//!
//! # Measured
//!
//! | | C | port |
//! |---|---|---|
//! | an address never heard of | broadcast `ff:ff:ff:ff:ff:ff` | the same |
//! | a second MAC for a known address | **ignored** — first write wins for ever | **replaces** it |
//! | the 11th distinct address, table of 10 | **never learned**, broadcast for ever | evicts the least recently used |
//!
//! The first is the rule that matters most and both agree. The other two are deliberate,
//! asserted here as divergences so neither can change unnoticed.
//!
//! # Why the port does not copy them
//!
//! `csp_eth_arp_set_addr` returns early when an entry exists (`csp_if_eth.c:101`, "Already
//! set"), and `arp_alloc` is a bump allocator over a fixed array with no free
//! (`csp_if_eth.c:72`), so `arp_used` only ever rises. Together: a node that has heard from
//! ten peers addresses every *new* peer by broadcast for the rest of the mission, and a peer
//! that changes MAC is unreachable for the rest of the mission. Neither is recoverable in
//! orbit, and the first-write-wins rule is not the security win it looks like — learning
//! happens on receive from any frame, so it only means a spoofer has to be first.

use csp_core::eth::{ArpTable, BROADCAST_MAC};
use difftest::*;

/// `ARP_MAX_ENTRIES` in `csp_if_eth.c`. The port table is built the same size so that
/// "the table is full" means the same thing on both sides.
const ARP_MAX: usize = 10;

fn mac(n: u8) -> [u8; 6] {
    [0x02, 0, 0, 0, 0, n]
}

/// One test, in order: libcsp's ARP list is file-scope with no reset and no eviction, so the
/// fill below exhausts it for the whole process. A second `#[test]` would be asking its
/// question of whatever the first one left behind — the mistake `node_alias.rs` made.
#[test]
fn the_port_resolves_a_mac_the_way_a_real_node_does_and_diverges_where_it_says_it_does() {
    let _g = lock();
    let mut port = ArpTable::<ARP_MAX>::new();

    // 1. An address never heard of is broadcast, in both. This is the rule a driver leans
    //    on, and getting it wrong means either dropping the packet or sending it nowhere.
    const UNKNOWN: u16 = 900;
    assert_eq!(
        c_arp_get(UNKNOWN),
        BROADCAST_MAC,
        "the C broadcasts to an address it has not learned"
    );
    assert_eq!(
        port.lookup(UNKNOWN),
        BROADCAST_MAC,
        "and so does the port -- same constant, ff:ff:ff:ff:ff:ff"
    );

    // 2. A first mapping is honoured by both.
    c_arp_set(UNKNOWN, mac(1));
    port.learn(UNKNOWN, mac(1));
    assert_eq!(c_arp_get(UNKNOWN), mac(1), "the C learns it");
    assert_eq!(port.lookup(UNKNOWN), mac(1), "and so does the port");

    // 3. A *second* mapping for the same address: the C keeps the first, the port takes the
    //    new one. A DELIBERATE DIVERGENCE.
    c_arp_set(UNKNOWN, mac(2));
    port.learn(UNKNOWN, mac(2));
    assert_eq!(
        c_arp_get(UNKNOWN),
        mac(1),
        "csp_eth_arp_set_addr returns early when an entry exists -- first write wins"
    );
    assert_eq!(
        port.lookup(UNKNOWN),
        mac(2),
        "the port follows the change, so a peer that moves stays reachable"
    );
    assert_ne!(
        c_arp_get(UNKNOWN),
        port.lookup(UNKNOWN),
        "and that is the divergence (SCOPE.md 34)"
    );

    // 4. Fill both tables past capacity with distinct addresses. The C stops learning; the
    //    port evicts the least recently used. Another DELIBERATE DIVERGENCE.
    //
    //    `UNKNOWN` already holds one slot in each, so `ARP_MAX` more addresses is one past
    //    full — the first of them is the one that decides it.
    const FIRST: u16 = 1000;
    for i in 0..ARP_MAX as u16 {
        c_arp_set(FIRST + i, mac(0x10 + i as u8));
        port.learn(FIRST + i, mac(0x10 + i as u8));
    }

    // The last address offered fits in neither table; only the port takes it.
    let last = FIRST + ARP_MAX as u16 - 1;
    assert_eq!(
        c_arp_get(last),
        BROADCAST_MAC,
        "the C never learned the address that arrived after its array filled"
    );
    assert_eq!(
        port.lookup(last),
        mac(0x10 + (ARP_MAX - 1) as u8),
        "the port learned it, by evicting the least recently used"
    );

    // And the C did not merely refuse everything: the addresses that arrived before the
    // array filled are still resolved. Without this the assertion above is satisfied by a
    // table that learned nothing at all.
    assert_eq!(
        c_arp_get(FIRST),
        mac(0x10),
        "the C still resolves what it learned before it ran out"
    );
    assert_eq!(
        c_arp_get(FIRST + ARP_MAX as u16 - 2),
        mac(0x10 + (ARP_MAX - 2) as u8),
        "up to the last one that fitted"
    );
}
