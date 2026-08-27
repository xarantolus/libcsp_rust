//! `csp_iflist_check_dfl` — and the claim that `csp_init` calls it — against a real node.
//!
//! # A doc comment that was wrong about the C
//!
//! `csp/src/iflist.rs` said of `check_default`: *"`csp_iflist_check_dfl`, called from
//! `csp_init`"*, and drew the consequence that a node which never set `is_default`
//! **floods every unroutable packet onto every interface**.
//!
//! `csp_init` does not call it. Grepping the whole libcsp tree finds the declaration in
//! `csp_iflist.h`, the definition in `csp_iflist.c:148`, an entry in the RST, and **no
//! caller** — and the only other place `src/` writes `is_default` is `csp_yaml.c` and the
//! Python bindings, both out of scope. It is a convenience an application may call.
//!
//! Measured, and the consequence is the opposite of what was written: with no interface
//! marked default, a real node sends an unroutable packet **nowhere**.
//!
//! ```text
//! as registered (EGRESS default):  unroutable -> 1 frame
//! after check_dfl:                 unchanged  -> 1 frame   (early return)
//! after clearing every default:    unroutable -> 0 frames
//! after check_dfl again:           all but LOOP default -> 2 frames
//! ```
//!
//! The last number is 2 and not 3 because split horizon drops the ingress interface — the
//! flooding is real, but it is "every default link except the one it came in on".
//!
//! # What is compared
//!
//! Which interfaces are default after each step, and how many frames an unroutable packet
//! puts on wires. Both stacks, same three interfaces, same packet.

use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const NODE_ADDR: u16 = 9;
const EGRESS_ADDR: u16 = 20;
const THIRD_ADDR: u16 = 40;
const NETMASK: u16 = 12;
const HDR: usize = 6;

/// An address no interface owns and no route covers.
const NOWHERE: u16 = 2;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn framed(dst: u16) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src: 4000,
        dst,
        dport: 10,
        sport: 40,
    };
    let mut v = vec![0u8; HDR + 4];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(b"cmd!");
    v
}

/// How many frames a real node puts on wires for a packet it cannot route.
fn c_unroutable() -> usize {
    c_node_exchange(&framed(NOWHERE), &[]).tx.len()
}

/// The same of a port node whose defaults are set by `set_default`, then optionally swept.
///
/// Returns (frames out, how many interfaces the sweep marked).
fn port_unroutable(defaults: &[u8], sweep: bool) -> (usize, usize) {
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(NODE_ADDR));
    for (i, (name, addr)) in [
        ("INGRESS", NODE_ADDR),
        ("EGRESS", EGRESS_ADDR),
        ("ROUTED", THIRD_ADDR),
    ]
    .into_iter()
    .enumerate()
    {
        node.ifaces
            .add(name, addr, NETMASK, defaults.contains(&(i as u8)))
            .unwrap();
    }
    // The port has no loopback interface to exempt, so there is no index to pass. The C
    // skips `&csp_if_lo` by identity; here there is nothing registered to skip.
    let marked = if sweep {
        node.ifaces.check_default(None)
    } else {
        0
    };

    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(NOWHERE)).expect("frame");
    node.router.receive(p, 0);
    let mut tx = 0;
    loop {
        match node.work(0) {
            Routed::Forwarded { packet, .. } => {
                drop(node.take_forwarded(packet));
                tx += 1;
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    (tx, marked)
}

/// The sweep's two branches and the loopback exemption, in both stacks.
///
/// One test: it mutates `is_default` on the harness's own static interfaces, which every
/// other case in a shared binary would then inherit. Its own file gives it its own process.
#[test]
fn a_node_with_no_default_interface_sends_an_unroutable_packet_nowhere() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, NODE_ADDR, NETMASK, EGRESS_ADDR, THIRD_ADDR),
        "C node came up at v2"
    );

    // 1. As registered: the harness marks EGRESS default, and that is where an unroutable
    //    packet goes. Establishes that the packet is genuinely unroutable-but-forwardable.
    assert_eq!(
        (
            c_iface_is_default("INGRESS"),
            c_iface_is_default("EGRESS"),
            c_iface_is_default("ROUTED"),
            c_iface_is_default("LOOP")
        ),
        (Some(false), Some(true), Some(false), Some(false)),
        "the harness registers exactly one default"
    );
    assert_eq!(c_unroutable(), 1, "and the packet leaves by it");
    assert_eq!(
        port_unroutable(&[1], false),
        (1, 0),
        "and the port does the same with the same one default"
    );

    // 2. The early return: something is already default, so the sweep changes nothing.
    c_iflist_check_dfl();
    assert_eq!(
        (c_iface_is_default("INGRESS"), c_iface_is_default("ROUTED")),
        (Some(false), Some(false)),
        "csp_iflist_check_dfl returns early when a default already exists"
    );
    assert_eq!(
        c_unroutable(),
        1,
        "so the packet still leaves by exactly one"
    );
    assert_eq!(
        port_unroutable(&[1], true),
        (1, 0),
        "and the port's sweep marks nothing and changes nothing"
    );

    // 3. With no default at all: the packet goes nowhere. This is the state a stock C node
    //    is in — `csp_init` never calls the sweep — and it is the opposite of the "floods
    //    every interface" the port's doc comment used to claim.
    c_iflist_clear_dfl();
    assert_eq!(c_unroutable(), 0, "a real node drops what it cannot route");
    assert_eq!(port_unroutable(&[], false), (0, 0), "and so does the port");

    // 4. The sweep with nothing default: every interface but the loopback becomes one, and
    //    the packet floods — minus the link it arrived on, which split horizon removes.
    c_iflist_check_dfl();
    assert_eq!(
        (
            c_iface_is_default("INGRESS"),
            c_iface_is_default("EGRESS"),
            c_iface_is_default("ROUTED"),
            c_iface_is_default("LOOP")
        ),
        (Some(true), Some(true), Some(true), Some(false)),
        "every interface but the loopback"
    );
    assert_eq!(
        c_unroutable(),
        2,
        "three defaults, minus the ingress link: split horizon still applies"
    );
    let (tx, marked) = port_unroutable(&[], true);
    assert_eq!(marked, 3, "the port's sweep marks its three interfaces");
    assert_eq!(tx, 2, "and floods the same two links");
}
