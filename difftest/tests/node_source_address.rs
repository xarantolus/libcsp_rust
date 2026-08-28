//! Which address a packet this node originates says it came from.
//!
//! # What the C does
//!
//! libcsp has no node address. `csp_connect` says so in as many words (`csp_conn.c:259`):
//! *"CSP does not support 'source address' on outgoing connections so the outgoing source
//! address will be automatically applied after outgoing routing selects which interface the
//! packet will leave from."* It leaves `outgoing_id.src` at **zero**, `csp_sendto` never sets
//! one, and `csp_sendto_reply` zeroes it for the all-nodes broadcast (`csp_io.c:431`). The
//! zero is filled in `send_packet` (`csp_io.c:119`): `if (from_me && src == 0) src =
//! snd_iface->addr` — the address of the interface the packet actually leaves by, chosen
//! per destination, after routing.
//!
//! The port stamped one node-wide `address` on everything it originated. On a node with one
//! interface the two agree. A flight node has more than one — CDH speaks CAN to the bus and
//! KISS to the radio, and at v2 each interface carries its own address — and there a packet
//! leaving by the radio was sourced from the CAN address.
//!
//! # What is measured
//!
//! Both nodes have two interfaces in different `/12` subnets, the second the default route:
//! the C at 9 and 20, the port at 10 and 21. Each row sends toward a peer and reads the
//! source off the frame that reaches the wire.
//!
//! | originated by | to a peer on the first subnet | to a peer beyond both (default route) |
//! |---|---|---|
//! | a reply to `ping 0x3FFF` | the first interface's address | the second's |
//! | `connect` + `send` | the first's | the second's |
//! | `sendto` | the first's | the second's |
//!
//! An alias or a subnet broadcast is not touched: a request sent *to* an address is answered
//! from that address (`csp_sendto_reply` copies it), and `node_reply_source` pins the
//! subnet-broadcast half of that.

use csp::{Config, CspStorage, Node, Outbound, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const NETMASK: u16 = 12;
/// The C node: interface addresses, and the two interfaces' subnets are 8..=11 and 20..=23.
const C_FIRST: u16 = 9;
const C_SECOND: u16 = 20;
const C_THIRD: u16 = 40;
/// The port: same shape, one address up.
const R_FIRST: u16 = 10;
const R_SECOND: u16 = 21;
/// A peer inside the first subnet of each node, and one beyond both.
const PEER_NEAR_C: u16 = 8;
const PEER_NEAR_R: u16 = 11 - 3; // 8, in the port's first subnet 8..=11 as well
const PEER_FAR: u16 = 30;
const HDR: usize = 6;
const ALL_NODES: u16 = 0x3FFF;
const PING: &[u8] = b"which interface";

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn src_of(frame: &[u8]) -> u16 {
    Id::decode(VERSION, &frame[..HDR]).expect("a v2 header").src
}

fn framed(src: u16, dst: u16, payload: &[u8]) -> Vec<u8> {
    let id = Id {
        pri: 2,
        flags: 0,
        src,
        dst,
        dport: csp_core::ports::PING,
        sport: 40,
    };
    let mut v = vec![0u8; HDR + payload.len()];
    id.encode(VERSION, &mut v).unwrap();
    v[HDR..].copy_from_slice(payload);
    v
}

/// A two-interface port node: the first owns 8..=11, the second 20..=23 and is the default.
fn two_iface<'a>(storage: &'a CspStorage<8, 24, 300, 64, 8>) -> TestNode<'a> {
    let mut node: TestNode = Node::new(storage, Config::new(VERSION).address(R_FIRST));
    node.ifaces.add("first", R_FIRST, NETMASK, false).unwrap();
    node.ifaces.add("second", R_SECOND, NETMASK, true).unwrap();
    node.bind(csp_core::ports::PING).unwrap();
    node
}

fn frame_of(out: Outbound<'_, 24, 300>) -> Vec<u8> {
    match out {
        Outbound::Transmit { mut packet, .. } => {
            packet.prepend_header(VERSION).unwrap();
            packet.with_frame(|f| f.to_vec())
        }
        other => panic!("must reach a wire: {other:?}"),
    }
}

/// The port answers a broadcast ping from `peer`; the reply frame comes back.
fn port_broadcast_reply(node: &mut TestNode, peer: u16) -> Vec<u8> {
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(peer, ALL_NODES, PING))
        .unwrap();
    node.router.receive(p, 0);
    let mut replies = Vec::new();
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    let mut reply = node.packet().expect("pool");
                    pkt.with_payload(|d| reply.set_payload(d).unwrap());
                    let out = node.reply_to(&pkt, reply).expect("reply");
                    replies.push(frame_of(out));
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    assert_eq!(replies.len(), 1);
    replies.remove(0)
}

#[test]
fn a_broadcast_reply_is_sourced_from_the_interface_it_leaves_by() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_FIRST, NETMASK, C_SECOND, C_THIRD));
    assert_eq!(c_node_bind(csp_core::ports::PING), 0);

    let near = c_node_serve(&framed(PEER_NEAR_C, ALL_NODES, PING), csp_core::ports::PING);
    let far = c_node_serve(&framed(PEER_FAR, ALL_NODES, PING), csp_core::ports::PING);
    assert_eq!((near.len(), far.len()), (1, 1), "the C answers both");
    assert_eq!(
        src_of(&near[0]),
        C_FIRST,
        "toward the first subnet: the first interface"
    );
    assert_eq!(
        src_of(&far[0]),
        C_SECOND,
        "beyond both: the default route's interface"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = two_iface(&storage);
    assert_eq!(
        src_of(&port_broadcast_reply(&mut node, PEER_NEAR_R)),
        R_FIRST,
        "the port: toward the first subnet, the first interface's address"
    );
    assert_eq!(
        src_of(&port_broadcast_reply(&mut node, PEER_FAR)),
        R_SECOND,
        "the port: beyond both subnets, the default route's interface -- not the node's \
         one configured address"
    );
}

#[test]
fn a_connection_is_sourced_from_the_interface_it_leaves_by() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_FIRST, NETMASK, C_SECOND, C_THIRD));

    let near = c_client_request(CClient::Ping, PEER_NEAR_C, 4, 0);
    let far = c_client_request(CClient::Ping, PEER_FAR, 4, 0);
    assert_eq!(
        (near.len(), far.len()),
        (1, 1),
        "csp_ping puts one request on the wire"
    );
    assert_eq!(
        src_of(&near[0]),
        C_FIRST,
        "csp_connect toward the first subnet"
    );
    assert_eq!(src_of(&far[0]), C_SECOND, "csp_connect beyond both");

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = two_iface(&storage);
    for (peer, want) in [(PEER_NEAR_R, R_FIRST), (PEER_FAR, R_SECOND)] {
        let conn = node
            .connect(2, peer, csp_core::ports::PING, 0, 0)
            .expect("connect");
        let mut p = node.packet().expect("pool");
        p.set_payload(PING).unwrap();
        let frame = frame_of(node.send(conn, p, 0).expect("send"));
        assert_eq!(
            src_of(&frame),
            want,
            "the port's connection to {peer} is sourced from the interface it leaves by"
        );
        node.close(conn, 0).unwrap();
    }
}

#[test]
fn a_connectionless_send_is_sourced_from_the_interface_it_leaves_by() {
    let _g = lock();
    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = two_iface(&storage);
    for (peer, want) in [(PEER_NEAR_R, R_FIRST), (PEER_FAR, R_SECOND)] {
        let mut p = node.packet().expect("pool");
        p.set_payload(PING).unwrap();
        let frame = frame_of(
            node.sendto(2, peer, csp_core::ports::PING, 40, 0, p)
                .expect("sendto"),
        );
        assert_eq!(
            src_of(&frame),
            want,
            "csp_sendto sets no source; the interface does"
        );
    }
}

/// Only the all-nodes broadcast is special-cased. A request sent *to* the subnet broadcast
/// is answered from that address, verbatim (`csp_io.c:431` copies `request.dst`), on both.
#[test]
fn a_subnet_broadcast_reply_is_sourced_from_the_broadcast_address_on_both() {
    let _g = lock();
    c_set_version(VERSION);
    assert!(c_node_init(VERSION, C_FIRST, NETMASK, C_SECOND, C_THIRD));
    assert_eq!(c_node_bind(csp_core::ports::PING), 0);

    let host_mask = (1u16 << (14 - NETMASK)) - 1;
    let c_bcast = C_FIRST | host_mask;
    let c = c_node_serve(&framed(PEER_NEAR_C, c_bcast, PING), csp_core::ports::PING);
    assert_eq!(c.len(), 1);
    assert_eq!(
        src_of(&c[0]),
        c_bcast,
        "the C echoes the subnet broadcast as the source"
    );

    let storage = CspStorage::<8, 24, 300, 64, 8>::new();
    let mut node = two_iface(&storage);
    let r_bcast = R_FIRST | host_mask;
    let mut p = node.packet().expect("pool");
    p.set_frame(VERSION, &framed(PEER_NEAR_R, r_bcast, PING))
        .unwrap();
    node.router.receive(p, 0);
    let mut src = None;
    loop {
        match node.work(0) {
            Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = node.read(conn) {
                    let mut reply = node.packet().expect("pool");
                    pkt.with_payload(|d| reply.set_payload(d).unwrap());
                    src = Some(src_of(&frame_of(
                        node.reply_to(&pkt, reply).expect("reply"),
                    )));
                    drop(pkt);
                }
            }
            Routed::Idle => break,
            _ => continue,
        }
    }
    assert_eq!(src, Some(r_bcast), "the port does the same");
}
