//! The C's service *client*, against the port's node — and the reboot command in particular.
//!
//! # The largest cluster of built-but-never-invoked C
//!
//! Measured across every `.c` file in either harness's build: 205 non-static `csp_*`
//! functions, 124 never named by any harness. Most of those are reached indirectly —
//! `csp_crc32_update` through `csp_crc32_append`, `csp_sha1_process` through
//! `csp_sha1_memory`, the `_fixup_cspv1` helpers through `csp_id_prepend` — so their
//! behaviour is observed even where the symbol is not.
//!
//! `src/csp_services.c` is the exception. Its twelve functions are the client an application
//! calls, nothing else in libcsp calls them, and nothing here did either. So `csp::client`
//! had been compared against the C's *server* (`node_service.rs`) and against its own round
//! trip, never against the C's client.
//!
//! # Why reboot, and why only reboot
//!
//! Ten of the twelve block in `csp_transaction_w_opts` waiting for a reply, and this harness
//! has no router thread to produce one. `csp_reboot` and `csp_shutdown` do not:
//! `csp_transaction_persistent` returns straight after `csp_send` when `inlen == 0`.
//!
//! They are also the pair where being wrong is worst and hardest to notice. A magic word the
//! port got wrong means "reboot the satellite" silently does nothing, and a round trip inside
//! the port cannot catch it — both halves read the same constant. Only the C can say.
//!
//! Safe to run at all because this build's reboot hook records instead of rebooting; the real
//! posix one calls `reboot(2)`.

use csp::service::Request as SvcRequest;
use csp::{Config, CspStorage, Node, Routed};
use csp_core::{Id, Version};
use difftest::*;

const VERSION: Version = Version::V2;
const C_ADDR: u16 = 9;
/// The port's address — where the C's client sends.
const R_ADDR: u16 = 20;
const NETMASK: u16 = 12;
const HDR: usize = 6;

type TestNode<'a> = Node<'a, 8, 24, 300, 64, 8, 8>;

fn setup() {
    c_set_version(VERSION);
    assert!(
        c_node_init(VERSION, C_ADDR, NETMASK, R_ADDR, 40),
        "C node came up at v2"
    );
    c_service_hooks_reset();
}

/// The magic words are the C's, byte for byte.
///
/// `csp::client::reboot()` and `csp_reboot()` are two independent transcriptions of
/// `CSP_REBOOT_MAGIC`. Comparing the port's client against the port's server would pass with
/// both wrong, because they share `service::REBOOT_MAGIC`.
#[test]
fn the_reboot_and_shutdown_words_match_the_c_byte_for_byte() {
    let _g = lock();
    setup();

    for (shutdown, ours) in [
        (false, csp::client::reboot()),
        (true, csp::client::shutdown()),
    ] {
        let frames = c_client_reboot(R_ADDR, shutdown);
        assert_eq!(frames.len(), 1, "the C's client sends one frame");
        let id = Id::decode(VERSION, &frames[0]).expect("a frame the C emitted decodes");
        assert_eq!(id.dport, ours.port, "same service port");
        assert_eq!(
            &frames[0][HDR..HDR + 4],
            ours.payload,
            "same magic word (shutdown={shutdown})"
        );
    }
}

/// The C's client checksums every reboot; the port's node must accept one that is.
///
/// `csp_reboot` passes `CSP_O_CRC32`, so the frame carries the CRC32 flag and four trailing
/// bytes — measured: `flags=0x01`, payload `80078007413e7883`. A node that does not strip
/// the trailer would hand its service layer eight bytes where four were sent. Reboot happens
/// to survive that, since the magic is read from the front; every other service would answer
/// from four bytes of checksum.
///
/// So this drives the C's own frame through the port's router to its bound port and asks what
/// the service layer was told to do.
#[test]
fn a_reboot_the_c_checksummed_is_understood_by_the_port() {
    let _g = lock();
    setup();

    for (shutdown, want) in [(false, SvcRequest::Reboot), (true, SvcRequest::Shutdown)] {
        let frames = c_client_reboot(R_ADDR, shutdown);
        assert_eq!(frames.len(), 1);
        let id = Id::decode(VERSION, &frames[0]).expect("decodes");
        assert_eq!(
            id.flags & csp_core::flags::CRC32,
            csp_core::flags::CRC32,
            "the C's reboot client always sets CSP_O_CRC32"
        );

        let storage = CspStorage::<8, 24, 300, 64, 8>::new();
        let mut node: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
        node.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
        node.bind(csp_core::ports::REBOOT).unwrap();

        let mut p = node.packet().expect("pool");
        p.set_frame(VERSION, &frames[0]).expect("the C's own frame");
        node.router.receive(p, 0);

        let mut seen = None;
        loop {
            match node.work(0) {
                Routed::Delivered { conn, .. } => {
                    while let Ok(Some(pkt)) = node.read(conn) {
                        seen = Some(pkt.with_payload(|got| {
                            (
                                got.len(),
                                SvcRequest::decode(csp_core::ports::REBOOT, got).ok(),
                            )
                        }));
                        drop(pkt);
                    }
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
        let (len, classified) = seen.expect("the frame must reach the application");
        // The length first, and not only the classification: the magic is read from the
        // front, so an unstripped four-byte checksum would classify correctly anyway. This
        // assertion is what distinguishes "verified and stripped" from "ignored".
        assert_eq!(
            (frames[0].len() - HDR, len),
            (8, 4),
            "the C sends magic+CRC32; the application must be handed the magic alone"
        );
        assert_eq!(
            classified,
            Some(want),
            "the port must act on a reboot a real libcsp client sent (shutdown={shutdown})"
        );

        // And it is verification, not truncation: flip a checksum bit and nothing arrives.
        let mut corrupt = frames[0].clone();
        *corrupt.last_mut().unwrap() ^= 0x01;
        let storage = CspStorage::<8, 24, 300, 64, 8>::new();
        let mut n2: TestNode = Node::new(&storage, Config::new(VERSION).address(R_ADDR));
        n2.ifaces.add("test", R_ADDR, NETMASK, true).unwrap();
        n2.bind(csp_core::ports::REBOOT).unwrap();
        let mut q = n2.packet().expect("pool");
        q.set_frame(VERSION, &corrupt).expect("frame");
        n2.router.receive(q, 0);
        let mut delivered = 0;
        loop {
            match n2.work(0) {
                Routed::Delivered { conn, .. } => {
                    while let Ok(Some(pkt)) = n2.read(conn) {
                        delivered += 1;
                        drop(pkt);
                    }
                }
                Routed::Idle => break,
                _ => continue,
            }
        }
        assert_eq!(
            delivered, 0,
            "a reboot whose checksum does not match must not reach the application"
        );
    }
}

/// And the reverse: what the port's client builds is a reboot a real C node obeys.
///
/// The C's hook records instead of rebooting, so "did it obey" is answerable. Without this
/// the port could emit a well-formed request that the C's `csp_service_handler` quietly
/// discards — which is what it does for every payload that is not the magic word, with no
/// reply and no error to distinguish it from a node that is not listening.
#[test]
fn a_reboot_the_port_built_is_obeyed_by_a_real_c_node() {
    let _g = lock();
    setup();
    assert_eq!(c_node_bind(csp_core::ports::REBOOT), 0);

    for (shutdown, req) in [
        (false, csp::client::reboot()),
        (true, csp::client::shutdown()),
    ] {
        c_service_hooks_reset();
        let id = Id {
            pri: 2,
            flags: 0,
            src: R_ADDR,
            dst: C_ADDR,
            dport: req.port,
            sport: 40,
        };
        let mut frame = vec![0u8; HDR + req.payload.len()];
        id.encode(VERSION, &mut frame).unwrap();
        frame[HDR..].copy_from_slice(req.payload);

        let out = c_node_serve(&frame, req.port);
        assert_eq!(out.len(), 0, "a reboot is never acknowledged");
        let (rebooted, shut) = c_service_rebooted();
        assert_eq!(
            (rebooted, shut),
            (!shutdown, shutdown),
            "the C must act on what the port's client built (shutdown={shutdown})"
        );
    }
}
