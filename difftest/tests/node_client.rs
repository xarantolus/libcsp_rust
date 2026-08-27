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
//! `csp_reboot` and `csp_shutdown` never wait — `csp_transaction_persistent` returns straight
//! after `csp_send` when `inlen == 0`. The other ten *look* like they block, and the first
//! version of this file said so and stopped there. They do not have to: the timeout is a
//! parameter, `csp_read` hands it to `csp_queue_dequeue`, and `pthread_queue_dequeue` with `0`
//! builds a deadline of *now*. At `timeout = 0` the request still goes out and the reply-wait
//! costs nothing, which is all that is needed to compare the two clients' requests.
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

/// Every service request the C's client builds, against the port's.
///
/// What is compared: the destination port and the payload bytes. **Not** the header flags —
/// `csp_ping` takes its `conn_options` from the caller and the others hard-code
/// `CSP_O_CRC32`, whereas the port's `client::Request` is `{port, payload}` and leaves
/// options to whoever sends it. That is a deliberate shape difference, not a payload one.
///
/// This is what caught `client::ps`: `csp_ps` puts a single `0x55` in its request
/// (`csp_services.c:117`) and the port sent nothing. Every `csp_ps_hook` libcsp ships ignores
/// the packet, so no stock node could tell — but a sentinel is the only reason the byte
/// exists, and comparing against the C is the only way the difference was ever going to
/// surface.
#[test]
fn every_service_request_matches_what_the_cs_client_builds() {
    let _g = lock();
    setup();

    let ping_body: Vec<u8> = (0..8u8).collect();
    // `PingNoReply` was the one kind the shim could drive and this loop did not ask for.
    // `csp_ping_noreply` opens its connection with CSP_O_CRC32 of its own accord rather
    // than taking the caller's options, so it is also the case that proves the checksum
    // arithmetic below is reading the flag and not a constant.
    let cases: [(CClient, u32, csp::client::Request<'_>); 6] = [
        (CClient::Ping, 8, csp::client::ping(&ping_body)),
        (CClient::MemFree, 0, csp::client::memfree()),
        (CClient::BufFree, 0, csp::client::buf_free()),
        (CClient::Uptime, 0, csp::client::uptime()),
        (CClient::Ps, 0, csp::client::ps()),
        (CClient::PingNoReply, 0, csp::client::ping_noreply()),
    ];

    for (kind, size, ours) in cases {
        let frames = c_client_request(kind, R_ADDR, size, 0);
        assert_eq!(frames.len(), 1, "{kind:?}: the C's client sends one frame");
        let id = Id::decode(VERSION, &frames[0]).expect("decodes");
        assert_eq!(id.dport, ours.port, "{kind:?}: same service port");

        // The C appends a CRC32 to everything but ping, so the payload is the front of the
        // body, not all of it. Comparing the whole body would compare our payload against
        // the C's payload-plus-checksum and fail for the wrong reason.
        let body = &frames[0][HDR..];
        let n = ours.payload.len();
        assert!(
            body.len() >= n,
            "{kind:?}: the C's body is shorter than the port's payload"
        );
        assert_eq!(
            &body[..n],
            ours.payload,
            "{kind:?}: the port must build the request the C builds"
        );
        let crc = if id.has_flag(csp_core::flags::CRC32) {
            4
        } else {
            0
        };
        assert_eq!(
            body.len(),
            n + crc,
            "{kind:?}: and nothing else — the C's body is the payload plus its checksum"
        );
    }
}

/// A reply of the wrong length is refused by both, and only the right length yields a value.
///
/// `csp_get_memfree`, `csp_get_buf_free` and `csp_get_uptime` all funnel through
/// `csp_transaction_persistent`, which refuses a reply whose length is not the one asked for
/// (`csp_io.c:352`) and returns nothing. Reaching that check needed a reply already on the
/// connection, which is why these three had never been driven: with an empty queue the
/// transaction times out long before the length is looked at.
///
/// Measured, `inlen = 4`:
///
/// | reply | C | port, before |
/// |---|---|---|
/// | 3 bytes | refused | `Truncated` |
/// | 4 bytes | the value | the value |
/// | 5 bytes | **refused** | **the first four** |
/// | 8 bytes | **refused** | **the first four** |
///
/// Accepting a longer reply hands an operator a number the peer never sent, which reads
/// exactly like one it did. The "never over-reject" rule that governs *incoming commands*
/// does not apply to a reply we asked for.
#[test]
fn a_reply_of_the_wrong_length_is_refused_by_both() {
    let _g = lock();
    setup();

    for len in [0usize, 3, 4, 5, 8] {
        let reply: Vec<u8> = (0..len).map(|i| 0xA0 + i as u8).collect();
        let (ret, got) = c_client_transaction(C_ADDR, csp_core::ports::MEMFREE, &reply, 4);
        let ours = csp::client::decode_u32(&reply);

        if len == 4 {
            assert_eq!(ret, 4, "the C accepts a four-byte reply");
            assert_eq!(got, reply, "and copies it out");
            assert_eq!(
                ours,
                Ok(u32::from_be_bytes([reply[0], reply[1], reply[2], reply[3]])),
                "and so must the port"
            );
        } else {
            assert_eq!(ret, 0, "the C refuses a {len}-byte reply");
            assert!(
                ours.is_err(),
                "the port must refuse it too — a {len}-byte reply decoded as a value is a \
                 number the peer never sent"
            );
        }
    }
}
