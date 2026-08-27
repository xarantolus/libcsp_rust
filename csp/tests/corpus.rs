#![cfg(all(
    feature = "rdp",
    feature = "sfp",
    feature = "cmp",
    feature = "hmac",
    feature = "rtable",
    feature = "if-eth"
))]

//! Replay of `corpus/ctest.jsonl` — what the real libcsp did, run against the port.
//!
//! The oracle that produced the corpus is built with every protocol compiled in, so this
//! harness needs the matching features. Without them the file is empty rather than broken:
//! a differential test against a configuration the oracle was not built for would be
//! comparing two different libraries.
//!
//! The corpus is produced by `just corpus`, which runs `ctest/` against the C. Each record
//! carries the **inputs** as well as the answer, and this file drives the port from those
//! inputs rather than re-declaring the scenario, so a replay cannot quietly drift into
//! testing something else and keep passing.
//!
//! Three verdicts:
//!
//! - `must_match` — the port has to produce what the C produced.
//! - `diverges` — the port deliberately does something else (`SCOPE.md`), asserted with
//!   `assert_ne!` plus a positive claim, so "fixing" the port back toward the C fails here.
//! - `c_only` — nothing to compare; the C's behaviour depends on something the port does
//!   not have (a clock-seeded sequence number, say). Recorded for reference.
//!
//! `every_record_has_a_replay` is what stops this file from being a subset: a record with
//! no arm fails the run.
//!
//! # Every arm must call into the port
//!
//! A replay that returns a literal — or anything else computed without touching `csp` or
//! `csp_core` — is a tautology. It passes whatever the port does, and it still counts
//! itself in "N records replayed", so it reads as evidence while being none.
//!
//! This is not hypothetical: `sfp::a_corrupt_fragment_reports_the_same_error_as_a_wrong_shape`
//! shipped as a hardcoded `json!` of the C's own answer, commented as though that were a
//! deliberate choice. It is the same failure the `diverges` key-set check exists to stop,
//! one layer up. The check for it is a mutation: break the port, and every record that
//! stays green is measuring nothing.

use csp::pool::Pool;
use csp::router::{DropReason, Routed, Router};
use csp_core::{Id, Version};
use serde::Deserialize;

const CORPUS: &str = include_str!("../../corpus/ctest.jsonl");

/// The same key `ctest/suite_security.c` installs with `csp_hmac_set_key`.
const HMAC_KEY: &[u8] = b"unit-test-key";

const LOCAL_ADDR: u16 = 10;
const PEER_ADDR: u16 = 11;
const TEST_PORT: u8 = 12;

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Verdict {
    MustMatch,
    Diverges,
    COnly,
}

/// The record envelope. `observed` and `input` stay untyped here and are parsed per suite,
/// so both levels can deny unknown fields without one schema having to know the other.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    suite: String,
    case: String,
    verdict: Verdict,
    #[serde(default)]
    input: serde_json::Value,
    observed: serde_json::Value,
}

fn records() -> Vec<Record> {
    CORPUS
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("bad corpus line {l}: {e}")))
        .collect()
}

// --- security -------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityInput {
    socket_opts: u32,
    flags: u8,
    trailer: Trailer,
    corrupt: bool,
}

#[derive(Debug, Deserialize, PartialEq, Eq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum Trailer {
    None,
    Crc32,
    Hmac,
    /// Both, in the order `csp_send_direct` appends them: MAC, then checksum over it.
    HmacThenCrc32,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct SecurityObserved {
    delivered: u32,
    /// Bytes the application received. The accepting cases are only meaningful with this:
    /// `delivered: 1` is the same whether the trailer was verified and stripped or the
    /// policy never ran at all.
    delivered_bytes: u32,
    /// And which bytes -- what the application reads, which is what the C's
    /// `test_the_checksum_is_stripped_before_delivery` asserted and never recorded.
    ///
    /// Not an independent check on *where* the trailer was removed: both stacks truncate by
    /// length from the end (`packet->length -= 4`; the port takes `stripped.len()` and
    /// shortens in place), so here the content follows from the length.
    delivered_body: String,
    rx_error: u32,
    autherr: u32,
}

fn replay_security(input: &SecurityInput) -> SecurityObserved {
    type P = Pool<8, 264>;
    type R = Router<4, 4, 48, 8>;

    let pool = P::new();
    let mut r = R::new(LOCAL_ADDR, Version::V2);
    r.bind(TEST_PORT).unwrap();
    // The C's socket carries CSP_SO_CONN_LESS too; only the *_REQ bits reach the policy,
    // so the value goes across unmasked rather than being filtered into a shape that
    // hides a difference.
    r.endpoint_opts = input.socket_opts;
    r.hmac_key = Some(HMAC_KEY);

    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", LOCAL_ADDR, 12, false).unwrap();
        l
    };

    // "payload", then whatever trailer the C appended, over the payload only —
    // csp_crc32_append and csp_hmac_append(_, false) both exclude the header.
    let mut body = [0u8; 32];
    let payload = b"payload";
    let n = match input.trailer {
        Trailer::None => {
            body[..payload.len()].copy_from_slice(payload);
            payload.len()
        }
        Trailer::Crc32 => csp_core::crc32::append(
            &[],
            payload,
            csp_core::crc32::Coverage::PayloadOnly,
            &mut body,
        )
        .unwrap(),
        Trailer::Hmac => csp_core::hmac::append(
            HMAC_KEY,
            &[],
            payload,
            csp_core::crc32::Coverage::PayloadOnly,
            &mut body,
        )
        .unwrap(),
        Trailer::HmacThenCrc32 => {
            let mut signed = [0u8; 32];
            let m = csp_core::hmac::append(
                HMAC_KEY,
                &[],
                payload,
                csp_core::crc32::Coverage::PayloadOnly,
                &mut signed,
            )
            .unwrap();
            csp_core::crc32::append(
                &[],
                &signed[..m],
                csp_core::crc32::Coverage::PayloadOnly,
                &mut body,
            )
            .unwrap()
        }
    };
    if input.corrupt {
        body[n - 1] ^= 0xFF;
    }

    let mut p = pool.acquire(0).unwrap();
    p.set_id(Id {
        pri: 2,
        flags: input.flags,
        src: PEER_ADDR,
        dst: LOCAL_ADDR,
        dport: TEST_PORT,
        sport: 40,
    });
    p.set_payload(&body[..n]).unwrap();

    r.receive(p, 0);
    let (delivered, delivered_bytes, delivered_body) = match r.work(&pool, &mut ifaces, 0) {
        Routed::Delivered { conn, .. } => {
            // Take the packet off the connection the way an application would, and
            // measure what it holds. The C reports `p->length` after csp_recvfrom.
            let got = match r.conns.dequeue_rx(conn) {
                Ok(Some(slot)) => pool
                    .from_index(slot)
                    .map(|p| p.with_payload(<[u8]>::to_vec))
                    .unwrap_or_default(),
                _ => Vec::new(),
            };
            (1, got.len() as u32, tohex(&got))
        }
        Routed::Dropped(DropReason::Refused(_)) => (0, 0, String::new()),
        other => panic!("neither delivered nor refused: {other:?}"),
    };

    SecurityObserved {
        delivered,
        delivered_bytes,
        delivered_body,
        // The **ingress interface's** counters, which is what the C records
        // (`csp_route_security_check` takes the iface and charges it directly). This used
        // to read the router's node-wide totals and say the two were the same event. They
        // are not the same quantity: with one interface in the scenario they coincide, so
        // the record passed while comparing something else, and the per-interface fields
        // an operator reads over CMP `IF_STATS` were never written at all.
        rx_error: ifaces.get(0).map_or(0, |e| e.stats.rx_error),
        autherr: ifaces.get(0).map_or(0, |e| e.stats.autherr),
    }
}

// --- dedup ----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DedupInput {
    /// `csp_dedup_types_e`: 0 off, 1 forwarded, 2 incoming, 3 all.
    mode: u8,
    pairs: u32,
}

/// The window cases: one pair of identical packets with a chosen gap between them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HmacInput {
    include_header: u8,
    payload: String,
    /// The exact header bytes the MAC covered; absent when it covered only the payload.
    #[serde(default)]
    header: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DedupWindowInput {
    mode: u8,
    gap_ms: u32,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DedupObserved {
    delivered_of_two: u32,
    forwarded_of_two: u32,
    /// The ingress interface's own drop counter. Without it the record cannot tell a node
    /// that counts a suppressed duplicate from one that silently discards it -- and the
    /// driver never sees the drop, because the packet has already left it.
    ingress_drop: u32,
}

/// Two identical packets `gap_ms` apart, counting what the application collected.
///
/// `start_ms` is where the clock is put first. The wrap cases set it just below 2^32:
/// `csp_dedup.c` ages entries with `time > stamp + CSP_DEDUP_WINDOW_MS` on a free-running
/// `uint32_t`, so the last 100 ms before the wrap has every entry looking expired. The port
/// ages by wrapping subtraction and does not.
fn replay_dedup_window_cased(
    input: &DedupWindowInput,
    start_ms: u32,
    differ: bool,
) -> serde_json::Value {
    use csp::dedup::DedupMode;
    type P = Pool<16, 264>;
    type R = Router<4, 4, 48, 8>;

    let pool = P::new();
    let mut r = R::new(LOCAL_ADDR, Version::V2);
    r.bind(TEST_PORT).unwrap();
    r.dedup_mode = match input.mode {
        3 => DedupMode::All,
        other => panic!("the window cases all run with dedup on, got {other}"),
    };

    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", LOCAL_ADDR, 12, true).unwrap();
        l
    };

    // Identical bytes are what make the second packet a duplicate; the "different packet"
    // case is the control that stops the others passing on a node that drops every second
    // packet regardless of content.
    let second: &[u8] = if differ { b"different" } else { b"identical" };
    let mut delivered = 0u32;
    for (i, body) in [b"identical".as_slice(), second].iter().enumerate() {
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: PEER_ADDR,
            dst: LOCAL_ADDR,
            dport: TEST_PORT,
            sport: 40,
        });
        p.set_payload(body).unwrap();
        r.receive(p, 0);
        let now = start_ms.wrapping_add(if i == 0 { 0 } else { input.gap_ms });
        if let Routed::Delivered { conn, .. } = r.work(&pool, &mut ifaces, now) {
            while let Ok(Some(slot)) = r.conns.dequeue_rx(conn) {
                drop(pool.from_index(slot));
                delivered += 1;
            }
            let mut drained = [0u16; 8];
            if let Ok(n) = r.conns.close(conn, &mut drained) {
                for &slot in &drained[..n] {
                    drop(pool.from_index(slot));
                }
            }
        }
    }

    serde_json::json!({ "delivered_of_two": delivered })
}

fn replay_dedup(input: &DedupInput) -> DedupObserved {
    use csp::dedup::DedupMode;
    type P = Pool<16, 264>;
    type R = Router<4, 4, 48, 8>;

    assert_eq!(input.pairs, 2, "the replay sends two of each");

    let mode = match input.mode {
        0 => DedupMode::Off,
        1 => DedupMode::Forwarded,
        2 => DedupMode::Incoming,
        3 => DedupMode::All,
        other => panic!("unknown csp_dedup_types_e {other}"),
    };

    let pool = P::new();
    let mut r = R::new(LOCAL_ADDR, Version::V2);
    r.bind(TEST_PORT).unwrap();
    r.routes.set(0, 0, 1, csp_core::rtable::NO_VIA).unwrap();
    r.dedup_mode = mode;

    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", LOCAL_ADDR, 12, false).unwrap();
        l.add("EGRESS", 20, 12, true).unwrap();
        l
    };

    let packet = |dst: u16| {
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: PEER_ADDR,
            dst,
            dport: TEST_PORT,
            sport: 40,
        });
        p.set_payload(b"identical").unwrap();
        p
    };

    let mut delivered = 0;
    for _ in 0..input.pairs {
        r.receive(packet(LOCAL_ADDR), 0);
        if let Routed::Delivered { .. } = r.work(&pool, &mut ifaces, 10) {
            delivered += 1;
        }
    }

    let mut forwarded = 0;
    for _ in 0..input.pairs {
        r.receive(packet(25), 0);
        if let Routed::Forwarded { packet: slot, .. } = r.work(&pool, &mut ifaces, 10) {
            forwarded += 1;
            // Reclaim the slot the router handed over, or the pool drains and the next
            // iteration fails for a reason unrelated to deduplication.
            drop(pool.from_index(slot));
        }
    }

    DedupObserved {
        delivered_of_two: delivered,
        forwarded_of_two: forwarded,
        ingress_drop: ifaces.get(0).map_or(0, |e| e.stats.drop),
    }
}

// --- cmp ------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CmpInput {
    /// The exact request bytes the C node was given, as lowercase hex.
    request: String,
    /// Whether the C node's clock accepted a `CLOCK` set, when the case turns it off.
    ///
    /// The refused and accepted cases send byte-identical requests, so without this the
    /// replay would have to assume one of them.
    #[serde(default)]
    clock_set_accepted: Option<u8>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct CmpObserved {
    replies: u32,
    reply_len: u32,
    /// `-1` when nothing was sent.
    reply_type: i32,
    reply_code: i32,
}

fn tohex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Answer a CMP request the way a server built on this port would: classify it with
/// `parse_request`, then encode the matching reply.
///
/// This is the port's equivalent of `csp_cmp_handler`, and the comparison is whether it
/// answers the same requests with the same shape. Nothing here inspects the port's
/// internals; a peer sees exactly these four numbers.
/// The same bounds-checked window `ctest/hooks.c` installs over the C's `__weak`
/// `csp_cmp_memcpy`, and the same pattern in it. Returns the bytes at `addr`, or `None` if
/// the request is outside the window — which is what makes the node answer nothing.
///
/// The C's default is a bare `memcpy`, so without an override a node answers a peek from
/// *any* address. Modelling the override rather than the default is the point: it is what a
/// node that intends to survive a hostile peek actually installs.
fn peek_window(addr: u64, len: usize, wide: bool) -> Option<Vec<u8>> {
    const BASE: u64 = 0x1000;
    const REGION: usize = 256;

    if wide {
        return None; // the corpus only exercises the 32-bit form so far
    }
    let off = addr.checked_sub(BASE)? as usize;
    if len > REGION || off > REGION - len {
        return None;
    }
    Some((off..off + len).map(|i| 0xA0 + (i & 0x0f) as u8).collect())
}

/// The oracle node's own answers, as `ctest/suite_cmp.c` configured it.
///
/// This exists so the replay drives [`csp::service::respond_cmp`] rather than a second copy
/// of the dispatcher. It used to be the latter: the arms below -- unknown interface means
/// silence, a peek outside the window means silence -- were written out longhand *in this
/// file*, so the C's 26 records checked the codec and the test's own reimplementation while
/// the library had no dispatcher at all. The test contained the missing production code,
/// which is exactly why nothing reported it missing.
struct OracleNode {
    /// Whether `set_clock` accepts, mirroring `ctest_clock_set_accepts`.
    clock_accepts: bool,
}

impl csp::hooks::Hooks<16, 264> for OracleNode {
    fn if_stats(&self, name: &str) -> Option<csp_core::cmp::IfStats> {
        // The oracle registers INGRESS; anything else is an interface the C does not have,
        // and it answers those with nothing rather than with zeros.
        if name == "INGRESS" {
            Some(csp_core::cmp::IfStats::default())
        } else {
            None
        }
    }

    fn route_set(&mut self, _dest: u16, _netmask: u16, iface: &str, _via: u16) -> bool {
        iface == "INGRESS" || iface == "ROUTED"
    }

    fn mem_read(&self, addr: u64, out: &mut [u8]) -> csp_core::Result<()> {
        match peek_window(addr, out.len(), false) {
            Some(src) => {
                out.copy_from_slice(&src);
                Ok(())
            }
            None => Err(csp_core::Error::AddressRefused { addr }),
        }
    }

    fn mem_write(&mut self, addr: u64, data: &[u8]) -> csp_core::Result<()> {
        match peek_window(addr, data.len(), false) {
            Some(_) => Ok(()),
            None => Err(csp_core::Error::AddressRefused { addr }),
        }
    }

    fn clock(&self) -> csp::hooks::Timestamp {
        csp::hooks::Timestamp::UNSET
    }

    fn set_clock(&mut self, _t: csp::hooks::Timestamp) -> bool {
        self.clock_accepts
    }
}

/// What `ctest/suite_cmp.c` puts in `csp_conf` before every case.
fn oracle_identity() -> csp::service::Identity<'static> {
    csp::service::Identity {
        hostname: "oracle-node",
        model: "ctest-model",
        revision: "rev-1",
        // The C fills these from __DATE__/__TIME__; only their length matters here and
        // they are deliberately absent from the corpus.
        date: "Jan  1 2026",
        time: "00:00:00",
    }
}

/// The IDENT reply up to `date` -- the part that comes from configuration rather than the
/// build. Derived from the field lengths so it tracks the wire format, not a literal.
const IDENT_PREFIX_LEN: usize = csp_core::cmp::Header::LEN
    + csp_core::cmp::len::HOSTNAME
    + csp_core::cmp::len::MODEL
    + csp_core::cmp::len::REVISION;

fn replay_cmp(input: &CmpInput) -> CmpObserved {
    use csp_core::cmp;

    let req = unhex(&input.request);
    let none = CmpObserved {
        replies: 0,
        reply_len: 0,
        reply_type: -1,
        reply_code: -1,
    };

    let Ok(query) = cmp::parse_request(&req) else {
        return none;
    };
    let identity = oracle_identity();

    let mut out = [0u8; 256];
    let mut hooks = OracleNode {
        clock_accepts: input.clock_set_accepted.unwrap_or(1) != 0,
    };
    match csp::service::respond_cmp(query, &identity, Version::V1, &mut hooks, &mut out) {
        // Read the type and code back out of the encoded reply rather than restating what
        // they were meant to be. They were literals here, so a dispatcher that never
        // flipped `type` to REPLY -- the one line `csp_cmp_dispatch.c` runs after every
        // successful handler -- reproduced the C's records perfectly.
        Ok(Some(n)) => CmpObserved {
            replies: 1,
            reply_len: n as u32,
            reply_type: out[0] as i32,
            reply_code: out[1] as i32,
        },
        Ok(None) | Err(_) => none,
    }
}

/// libcsp's own expected MAC bytes, replayed.
///
/// `csp_hmac_append(packet, include_header)` writes four bytes a peer must reproduce
/// exactly, and the flag decides which span they cover: `frame_begin..frame_length` when
/// set, `data..length` when clear. `difftest` covers the raw `mac_full(key, msg)` primitive
/// against the real C, but nothing covered the packet-level operation -- so which bytes get
/// authenticated, and where the tag lands, was compared to no oracle. The key is libcsp's
/// zeroed static `csp_hmac_key`, never set by these tests.
fn replay_hmac(input: &HmacInput) -> serde_json::Value {
    use csp_core::crc32::Coverage;
    let key = [0u8; 16];
    let payload = unhex(&input.payload);
    let header = unhex(&input.header);
    let coverage = if input.include_header != 0 {
        Coverage::HeaderAndPayload
    } else {
        Coverage::PayloadOnly
    };

    let mut buf = [0u8; 64];
    let Ok(n) = csp_core::hmac::append(&key, &header, &payload, coverage, &mut buf) else {
        return serde_json::json!({ "tagged": "", "verified": 0, "recovered": "" });
    };
    let tagged = tohex(&buf[..n]);
    match csp_core::hmac::verify_over(&key, &header, &buf[..n], coverage) {
        Ok(recovered) => serde_json::json!({
            "tagged": tagged,
            "verified": 1,
            "recovered": tohex(recovered),
        }),
        Err(_) => serde_json::json!({ "tagged": tagged, "verified": 0, "recovered": "" }),
    }
}

// --- eth ------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EthInput {
    /// Every frame the C's receive path saw, in order, each already truncated to the
    /// `received_len` a NIC would have delivered.
    frames: Vec<String>,
    /// Whether the interface accepts packets addressed elsewhere.
    promisc: u8,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EthObserved {
    refused: u32,
    frame: u32,
    drop: u32,
    buffers_consumed: u32,
    /// How many packets reached the application, and the body of the first. Without these
    /// the record said only whether a frame was refused -- identical whether reassembly
    /// put the right bytes together or none at all.
    delivered: u32,
    delivered_body: String,
}

/// The port's equivalent of `csp_eth_rx`, applied to the same frames in the same order.
///
/// The C's nine guards live in one function; here they are `Header::decode`,
/// `Header::is_csp` and `Reassembler::push`. What is compared is the outcome a peer and an
/// operator can see: was the frame refused, and was the interface's `frame` counter
/// charged for it.
///
/// `buffers_consumed` is always zero on this side and is compared anyway — the port's
/// reassembler is caller-allocated, so it cannot leak a pool buffer the way a missed
/// `csp_eth_pbuf_free` can. Comparing it is what would catch the C growing a leak.
fn replay_eth(input: &EthInput) -> EthObserved {
    use csp_core::eth;

    // The same bounds the oracle's node has: a CSP_BUFFER_SIZE payload plus a v2 header,
    // and a v2 header as the floor. Using a bigger buffer here would quietly make the
    // port look more permissive than the C when it is only better provisioned.
    const CSP_BUFFER_SIZE: usize = 256;
    const V2_HEADER: usize = 6;
    let mut r = eth::Reassembler::with_min_len(V2_HEADER as u16);
    let mut out = [0u8; CSP_BUFFER_SIZE + V2_HEADER];
    let mut refused = 0;
    let mut frame = 0;
    let mut delivered = 0;
    let mut body = String::new();

    for hex in &input.frames {
        let bytes = unhex(hex);
        let outcome = (|| -> Result<(), ()> {
            let h = eth::Header::decode(&bytes).map_err(|_| ())?;
            // The whole payload, not a slice pre-trimmed to `seg_size`, and no ethertype
            // test here. Both used to be done *in this closure* -- so removing either
            // guard from `Reassembler::push` left every `eth::` record green, because the
            // replay was still refusing the frame itself. The same shape that once hid a
            // missing CMP server: the test contained the production logic.
            // The frame as it arrived, padding included -- `push` takes `seg_size` from
            // the header and ignores the rest, as `csp_eth_rx` does. Trimming here would
            // put the guard in the test again.
            let payload = bytes.get(eth::HEADER_LEN..).ok_or(())?;
            if r.push(&h, payload, &mut out).map_err(|_| ())? {
                let total = h.packet_length as usize;
                let id = csp_core::id::Id::decode(Version::V2, &out[..total]).map_err(|_| ())?;
                // Only what is addressed to this node reaches the application; the C suite
                // sends some frames to a peer to exercise the address filter.
                if id.dst == LOCAL_ADDR || input.promisc != 0 {
                    delivered += 1;
                    if body.is_empty() {
                        body = tohex(&out[V2_HEADER..total]);
                    }
                }
                r.reset();
            }
            Ok(())
        })();
        if outcome.is_err() {
            refused = 1;
            frame = 1;
        }
    }

    EthObserved {
        refused,
        frame,
        drop: 0,
        buffers_consumed: 0,
        delivered,
        delivered_body: body,
    }
}

// --- rdp ------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RdpInput {
    #[serde(default)]
    delayed_acks: u8,
    /// Only the reset cases set this.
    #[serde(default)]
    rst_in_sequence: u8,
    /// Only the connection-timeout case sets these.
    #[serde(default)]
    conn_timeout: u32,
    #[serde(default)]
    idled_ms: u32,
    /// Only the ack-timeout case sets this.
    #[serde(default)]
    ack_timeout: u32,
    /// Only the clamp case sets this; the others open with the C helper's window of 4.
    #[serde(default)]
    window_size: u32,
    #[serde(default)]
    ack_delay_count: u32,
    #[serde(default)]
    packets: u32,
    #[serde(default)]
    packets_since_last_ack: u32,
}

/// Count the acknowledgements the port would put on the wire for the same exchange.
///
/// An open connection, then `packets` in-order data packets, asking after each one whether
/// an acknowledgement is due. `poll_ack` is what decides, and taking one restarts the delay
/// counters — so this counts frames a peer would see, not internal state.
fn replay_rdp_acks(input: &RdpInput) -> u32 {
    use csp_core::rdp;

    let mut c = rdp::Connection::new(
        1000,
        rdp::SynOptions {
            delayed_acks: input.delayed_acks != 0,
            ack_delay_count: input.ack_delay_count,
            ack_timeout: 100_000, // so only the count can trigger it, as in the C test
            ..rdp::SynOptions::default()
        },
    );
    c.state = rdp::State::Open;
    c.rcv_cur = 1000;
    c.rcv_lsa = 1000;
    c.ack_timestamp = 0;

    let mut acks = 0;
    for i in 1..=input.packets {
        c.rcv_cur = 1000u16.wrapping_add(i as u16);
        if c.poll_ack(0).is_some() {
            acks += 1;
        }
    }
    // The "nothing to acknowledge" case sends no packets and just asks. The C records
    // how many arrived since its last acknowledgement; asserting it here is what keeps the
    // replay honest about which scenario it is reproducing.
    if input.packets == 0 {
        assert_eq!(
            input.packets_since_last_ack, 0,
            "this arm only models an idle connection"
        );
        if c.poll_ack(0).is_some() {
            acks += 1;
        }
    }
    acks
}

// --- sfp ------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SfpInput {
    frag_flag: bool,
    #[serde(default)]
    body: String,
    #[serde(default)]
    offset: u32,
    #[serde(default)]
    totalsize: u32,
}

/// A transfer that is over after its first packet.
struct NoMore;
impl<'p> csp::delivery::PacketSource<'p, 8, 264> for NoMore {
    fn next_packet(&mut self, _timeout_ms: u32) -> Option<csp::pool::Packet<'p, 8, 264>> {
        None
    }
}
// The node-level replays use a 16-buffer pool, so the same "no second packet" source is
// needed at that size too.
impl<'p> csp::delivery::PacketSource<'p, 16, 264> for NoMore {
    fn next_packet(&mut self, _timeout_ms: u32) -> Option<csp::pool::Packet<'p, 16, 264>> {
        None
    }
}

/// What the port does with the same packet handed to a stream reader.
///
/// `ret` is normalised to the C's vocabulary — 0 for success, -103 for `CSP_ERR_SFP` —
/// because the comparison is "did the peer's message get through", not which enum variant
/// each side happens to use.
fn replay_sfp(input: &SfpInput) -> serde_json::Value {
    use csp::pool::Pool;

    // The pool has to outlive the `Delivery`, which borrows from it, so it is created by
    // the caller and the work happens inside.
    let pool: Pool<8, 264> = Pool::new();
    replay_sfp_in(&pool, input)
}

fn replay_sfp_in(pool: &Pool<8, 264>, input: &SfpInput) -> serde_json::Value {
    use csp::delivery::Delivery;

    let body = unhex(&input.body);
    let mut payload = body.clone();
    if input.frag_flag {
        payload.extend_from_slice(&input.offset.to_be_bytes());
        payload.extend_from_slice(&input.totalsize.to_be_bytes());
    }

    let mut p = pool.acquire(0).unwrap();
    p.set_id(Id {
        pri: 2,
        flags: if input.frag_flag {
            csp_core::flags::FRAG
        } else {
            0
        },
        src: PEER_ADDR,
        dst: LOCAL_ADDR,
        dport: TEST_PORT,
        sport: 40,
    });
    p.set_payload(&payload).unwrap();

    let mut src = NoMore;
    match Delivery::classify(p, &mut src) {
        // The whole point of the divergence: a datagram handed to a stream reader comes
        // back intact instead of being freed, so the caller can read it as what it is.
        Delivery::Datagram(pkt) => {
            let len = pkt.with_payload(|d| d.len());
            serde_json::json!({ "ret": -103, "delivered_bytes": 0, "recovered": len })
        }
        Delivery::Stream(mut st) => {
            let mut buf = [0u8; 256];
            match st.read_to_slice(1000, &mut buf) {
                Ok(n) => serde_json::json!({
                    "ret": 0, "delivered_bytes": n, "recovered": 0
                }),
                // `recovered: 0` even here, so this object has the same keys as the
                // `Datagram` arm above. A `diverges` verdict compares whole objects, and
                // two objects with different key sets are unequal whatever their values —
                // which would make the assertion pass without ever comparing anything.
                Err(_) => serde_json::json!({
                    "ret": -103, "delivered_bytes": 0, "recovered": 0
                }),
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SfpFragment {
    body: String,
    offset: u32,
    totalsize: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SfpMultiInput {
    fragments: Vec<SfpFragment>,
}

/// The fragments queued behind the first, handed over one at a time.
///
/// This is what the C's `csp_read` at the bottom of the reassembly loop reaches into, so
/// the port has to be driven the same way — a stream whose source runs dry is the
/// difference between a complete transfer and a truncated one, and that difference is the
/// whole of `a_transfer_that_stops_early_still_reports_its_last_write`.
struct Queued<'a> {
    pool: &'a csp::pool::Pool<8, 264>,
    rest: std::collections::VecDeque<Vec<u8>>,
}

impl<'a> csp::delivery::PacketSource<'a, 8, 264> for Queued<'a> {
    fn next_packet(&mut self, _timeout_ms: u32) -> Option<csp::pool::Packet<'a, 8, 264>> {
        let payload = self.rest.pop_front()?;
        let mut p = self.pool.acquire(0)?;
        p.set_id(sfp_fragment_id());
        p.set_payload(&payload).ok()?;
        Some(p)
    }
}

fn sfp_fragment_id() -> Id {
    Id {
        pri: 2,
        flags: csp_core::flags::FRAG,
        src: PEER_ADDR,
        dst: LOCAL_ADDR,
        dport: TEST_PORT,
        sport: 40,
    }
}

/// A transfer of more than one fragment, compared the way the C reports one.
///
/// The C calls `user->write` per fragment and returns a single code at the end, so this
/// drives `read_chunk` in a loop rather than `read_to_slice`: `writes` is how many times
/// the application was handed data and `assembled` is what it ended up holding. An
/// aggregate reader would report zero bytes for a transfer the C had already delivered
/// half of, which would make the two disagree about the payload as well as the verdict and
/// obscure which of the two the divergence is actually about.
fn replay_sfp_multi(input: &SfpMultiInput) -> serde_json::Value {
    use csp::delivery::Delivery;
    use csp::pool::Pool;

    let framed: Vec<Vec<u8>> = input
        .fragments
        .iter()
        .map(|f| {
            let mut v = unhex(&f.body);
            v.extend_from_slice(&f.offset.to_be_bytes());
            v.extend_from_slice(&f.totalsize.to_be_bytes());
            v
        })
        .collect();

    let pool: Pool<8, 264> = Pool::new();
    let mut first = pool.acquire(0).unwrap();
    first.set_id(sfp_fragment_id());
    first.set_payload(&framed[0]).unwrap();

    let mut src = Queued {
        pool: &pool,
        rest: framed[1..].iter().cloned().collect(),
    };

    let mut assembled: Vec<u8> = Vec::new();
    let mut writes = 0u32;
    let ret;

    match Delivery::classify(first, &mut src) {
        Delivery::Datagram(_) => {
            return serde_json::json!({ "ret": -103, "writes": 0, "assembled": "" });
        }
        Delivery::Stream(mut st) => loop {
            match st.read_chunk(0, |d, off, _| (d.to_vec(), off as usize)) {
                Ok(Some((chunk, off))) => {
                    writes += 1;
                    if assembled.len() < off + chunk.len() {
                        assembled.resize(off + chunk.len(), 0);
                    }
                    assembled[off..off + chunk.len()].copy_from_slice(&chunk);
                }
                Ok(None) => {
                    ret = 0;
                    break;
                }
                Err(_) => {
                    ret = -103;
                    break;
                }
            }
        },
    }

    let hex: String = assembled.iter().map(|b| format!("{b:02x}")).collect();
    serde_json::json!({ "ret": ret, "writes": writes, "assembled": hex })
}

// --- conn -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConnInput {
    /// Absent on the record that only exercises reuse, where the table size is irrelevant.
    /// The pressure replay asserts it rather than silently treating a missing value as 0.
    #[serde(default)]
    conn_max: u32,
    #[serde(default)]
    buffer_count: u32,
    #[serde(default)]
    offered: u32,
    #[serde(default)]
    rounds: u32,
    #[serde(default)]
    packets_from_one_peer: u32,
    #[serde(default)]
    packets_after_accept: u32,
}

/// Offer `offered` packets from distinct peer ports and see how many connections the
/// application can take, and whether every buffer comes back.
///
/// Sized to the oracle's node: `CSP_CONN_MAX` 8 connections over a 15-buffer pool. Getting
/// that wrong in either direction would compare two differently-provisioned nodes and call
/// the difference a divergence.
fn replay_conn_pressure(input: &ConnInput) -> (u32, i64) {
    assert_eq!(
        input.conn_max, 8,
        "the replay's Router is sized for the oracle's CSP_CONN_MAX; a corpus from a \
         differently-sized build would compare two different nodes"
    );
    // Same reasoning for the pool: the point at which the oracle stopped offering peers was
    // its buffer count, not its connection count, so a replay with a bigger pool would
    // offer more and call the difference a divergence.
    assert_eq!(
        input.buffer_count, 15,
        "pool sized to the oracle's CSP_BUFFER_COUNT"
    );
    type P = Pool<16, 264>;
    type R = Router<8, 16, 48, 32>;

    let pool = P::new();
    let mut r = R::new(LOCAL_ADDR, Version::V2);
    r.bind(TEST_PORT).unwrap();
    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", LOCAL_ADDR, 12, false).unwrap();
        l
    };

    let before = pool.available();
    let rounds = input.rounds.max(1);
    let per_round = if input.rounds > 0 {
        input.conn_max
    } else {
        input.offered
    };
    let mut accepted_total = 0;

    for _ in 0..rounds {
        for i in 0..per_round {
            if pool.available() < 2 {
                break;
            }
            let Some(mut p) = pool.acquire(0) else { break };
            p.set_id(Id {
                pri: 2,
                flags: 0,
                src: 11,
                dst: LOCAL_ADDR,
                dport: TEST_PORT,
                sport: 40 + i as u8,
            });
            p.set_payload(b"hi").unwrap();
            r.receive(p, 0);
            let _ = r.work(&pool, &mut ifaces, 0);
        }
        // Drain the way an application does: accept, read everything, close.
        while let Some(h) = r.accept() {
            while let Ok(Some(slot)) = r.conns.dequeue_rx(h) {
                drop(pool.from_index(slot));
            }
            // close() hands back whatever was still queued so the caller can return it to
            // the pool -- dropping the indices instead is exactly how a buffer leaks.
            let mut drained = [0u16; 32];
            if let Ok(n) = r.conns.close(h, &mut drained) {
                for &slot in &drained[..n] {
                    drop(pool.from_index(slot));
                }
            }
            accepted_total += 1;
        }
    }

    (accepted_total, before as i64 - pool.available() as i64)
}

// --- promisc --------------------------------------------------------------------------

/// The promiscuous tap as the router drives it.
///
/// Counted as frames: how many the tap copied, how many the application received, how many
/// left by a wire. The placement is the behaviour — after deduplication so a suppressed
/// duplicate is not reported, and before the local/forward branch so traffic passing
/// *through* the node is tapped too.
/// What the promiscuous tap hands the application, and who owns it afterwards.
///
/// Eight `ck_assert`s in the C and, until now, no record: the port was never compared on
/// any of it. Ownership is a leak on one side and a double free on the other, and neither
/// shows up in the `tapped`/`delivered`/`forwarded` counts the other promisc records carry.
/// Two packets through the tap, both read back exactly once.
///
/// A `read` that hands the packet over but leaves its slot occupied passes the
/// single-packet case: the queue count says empty, so the stale entry is never reached. It
/// only shows on the second round, when the count rises again and the stale slot is handed
/// out ahead of the new one -- the application given a buffer already released.
fn replay_promisc_two() -> serde_json::Value {
    const LOCAL: u16 = 10;

    type P = Pool<16, 264>;
    type R = Router<8, 16, 48, 32>;
    let pool = P::new();
    let mut r = R::new(LOCAL, Version::V2);
    r.bind(TEST_PORT).unwrap();
    r.set_promisc(true);
    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", LOCAL, 12, true).unwrap();
        l
    };

    let before = pool.available();
    for tag in [0xA1u8, 0xB2] {
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: 11,
            dst: LOCAL,
            dport: TEST_PORT,
            sport: 40,
        });
        p.set_payload(&[tag, 0, 0, 0]).unwrap();
        r.receive(p, 0);
        if let Routed::Delivered { conn, .. } = r.work(&pool, &mut ifaces, 0) {
            if let Ok(Some(slot)) = r.conns.dequeue_rx(conn) {
                drop(pool.from_index(slot));
            }
        }
    }

    let mut tags = Vec::new();
    while let Some(p) = r.promisc_read(&pool) {
        tags.push(p.with_payload(|d| d[0]));
        drop(p);
        if tags.len() > 4 {
            break; // a read that never empties would otherwise spin
        }
    }
    let third_read_empty = u8::from(r.promisc_read(&pool).is_none());

    serde_json::json!({
        "first_tag": tags.first().copied().unwrap_or(0),
        "second_tag": tags.get(1).copied().unwrap_or(0),
        "tags_differ": u8::from(tags.len() == 2 && tags[0] != tags[1]),
        "third_read_empty": third_read_empty,
        "buffers_lost": before as i64 - pool.available() as i64,
    })
}

fn replay_promisc_ownership() -> serde_json::Value {
    const LOCAL: u16 = 10;

    type P = Pool<16, 264>;
    type R = Router<8, 16, 48, 32>;
    let pool = P::new();
    let mut r = R::new(LOCAL, Version::V2);
    r.bind(TEST_PORT).unwrap();
    r.set_promisc(true);
    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", LOCAL, 12, true).unwrap();
        l
    };

    let baseline = pool.available();
    let body = b"tapped";
    let mut p = pool.acquire(0).unwrap();
    p.set_id(Id {
        pri: 2,
        flags: 0,
        src: 11,
        dst: LOCAL,
        dport: TEST_PORT,
        sport: 40,
    });
    p.set_payload(body).unwrap();
    r.receive(p, 0);

    // Deliver it; the tap takes a copy on the way past.
    let delivered_slot = match r.work(&pool, &mut ifaces, 0) {
        Routed::Delivered { conn, .. } => r.conns.dequeue_rx(conn).ok().flatten(),
        _ => None,
    };

    // With both the delivered packet and the tap's copy outstanding, two buffers are gone
    // rather than one -- the tap cloned instead of aliasing.
    let held = pool.available();
    let tap_consumed_a_buffer = u8::from(held <= baseline - 2);

    // Recorded, not asserted. This used to `expect` the packet, so a tap that captured
    // nothing panicked instead of diverging -- the run was red either way, but the failure
    // named no record, and `just mutants` counts divergences, so every mutation that broke
    // the tap was scored as noticed by nothing.
    let (tapped_payload_matches, tapped_is_a_distinct_packet, buffers_back_after_free) =
        match r.promisc_read(&pool) {
            Some(tapped) => {
                let matches = u8::from(tapped.with_payload(|d| d == body));
                let idx = tapped.into_index();
                // Distinct from the delivered packet: two live slots, not one aliased twice.
                let distinct = u8::from(delivered_slot.is_some_and(|s| s != idx));
                drop(pool.from_index(idx));
                // Releasing what `promisc_read` handed back returned the buffer, so `read`
                // gave ownership away rather than lending it.
                (matches, distinct, u8::from(pool.available() == held + 1))
            }
            None => (0, 0, 0),
        };

    let second_read_empty = u8::from(r.promisc_read(&pool).is_none());
    if let Some(s) = delivered_slot {
        drop(pool.from_index(s));
    }

    serde_json::json!({
        "tap_consumed_a_buffer": tap_consumed_a_buffer,
        "tapped_is_a_distinct_packet": tapped_is_a_distinct_packet,
        "tapped_payload_matches": tapped_payload_matches,
        "buffers_back_after_free": buffers_back_after_free,
        "second_read_empty": second_read_empty,
    })
}

fn replay_promisc(case: &str) -> serde_json::Value {
    use csp::dedup::DedupMode;
    type P = Pool<16, 264>;
    type R = Router<8, 16, 48, 32>;

    const EGRESS: u16 = 20;
    const ELSEWHERE: u16 = 25;

    // `opts` is the endpoint's security policy. `csp_route.c` taps at :252 and applies the
    // policy at :289, so a refused packet is tapped and then dropped.
    let (tap_on, dedup, dsts, opts): (bool, DedupMode, &[u16], u32) = match case {
        "the_tap_sees_a_locally_delivered_packet" => (true, DedupMode::Off, &[LOCAL_ADDR], 0),
        "the_tap_sees_a_forwarded_packet" => (true, DedupMode::Off, &[ELSEWHERE], 0),
        "the_tap_does_not_see_a_suppressed_duplicate" => {
            (true, DedupMode::All, &[LOCAL_ADDR, LOCAL_ADDR], 0)
        }
        "delivery_is_the_same_with_the_tap_off" => {
            (false, DedupMode::Off, &[LOCAL_ADDR, ELSEWHERE], 0)
        }
        "the_tap_sees_a_packet_the_security_check_rejects" => (
            true,
            DedupMode::Off,
            &[LOCAL_ADDR],
            csp_core::security::opts::CRC32_REQ,
        ),
        other => panic!("no promisc replay for {other}"),
    };

    let pool = P::new();
    let mut r = R::new(LOCAL_ADDR, Version::V2);
    r.bind(TEST_PORT).unwrap();
    r.dedup_mode = dedup;
    r.endpoint_opts = opts;
    r.set_promisc(tap_on);

    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", LOCAL_ADDR, 12, false).unwrap();
        l.add("EGRESS", EGRESS, 12, true).unwrap();
        l
    };

    let before = pool.available();
    let mut delivered = 0;
    let mut forwarded = 0;

    for &dst in dsts {
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: PEER_ADDR,
            dst,
            dport: TEST_PORT,
            sport: 40,
        });
        p.set_payload(b"watched").unwrap();
        r.receive(p, 0);
        match r.work(&pool, &mut ifaces, 0) {
            Routed::Delivered { conn, .. } => {
                delivered += 1;
                // Read it the way an application does, so the buffer comes back.
                while let Ok(Some(slot)) = r.conns.dequeue_rx(conn) {
                    drop(pool.from_index(slot));
                }
                let mut drained = [0u16; 32];
                if let Ok(n) = r.conns.close(conn, &mut drained) {
                    for &slot in &drained[..n] {
                        drop(pool.from_index(slot));
                    }
                }
            }
            Routed::Forwarded { packet, .. } => {
                forwarded += 1;
                // The caller owns a forwarded packet; a driver would transmit and release.
                drop(pool.from_index(packet));
            }
            _ => {}
        }
    }

    let mut tapped = 0;
    while r.promisc_read(&pool).is_some() {
        tapped += 1;
    }

    serde_json::json!({
        "tapped": tapped,
        "delivered": delivered,
        "forwarded": forwarded,
        "buffers_lost": before as i64 - pool.available() as i64,
    })
}

// --- route ----------------------------------------------------------------------------

/// Forwarding when more than one destination matches.
///
/// Counted as frames leaving and the interfaces they left by — the only thing a peer on a
/// redundant link can observe about whether the redundancy is being used.
/// An application send, resolved by a real `Node` rather than by the router's forward path.
///
/// The two are separate implementations of `csp_send_direct` in this port, and only the
/// forward path had records. This drives the one an application actually calls.
/// The RDP handshake, driven through a real `Node` rather than the state machine alone.
///
/// Everything else in the `rdp` suite replays `csp_core::rdp::Connection` directly, which
/// is why the router never reaching it went unnoticed: the state machine was correct and
/// nothing called it.
/// A SYN whose option block is absent or one word short.
///
/// `csp_rdp.c` reads `packet->data32[0..5]` unconditionally once it has decided a packet is
/// a SYN, so a block shorter than six words is a read past what the peer actually sent --
/// on input a peer fully controls. What is compared is only what that peer can see: how
/// many frames came back, what the first one carried, and whether the node then had a
/// connection to hand its application.
/// A peer proposing a window of two must get two packets out.
///
/// The overflow is not comparable -- `csp_rdp_send` loops around a semaphore whose only
/// exits need another thread, so the third call never returns in a single-threaded harness
/// (measured, not assumed: the probe was killed by libcheck's timeout). The boundary is.
#[cfg(feature = "rdp")]
fn replay_rdp_window_boundary() -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    let opts = rdp::SynOptions {
        window_size: 2,
        conn_timeout: 20_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut syn = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut syn).unwrap();

    let inject = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>,
                  body: &[u8],
                  flags: u8,
                  seq: u16,
                  ack: u16| {
        let mut buf = [0u8; 64];
        buf[..body.len()].copy_from_slice(body);
        let h = rdp::Header {
            flags,
            seq_nr: seq,
            ack_nr: ack,
        };
        let hl = h.encode(&[], &mut buf[body.len()..]).unwrap();
        let Some(mut p) = n.packet() else { return };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        p.set_payload(&buf[..body.len() + hl]).unwrap();
        n.router.receive(p, 0);
        loop {
            match n.work(CLOCK) {
                csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
                csp::Routed::Delivered { conn, .. } => {
                    while let Ok(Some(x)) = n.read(conn) {
                        drop(x);
                    }
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    };

    inject(&mut n, &syn[..olen], rdp::SYN, 1000, 0);
    let Some(h) = n.accept() else {
        return serde_json::json!({ "frames": 0, "sequential": 0 });
    };
    let iss = n.router.conns.rdp(h).map(|r| r.snd_iss).unwrap_or(0);
    inject(&mut n, &[], rdp::ACK, 1001, iss);

    let mut frames = 0u32;
    let mut seqs = [0u16; 2];
    for (i, seq) in seqs.iter_mut().enumerate() {
        let Some(mut p) = n.packet() else { break };
        p.set_payload(&[b'a' + i as u8]).unwrap();
        if let Ok(out) = n.send(h, p, CLOCK) {
            frames += 1;
            let pk = out.into_packet();
            *seq = pk.with_payload(|b| rdp::Header::decode(b).map(|x| x.seq_nr).unwrap_or(0));
            drop(pk);
        }
    }

    serde_json::json!({
        "frames": frames,
        "sequential": u8::from(seqs[0] == iss.wrapping_add(1) && seqs[1] == iss.wrapping_add(2)),
    })
}

/// Three sends in a row, then one acknowledgement covering all of them.
///
/// Consecutive sends must take consecutive sequence numbers, and an acknowledgement must
/// release what it covers -- `csp_rdp_check_timeouts` frees a queued packet whose sequence
/// is before `snd_una`. Without that a sender repeats data the peer already has for as long
/// as the connection lives.
#[cfg(feature = "rdp")]
fn replay_rdp_three_sends() -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    let opts = rdp::SynOptions {
        window_size: 4,
        conn_timeout: 20_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut syn = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut syn).unwrap();

    let inject = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>,
                  body: &[u8],
                  flags: u8,
                  seq: u16,
                  ack: u16| {
        let mut buf = [0u8; 64];
        buf[..body.len()].copy_from_slice(body);
        let h = rdp::Header {
            flags,
            seq_nr: seq,
            ack_nr: ack,
        };
        let hl = h.encode(&[], &mut buf[body.len()..]).unwrap();
        let Some(mut p) = n.packet() else { return };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        p.set_payload(&buf[..body.len() + hl]).unwrap();
        n.router.receive(p, 0);
        loop {
            match n.work(CLOCK) {
                csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
                csp::Routed::Delivered { conn, .. } => {
                    while let Ok(Some(x)) = n.read(conn) {
                        drop(x);
                    }
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    };

    inject(&mut n, &syn[..olen], rdp::SYN, 1000, 0);
    let Some(h) = n.accept() else {
        return serde_json::json!({ "sequential": 0 });
    };
    let iss = n.router.conns.rdp(h).map(|r| r.snd_iss).unwrap_or(0);
    inject(&mut n, &[], rdp::ACK, 1001, iss);

    // Buffer accounting: "nothing retransmitted" is also true of a node that dropped the
    // queue entry and leaked its buffer.
    let free_before = storage.pool_ref().available();

    let mut seqs = [0u16; 3];
    for (i, seq) in seqs.iter_mut().enumerate() {
        let Some(mut p) = n.packet() else { break };
        p.set_payload(&[b'a' + i as u8]).unwrap();
        if let Ok(out) = n.send(h, p, CLOCK) {
            let pk = out.into_packet();
            *seq = pk.with_payload(|b| rdp::Header::decode(b).map(|x| x.seq_nr).unwrap_or(0));
            drop(pk);
        }
    }
    let sequential = u8::from(
        seqs[0] == iss.wrapping_add(1)
            && seqs[1] == iss.wrapping_add(2)
            && seqs[2] == iss.wrapping_add(3),
    );

    // One acknowledgement covering all three.
    inject(&mut n, &[], rdp::ACK, 1002, seqs[2]);

    // Nothing may go out after that, however long we wait.
    let mut after = 0u32;
    let mut t = CLOCK;
    for _ in 0..40 {
        t = t.wrapping_add(250);
        n.tick(t, 60_000);
        loop {
            match n.work(t) {
                csp::Routed::Respond { packet, .. } | csp::Routed::Forwarded { packet, .. } => {
                    after += 1;
                    drop(n.take_forwarded(packet));
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    }

    serde_json::json!({
        "sequential": sequential,
        "frames_after_the_ack": after,
        "buffers_lost": free_before as i64 - storage.pool_ref().available() as i64,
    })
}

/// One packet, one `packet_timeout`, and what comes back out.
///
/// The total-frame record is a `diverges` and so cannot protect the send path -- breaking
/// it leaves the two disagreeing either way. This is the `must_match` half: the repeat
/// happens, carries `ACK`, and still carries the payload.
#[cfg(feature = "rdp")]
fn replay_rdp_one_retransmission() -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    let opts = rdp::SynOptions {
        window_size: 4,
        conn_timeout: 20_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut syn = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut syn).unwrap();

    let inject = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>,
                  body: &[u8],
                  flags: u8,
                  seq: u16,
                  ack: u16| {
        let mut buf = [0u8; 64];
        buf[..body.len()].copy_from_slice(body);
        let h = rdp::Header {
            flags,
            seq_nr: seq,
            ack_nr: ack,
        };
        let hl = h.encode(&[], &mut buf[body.len()..]).unwrap();
        let Some(mut p) = n.packet() else { return };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        p.set_payload(&buf[..body.len() + hl]).unwrap();
        n.router.receive(p, 0);
        loop {
            match n.work(CLOCK) {
                csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
                csp::Routed::Delivered { conn, .. } => {
                    while let Ok(Some(x)) = n.read(conn) {
                        drop(x);
                    }
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    };

    inject(&mut n, &syn[..olen], rdp::SYN, 1000, 0);
    let Some(h) = n.accept() else {
        return serde_json::json!({ "repeats": 0 });
    };
    let iss = n.router.conns.rdp(h).map(|r| r.snd_iss).unwrap_or(0);
    inject(&mut n, &[], rdp::ACK, 1001, iss);

    let Some(mut p) = n.packet() else {
        return serde_json::json!({ "repeats": 0 });
    };
    p.set_payload(b"hello").unwrap();
    if let Ok(out) = n.send(h, p, CLOCK) {
        drop(out.into_packet());
    }

    // Sweep just past the 1000 ms packet timeout.
    let mut repeats = 0u32;
    let (mut flags, mut carries) = (0u8, 0u32);
    let mut t = CLOCK;
    for _ in 0..5 {
        t = t.wrapping_add(250);
        n.tick(t, 60_000);
        loop {
            match n.work(t) {
                csp::Routed::Respond { packet, .. } | csp::Routed::Forwarded { packet, .. } => {
                    repeats += 1;
                    if let Some(pk) = n.take_forwarded(packet) {
                        pk.with_payload(|b| {
                            if let Ok(hd) = rdp::Header::decode(b) {
                                flags = hd.flags & 0x0F;
                            }
                            carries = u32::from(b.len().saturating_sub(rdp::HEADER_LEN) == 5);
                        });
                        drop(pk);
                    }
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    }

    serde_json::json!({
        "repeats": repeats,
        "repeat_flags": flags,
        "repeat_carries_the_payload": carries,
    })
}

/// The frame an application's send produces on an RDP connection.
///
/// Absolute sequence numbers are not comparable -- the port does not reproduce the C's
/// `rand_r` initial sequence number, deliberately -- so what is recorded is relative to the
/// connection's own ISN, plus the flags and the payload length. That is what says the
/// trailer was framed at all.
///
/// `must_match`, on purpose: the retransmission record next door is a `diverges`, and a
/// divergence record cannot catch a broken send path -- breaking it keeps the two
/// disagreeing. The mutation sweep said so, with three send-path mutations noticed by
/// nothing.
#[cfg(feature = "rdp")]
fn replay_rdp_sent_framing() -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    let opts = rdp::SynOptions {
        window_size: 4,
        conn_timeout: 20_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut syn = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut syn).unwrap();

    let inject = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>,
                  body: &[u8],
                  flags: u8,
                  seq: u16,
                  ack: u16| {
        let mut buf = [0u8; 64];
        buf[..body.len()].copy_from_slice(body);
        let h = rdp::Header {
            flags,
            seq_nr: seq,
            ack_nr: ack,
        };
        let hl = h.encode(&[], &mut buf[body.len()..]).unwrap();
        let Some(mut p) = n.packet() else { return };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        p.set_payload(&buf[..body.len() + hl]).unwrap();
        n.router.receive(p, 0);
        loop {
            match n.work(CLOCK) {
                csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
                csp::Routed::Delivered { conn, .. } => {
                    while let Ok(Some(x)) = n.read(conn) {
                        drop(x);
                    }
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    };

    inject(&mut n, &syn[..olen], rdp::SYN, 1000, 0);
    let Some(h) = n.accept() else {
        return serde_json::json!({ "frames": 0 });
    };
    let iss = n.router.conns.rdp(h).map(|r| r.snd_iss).unwrap_or(0);
    inject(&mut n, &[], rdp::ACK, 1001, iss);
    let rcv_cur = n.router.conns.rdp(h).map(|r| r.rcv_cur).unwrap_or(0);

    let Some(mut p) = n.packet() else {
        return serde_json::json!({ "frames": 0 });
    };
    p.set_payload(b"hello").unwrap();
    let Ok(out) = n.send(h, p, CLOCK) else {
        return serde_json::json!({ "frames": 0 });
    };
    let pk = out.into_packet();
    let (flags, seq, ack, plen) = pk.with_payload(|b| {
        let hd = rdp::Header::decode(b).ok();
        (
            hd.map(|x| x.flags & 0x0F).unwrap_or(0),
            hd.map(|x| x.seq_nr).unwrap_or(0),
            hd.map(|x| x.ack_nr).unwrap_or(0),
            b.len().saturating_sub(rdp::HEADER_LEN) as u16,
        )
    });
    drop(pk);

    serde_json::json!({
        "frames": 1,
        "flags": flags,
        "seq_is_iss_plus_one": u8::from(seq == iss.wrapping_add(1)),
        "ack_is_rcv_cur": u8::from(ack == rcv_cur),
        "payload_len": plen,
    })
}

/// What the node puts on the wire when the application sends on an RDP connection, and
/// what happens when the peer never acknowledges it.
///
/// `csp_rdp_check_timeouts` walks the transmit queue, retransmits anything past
/// `packet_timeout`, counts one attempt per sweep, and gives up past
/// `CSP_RDP_MAX_RETRANSMITS`.
#[cfg(feature = "rdp")]
fn replay_rdp_unacked_send() -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    let opts = rdp::SynOptions {
        window_size: 4,
        conn_timeout: 20_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut syn = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut syn).unwrap();

    // A `Cell`, because the two closures below both touch it and the borrow checker is
    // right that two `&mut` captures of the same counter is not a thing.
    let frames = core::cell::Cell::new(0u32);
    let drain = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>, now: u32, count: bool| loop {
        match n.work(now) {
            csp::Routed::Respond { packet, .. } | csp::Routed::Forwarded { packet, .. } => {
                if count {
                    frames.set(frames.get() + 1);
                }
                drop(n.take_forwarded(packet));
            }
            csp::Routed::Delivered { conn, .. } => {
                while let Ok(Some(p)) = n.read(conn) {
                    drop(p);
                }
            }
            csp::Routed::Idle => break,
            _ => {}
        }
    };

    let inject = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>,
                  body: &[u8],
                  flags: u8,
                  seq: u16,
                  ack: u16| {
        let mut buf = [0u8; 64];
        buf[..body.len()].copy_from_slice(body);
        let h = rdp::Header {
            flags,
            seq_nr: seq,
            ack_nr: ack,
        };
        let hl = h.encode(&[], &mut buf[body.len()..]).unwrap();
        let Some(mut p) = n.packet() else { return };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        p.set_payload(&buf[..body.len() + hl]).unwrap();
        n.router.receive(p, 0);
    };

    inject(&mut n, &syn[..olen], rdp::SYN, 1000, 0);
    drain(&mut n, CLOCK, false);
    let conn = n.accept();
    let iss = conn
        .and_then(|h| n.router.conns.rdp(h).ok().map(|r| r.snd_iss))
        .unwrap_or(0);
    inject(&mut n, &[], rdp::ACK, 1001, iss);
    drain(&mut n, CLOCK, false);

    // The application sends. Everything from here is counted.
    let first = if let Some(h) = conn {
        let before = frames.get();
        if let Some(mut p) = n.packet() {
            p.set_payload(b"hello").unwrap();
            // `send` hands the frame straight back for the caller to transmit; it does not
            // go through `work`, so it is counted here.
            if let Ok(out) = n.send(h, p, CLOCK) {
                frames.set(frames.get() + 1);
                drop(out);
            }
        }
        drain(&mut n, CLOCK, true);
        frames.get() - before
    } else {
        0
    };

    // The peer stays silent.
    let mut t = CLOCK;
    for _ in 0..1000 {
        t = t.wrapping_add(250);
        n.tick(t, 60_000);
        drain(&mut n, t, true);
    }
    let total = frames.get();

    let before_tail = frames.get();
    for _ in 0..1000 {
        t = t.wrapping_add(250);
        n.tick(t, 60_000);
        drain(&mut n, t, true);
    }

    serde_json::json!({
        "frames_on_first_send": first,
        "total_frames": total,
        "frames_after_giving_up": frames.get() - before_tail,
    })
}

/// Two data packets in the order given, then everything the application can read.
///
/// `csp_rdp.c` stores an out-of-sequence packet and walks the queue once the gap is filled,
/// so a packet that overtook its predecessor is still delivered, in sequence order. What is
/// compared is the bytes the application ends up with and their order -- nothing about how
/// either side holds them meanwhile.
#[cfg(feature = "rdp")]
fn replay_rdp_reordered(packets: &[(u16, u8)]) -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    let opts = rdp::SynOptions {
        window_size: 4,
        conn_timeout: 20_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut syn = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut syn).unwrap();

    let mut got: Vec<u8> = Vec::new();
    let mut feed = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>,
                    payload: &[u8],
                    flags: u8,
                    seq: u16,
                    ack: u16,
                    collect: bool| {
        let mut buf = [0u8; 64];
        buf[..payload.len()].copy_from_slice(payload);
        let h = rdp::Header {
            flags,
            seq_nr: seq,
            ack_nr: ack,
        };
        let hlen = h.encode(&[], &mut buf[payload.len()..]).unwrap();
        let Some(mut p) = n.packet() else { return };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        p.set_payload(&buf[..payload.len() + hlen]).unwrap();
        n.router.receive(p, 0);
        loop {
            match n.work(CLOCK) {
                csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
                csp::Routed::Delivered { conn, .. } => {
                    while let Ok(Some(pkt)) = n.read(conn) {
                        if collect {
                            pkt.with_payload(|d| got.extend_from_slice(d));
                        }
                        drop(pkt);
                    }
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    };

    feed(&mut n, &syn[..olen], rdp::SYN, 1000, 0, false);
    let iss = n
        .accept()
        .and_then(|h| n.router.conns.rdp(h).ok().map(|r| r.snd_iss))
        .unwrap_or(0);
    feed(&mut n, &[], rdp::ACK, 1001, iss, false);

    for (offset, byte) in packets {
        feed(&mut n, &[*byte], rdp::ACK, 1000 + offset, iss, true);
    }

    serde_json::json!({
        "delivered_bytes": got.len(),
        "delivered_body": tohex(&got),
    })
}

/// One crafted packet on an established connection: what the application gets, and what
/// goes back on the wire.
///
/// Covers the two EAK paths, the flag `csp-core` defines and never reads. `csp_rdp.c:712`
/// treats an extended acknowledgement as acknowledgement *only* -- `snd_una` moves, the
/// retransmit counter resets, and `goto discard_open` throws the packet away including any
/// payload. And data arriving with a gap is queued silently: measured, the C answers
/// nothing, which is not what its own comment ("send EACK and store packet") suggests.
#[cfg(feature = "rdp")]
fn replay_rdp_one_packet(flags: u8, seq_offset: u16, payload: &[u8]) -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    let opts = rdp::SynOptions {
        window_size: 4,
        conn_timeout: 20_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut syn = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut syn).unwrap();

    let (mut delivered, mut delivered_bytes) = (0u32, 0u32);
    let mut frames = 0u32;
    let mut last_flags = 0u8;

    let mut feed = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>,
                    payload: &[u8],
                    flags: u8,
                    seq: u16,
                    ack: u16,
                    count: bool| {
        let mut buf = [0u8; 64];
        buf[..payload.len()].copy_from_slice(payload);
        let h = rdp::Header {
            flags,
            seq_nr: seq,
            ack_nr: ack,
        };
        let hlen = h.encode(&[], &mut buf[payload.len()..]).unwrap();
        let Some(mut p) = n.packet() else { return };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        p.set_payload(&buf[..payload.len() + hlen]).unwrap();
        n.router.receive(p, 0);
        loop {
            match n.work(CLOCK) {
                csp::Routed::Respond { packet, .. } => {
                    if count {
                        frames += 1;
                    }
                    if let Some(pk) = n.take_forwarded(packet) {
                        if count {
                            last_flags = pk.with_payload(|b| {
                                rdp::Header::decode(b).map(|h| h.flags).unwrap_or(0)
                            });
                        }
                        drop(pk);
                    }
                }
                csp::Routed::Delivered { conn, .. } => {
                    while let Ok(Some(pkt)) = n.read(conn) {
                        if count {
                            delivered += 1;
                            delivered_bytes += pkt.with_payload(|d| d.len() as u32);
                        }
                        drop(pkt);
                    }
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    };

    feed(&mut n, &syn[..olen], rdp::SYN, 1000, 0, false);
    let iss = n
        .accept()
        .and_then(|h| n.router.conns.rdp(h).ok().map(|r| r.snd_iss))
        .unwrap_or(0);
    feed(&mut n, &[], rdp::ACK, 1001, iss, false);

    // `rcv_cur` is 1000 after the handshake.
    feed(&mut n, payload, flags, 1000 + seq_offset, iss, true);

    serde_json::json!({
        "delivered": delivered,
        "delivered_bytes": delivered_bytes,
        "frames_back": frames,
        "reply_flags": if frames > 0 { last_flags & 0x0F } else { 0 },
    })
}

/// A peer resetting an established connection, in sequence and out of it.
///
/// `csp_rdp.c` honours a reset only when `seq_nr == rcv_cur + 1`: it moves to CLOSE_WAIT and
/// answers `ACK|RST`. Any other sequence number hits "RST out of sequence, keep connection
/// open" -- a blind-reset defence, so an injector who cannot guess the sequence number
/// cannot drop the link with one spoofed frame.
///
/// Driven through a real `Node`, and what is compared is only what the peer sees: the reply
/// to the reset, and the flags on the answer to the *next* data packet. Flags rather than a
/// bool, because "something came back" cannot separate an `ACK` on a live connection from an
/// `ACK|RST` on a dead one.
#[cfg(feature = "rdp")]
fn replay_rdp_reset(in_sequence: bool) -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    // Immediate acknowledgement, matching the C helper's `open_conn(0, 2)`.
    let opts = rdp::SynOptions {
        window_size: 4,
        conn_timeout: 20_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut syn = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut syn).unwrap();

    // Returns the flags of the last frame the node sent, and how many it sent.
    let send = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>,
                payload: &[u8],
                flags: u8,
                seq: u16,
                ack: u16|
     -> (u32, u8) {
        let mut buf = [0u8; 64];
        buf[..payload.len()].copy_from_slice(payload);
        let h = rdp::Header {
            flags,
            seq_nr: seq,
            ack_nr: ack,
        };
        let hlen = h.encode(&[], &mut buf[payload.len()..]).unwrap();
        let Some(mut p) = n.packet() else {
            return (0, 0);
        };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        p.set_payload(&buf[..payload.len() + hlen]).unwrap();
        n.router.receive(p, 0);
        let (mut frames, mut last) = (0u32, 0u8);
        loop {
            match n.work(CLOCK) {
                csp::Routed::Respond { packet, .. } => {
                    frames += 1;
                    if let Some(pk) = n.take_forwarded(packet) {
                        last = pk
                            .with_payload(|b| rdp::Header::decode(b).map(|h| h.flags).unwrap_or(0));
                        drop(pk);
                    }
                }
                csp::Routed::Delivered { conn, .. } => {
                    while let Ok(Some(pkt)) = n.read(conn) {
                        drop(pkt);
                    }
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
        (frames, last)
    };

    send(&mut n, &syn[..olen], rdp::SYN, 1000, 0);
    let iss = n
        .accept()
        .and_then(|h| n.router.conns.rdp(h).ok().map(|r| r.snd_iss))
        .unwrap_or(0);
    send(&mut n, &[], rdp::ACK, 1001, iss);

    // `rcv_cur` is 1000 after the handshake, so the next expected sequence is 1001.
    let rst_seq = if in_sequence { 1001 } else { 1001 + 5000 };
    let (frames, reply) = send(&mut n, &[], rdp::RST, rst_seq, iss);

    // The next data packet, in sequence for whichever connection is left.
    let (_, followup) = send(
        &mut n,
        b"x",
        rdp::ACK,
        if in_sequence { 1002 } else { 1001 },
        iss,
    );

    serde_json::json!({
        "frames_after_rst": frames,
        "reply_flags": if frames > 0 { reply & 0x0F } else { 0 },
        "followup_flags": followup & 0x0F,
    })
}

/// An established RDP connection left idle past its negotiated `conn_timeout`.
///
/// libcsp does not reap it: `csp_rdp_check_timeouts`'s CONNECTION TIMEOUT branch is guarded
/// by `conn->dest_socket != NULL`, and `dest_socket` is cleared the moment the connection is
/// *announced* to the socket, not when the application accepts it. So the branch only covers
/// the window before announcement.
///
/// Driven through a real `Node` -- handshake, idle with `tick`, then one data packet -- so
/// what is compared is whether the peer still gets an answer.
#[cfg(feature = "rdp")]
fn replay_rdp_conn_timeout(conn_timeout: u32, idled_ms: u32) -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    let opts = rdp::SynOptions {
        window_size: 4,
        conn_timeout,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut body = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut body).unwrap();

    // Drive the peer's half: SYN, then the handshake's final ACK, then one data packet.
    let send = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>,
                payload: &[u8],
                flags: u8,
                seq: u16,
                ack: u16,
                now: u32|
     -> u32 {
        let mut buf = [0u8; 64];
        buf[..payload.len()].copy_from_slice(payload);
        let h = rdp::Header {
            flags,
            seq_nr: seq,
            ack_nr: ack,
        };
        let hlen = h.encode(&[], &mut buf[payload.len()..]).unwrap();
        let Some(mut p) = n.packet() else { return 0 };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        p.set_payload(&buf[..payload.len() + hlen]).unwrap();
        n.router.receive(p, 0);
        let mut frames = 0;
        loop {
            match n.work(now) {
                csp::Routed::Respond { packet, .. } => {
                    frames += 1;
                    drop(n.take_forwarded(packet));
                }
                csp::Routed::Delivered { conn, .. } => {
                    while let Ok(Some(pkt)) = n.read(conn) {
                        drop(pkt);
                    }
                }
                csp::Routed::Idle => break,
                _ => {}
            }
        }
        frames
    };

    send(&mut n, &body[..olen], rdp::SYN, 1000, 0, CLOCK);
    let iss = n
        .accept()
        .and_then(|h| n.router.conns.rdp(h).ok().map(|r| r.snd_iss))
        .unwrap_or(0);
    send(&mut n, &[], rdp::ACK, 1001, iss, CLOCK);

    // Idle, the way the C's loop does: advance and tick, no traffic.
    let mut t = CLOCK;
    let mut step = 0;
    while step < idled_ms {
        step += 250;
        t = CLOCK.wrapping_add(step);
        // The *node's* idle policy, deliberately well past the test window, not the peer's
        // proposal. Two different mechanisms: `ConnTable::expire_idle` is the node deciding
        // how long to hold a slot, and libcsp has no counterpart for an established RDP
        // connection -- its table is bounded and reused instead. What this record measures
        // is whether the peer-proposed `conn_timeout` alone stops the answers, so the
        // node-level reaper must not fire inside the window or it would answer a different
        // question.
        let _ = conn_timeout;
        n.tick(t, 60_000);
        loop {
            match n.work(t) {
                csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    }

    // Now the peer speaks. `answered` is the whole question: does anything come back?
    let answered = u32::from(send(&mut n, b"x", rdp::ACK, 1001, iss, t) > 0);

    // Only what the peer can see. Whether a table slot still exists is implementation.
    serde_json::json!({ "answered_after_idle": answered })
}

#[cfg(feature = "rdp")]
fn replay_rdp_malformed_syn(words: usize) -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    // `words` option words, then the five-byte trailer. The C's own case uses these values
    // for the five-word variant; with `words == 0` there is no block at all.
    const PARTIAL: [u32; 5] = [4, 10_000, 1_000, 1, 250];
    let mut body = [0u8; 6 * 4 + rdp::HEADER_LEN];
    for (i, w) in PARTIAL.iter().take(words).enumerate() {
        body[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    let olen = words * 4;
    let h = rdp::Header {
        flags: rdp::SYN,
        seq_nr: 1000,
        ack_nr: 0,
    };
    let hlen = h.encode(&[], &mut body[olen..]).unwrap();

    let mut syn = n.packet().expect("the pool is empty");
    syn.set_id(Id {
        pri: 2,
        flags: csp_core::flags::RDP,
        src: PEER,
        dst: NODE,
        dport: PORT,
        sport: 40,
    });
    syn.set_payload(&body[..olen + hlen]).unwrap();
    n.router.receive(syn, 0);

    let mut frames = 0u32;
    let mut reply_flags = 0u8;
    loop {
        match n.work(0) {
            csp::Routed::Respond { packet, .. } => {
                frames += 1;
                if let Some(p) = n.take_forwarded(packet) {
                    if frames == 1 {
                        reply_flags = p
                            .with_payload(|b| rdp::Header::decode(b).map(|h| h.flags).unwrap_or(0));
                    }
                    drop(p);
                }
            }
            csp::Routed::Idle => break,
            _ => {}
        }
    }

    let accepted_after = u32::from(n.accept().is_some());

    serde_json::json!({
        "frames_out": frames,
        "reply_flags": reply_flags,
        "accepted_after": accepted_after,
    })
}

/// More malformed SYNs than the connection table holds, then an honest peer.
///
/// A node that keeps the slot for a SYN it rejected is closed for business after that many
/// packets, from a peer that never completed a handshake. What is compared is only what the
/// honest peer gets: a connection, and a `SYN|ACK` on the wire.
#[cfg(feature = "rdp")]
fn replay_rdp_syn_flood() -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CONNS: usize = 8;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    let send = |n: &mut csp::Node<'_, 8, 16, 264, 48, 32, 4>, body: &[u8], sport: u8| {
        let Some(mut p) = n.packet() else { return };
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport,
        });
        p.set_payload(body).unwrap();
        n.router.receive(p, 0);
        loop {
            match n.work(0) {
                csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
                csp::Routed::Idle => break,
                _ => {}
            }
        }
    };

    // A SYN with no option block at all, from a different source port each time so each one
    // asks for its own connection rather than re-finding the last.
    let h = rdp::Header {
        flags: rdp::SYN,
        seq_nr: 1000,
        ack_nr: 0,
    };
    let mut bad = [0u8; rdp::HEADER_LEN];
    let blen = h.encode(&[], &mut bad).unwrap();
    for i in 0..(CONNS * 3) {
        send(&mut n, &bad[..blen], 40u8.wrapping_add(i as u8));
        while n.accept().is_some() {}
    }

    // Now an honest peer.
    let opts = rdp::SynOptions {
        window_size: 3,
        conn_timeout: 20_000,
        packet_timeout: 500,
        delayed_acks: true,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut good = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut good).unwrap();
    let glen = h.encode(&[], &mut good[olen..]).unwrap();

    let Some(mut p) = n.packet() else {
        return serde_json::json!({ "honest_peer_opened": 0, "honest_peer_got_syn_ack": 0 });
    };
    p.set_id(Id {
        pri: 2,
        flags: csp_core::flags::RDP,
        src: PEER,
        dst: NODE,
        dport: PORT,
        sport: 39,
    });
    p.set_payload(&good[..olen + glen]).unwrap();
    n.router.receive(p, 0);

    let mut got_syn_ack = 0u32;
    loop {
        match n.work(0) {
            csp::Routed::Respond { packet, .. } => {
                if let Some(pk) = n.take_forwarded(packet) {
                    let f =
                        pk.with_payload(|b| rdp::Header::decode(b).map(|h| h.flags).unwrap_or(0));
                    if f & (rdp::SYN | rdp::ACK) == (rdp::SYN | rdp::ACK) {
                        got_syn_ack = 1;
                    }
                    drop(pk);
                }
            }
            csp::Routed::Idle => break,
            _ => {}
        }
    }

    serde_json::json!({
        "honest_peer_opened": u32::from(n.accept().is_some()),
        "honest_peer_got_syn_ack": got_syn_ack,
    })
}

#[cfg(feature = "rdp")]
/// A reply to a connection the node opened, on a port nothing bound.
///
/// This is the request/reply exchange every client does: `connect` picks an ephemeral
/// source port, the peer answers to it, and no `bind` ever names it. The port refused these
/// as `PortNotBound` because it checked the socket table and not the connection table, so
/// nothing a `connect` asked for ever came back.
fn replay_reply_to_a_connect() -> serde_json::Value {
    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const BOUND: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 12, true).unwrap();
    n.bind(BOUND).unwrap();

    let h = n.connect(2, PEER, 20, 0, CLOCK).expect("connect");
    let info = n.conn_info(h).expect("live");

    let mut reply = n.packet().expect("the pool is empty");
    reply.set_id(Id {
        pri: 2,
        flags: 0,
        src: PEER,
        dst: NODE,
        dport: info.dport,
        sport: info.sport,
    });
    reply.set_payload(b"pong").unwrap();
    n.router.receive(reply, 0);

    let mut delivered = 0;
    let mut body: Vec<u8> = Vec::new();
    loop {
        match n.work(CLOCK) {
            csp::Routed::Delivered { conn, .. } => {
                while let Ok(Some(p)) = n.read(conn) {
                    delivered += 1;
                    p.with_payload(|d| body.extend_from_slice(d));
                    drop(p);
                }
            }
            csp::Routed::Idle => break,
            _ => continue,
        }
    }

    serde_json::json!({
        "delivered": delivered,
        "delivered_len": body.len(),
        "delivered_body": body.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    })
}

/// The receive-queue gate: acknowledgements stop while the connection is nearly full.
///
/// `csp_rdp_check_ack` refuses to acknowledge while the receive queue has less than a window
/// of spare room, so a peer stalls instead of overflowing a node whose application has
/// stopped reading. The port had no such gate, and worse, acknowledged *before* attempting
/// the enqueue — so a packet it then dropped had already been promised to the peer.
#[cfg(feature = "rdp")]
fn replay_rdp_receive_gate(window_size: u32, delivered: u32) -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    // RXQ = 16, matching `CSP_CONN_RXQUEUE_LEN`; the pool is sized to outlast the burst.
    type S = csp::CspStorage<8, 24, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 24, 264, 48, 32, 16> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    // A peer opens the connection, proposing the window the C was given.
    let opts = rdp::SynOptions {
        window_size,
        conn_timeout: 20_000,
        packet_timeout: 1_000,
        delayed_acks: false,
        ack_timeout: 250,
        ack_delay_count: 2,
    };
    let mut body = [0u8; rdp::SYN_OPTIONS_LEN];
    let bn = opts.encode(&mut body).unwrap();
    let peer_iss = 1000u16;
    let mut syn = n.packet().expect("pool");
    syn.set_id(Id {
        pri: 2,
        flags: csp_core::flags::RDP,
        src: PEER,
        dst: NODE,
        dport: PORT,
        sport: 40,
    });
    let mut framed = [0u8; rdp::HEADER_LEN + rdp::SYN_OPTIONS_LEN];
    let k = rdp::Header {
        flags: rdp::SYN,
        seq_nr: peer_iss,
        ack_nr: 0,
    }
    .encode(&body[..bn], &mut framed)
    .unwrap();
    syn.set_payload(&framed[..k]).unwrap();
    n.router.receive(syn, 0);

    let mut our_iss = 0u16;
    loop {
        match n.work(CLOCK) {
            csp::Routed::Respond { packet, .. } => {
                let p = n.take_forwarded(packet).expect("slot");
                p.with_payload(|b| {
                    if let Ok(h) = rdp::Header::decode(b) {
                        our_iss = h.seq_nr;
                    }
                });
                drop(p);
            }
            csp::Routed::Idle => break,
            _ => continue,
        }
    }

    // The handshake's third leg, then data — never read by the application.
    let send = |n: &mut csp::Node<'_, 8, 24, 264, 48, 32, 16>, h: rdp::Header| {
        let mut p = n.packet().expect("pool");
        p.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        let mut buf = [0u8; rdp::HEADER_LEN + 8];
        let payload: &[u8] = if h.flags == rdp::ACK && h.seq_nr != peer_iss {
            b"x"
        } else {
            &[]
        };
        let k = h.encode(payload, &mut buf).unwrap();
        p.set_payload(&buf[..k]).unwrap();
        n.router.receive(p, 0);
    };

    send(
        &mut n,
        rdp::Header {
            flags: rdp::ACK,
            seq_nr: peer_iss,
            ack_nr: our_iss,
        },
    );
    while !matches!(n.work(CLOCK), csp::Routed::Idle) {}

    let mut acks = 0u32;
    let mut first_unacked = 0u32;
    for i in 1..=delivered {
        send(
            &mut n,
            rdp::Header {
                flags: rdp::ACK,
                seq_nr: peer_iss.wrapping_add(i as u16),
                ack_nr: our_iss,
            },
        );
        let mut saw_ack = false;
        loop {
            match n.work(CLOCK) {
                csp::Routed::Respond { packet, .. } => {
                    let p = n.take_forwarded(packet).expect("slot");
                    p.with_payload(|b| {
                        if let Ok(h) = rdp::Header::decode(b) {
                            if h.flags & rdp::ACK != 0 {
                                saw_ack = true;
                            }
                        }
                    });
                    drop(p);
                }
                csp::Routed::Idle => break,
                _ => continue,
            }
        }
        if saw_ack {
            acks += 1;
        } else if first_unacked == 0 {
            first_unacked = i;
        }
    }

    serde_json::json!({ "acks": acks, "first_unacked": first_unacked })
}

/// The port opening an RDP connection: what `Node::connect(RDP_REQ)` puts on the wire.
///
/// The C's `csp_rdp_connect` emits the SYN and then blocks on a semaphore only its router
/// task can release, so what is comparable is the frame, not the call. Here the SYN is
/// queued and `work` reports it, which is the same frame reached without blocking.
///
/// The sequence number is absent from both sides on purpose: it is the ISN, and the port
/// deliberately does not reproduce the C's `rand_r(csp_get_ms())`. See the C test.
#[cfg(feature = "rdp")]
fn replay_rdp_client_connect() -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();

    let opened = n.connect(2, PEER, PORT, csp_core::security::opts::RDP_REQ, CLOCK);
    let ok = opened.is_ok();

    let mut syn_flags = 0u8;
    let mut syn_ack = 0u16;
    let mut option_bytes = 0usize;
    loop {
        match n.work(CLOCK) {
            csp::Routed::Respond { packet, .. } => {
                let p = n.take_forwarded(packet).expect("a live slot");
                p.with_payload(|b| {
                    if let Ok(h) = rdp::Header::decode(b) {
                        syn_flags = h.flags;
                        syn_ack = h.ack_nr;
                        option_bytes = b.len() - rdp::HEADER_LEN;
                    }
                });
                drop(p);
            }
            csp::Routed::Idle => break,
            _ => continue,
        }
    }
    assert!(ok, "connect(RDP_REQ) must open a connection");

    serde_json::json!({
        "syn_flags": syn_flags,
        "syn_ack": syn_ack,
        "option_bytes": option_bytes,
    })
}

fn replay_rdp_handshake(case: &str) -> serde_json::Value {
    use csp_core::rdp;

    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 12;
    const CLOCK: u32 = 100_000;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(PORT).unwrap();

    // The SYN: the option block, then the five-byte trailer. libcsp writes the RDP header
    // *after* the payload, so it is a trailer and not a header.
    let mut syn = n.packet().expect("the pool is empty");
    syn.set_id(Id {
        pri: 2,
        flags: csp_core::flags::RDP,
        src: PEER,
        dst: NODE,
        dport: PORT,
        sport: 40,
    });
    // The hostile case proposes the largest value every field can hold; everything else
    // uses the oracle's ordinary block.
    let hostile = case == "a_hostile_syn_cannot_suppress_acknowledgement";
    let opts = if hostile {
        rdp::SynOptions {
            window_size: u32::MAX,
            conn_timeout: u32::MAX,
            packet_timeout: 0,
            delayed_acks: true,
            ack_timeout: u32::MAX,
            ack_delay_count: u32::MAX,
        }
    } else {
        rdp::SynOptions {
            window_size: 4,
            conn_timeout: 20_000,
            packet_timeout: 1_000,
            delayed_acks: false,
            ack_timeout: 250,
            ack_delay_count: 2,
        }
    };
    let mut body = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let olen = opts.encode(&mut body).unwrap();
    let h = rdp::Header {
        flags: rdp::SYN,
        seq_nr: 1000,
        ack_nr: 0,
    };
    let mut framed = [0u8; rdp::SYN_OPTIONS_LEN + rdp::HEADER_LEN];
    let n_bytes = h.encode(&body[..olen], &mut framed).unwrap();
    syn.set_payload(&framed[..n_bytes]).unwrap();
    n.router.receive(syn, 0);

    // Drain the router and keep the control frames it produced.
    let mut replies: Vec<(u8, u16, u16, usize)> = Vec::new();
    loop {
        match n.work(CLOCK) {
            csp::Routed::Respond { packet, .. } => {
                let p = n
                    .take_forwarded(packet)
                    .expect("the router named a live slot");
                let (flags, seq, ack, plen) = p.with_payload(|b| {
                    let hh = rdp::Header::decode(b).unwrap();
                    (hh.flags, hh.seq_nr, hh.ack_nr, b.len() - rdp::HEADER_LEN)
                });
                replies.push((flags, seq, ack, plen));
                drop(p);
            }
            csp::Routed::Idle => break,
            _ => continue,
        }
    }

    if case == "a_syn_is_answered_with_syn_ack" {
        // Reported, not asserted. A port that answers no SYN has no connection to accept,
        // and `expect` here turned that into a panic naming no record -- so every mutation
        // that stopped a control frame reaching the wire was scored as noticed by nothing.
        let own_iss = n
            .accept()
            .and_then(|h| n.router.conns.rdp(h).ok().map(|r| r.snd_iss));
        let first = replies.first().copied().unwrap_or((0, 0, 0, 0));
        return serde_json::json!({
            "frames": replies.len(),
            "flags": first.0,
            "seq_is_own_iss": u8::from(own_iss.is_some_and(|iss| first.1 == iss)),
            "ack": first.2,
            "payload_len": first.3,
        });
    }

    // the_handshakes_final_ack_is_not_itself_answered: complete the handshake and count
    // what the third leg provokes, which must be nothing.
    // Same reason. The remaining cases all need the connection the handshake should have
    // opened; if it did not, say so as an observation. The key set differs from the C's,
    // which a `must_match` record reports as a divergence naming itself -- a panic did not.
    let Some(conn) = n.accept() else {
        return serde_json::json!({ "handshake_opened": 0 });
    };
    let Ok(own_iss) = n.router.conns.rdp(conn).map(|r| r.snd_iss) else {
        return serde_json::json!({ "handshake_opened": 0 });
    };

    // Placed before the final ACK: the C's scenario is a peer that never acknowledges,
    // so completing the handshake here would leave the connection Open and the
    // retransmit path -- which only applies while the SYN|ACK is outstanding -- unreached.
    if case == "an_unacknowledged_syn_ack_is_retransmitted_then_reset" {
        // The peer never acknowledges. `Router::tick` drives the RDP timers; every frame
        // it produces has to reach the caller or the peer hears nothing.
        // What the original SYN|ACK carried, before any repeat.
        let first = replies.first().copied().unwrap_or((0, 0, 0, 0));
        let (first_seq, first_ack) = (first.1, first.2);
        let mut frames = 0usize;
        let mut closed = false;
        let mut repeat: Option<(u8, u16, u16)> = None;
        let mut t = CLOCK;
        for _ in 0..1000 {
            t += 20;
            if n.tick(t, 1_000_000) > 0 {
                closed = true;
            }
            loop {
                match n.work(t) {
                    csp::Routed::Respond { packet, .. } => {
                        frames += 1;
                        let p = n.take_forwarded(packet).expect("a live slot");
                        if repeat.is_none() {
                            repeat = Some(p.with_payload(|b| {
                                let h = rdp::Header::decode(b).unwrap();
                                (h.flags, h.seq_nr, h.ack_nr)
                            }));
                        }
                        drop(p);
                    }
                    csp::Routed::Idle => break,
                    other => {
                        if let csp::Routed::Delivered { conn, .. } = other {
                            while let Ok(Some(p)) = n.read(conn) {
                                drop(p);
                            }
                        }
                    }
                }
            }
            if closed {
                break;
            }
        }
        let r = repeat.unwrap_or((0, 0, 0));
        return serde_json::json!({
            "more_than_one_frame": u8::from(frames > 1),
            "at_least_max_retransmits": u8::from(frames as u32 >= csp_core::rdp::MAX_RETRANSMITS),
            "connection_gone": u8::from(closed),
            "repeat_is_syn_ack": u8::from(r.0 == rdp::SYN | rdp::ACK),
            "repeat_seq_matches_first": u8::from(r.1 == first_seq),
            "repeat_ack_matches_first": u8::from(r.2 == first_ack),
        });
    }

    let mut ack = n.packet().expect("the pool is empty");
    ack.set_id(Id {
        pri: 2,
        flags: csp_core::flags::RDP,
        src: PEER,
        dst: NODE,
        dport: PORT,
        sport: 40,
    });
    let h = rdp::Header {
        flags: rdp::ACK,
        seq_nr: 1001,
        ack_nr: own_iss,
    };
    let mut framed = [0u8; rdp::HEADER_LEN];
    let n_bytes = h.encode(&[], &mut framed).unwrap();
    ack.set_payload(&framed[..n_bytes]).unwrap();
    n.router.receive(ack, 0);

    let mut after = 0usize;
    loop {
        match n.work(CLOCK) {
            csp::Routed::Respond { packet, .. } => {
                after += 1;
                drop(n.take_forwarded(packet));
            }
            csp::Routed::Idle => break,
            _ => continue,
        }
    }
    if case == "the_handshakes_final_ack_is_not_itself_answered" {
        return serde_json::json!({ "frames_after_final_ack": after });
    }

    if case == "a_multi_fragment_stream_reassembles_over_rdp" {
        // Two fragments, both accepted by RDP before the reader starts. The C's
        // `csp_sfp_recv_fp` reaches back into the connection queue mid-call for the second
        // one, so the port has to be driven the same way: the stream's source is the node
        // connection itself, not a fixed list.
        //
        // `Node::read` hands back a `Packet<'a, ..>` borrowed from the storage rather than
        // from `&mut self`, which is what makes a connection-backed source expressible at
        // all -- one tied to the `&mut Node` borrow could not outlive the call that
        // produced the first packet.
        for i in 0..2u32 {
            let body: &[u8] = if i == 0 { b"hello" } else { b"world" };
            let mut payload = body.to_vec();
            payload.extend_from_slice(&(i * 5).to_be_bytes());
            payload.extend_from_slice(&10u32.to_be_bytes());
            let dh = rdp::Header {
                flags: rdp::ACK,
                seq_nr: 1001 + i as u16,
                ack_nr: own_iss,
            };
            let mut framed = [0u8; 32];
            let k = dh.encode(&payload, &mut framed).unwrap();

            let mut d = n.packet().expect("the pool is empty");
            d.set_id(Id {
                pri: 2,
                flags: csp_core::flags::RDP | csp_core::flags::FRAG,
                src: PEER,
                dst: NODE,
                dport: PORT,
                sport: 40,
            });
            d.set_payload(&framed[..k]).unwrap();
            n.router.receive(d, 0);
        }

        // Drive the router to completion first, so both fragments are queued on the
        // connection before the reader runs -- the same ordering the C test sets up.
        let mut handle = None;
        loop {
            match n.work(CLOCK) {
                csp::Routed::Delivered { conn, .. } => handle = Some(conn),
                csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
                csp::Routed::Idle => break,
                _ => continue,
            }
        }
        let stalled = serde_json::json!({
            "sfp_result": -1, "reassembled_len": 0, "reassembled": "",
        });
        let Some(conn) = handle else { return stalled };
        let Ok(Some(first)) = n.read(conn) else {
            return stalled;
        };

        struct ConnSource<'s, 'a> {
            node: &'s mut csp::Node<'a, 8, 16, 264, 48, 32, 4>,
            conn: csp::conn::Handle,
        }
        impl<'a> csp::delivery::PacketSource<'a, 16, 264> for ConnSource<'_, 'a> {
            fn next_packet(&mut self, _timeout_ms: u32) -> Option<csp::Packet<'a, 16, 264>> {
                self.node.read(self.conn).ok().flatten()
            }
        }

        let mut src = ConnSource { node: &mut n, conn };
        return match csp::delivery::Delivery::classify(first, &mut src) {
            csp::delivery::Delivery::Stream(mut st) => {
                let mut buf = [0u8; 64];
                match st.read_to_slice(1000, &mut buf) {
                    Ok(got) => serde_json::json!({
                        "sfp_result": 0,
                        "reassembled_len": got,
                        "reassembled": buf[..got]
                            .iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    }),
                    Err(_) => serde_json::json!({
                        "sfp_result": -103, "reassembled_len": 0, "reassembled": "",
                    }),
                }
            }
            csp::delivery::Delivery::Datagram(_) => serde_json::json!({
                "sfp_result": -103, "reassembled_len": 0, "reassembled": "",
            }),
        };
    }

    if case == "a_stream_fragment_survives_being_carried_over_rdp" {
        // Both protocols append their header, and the send path stacks them:
        // `[body][sfp trailer][rdp trailer]`. The receiver strips from the outside in.
        let mut payload = b"stream".to_vec();
        payload.extend_from_slice(&0u32.to_be_bytes()); // sfp offset
        payload.extend_from_slice(&6u32.to_be_bytes()); // sfp totalsize
        let dh = rdp::Header {
            flags: rdp::ACK,
            seq_nr: 1001,
            ack_nr: own_iss,
        };
        let mut framed = [0u8; 32];
        let k = dh.encode(&payload, &mut framed).unwrap();

        let mut d = n.packet().expect("the pool is empty");
        d.set_id(Id {
            pri: 2,
            flags: csp_core::flags::RDP | csp_core::flags::FRAG,
            src: PEER,
            dst: NODE,
            dport: PORT,
            sport: 40,
        });
        d.set_payload(&framed[..k]).unwrap();
        n.router.receive(d, 0);

        let mut handed: Option<csp::Packet<'_, 16, 264>> = None;
        loop {
            match n.work(CLOCK) {
                csp::Routed::Delivered { conn, .. } => {
                    if let Ok(Some(p)) = n.read(conn) {
                        handed = Some(p);
                    }
                }
                csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
                csp::Routed::Idle => break,
                _ => continue,
            }
        }

        let Some(pkt) = handed else {
            return serde_json::json!({
                "after_rdp_len": 0, "sfp_result": -1,
                "reassembled_len": 0, "reassembled": "",
            });
        };
        let after_rdp_len = pkt.with_payload(|d| d.len());

        // Hand it to the stream reader, which is what the C's csp_sfp_recv_fp does next.
        let mut src = NoMore;
        return match csp::delivery::Delivery::classify(pkt, &mut src) {
            csp::delivery::Delivery::Stream(mut st) => {
                let mut buf = [0u8; 64];
                match st.read_to_slice(1000, &mut buf) {
                    Ok(got) => serde_json::json!({
                        "after_rdp_len": after_rdp_len,
                        "sfp_result": 0,
                        "reassembled_len": got,
                        "reassembled": buf[..got].iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    }),
                    Err(_) => serde_json::json!({
                        "after_rdp_len": after_rdp_len, "sfp_result": -103,
                        "reassembled_len": 0, "reassembled": "",
                    }),
                }
            }
            csp::delivery::Delivery::Datagram(_) => serde_json::json!({
                "after_rdp_len": after_rdp_len, "sfp_result": -103,
                "reassembled_len": 0, "reassembled": "",
            }),
        };
    }

    if hostile {
        // Twelve data packets. With the proposal unclamped the node would wait four
        // billion before acknowledging, so the peer retransmits forever -- the clamp is
        // only visible as acks reaching the wire at all.
        let mut acks = 0usize;
        for i in 1..=12u16 {
            let mut d = n.packet().expect("the pool is empty");
            d.set_id(Id {
                pri: 2,
                flags: csp_core::flags::RDP,
                src: PEER,
                dst: NODE,
                dport: PORT,
                sport: 40,
            });
            let dh = rdp::Header {
                flags: rdp::ACK,
                seq_nr: 1000 + i,
                ack_nr: own_iss,
            };
            let mut framed = [0u8; 1 + rdp::HEADER_LEN];
            let k = dh.encode(b"x", &mut framed).unwrap();
            d.set_payload(&framed[..k]).unwrap();
            n.router.receive(d, 0);
            loop {
                match n.work(CLOCK) {
                    csp::Routed::Respond { packet, .. } => {
                        acks += 1;
                        drop(n.take_forwarded(packet));
                    }
                    csp::Routed::Delivered { conn, .. } => {
                        while let Ok(Some(p)) = n.read(conn) {
                            drop(p);
                        }
                    }
                    csp::Routed::Idle => break,
                    _ => continue,
                }
            }
        }
        let c = n.router.conns.rdp(conn).unwrap();
        return serde_json::json!({
            "acks": acks,
            "clamped_window": c.opts.window_size,
            "clamped_ack_delay_count": c.opts.ack_delay_count,
        });
    }

    if case == "without_delayed_acks_every_packet_is_acknowledged" {
        // Acknowledgements counted as frames leaving a node, which is the only place they
        // are observable. This record used to be replayed by setting `rcv_cur` by hand and
        // calling `poll_ack` -- so it measured the state machine, and the node delivered
        // RDP data without acknowledging any of it while this stayed green.
        let mut acks = 0usize;
        let mut acked: Vec<u16> = Vec::new();
        for i in 1..=3u16 {
            let mut d = n.packet().expect("the pool is empty");
            d.set_id(Id {
                pri: 2,
                flags: csp_core::flags::RDP,
                src: PEER,
                dst: NODE,
                dport: PORT,
                sport: 40,
            });
            let dh = rdp::Header {
                flags: rdp::ACK,
                seq_nr: 1000 + i,
                ack_nr: own_iss,
            };
            let mut framed = [0u8; 1 + rdp::HEADER_LEN];
            let k = dh.encode(b"x", &mut framed).unwrap();
            d.set_payload(&framed[..k]).unwrap();
            n.router.receive(d, 0);

            loop {
                match n.work(CLOCK) {
                    csp::Routed::Respond { packet, .. } => {
                        acks += 1;
                        let p = n.take_forwarded(packet).expect("a live slot");
                        acked.push(p.with_payload(|b| rdp::Header::decode(b).unwrap().ack_nr));
                        drop(p);
                    }
                    csp::Routed::Delivered { conn, .. } => {
                        while let Ok(Some(p)) = n.read(conn) {
                            drop(p);
                        }
                    }
                    csp::Routed::Idle => break,
                    _ => continue,
                }
            }
        }
        return serde_json::json!({ "acks": acks, "acked": acked });
    }

    // data_reaches_the_application_without_the_rdp_trailer: one data packet on the now-open
    // connection, read back the way an application would.
    let mut data = n.packet().expect("the pool is empty");
    data.set_id(Id {
        pri: 2,
        flags: csp_core::flags::RDP,
        src: PEER,
        dst: NODE,
        dport: PORT,
        sport: 40,
    });
    let dh = rdp::Header {
        flags: rdp::ACK,
        seq_nr: 1001,
        ack_nr: own_iss,
    };
    let mut framed = [0u8; 5 + rdp::HEADER_LEN];
    let n_bytes = dh.encode(b"hello", &mut framed).unwrap();
    data.set_payload(&framed[..n_bytes]).unwrap();
    n.router.receive(data, 0);

    let mut delivered: Option<Vec<u8>> = None;
    loop {
        match n.work(CLOCK) {
            csp::Routed::Delivered { conn, .. } => {
                if let Ok(Some(p)) = n.read(conn) {
                    delivered = Some(p.with_payload(<[u8]>::to_vec));
                }
            }
            csp::Routed::Respond { packet, .. } => drop(n.take_forwarded(packet)),
            csp::Routed::Idle => break,
            _ => continue,
        }
    }
    let body = delivered.unwrap_or_default();
    serde_json::json!({
        "delivered_len": body.len(),
        "delivered": body.iter().map(|b| format!("{b:02x}")).collect::<String>(),
    })
}

/// The route-table text format, replayed the way the C measures it: load a string, then
/// ask where a packet for the address goes.
///
/// `rtable` was the one module with neither a golden vector nor a corpus record. Its
/// parser is the only way a route reaches a flying node from the ground.
/// A CMP request served by a real `Node`: routed to a bound port 0, read by the
/// application, answered with `respond_cmp`.
///
/// The other CMP records replay `respond_cmp` as a function, which is what let the whole
/// server go missing once already -- the C routes every one of its CMP cases through
/// `csp_route_work` and a bound socket. This drives the same path the C does, so "the
/// application can reach the server at all" is measured and not assumed.
#[cfg(feature = "cmp")]
/// A fragmented packet delivered to a node whose application reads with the plain datagram
/// call. `csp_route.c` never looks at `CSP_FFRAG` -- only `csp_sfp.c` does -- so the C hands
/// the reader the body with the SFP header still attached. This drives the port's real
/// router and its real `read`, so what it reports is what an application would get.
fn replay_fragment_read_as_a_datagram(input: &SfpInput) -> serde_json::Value {
    const NODE: u16 = 10;
    const PEER: u16 = 11;
    const PORT: u8 = 10;

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("INGRESS", NODE, 12, true).unwrap();
    n.bind(PORT).unwrap();

    let body = unhex(&input.body);
    let mut payload = body.clone();
    if input.frag_flag {
        payload.extend_from_slice(&input.offset.to_be_bytes());
        payload.extend_from_slice(&input.totalsize.to_be_bytes());
    }

    let mut p = n.packet().expect("the pool is empty");
    p.set_id(Id {
        pri: 2,
        flags: if input.frag_flag {
            csp_core::flags::FRAG
        } else {
            0
        },
        src: PEER,
        dst: NODE,
        dport: PORT,
        sport: 40,
    });
    p.set_payload(&payload).unwrap();
    n.router.receive(p, 0);

    let mut delivered = 0u32;
    let mut delivered_len = 0usize;
    let mut delivered_body = String::new();
    let mut frag_flag_visible = 0u32;

    loop {
        match n.work(0) {
            csp::Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = n.read(conn) {
                    delivered += 1;
                    if pkt.id().is_fragment() {
                        frag_flag_visible = 1;
                    }
                    let got = pkt.with_payload(<[u8]>::to_vec);
                    if delivered_body.is_empty() {
                        delivered_len = got.len();
                        delivered_body = tohex(&got);
                    }
                }
                let _ = n.close(conn);
            }
            csp::Routed::Idle => break,
            _ => {}
        }
    }

    serde_json::json!({
        "delivered": delivered,
        "delivered_len": delivered_len,
        "delivered_body": delivered_body,
        "frag_flag_visible": frag_flag_visible,
    })
}

fn replay_cmp_through_a_node() -> serde_json::Value {
    const NODE: u16 = 10;
    const PEER: u16 = 11;

    struct NoHooks;
    impl csp::hooks::Hooks<16, 264> for NoHooks {}

    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(NODE));
    n.ifaces.add("test", NODE, 14, true).unwrap();
    n.bind(csp_core::ports::CMP).unwrap();

    // Padded to the full reply size, which is the smallest request the C answers.
    let mut req = [0u8; 256];
    let k = csp::client::cmp_request(csp_core::cmp::code::IDENT, &[], &mut req).unwrap();
    let mut p = n.packet().expect("the pool is empty");
    p.set_id(Id {
        pri: 2,
        flags: 0,
        src: PEER,
        dst: NODE,
        dport: csp_core::ports::CMP,
        sport: 40,
    });
    p.set_payload(&req[..k]).unwrap();
    n.router.receive(p, 0);

    let identity = oracle_identity();
    let mut replies = 0usize;
    let mut reply_len = 0usize;
    let (mut reply_type, mut reply_code) = (-1i32, -1i32);

    loop {
        match n.work(0) {
            csp::Routed::Delivered { conn, .. } => {
                while let Ok(Some(pkt)) = n.read(conn) {
                    let got = pkt.with_payload(<[u8]>::to_vec);
                    let mut out = [0u8; 256];
                    let mut hooks = NoHooks;
                    if let Ok(q) = csp_core::cmp::parse_request(&got) {
                        if let Ok(Some(len)) = csp::service::respond_cmp(
                            q,
                            &identity,
                            Version::V2,
                            &mut hooks,
                            &mut out,
                        ) {
                            replies += 1;
                            reply_len = len;
                            reply_type = out[0] as i32;
                            reply_code = out[1] as i32;
                        }
                    }
                    drop(pkt);
                }
            }
            csp::Routed::Idle => break,
            _ => continue,
        }
    }

    serde_json::json!({
        "replies": replies,
        "reply_len": reply_len,
        "reply_type": reply_type,
        "reply_code": reply_code,
    })
}

/// Which broadcast addresses a node treats as its own, and what happens to the rest.
///
/// The C's condition names the **ingress** interface: `csp_id_is_broadcast(dst,
/// input.iface)`. A broadcast for a different subnet is therefore not for this node and is
/// relayed. Driven through a real `Router` so both halves are visible -- what the
/// application receives, and how many frames leave.
fn replay_broadcast(case: &str) -> serde_json::Value {
    const LOCAL: u16 = 10;
    const NETMASK: u16 = 12;

    let dst: u16 = match case {
        "the_ingress_subnets_broadcast_is_delivered_and_not_relayed" => 11,
        "the_all_ones_address_is_delivered_and_not_relayed" => 16383,
        "another_subnets_broadcast_is_relayed_not_delivered" => 43,
        other => panic!("no broadcast replay for {other}"),
    };

    type P = Pool<16, 264>;
    type R = Router<8, 16, 48, 32>;
    let pool = P::new();
    let mut r = R::new(LOCAL, Version::V2);
    r.bind(TEST_PORT).unwrap();
    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", LOCAL, NETMASK, true).unwrap();
        l.add("OTHER", 40, NETMASK, false).unwrap();
        l
    };

    let mut p = pool.acquire(0).unwrap();
    p.set_id(Id {
        pri: 2,
        flags: 0,
        src: 11,
        dst,
        dport: TEST_PORT,
        sport: 40,
    });
    p.set_payload(b"hi").unwrap();
    r.receive(p, 0);

    let mut delivered = 0;
    let mut frames_out = 0;
    loop {
        match r.work(&pool, &mut ifaces, 0) {
            Routed::Delivered { conn, .. } => {
                delivered = 1;
                if let Ok(Some(slot)) = r.conns.dequeue_rx(conn) {
                    drop(pool.from_index(slot));
                }
            }
            Routed::Forwarded { packet, .. } | Routed::Respond { packet, .. } => {
                frames_out += 1;
                drop(pool.from_index(packet));
            }
            Routed::Idle => break,
            _ => continue,
        }
    }

    serde_json::json!({ "delivered": delivered, "frames_out": frames_out })
}

/// Per-interface counters after traffic, read the way `IF_STATS` reads them.
///
/// `csp_route_work` increments `rx`/`rxbytes` for every packet it handles and `drop` for
/// one it deduplicates. These are the *router's* counters, not the driver's: a driver only
/// sees frames it handed up, while the drop happens after the packet has left it. Nothing
/// wrote `IfList::Entry::stats`, so `IF_STATS` reported a permanent zero -- which an
/// operator reads as "this link is idle", not as "this node does not count".
///
/// The oracle sends three six-byte packets and then the `IF_STATS` request itself, which
/// the router also counts: four packets, and 3*6 + 13 = 31 bytes.
fn replay_if_stats_counters() -> serde_json::Value {
    const LOCAL: u16 = 10;
    const PEER: u16 = 11;

    type P = Pool<16, 264>;
    type R = Router<8, 16, 48, 32>;
    let pool = P::new();
    let mut r = R::new(LOCAL, Version::V2);
    r.bind(TEST_PORT).unwrap();
    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", LOCAL, 12, true).unwrap();
        l
    };

    let mut feed = |r: &mut R, payload: &[u8], dport: u8| {
        let mut p = pool.acquire(0).unwrap();
        p.set_id(Id {
            pri: 2,
            flags: 0,
            src: PEER,
            dst: LOCAL,
            dport,
            sport: 40,
        });
        p.set_payload(payload).unwrap();
        r.receive(p, 0);
        loop {
            match r.work(&pool, &mut ifaces, 0) {
                csp::Routed::Idle => break,
                csp::Routed::Forwarded { packet, .. } | csp::Routed::Respond { packet, .. } => {
                    drop(pool.from_index(packet));
                }
                csp::Routed::Delivered { conn, .. } => {
                    if let Ok(Some(slot)) = r.conns.dequeue_rx(conn) {
                        drop(pool.from_index(slot));
                    }
                }
                _ => continue,
            }
        }
    };

    for _ in 0..3 {
        feed(&mut r, b"onward", TEST_PORT);
    }
    // The IF_STATS request: 2-byte CMP header plus the 11-byte interface name.
    feed(&mut r, &[0u8; 13], csp_core::ports::CMP);

    let e = ifaces.get(0).expect("INGRESS is registered");
    serde_json::json!({
        "rx": e.stats.rx,
        "rxbytes": e.stats.rxbytes,
        "drop": e.stats.drop,
    })
}

fn replay_rtable(case: &str) -> serde_json::Value {
    use csp_core::rtable;

    // Load a table string into a real table, applying entries as they parse -- the C's
    // parser calls `csp_rtable_set` per entry with no rollback, so a later failure leaves
    // the earlier ones installed.
    fn load(text: &str) -> (i32, rtable::Table<8>) {
        let mut t = rtable::Table::<8>::new(Version::V2);
        let host_bits = Version::V2.host_bits() as u16;
        let mut applied = 0i32;
        // No range checks here: `parse` makes them, as `csp_rtable_stdio.c:44` does. They
        // used to live in this closure, so `"3000/99 LINK_A"` was refused by the *test*
        // while the port accepted it and `set` silently clamped the netmask -- the record
        // passed and the divergence was invisible.
        //
        // The interface lookup stays with the caller: `parse` has no interface list, which
        // is the sans-io boundary. Returning `Err` from the callback aborts the whole
        // string, which is what the C does when `csp_iflist_get_by_name` returns NULL.
        let res = rtable::parse(text, Version::V2, |r| {
            if r.iface != "LINK_A" {
                return Err(csp_core::Error::InvalidRoute {
                    reason: csp_core::RouteError::MissingInterface,
                });
            }
            t.set(
                r.address,
                r.netmask.unwrap_or(host_bits),
                0,
                r.via.unwrap_or(rtable::NO_VIA),
            )?;
            applied += 1;
            Ok(())
        });
        match res {
            // The C returns the number of valid entries.
            Ok(n) => (n as i32, t),
            // ...and CSP_ERR_INVAL, which is -2, for a refused one.
            Err(_) => (-2, t),
        }
    }

    // Does a packet for `dst` leave by the routed interface? One frame or none, which is
    // what the C's `goes_by` reports.
    let frames = |t: &rtable::Table<8>, dst: u16| -> usize {
        // 3000 and 3001 are in no interface's subnet, so only the table can carry them.
        usize::from(t.find(dst).is_some())
    };

    match case {
        "a_netmask_wider_than_the_address_space_is_refused_by_the_parser" => {
            let (res, t) = load("3000/99 LINK_A");
            serde_json::json!({ "load_result": res, "frames": frames(&t, 3000) })
        }
        "the_same_netmask_set_directly_is_clamped_not_refused" => {
            let mut t = rtable::Table::<8>::new(Version::V2);
            let set_result = -i32::from(t.set(3000, 99, 0, rtable::NO_VIA).is_err());
            serde_json::json!({ "set_result": set_result, "frames": frames(&t, 3000) })
        }
        "a_refused_table_string_keeps_the_entries_before_the_bad_one" => {
            let (res, t) = load("3000 LINK_A,3001/99 LINK_A");
            serde_json::json!({
                "load_result": res,
                "first_entry_installed": frames(&t, 3000),
            })
        }
        "a_next_hop_survives_the_text_format" => {
            let (res, t) = load("3000 LINK_A 42");
            serde_json::json!({
                "load_result": res,
                "via_on_tx": t.find(3000).map(|r| r.via).unwrap_or(0),
            })
        }
        "a_route_without_a_next_hop_sends_direct" => {
            let (res, t) = load("3000 LINK_A");
            serde_json::json!({
                "load_result": res,
                "via_on_tx": t.find(3000).map(|r| r.via).unwrap_or(0),
            })
        }
        "an_address_outside_the_address_space_is_refused" => {
            let (res, t) = load("20000 LINK_A");
            serde_json::json!({ "load_result": res, "frames": frames(&t, 20000) })
        }
        "a_one_character_entry_ends_the_parse_and_still_reports_success" => {
            let (res, t) = load("3000 LINK_A,x,3001 LINK_A");
            serde_json::json!({
                "load_result": res,
                "routes_after_the_short_token": frames(&t, 3001),
            })
        }
        other => panic!("no rtable replay for {other}"),
    }
}

/// An application send, driven through `Node::sendto` the way the C drives `csp_sendto`.
///
/// This used to call `Node::resolve` and report `"buffers_lost": 0` as a literal. Two
/// things were wrong with that: nothing was ever sent, so the send path was not exercised
/// at all -- only the resolver -- and the buffer figure the C measures with
/// `before - csp_buffer_remaining()` was a constant that could not move however badly the
/// port leaked.
fn replay_node_send(case: &str) -> serde_json::Value {
    type S = csp::CspStorage<8, 16, 264, 48, 32>;
    let storage = S::new();
    let mut n: csp::Node<'_, 8, 16, 264, 48, 32, 4> =
        csp::Node::new(&storage, csp::Config::new(Version::V2).address(9999));
    n.ifaces.add("LINK_A", 8, 12, false).unwrap();

    // LINK_A is 8/12, so it owns 8..11 and 11 is its broadcast address.
    let dst = match case {
        "a_local_subnet_beats_the_default_interface" => {
            n.ifaces.add("DEFAULT", 40, 12, true).unwrap();
            10
        }
        "an_application_send_to_a_broadcast_is_rewritten_too" => 11,
        other => panic!("no node-send replay for {other}"),
    };

    let before = n.buffers_free();

    // Every destination, as `csp_send_direct` fans out -- and then the actual send, so a
    // buffer the send path fails to release shows up below.
    let dests = n.resolve(dst, None);
    let (frames, left_by, dst_on_wire) = match dests {
        Ok(d) => (
            d.len(),
            d.as_slice()
                .iter()
                .map(|e| {
                    n.ifaces
                        .get(e.iface)
                        .map(|i| i.name.to_lowercase())
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>(),
            // The destination each frame carries, read off the resolution rather than
            // assumed from what was asked for.
            d.as_slice().iter().map(|e| e.dst).collect::<Vec<_>>(),
        ),
        Err(_) => (0, Vec::new(), Vec::new()),
    };

    let p = n.packet().expect("the pool is empty");
    let out = n.sendto(2, dst, 12, 40, 0, p).expect("sendto");
    // The caller owns the packet whatever the outcome; dropping it is what an interface
    // driver does once the frame is on the wire.
    drop(out.into_packet());

    serde_json::json!({
        "frames": frames,
        "left_by": left_by,
        "dst_on_wire": dst_on_wire,
        "buffers_lost": before as i64 - n.buffers_free() as i64,
    })
}

fn replay_route(case: &str) -> serde_json::Value {
    type P = Pool<16, 264>;
    type R = Router<8, 16, 48, 32>;

    const INGRESS: u16 = 40;
    const LINK_A: u16 = 8;
    const LINK_B: u16 = 9;
    const TARGET: u16 = 10;

    // LINK_A is 8/12, so with 14 host bits it owns 8..11 and 11 is its broadcast address.
    const LINK_A_BROADCAST: u16 = 11;

    let (two_links, defaults, dst) = match case {
        "one_owning_link_sends_one_frame" => (false, false, TARGET),
        "two_owning_links_send_two_frames" => (true, false, TARGET),
        "two_default_interfaces_send_two_frames" => (true, true, 3000),
        "a_routed_broadcast_leaves_as_the_local_broadcast" => (false, false, LINK_A_BROADCAST),
        "an_ordinary_destination_is_not_rewritten" => (false, false, TARGET),
        "a_broadcast_rewrite_carries_to_the_other_interface" => (true, false, LINK_A_BROADCAST),
        // Reached through the routing table, not a subnet: no interface owns 3000.
        "a_table_routed_destination_leaves_unchanged" => (false, false, 3000),
        "split_horizon_vetoes_a_second_link_on_the_same_subnet" => (true, false, TARGET),
        other => panic!("no route replay for {other}"),
    };

    let pool = P::new();
    let mut r = R::new(9999, Version::V2); // an address no interface has
    let mut ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", INGRESS, 12, false).unwrap();
        l.add("LINK_A", LINK_A, 12, defaults).unwrap();
        if case == "a_broadcast_rewrite_carries_to_the_other_interface" {
            // Same address, one bit wider: owns 8..15, so 11 is inside it but is not its
            // broadcast.
            l.add("LINK_C", LINK_A, 11, false).unwrap();
        } else if two_links {
            let b = if defaults { 200 } else { LINK_B };
            l.add("LINK_B", b, 12, defaults).unwrap();
        }
        l
    };

    if case == "a_table_routed_destination_leaves_unchanged" {
        let a = ifaces.find_by_name("LINK_A").expect("LINK_A is registered");
        r.routes
            .set(
                3000,
                Version::V2.host_bits() as u16,
                a,
                csp_core::rtable::NO_VIA,
            )
            .unwrap();
    }

    let before = pool.available();
    let mut p = pool.acquire(0).unwrap();
    p.set_id(Id {
        pri: 2,
        flags: 0,
        src: PEER_ADDR,
        dst,
        dport: TEST_PORT,
        sport: 40,
    });
    p.set_payload(b"onward").unwrap();
    // Arrives on LINK_A (index 1) for the split-horizon case, INGRESS (0) otherwise.
    let ingress = u8::from(case == "split_horizon_vetoes_a_second_link_on_the_same_subnet");
    r.receive(p, ingress);

    // `work` is a step: drain it until it stops producing, so a router that fans out over
    // several calls is counted the same as one that reports them together.
    let mut left_by: Vec<String> = Vec::new();
    let mut dst_on_wire: Vec<u16> = Vec::new();
    loop {
        match r.work(&pool, &mut ifaces, 0) {
            Routed::Forwarded { iface, packet, .. } => {
                let name = ifaces
                    .get(iface)
                    .map(|e| e.name.to_lowercase())
                    .unwrap_or_default();
                left_by.push(name);
                let fwd = pool
                    .from_index(packet)
                    .expect("the router named a live slot");
                // The destination the frame actually carries, read off the packet rather
                // than assumed from what was sent -- the two differ for a routed broadcast.
                dst_on_wire.push(fwd.id().dst);
                drop(fwd);
            }
            Routed::Idle => break,
            _ => break,
        }
    }

    // The two broadcast cases look at the destination field; the rest look at fan-out.
    serde_json::json!({
        "frames": left_by.len(),
        "left_by": left_by,
        "dst_on_wire": dst_on_wire,
        "buffers_lost": before as i64 - pool.available() as i64,
    })
}

// --- the run --------------------------------------------------------------------------

/// Replay one record. `None` means the suite is `c_only` and there is nothing to run.
fn replay(rec: &Record) -> Option<(serde_json::Value, String)> {
    match rec.suite.as_str() {
        "cmp" if rec.case == "the_minimum_request_length_is_the_whole_reply" => {
            // This record is the measured contract itself rather than one exchange: the
            // smallest request the C will answer, per code. The port's table has to agree
            // with it, because `cmp_request` pads to it and `parse_request` refuses below
            // it — one constant standing in for the C's per-handler length checks.
            let got = serde_json::json!({
                "ident_min": csp_core::cmp::request_len(csp_core::cmp::code::IDENT),
                "clock_min": csp_core::cmp::request_len(csp_core::cmp::code::CLOCK),
            });
            Some((got, "cmp::request_len".to_string()))
        }
        // The header round-trip records the packed bytes rather than an rx outcome.
        "eth" if rec.case == "the_header_round_trips" => {
            let h = csp_core::eth::Header {
                dst_mac: [0; 6],
                src_mac: [0; 6],
                // csp_eth_pack_header leaves the ethertype alone -- csp_eth_tx writes it
                // separately -- so the C's recorded bytes have zero there.
                ethertype: 0,
                packet_id: 0x1234,
                src_addr: 0x0abc,
                seg_size: 1400,
                packet_length: 2000,
            };
            let mut out = [0u8; 64];
            let n = h.encode(&mut out).unwrap();
            let hex: String = out[..n].iter().map(|b| format!("{b:02x}")).collect();
            Some((
                serde_json::json!({ "header": hex }),
                "pack_header".to_string(),
            ))
        }
        "eth" => {
            let input: EthInput = serde_json::from_value(rec.input.clone()).unwrap();
            let got = replay_eth(&input);
            Some((
                serde_json::to_value(EthJson::from(got)).unwrap(),
                format!("{} frame(s)", input.frames.len()),
            ))
        }
        // The C reports a corrupt fragment and a wrong-shape delivery with the same code.
        // The port's answer to the same pair is what this compares — and it is different,
        // which is the whole point of the divergence recorded beside it.
        // The fragment MTU per option set. Measured from `csp_sfp_opts_max_mtu` rather
        // than restated: the four values `sfp::max_mtu_matches_the_c` asserts carried a
        // comment claiming they came from the C, which is a provenance claim and not a
        // measurement. They did; this is what checks that they still do.
        "sfp" if rec.case == "the_fragment_mtu_for_each_option_set" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct MtuInput {
                buffer_size: usize,
            }
            let input: MtuInput = serde_json::from_value(rec.input.clone()).unwrap();
            // The oracle's `CSP_BUFFER_SIZE` is the payload area; this port sizes a buffer
            // as payload plus `PADDING` scratch, so the comparable figure is BUFSZ - PADDING.
            assert_eq!(
                input.buffer_size, 256,
                "the oracle's buffer size changed; the port's equivalent is BUFSZ - PADDING"
            );
            let b = input.buffer_size;
            use csp_core::security::opts;
            use csp_core::sfp::max_mtu;
            Some((
                serde_json::json!({
                    "plain": max_mtu(b, 0),
                    "rdp": max_mtu(b, opts::RDP_REQ),
                    "crc32": max_mtu(b, opts::CRC32_REQ),
                    "hmac": max_mtu(b, opts::HMAC_REQ),
                    "all_three": max_mtu(b, opts::RDP_REQ | opts::CRC32_REQ | opts::HMAC_REQ),
                }),
                "sfp::max_mtu".to_string(),
            ))
        }
        "sfp" if rec.case == "a_corrupt_fragment_reports_the_same_error_as_a_wrong_shape" => {
            let corrupt = replay_sfp(&SfpInput {
                frag_flag: true,
                body: "68656c6c6f".into(),
                offset: 99,
                totalsize: 5,
            });
            let wrong_shape = replay_sfp(&SfpInput {
                frag_flag: false,
                body: "68656c6c6f".into(),
                offset: 0,
                totalsize: 0,
            });
            let corrupt_ret = corrupt["ret"].as_i64().unwrap();
            // A wrong shape is not an error here at all: the datagram comes back whole, so
            // this reports success where the C reports -103.
            let wrong_shape_ret = if wrong_shape["recovered"].as_i64().unwrap() > 0 {
                0
            } else {
                wrong_shape["ret"].as_i64().unwrap()
            };
            Some((
                serde_json::json!({
                    "corrupt_ret": corrupt_ret,
                    "wrong_shape_ret": wrong_shape_ret,
                    "indistinguishable": corrupt_ret == wrong_shape_ret,
                }),
                "corrupt vs wrong-shape".to_string(),
            ))
        }
        "sfp" if rec.case == "a_fragment_read_as_a_datagram_keeps_the_sfp_header" => {
            let input: SfpInput = serde_json::from_value(rec.input.clone()).unwrap();
            Some((
                replay_fragment_read_as_a_datagram(&input),
                "through a Node, read as a datagram".to_string(),
            ))
        }
        // The multi-fragment cases carry a `fragments` array instead of one flat frame.
        "sfp" if rec.input.get("fragments").is_some() => {
            let input: SfpMultiInput = serde_json::from_value(rec.input.clone()).unwrap();
            Some((
                replay_sfp_multi(&input),
                format!("{} fragment(s)", input.fragments.len()),
            ))
        }
        "sfp" => {
            let input: SfpInput = serde_json::from_value(rec.input.clone()).unwrap();
            Some((replay_sfp(&input), format!("{input:?}")))
        }
        "cmp" if rec.case == "if_stats_counters_after_three_packets" => Some((
            replay_if_stats_counters(),
            "per-interface counters".to_string(),
        )),
        #[cfg(feature = "cmp")]
        "cmp" if rec.case == "a_full_size_ident_request_is_answered" => {
            Some((replay_cmp_through_a_node(), "through a Node".to_string()))
        }
        "cmp" if rec.case == "an_ident_reply_carries_the_configured_identity" => {
            // The identity fields only. The C's `date`/`time` come from __DATE__/__TIME__
            // and the trace stops before them, so this compares exactly the part a node
            // is configured with -- and it is the only record that looks at an IDENT
            // reply's *contents* rather than its length.
            let input: CmpInput = serde_json::from_value(rec.input.clone()).unwrap();
            let req = unhex(&input.request);
            let query = csp_core::cmp::parse_request(&req).expect("the C answered it");
            let identity = oracle_identity();
            let mut out = [0u8; 256];
            let mut hooks = OracleNode {
                clock_accepts: true,
            };
            let n = csp::service::respond_cmp(query, &identity, Version::V1, &mut hooks, &mut out)
                .unwrap()
                .expect("IDENT is answered");
            assert!(n >= IDENT_PREFIX_LEN);
            let hex: String = out[..IDENT_PREFIX_LEN]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            Some((
                serde_json::json!({ "identity": hex }),
                "ident reply".to_string(),
            ))
        }
        "cmp" if rec.case == "the_peek_tail_when_the_request_did_not_cover_it" => {
            // The C declares a PEEK reply three bytes longer than the data it wrote. What
            // is in them is a property of the *build*, which is why `buffer_zero_clear`
            // rides along as an input: with the pool cleared they are zeros, without it
            // they are the previous packet's bytes (`just ctest-noclear` shows that).
            //
            // The port zeroes them unconditionally, so it matches a cleared-pool C and
            // deliberately does not match an uncleared one. Asserting that here means a
            // corpus regenerated from the other build fails loudly instead of quietly
            // comparing against the wrong condition.
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct TailInput {
                request: String,
                buffer_zero_clear: u8,
            }
            let input: TailInput = serde_json::from_value(rec.input.clone()).unwrap();
            assert_eq!(
                input.buffer_zero_clear, 1,
                "corpus was generated from an uncleared-pool build; the port zeroes the \
                 tail unconditionally, so this record needs the `diverges` verdict"
            );

            let req = unhex(&input.request);
            let len = req[6] as usize;
            let mut out = [0u8; 64];
            let src = peek_window(
                u32::from_be_bytes([req[2], req[3], req[4], req[5]]) as u64,
                len,
                false,
            )
            .unwrap();
            let n = csp_core::cmp::Peek {
                addr: 0,
                len: len as u8,
                data: &src,
            }
            .encode(
                csp_core::cmp::Header {
                    kind: csp_core::cmp::REPLY,
                    code: csp_core::cmp::code::PEEK,
                },
                &mut out,
            )
            .unwrap();

            let tail: String = out[csp_core::cmp::Peek::HEADER_LEN + len..n]
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            let got = serde_json::json!({ "reply_len": n, "tail": tail });
            Some((got, format!("peek len {len}")))
        }
        "cmp" => {
            let input: CmpInput = serde_json::from_value(rec.input.clone()).unwrap();
            let got = replay_cmp(&input);
            Some((
                serde_json::to_value(CmpJson::from(got)).unwrap(),
                format!("request {} bytes", input.request.len() / 2),
            ))
        }
        // How many times the application is offered a connection it already holds.
        "conn"
            if matches!(
                rec.case.as_str(),
                "the_ingress_subnets_broadcast_is_delivered_and_not_relayed"
                    | "the_all_ones_address_is_delivered_and_not_relayed"
                    | "another_subnets_broadcast_is_relayed_not_delivered"
            ) =>
        {
            Some((replay_broadcast(&rec.case), rec.case.clone()))
        }
        "conn" if rec.case == "a_reply_reaches_the_connection_that_asked_for_it" => Some((
            replay_reply_to_a_connect(),
            "a reply on an unbound ephemeral port".to_string(),
        )),
        "conn" if rec.case == "a_connection_is_offered_to_the_application_only_once" => {
            let input: ConnInput = serde_json::from_value(rec.input.clone()).unwrap();
            type P = Pool<16, 264>;
            type R = Router<8, 16, 48, 32>;
            let pool = P::new();
            let mut r = R::new(LOCAL_ADDR, Version::V2);
            r.bind(TEST_PORT).unwrap();
            let mut ifaces = {
                let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
                l.add("INGRESS", LOCAL_ADDR, 12, false).unwrap();
                l
            };
            let mut deliver = |r: &mut R| {
                let mut p = pool.acquire(0).unwrap();
                p.set_id(Id {
                    pri: 2,
                    flags: 0,
                    src: 11,
                    dst: LOCAL_ADDR,
                    dport: TEST_PORT,
                    sport: 40,
                });
                p.set_payload(b"hi").unwrap();
                r.receive(p, 0);
                let _ = r.work(&pool, &mut ifaces, 0);
            };

            deliver(&mut r);
            // Reported rather than asserted, for the reason the RDP replay carries: a port
            // that announces nothing has nothing to accept, and a panic here would name no
            // record. `extra_offers` counts what came *after* the first announcement, so a
            // first announcement that never happened has to be visible in the answer.
            let Some(h) = r.accept() else {
                return Some((
                    serde_json::json!({ "extra_offers": -1 }),
                    "the first packet announced no connection".to_string(),
                ));
            };
            if let Ok(Some(slot)) = r.conns.dequeue_rx(h) {
                drop(pool.from_index(slot));
            }

            // More packets while the application already holds the connection.
            let mut extra_offers = 0;
            for _ in 0..input.packets_after_accept {
                deliver(&mut r);
                if r.accept().is_some() {
                    extra_offers += 1;
                }
            }
            Some((
                serde_json::json!({ "extra_offers": extra_offers }),
                format!("{} packets after accept", input.packets_after_accept),
            ))
        }
        "conn" if rec.case == "a_second_packet_reuses_the_same_connection" => {
            let input: ConnInput = serde_json::from_value(rec.input.clone()).unwrap();
            type P = Pool<16, 264>;
            type R = Router<8, 16, 48, 32>;
            let pool = P::new();
            let mut r = R::new(LOCAL_ADDR, Version::V2);
            r.bind(TEST_PORT).unwrap();
            let mut ifaces = {
                let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
                l.add("INGRESS", LOCAL_ADDR, 12, false).unwrap();
                l
            };
            for _ in 0..input.packets_from_one_peer {
                let mut p = pool.acquire(0).unwrap();
                p.set_id(Id {
                    pri: 2,
                    flags: 0,
                    src: 11,
                    dst: LOCAL_ADDR,
                    dport: TEST_PORT,
                    sport: 40,
                });
                p.set_payload(b"hi").unwrap();
                r.receive(p, 0);
                let _ = r.work(&pool, &mut ifaces, 0);
            }
            let mut connections = 0;
            let mut packets_on_it = 0;
            while let Some(h) = r.accept() {
                connections += 1;
                while let Ok(Some(slot)) = r.conns.dequeue_rx(h) {
                    drop(pool.from_index(slot));
                    packets_on_it += 1;
                }
                let mut drained = [0u16; 32];
                if let Ok(n) = r.conns.close(h, &mut drained) {
                    for &slot in &drained[..n] {
                        drop(pool.from_index(slot));
                    }
                }
            }
            Some((
                serde_json::json!({
                    "connections": connections, "packets_on_it": packets_on_it
                }),
                "one peer, two packets".to_string(),
            ))
        }
        "conn" => {
            let input: ConnInput = serde_json::from_value(rec.input.clone()).unwrap();
            let (accepted, lost) = replay_conn_pressure(&input);
            if let Some(n) = accepted.checked_div(input.rounds) {
                Some((
                    serde_json::json!({
                        "accepted_total": accepted,
                        "accepted_per_round": vec![n; input.rounds as usize],
                        "buffers_lost": lost,
                    }),
                    format!("{} rounds", input.rounds),
                ))
            } else {
                Some((
                    serde_json::json!({ "accepted": accepted, "buffers_lost": lost }),
                    format!("{} offered", input.offered),
                ))
            }
        }
        "route"
            if matches!(
                rec.case.as_str(),
                "a_local_subnet_beats_the_default_interface"
                    | "an_application_send_to_a_broadcast_is_rewritten_too"
            ) =>
        {
            Some((replay_node_send(&rec.case), rec.case.clone()))
        }
        "rtable" => Some((replay_rtable(&rec.case), rec.case.clone())),
        "route" => Some((replay_route(&rec.case), rec.case.clone())),
        "promisc" if rec.case == "two_tapped_packets_come_back_once_each" => {
            Some((replay_promisc_two(), "two through the tap".to_string()))
        }
        "promisc" if rec.case == "read_transfers_ownership" => {
            Some((replay_promisc_ownership(), "tap ownership".to_string()))
        }
        "promisc" => Some((replay_promisc(&rec.case), rec.case.clone())),
        "security" => {
            let input: SecurityInput = serde_json::from_value(rec.input.clone()).unwrap();
            let got = replay_security(&input);
            Some((
                serde_json::to_value(SecurityJson::from(got)).unwrap(),
                format!("{input:?}"),
            ))
        }
        "hmac" => {
            let input: HmacInput = serde_json::from_value(rec.input.clone()).unwrap();
            Some((
                replay_hmac(&input),
                format!("include_header={}", input.include_header),
            ))
        }
        "dedup" if rec.input.get("gap_ms").is_some() => {
            let input: DedupWindowInput = serde_json::from_value(rec.input.clone()).unwrap();
            // `a_different_packet_is_not_a_duplicate` is the one case whose two packets
            // differ; the others send the same bytes twice.
            let differ = rec.case == "a_different_packet_is_not_a_duplicate";
            let start = if rec.case.contains("wrap") {
                u32::MAX - 50
            } else {
                100_000
            };
            let got = replay_dedup_window_cased(&input, start, differ);
            Some((got, format!("{input:?} from {start}")))
        }
        "dedup" => {
            let input: DedupInput = serde_json::from_value(rec.input.clone()).unwrap();
            let got = replay_dedup(&input);
            Some((
                serde_json::to_value(DedupJson::from(got)).unwrap(),
                format!("{input:?}"),
            ))
        }
        // The initial send sequence number is rand_r() over the C's clock; the port takes
        // it as a parameter, so there is nothing to compare.
        #[cfg(feature = "rdp")]
        "rdp"
            if matches!(
                rec.case.as_str(),
                "a_syn_is_answered_with_syn_ack"
                    | "the_handshakes_final_ack_is_not_itself_answered"
                    | "data_reaches_the_application_without_the_rdp_trailer"
                    | "without_delayed_acks_every_packet_is_acknowledged"
                    | "a_stream_fragment_survives_being_carried_over_rdp"
                    | "a_multi_fragment_stream_reassembles_over_rdp"
                    | "a_hostile_syn_cannot_suppress_acknowledgement"
                    | "an_unacknowledged_syn_ack_is_retransmitted_then_reset"
            ) =>
        {
            Some((replay_rdp_handshake(&rec.case), rec.case.clone()))
        }
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "an_rdp_connect_puts_a_syn_on_the_wire" => Some((
            replay_rdp_client_connect(),
            "Node::connect(RDP)".to_string(),
        )),
        "rdp" if rec.case == "isn_is_a_function_of_the_clock" => None,
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "a_syn_without_options_is_rejected" => Some((
            replay_rdp_malformed_syn(0),
            "a SYN with no option block".to_string(),
        )),
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "a_syn_with_partial_options_is_rejected" => Some((
            replay_rdp_malformed_syn(5),
            "a SYN one option word short".to_string(),
        )),
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "malformed_syns_do_not_exhaust_the_table" => Some((
            replay_rdp_syn_flood(),
            "bad SYNs, then an honest peer".to_string(),
        )),
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "a_window_of_two_admits_exactly_two" => Some((
            replay_rdp_window_boundary(),
            "window 2, two offered".to_string(),
        )),
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "three_sends_are_sequential_and_an_ack_releases_them" => {
            Some((replay_rdp_three_sends(), "three sends, one ack".to_string()))
        }
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "one_retransmission_after_the_packet_timeout" => {
            Some((replay_rdp_one_retransmission(), "one timeout".to_string()))
        }
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "a_sent_data_packet_carries_an_rdp_trailer" => {
            Some((replay_rdp_sent_framing(), "one 5-byte send".to_string()))
        }
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "unacknowledged_data_is_retransmitted_then_given_up_on" => Some((
            replay_rdp_unacked_send(),
            "one packet, never acknowledged".to_string(),
        )),
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "a_gap_filled_late_delivers_both_in_order" => Some((
            // `B` overtakes, then `A` fills the gap.
            replay_rdp_reordered(&[(2, b'B'), (1, b'A')]),
            "B at +2 then A at +1".to_string(),
        )),
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "an_eak_carries_no_data_to_the_application" => Some((
            replay_rdp_one_packet(csp_core::rdp::ACK | csp_core::rdp::EAK, 1, b"xy"),
            "ACK|EAK carrying two bytes".to_string(),
        )),
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "out_of_sequence_data_is_answered_but_not_delivered" => Some((
            replay_rdp_one_packet(csp_core::rdp::ACK, 2, b"z"),
            "data one sequence number ahead".to_string(),
        )),
        #[cfg(feature = "rdp")]
        "rdp" if rec.case.contains("_rst_") => {
            let input: RdpInput = serde_json::from_value(rec.input.clone()).unwrap();
            Some((
                replay_rdp_reset(input.rst_in_sequence != 0),
                format!("rst in sequence: {}", input.rst_in_sequence != 0),
            ))
        }
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "a_proposed_conn_timeout_is_adopted" => {
            let input: RdpInput = serde_json::from_value(rec.input.clone()).unwrap();
            Some((
                replay_rdp_conn_timeout(input.conn_timeout, input.idled_ms),
                format!(
                    "conn_timeout {} idled {}",
                    input.conn_timeout, input.idled_ms
                ),
            ))
        }
        "rdp" if rec.case == "a_proposed_ack_timeout_is_adopted" => {
            let input: RdpInput = serde_json::from_value(rec.input.clone()).unwrap();
            // Through `decode_clamped`, so the proposal is adopted the way a SYN's is.
            let words: [u32; 6] = [
                4,
                20_000,
                1_000,
                u32::from(input.delayed_acks),
                input.ack_timeout,
                input.ack_delay_count,
            ];
            let mut wire = [0u8; csp_core::rdp::SYN_OPTIONS_LEN];
            for (i, w) in words.iter().enumerate() {
                wire[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            let opts =
                csp_core::rdp::SynOptions::decode_clamped(&wire, csp::router::RDP_MAX_WINDOW)
                    .expect("a complete option block");

            let mut c = csp_core::rdp::Connection::new(1000, opts);
            c.state = csp_core::rdp::State::Open;
            c.rcv_cur = 1000;
            c.rcv_lsa = 1000;
            c.ack_timestamp = 0;

            // One packet, well under the delay count: only the timeout can produce an ack.
            c.rcv_cur = 1001;
            let acked_immediately = u32::from(c.poll_ack(0).is_some());

            // The C's loop advances 250 ms at a time and calls `csp_conn_check_timeouts`.
            let mut waited = 0u32;
            let mut acked = 0u32;
            while waited < 20_000 {
                waited += 250;
                if c.poll_ack(waited).is_some() {
                    acked = 1;
                    break;
                }
            }
            Some((
                serde_json::json!({
                    "acked_immediately": acked_immediately,
                    "acked": acked,
                    "waited_ms": waited,
                }),
                format!("ack_timeout {}", input.ack_timeout),
            ))
        }
        "rdp" if rec.case == "a_nonzero_delayed_acks_is_on_not_a_count" => {
            let input: RdpInput = serde_json::from_value(rec.input.clone()).unwrap();
            // The option block is written word by word, because the value under test is a
            // raw wire word the port's `SynOptions` stores as a `bool` -- encoding from the
            // struct would drop the very thing being checked. Word 3 is `delayed_acks`.
            let words: [u32; 6] = [
                3,
                20_000,
                500,
                u32::from(input.delayed_acks),
                250,
                input.ack_delay_count,
            ];
            let mut wire = [0u8; csp_core::rdp::SYN_OPTIONS_LEN];
            for (i, w) in words.iter().enumerate() {
                wire[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
            }
            let opts =
                csp_core::rdp::SynOptions::decode_clamped(&wire, csp::router::RDP_MAX_WINDOW)
                    .expect("a complete option block");

            let mut c = csp_core::rdp::Connection::new(1000, opts);
            c.state = csp_core::rdp::State::Open;
            c.rcv_cur = 1000;
            c.rcv_lsa = 1000;
            let mut running = Vec::new();
            let mut acks = 0;
            for i in 1..=5u16 {
                c.rcv_cur = 1000 + i;
                if c.poll_ack(0).is_some() {
                    acks += 1;
                }
                running.push(acks);
            }
            Some((
                serde_json::json!({
                    "normalised_to_on": u8::from(opts.delayed_acks),
                    "acks_after_n_packets": running,
                }),
                format!("delayed_acks proposed as {}", input.delayed_acks),
            ))
        }
        "rdp" if rec.case == "a_delay_count_beyond_the_window_is_bound_by_it" => {
            let input: RdpInput = serde_json::from_value(rec.input.clone()).unwrap();
            // Through `decode_clamped`, not by constructing `SynOptions` directly. The
            // whole point is the bound the *negotiated* window puts on `ack_delay_count`,
            // and a hand-built options struct skips the only code that applies it -- which
            // is exactly what the neighbouring cadence replay does, and why none of them
            // could ever have caught a wrong bound.
            let proposed = csp_core::rdp::SynOptions {
                window_size: input.window_size,
                conn_timeout: 20_000,
                packet_timeout: 1_000,
                delayed_acks: input.delayed_acks != 0,
                ack_timeout: 250,
                ack_delay_count: input.ack_delay_count,
            };
            let mut wire = [0u8; csp_core::rdp::SYN_OPTIONS_LEN];
            let n = proposed.encode(&mut wire).unwrap();
            let opts =
                csp_core::rdp::SynOptions::decode_clamped(&wire[..n], csp::router::RDP_MAX_WINDOW)
                    .expect("a complete option block");

            let mut c = csp_core::rdp::Connection::new(1000, opts);
            c.state = csp_core::rdp::State::Open;
            c.rcv_cur = 1000;
            c.rcv_lsa = 1000;
            let mut running = Vec::new();
            let mut acks = 0;
            for i in 1..=5u16 {
                c.rcv_cur = 1000 + i;
                if c.poll_ack(0).is_some() {
                    acks += 1;
                }
                running.push(acks);
            }
            Some((
                serde_json::json!({ "acks_after_n_packets": running }),
                format!(
                    "window {}, delay count {}",
                    input.window_size, input.ack_delay_count
                ),
            ))
        }
        "rdp" if rec.case == "the_delay_count_fires_one_packet_after_it" => {
            let input: RdpInput = serde_json::from_value(rec.input.clone()).unwrap();
            // The C records the running total after each of five packets.
            let mut c = csp_core::rdp::Connection::new(
                1000,
                csp_core::rdp::SynOptions {
                    delayed_acks: input.delayed_acks != 0,
                    ack_delay_count: input.ack_delay_count,
                    ack_timeout: 100_000,
                    ..csp_core::rdp::SynOptions::default()
                },
            );
            c.state = csp_core::rdp::State::Open;
            c.rcv_cur = 1000;
            c.rcv_lsa = 1000;
            let mut running = Vec::new();
            let mut acks = 0;
            for i in 1..=5u16 {
                c.rcv_cur = 1000 + i;
                if c.poll_ack(0).is_some() {
                    acks += 1;
                }
                running.push(acks);
            }
            Some((
                serde_json::json!({ "acks_after_n_packets": running }),
                format!("delay count {}", input.ack_delay_count),
            ))
        }
        // Receiver-side flow control. `csp_rdp_check_ack` stops acknowledging once the
        // connection's queue leaves less than a window of room, so an unread connection
        // stops inviting data. `poll_ack` has no equivalent.
        //
        // **At the oracle's sizes this record cannot tell the two apart**, and says so:
        // the gate needs a queue deeper than 12, and the node runs out of its 15 buffers
        // at 12 delivered. Both sides acknowledge all 12. The flight configuration — 64
        // buffers, a queue of 32 — does reach it. Kept because it pins the numbers and
        // because it will start discriminating the moment the oracle is built with them.
        #[cfg(feature = "rdp")]
        "rdp" if rec.case == "the_receive_queue_gate_stops_acknowledgements" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct GateInput {
                window_size: u32,
                rxqueue_len: u32,
                buffer_count: u32,
                delivered: u32,
            }
            let input: GateInput = serde_json::from_value(rec.input.clone()).unwrap();
            let _ = input.buffer_count;
            // The node has to be the same shape as the C it is compared with: `RXQ` here is
            // `CSP_CONN_RXQUEUE_LEN` there, and the gate is a function of the two together.
            // A 4-deep queue against the C's 16 would be a different experiment reported as
            // a difference.
            assert_eq!(input.rxqueue_len, 16, "this replay's node is RXQ = 16");
            Some((
                replay_rdp_receive_gate(input.window_size, input.delivered),
                format!(
                    "window {}, {} delivered unread",
                    input.window_size, input.delivered
                ),
            ))
        }
        "rdp" if rec.case == "acks_stop_when_the_application_is_not_reading" => {
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct FlowInput {
                delivered: u32,
                rxqueue_len: u32,
                buffer_count: u32,
                window_size: u32,
            }
            let input: FlowInput = serde_json::from_value(rec.input.clone()).unwrap();
            assert!(
                input.delivered <= input.rxqueue_len.saturating_sub(input.window_size),
                "the oracle reached a queue depth where the gate fires ({} delivered, \
                 gate at >{}), so this replay is no longer a no-op and needs the port to \
                 grow the same flow control",
                input.delivered,
                input.rxqueue_len - input.window_size
            );
            let _ = input.buffer_count;

            let mut c = csp_core::rdp::Connection::new(
                1000,
                csp_core::rdp::SynOptions {
                    delayed_acks: false,
                    ..csp_core::rdp::SynOptions::default()
                },
            );
            c.state = csp_core::rdp::State::Open;
            c.rcv_cur = 1000;
            c.rcv_lsa = 1000;
            let mut acks = 0;
            let mut last = 0;
            for i in 1..=input.delivered {
                c.rcv_cur = 1000u16.wrapping_add(i as u16);
                if c.poll_ack(0).is_some() {
                    acks += 1;
                    last = i;
                }
            }
            Some((
                serde_json::json!({ "acks": acks, "last_acked_packet": last }),
                format!("{} delivered, unread", input.delivered),
            ))
        }
        "rdp" => {
            let input: RdpInput = serde_json::from_value(rec.input.clone()).unwrap();
            let acks = replay_rdp_acks(&input);
            Some((serde_json::json!({ "acks": acks }), format!("{input:?}")))
        }
        other => panic!("no replay for suite {other}: add one or the corpus is not being checked"),
    }
}

// Serialising back to JSON keeps the comparison in the corpus's own vocabulary, so a
// mismatch prints the two records side by side rather than two Rust structs.
#[derive(serde::Serialize)]
struct SecurityJson {
    delivered: u32,
    delivered_bytes: u32,
    delivered_body: String,
    rx_error: u32,
    autherr: u32,
}
impl From<SecurityObserved> for SecurityJson {
    fn from(o: SecurityObserved) -> Self {
        SecurityJson {
            delivered: o.delivered,
            delivered_bytes: o.delivered_bytes,
            delivered_body: o.delivered_body,
            rx_error: o.rx_error,
            autherr: o.autherr,
        }
    }
}

#[derive(serde::Serialize)]
struct EthJson {
    refused: u32,
    frame: u32,
    drop: u32,
    buffers_consumed: u32,
    delivered: u32,
    delivered_body: String,
}
impl From<EthObserved> for EthJson {
    fn from(o: EthObserved) -> Self {
        EthJson {
            refused: o.refused,
            frame: o.frame,
            drop: o.drop,
            buffers_consumed: o.buffers_consumed,
            delivered: o.delivered,
            delivered_body: o.delivered_body,
        }
    }
}

#[derive(serde::Serialize)]
struct CmpJson {
    replies: u32,
    reply_len: u32,
    reply_type: i32,
    reply_code: i32,
}
impl From<CmpObserved> for CmpJson {
    fn from(o: CmpObserved) -> Self {
        CmpJson {
            replies: o.replies,
            reply_len: o.reply_len,
            reply_type: o.reply_type,
            reply_code: o.reply_code,
        }
    }
}

#[derive(serde::Serialize)]
struct DedupJson {
    delivered_of_two: u32,
    forwarded_of_two: u32,
    ingress_drop: u32,
}
impl From<DedupObserved> for DedupJson {
    fn from(o: DedupObserved) -> Self {
        DedupJson {
            delivered_of_two: o.delivered_of_two,
            forwarded_of_two: o.forwarded_of_two,
            ingress_drop: o.ingress_drop,
        }
    }
}

#[test]
fn the_corpus_is_not_empty() {
    // A corpus that failed to regenerate would otherwise make every test below pass by
    // having nothing to check — the vacuous-success shape this whole suite exists to stop.
    let n = records().len();
    assert!(n >= 20, "only {n} records; run `just corpus`");
}

#[test]
fn every_record_has_a_replay() {
    for rec in records() {
        if rec.verdict == Verdict::COnly {
            continue;
        }
        assert!(
            replay(&rec).is_some(),
            "{}::{} is {:?} but has no replay",
            rec.suite,
            rec.case,
            rec.verdict
        );
    }
}

/// A deliberate divergence has to be written down where a reader will find it.
///
/// The `diverges` verdict is the port saying "the C does X and I do Y on purpose". That is
/// only a decision if the reason exists somewhere; otherwise it is a bug with a label. So
/// every such record must name itself in `SCOPE.md`, as `suite::case`.
///
/// This checks one direction only — every divergence in the corpus is documented. The
/// reverse, that every deviation `SCOPE.md` lists has a corpus record, is not enforced:
/// most of the 29 are not reachable from a C test at all (they are about API shape, or
/// about code paths the oracle does not build), and a check that has to be told which ones
/// to skip is a check nobody trusts. `SCOPE.md` says which are measured.
#[test]
fn every_deliberate_divergence_is_documented() {
    const SCOPE: &str = include_str!("../../SCOPE.md");

    let diverging: Vec<_> = records()
        .into_iter()
        .filter(|r| r.verdict == Verdict::Diverges)
        .collect();

    for rec in &diverging {
        let anchor = format!("{}::{}", rec.suite, rec.case);
        assert!(
            SCOPE.contains(&anchor),
            "{anchor} is recorded as a deliberate divergence but SCOPE.md does not mention \
             it. Add the case name where the reason is written down, or change the verdict."
        );
    }

    // Not a floor for its own sake: it fires if the corpus is regenerated from a build
    // where the divergence stopped being reachable, which would otherwise make this test
    // pass by having nothing to check.
    assert!(
        !diverging.is_empty(),
        "no `diverges` records at all — the verdict machinery is not being exercised"
    );
}

#[test]
fn the_port_reproduces_what_the_c_did() {
    // Every mismatch, not the first: one divergence usually implies others in the same
    // area, and stopping at the earliest turns a shape into a single data point.
    let mut failures: Vec<String> = Vec::new();
    let mut checked = 0;

    for rec in records() {
        let Some((got, input)) = replay(&rec) else {
            continue;
        };
        checked += 1;
        match rec.verdict {
            Verdict::MustMatch => {
                if got != rec.observed {
                    failures.push(format!(
                        "{}::{}\n     input: {input}\n     C:    {}\n     port: {}",
                        rec.suite, rec.case, rec.observed, got
                    ));
                }
            }
            Verdict::Diverges => {
                // A divergence is only meaningful if the two are *comparable*. Objects
                // with different key sets are unequal for free, so `assert_ne!` would
                // pass without looking at a single value — which is exactly how the first
                // SFP divergence passed while the port's behaviour was mutated away.
                let keys = |v: &serde_json::Value| -> Vec<String> {
                    v.as_object()
                        .map(|o| {
                            let mut k: Vec<_> = o.keys().cloned().collect();
                            k.sort();
                            k
                        })
                        .unwrap_or_default()
                };
                assert_eq!(
                    keys(&got),
                    keys(&rec.observed),
                    "{}::{} is a `diverges` record whose replay reports different fields \
                     from the C's. It would pass by being a different shape rather than a \
                     different answer.",
                    rec.suite,
                    rec.case
                );
                if got == rec.observed {
                    failures.push(format!(
                        "{}::{} is recorded as a deliberate divergence but now matches the C. \
                         Either the port regressed toward the C or SCOPE.md is out of date.",
                        rec.suite, rec.case
                    ));
                }
            }
            Verdict::COnly => unreachable!("replay returned Some for a c_only record"),
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {checked} records diverged from the C:\n\n  {}\n",
        failures.len(),
        failures.join("\n\n  ")
    );

    // Derived from the corpus rather than written down, so adding a C test and forgetting
    // the replay is a failure instead of a silently smaller run.
    let expected = records()
        .iter()
        .filter(|r| r.verdict != Verdict::COnly)
        .count();
    assert_eq!(
        checked, expected,
        "not every comparable record was replayed"
    );
}
