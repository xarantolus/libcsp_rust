//! Replay of `corpus/ctest.jsonl` — what the real libcsp did, run against the port.
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

    let ifaces = {
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
    let (delivered, delivered_bytes) = match r.work(&pool, &ifaces, 0) {
        Routed::Delivered { conn, .. } => {
            // Take the packet off the connection the way an application would, and
            // measure what it holds. The C reports `p->length` after csp_recvfrom.
            let len = match r.conns.dequeue_rx(conn) {
                Ok(Some(slot)) => pool
                    .from_index(slot)
                    .map(|p| p.with_payload(|d| d.len() as u32))
                    .unwrap_or(0),
                _ => 0,
            };
            (1, len)
        }
        Routed::Dropped(DropReason::Refused(_)) => (0, 0),
        other => panic!("neither delivered nor refused: {other:?}"),
    };

    SecurityObserved {
        delivered,
        delivered_bytes,
        // The C charges its interface, the port charges its router. Same event, and the
        // split between the two counters is the thing being compared.
        rx_error: r.counters.rx_error,
        autherr: r.counters.auth_error,
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

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DedupObserved {
    delivered_of_two: u32,
    forwarded_of_two: u32,
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

    let ifaces = {
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
        if let Routed::Delivered { .. } = r.work(&pool, &ifaces, 10) {
            delivered += 1;
        }
    }

    let mut forwarded = 0;
    for _ in 0..input.pairs {
        r.receive(packet(25), 0);
        if let Routed::Forwarded { packet: slot, .. } = r.work(&pool, &ifaces, 10) {
            forwarded += 1;
            // Reclaim the slot the router handed over, or the pool drains and the next
            // iteration fails for a reason unrelated to deduplication.
            drop(pool.from_index(slot));
        }
    }

    DedupObserved {
        delivered_of_two: delivered,
        forwarded_of_two: forwarded,
    }
}

// --- cmp ------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CmpInput {
    /// The exact request bytes the C node was given, as lowercase hex.
    request: String,
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

fn replay_cmp(input: &CmpInput) -> CmpObserved {
    use csp_core::cmp;

    const HOSTNAME: &str = "oracle-node";
    const MODEL: &str = "ctest-model";
    const REVISION: &str = "rev-1";

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
    let code = req[1];
    let h = cmp::Header {
        kind: cmp::REPLY,
        code,
    };

    let mut out = [0u8; 256];
    let n = match query {
        cmp::Query::Ident => cmp::Ident {
            hostname: HOSTNAME,
            model: MODEL,
            revision: REVISION,
            // The C fills these from __DATE__/__TIME__; only the length matters here and
            // they are deliberately absent from the corpus.
            date: "Jan  1 2026",
            time: "00:00:00",
        }
        .encode(h, &mut out),
        cmp::Query::IfStats { interface } => {
            // The C answers only for an interface it has. "INGRESS" is the one the oracle
            // registers; anything else gets no reply.
            if interface != "INGRESS" {
                return none;
            }
            cmp::IfStatsMsg {
                interface,
                stats: cmp::IfStats::default(),
            }
            .encode(h, &mut out)
        }
        cmp::Query::Clock { .. } => cmp::Timestamp {
            tv_sec: 0,
            tv_nsec: 0,
        }
        .encode(h, &mut out),
        // Both route forms answer only for an interface the node has, and the C looks the
        // name up before touching the table — so an unknown name changes nothing *and*
        // says nothing. "INGRESS" and "ROUTED" are the two the oracle registers.
        cmp::Query::RouteSet(r) => {
            if r.interface != "INGRESS" && r.interface != "ROUTED" {
                return none;
            }
            r.encode(h, &mut out)
        }
        cmp::Query::RouteSetV1(r) => {
            if r.interface != "INGRESS" && r.interface != "ROUTED" {
                return none;
            }
            r.encode(h, &mut out)
        }
        cmp::Query::Peek { addr, len, wide } => {
            let Some(src) = peek_window(addr, len as usize, wide) else {
                return none;
            };
            cmp::Peek {
                addr: addr as u32,
                len,
                data: &src,
            }
            .encode(h, &mut out)
        }
        cmp::Query::Poke { addr, data, wide } => {
            if peek_window(addr, data.len(), wide).is_none() {
                return none;
            }
            cmp::Peek {
                addr: addr as u32,
                len: data.len() as u8,
                data,
            }
            .encode(h, &mut out)
        } // No catch-all: every `Query` variant now has an encoder, so exhaustiveness does
          // what the old `panic!` did and does it at compile time. Adding a variant to
          // `Query` without teaching this replay about it becomes a build error rather than
          // a record that silently scores zero.
    };

    match n {
        Ok(n) => CmpObserved {
            replies: 1,
            reply_len: n as u32,
            reply_type: cmp::REPLY as i32,
            reply_code: code as i32,
        },
        Err(_) => none,
    }
}

// --- eth ------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EthInput {
    /// Every frame the C's receive path saw, in order, each already truncated to the
    /// `received_len` a NIC would have delivered.
    frames: Vec<String>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EthObserved {
    refused: u32,
    frame: u32,
    drop: u32,
    buffers_consumed: u32,
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

    for hex in &input.frames {
        let bytes = unhex(hex);
        let outcome = (|| -> Result<(), ()> {
            let h = eth::Header::decode(&bytes).map_err(|_| ())?;
            if !h.is_csp() {
                return Err(());
            }
            let payload = bytes.get(eth::HEADER_LEN..).ok_or(())?;
            let seg = payload.get(..h.seg_size as usize).ok_or(())?;
            r.push(&h, 0, seg, &mut out).map_err(|_| ())?;
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
    }
}

// --- rdp ------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RdpInput {
    delayed_acks: u8,
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

/// A transfer that is over after its first packet — every SFP case in the corpus is a
/// single frame, so there is never a second one to hand back.
struct NoMore;
impl<'p> csp::delivery::PacketSource<'p, 8, 264> for NoMore {
    fn next_packet(&mut self, _timeout_ms: u32) -> Option<csp::pool::Packet<'p, 8, 264>> {
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
    let ifaces = {
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
            let _ = r.work(&pool, &ifaces, 0);
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
fn replay_promisc(case: &str) -> serde_json::Value {
    use csp::dedup::DedupMode;
    type P = Pool<16, 264>;
    type R = Router<8, 16, 48, 32>;

    const EGRESS: u16 = 20;
    const ELSEWHERE: u16 = 25;

    let (tap_on, dedup, dsts): (bool, DedupMode, &[u16]) = match case {
        "the_tap_sees_a_locally_delivered_packet" => (true, DedupMode::Off, &[LOCAL_ADDR]),
        "the_tap_sees_a_forwarded_packet" => (true, DedupMode::Off, &[ELSEWHERE]),
        "the_tap_does_not_see_a_suppressed_duplicate" => {
            (true, DedupMode::All, &[LOCAL_ADDR, LOCAL_ADDR])
        }
        "delivery_is_the_same_with_the_tap_off" => {
            (false, DedupMode::Off, &[LOCAL_ADDR, ELSEWHERE])
        }
        other => panic!("no promisc replay for {other}"),
    };

    let pool = P::new();
    let mut r = R::new(LOCAL_ADDR, Version::V2);
    r.bind(TEST_PORT).unwrap();
    r.dedup_mode = dedup;
    r.set_promisc(tap_on);

    let ifaces = {
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
        match r.work(&pool, &ifaces, 0) {
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
fn replay_route(case: &str) -> serde_json::Value {
    type P = Pool<16, 264>;
    type R = Router<8, 16, 48, 32>;

    const INGRESS: u16 = 40;
    const LINK_A: u16 = 8;
    const LINK_B: u16 = 9;
    const TARGET: u16 = 10;

    let (two_links, defaults, dst) = match case {
        "one_owning_link_sends_one_frame" => (false, false, TARGET),
        "two_owning_links_send_two_frames" => (true, false, TARGET),
        "two_default_interfaces_send_two_frames" => (true, true, 3000),
        other => panic!("no route replay for {other}"),
    };

    let pool = P::new();
    let mut r = R::new(9999, Version::V2); // an address no interface has
    let ifaces = {
        let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
        l.add("INGRESS", INGRESS, 12, false).unwrap();
        l.add("LINK_A", LINK_A, 12, defaults).unwrap();
        if two_links {
            let b = if defaults { 200 } else { LINK_B };
            l.add("LINK_B", b, 12, defaults).unwrap();
        }
        l
    };

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
    r.receive(p, 0);

    // `work` is a step: drain it until it stops producing, so a router that fans out over
    // several calls is counted the same as one that reports them together.
    let mut left_by: Vec<String> = Vec::new();
    loop {
        match r.work(&pool, &ifaces, 0) {
            Routed::Forwarded { iface, packet, .. } => {
                let name = ifaces
                    .get(iface)
                    .map(|e| e.name.to_lowercase())
                    .unwrap_or_default();
                left_by.push(name);
                drop(pool.from_index(packet));
            }
            Routed::Idle => break,
            _ => break,
        }
    }

    serde_json::json!({
        "frames": left_by.len(),
        "left_by": left_by,
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
        "sfp" => {
            let input: SfpInput = serde_json::from_value(rec.input.clone()).unwrap();
            Some((replay_sfp(&input), format!("{input:?}")))
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
        "conn" if rec.case == "a_connection_is_offered_to_the_application_only_once" => {
            let input: ConnInput = serde_json::from_value(rec.input.clone()).unwrap();
            type P = Pool<16, 264>;
            type R = Router<8, 16, 48, 32>;
            let pool = P::new();
            let mut r = R::new(LOCAL_ADDR, Version::V2);
            r.bind(TEST_PORT).unwrap();
            let ifaces = {
                let mut l = csp::iflist::IfList::<4, 4>::new(Version::V2);
                l.add("INGRESS", LOCAL_ADDR, 12, false).unwrap();
                l
            };
            let deliver = |r: &mut R| {
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
                let _ = r.work(&pool, &ifaces, 0);
            };

            deliver(&mut r);
            let h = r
                .accept()
                .expect("the first packet announces the connection");
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
            let ifaces = {
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
                let _ = r.work(&pool, &ifaces, 0);
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
        "route" => Some((replay_route(&rec.case), rec.case.clone())),
        "promisc" => Some((replay_promisc(&rec.case), rec.case.clone())),
        "security" => {
            let input: SecurityInput = serde_json::from_value(rec.input.clone()).unwrap();
            let got = replay_security(&input);
            Some((
                serde_json::to_value(SecurityJson::from(got)).unwrap(),
                format!("{input:?}"),
            ))
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
        "rdp" if rec.case == "isn_is_a_function_of_the_clock" => None,
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
    rx_error: u32,
    autherr: u32,
}
impl From<SecurityObserved> for SecurityJson {
    fn from(o: SecurityObserved) -> Self {
        SecurityJson {
            delivered: o.delivered,
            delivered_bytes: o.delivered_bytes,
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
}
impl From<EthObserved> for EthJson {
    fn from(o: EthObserved) -> Self {
        EthJson {
            refused: o.refused,
            frame: o.frame,
            drop: o.drop,
            buffers_consumed: o.buffers_consumed,
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
}
impl From<DedupObserved> for DedupJson {
    fn from(o: DedupObserved) -> Self {
        DedupJson {
            delivered_of_two: o.delivered_of_two,
            forwarded_of_two: o.forwarded_of_two,
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
