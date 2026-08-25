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
    let delivered = match r.work(&pool, &ifaces, 0) {
        Routed::Delivered { .. } => 1,
        Routed::Dropped(DropReason::Refused(_)) => 0,
        other => panic!("neither delivered nor refused: {other:?}"),
    };

    SecurityObserved {
        delivered,
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
        "rdp" => None,
        other => panic!("no replay for suite {other}: add one or the corpus is not being checked"),
    }
}

// Serialising back to JSON keeps the comparison in the corpus's own vocabulary, so a
// mismatch prints the two records side by side rather than two Rust structs.
#[derive(serde::Serialize)]
struct SecurityJson {
    delivered: u32,
    rx_error: u32,
    autherr: u32,
}
impl From<SecurityObserved> for SecurityJson {
    fn from(o: SecurityObserved) -> Self {
        SecurityJson {
            delivered: o.delivered,
            rx_error: o.rx_error,
            autherr: o.autherr,
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
