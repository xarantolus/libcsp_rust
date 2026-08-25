# Per-function audit

One section per module. Each records what was checked against the C, whether the port is
**faithful** (same observable behaviour, deviations recorded in `SCOPE.md`) and whether it
is **rusty** (an API a Rust caller would want, not a transliteration), plus anything found
and what was done about it.

Where a divergence is deliberate it points at the `SCOPE.md` entry. Nothing here is filed
upstream.

Status key: ✅ done · 🔶 partial · ❌ missing

---

## `csp-core::id` — header codec

Against `src/csp_id.c` (15 functions).

| C | Rust | |
|---|---|---|
| `csp_id1_prepend` / `csp_id2_prepend` | `Id::encode` | ✅ |
| `csp_id1_extract` / `csp_id2_extract` | `Id::decode` | ✅ |
| `csp_id_prepend` / `csp_id_extract` (version dispatch) | `Version` parameter | ✅ |
| `csp_id_strip` | `Packet::set_frame` | ✅ length check included |
| `csp_id1_setup_rx` / `csp_id2_setup_rx` | `Packet::set_frame` | ✅ different shape, same job |
| `csp_id_get_host_bits` / `max_nodeid` / `max_port` / `header_size` | `Version` methods | ✅ |
| `csp_id_is_broadcast` | `Version::is_broadcast` | ✅ plus a shift guard |
| `csp_id_prepend_fixup_cspv1` and the two siblings | — | ❌ **out of scope** |

**The `_fixup_cspv1` trio is out of scope, verified not assumed.** They swap CSP v1 headers
to little-endian, and `grep` across `src/` shows the only callers are
`csp_if_zmqhub.c:88,137`. ZMQ is out of scope (`SCOPE.md`), so these go with it. Recorded
here because "we didn't port three public functions" should not be something a reader has
to discover.

**Faithful:** yes. Verified beyond reading — the differential suite runs encode over every
in-range id and decode over **every bit pattern** in both versions, ~300k inputs per run,
byte-identical. `is_broadcast` is also differentially tested across random
address/netmask combinations.

**Rusty:** yes. `Version` is a parameter rather than a global, which is what makes the
`csp_conf.version`-after-init leak (`SCOPE.md` 13) unrepresentable. `encode` validates
field widths instead of shifting an oversized value into its neighbour (`SCOPE.md` 7).

**Deviations:** `SCOPE.md` 7 (field validation), 13 (immutable version).

**Found during the audit:** nothing wrong; four coverage gaps, now tested — encoding into
an oversized buffer must not clobber past the header, decoding must ignore trailing
payload bytes, the flags field is 8 bits in v1 and 6 in v2, and broadcast detection across
every netmask rather than only the all-ones case. 11 tests → 16.

---

## `csp-core::{crc32, sha1, hmac}` — checksums and authentication

Against `src/csp_crc32.c`, `src/crypto/csp_sha1.c`, `src/crypto/csp_hmac.c` (14 functions).

| C | Rust | |
|---|---|---|
| `csp_crc32_init` / `update` / `final` | `Crc32::new` / `update` / `finalize` | ✅ |
| `csp_crc32_memory` | `crc32::checksum` | ✅ |
| `csp_crc32_append` / `verify` | `crc32::append` / `verify` with `Coverage` | ✅ |
| `csp_sha1_init` / `process` / `done` | `Sha1::new` / `update` / `finalize` | ✅ |
| `csp_sha1_memory` | `sha1::digest` | ✅ |
| `csp_hmac_memory` | `hmac::mac_full` / `mac` | ✅ returns a sized array |
| `csp_hmac_set_key` | `hmac::derive_key` | ✅ |
| `csp_hmac_append` / `verify` | `hmac::append` / `verify_over` | ✅ **added during this audit** |

**Faithful:** yes. The differential suite checks CRC-32C over random buffers, SHA-1 with
lengths clustered on the 55/56 and 64-byte padding boundaries, and HMAC with key lengths
straddling the 64-byte block where the key is hashed rather than padded — all byte-identical.

**Rusty:** yes. Sized return arrays instead of unsized out-parameters, `Result` instead of
an int code, and `Coverage` as an explicit enum rather than a `bool include_header`.

**Found during the audit — a real gap in the port.** `csp_hmac_append` and
`csp_hmac_verify` take an `include_header` flag, exactly the two-coverage structure CRC32
has, and the port only ever authenticated the payload. Mismatching coverage makes **every
packet fail authentication with no indication why**. Added `mac_over`, `append` and
`verify_over` taking [`Coverage`], with tests that the two are not interchangeable, that
header coverage actually covers the header (otherwise the flag is decorative and a tampered
header authenticates), and that payload-only genuinely ignores it.

**Three defects in the C, recorded not reported:**

1. **`csp_hmac_verify` uses `memcmp`.** With a 32-bit tag, a comparison that stops at the
   first wrong byte reduces a 2^32 forgery to roughly 4 × 2^8 attempts, and a spacecraft
   link has no rate limit an attacker must respect. The port compares in constant time.
2. **`csp_hmac_verify`'s length check does not match the branch it guards.** It tests
   `packet->length < CSP_HMAC_LENGTH`, then in the `include_header` branch computes
   `frame_length - CSP_HMAC_LENGTH`. A packet with `length >= 4` but `frame_length < 4`
   underflows that subtraction to roughly 4 billion and hashes far past the buffer.
3. **`csp_hmac_memory` writes 20 bytes through an unsized pointer** while
   `CSP_HMAC_LENGTH` is 4 (`SCOPE.md` 4), and an empty key leaves the output untouched
   (`SCOPE.md` 5).

**Deviations:** `SCOPE.md` 4, 5, plus `crc32::Coverage` being explicit where the C's
verifier silently falls back (`SCOPE.md`, KISS/`CSP_21` note).

**Tests:** 183 in `csp-core`, up from 174.

---

## `csp-core::rdp` — reliable delivery

Against `src/csp_rdp.c` (1 022 lines, 30 `goto`s) and `src/csp_rdp_queue.c`. The riskiest
module in the library, and the audit found the most here.

| C | Rust | |
|---|---|---|
| header add/remove/ref | `Header::encode` / `decode` / `strip` | ✅ |
| SYN option block + clamping | `SynOptions::decode_clamped` | ✅ every bound tested |
| `csp_rdp_seq_between` / `seq_before` | `seq_between` / `seq_before` | ✅ wrapping |
| state machine (5 states) | `Connection::step` | ✅ |
| `csp_rdp_should_ack` / `check_ack` | `should_ack` / `poll_ack` | ✅ **added during this audit** |
| TX queue + retransmission | `TxQueue` | ✅ added earlier in this work |
| RX reorder queue | `RxQueue` | ✅ **added during this audit** |
| `csp_rdp_set_opt` / `get_opt` | `Connection::opts`, per connection | ✅ better than the C's globals |
| `RDP_EAK` | parsed, never generated | ✅ faithful — the C never generates one either |

**Two real defects found in the port, both serious:**

1. **Received data was never acknowledged.** The `Open` state delivered in-order data and
   returned; only a *duplicate* was re-acked. The protocol still converged, but solely via
   the sender's retransmission timer — so every packet cost a full `packet_timeout` of
   latency and a duplicate on the link, and a connection that lost its window would give up
   after `MAX_RETRANSMITS` believing the peer was dead when every packet had arrived.
   Fixed with the C's three-condition `should_ack`, exposed as `poll_ack` and checked
   separately from packet handling — which is faithful, since `csp_rdp_check_ack` is called
   by the router, not the receive path.

2. **Out-of-order packets were discarded.** A packet arriving after a gap was dropped, so a
   single lost packet forced retransmission of everything sent after it — on a link with
   real latency, most of the window. `RxQueue` holds them and releases everything the gap
   unblocked, which is the C's backward `goto front` at `csp_rdp.c:256` expressed as a
   `while let`.

**Faithful:** yes, now. `RDP_EAK` is parsed and never generated, which matches the C
exactly — it defines the flag and inspects it in three places but has no path that sets it.

**Rusty:** yes, and materially better in one respect: RDP options are **per connection**.
The C keeps its six tunables (`csp_rdp_window_size`, `conn_timeout`, `packet_timeout`,
`delayed_acks`, `ack_timeout`, `ack_delay_count`) as file statics shared by every
connection, so two connections with different timeouts are not expressible. Both queues are
per connection too; the C keeps one TX and one RX queue globally and tells entries apart by
comparing `packet->conn`, so a busy connection crowds out a quiet one.

**Deviations:** `SCOPE.md` — SYN option clamping is treated as a security control, and the
give-up counter bounds retransmission.

**Tests:** 48 in `rdp`, up from 33.
