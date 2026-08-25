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

---

## `csp-core::sfp` + `csp::delivery` — fragmentation and the either-shape port

Against `src/csp_sfp.c` (6 functions).

| C | Rust | |
|---|---|---|
| `csp_sfp_header_add` / `remove` | `Fragment::encode` / `parse` | ✅ trailer placement verified against 184 golden fragments |
| `csp_sfp_opts_max_mtu` | `sfp::max_mtu` | ✅ all six option combinations differentially checked |
| `csp_sfp_conn_max_mtu` | `Node::conn_sfp_mtu` | ✅ one call, not the C's flags→opts dance |
| `csp_sfp_send` | `Fragmenter` | ✅ |
| `csp_sfp_recv_fp` incl. `first_packet` | `Reassembler`, `Delivery::classify` | ✅ |

**Faithful:** yes. The golden vectors cover 36 transfers and 184 fragments across both wire
versions, and reassembling the C's *own* frames reproduces the message exactly.

**Rusty:** yes. `Delivery` is the part that is genuinely better rather than merely
different — see `SCOPE.md` 3.

**Found during the audit — a fifth C defect, and it compounds with one already recorded.**
`csp_sfp.c:131` does `conn->idout.flags |= CSP_FFRAG` inside the send loop, and **nothing
in the library ever clears it**: grep across `src/` finds exactly one write to that flag
and no reset anywhere. So after a single SFP transfer, every later plain datagram on that
connection is marked as a fragment.

Combined with deviation 3 — a receiver that sees `FFRAG`, fails to parse an SFP trailer,
and *frees the packet* — this means **the sender creates the condition and the receiver
destroys the packet**, with the sender told only `-103 CSP_ERR_SFP`. The flight code runs
SFP on the config and log-dump ports, so any connection reused for a plain reply afterwards
hits it.

In the port the flag lives on the packet, never on the connection. There is a test that
sends a fragment-flagged packet and then a plain one on the same connection and asserts the
second is not marked.

**Deviations:** `SCOPE.md` 3 (non-destructive wrong-shape delivery), 15 (non-sticky flag).

---

## `csp-core::cfp` — CAN fragmentation

Against `src/interfaces/csp_if_can.c` and `csp_if_can_pbuf.c`.

| C | Rust | |
|---|---|---|
| CFP1 identifier build/parse | `v1_id` / `v1_parse` | ✅ differentially fuzzed both ways |
| CFP1 begin/more framing, `remain` | `V1Fragmenter` | ✅ 101 golden frames |
| CFP1 reassembly | `V1Reassembler` | ✅ |
| CFP2 framing, begin/end, 3-bit `fc` | `V2Fragmenter` | ✅ |
| CFP2 reassembly, split header | `V2Reassembler` | ✅ added earlier in this work |
| `csp_can_pbuf_*` — concurrent transfers | `Pbufs` | ✅ added earlier in this work |
| **loopback shortcut** | `Interface::send` → `Sent::Loopback` | ✅ **added during this audit** |

**Found during the audit.** `csp_can1_tx` and `csp_can2_tx` both open with

```c
if (packet->id.dst == iface->addr) { csp_qfifo_write(packet, iface, NULL); return CSP_ERR_NONE; }
```

The port checked only the **node** address in `Node::route`, and a node's address and an
*interface's* address are not the same thing — a node can hold several interfaces on
different subnets. A packet addressed to an interface would have gone out on the wire
instead of looping back. `Interface::send` now returns `Sent::Loopback` for it, which the
caller must feed back in; making it a returned value rather than a silent branch means a
caller cannot forget to handle it.

CFP2 additionally consults `csp_addr_is_alias`; aliases live in [`IfList`], which is where
that check belongs.

**Faithful:** yes. Identifiers, DLCs and data match the C byte-for-byte across 16 transfers
and 101 frames, and the identifier packing/parsing is differentially fuzzed over every
29-bit pattern.

**Rusty:** yes. Iterators rather than a callback-driven send loop, and `Pbufs` is generic
over the reassembler so CFP1, CFP2 and Ethernet share one implementation.

**Note, not a defect:** CFP2's fragment counter is 3 bits, so losing exactly 8 consecutive
fragments is undetectable. That is the wire format, and it is documented rather than
papered over.

**Tests:** 158 in `csp`, and the `cfp` module's own suite covers both versions.

---

## `csp-core::{kiss, eth}` — serial framing and Ethernet

Against `src/interfaces/csp_if_kiss.c` and `csp_if_eth.c` / `csp_if_eth_pbuf.c`.

| C | Rust | |
|---|---|---|
| `csp_kiss_tx` escaping | `kiss::encode` | ✅ 6 golden frames, incl. the escape cases |
| `csp_kiss_rx` state machine | `kiss::Decoder` | ✅ |
| ETH header pack/unpack | `eth::Header` | ✅ |
| ETH segmentation / reassembly | `Segmenter` / `Reassembler` | ✅ out-of-order tolerated |
| ARP | `ArpTable` | ✅ added earlier in this work |

**Found during the audit — an interop difference.** The C's `KISS_MODE_ESCAPED` appends
**only** for `TFESC` and `TFEND`:

```c
if (inputbyte == TFESC) ...frame_begin[rx_length++] = FESC;
if (inputbyte == TFEND) ...frame_begin[rx_length++] = FEND;
```

Any other byte after `FESC` is silently dropped. The port passed it through, which would
build a frame **one byte longer** than the peer built — a payload disagreement, and with
the KISS CRC enabled a checksum disagreement too. Now matched, with a test feeding
`FESC 0x99` and asserting the byte vanishes.

**Two differences checked and deliberately kept:**

- On an over-long frame the C resets to `NOT_STARTED` *mid-frame*, so the tail of the
  discarded frame is then read as the start of a new one. The port goes to a skip state and
  waits for the delimiter. Cleaner, and not observable to a peer.
- The port treats a closing `FEND` as also opening the next frame; the C requires a
  separate one. Since the C's encoder always emits a leading `FEND`, both interoperate —
  the port is simply tolerant of shared delimiters.

**Faithful:** yes. KISS frames match the C byte-for-byte, and that match is what settled the
`CSP_21` CRC-coverage question empirically.

**Rusty:** yes. The decoder is a fixed-capacity state machine returning borrowed frames,
with over-long frames counted rather than truncated into something that would still parse.

**ETH:** the C's header does not match the bit-packed EFP layout its own file comment
specifies; the port follows the code, since that is what is on the wire. Its unpacker is
also asymmetric with its packer and shifts a promoted `int` into the sign bit
(`SCOPE.md` 11).

---

## `csp-core::cmp` — management protocol

Against `include/csp/csp_cmp.h` and the seven `src/cmp/*.c` handlers.

All nine message types are present and offset-checked against the packed structs:
`ident` (93), `route_set_v1` (15), `route_set_v2` (19), `if_stats` (53), `peek`/`poke`
(7 + data), `peek_v2`/`poke_v2` (11 + data), `clock` (10). Sizes verified by compiling a C
program against the real headers and comparing `sizeof` — not by counting fields.

**Two findings.**

**1. `ROUTE_SET_V1` was missing from the port.** It is a distinct message with single-byte
addresses (not the `u16`s of v2) and its own handler, `csp_cmp_route_set_v1_handler`. A
node speaking CSP v1 sends this form. Added, with a test that the two dispatch separately.

**2. A peek reply pads itself with unrelated buffer contents — a C defect.**
`csp_cmp_peek_handler` writes `len` bytes at `cmp->data`, which the packed struct places at
offset **7**, then sets `packet->length = CMP_PEEK_SIZE(cmp->len)` = `7 + 3 + len` = **10 +
len**. The three tail bytes are never written, so they carry whatever the previous user of
that pooled buffer left. The header comment is explicit that the tail is deliberate —
*"Legacy variable CMP messages include the tail padding from the original fixed-size
member"* — so the length is intentional and only the **filling** is not.

On a service whose entire purpose is reading memory, padding the reply with unrelated
memory is the wrong direction to be wrong in. The port emits the same wire length so a C
peer sees the size it expects, and zeroes the tail. Recorded as `SCOPE.md` 16, with a test
that pre-dirties the output buffer and asserts the tail comes back zero.

**Faithful:** yes, now — including the 3-byte tail, which a naive port would omit and then
be three bytes short of what a C peer expects.

**Rusty:** yes, and this module is a capability gain rather than a port: the C has request
builders and server handlers but **no decoder**, which is why the packet sniffer in the
flight repository reimplements the entire wire format by hand.

**Tests:** 25 in `cmp`, up from 18.

---

## `csp-core::rtable` + routing in `csp::node`

Against `src/csp_rtable_cidr.c`, `csp_rtable_stdio.c`, and the routing half of `csp_io.c`.

**Two gaps found, both in the *use* of the table rather than the table itself.**

**1. Redundant routes were collapsed to one.** `csp_send_direct` does not stop at the
first match — it walks *backwards* with `csp_rtable_search_backward`, collecting every
entry with the same address and netmask, and **sends a clone to each**, the last getting
the original. That is how a redundant link is configured. The port returned a single route,
so the second path would never have been used and the redundancy would have been
decorative. Added `Table::find_all`.

**2. Split horizon was missing.** The C skips a route whose interface shares a subnet with
the one the packet arrived on. Without it a forwarded packet can go straight back out the
interface it came from and loop. Added `Node::route_from(packet, id, routed_from)`, with
`Unroutable::SplitHorizon { iface }` so a caller can tell "nowhere to send this" from
"the only path is backwards" — two different operational problems.

`Outbound::NoRoute` now carries an [`Unroutable`] saying which.

**Still open, tracked separately:** the C falls back to `csp_iflist_get_by_isdfl` when no
route matches, walking every default-marked interface. The port has `IfList::find_default`
but the node does not yet own an `IfList`, so the fallback is not wired. Recorded in the
`csp::node` audit rather than silently left.

**Faithful:** the table itself, yes — longest-prefix match, the equal-length tie-break, and
update-in-place all match. Routing *policy* now matches too.

**Rusty:** yes. `find_all` writes into a caller slice and returns the count rather than
handing out an iterator over an internal pointer, and the table is a value rather than a
`static`.

**Deviations:** `SCOPE.md` — full-table refusal, and the parser's lack of a 100-character
cliff.

---

## `csp::pool` — the packet buffer pool

Against `src/csp_buffer.c` (9 public + 2 private functions), plus libcsp's own
`unittests/buffer.c` and the ownership test in `unittests/promisc.c`.

| C | Rust | |
|---|---|---|
| `csp_buffer_init` | `Pool::new` | ✅ |
| `csp_buffer_get` / `_isr` | `Pool::acquire(reserve)` | ✅ |
| `csp_buffer_get_always` / `_isr` | — | ❌ **deliberately absent** (`SCOPE.md` 7) |
| `csp_buffer_free` / `_isr` | `Drop` | ✅ cannot be forgotten or repeated |
| `csp_buffer_refc_inc` | `Packet::add_ref` | ✅ |
| `csp_buffer_clone` / `copy` | `Packet::deep_copy` | ✅ |
| `csp_buffer_remaining` | `Pool::available` | ✅ |

**libcsp's own two buffer tests are ported, not merely "covered in spirit":**

- `test_alloc_clean_734` — every slot must come back clean. A reused buffer still holding
  the previous packet leaks it into whatever is sent next.
- `test_clone_frame_begin_fixed` — the clone's frame must be its own. In the C
  `frame_begin` is a *pointer* into the packet's own array, so `csp_buffer_copy` has to
  recompute it after the `memcpy`; get that wrong and the clone's frame points into the
  source. Here it is an offset, so the copy is exact by construction — pinned anyway,
  because "correct by construction" is a claim that should still have a test.

**Faithful:** yes, with one deliberate absence. There is no `get_always` equivalent: the C's
version calls `csp_panic` and then `while(1)`, and the default `csp_panic` just *returns*,
so its real behaviour on exhaustion is a silent hang. `acquire` returns `None`.

**Rusty:** this is the module where the port earns the most. Three C properties dissolve
together — `frame_begin` becomes an offset, the handle carries a slot index so there is no
`CONTAINER_OF` walk backwards, and the refcount is an `AtomicU8` rather than an
`unsigned int` touched from ISR and task context. The consequence is operational: a handler
cannot leak a buffer, which is the entire reason `test_csp_robustness.py` exists in the
flight test suite.

**Found during the audit:** no defects; three coverage gaps now tested — that `deep_copy`
preserves the frame across both wire versions, the exhaustive form of issue #734, and that
`add_ref` (shared slot) and `deep_copy` (new slot) are genuinely different, since confusing
them is how a "clone" ends up aliasing its source.

**Also worth recording:** my first draft of the #734 test used `flags: 0xff` with CSP v2 and
was rejected by the port's own field validation — v2 flags are six bits. The test data was
wrong and the code was right, which is the validation from `SCOPE.md` 7 doing its job.

**Tests:** 18 in `pool`, up from 15.

---

## `csp::conn` + `csp::qfifo` — connections and the router queue

Against `src/csp_conn.c` (17 functions) and `src/csp_qfifo.c`.

**One real gap found: client and server connections match differently, and the port
matched everything the server way.**

`csp_conn_find_existing` distinguishes the two, and the C's own comment says why a client
connection matches on **destination port alone**:

> *"Outgoing connections are uniquely defined by the source port, so only the incoming
> destination port must match. This means that responses to broadcast addresses are
> accepted as long as the incoming port matches the unique source port of the connection."*

Our source port is ephemeral and therefore unique, so the reply's destination port
identifies the connection by itself. Matching on source address as well — which is what the
port did — means **a reply to a broadcast request lands on a new connection instead of the
one waiting for it**, and the caller waits out its timeout while the answer sits somewhere
else. A server connection does need all three, because several peers can talk to one bound
port at once.

Added `Kind::{Client, Server}`, set by `Node::connect` and by the router respectively, with
tests for both rules.

**Faithful:** yes, now. Also checked and matching: round-robin allocation, close draining
the receive queue, and the timeout sweep.

**Rusty:** yes, and better in one respect that has no C equivalent — handles are
generation-tagged, so a handle to a closed connection is *detected* rather than silently
addressing whoever recycled the slot. That use-after-free is trivially available with a raw
`csp_conn_t *`.

**`qfifo`:** clean. Drop-and-count when full matches `csp_qfifo_write`; the C frees the
packet on a full queue too, and the difference is that `Qfifo::dropped` is a real counter
rather than a `uint8_t` written from two contexts without synchronisation.

**Tests:** 166 in `csp`, up from 160.
