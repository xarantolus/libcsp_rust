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

Handshake retransmission is checked against the C rather than against a reading of it: a
corpus record drives a peer that never acknowledges and compares the flags, sequence number
and acknowledgement of the first repeat against the original `SYN|ACK`. Both agree. The C
refreshes `ack_nr` to `rcv_cur` on each repeat (`csp_rdp.c`, "Update to latest outgoing
ACK"); `SynRcvd` cannot advance `rcv_cur`, so the record cannot distinguish that from any
other equal-valued field and does not claim to.

**Tests:** 49 in `rdp`, up from 33.

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
| ETH segmentation / reassembly | `Segmenter` / `Reassembler` | ✅ arrival order, padding tolerated |
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

**ETH:** reassembly appends at the running byte count, as `csp_eth_rx` copies to
`frame_begin + rx_count`; EFP carries no offset field, so segments belong in arrival order
and `push` derives the position rather than taking it. A frame longer than
`header + seg_size` is accepted and the surplus ignored — Ethernet pads to 60 bytes, and
requiring an exact length refused every small packet (`SCOPE.md`). The corpus records what
the application received, body included, not only whether a frame was refused.

The C's header does not match the bit-packed EFP layout its own file comment
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

---

## `csp::router` + `dedup` + promisc + bridge

Against `src/csp_route.c`, `csp_dedup.c`, `csp_promisc.c`, `csp_bridge.c`.

**The most security-relevant gap of the whole audit: the endpoint security check was
missing entirely.**

`csp_route_security_check` runs before a packet reaches the application and does two
things:

- a packet that **claims** a protection must pass it — a wrong CRC or a wrong MAC is
  rejected;
- a packet that **omits** a protection the endpoint requires (`CSP_SO_CRC32REQ`,
  `CSP_SO_HMACREQ`, `CSP_SO_RDPREQ`) is rejected even though nothing about the packet
  itself is malformed.

The second is the one that is easy to leave out and silent when you do: every packet still
arrives, the endpoint has simply stopped requiring anything. A node configured to demand
HMAC would have accepted unauthenticated traffic. `csp_route_check_options` is the
companion — a packet using a feature the build lacks is dropped, because delivering it
would mean delivering it *unverified*.

Added `csp-core::security`, a pure function over `(endpoint_opts, id, payload)`. Beyond the
C it also: refuses a packet claiming HMAC when **no key is configured** (accepting would
mean treating an unverifiable packet as authentic), enforces the `*PROHIB` options the C
declares but never checks, and keeps authentication failures on a separate counter from
link errors — a rising `autherr` means someone is talking to you who should not be, a
rising `rx_error` usually means a bad link, and conflating them hides both.

**Also confirmed during this audit:** HMAC is verified **before** CRC32 on receive, because
it authenticates the bytes the checksum then covers.

**Dedup, promisc, bridge:** already audited and fixed earlier in this work — the clock-wrap
defect (`SCOPE.md` 10), the tap counting what it could not hold, and the bridge refusing a
frame from neither side (`SCOPE.md` 12).

**Now wired.** `Router::deliver_local` runs `security::check` before a packet reaches a
connection, strips what it verified so the application sees only the payload, and counts
authentication failures on `auth_error` separately from `rx_error`.
`DropReason::Refused(Refusal)` says which policy turned the packet away — distinct from
every other drop reason, because it means the packet arrived intact and was refused on
policy, which is an operational signal rather than a fault.

**Still open:** the default-interface fallback, tracked in the `csp::node` audit.

**Tests:** 13 in `security`; 410 in total.

---

## `csp::service` + `csp::client` — both halves of the built-in services

Against `src/csp_service_handler.c` and `src/csp_services.c`.

Every port checked in both directions — CMP, ping, ps, memfree, reboot, buf_free, uptime —
with round-trip tests asserting the client's request is what the server accepts. A mismatch
there is silent: the request simply does nothing.

**A correction to an earlier claim in this audit.** I recorded that `csp_ping` "compares
only the length". That is **wrong**, and re-reading the source is what caught it: `csp_ping`
fills the request with `i % 256` and verifies **every byte** of the reply against that
pattern. The content check is there and it is correct.

What it never checks is the **length**. The loop runs to `size` — the size that was
*requested* — and indexes `packet->data[i]` without consulting `packet->length`. A short
reply is therefore compared against stale bytes left in the pooled buffer by whatever used
it last. In practice those usually fail the pattern and the ping correctly reports failure,
so this is a wrong-reason-right-answer rather than a false pass; but the comparison is
reading data that is not part of the reply. `check_ping` checks length first, then content,
with a test for a truncated-but-correct prefix.

**Round-trip time:** `csp_ping` returns elapsed milliseconds. The port does not, and that is
a shape difference rather than a gap — the caller owns the clock everywhere else in this
library, so having one function reach for it would be the odd one out.

**`csp_ping_noreply`** is a fire-and-forget ping; covered by `sendto` with no reply
expected.

**Faithful:** yes, with the length check added on top.

**Rusty:** the two halves are separate modules, so a node that only answers does not link
the client and vice versa. `check_cmp_reply` verifies a reply answers the request that was
sent — `csp_cmp` returns whatever came back on the connection, so a reply to an *earlier*
request is accepted as the answer to this one and then read as the wrong message type.

**Tests:** 14 in `client`, 12 in `service`.

## `csp::iface` + `csp::iflist` + `csp::hooks` — interfaces, the registry, and callbacks

**Rating: faithful in behaviour, rusty in shape.** 34 tests.

### `iface` — the nexthop contract

The C's contract is conditional ownership: `csp_send_direct_iface` frees the packet
**only when `nexthop` returns an error** (`csp_io.c:285-295`), so a driver owns the packet
on success and must not free it on failure. Undocumented and uncheckable; getting it
backwards double-frees. `Transmit::transmit` borrows, so the caller frees either way and
the rule cannot be got wrong. Verified by a pool-accounting test across both outcomes.

Header prepending moved from the driver into `Interface::send`. In the C it is each
driver's job (`csp_id_prepend`) and a driver that forgets transmits a zero-length frame —
which is exactly what the golden-vector oracle did until it was fixed, producing 92 empty
SFP vectors.

**Counters — all ten checked against their C increment sites.** Six were already right.
Four were not:

- `rx_error` and `autherr` had no way to be incremented at all. `security.rs` computed
  which counter a refusal belonged to and nothing applied it. Now `note_refusal` routes it
  through `Refusal::counter()`, making one rule of what the C spreads across six call
  sites in `csp_route.c`.
- `irq` is never written anywhere in libcsp (deviation 21) yet is telemetered. Kept, with
  `note_irq` so a driver can mean something by it.
- `txbytes`/`rxbytes` count the frame here, not the payload (deviation 22), consistently
  on both sides so they stay comparable.

`csp_if_udp_tx` returning `CSP_ERR_NONE` unconditionally (deviation 23) is the silent-success
pattern again; `Transmit` returning `Result` is what makes the honest answer expressible.

### `iflist` — the registry

Two errors were wrong before this pass and are now precise: a duplicate name returned
`TableFull` (it is not a full table — `DuplicateName { name }`), and removing an unknown
index returned `NoTransferInProgress` (`NoSuchInterface { index }`). Both were the
"returning weird error codes" the error-enum rework was supposed to eliminate, surviving
because nothing had tested the failure paths.

Two lookups were missing and are now present:

- `find_by_broadcast` (`csp_iflist_get_by_broadcast`) — decides whether an inbound packet
  is a subnet broadcast this node should accept though it is not addressed to it.
- `check_default` (`csp_iflist_check_dfl`) — if nothing is marked default, mark
  everything except loopback. Worth stating plainly because of how it composes with the
  routing fix below: **a node with no routes and no configured default floods every
  packet onto every interface.** That is libcsp's intent for a zero-config node, not a
  defect, but it is not what the code looks like it does.

`csp_iflist_add`'s list-truncating re-add (deviation 20) is unrepresentable here — the
list is an array of slots and `add` mutates nothing before it has decided to accept.

### The routing fix this audit turned up

Reading `csp_send_direct` for the nexthop contract exposed something larger, in `node`:
**the C does not pick one destination.** It collects every routing-table entry tied for
the longest prefix and sends a **clone to each**, the last getting the original; if no
route matched at all, it does the same over every default-marked interface
(`csp_io.c:209-240`). Both redundant links and broadcast-to-all-interfaces are configured
this way. The port resolved to a single destination, silently making both single-path —
a node with two routes to the same subnet for redundancy would have been using one of
them, with nothing to indicate the other was idle.

`Node::resolve` now returns a `Destinations` set with `clones_needed()`, applying split
horizon to both the table and the default fallback, and preserving the C's ordering rule
that a table match suppresses the default fallback entirely — even when split horizon
leaves that match unusable, because the C returns as soon as `route_found` is set. Six
tests cover the policy. `route_from` keeps the single-destination convenience shape and
documents when it is not enough.

### `hooks`

Fourteen of libcsp's fifteen hooks now have a counterpart. The four that were missing:

- `csp_cmp_memcpy`, `csp_cmp_memread64`, `csp_cmp_memwrite64` → `Hooks::mem_read` /
  `mem_write`, **defaulting to refusing**. This is the most security-relevant finding in
  the whole audit (deviation 19): libcsp's default is an unvalidated `memcpy`, so peek and
  poke give arbitrary read and write to any peer, and the function provided to fix that has
  an empty body. A test pins the refusal, and a second shows the shape a node that really
  wants the service should use — one bounded region, with the offset subtraction checked so
  an address below the base cannot wrap into a huge one.
- `csp_panic` → deliberately absent. Rust's `#[panic_handler]` is the application's
  already; a hook would be a second, weaker way to say the same thing.

The duplicate `__weak csp_input_hook` (`csp_route.c:106` and `csp_bridge.c:19`,
byte-identical, link-order dependent) remains unrepresentable: a trait method cannot be
defined twice.

## `csp::node` — the application API

**Rating: faithful, and rusty where the C's shape was the problem.** 46 tests.

All 46 public functions in `csp.h` are now accounted for: 40 have a counterpart, three
(`csp_cmp_set_memcpy` and friends) are no-ops in the C replaced by the `Hooks` trait, and
three (`csp_bind_callback`, `csp_conn_print_table`, `csp_hex_dump`) are deferred by
decision. Four were genuinely missing and this pass closed three of them.

### What was missing

- **`csp_ping_noreply`** — one 0x55 byte to the ping port, fire and forget. Not a
  degenerate ping: it is what you send when the *reply* path may not work, after a radio
  reconfiguration say, and the useful signal is whether the node reacts at all. Added, with
  a test that the server still answers it correctly so the two halves cannot drift.
- **`csp_listen`** — no counterpart, and none needed: the backlog is a const generic, so
  the number lives where the storage does rather than being accepted and discarded
  (deviation 24).
- **`csp_socket_close`** — this one mattered. `unbind` cleared a flag and stopped.

### The bug `unbind` was hiding

Clearing the bound flag stops *new* connections. It does nothing about connections created
before the unbind, which stay in the accept backlog holding pool buffers. Following that
led to a worse one, in code that had nothing to do with unbinding:

**The accept backlog holds handles, and the idle sweep closes connections underneath
them.** A connection that timed out before anyone accepted it left a stale handle in the
backlog, so `accept()` returned a handle that every subsequent call rejected — the caller
learns the connection is dead by being told so once per method. `purge_dead_accepts` now
runs after any sweep that closed something, and after `unbind`. Two tests cover it.

### Two slot leaks in my own code

`Table::close` and `Table::expire_idle` both took a packet index out of a connection's
receive queue and **discarded it when the report buffer was full** — `if n < drained.len()`
guarded the write but not the `take()`. A slot removed from the queue and not reported is
a slot nobody releases; the pool never gets it back. This is the same shape as the
`TxQueue::poll` defect the RDP audit found, which is the argument for auditing every
module rather than the ones that look risky.

`close` now refuses up front with `BufferTooSmall { needed }`, before anything is taken.
`expire_idle` and `close_port` stop at the connection they cannot report and leave it for
the next sweep — one slot held for one tick, rather than one slot lost permanently.

### Route resolution

The fan-out fix from the interface audit lands here: `Node::resolve` returns every
destination, `route_from` keeps the one-destination convenience shape. Documented in the
`iface` section above.

### Still faithful, deliberately

- `accept` does not block. `csp_accept` takes a timeout and sleeps; here the caller owns
  the thread, which is what makes the crate usable from a bare interrupt loop.
- `transaction` takes a clock closure rather than a fixed `now`. An earlier version took a
  timestamp and advanced it by one per iteration, which is not a transaction but a
  simulation of one.
- RDP option defaults match the C's compiled-in values exactly, pinned by a test
  (deviation 26). They are per-connection here rather than six process-wide statics.

## Differential fuzzing — extending it past the codecs

**19 differential tests**, up from 12. The additions are the modules where the port is a
*rewrite* rather than a transliteration, because those are the ones where nothing forces
the two implementations to agree.

### CFP 2 — the CSP v2 CAN identifier

Two tests. The important one runs the real `V2Fragmenter` over random ids and payloads and
reads every frame's CAN identifier back through the C's macros. Comparing constants would
not have done: an offset or mask typo in `base_id` corrupts every v2 CAN frame the node
sends, and a round-trip against our own reassembler would pass, because both sides would
be wrong the same way.

### Routing table — the strongest test here

The parser is a full rewrite: no `sscanf`, no VLA. Two thousand random tables are parsed
by both sides, and for every table both accept, all 32 addresses are looked up in both and
compared — interface and via. That found nothing, which is the useful outcome for the piece
of code with the least shared structure.

It did find two things about the C, both now pinned by their own tests:

- **A one-character entry ends the parse and it reports success** (deviation 27).
  `while (str && (strlen(str) > 1))` is the loop condition, not a skip. `"1 CAN,2,3 KISS"`
  installs one route and returns a positive count. **A comment in `rtable.rs` claimed the
  C skipped such entries; it does not, and the comment is corrected.**
- **The 100-character truncation costs different things depending on where it lands**
  (deviation 28). Mid-entry, the fragment fails to parse and the whole table is rejected —
  a valid table refused for being long. On a separator, everything that fits parses, a
  positive count comes back, and the dropped tail is never mentioned.

### KISS — driving the real `csp_kiss_rx`

The shim replaces only `csp_qfifo_write`, so the actual state machine runs. This cost more
than the others (the buffer pool and the POSIX queue shim come with it) and was worth it,
because it surfaced something the unit tests could not:

**`CSP_ENABLE_KISS_CRC` defaults to ON, so a KISS frame without a trailing CRC32 is
dropped by any stock C peer** — with `iface->frame++` as the only trace. No log, no error,
nothing on the wire. A node whose frames all disappear this way is indistinguishable from
one with a dead UART. `kiss::encode`'s documentation said the CRC was used "if one is in
use", which is true of the format and misleading about the deployment; it now says what
the default actually requires.

Two tests: frames the port encodes arrive at a C node with the same id and payload, both
wire versions, payloads biased hard toward `FEND`/`FESC`; and a corruption test — take a
valid frame, flip a bit or inject a delimiter or truncate it, and assert the C never
delivers a payload other than the one that was sent.

Random byte streams turned out to be the wrong tool for this decoder: with the CRC gate,
arbitrary bytes are rejected essentially always, and a test that never reaches acceptance
tests nothing. Two intermediate versions of that test asserted properties that held
vacuously; the assertion counting how many streams reached the decoder is what caught it,
and is why every generator here now carries one.

## API shape review

Held until last on purpose: the shape of an API that does the wrong thing is not worth
arguing about. With all fifteen modules audited and the differential suite green, two
problems were left, both of the kind that only shows up when you read the surface as a
whole rather than one function at a time.

**`Destinations` handed back `&[(u8, u16)]`.** Interface index and next hop, both small
unsigned integers, in an unnamed pair — so `for (via, iface) in d.as_slice()` compiles and
routes every packet to the wrong place. Now a named `Destination { iface, via }`. This is
in the hottest path in the crate and was introduced by the routing fix in this same audit
round, which is a fair illustration of how quickly the shape degrades when you are
concentrating on behaviour.

**Five accessors to describe one connection.** `conn_src`, `conn_dst`, `conn_dport`,
`conn_sport`, `conn_opts` — the C's five calls, transliterated. Each is separately
fallible, so a caller logging a connection makes five lookups and unwraps five results,
and a connection that closes between the first and the fifth yields a description that
never existed. `conn_info` returns all of it from one lookup with one error; the
individual accessors stay for callers that want a single field. A test pins the two
against each other so they cannot drift.

Everything else survived the review. In particular the decisions that looked most
questionable when they were made held up:

- **`accept` does not block.** The C takes a timeout and sleeps. Non-blocking is what lets
  the crate run from a bare interrupt loop, and a caller that wants blocking has a clock.
- **`transmit` borrows the packet.** The C's conditional ownership — nexthop owns it on
  success, must not free it on failure — is uncheckable and every driver has to get it
  right. Borrowing makes the question not arise.
- **`Delivery::{Datagram, Stream}` decided per packet rather than per port.** The wire
  carries `CSP_FFRAG` on every packet; making the registrant choose in advance is what
  makes the C free a perfectly good packet and report an SFP error.
- **Errors carry their context.** `BufferTooSmall { needed }`, `DuplicateName { name }`,
  `NoSuchInterface { index }`, `AddressRefused { addr }`. Two of those replaced codes this
  audit found being reused for unrelated conditions — `TableFull` for a duplicate name and
  `NoTransferInProgress` for an unknown index — which had survived because nothing tested
  the failure path.

## Test-suite audit (2026-08-25)

All 465 tests as they stood at the time of this audit, reviewed against ten criteria.
Findings, measured rather than eyeballed. (`just numbers` prints the current total; it is
larger now, and this figure is deliberately left as the audit's own denominator.)

### Fixed

| # | Criterion | Finding |
|---|---|---|
| 1 | Vacuous | **`dedup`'s fuzz test fired the duplicate branch 0 times in 50 000.** It passed a *random* `u32` as the timestamp, so two sightings of the same bytes were never within `DEDUP_WINDOW_MS` — structurally it could not detect a duplicate however the frames were generated. It therefore only ever exercised the "not a duplicate" path, in the module whose entire job is the other one. Now advances a monotonic clock, replays every fourth frame, and asserts **both** branches fire. Not a coverage hole — `an_identical_frame_inside_the_window_is_a_duplicate` covers the positive case — but the test claimed far more than it delivered. |
| 1 | Vacuous | **No fuzz test asserted its own reach.** Measured: `service` answers **1139 of 50 000** random requests (2.3 %); `kiss` completes **83 frames in 200 000 bytes**; `cmp` decodes ~140 000 of 160 000; `eth` 100 000. None is vacuous today, but nothing stopped a stricter decoder taking any of them to zero silently — which is precisely how a KISS fuzz test here once ran against no input at all. All four now assert a floor, with the measured value in the comment. |
| 8 | Shared state | **`LOCK.lock().unwrap()` turned one failure into a cascade.** A panicking test poisons the mutex and every later test reports `PoisonError` instead of its own result. This happened during the route-table work and sent the investigation at the wrong test first. Replaced with a `lock()` helper that recovers; the C state a panicking test leaves behind is re-established by the next `setup`. |
| 10 | Name overclaims | `arbitrary_traffic_never_panics` → `arbitrary_traffic_hits_both_the_duplicate_and_the_fresh_path`; `decoding_arbitrary_bytes_never_panics` → `..._and_still_decodes_some`. Both now assert what the name says. |

### Checked, and clean

- **C6 impossible test data** — swept every `Version::V1` test for addresses above 31 and found none. The `dst=99` / `flags=0xff` class of error was fixed earlier and has not returned.
- **C7 nondeterminism** — zero uses of `Instant::now`, `SystemTime`, `thread::sleep` or unseeded randomness. Every fuzz test is a seeded xorshift, so a failure reproduces from its seed.
- **C5 no teeth** — the three `is_to_me` tests were verified by temporarily restoring the old code; all three fail without the fix. The forwarding tests were verified the same way last cycle.
- **C3 internals** — the nine flagged were false positives (`.len()` on a `Vec`) except `rdp`'s state fuzzer, which sets `c.state` directly to reach all five states. That is reachability, not an assertion about internals, and there is no other way in.
- **C9 weak assertions** — the two flagged (`frame_is_empty_until...`, `clear_empties_the_table`) assert exactly the property under test. False positives.
- **C2 artefact vs behaviour** — every forwarding test now compares the interface as well as the frame, fixed last cycle after a byte-only comparison passed while the port used the wrong link.

### Fixed since — the structural one

**As written, at the time of the audit: `rdp` (49 tests), `cmp` (27), `eth` (22) and `security` (13) had no external oracle at all.** No golden vectors, no differential test against the C. 111 tests — a quarter of the suite — verified only against my own reading of the C.

**That is no longer true.** `ctest/` builds a real libcsp node and records what it does;
all four modules now have corpus records replayed against the port (`just numbers` prints
the current count per suite — at the time of writing, `cmp` 27, `security` 17, `eth` 16,
`rdp` 8). The C oracle found a defect on nearly every pass over them, which is what the
paragraph below predicted.

`rtable` was the last module with neither a golden vector nor a corpus record — its parser
is the only way a route reaches a flying node from the ground — and now has six. Every
module in `csp-core` has an external oracle.

The original reasoning, kept because it was right:

That is the same shape as the node layer before the C-node harness existed, and the node layer turned out to contain a total functional failure (`Router::forward` destroying every packet) plus two precedence bugs. `rdp` is the largest module in the port and implements a reliability protocol; `security` is the authentication gate. Neither had ever been run against libcsp.

`rdp` and `security` are reachable from the existing node harness — the C node links `csp_rdp.c` already. `cmp` needs `csp_service_handler` wired to a bound port. `eth` needs no node at all, only a codec-level shim like the CFP one.

All four were done that way, and the prediction held: the oracle found the CMP server
missing entirely, an RDP node that acknowledged nothing it delivered, and a handshake that
left a gratuitous ack owing. Each is written up in `SCOPE.md`.
