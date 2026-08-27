# Scope lock

What gets ported, what is feature-gated, what is deliberately dropped. This is the
completeness checklist every port branch is measured against.

Source of truth: the `libcsp` submodule at `13a8c841` (`v2.1-139-g13a8c841`), the
`move-iii` branch of `xarantolus/libcsp`. Not upstream — the fork is what flies, and its
`unittests/` are part of the oracle.

## Canonical C configuration

c2rust sees exactly one preprocessor configuration, so it has to be pinned. Everything
optional is turned **on**, because a feature that is off is a feature that does not get
ported:

```sh
cmake -S libcsp -B build/canonical -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
  -DCSP_USE_RDP=ON -DCSP_USE_HMAC=ON -DCSP_USE_PROMISC=ON -DCSP_USE_RTABLE=ON \
  -DCSP_HAVE_STDIO=ON -DCSP_ENABLE_CSP_PRINT=ON -DCSP_PRINT_STDIO=ON \
  -DCSP_BUFFER_ZERO_CLEAR=ON -DCSP_ENABLE_KISS_CRC=ON \
  -DCSP_BUILD_SAMPLES=OFF -DCSP_ENABLE_PYTHON3_BINDINGS=OFF
```

Note `CSP_USE_RTABLE` defaults to **OFF** upstream; it is forced on here so the routing
table and its string parser are in the transpile.

Yields **71 translation units**. The library and `unittests/csp_tests` both build clean,
and the C suite is **20/20 green** — that is the baseline every port is diffed against.

Two things the compilation database must preserve, or the transpile silently changes
meaning: `-I src` (because `src/endian.h` shadows the system `<endian.h>` via
`#include_next`), and the per-file `_DEFAULT_SOURCE` on `csp_rdp.c`.

**Environment gap:** libyaml is not installed, so `csp_yaml.c` is absent from the
database. It is not blocking — the YAML support is being written as a Rust parser
regardless (see below) — but it means there is no C oracle for it, so its tests are
written against the format, not differentially.

## Sizing constants

These become const generics on `CspStorage`, not compile-time constants:

| Constant | C default | Notes |
|---|---|---|
| `CSP_BUFFER_COUNT` | 15 | flight config uses 64 |
| `CSP_BUFFER_SIZE` | 256 | flight config uses 256 |
| `CSP_CONN_MAX` | 8 | flight config uses 16 |
| `CSP_CONN_RXQUEUE_LEN` | 16 | flight config uses 32 |
| `CSP_QFIFO_LEN` | 15 | flight config uses 100 |
| `CSP_PORT_MAX_BIND` | 16 | flight config uses 48 |
| `CSP_RDP_MAX_WINDOW` | 5 | |
| `CSP_RTABLE_SIZE` | 10 | |

## Core — always compiled, no feature gate

| C source | Rust home | Notes |
|---|---|---|
| `csp_init.c` | `Node::new` / `Config` | the global `csp_conf` becomes a field |
| `csp_io.c` | `csp/io.rs` | send / recv / sendto / transaction |
| `csp_conn.c` | `csp/conn.rs` | connection pool; the one real CAS becomes `AtomicU8` |
| `csp_port.c` | `csp/port.rs` | port table; **fixes the `.bss`-reliance re-init leak** |
| `csp_qfifo.c` | `csp/qfifo.rs` | router input queue |
| `csp_route.c` | `csp/route.rs` | `route_work` — must not report idle as an error |
| `csp_buffer.c` | `csp/pool.rs` | **redesigned**: index-based slots, offset instead of `frame_begin`, `AtomicU8` refcount |
| `csp_id.c` | `csp-core/id.rs` | v1 + v2 header codec — **published**; three consumers hand-roll this today |
| `csp_iflist.c` | `csp/iflist.rs` | incl. aliases and subnet lookup |
| `csp_service_handler.c` | `csp/service.rs` | built-in service ports; `respond_cmp` is `csp_cmp_handler` plus the reply-or-discard decision around it |
| `csp_services.c` | `csp/client.rs` | ping / uptime / memfree / buf_free / reboot / shutdown / ps |
| `csp_crc32.c` | `csp-core/crc32.rs` | CRC32-C — **published**, the Python ground tooling needs it |

## Feature-gated — all default-on except where noted

| Feature | C sources | Notes |
|---|---|---|
| `rdp` | `csp_rdp.c`, `csp_rdp_queue.c` | 1022 lines, 30 gotos → `fn step(&mut self, ev, now) -> Action` |
| `sfp` | `csp_sfp.c` | fragmentation; drives the `Delivery::Stream` half of the port API |
| `cmp` | `cmp/*.c` (7 files) | client **and parser** — the C has no decoder, so `csp-sniff` reimplements the wire format |
| `hmac` | `crypto/csp_hmac.c`, `csp_sha1.c` | |
| `promisc` | `csp_promisc.c` | |
| `dedup` | `csp_dedup.c` | |
| `bridge` | `csp_bridge.c` | |
| `rtable` | `csp_rtable_cidr.c`, `csp_rtable_stdio.c` | parser rewritten in Rust — **no `sscanf`, no VLA, no C-primitive shim** |
| `yaml` *(off)* | `csp_yaml.c` | Rust parser, same inputs. No C oracle available here |
| `print` | `csp_debug.c`, `csp_hex_dump.c` | replaces the variadic `csp_print_func` and the 10 non-atomic counters |
| `if-can` | `csp_if_can.c`, `csp_if_can_pbuf.c` | CFP fragmentation + reassembly |
| `if-kiss` | `csp_if_kiss.c` | framing, incl. the legacy KISS CRC |
| `if-i2c` | `csp_if_i2c.c` | |
| `if-eth` | `csp_if_eth.c`, `csp_if_eth_pbuf.c` | incl. the ARP table |
| `if-udp` *(std)* | `csp_if_udp.c` | needs sockets, gated on `std` |
| `if-tun` | `csp_if_tun.c` | carries the two `csp_crypto_*` hooks |
| `alloc` *(off)* | — | enables `read_to_vec` and friends. The crate works fully without it |
| `std` *(off)* | — | host conveniences only |

Loopback (`csp_if_lo.c`) is core, not gated — but `csp_if_lo.addr` stops being a mutable
global and becomes a `loopback_to_self()` call.

## Out of scope, deliberately

| Dropped | Why |
|---|---|
| `src/arch/{posix,freertos,zephyr}/` | Replaced by `trait Platform`. The whole point: 16 C shim functions become associated types (`Mutex`, `Queue`, `Sem`) plus a clock |
| `src/drivers/` (socketcan, zephyr CAN, usart linux/zephyr, eth_linux) | Platform drivers, not protocol. The *interface logic* they feed is in scope; the syscalls are not |
| `csp_if_zmqhub.c` | Needs libzmq. No flight relevance, and it drags `calloc` + pthread mutex into the core |
| `csp_id_{prepend,extract,strip}_fixup_cspv1` | The little-endian CSP v1 header variants. Verified by grep that their only callers are `csp_if_zmqhub.c:88,137`, so they leave with ZMQ |
| `src/bindings/python/pycsp.c` | Out of scope by definition |
| `examples/`, `samples/` | Rewritten as Rust examples where useful |

## Implementation status

An early version of this section claimed full coverage by comparing *module names* against
the goal's list, which is not the same thing and was wrong: 91 had no counterpart, ~35 of
them genuinely missing — including the whole application-facing socket API. Those 35 were
built, and then every module was audited against its original function by function (see
`AUDIT.md`), which found more: the default-interface routing fan-out, the three CMP memory
hooks, `csp_socket_close`, `csp_ping_noreply`, and four interface counters that had no way
to be incremented.

### The denominator

`just api-surface` prints it. On the canonical configuration pinned above:

```
exported from the canonical build   229
declared in include/csp/**.h        201
  both                              171
  declared, not in this build        30   ZMQ, yaml, drivers this build leaves out
  exported, not a public header      58   internal to src/ — csp_qfifo_*, csp_conn_*, csp_rdp_*
```

**This section previously said 186, and that number is not reproducible by either method.**
It was recorded as "`nm -D` on the built C library plus a header scan" with no command, so
there is no way to recompute it or to find out which of the two it meant. It also carried a
four-row split — 140 covered, ~40 out of scope, 6 replaced, ~5 absent — summing to 191
against a stated total of 186, with two of the four rows approximate. A table that does not
add up and cannot be recomputed is worse than no table: it reads as a measurement and
behaves as a memory.

So it is gone rather than corrected. What replaces it is the reproducible denominator above
and the per-area status table below, which names *where* each area lives and can be checked
by opening the file. Coverage of the 229 is not currently measured function by function;
saying so is the honest position, and re-establishing it is a piece of work in its own
right rather than a number to assert here.

### Absent by decision

| What | Why |
|---|---|
| `print` — `csp_print_func`, `csp_hex_dump`, `csp_conn_print_table` | A variadic formatter and ten non-atomic global counters. A `no_std` crate has no business owning either; the caller has `defmt`, `log`, or nothing, and `Stats` is already a struct it can print however it likes |
| `csp_bind_callback` | Binds a bare `fn` to a port, bypassing the connection layer. Every consumer surveyed used `bind(CSP_ANY)` + `accept` + a dispatch table instead, and a callback that cannot own a connection cannot answer a stream |
| `yaml` | libyaml is not installed in this environment, so there is no C oracle to check a Rust parser against. Feature-gated and stubbed rather than written blind |
| `if-tun` | Needs the two `csp_crypto_*` hooks, which exist as `Hooks::encrypt`/`decrypt`; the interface itself is a Linux TUN device and belongs with the platform drivers that are out of scope |

### Implemented

Where each area lives, and whether it is reached from the node. Two rows are not plain
"done" and say so; treat any row here as a claim to check rather than a result.

| Area | Where | Status |
|---|---|---|
| Core (io, conn, route, qfifo, port, buffer, id) | `csp/{pool,conn,qfifo,router,iface}.rs`, `csp-core/id.rs` | done |
| RDP | `csp-core/rdp.rs` + `csp/router.rs::deliver_rdp` | **server side only** — the node answers a handshake and delivers data; it cannot yet *open* a connection or retransmit — see below |
| SFP | `csp-core/sfp.rs` + `csp/delivery.rs` | done |
| CMP | `csp-core/cmp.rs` — client **and** decoder | done |
| Crypto | `csp-core/{crc32,sha1,hmac}.rs` | done |
| Promisc | `csp/router.rs` tap | done |
| Dedup | `csp/dedup.rs` — all four `csp_dedup_types_e` modes, checked against the C | done |
| Bridge | `csp/router.rs::bridge_work` | done |
| Routing | `csp-core/rtable.rs` + `csp/route_policy.rs` — one implementation of `csp_send_direct`'s policy, used by `Node::resolve` (send), `Router::forward` (transit) and the RDP reply path | done |
| Socket / client API | `csp/node.rs` — connect, bind, unbind, accept, read, send ×4, recvfrom, transaction, close | done |
| Interface registry | `csp/iflist.rs` — add/remove, lookup by name/addr/subnet/broadcast, `check_default`, aliases | done |
| Client service calls | `csp/client.rs` — ping, ping_noreply, ps, reboot, shutdown, memfree, buf_free, uptime, CMP requests | done |
| Hooks | `csp/hooks.rs` — 14 of the C's 15, incl. the CMP memory hooks; every fallible default refuses | done |
| Interface counters | `csp/iface.rs` — all ten, with `note_refusal` routing a security refusal to the right one | done |
| CAN / CFP | `csp-core/cfp.rs` (CFP1 + CFP2) | done |
| KISS | `csp-core/kiss.rs` | done |
| Ethernet / EFP | `csp-core/eth.rs` | done |
| I2C, LOOP, UDP | `csp/iface.rs` | done — each is a datagram interface, so the whole protocol logic is `Interface::send` + `Packet::set_frame`. Proven by a loopback round-trip test, not asserted |
| Built-in services | `csp/service.rs` | done |

### The RDP acknowledgement policy: one gratuitous difference, one deliberate

Three divergences in `csp_rdp_should_ack` were predicted from reading in the plan for this
suite. `ctest/suite_rdp.c` settles two of them by measuring what reaches the wire — the
sequence numbers are how the decision is computed, not the behaviour, so what is counted is
acknowledgement *frames*.

**Measured, with `ack_delay_count = 2` and five in-order packets:** the C sends
acknowledgements `[0, 0, 1, 1, 1]` — nothing until the third packet.

**1. The off-by-one was real, and the port was wrong.** `csp_rdp_should_ack` tests
`csp_rdp_seq_after(rcv_cur, rcv_lsa + ack_delay_count)`, which is *strictly* after, so the
acknowledgement fires once the outstanding count **exceeds** the delay — at count + 1. The
port used `>=` and fired one packet early: 50% more acknowledgements at the default count of
2. Not a correctness difference, and not worth having, so it now matches. A `>=` here is the
kind of difference that looks like nothing and costs power on the one link that has none to
spare.

**2. The "nothing to acknowledge" guard stays, as a recorded divergence.** With delayed acks
off, the C's first condition returns `true` unconditionally, so `csp_rdp_check_ack` transmits
an acknowledgement for a sequence number the peer already has. Measured: one frame, for
nothing. The port returns `false` when `rcv_cur == rcv_lsa`. A peer that does not receive a
redundant acknowledgement loses nothing, and the frame is not free.

Corpus case: `rdp::an_ack_is_sent_even_with_nothing_to_acknowledge`. A test asserts that
every `diverges` record names itself here, so a divergence cannot be recorded without a
reason a reader can find.

This is the **first record in the corpus carrying the `diverges` verdict**, so the machinery
that has been in `csp/tests/corpus.rs` since the security suite is now exercised: the arm
asserts `assert_ne!`, and removing the port's guard makes the run fail with *"recorded as a
deliberate divergence but now matches the C"*. Verified by mutation, not by inspection.

**3. The receive-queue gate is real, and unreachable at the test sizes.**
`csp_rdp_check_ack` opens with

```c
if (abs(CSP_CONN_RXQUEUE_LEN - csp_queue_size(conn->rx_queue)) < window_size) return;
```

— acknowledge only while there is room for a full window still to arrive. That is
receiver-side flow control: an unread connection stops *inviting* data rather than accepting
it and dropping it. `poll_ack` has no equivalent.

Measured with the application never reading: **12 delivered, 12 acknowledged, the gate never
fired.** It suppresses at a queue depth above `16 − 4 = 12`, and the node exhausts its
**15** buffers at 12 delivered.

**That conclusion was wrong, and the wrongness was in the word "cannot".** The gate cannot
trigger *at those numbers* — window 4. Proposing a window of 5 moves the threshold to 12,
which the same pool reaches: 13 delivered, 11 acknowledged, the 12th onward silent. The port
had no gate and, worse, acknowledged before attempting the enqueue; against a real C peer it
promised four packets it then dropped. Both are fixed and the section below records it.
`poll_ack` now has an equivalent, so the sentence that followed this one — "the port's
missing gate is not a behavioural difference at all" — is doubly obsolete.

At the flight sizes it is. `CSP_BUFFER_COUNT` 64 with `CSP_CONN_RXQUEUE_LEN` 32 and a
window of 4 gates at a depth above 28, reachable long before 64 buffers are gone. So this is
a divergence that is invisible in every test build and present in the one that flies, which
is a good reason it has never been observed.

The replay says so out loud rather than passing quietly: it asserts that the recorded depth
stayed below the gate, and fails with *"the oracle reached a queue depth where the gate
fires … so this replay is no longer a no-op"* if the oracle is ever built with the flight
sizes. Closing the gap in the port is [task #126]'s neighbour, not this suite's job.

### Ethernet reassembly was missing three of the C's nine guards

Found on 2026-08-25 by `ctest/suite_eth.c`, which drives `csp_eth_rx` directly and asserts,
for every refusal, both the counter charged **and** that no pool buffer was consumed. That
second half is the one worth having: a bounds check that refuses a frame but keeps the
packet it allocated turns a stream of malformed frames into pool exhaustion, which presents
as a hang rather than a rejection.

Four of fifteen records diverged. Three were missing guards in `csp-core::eth::Reassembler`:

1. **A zero-length segment was accepted.** It cannot advance reassembly, so a peer sending
   nothing but those holds a transfer open forever without ever failing — a stall, which is
   harder to diagnose than an error.
2. **Only the per-segment extent was bounded, never the running total.** `csp_eth_rx`
   checks `rx_count + seg_size` against the declared length; the port checked
   `offset + len`. Segments that each fit on their own can still add up to more than the
   packet claimed, and the second silently overwrote the first.
3. **A declared length larger than the buffer was accepted on the first segment** and only
   failed later, if a segment happened to reach that far. The C refuses it up front. Fixed
   sans-io: the caller's `out` buffer *is* the bound, so a transfer that can never complete
   is rejected before it occupies the reassembler.

The fourth was a floor on the declared length — `csp_eth_rx` refuses anything shorter than
`csp_id_get_header_size()`, since it would be reassembled and then routed on whatever
followed. That size depends on the wire version, which this module has no other reason to
know, so `Reassembler::with_min_len` takes it and `new()` stays for a caller that does not
care.

**One divergence turned out to be the harness.** The replay used a 512-byte buffer where the
C's bound is `CSP_BUFFER_SIZE`, which made the port look permissive when it was only better
provisioned. The replay now sizes its buffer to the oracle's.

### EAK: a flag the port defined and never read

2026-08-26. The last RDP flag with no test on either side. `csp-core` declared `EAK = 0x02`
and never looked at it; `csp_rdp.c` acts on it twice.

**A peer could hand the application data by flagging it as acknowledgement.**
`csp_rdp.c:712` treats an extended acknowledgement as acknowledgement only — `snd_una` moves,
the retransmit counter clears, then `goto discard_open` throws the packet away *including any
payload*. The port took the payload branch first, so a packet carrying `ACK|EAK` and a body
was delivered to the application as an ordinary message, and answered. Measured: the C
delivers 0 bytes and sends nothing; the port delivered 2 and replied `ACK`. Now
acknowledgement-only, matching.

**The C's own comment is wrong about the other path.** `csp_rdp.c:722` reads *"If message is
not in sequence, send EACK and store packet"*. Measured, it stores and answers **nothing** —
no EAK goes out. I would have implemented the comment.

### The RDP send path, built -- and the C does not stop when it says it stops

2026-08-26. Yesterday's measurement was that the port had no RDP send path at all:
`Node::send` filled in the header and routed, with no trailer, no sequence number and
nothing queued. That half now exists.

- `Connection::begin_send` mirrors `csp_rdp_send`: refuses unless open and the window has
  room (`snd_nxt` no further than `snd_una + window_size - 1`), then stamps
  `seq_nr = snd_nxt`, `ack_nr = rcv_cur`, sets `ACK` and advances. A full window is
  `Error::SendWindowFull` -- where the C blocks on `tx_wait`, a sans-io node reports
  back-pressure and the caller drains `work` and retries.
- `Node::send` appends the trailer, keeps a copy in the connection's `TxQueue`, and routes
  the original.
- `Router::tick` sweeps: release what `snd_una` covers, retransmit what timed out with the
  acknowledgement refreshed to `rcv_cur` ("Update to latest outgoing ACK"), give up past
  `MAX_RETRANSMITS`. Retransmissions leave through `work` as any node-originated frame does.
- `Table::close` drains the transmit queue too -- the third place a connection holds pool
  slots -- and the shared `RXQ` budget now covers all three.

**`rdp::unacknowledged_data_is_retransmitted_then_given_up_on` stays `diverges`, and the
reason is the C.** One packet, never acknowledged:

| | total frames |
|---|---|
| libcsp, `conn_timeout` 20 s | 29 |
| libcsp, `conn_timeout` 5 s | **10** |
| the port | 12 |

The C's total scales with `conn_timeout`, not with `CSP_RDP_MAX_RETRANSMITS`. Measured, not
inferred: halving the connection timeout changes the count. What happens is that
`csp_rdp_check_timeouts` logs "No progress after 10 retransmissions, closing" and calls
`csp_conn_close` -- but on an **accepted** handle that only wakes user-space, leaving the
connection for the application to close. `csp_conn_check_timeouts` keeps sweeping it and
keeps retransmitting, until the CLOSE-WAIT branch finally returns early. The give-up does not
give up.

The port stops at 12: one send and eleven attempts, which is what
`retransmits > MAX_RETRANSMITS` is written to mean. Reproducing the C here would mean
reproducing a retransmit storm past the point the library itself declared the peer dead, on a
link where every frame costs power. Recorded as a divergence with the arithmetic rather than
matched.

**Two records, deliberately.** `a_sent_data_packet_carries_an_rdp_trailer` and
`one_retransmission_after_the_packet_timeout` are `must_match`; the total-frame one is the
`diverges`. That split exists because **a divergence record cannot protect the code it
describes** -- breaking the send path leaves the two disagreeing either way. The mutation
sweep said exactly that: three send-path mutations noticed by nothing until the two
`must_match` records were added.

**A bug the new record caught immediately.** `with_payload_mut` hands the closure the whole
slot and *sets* the length from what it returns. Taking `b.len()` for it stretched every
retransmission to the full 256-byte buffer and wrote the refreshed acknowledgement past the
real trailer. The frame still carried `hello` and a valid header, so nothing but a length
comparison would have seen it.

**Multi-packet sequencing and release-on-acknowledgement**, the two gaps this entry named
when the send path landed, are now measured.
`rdp::three_sends_are_sequential_and_an_ack_releases_them` sends three packets, checks each
takes the next sequence number, then has the peer acknowledge all three at once and waits ten
seconds. Both stacks: sequential, nothing retransmitted, no buffers lost.

The buffer count is not decoration. "Nothing was retransmitted" is *also* true of a node that
drops the queue entry and leaks its buffer, and that is exactly what happened when the
release was tried against the record: breaking `TxAction::Release` changed no frame count at
all, because `poll` clears the entry either way. Only `buffers_lost: 3` sees it. Two of the
three send-path invariants would otherwise have been pinned by nothing:

| broken | caught by frames | caught by buffers |
|---|---|---|
| `snd_nxt` does not advance | yes | — |
| `snd_una` does not advance on the peer's ack | yes | — |
| the acknowledged buffer is never released | **no** | yes |

**The send window, and a claim of mine that was too broad.** This entry said the window had
"no C comparison, because the C blocks rather than returning". Half right. Measured with a
probe under libcheck's timeout: with a window of two, `csp_send` **returns for both packets**
and only the third never comes back -- `csp_rdp_send` loops around
`csp_bin_sem_wait(&conn->rdp.tx_wait, conn->rdp.conn_timeout)` whose only exits need another
thread, so in a single-threaded harness it hangs. The *overflow* is uncomparable; the
*boundary* was comparable all along and I had written it off.

`rdp::a_window_of_two_admits_exactly_two` now pins it: two proposed, two on the wire,
sequential, on both stacks. The two failure directions need different tests, which is why
both exist:

| the bound is | caught by |
|---|---|
| one too small (a window of two admits one) | the record -- one frame instead of two |
| one too large (a window of two admits three) | `the_send_window_bounds_what_may_be_claimed`, because the record only offers two |

Neither catches the other. Only the overflow *call* remains outside the oracle, and that is a
property of the C's threading model rather than something left undone.

### The receive reorder queue is wired in; the transmit queue still is not

2026-08-26. Closing the gap named the day before.

`csp_rdp.c:723` stores an out-of-sequence packet with `csp_rdp_rx_queue_add` and walks the
queue once the hole fills. Measured with `rdp::a_gap_filled_late_delivers_both_in_order` --
`B` sent at `rcv_cur+2`, then `A` at `rcv_cur+1` -- the C hands the application `AB`. The
port handed it `A` and dropped `B`, so one lost packet cost the sender a round trip for every
packet behind it.

`csp-core::rdp::RxQueue` had existed since the port was written, with reorder tests including
the sequence wrap, and **nothing called it**. Now: `Action::Hold(seq)` for a packet inside the
window but ahead of the gap, the router holds the pool slot under that sequence number, and
`release_held` drains in order after each in-order delivery, stopping at the first gap.

Two hazards came with it, both found rather than reasoned about:

- **The held packets were a second place a connection holds pool slots**, and `Table::close`
  drained only the receive queue. A connection torn down mid-gap leaked one buffer per held
  packet. `close` now drains both, and
  `router::a_held_out_of_order_packet_is_returned_on_close` pins it.
- **Sizing.** Draining both into one array would have needed `RXQ * 2`, which Rust will not
  let an array length compute from a generic parameter -- and rewriting the 30 call sites late
  in a cycle is how the next mistake happens. Instead the two queues *share* the `RXQ` budget:
  `hold_rx` refuses once they reach it together. Every existing `[0u16; RXQ]` stays correct,
  and a peer that never fills a gap cannot pin more than one connection's worth of pool.
  `conn::the_two_receive_queues_share_one_budget` pins that, added because the mutation sweep
  reported the cap as noticed by nothing -- and then *rejected the first version of the test*,
  which only held packets and checked it refused eventually. `RxQueue`'s own capacity
  guarantees that much, so it passed with the cap removed. Filling the receive queue first is
  what makes it a test of the shared budget.

**`TxQueue` was unused. That is no longer true, and this paragraph said otherwise for
several cycles.** It has eight call sites in `csp/src/conn.rs` -- `tx_unacked`,
`hold_unacked`, `poll_unacked`, the shared budget, `rdp_handles` -- and `Router::sweep_unacked`
drives retransmission from `tick`. `node_rdp_retransmit.rs` shows a lost packet resent in a
form a real C peer accepts.

The conclusion drawn from the stale claim was wrong with it: libcsp PR #3's fourth item --
freeing packets when an RDP queue is flushed -- *does* have a counterpart. `Table::close`
drains `tx_unacked` alongside the receive and reorder queues, and
`node_rdp_inflight.rs` measures it: three packets in flight, closed underneath, every buffer
back. Dropping that drain loses exactly three. The other three items of that PR are in the
pinned submodule (`1bc00a0f`, an ancestor of `13a8c841`) and are covered by records: the SYN
option-block length check, the parameter clamping, and the retransmit limit.

**A measured difference in *when*, and an open question.** The port releases on close. The C
does not: `csp_conn_close` returns early while the RDP close handshake is outstanding
(`csp_conn.c:230`), *before* both `csp_conn_flush_rx_queue` and `csp_rdp_queue_flush`, so
four buffers stay held immediately after `csp_close`. Its close does reset the peer -- one
`ACK|RST` frame -- but feeding that to the peer and pumping the reply back did not release
them within the exchange.

**The harness can now ask.** `difftest` no longer builds `arch/posix/csp_time.c`; `shim.c`
supplies `csp_get_ms` itself, so libcsp's own timers — RDP retransmission, the connection
timeout, the close-wait timeout — are reachable by assignment instead of by sleeping for
whole seconds. Every existing differential test passes unchanged with the substituted clock.
That capability is the point: "does the C ever free that?" was previously a question this
harness could not put.

What it answers, measured: **it does not, within 32 virtual seconds of a 10 s connection
timeout.** Free buffers stay at 11 of 15 throughout. One of the two open connections does
close at +16 s; the survivor's `timestamp` is refreshed to that moment and then stops
advancing, so its close-wait deadline is measured from a baseline that moved.

What is **still not established**, and deliberately not asserted: whether that is a genuine
libcsp leak or an artefact of this harness driving only one end of the close. Both branches
in `csp_rdp_check_timeouts` that would release it (`csp_conn.c` CONNECTION TIMEOUT at
`csp_rdp.c:357`, CLOSE-WAIT at `:370`) call `csp_conn_close` a second time, which should get
past the `CSP_ERR_AGAIN` early return — so the mechanism exists and something is preventing
it firing. Characterising that means going further into libcsp than a done-check on the port
warrants. Recorded with its numbers and conditions so it can be picked up deliberately,
rather than as "the C leaks four buffers", which is the claim the evidence does not yet
support.

### One spoofed RST dropped the link — the port had no blind-reset defence

2026-08-26. Thirty tests in `suite_rdp.c` and not one sent a reset: teardown was the half of
the protocol nothing measured, on either side.

`csp_rdp.c` honours a reset only **in sequence** — `rx_header->seq_nr == conn->rdp.rcv_cur +
1`. Then it moves to CLOSE-WAIT, answers `ACK|RST`, and `discard_close`s into
`csp_conn_close`, which releases what the connection was holding. An RST with any other
sequence number takes the branch spelled *"RST out of sequence, keep connection open"*.

`Connection::on_packet` honoured **any** reset, in any live state, and answered nothing.
Three defects, worst first:

1. **A blind reset dropped the connection.** An injector who could put a CSP packet on the
   wire with the right addresses and ports — and no knowledge of the sequence number — ended
   the link with one frame. On a spacecraft that is a pass terminated by a single spoofed
   packet. `rdp::an_out_of_sequence_rst_is_ignored` measures it: against the C the next data
   packet still gets a plain `ACK`; against the port as it stood, nothing came back at all.
2. **An in-sequence reset was never acknowledged.** The C replies `ACK|RST` so the peer
   learns its close arrived; the port closed silently.
3. **In CLOSE-WAIT the C answers everything with `ACK|RST`** (`case RDP_CLOSE_WAIT`, "Send
   back a reset"); the port said nothing, leaving a peer that kept transmitting with no
   indication the connection was over.

The records compare flags rather than booleans, because "something came back" cannot separate
an `ACK` on a live connection from an `ACK|RST` on a dead one — the first version of this test
did exactly that, and also read `tx_flags` after a case where nothing was sent, reporting the
handshake's stale `SYN|ACK` as the reply to a reset.

**A fourth unit test asserted the hole.** `rst_closes_from_every_live_state` used `seq_nr: 0`
— out of sequence — and required a close, so it pinned the vulnerability in place and would
have blocked the fix. It is now `a_reset_is_honoured_only_in_sequence` and checks both halves.
That is the fourth test written from my reading of the C that had to be corrected alongside
the code it was guarding, and the second in two days.

**The sweep caught a coverage regression in the fix itself.** Routing an established reset to
`SendControl` left the `Action::Closed` arm's drain reachable only by connections with nothing
queued, so `drain: the rst path sizes by RXQ` silently stopped testing anything. Re-pointed at
the new drain, where `router::a_reset_connection_returns_every_buffer_it_held` notices it.

**Not reproduced, and said so rather than added from reading:** in CLOSE-WAIT the C
range-checks `ack_nr` against the send window before replying and discards silently if it is
outside. No record distinguishes that, so the port does not implement it.

### The port reaped idle RDP connections; libcsp does not

2026-08-26, from the one gap the untraced sweep left open — `conn_timeout` adoption.

I wrote the test expecting to show that a peer's proposed `conn_timeout` closes an idle
connection sooner than the compiled-in default. **The measurement said the connection was
still open and still answering.** `csp_rdp_check_timeouts` guards its CONNECTION TIMEOUT with
`if (conn->dest_socket != NULL)`, and `dest_socket` is cleared the moment the connection is
*announced* to the socket — `csp_rdp.c:695`, "the connection handle has been passed to
userspace" — not when the application accepts it. So that branch only ever reaps a handshake
that never finished. **libcsp does not idle-expire an established RDP connection at all**;
`conn_timeout` survives as the CLOSE-WAIT bound and as the upper bound on `ack_timeout`.

`Connection::step`'s `Event::Tick` closed on `conn_timeout` in **any** state. Two
consequences, and the second is the serious one:

- a connection that is merely quiet — a telemetry link between passes — was dropped while
  the C kept answering on it, so the peer's next packet went unanswered; and
- `conn_timeout` is **proposed by the peer**, so it was a lever a peer could pull to make
  this node discard its own connection early.

Now gated on `state != Open`. Idle expiry as resource management still happens, in
`ConnTable::expire_idle`, against the timeout the *node* chooses rather than one a peer sent.
`rdp::a_proposed_conn_timeout_is_adopted` pins it end to end: 3000 ms proposed, 4000 ms idle,
and the peer still gets an answer.

**Two unit tests asserted the behaviour I removed** — `rdp::idle_connections_time_out` and
`conn::the_router_tick_drives_rdp_timeouts`. Both encoded my reading rather than the C's, and
both would have blocked the fix. The first is now
`only_an_unestablished_connection_times_out` and pins both halves; the second keeps its real
subject (that the tick reaches the timers) and drives it with a `SynSent` connection instead.
That is the third time a unit test written from my reading of the C had to be corrected
alongside the code it was guarding.

### The seventeen untraced C tests, justified one at a time

2026-08-26. `just untraced` reports 142 of 159 C tests recording something. I had been
calling the remainder "legitimate" in the aggregate without checking them individually,
which is the same shape as the coverage claims this file exists to correct. Each is now
either covered elsewhere, structurally inapplicable, or named as a real remaining gap.

The table below is **checked**, not merely written: `untraced.py` fails when an untraced
test has no row, or a row names a test that is no longer untraced, and `just check` runs
that check. Before it existed, the prose here asserted "each is justified" for several
cycles with nothing verifying it, and the ratio above went stale as tests were added — a
justification nobody checks decays into the same hand-wave as no justification at all.

| test | basis |
|---|---|
| `buffer::alloc_clean_734` | Structural. `Slot::new()` sets `bytes: [0; SZ]` and `len: 0` on every `acquire`, and `with_payload` slices exactly `PADDING..PADDING + len` — a `Packet` cannot expose a byte past its payload, so issue 734's leak class does not exist to test. Read, not assumed. |
| `buffer::clone_frame_begin_fixed` | Covered by `promisc::read_transfers_ownership`: `tapped_is_a_distinct_packet` and `buffers_back_after_free` are the clone-independence property, measured through the tap. |
| `cmp::the_peek_tail_leaks_the_previous_packet_when_the_pool_is_not_cleared` | Registered under `#if !CSP_BUFFER_ZERO_CLEAR`; runs in `just ctest-noclear`, not in the canonical build. Not a canonical gap. |
| `promisc::leaves_a_buffer_reserve` | libcsp's tap allocates from the shared pool and must not starve it. The port's tap is a fixed array inside `Router` with `promisc_missed` counting overflow — no shared allocation to starve. |
| `promisc::queue_size_argument_is_ignored` | `csp_promisc_enable(N)` ignoring `N` is a libcsp quirk. `Router::set_promisc` takes a bool; there is no argument to ignore. |
| `promisc::disabled_consumes_nothing` | Covered by `promisc::delivery_is_the_same_with_the_tap_off`: `tapped: 0`, `buffers_lost: 0`. |
| `promisc::csp1_id_layout_matches_the_binding` | Covered byte-for-byte by `vectors/v1.tsv` (267 lines of real wire bytes from the C) and the difftest header codec, which compare the layout rather than a hand-written formula for it. |
| `queue::queue_free_707` | `csp_queue_*` is an arch shim, out of scope in this file's exclusion table and marked `out-of-scope` in `api_map.tsv`. Sans-io: the caller owns the queues. |
| `rdp::syn_options_are_bounded_above` | Behaviour covered by `a_hostile_syn_cannot_suppress_acknowledgement` (every field at its maximum) and `a_delay_count_beyond_the_window_is_bound_by_it`. The test itself reads `conn->rdp.*`. |
| `rdp::syn_options_are_bounded_below` | Same as the row above, from the other side of the range. |
| `rdp::syn_keeps_valid_options` | **Partial.** `window_size`, `delayed_acks` and `ack_delay_count` adoption are covered by the two cadence records; `conn_timeout` and `ack_timeout` adoption are not, and no record varies them. The nearest thing is `packet_timeout`, exercised by the retransmission record. |
| `rdp::isn_does_not_depend_on_history` | The ISN is a deliberate divergence — the port does not reproduce `rand_r` (entry above). `isn_is_a_function_of_the_clock` records the C's side; the port's is different by design. |
| `rdp::delayed_acks_is_a_flag` | Covered by `a_nonzero_delayed_acks_is_on_not_a_count`, added the same day. |
| `rdp::retransmit_count_resets_on_ack` | No observable consequence in the port; see the entry above. Aligned with the C anyway, and said there that no record can catch it. |
| `rdp::queue_flush_all_releases_buffers` | libcsp's *global* RDP queue (`csp_rdp_queue.c`). The port's `TxQueue` is per connection. Release on close is covered by `conn::a_closed_connection_can_be_used_again` (`buffers_lost: 0`) and the `drain:` mutation family. |
| `rdp::queue_flush_all_releases_receive_buffers` | Same as the row above, for the receive side. |
| `security::the_checksum_is_stripped_before_delivery` | Now redundant: `a_valid_checksum_is_accepted` is the same scenario and carries `delivered_body` since this cycle. |

**One real gap fell out of this**, and it is smaller than the raw count suggested:
`conn_timeout` and `ack_timeout` are adopted from a peer's SYN and no record varied either.
`rdp::a_proposed_ack_timeout_is_adopted` now closes the `ack_timeout` half — it proposes
5000 ms against the compiled-in 250 and measures how long the peer waits for the
acknowledgement when the delay *count* has not been reached. Both sides wait 5250 ms
(5000 plus one step of the 250 ms polling granularity). Ignoring the proposal and keeping
the default acknowledges at 500 ms, a tenth of what the peer asked for — on a long
round-trip link that is a sender retransmitting into a receiver that already had the data.
`conn_timeout` adoption remains uncovered.
Everything else is covered, structurally absent, or a divergence already written down.

### The untraced tool mis-reported, and a field that measured nothing new

2026-08-26. Two corrections, one to a tool I built two cycles ago and one to a claim I was
about to commit.

**`just untraced` resolved helper chains one level deep, not to a fixed point.**
`suite_hmac.c` records through `hmac_record` -> `hmac_record_hdr` -> `ctest_trace_begin`, so
a test that *does* record was listed as recording nothing — and I had traced it myself the
day before. That is the same mistake the tool exists to catch, made by the tool, and it is
the second time: the first version looked only for a literal `ctest_trace_begin` and missed
single-level helpers. Now iterated to a fixed point: 128/145 rather than 127/145 as the
suites stood that day. The current ratio is the one `just untraced` prints, not this one.

**`security` records now carry `delivered_body`, and it moved nothing.**
`test_the_checksum_is_stripped_before_delivery` asserts both the length *and* the content of
what the application reads, and recorded neither — the other seventeen records carried
`delivered_bytes` alone. Adding the content is right in principle: it is what the C asserts,
and the record should carry the same assertion the oracle makes.

But the reach figure is **102 of 130 before and after**. It moves no mutation the existing
fields did not already move, and I nearly justified it with a claim that is simply false
here: that the length cannot separate a trailer stripped from the end from one stripped off
the front. Both stacks truncate by length from the end — `csp_crc32_verify` does
`packet->length -= 4`, and the port takes only `stripped.len()` from `security::check` and
shortens in place, never using *which* bytes came back. I proved it by making `crc32::verify`
return a correctly-verified but shifted slice: the CRC-only records stayed green.

Kept, because it pins what the application reads and costs nothing. Recorded here with the
measurement that it added no detection power, rather than the argument I first wrote for it.

### A flag checked as a field, and a counter reset nothing reads

2026-08-26, both from `just untraced` on `suite_rdp.c`.

**`delayed_acks` is a flag, not a count.** `csp_rdp.c` normalises any non-zero proposal to 1.
`test_rdp_delayed_acks_is_a_flag` asserted `conn->rdp.delayed_acks == 1`, which is how the C
spells it, and recorded nothing — so what a *peer* sees was never compared.
`rdp::a_nonzero_delayed_acks_is_on_not_a_count` proposes 2 with a delay count of 2 and
records the acknowledgement cadence, which must then match the case that proposes 1. Both
sides give `[0,0,1,1,1]`. The port was already right. Reading the word as `== 1` instead of
`!= 0` turns delayed acknowledgement off entirely — five acks instead of one over five
packets, a bandwidth difference the peer sees immediately, and the field assertion alone
cannot distinguish it.

The replay writes the option block word by word rather than encoding the port's
`SynOptions`, whose `delayed_acks` is a `bool` — encoding from the struct would drop the very
value under test.

**A reset that changes nothing observable.** `Connection::step`'s `SynRcvd → Open` arm did
not clear `retransmits`; `csp_rdp.c` does on that ack, and the port's other two transitions
into an open state already did. Aligned — but stated plainly: **no record can catch it.**
`retransmits` is read in exactly one place, the `SynRcvd` arm of `Tick` for the `SYN|ACK`
repeat, and a connection never returns to `SynRcvd`, so a stale value is never consulted.
Changed because it is what the C does and what the neighbouring arms do, not because
anything observed it. If RDP data retransmission is ever driven from `Connection` rather
than from `TxQueue`'s own counter, it stops being harmless.

### The wire MAC's coverage was never compared to the C

2026-08-26, found with `just untraced`: `suite_hmac.c` had two tests and no records.

`difftest` covers `mac_full(key, msg)` — the raw HMAC primitive — against the real C on
random keys and messages. Nothing covered `csp_hmac_append(packet, include_header)`: **which
bytes are authenticated** and where the four tag bytes land. The flag selects
`frame_begin..frame_length` or `data..length`, and libcsp's own test carries a different
expected tag for each (`9b4a918f` payload-only, `3cc7498b` with the header) over the same
`abc` under the zeroed static key.

The port reproduces both, byte for byte. **No defect** — this closes a gap in what was
checked.

Why it was worth checking rather than reading: computing the tag over the wrong span is
invisible to every self-test. Forcing the port to `PayloadOnly` regardless of the flag still
reports `verified: 1`, because it verifies against its own computation — it simply emits
`9b4a918f` where a peer expects `3cc7498b`. A self-consistent implementation with the wrong
coverage passes everything it owns and fails against every real peer, with nothing in the
error to say why. Only the C's expected bytes catch that, and now one record does.

**One field deliberately not compared.** On the include-header path `csp_hmac_verify`
decrements only `frame_length`, while `csp_hmac_append` incremented *both* it and `length` —
so after a verify, `packet->length` still counts the four MAC bytes and an application
reading `data[0..length]` sees them as payload. That is a real libcsp trap, and it is also
bookkeeping the port's slice-returning API cannot have. The record compares what the caller
recovers, not the length field; comparing the field would have manufactured a divergence
instead of finding one. It caught me first: deriving the header span as
`frame_length - length` gave 2 bytes for what is a 6-byte v2 header.

### The negotiated window never bounded anything, in any test

2026-08-26. `csp_rdp.c:576` clamps the peer's proposed `ack_delay_count` to
`conn->rdp.window_size` — the window it has just negotiated, not a compile-time maximum.
Every cadence test in `suite_rdp.c` opens through a helper that hardcodes `window_size = 4`
and passes an `ack_delay_count` below it, so the clamp never fired and the relationship
between the two was exercised nowhere.

`rdp::a_delay_count_beyond_the_window_is_bound_by_it` proposes a two-packet window and a
delay count of 250. Both nodes acknowledge on the third packet: the count is bound to 2.
**The port was already right** — this pins a bound, it does not fix one. Clamping to
`max_window` instead produces no acknowledgement at all within five packets, which a sender
sees as a dead link on a window that only allows two packets in flight.

The replay had to go through `SynOptions::decode_clamped` to test it. The neighbouring
cadence replays build `SynOptions` directly, which skips the only code that applies the
bound — so none of them could ever have caught a wrong one, whatever they asserted. Their
hand-built window is 4, the same as the C helper's, so they were at the right operating
point and honest; they were simply blind to this.

**The lead is now a tool.** `just untraced` prints, per suite, the C tests that assert
against a real node and record nothing — 148 of 165 record something today. That measurement
found the dedup window, the malformed-SYN connection leak, and this. It resolves recording
helpers, because an earlier hand-rolled version that only looked for a literal
`ctest_trace_begin` reported two already-covered tests as gaps and would have sent me to
re-do work. It is deliberately not in `just check`: an untraced test is a lead, not a defect,
and several of the remaining nineteen are libcsp internals with no port equivalent.

### Function-level coverage, checked rather than claimed

2026-08-26. The first "the port is complete" here compared module names and missed about
thirty-five functions, the socket API among them. `ctest/tools/api_map.tsv` is the
function-level answer: every `csp_*` declared in `libcsp/include/csp/**.h` — **199** of them
— mapped to `ported`, `out-of-scope` or `deferred`, and `just api` (now part of `just check`)
fails on any function missing from the map, any row naming a function that no longer exists,
and any `ported` row naming a Rust item that does not.

**199 = 148 ported + 46 out-of-scope + 5 deferred.**

The five not ported, all by prior decision: `csp_yaml_init` (`yaml`, off, no C oracle),
`csp_if_tun_init` with `csp_crypto_encrypt`/`csp_crypto_decrypt` (`if-tun` and its two
hooks), and `csp_bind_callback`. The 46 are arch shims, `src/drivers`, the ZeroMQ hub, and
the printf-style diagnostics SCOPE.md's own "deliberately not ported" section names.

Writing the map found one wrong entry of mine immediately: I had `csp_hex_dump` as ported to
`csp::print`, a module that does not exist — SCOPE.md line 148 puts it in the
deliberately-not-ported set with `csp_print_func` and `csp_conn_print_table`. Two more
failures were the tool's own fault, not the port's: a `const` alternative in the symbol regex
swallowed the `fn` of `pub const fn`, so `Id::is_broadcast` and `sfp::max_mtu` were reported
missing when both exist. Worth recording because the failure was in the direction that
matters least — a tool that cries wolf gets ignored, and then the one real row is missed too.

**What green here does not mean.** A Rust item existing under a name is not evidence it
behaves like the C; a grep proves spelling. Equivalence is what the 126 corpus records, the
510 golden vector lines and the 33 differential tests are for. The map answers "is anything
unaccounted for", which is a different and previously unanswered question.

#### The map was at module granularity again, one level down

2026-08-27. The third check above — "every `ported` row names a Rust item that exists" — was
worth much less than it reads. Measured across the 152 rows it then had: **28 distinct Rust
names, 148 rows sharing a target with at least one other row.** A row was allowed to name the
*type* that holds the method, so `csp_iflist_get_by_broadcast` → `csp::iflist::IfList` passed
for as long as the struct existed, whatever became of `get_by_broadcast`. Eighteen rows
resolved to a bare module name. That is the module-granularity failure this map was written
to stop, re-formed inside the map itself, one level down — and the docstring asserting "only
an inventory at function granularity can catch that" sat directly above a check that was not
enforcing function granularity.

The fix is a fourth check: a `ported` row must name something the tool sees defined as `fn`.
Retargeting 139 rows took it to **115 distinct targets**. The rest still share one, and
correctly — the port folds several C entry points into a single function (`csp_buffer_get`
with `csp_buffer_get_isr`; the three `csp_transaction` variants) — but every target is now a
function that can be noticed going missing.

Measuring the result found the same flaw once more, one level further down: check 4 looks the
name up *workspace-wide*, and **57 of the 148 rows name a function that is defined in more
than one module** — `new` in nineteen of them. So a row could keep passing after its own
target was deleted, carried by an unrelated `fn` of the same name. Check 5 resolves the path
to the module it names and requires the function to be defined there, which makes a row a
pointer rather than a spelling. All 148 already satisfied it, so it changed no verdict today —
its value is that the next deletion cannot hide behind a namesake. Two controls confirm it
bites: repointing `csp_accept` at `csp::conn::Table::accept` (a real `accept`, wrong module)
and renaming `IfList::find_by_broadcast` in place each fail the run.

Four rows turned out not to be `ported` at all once a *function* had to be named, and moved to
`out-of-scope` (42 → 46): `csp_id_clear` and `csp_id_copy` (zeroing and struct assignment —
`Id` is `Copy`, so the second is the `=` operator), `csp_panic` (an abort hook; the port
returns errors), and `csp_bytesize` (printf-style formatting).

The transferable part, now true twice: **a completeness check is only as strong as the
granularity of the thing it names, and that granularity is a measurement, not a property of
the checker's docstring.** What matters is not how many rows pass but how many distinct things
they pin — 152 and 28 were the same run.

### A malformed SYN got an RST *and* an accepted connection

2026-08-26, and the most serious thing this exercise has turned up since the forwarding bug.

Found by the same measurement as the dedup gap the day before — tests per suite against
records per suite. `suite_rdp.c` was the worst offender: 21 tests, 11 records. Five of the
ten untraced covered SYN option-block validation, the path a hostile peer reaches first.

`csp_rdp.c` requires a complete six-word option block. Given a SYN with none, or one word
short, it sends `RST` and frees the connection; the socket never sees it. The port sent the
same `RST` — the state machine was right and stays `Closed` — but `queue_rdp` announced the
connection to the application regardless, because `is_new` was true and nothing distinguished
"a handshake is starting" from "this is being refused". So:

- the application accepted a connection whose peer had already been reset, and
- the table slot stayed allocated.

The second is the one that bites. `rdp::malformed_syns_do_not_exhaust_the_table` sends
`CSP_CONN_MAX * 3` option-less SYNs and then one honest peer. Against the C the honest peer
gets its connection and its `SYN|ACK`. Against the port as it stood it got **neither** — no
connection, no frame. Twenty-four malformed packets, from a peer that never completed a
handshake, and the node stops accepting RDP connections at all.

`Action::SendControl` now treats an `RST` on a brand-new connection as a refusal: no
`queue_accept`, and the slot is released the way `Action::Closed` releases one. Three records
pin it, and all three fail if the distinction is removed.

Worth naming the shape, because it is the inverse of the earlier RDP findings and it took
four cycles to reach: those were *the state machine offers an action and the layer above
drops it*. This is *the state machine refuses and the layer above proceeds anyway*. Both are
invisible to any test that checks only the state machine, and there were 49 of those.

### Three C tests that measured the dedup window and recorded none of it

2026-08-26. `suite_dedup.c` had seven tests: four traced the mode matrix, three asserted the
window boundary against a real libcsp node and traced nothing. So the port's dedup window
was compared to no oracle at all — the mode matrix pinned *which* packets are candidates,
never *for how long*. The three now record, plus two new cases at the 32-bit clock wrap, and
all five replay.

**And the wrap entry (SCOPE 10) was wrong.** It has said since this began that after the
wrap `time` is small, every entry looks expired, and dedup stops suppressing. Measured on the
real library, a duplicate 60 ms apart *spanning* the wrap is suppressed exactly as it is at
any other time. The reason is arithmetic I had not done: `stamp + 100` overflows to a small
number **and** `time` wraps to a small number, and the two cancel.

The real failure is the last 100 ms *before* the counter turns over, where the addition
overflows but `time` has not wrapped yet and is still huge — so every entry looks expired.
Both points are now records: `a_duplicate_in_the_last_window_before_the_wrap` (C delivers 2,
port suppresses, `diverges`) and `a_duplicate_across_the_clock_wrap` (both deliver 1,
`must_match`).

"Dedup dies at 49 days" and "dedup drops one 100 ms window every 49 days" are different
operational claims and only the second is true. The first is what a reader would have taken
away, and it came from reading the comparison rather than evaluating it.

`clock.h` has documented since it was written that the wrap is "reachable by assignment".
Nothing had used it. The capability existing is not the same as the case being covered.

### The panic that hid mutations was a class, not an instance

2026-08-26, following straight on from the promiscuous-tap finding below. If one `expect` in
a replay could hide five mutations for a whole subsystem, the question is how many others
did. The fingerprint is in the sweep's own output: a mutation scoring "N unit test(s)
notice" is one the corpus reported nothing about.

`rdp: a control frame reaches the wire` scored 5 unit tests and no records — while
`rdp::a_syn_is_answered_with_syn_ack` observes `frames`, `flags` and `seq_is_own_iss`, all of
which must change if no control frame is emitted. It was the same cause:
`n.accept().expect("the handshake opened a connection")`, twice. Recording the failure
instead moves that mutation to **7 records**, and a port that answers no SYN now names all
seven rather than panicking on one. The connection replay had a third instance
(`expect("the first packet announces the connection")`), fixed the same way.

**The durable part is in the sweep.** A replay panic opens a `---- the_port_reproduces_what_the_c_did
stdout ----` block, which the counter was charging to the unit-test fallback — so the
mutation looked covered and the records that actually cover the code sat in the never-moved
list looking vacuous. `mutants.py` now recognises the two harness test names and prints
`REPLAY PANICKED` instead of a count. It found a third case on its first run.

That third case was a **badly-formed mutation, not a harness defect**: dropping the
`payload.len() < seg_size` guard leaves the slice on the next line out of range, so the
mutation modelled a crash rather than a wrong answer. Rewritten to span both lines and clamp
— which is what a receiver would actually get wrong, and what `csp_eth_rx` refuses via
`ETH_HDR + seg_size > received_len`. One record notices.

Remaining "unit test(s) notice" entries are port-only invariants with no C equivalent
(`shutdown`, the `drain` sizing family, node identity, the hooks default) plus the three
tied to the ISN divergence. Those are the case the fallback exists for.

### The tap's third placement, and a replay whose panic hid five mutations

2026-08-26.

**Tapped, then refused.** `csp_route_work` calls `csp_promisc_add` at `csp_route.c:252` and
applies the endpoint's security policy at :289. A packet the policy rejects is therefore
seen by the tap and *then* dropped — which is what makes a promiscuous tap usable for
diagnosing a peer that is being refused. The suite's own comment described the placement
"after dedup" and "before the is-this-for-me branch" and pinned both; the third boundary was
only ever read, never measured, and every existing promisc test used a socket with no policy,
so a tap moved below the check would have kept all of them green.
`promisc::the_tap_sees_a_packet_the_security_check_rejects` measures it on both sides:
`delivered: 0`, `tapped: 1`. The port already agreed — this pins an ordering, it does not fix
one. Moving the port's tap below the gate fails that record and only that record.

**A replay that panicked instead of recording.** `replay_promisc_ownership` did
`promisc_read(...).expect("the tap holds a packet")`. With the tap broken the run was still
red, so no regression could slip through — but the failure named no record, and `just
mutants` counts divergences. Two promiscuous mutations had been in the list all along,
scoring "4 unit test(s) notice" via the fallback while the three records that actually cover
the tap sat in the never-moved list. Recording `0` instead of panicking moves them to 6
records each.

I had first read those three as "no mutation targets the tap", by analogy with the
connection-reuse records the day before. That was wrong: the mutations existed and were
firing. The lesson is not the same one twice — a record can fail to move because nothing
tried it, *or* because the replay cannot express the failure.

`delivery_is_the_same_with_the_tap_off` stays unmoved, correctly: it is the tap-off case, so
no tap mutation can change it by construction.

### The other shape mismatch, and a stale number under a paragraph promising measurement

2026-08-26. Two checks, one clean and one not.

**The shape mismatch in the direction an application hits by accident.** The corpus covered
a plain datagram handed to the stream reader; it did not cover a *fragmented* transfer read
with the ordinary datagram call, which is what happens to any receiver that never opted into
SFP. Nothing in `csp_route.c` reads `CSP_FFRAG` — only `csp_sfp.c` does — so the C delivers
it like any other packet and the reader gets the body with the 8-byte SFP header still on
the end, with no indication. `sfp::a_fragment_read_as_a_datagram_keeps_the_sfp_header` drives
the real router and the real socket on both sides and they agree: 13 bytes for a 5-byte body,
`FRAG` visible on the id. **The port is faithful here** — this closes a gap in what was
checked, not a defect.

**"487 tests" against a measured 492.** In `docs/API.md`, three lines under a paragraph
saying every number in it is printed by `just numbers`. I had corrected the record and check
counts in that same list the day before and did not re-measure this one. `just numbers check`
now compares all five figures against the measurement and fails on a mismatch, so the promise
is enforced instead of restated.

**A record no mutation moves is not a dead record.** Both connection-reuse records
(`a_second_packet_reuses_the_same_connection`, `a_closed_connection_can_be_used_again`) sat
in the "no mutation could move" list, which is where the padded-frame defect was found — so
the list reads as a list of suspects. Breaking `Conn::find` and `Conn::close` failed both
immediately. The list means "nothing has tried this yet"; it takes a mutation to tell the two
apart, and three were added.

### The Ethernet replay refused every padded frame, and no record could see it

Found on 2026-08-26, starting from the mutation sweep rather than from reading. Removing
`Reassembler`'s running-total bound left every record green, so either the guard was dead or
something upstream refused the frame first. It was the second.

`Reassembler::push` required `payload.len() == seg_size`. `csp_eth_rx` requires only that
`sizeof(header) + seg_size` fits in what arrived, copies `seg_size` bytes and ignores the
rest. **Ethernet pads every frame to 60 bytes**, so a small CSP packet arrives with trailing
bytes past `seg_size` — and the port refused it. On a real link the port would have dropped
every packet small enough to be padded, which is most telemetry.

`eth::segments_totalling_more_than_the_packet_are_refused` was green throughout. Its first
frame carries 34 data bytes in a 38-byte region; the C accepts it and refuses the *second*
frame on the running total, the port refused the *first* on its length. Both ended at
`refused: 1`, and `refused` was all the record compared. `a_frame_padded_to_the_ethernet_minimum_is_delivered`
now covers the padding directly.

Three things changed:

1. **`push` tolerates the surplus** and takes `seg_size` bytes, as the C does. A frame
   shorter than its declared segment is still refused.
2. **The `offset` parameter is gone.** EFP has no offset field; `csp_eth_rx` copies to
   `frame_begin + rx_count`. The parameter let a caller place a segment where no peer could
   have asked for one — and it is *why* this hid, because the replay passed `0` for every
   segment, so the second segment overwrote the first and the running-total guard was the
   only bound left standing. With the offset derived internally, the two bounds collapse
   into one.
3. **A unit test asserted a capability the C does not have.**
   `out_of_order_segments_are_accepted` claimed "EFP explicitly permits this". It passed
   only because it handed `push` an offset the *sender* had computed, which no receiver
   has. libcsp assembles in arrival order and cannot do otherwise. Replaced by
   `segments_are_assembled_in_arrival_order`, which asserts the arrival-order result.

**The records observed no delivery at all.** All eighteen compared `refused`/`frame`/`drop`/
`buffers_consumed` — nothing about whether reassembly produced the right bytes, which is why
`two_segments_are_reassembled` was one of the records no mutation could move. They now carry
`delivered` and `delivered_body`, and the C fills the payload positionally (`0xD5 ^ i`)
rather than with a constant, so segments reassembled in the wrong order no longer match.

### The mutation sweep did not run the tests for the crate it mutates

Same day, and the reason the above took two cycles to surface. `ctest/tools/mutants.py` ran
`cargo test -p csp`. Most mutations target `csp-core/src`, whose unit tests live in
`csp-core` — never compiled. Four Ethernet guards were reported as noticed by nothing while
`csp-core/src/eth.rs` held unit tests asserting the exact error each one raises.

The sweep now runs `-p csp -p csp-core`. Three of the four were false; one was real and is
the finding above.

I had also been reporting "no mutation went unnoticed" from a grep for `UNNOTICED`, which is
not the string the script prints (`<-- NOTHING NOTICED`). The grep matched nothing on every
run and I read that as nothing to report.

### SCOPE 11's undefined behaviour is now observed, not just read

The entry below has said `csp_if_eth_unpack_header` shifts a promoted `uint16_t` into the
sign bit of an `int`. `just ctest-ubsan` now shows it:

```
csp_if_eth.c:46:33: runtime error: left shift of 32768 by 16 places
                    cannot be represented in type 'int'
```

It needs a packet id whose **low** byte is ≥ 0x80 — the field is read without a byte swap,
so the wire's low byte lands in the top half. That is half of all packet ids, on the
Ethernet reassembly path. `ctest-ubsan` is separate from `ctest-asan` because ASan aborts on
the same file's out-of-bounds reads before a test can record anything, while UBSan reports
and continues.

Also confirmed while writing the suite: `csp_eth_pack_header` does **not** set the
ethertype — `csp_eth_tx` writes that separately — and `csp_eth_unpack_header`, declared in
the public header, is **defined nowhere in libcsp**. Linking against it is a build failure.

### PEEK/POKE: a write that did not happen, reported as success

Found on 2026-08-25 by the second `suite_cmp.c` slice, which overrides libcsp's `__weak`
`csp_cmp_memcpy` with a bounds-checked window — the default is a bare `memcpy`, so a node
built with CMP and no override answers a peek from any address and a poke to any address.

**The port answered a `POKE` the C refuses.** `csp_cmp_poke_handler` checks the length
**twice**: once for the header, then again for `sizeof(*cmp) + cmp->len`, so a request that
declares 64 bytes and carries none is refused outright. `csp_cmp_peek_handler` has no second
check, because a `PEEK` request legitimately carries no body while declaring how much to
read.

`Peek::decode` is shared between the two codes and cannot tell them apart, and its own
"a POKE must carry all of it" check was written as

```rust
if !body.is_empty() && body.len() < declared as usize {
```

— skipped exactly when the body is *empty*, which is the case that matters. So a `POKE` for
64 bytes carrying none became a silent zero-byte write, answered as success. On a
memory-write service, reporting a write that did not happen is worse than refusing. The
check now lives in `parse_request`, where the code is known.

### The peek reply's three-byte tail: right mechanism, missing condition

`CMP_PEEK_SIZE(len)` is `10 + len` while the handler writes `len` bytes at packed offset 7,
so the C declares a reply three bytes longer than the data it wrote. `csp-core::cmp` has
documented that for a while as "those three bytes are whatever was already in the pooled
buffer — a peek reply pads itself with unrelated memory".

Measured, both branches:

| `CSP_BUFFER_ZERO_CLEAR` | tail |
|---|---|
| `1` (upstream default, canonical build) | zeros — **no leak** |
| `0` (`just ctest-noclear`) | the previous packet's bytes |

So the claim was right about the mechanism and wrong to state without its condition: in the
default configuration it simply does not happen. Reaching it also needs a request *shorter*
than `10 + len`, which the C's own client never sends — `csp_cmp_peek` sends
`CMP_PEEK_SIZE(peek->len)`, so an ordinary exchange just echoes the requester's own bytes
back. It takes a hand-crafted request to turn the padding into a read of someone else's
packet.

Demonstrating it needed the pool *cycled*, not just one allocate-and-free: the free list is
a queue, so the next `csp_buffer_get` returns a different, never-used buffer. The first
version of the test asserted the leak, failed, and was nearly written off as "not
reproducible" — which would have been the wrong conclusion from a test that was too weak
rather than a claim that was false.

`ctest/` now takes `CTEST_BUFFER_ZERO_CLEAR` as a build option, so both branches are
reachable. The port zeroes the tail in every configuration.

### CMP: the request has to be as big as the reply, on both sides

Found on 2026-08-25 by `ctest/suite_cmp.c`, the third oracle suite. It measures the
smallest request a real node will answer, per code, by sweeping the length rather than
reading it off the struct definitions.

Every handler in `src/cmp/` opens with `csp_cmp_check_len`, and for most codes the bound is
the size of the **whole reply** — the node writes its answer back into the buffer the
request arrived in, so a request too small to hold the reply is refused before anything
happens. `csp_cmp_handler` returns `CSP_ERR_INVAL` and `csp_service_handler` discards the
packet **without answering**, so the caller waits out its timeout and learns nothing.

| code | smallest answered request |
|---|---|
| `IDENT` | 93 — the entire reply |
| `CLOCK` | 10 — the entire reply |
| `IF_STATS` | 13 — header plus interface name only |

Two port defects, one on each side of that:

**1. `cmp_request` built requests no node would answer.** It emitted
`Header::LEN + body.len()`, so `cmp_request(code::IDENT, &[], …)` produced two bytes — and
the crate's own test asserted `n == 2`, presenting the unanswerable form as correct. Now
padded to `cmp::request_len(code)`, zero-filled, matching what the C's own clients send
(`csp_cmp_ident` passes `sizeof(struct csp_cmp_ident_msg)`).

**2. `parse_request` had no length check for `IDENT` at all.** A node built on this port
answered a two-byte request with 93 bytes, where a C node stays silent. Tempting to keep —
the C's requirement is an artifact of writing the reply in place, which this port does not
do — but it turns an unauthenticated port into a **46× amplifier**, and amplification on a
link that costs power to transmit is not a good trade for accepting a malformed request.
Now gated on `request_len` for every code, which is the same constant the request builder
pads to.

Removing the gate makes the corpus report both IDENT cases as `replies: 1, reply_len: 93`
against the C's silence, so neither half is vacuous.

*Also confirmed, and not a divergence:* libcsp does **not** serve CMP from the router. The
application calls `csp_service_handler` from its own receive loop
(`examples/csp_server.c:77`). The port's `service`/`cmp` modules are opt-in the same way —
`Router` never calls them. Worth stating because the opposite would mean a node answering
`CSP_REBOOT` that its author never opted into.

### The crypto hooks defaulted to reporting success on plaintext

Found on 2026-08-26 by running `cargo llvm-cov` over the suite for the first time.
`csp/src/hooks.rs` had the lowest function coverage of any module (82.86%), and six of the
fourteen `Hooks` defaults were never entered by any test — including both crypto hooks.

Every fallible default in that trait errs toward refusing: `on_power_request` returns
`Refuse` ("should say so rather than appear to accept and do nothing"), `set_clock` returns
`false`, `mem_read`/`mem_write` return `AddressRefused`. Except:

```rust
fn encrypt(&mut self, _data: &mut [u8], len: usize) -> Option<usize> { Some(len) }
```

`Some(len)` with the buffer untouched means **"encrypted"** — for plaintext. A node that
switched on a tunnel without supplying crypto would have transmitted in the clear while
every layer above it believed otherwise. `decrypt` was the same, handing the application
whatever the peer sent.

**The C is the safer of the two here**, which is unusual enough to be worth stating: its
`__weak csp_crypto_encrypt` and `csp_crypto_decrypt` both return `-1` (`csp_if_tun.c:7,16`).
The port inverted the default on the one hook whose failure direction is "transmit in the
clear".

Nothing in the port calls them yet — `if-tun` is out of scope — but `Hooks` is public API,
and a caller writing a tunnel inherits the default. Both now return `None`, and
`every_fallible_default_refuses` covers the rest of the value-returning defaults that
`the_default_hooks_are_safe_and_say_nothing` never reached: it checked three of fourteen.

SCOPE.md's own claim that the hooks were "all defaulting safely" was, for these two, false.

### `shutdown` released neither connections nor pending forwards

Measured on 2026-08-26 by watching the buffer pool across `Router::shutdown`, which
documents itself as *"Release everything the router is holding"*. It released the input
queue and the promiscuous tap and nothing else.

- **Packets queued on a connection.** A node torn down with anything unread lost a buffer
  per packet. Pre-existing.
- **Fan-out destinations reported but not collected.** Introduced by the fan-out change one
  day earlier: the pending queue holds a pool slot per destination and shutdown walked past
  it.

`Table::close_all` closes every open connection and hands back what each held, and
`shutdown` now drains that and the pending forwards.

**The test that should have caught it was named for it and did not test it.**
`shutdown_releases_everything` calls `tick` first — *"drain what is on connections too"* —
which expires the connections and empties them, so `shutdown` is handed a node that is
already clean. The path it is named after was never exercised.
`shutdown_alone_releases_connections_and_pending_forwards` does that, with no tick, and
fails under either mutation.

**`just mutants` now counts unit tests as well as corpus records.** `shutdown` has no libcsp
equivalent, so no corpus record can cover it; counting only records reported the mutation as
a hole when the real answer is "covered, elsewhere". A `0` in that column now means nothing
at all noticed.

### The promiscuous tap in the routing path: checked, and correct

Measured on 2026-08-26. libcsp's own promiscuous tests drive `csp_promisc_add` directly,
which says nothing about whether the router reaches it — the tap could be entirely
disconnected and every one of them would still pass. `ctest/suite_promisc.c` now drives it
through `csp_route_work`.

`csp_route_work` places the tap after deduplication and before the "is this for me" branch,
and both halves are behaviour:

- **after dedup**, so a suppressed duplicate never reaches the tap — a diagnostic feed
  showing frames the node discarded would misreport what the node acted on;
- **before the branch**, so the tap sees traffic passing *through* the node as well as
  traffic addressed to it. A tap blind to forwarded packets is blind on exactly the node
  where it is most useful.

| | tapped | delivered | forwarded |
|---|---|---|---|
| local delivery | 1 | 1 | 0 |
| forwarded onward | 1 | 0 | 1 |
| duplicate suppressed | 1 | 1 | 0 |
| tap disabled | 0 | 1 | 1 |

**The port matches on all four, and no defect was found.** That is worth recording as a
result rather than silence: the tap is one of the few things that was right first time. What
changed is that it is now *known* to be right, and two mutations enforce it — disabling the
tap is caught by three records, and moving it after the local/forward branch is caught by
one.

### The same connection was announced to the application once per packet

Found on 2026-08-25 by `ctest/suite_conn.c`, the first suite covering the connection table.

`csp_route_deliver_connection` posts a new connection to its socket and then immediately
does `conn->dest_socket = NULL`, with the comment *"Ensure that this connection will not be
posted to this socket again"*. A second packet joins a connection the application already
holds without announcing it again.

`Router::deliver_local` called `queue_accept(handle)` on **every** delivery, because
`enqueue_rx` returns `Ok(true)` for any successful enqueue and not just the first. Measured:
three packets arriving after the application accepted the connection produced **three extra
offers** where the C produces none.

Two consequences, and the second is the one that matters:

- An application looping on `accept` is handed the same connection repeatedly, and would
  read and close it more than once.
- The accept backlog is a fixed array. One peer sending eight packets fills it with eight
  copies of itself, so **every other peer's new connection has nowhere to be announced** —
  `accept_missed` climbs and those peers are never served. One peer starves the rest by
  sending entirely ordinary traffic.

The delivery path now tracks whether the connection was newly allocated and announces only
then.

**How the mutation sweep found it.** The first two connection-table records — exhaustion and
slot reuse — both passed, and both still passed with `Table::close` neutered to return
without freeing anything. That is what a sweep is for: `conn: slot returned on close` was
the one mutation nothing noticed. Chasing *why* the port still accepted 24 connections
across three rounds with `close` disabled turned up the re-announcement, which was doing the
work the reuse test thought it was measuring. The suspicious result was not the bug, but it
was the thread that led to it.

### Mutation testing the corpus: what the records could not see

On 2026-08-25, after a `diverges` verdict was found passing vacuously, the whole corpus was
mutation-tested rather than reasoned about: break the port, count which records notice.

**One replay arm was a tautology.** `sfp::a_corrupt_fragment_reports_the_same_error_as_a_wrong_shape`
returned a hardcoded `json!` of the C's own answer and never called into the port at all. It
passed whatever the port did, while counting itself in "N records replayed". It was written
in the same session that fixed a different instance of the same class, and commented as
though it were deliberate. It now runs both cases through `Delivery::classify` and reports
`indistinguishable: false` where the C reports `true` — a real divergence rather than an
echo.

**Nine of seventeen security records could not tell a verified packet from an unchecked
one.** Disabling `security::check` entirely — returning `Ok` before any verification — left
them green, because they recorded only `delivered: 1`, which is the same either way. The
missing observation was the one an application actually cares about: *how many bytes did it
get*. A CRC32 packet accepted-and-stripped delivers 7; accepted-unchecked delivers 11.

Adding `delivered_bytes` to both sides took the mutation from 9 to **15 of 17**. The two
that still do not notice are correct not to: a plain packet with no policy, and a plain
packet carrying an option the C ignores, have nothing for the policy to do. It also means
the trailer stripping is now pinned across every accepting case — `both_protections_together`
turns 15 wire bytes into 7 — where before it was tested only by a C-side case that had no
corpus record at all.

The general rule, now stated at the top of `csp/tests/corpus.rs`: **a replay that does not
call into `csp` or `csp_core` is measuring nothing**, and the check for it is a mutation, not
a reading.

### The security policy verified the trailers in the wrong order

Found on 2026-08-25, on the **first run** of the corpus replay (`csp/tests/corpus.rs`)
against `ctest/suite_security.c`. Three records diverged; all three were port bugs.

**1. CRC32 and HMAC were checked in the wrong order.** `csp_send_direct` appends the MAC
and *then* the checksum over it (`csp_io.c:250-271`), so the wire layout is
`[payload][MAC][CRC32]` and the checksum covers the MAC. A receiver must unwrap
outermost-first. `security::check` verified the MAC first, over a body that still carried
the CRC32 — authenticating `payload || MAC || CRC32` instead of `payload`.

So a packet using **both** protections — the configuration a flight node would actually
choose — failed authentication on this port and was accepted by every real libcsp node.
Not a counter-attribution nit: a working peer could not talk to us.

It survived because `both_protections_together_verify_and_strip_in_order` *assembled the
packet from the same misreading*: checksum inner, MAC outer. It was named as if it proved
the layering. This is the self-referential-test failure the C oracle exists to break, caught
the first time the oracle ran.

**2. The `*_PROHIB` options were enforced on receive.** They are outgoing options.
`csp_connect` reads `CSP_O_NOCRC32` to clear the *request* on what this node sends
(`csp_conn.c:279`); `CSP_SO_HMACPROHIB` and `CSP_SO_RDPPROHIB` are read nowhere in libcsp
at all, and `csp_route_security_check` looks at none of them. The port refused such packets
with `Refusal::Prohibited`, so a peer sending a correctly authenticated packet to a node
whose socket carried `HMACPROHIB` was dropped here and accepted everywhere else. Refusing
traffic that carries *more* protection than was asked for is the wrong direction to err in.
Removed, along with the now-unproducible `Refusal::Prohibited` variant.

**3. The counter split followed from (1).** A packet failing the checksum was charged to
`autherr` rather than `rx_error`, so an operator would read "someone is spoofing us" where
the C says "the link is corrupting frames".

### Deduplication was a bool where the C has four modes

Found on 2026-08-25 by writing `ctest/suite_dedup.c` — the first thing built on the C
oracle, and it fired immediately.

`csp_dedup.c` does not mention a mode, because the mode lives in the caller:
`csp_route.c:238` combines `csp_conf.dedup` with `is_to_me`. The port had
`dedup_enabled: bool`, which can express only `CSP_DEDUP_OFF` and `CSP_DEDUP_ALL`, and it
ran the check in `Router::work` *before* the destination was known — so the two middle
modes were not merely unimplemented, they were unreachable.

Measured on the real libcsp: two identical packets addressed to the node, and two
identical packets through it, per mode.

| mode | delivered of 2 | forwarded of 2 |
|---|---|---|
| `CSP_DEDUP_OFF` | 2 | 2 |
| `CSP_DEDUP_FWD` | 2 | 1 |
| `CSP_DEDUP_INCOMING` | 1 | 2 |
| `CSP_DEDUP_ALL` | 1 | 1 |

The middle two point in opposite directions, so collapsing them is not a simplification.
`FWD` — suppress a frame that arrived over two paths of a mesh, leave traffic addressed to
this node alone — is what deduplication is normally *for*. `INCOMING` is the one to be
careful with: a ground station retransmitting an identical command 50 ms after the first,
because no acknowledgement came back, loses the retransmission. Two identical commands
inside 100 ms are indistinguishable from one command seen twice.

Now `DedupMode`, evaluated where the C evaluates it: after `is_to_me`, before the
promiscuous tap. `every_dedup_mode_matches_the_c` asserts the table above.

**A second divergence in the same area:** `csp_bridge.c:45` deduplicates **unconditionally**,
without consulting `csp_conf.dedup` at all — a bridge is forwarding by definition and one
that does not deduplicate loops a frame between its interfaces forever. `bridge_work` gated
it on the flag, so a bridge built from the port with deduplication off, the default, looped
where the C does not. Now unconditional.

### RDP: the node answers it, and cannot yet initiate it

Found on 2026-08-25 while building `ctest/`, by reading the C's `csp_connect` against ours.
`csp-core/rdp.rs` was a complete RDP — state machine, SYN option clamping, retransmission
queue, 49 passing tests — and **nothing in the `csp` crate drove any of it**. `Routed` had
no variant that could put a frame on the wire on this node's own behalf, so a `SYN` reached
a bound port and nothing came back.

The receiving half is now wired (`Router::deliver_rdp`, gated on `CSP_FRDP` exactly where
`csp_route_deliver_connection` gates it) and measured at node level against a real C node:

| Behaviour | Where it is measured |
|---|---|
| A `SYN` is answered with `SYN\|ACK` carrying this node's ISN and acknowledging the peer's | `corpus`: `rdp::a_syn_is_answered_with_syn_ack` |
| The handshake's third leg provokes no further frame | `corpus`: `rdp::the_handshakes_final_ack_is_not_itself_answered` |
| Data reaches the application with the five-byte trailer removed | `corpus`: `rdp::data_reaches_the_application_without_the_rdp_trailer` |
| Every delivered packet is acknowledged, with an advancing sequence | `corpus`: `rdp::without_delayed_acks_every_packet_is_acknowledged` |
| The initial sequence number moves with the clock | `router.rs::the_sequence_a_peer_receives_moves_with_the_clock` |

`conn.rs` passed a literal `0` as the ISN for every connection — constant across reboots and
across peers, so a delayed segment from a previous connection falls inside the window of the
next one between the same pair of ports. That is strictly worse than the C, whose ISN is at
least a function of the clock (`csp_rdp.c:548`, `rand_r` seeded from `csp_get_ms()`).
`Router::initial_seq` now derives it from `now_ms`. It is **not** a random number and is not
treated as one: a sans-io core has no entropy source, and the C's own ISN is guessable by
anyone who can estimate the peer's uptime to the millisecond.

### A one-character entry ends the C's route-table parse

`csp_rtable_stdio.c:25` is `while (str && (strlen(str) > 1))`. That is the loop
**condition**, not a per-entry skip: the first token of one character or fewer stops the
whole scan, every entry after it is silently dropped, and the function returns the count of
entries accepted *so far* — a positive number that reads as success.

Measured in `rtable::a_one_character_entry_ends_the_parse_and_still_reports_success`
(the cases live in `ctest/suite_route.c`; the trace suite is `rtable`):
loading `"3000 LINK_A,x,3001 LINK_A"` returns **1**, installs the first route and drops the
third. An operator who types a stray comma loses every route after it and is told the load
worked.

`rtable::parse` **skips** the short entry and carries on, so the same string installs both
routes and returns 2. A route table is uploaded from the ground and cannot be inspected
afterwards except by trying it; silently discarding the tail of one, while reporting
success, is the kind of failure that is only discovered when a link that should exist does
not. Recorded as a divergence rather than reproduced.

The rest of the parser is faithful, including the parts that surprise:

- a netmask wider than the address space is **refused by the parser**
  (`csp_rtable_stdio.c:44`) even though `csp_rtable_set` would have *clamped* it
  (`csp_rtable_cidr.c:109`) — the two paths to the same table disagree, and only the string
  path is reachable from the ground;
- a refused string still leaves the entries before the bad one installed, so a non-zero
  error return does not mean the table is unchanged.

Both are pinned by `rtable::` records — but the first was pinned by the *test* until
now. `rtable::parse` made no range checks at all; the replay's callback made them, so
`"3000/99 LINK_A"` was refused by the harness while the port parsed it happily and
`Table::set` silently clamped the netmask to /14. An operator's malformed route table was
reinterpreted rather than refused, and the record said the port matched. The checks now
live in `parse`, where `csp_rtable_stdio.c:44` has them.

The address check moved with them and is **redundant**: `Table::set` refuses an
out-of-range address too, so no record can isolate `parse`'s copy — the string is refused
either way. It is kept because `parse` should be able to reject a malformed string without
a table to hand, which is what the C's parser does, and it is deliberately not in the
mutation suite since nothing could notice it. The netmask check is the one that mattered,
because `set` clamps instead of refusing.

### A lost SYN/ACK was never repeated

`rdp_retransmits_are_limited` asserts that an unanswered `SYN|ACK` is retransmitted up to
`CSP_RDP_MAX_RETRANSMITS` and then reset — four `ck_assert`s, no record, so the port had
never been compared on retransmission at all.

Measured: over 1000 ticks with the peer silent, the C sends at least ten frames and closes
the connection; this port sent **none** and kept the connection open indefinitely. A peer
whose `SYN|ACK` was lost waited forever for a connection this node believed it had opened,
and nothing ever told it otherwise.

Two layers were wrong, and either alone would have been enough:

- `Connection::step(Event::Tick)` only checked the connection timeout. It never looked at
  whether anything was outstanding, so no retransmission was ever produced.
- `Table::tick_rdp` matched on `Action::Closed` and nothing else, so a control frame from a
  timer would have been discarded even if one had been produced. That is the same shape as
  the acknowledgement finding: the state machine offers an action and the layer above drops
  it.

Only `SynRcvd` is handled. It is the one state in which this port has something outstanding
of its own — data retransmission needs the send side, which the node does not have.
`Router::tick` now takes the interface list so the frames it produces can be routed, and
reports them through `Routed::Respond` like anything else this node originates.

### The tap's ownership rules were asserted eight times and recorded none

`promisc_read_transfers_ownership` makes eight `ck_assert`s about what
`csp_promisc_add`/`csp_promisc_read` do with buffers, and recorded nothing — so the port
was never compared on any of it. Ownership is a leak on one side and a buffer handed out
twice on the other, and neither shows in the `tapped`/`delivered`/`forwarded` counts the
other `promisc::` records carry.

Four properties, all counted in pool buffers and payload bytes rather than in queue state:
the tap **clones** rather than aliasing, `read` gives ownership away so releasing the
packet returns the buffer, a second read yields nothing, and the source stays the caller's.
The port matches the C on all of them.

`promisc::two_tapped_packets_come_back_once_each` exists because the single-packet case
cannot see the interesting failure. A `read` that hands the packet over but leaves its slot
occupied passes it — the queue count says empty, so the stale entry is never reached. It
only shows on the second round, when the count rises again and the stale slot is handed out
ahead of the new one, giving the application a buffer already released. That mutation was
unnoticed until the two-packet record existed.

### The C asserted the SYN clamping and recorded none of it

`rdp_syn_options_are_bounded_above`, `_below` and `keeps_valid_options` make twenty
`ck_assert`s between them about what `csp_rdp_new_packet` does to a peer's proposed options
— and **record nothing**, so `SynOptions::decode_clamped` had never been compared against
libcsp. It was verified by reading, which is what this check exists to catch.

Found by sweeping every C test for assertions-without-a-record; those three were the largest
gap. `rdp::a_hostile_syn_cannot_suppress_acknowledgement` now measures it, and the port
matches the C exactly: a SYN proposing `0xFFFFFFFF` for every field is clamped to a window
of 5 and an ack delay count of 5, and the node still acknowledges.

Framed as acks reaching the wire rather than as the connection's fields: an unclamped
`ack_delay_count` means the node waits four billion packets before acknowledging, so the
peer retransmits until it gives up. The clamp is only observable as acks appearing at all.

**The first version of this test measured the wrong thing.** With the application not
reading, the C emitted one ack and the port two — not a clamping difference but the
receive-queue gate in `csp_rdp_check_ack`, the separate divergence recorded at
`acks_stop_when_the_application_is_not_reading`. The test now drains the connection as
packets arrive, so the clamp is what decides. Left as a caution: a `must_match` record
placed where a known divergence is live will fail for a reason that has nothing to do with
its name.

### Which records can actually fail, measured

`just mutants` now reports **how many corpus records some mutation was able to move**, and
lists the ones none could. The file header had long claimed "a replay that does not call
into `csp`/`csp_core` is measuring nothing"; nothing enforced it, and `every_record_has_a_replay`
only checks that a replay *exists*. The number turns that prose into a figure: currently
**113 of 142**.

It is a measure of the *mutation suite's* reach, not proof that the other 28 are vacuous —
most are guards no mutation happens to break. Both connection-reuse records sat in that
list until 2026-08-26, when the first mutation to break `Conn::find` and `Conn::close` was
added; both failed immediately. The three promiscuous records sat there for a different
reason again — a mutation *did* break them, and the replay answered with a panic instead of
a divergence, which the counter does not see. Read the list as "no mutation has produced a
divergence here yet"; that can mean the guard is untested, or that the replay cannot report.
Check before concluding a record is dead. It has, though, found two that genuinely were:

- **`replay_eth` contained its own copies of two production checks.** It tested
  `!h.is_csp()` and sliced `payload.get(..seg_size)` inside the replay closure, before
  calling `Reassembler::push`. Removing either guard from the port left every `eth::`
  record green, because the *test* was still refusing the frame. This is the shape that
  once hid a missing CMP server entirely: the test contained the production logic. Both
  copies are gone; the replay hands `push` the whole payload and lets it judge.
- **`replay_node_send` reported `"buffers_lost": 0` as a literal** and called
  `Node::resolve` without ever sending anything, so the send path was not exercised and
  the C's `before - csp_buffer_remaining()` figure could not move however badly the port
  leaked. It now sends through `Node::sendto` and counts the pool; leaking the packet is
  caught by both its records.

Two caveats worth stating rather than leaving implied. `eth::a_foreign_ethertype_is_refused_before_the_length_check`
sends a four-byte frame, so the header-length check refuses it whether or not the ethertype
is examined — the record cannot observe the ordering its name claims;
`eth::only_the_ethertype_makes_an_otherwise_valid_frame_refused` was added to do that, and
does. And `eth::a_zero_length_transfer_is_refused` still does not discriminate: with
`packet_length == 0` the `< min_len` guard refuses the frame anyway, so removing the
zero-total check is caught by a different record, not by the one named after it. The guard
is covered; that record is not what covers it.

### Per-interface counters existed as a field and were never written

`IfList::Entry::stats` is public, has the ten counters `csp_iface_t` has, and nothing
outside its own constructor ever touched it. An application reading it — or answering CMP
`IF_STATS` from it, which is what it is for — got a permanent zero. That reads as "this link
is idle", not as "this node does not count", which is the worse of the two failures.

`csp_route_work` keeps three of them itself: `rx` and `rxbytes` for every packet it handles
(`csp_route.c:229`, above the deduplication check, so a duplicate counts as received *and*
then as dropped) and `drop` for one deduplication discards (`:244`). These are the router's,
not the driver's — a driver only sees frames it handed up, and the drop happens after the
packet has left it, so there is no other place they can come from.

`Router::work` now takes `&mut IfList` and keeps all three. Measured against the C:
`cmp::if_stats_counters_after_three_packets` (rx 4, rxbytes 31 — three six-byte packets plus
the thirteen-byte `IF_STATS` request, which the router counts too) and the `ingress_drop`
field now on all four `dedup::` records (0, 1, 1, 2 across the modes).

`autherr` and `rx_error` are the same story on the authentication path.
`csp_route_security_check` takes the ingress interface and charges it directly — a bad MAC
or a policy-required MAC that is absent goes to `autherr` (`csp_route.c:83`, `:87`), a bad
CRC or a required-but-absent one to `rx_error` (`:68`, `:72`) — and `autherr` on a link is
how an operator sees that link being probed. This port kept only node-wide totals, so a node
under attack answered `IF_STATS` with a zero for every interface.

The 17 `security::` records already carried `rx_error` and `autherr` from the C, and passed
anyway: the replay was reporting the **router's** totals rather than the interface's. With
one interface in the scenario the two numbers coincide, so the record compared a different
quantity and matched. It now reads `Entry::stats`, which is what the C recorded and what
`IF_STATS` returns.

`tx`/`txbytes` stay with `iface::Iface`, which already keeps them, because that is where the
C keeps them too (`csp_io.c:287`).

### The minimal build was compiled, never run

`just check` built `--no-default-features` for the embedded target and stopped there. Nothing
in that configuration had ever been *executed*: the library compiled, and its test code had
drifted far enough that `cargo test --no-default-features` failed with 17 errors — tests
calling `route_set`, `respond_cmp`, `csp_core::rdp` and so on with no `cfg` gate on them.

A divergence had been living in the gap. `csp_send_direct` puts only its **middle** stage
inside `#if CSP_USE_RTABLE`; the local-subnet scan and the default-interface scan run either
way. This port gated the whole of `Router::forward` on the `rtable` feature and substituted
a stub returning `NoRoute`, so a node built without the routing table relayed **nothing** —
not to a directly attached subnet, not out a default link. Fixed by deleting the gate:
`route_policy::destinations` already handles a compiled-out table through a stub whose
`find_all` returns nothing.

`just check` now runs `cargo test -p csp-core -p csp --no-default-features`, which is **215
tests** that previously did not run. The two differential harnesses — `csp/tests/corpus.rs`
and `csp-core/tests/vectors.rs` — carry a file-level `cfg` for the features their oracle was
built with, so they are empty in that configuration rather than broken: comparing against
bytes the other build never produced would not be a differential test.

### One routing policy, not three

`csp_send_direct` decides where a packet goes. This port had **three** implementations of
it: `Node::resolve` for packets the application sends, `Router::forward` for packets passing
through, and a private lookup inside the RDP reply path. Each was written from the same C
function, and each drifted:

| Copy | What it got wrong | Found by |
|---|---|---|
| `Node::resolve` | no local-subnet stage at all, so a send to a directly attached address fell through to the defaults | `route::a_local_subnet_beats_the_default_interface` |
| `Node::resolve` | split horizon was only the identity half of `is_same_subnet`, so it relayed a packet back onto the wire it came from by way of a second link on the same subnet | `route::split_horizon_vetoes_a_second_link_on_the_same_subnet` |
| RDP reply path | never consulted the routing table, while its doc comment said it did, so a peer reachable only by a route got no `SYN\|ACK` | `router::a_peer_reachable_only_by_a_route_still_gets_its_handshake` |

All three were found by the C oracle, weeks apart, and none could have been found by reading
one copy — each looked right on its own. `csp/route_policy.rs` is now the only copy;
`resolve` went from 128 lines to 43 and `forward` from 80 to 39.

The mutation sweep shows the difference directly: disabling the local-subnet stage used to
be two separate mutations catching 2 records between them, and is now one catching **8** —
the same policy, reached from both paths.

**Broadcast is judged against the interface it arrived on.** `csp_route.c:235` is
`csp_id_is_broadcast(packet->id.dst, input.iface)` — the *ingress* interface, not every
interface the node has. So a packet addressed to another subnet's broadcast is **not** for
this node and is relayed, while the ingress subnet's broadcast is delivered and
deliberately not relayed on. Widening it to "any interface I know about" is the plausible
wrong fix and would both swallow traffic meant for a neighbouring subnet and stop relaying
it. Measured in the three `conn::..._broadcast_...` records, which count what the
application receives *and* how many frames leave, because those are the two halves that can
disagree.

**Scratch arrays must be sized by `RXQ`.** `Table::close`, `close_all` and `expire_idle`
all refuse rather than partially draining a connection's receive queue — a slot removed but
not reported is a slot nobody releases. **Five** call sites passed fixed literals — `[0u16; 8]` on the
RST path, `[0u16; 32]` in `tick`, `shutdown`, `Node::unbind` and `Node::close` — while
`RXQ` is a const generic, so a queue deeper than the literal made the drain fail *in
silence*: measured at nine buffers
lost for good when a peer reset a connection holding nine unread packets. `tick`'s sweep
would retry, but a reset happens once and `shutdown` runs once. All five now size by `RXQ`, the bound on a
single queue, and the two that call a stop-when-full API (`unbind`, `shutdown`) loop.

The two found later are the worse pair, because neither is a background sweep that gets
another chance:

- **`Node::unbind`** called `close_port` once. Past the array's capacity the remaining
  connections stayed **open on a port the application had stopped serving** — still
  matching incoming packets, which is the exact situation unbinding exists to prevent —
  each holding a buffer per unread packet. Measured: three connections of twelve packets,
  two closed, one left open with twelve buffers gone.
- **`Node::close`** propagated `BufferTooSmall` with `?`. An application closing a
  connection whose queue was deeper than 32 got an *error* from the one call it makes when
  it has nothing left to try, and the connection stayed open. Measured:
  `BufferTooSmall { needed: 33 }`.

Sizing by `RXQ` makes both unreachable rather than unlikely: `rx_len <= RXQ` by
construction, so the refusal branch cannot be taken.

`rdp::Action` names **one** action per step, and for in-order data that action is `Deliver`
— so the acknowledgement can only come from the separate `poll_ack`. Nothing called it, so
the first version of this wiring delivered RDP data to the application and acknowledged none
of it: correct to the application, and a peer that retransmits every packet until
`MAX_RETRANSMITS` and then gives up. The ack is now queued alongside the delivery and
surfaces on the next `work` call, the same as a fan-out destination.

Fixing that exposed a second divergence in `csp-core`, invisible while nothing polled an ack
after a handshake: the **server** SYN path set `rcv_lsa = seq_nr - 1`, which is the *client*
path's assignment (`csp_rdp.c:601`, where acking at once is the point). `csp_rdp.c:556` sets
all three of `rcv_cur`/`rcv_irs`/`rcv_lsa` equal on the server path, so the handshake leaves
nothing owing. Ours emitted one gratuitous ack after every incoming connection.

**Still not done: this node cannot open an RDP connection.** `Node::connect` continues to
refuse `RDP_REQ` with `Error::Unsupported { feature: Rdp }`, and the application send path
adds no trailer and queues nothing for retransmission. So the port speaks RDP as a server
and not as a client. Refusing remains better than flagging RDP without speaking it, which
would have the peer read five bytes of payload as a header.

**Why the audits missed it.** `AUDIT.md`'s RDP entry audited `csp-core/rdp.rs` against
`csp_rdp.c` function by function and was right about all of it. Nothing asked whether the
layer above called any of those functions. This is the `Router::forward` shape again — a
component with green tests that nothing reaches — and it is the second instance, which
makes "is this reached from the node?" a question the node suite has to answer per feature
rather than a thing to notice.

Three further items listed in the feature table above are **not implemented**, and none is
in scope for the goal:

- **`yaml`** — configuration file loading. Off by default in the C too, meaningless on a
  `no_std` flight target, and libyaml is not installed here so there is no oracle. Routes
  are configured programmatically or through `rtable::parse`.
- **`if-tun`** — the tunnel interface, which exists to carry the two `csp_crypto_*` hooks.
  No flight relevance.
- **`print`** — the debug printer. Its C form is a variadic function plus ten `uint8_t`
  counters written from two contexts without synchronisation; the replacement is the
  typed counters already on `Router` and `Interface`.

## Deviations from the C that are intentional

These are places the port deliberately does **not** reproduce C behaviour. Each one is a
defect in the original, and each is covered by a conformance test asserting the *new*
behaviour.

**This list is a record, not a bug report.** Nothing here is filed upstream; it exists so
whoever maintains the fork can see what was found and decide for themselves.

1. **`csp_port` re-init leak** — `csp_port.c:30` relies on `.bss` and has no
   `csp_port_init()`, so a second `csp_init()` leaks bindings. The C unittests only
   survive this because libcheck forks per test. `Node::new` starts clean.
2. **Duplicate weak `csp_input_hook`** — defined `__weak` twice in one library
   (`csp_route.c:106` and `csp_bridge.c:19`); which wins is link-order dependent. Becomes
   one trait method.
3. **Wrong-shape SFP delivery is destructive** — `csp_sfp_header_remove` (`csp_sfp.c:32-35`)
   bails the moment `CSP_FFRAG` is clear and the caller frees the packet, so a plain
   datagram sent to a stream port is lost with a misleading `-103`. The port returns the
   packet to the handler instead.

   Measured on 2026-08-25 rather than read. `csp_sfp_recv_fp` given a well-formed datagram
   returns **-103 with the packet freed and nothing delivered** — and the same -103 for a
   genuinely corrupt fragment, recorded as `indistinguishable: true`. So the application
   cannot tell "you used the wrong reader on valid data" from "the peer sent rubbish", and
   in both cases the data is gone. Which shape arrived is a per-packet flag any peer
   controls, so a narrow handler is one flag away from silently losing a message.
   `Delivery::classify` returns `Datagram(packet)` with the payload intact.
   Corpus cases: `sfp::a_plain_datagram_given_to_the_stream_reader_is_destroyed` and
   `sfp::a_corrupt_fragment_reports_the_same_error_as_a_wrong_shape` — the second compares
   the pair directly, and the port answers `indistinguishable: false` where the C answers
   `true`.
4. **`csp_buffer_free` sets an error code on the success path** — `csp_buffer.c` flags
   `CSP_DBG_ERR_REFCOUNT` on the perfectly normal "still referenced" branch.
5. **`csp_buffer_copy` copies stale `next`/`conn` pointers** into the clone
   (`csp_buffer.c:163`) and nothing clears them.
6. **`route_work()` reports idle as an error**, which forces callers to filter a normal
   tick.
7. **`csp_buffer_get_always` hangs forever on exhaustion** (`csp_panic` then `while(1)`,
   and the default `csp_panic` just returns). The port returns an error.
8. **`csp_transaction` demands an exact reply length** unless given `-1`. All three
   existing consumers work around this identically; the port returns an owned reply.
9. **The reboot service reads past the packet.** `csp_service_handler`'s `CSP_REBOOT`
   case does `memcpy(&magic_word, packet->data, sizeof(magic_word))` with **no length
   check**, so a one-byte packet sent to port 4 compares four bytes against a payload that
   has one. Buffers are pooled and reused, so the extra bytes are whatever the previous
   user left there. Not a remote reboot primitive — matching a 32-bit magic by accident is
   unlikely — but an out-of-bounds read on the one port whose job is recovery, reachable
   by anyone who can send a packet. The port requires the four bytes.
10. **Deduplication stops working for the last 100 ms before the 49-day clock wrap** —
    not, as this entry said until 2026-08-26, *after* the wrap. `csp_dedup.c:32` compares
    `time > csp_dedup_timestamp[i] + CSP_DEDUP_WINDOW_MS` on a free-running 32-bit
    millisecond counter. Two things can go wrong: `stamp + 100` can overflow, and `time`
    can wrap. **Where both happen they cancel**, so the naive comparison is correct across
    the wrap itself. Where only the addition overflows — the last window before the counter
    turns over — `stamp + 100` is a small number while `time` is still huge, every entry
    looks expired, the scan breaks on the first one, and duplicates are delivered.

    Both sides are now measured on a real libcsp node rather than reasoned about, the
    virtual clock being what makes 2^32 reachable by assignment:
    `dedup::a_duplicate_in_the_last_window_before_the_wrap` (40 ms apart, both before the
    wrap — the C delivers **2**, the port suppresses, `diverges`) and
    `dedup::a_duplicate_across_the_clock_wrap` (60 ms apart, spanning the wrap — both
    deliver **1**, `must_match`). The port ages by wrapping subtraction throughout.

    The correction matters beyond the wording: "dedup dies at 49 days" and "dedup drops one
    100 ms window every 49 days" are very different operational claims, and only the second
    one is true.
11. **`csp_if_eth_unpack_header` is asymmetric with its packer and shifts into a sign
    bit.** The packer writes `packet_id`/`src_addr` with `htobe16`; the unpacker does
    `*packet_id = buf->packet_id << 16 | buf->src_addr` with no `be16toh` on either. The
    recovered value is byte-swapped relative to what was sent (harmless only because both
    ends make the same mistake and it is used as an opaque key), and `buf->packet_id` is a
    `uint16_t` promoted to `int`, so `<< 16` with the top bit set is undefined behaviour.
    Separately, the header the code implements is **not** the bit-packed EFP header its
    own file comment specifies.
12. **The bridge forwards a stranger's packet into side A.** `csp_bridge_work` picks the
    opposing interface with `if (input.iface == bif_a) destif = bif_b; else destif = bif_a;`
    — no third branch. A frame arriving on an interface that is neither side of the bridge
    is injected into side A as though it had come from side B. The port refuses it.
13. **`csp_hmac_verify` compares the tag with `memcmp`.** Not constant time. With a
    32-bit tag, stopping at the first wrong byte reduces a 2^32 forgery to roughly
    4 × 2^8 attempts, and a spacecraft link has no rate limit an attacker must respect.
    The port compares in constant time.
14. **`csp_hmac_verify`'s length check guards the wrong field.** It tests
    `packet->length < CSP_HMAC_LENGTH` and then, in the `include_header` branch, computes
    `packet->frame_length - CSP_HMAC_LENGTH`. A packet with `length >= 4` but
    `frame_length < 4` underflows that subtraction to about four billion and hashes far
    past the buffer.
15. **The SFP fragment flag is sticky on the connection.** `csp_sfp.c:131` does
    `conn->idout.flags |= CSP_FFRAG` inside the send loop, and **nothing in the library
    ever clears it** — grep across `src/` finds exactly one write and no reset. So after a
    single SFP transfer, every later plain datagram on that connection is marked as a
    fragment. Combined with deviation 3, the receiver then parses it as one, fails, and
    frees it: the sender creates the condition and the receiver destroys the packet. The
    flight code runs SFP on the config and log-dump ports, so any connection reused for a
    plain reply hits this. In the port the flag lives on the packet, not the connection.
16. **A CMP peek reply pads itself with unrelated buffer contents.**
    `csp_cmp_peek_handler` writes `len` bytes at `cmp->data` — packed offset **7** — and
    then sets `packet->length = CMP_PEEK_SIZE(cmp->len)`, which is
    `sizeof(struct) + tail + len` = **10 + len**. The last three bytes are never written,
    so they are whatever the previous user of that pooled buffer left there. On a service
    whose entire job is reading memory, padding the reply with unrelated memory is the
    wrong direction to be wrong in. The port emits the same wire length, so a C peer sees
    the size it expects, but **zeroes** the tail.
17. **`csp_ping` never checks the reply length.** It verifies the *content* correctly —
    filling the request with `i % 256` and checking every byte — but its loop runs to the
    **requested** size and indexes `packet->data[i]` without consulting
    `packet->length`. A short reply is compared against stale bytes left in the pooled
    buffer. Usually those fail the pattern, so the ping reports failure for the wrong
    reason rather than passing wrongly; the comparison is still reading data that is not
    part of the reply.
18. **`csp_conf.version` is silently unsafe to change after `csp_init()`.** Found while
   building the oracle. `host_bits` (5 for v1, 14 for v2) is baked into the routing and
   broadcast maths at init, so flipping the version afterwards misroutes every packet
   into the qfifo where nothing drains it. Measured: 18/18 sends clean under v1, then the
   same 18 sends after switching to v2 leak **one buffer per fragment** until the pool is
   empty and every call returns `CSP_ERR_NOMEM` — with no error reported at the point of
   misuse. Nothing in the API says the field is init-only. In the port the version is an
   immutable field of the `Node` value, so this is unrepresentable.
19. **CMP `PEEK`/`POKE` are arbitrary memory read and write, on by default.** The handler
    checks only `len <= 200`, then calls `csp_cmp_memcpy` with an address taken straight
    off the wire. The default `csp_cmp_memcpy` (`csp_cmp_mem.c:15`) is a bare `memcpy`
    with no validation of any kind. So a node built with CMP — the default — will read any
    32-bit address a peer names and send the contents back, and write to any address a
    peer names. The 64-bit variants `csp_cmp_memread64`/`csp_cmp_memwrite64` default to
    `CSP_ERR_DRIVER`, i.e. refusing, which is what makes the 32-bit pair look like an
    oversight rather than a decision. Compounding it, `csp_cmp_set_memcpy` — the function
    an integrator would call to install a validating replacement — has an **empty body**:
    it takes the pointer, discards it, returns. It carries `CSP_DEPRECATED`, so a compiler
    warning is the only signal, and embedded builds routinely suppress those. In the port
    the equivalent is `Hooks::mem_read`/`mem_write`, whose **defaults refuse**; a node that
    wants the service implements them for the one region it is willing to expose.
20. **Re-registering an interface silently unlinks every interface after it.**
    `csp_iflist_add` sets `ifc->next = NULL` *before* walking the list to check whether
    `ifc` is already in it. When it is, the duplicate check returns — but `next` has
    already been cleared, so every interface registered after this one is now unreachable
    from the head. The function returns `void`, so nothing is reported. Add LOOP, add CAN,
    call `csp_iflist_add(&csp_if_lo)` a second time, and CAN has left the node. The port
    returns `Error::DuplicateName` and touches nothing.
21. **`iface->irq` is declared, printed and telemetered, and never incremented.** Grep
    across `src/` and `include/` finds no write to it anywhere in the library. It is
    printed by `csp_iflist_print` and reported over CMP `IF_STATS`
    (`csp_cmp_if_stats.c:27`), so ground software receives a field that is structurally
    always zero. Kept in the port because a driver may legitimately fill it in, with
    `Interface::note_irq` as the way to do that.
22. **`txbytes`/`rxbytes` exclude the header they just added.** Both count
    `packet->length` — the payload — not the framed length (`csp_io.c:282`,
    `csp_route.c:230`). For the 8-byte telemetry packets this fleet sends, a field
    documented as "Transmitted bytes" under-reports the link by a third. The port counts
    the frame, consistently on both sides.
23. **A UDP interface can never report a transmit error.** `csp_if_udp_tx` ignores
    `sendto`'s return value entirely, and returns `CSP_ERR_NONE` even when it took the
    early exit for a missing socket. `csp_send_direct_iface` therefore increments `tx` and
    `txbytes` for every packet, and `tx_error` on a UDP interface is structurally zero. A
    node whose UDP peer is unreachable reports a perfectly healthy link.
24. **`csp_listen`'s backlog parameter is ignored.** `(void)backlog;` — the RX queue is
    always `CSP_CONN_RXQUEUE_LEN`, a compile-time constant. An application asking for a
    backlog of 1 to bound its memory, or 100 to absorb a burst, gets neither and is told
    nothing. The port has no separate listen step: `bind` is the whole operation, and the
    backlog is a const generic on the node, so the number is where the storage is.
25. **`csp_socket_close` unbinds only the first port that names the socket.** It `break`s
    out of the scan (`csp_port.c:145`), but `csp_bind` never checks whether the socket is
    already bound elsewhere — it only checks that the *port* is free. So one socket bound
    to ports 10 and 11, then closed, leaves port 11 pointing at a socket whose receive
    queue has just been drained and whose storage the caller is about to reuse. In the
    port a port is unbound by number, so the situation cannot arise.
26. **RDP options are process-wide.** `csp_rdp_set_opt` writes six file-scope statics that
    every subsequent connection copies from (`csp_rdp.c:801-804`, `920-921`). They are read
    at connection setup, not per packet, so already-open connections keep their negotiated
    values — but any component calling it changes the defaults for every other component
    in the node. In the port they are per-connection `SynOptions`; a test pins the default
    values to the C's compiled-in ones, because a Rust node and a C node that disagree here
    negotiate different windows.
27. **A one-character route-table entry ends the C's parse and it reports success.**
    `while (str && (strlen(str) > 1))` (`csp_rtable_stdio.c:25`) is the loop condition, so
    the first short token terminates parsing. Every entry after it is dropped and
    `csp_rtable_load` returns the count it managed before stopping — a non-negative number,
    which every caller reads as success. `"1 CAN,2,3 KISS"` installs one route and reports
    it worked. Confirmed by a differential test; the port skips the short entry and parses
    the rest.
28. **The route table is truncated at 100 characters, and what that costs depends on where
    the cut lands.** `strnlen(rtable, 100)` into a VLA (`csp_rtable_stdio.c:17-20`). If the
    cut falls mid-entry, the fragment fails to parse and the *whole* load is rejected — a
    completely valid table refused for being long. If it falls on a separator, every
    surviving entry parses, a positive count comes back, and the dropped tail is never
    mentioned: the caller sees success and a routing table missing routes. Both cases are
    pinned by differential tests. The port parses the whole string.
29. **A KISS frame without a CRC32 is dropped silently by any stock C peer.**
    `CSP_ENABLE_KISS_CRC` defaults to `ON` (`CMakeLists.txt:50`) and `csp_kiss_rx` runs
    `csp_crc32_verify` on every completed frame; a frame that fails is dropped with
    `iface->frame++` and nothing else — no log line, no error to any caller, nothing on the
    wire. A node whose frames all vanish this way is indistinguishable from one with a dead
    UART. Not a defect in the framing, but a deployment default sharp enough that
    `kiss::encode`'s documentation now states it, backed by a differential test against the
    real `csp_kiss_rx`.
30. **A truncated SFP transfer is reported as a complete one.** `csp_sfp_recv_fp`
    (`csp_sfp.c:168-265`) seeds `int error = CSP_ERR_TIMEDOUT`, but every accepted fragment
    overwrites it with the return of `user->write`, and a successful write returns
    `CSP_ERR_NONE`. The reassembly loop ends when `csp_read` comes back NULL, falls into
    the `error:` label, and returns whatever `error` last held — so a transfer that stops
    early returns **0**, the same code as one that finished.

    Measured on 2026-08-26 rather than read. Ten bytes promised, five delivered, nothing
    behind them: `ret: 0, writes: 1, assembled: "hello"`. The application is told the
    message arrived while holding half of it. A caller *can* notice — `user->write` is
    given `totalsz` on every call, so it can sum the sizes it was handed and compare — but
    it has to know to. The `error = CSP_ERR_TIMEDOUT` seed shows the intent was the
    opposite.

    Only reachable with more than one fragment, which is why the earlier SFP tests missed
    it: all seven handed `csp_sfp_recv_fp` a single packet, so the reassembly loop had
    never run against the C at all.

    The port returns `Error::Truncated` from `Stream::read_chunk` when the source runs dry
    before `total` bytes, and `is_complete()` stays false. Corpus case:
    `sfp::a_transfer_that_stops_early_still_reports_its_last_write` — the two agree on
    `writes` and on the bytes delivered and disagree only on `ret`, which is the point:
    the same data, one stack calling it a success.

---

## Port defects found by the node-level differential harness

Not divergences from the C — **bugs in this port**, found on 2026-08-25 by building the
Rust-node-against-C-node harness that the plan called for and the branches were reported
done without.

1. **A forwarded packet was destroyed and never sent.** `Router::forward` reported
   `Routed::Forwarded { iface, via }` and then `drop(packet)`, with a comment deferring to
   a `Node::forward` **that was never written**. Nothing anywhere re-sent it. So the node
   routed nothing at all: every packet addressed to another node was silently discarded
   while the router reported success and incremented `forwarded`. `Routed::Forwarded` now
   carries the pool slot index, reclaimed with `Node::take_forwarded`.

   The shape of the enum caused the bug: `Routed` has no lifetime or size parameters, so
   there was nowhere to put the packet, and dropping it compiled.

   It survived 451 unit tests, the `csp::router` audit and the `csp::node` audit. What
   the unit tests asserted was the *interface index* the router chose — never that a frame
   reached a wire. The C-node comparison found it in one test.

2. **`SHIM_PORTS` was 8 while `CSP_PORT_MAX_BIND` is 16** (harness, not the port): binding
   port 10 returned an error nobody checked, so the first version of the harness compared
   "C delivered nothing" against "Rust delivered correctly" and looked like a port bug.
   Checking the C's own return code is what separated the two.

**v2 at node level.** Every node-level test in `diff.rs` pinned `Version::V1`; the
`versions()` loops there are all codec-level, so v2 *headers* were verified and v2
*routing and delivery* had never been exercised at all. `difftest/tests/node_v2.rs` now
runs the same four behaviours on v2 — in its own test binary, because `csp_conf.version`
is init-only and one process gets one C node at one version. The topology had to be
recomputed rather than copied: v1's netmask of 2 means 12 network bits under v2's 14 host
bits, which collapses both interfaces into subnet 0 and would have produced a test that
passed by asserting nothing happened. All four pass, with source addresses deliberately
biased above 31 so the cases could not have been carried by a v1 header.

3. **The routing table was consulted before local subnets — a whole precedence level was
   missing.** `csp_send_direct` tries **local subnets first** (`csp_iflist_get_by_subnet`),
   and if any interface owns the destination's subnet it sends there and `return`s; the
   routing table is only the fallback for destinations no interface owns, and the default
   interfaces are the fallback after that. Each level is terminal: if it matched but split
   horizon left nothing usable, the packet is dropped rather than falling through.

   `Router::forward` began at the routing table, so a route could divert traffic the C
   would have put straight onto the interface owning that subnet. `Router::work` now takes
   the interface list — it cannot decide correctly without it — and implements all three
   levels, with split horizon comparing *subnets* (`is_same_subnet`) rather than interface
   identity. The router was also discarding the ingress interface `qfifo.pop` handed it,
   which is what split horizon needs.

   **How this was nearly missed twice.** The first version of the test compared the
   forwarded frame's *bytes* and passed — the bytes are identical whichever link the packet
   leaves by. It only failed once strengthened to compare which interface the frame went
   out of. Every forwarding test now asserts the interface, not just the frame.

4. **"Is this packet for me?" was one condition where the C has three.** `csp_route.c`:

   ```c
   int is_to_me = (csp_iflist_get_by_addr(packet->id.dst) != NULL
                || csp_id_is_broadcast(packet->id.dst, input.iface)
                || csp_addr_is_alias(packet->id.dst));
   ```

   — **any** interface's address, the broadcast address of the interface it **arrived on**,
   or a bound alias. The port had
   `id.dst == self.address || is_broadcast(id.dst, self.address, 0)`. Three defects in one
   line:

   - *A packet for the node's other interface was forwarded back onto the wire.* A node
     with a CAN interface and a KISS interface answers to both addresses in the C; the port
     recognised only one, so a command addressed to the radio-side address was bounced onto
     the bus instead of delivered. Measured against the C: it delivers, the port emitted a
     frame.
   - *Every subnet broadcast was missed.* The hardcoded netmask `0` makes the host mask the
     whole address space, so the subnet test degenerates to `addr == max_node_id()` — the
     global broadcast — and a packet to an interface's own subnet broadcast was forwarded
     rather than delivered. `Version::is_broadcast` itself was correct, including the global
     case; only its arguments were wrong.
   - *Aliases were never consulted*, though `IfList` implements them.

   `IfList::find_by_addr` covers the interface addresses and the aliases together, and
   `is_broadcast_for` takes the ingress interface. Verified by temporarily restoring the
   old line: all three new tests fail without the fix.

**Still open:** the alias branch is fixed but **not** covered by a differential test — the
C shim would need `csp_alias_add` wired up. It rides on `find_by_addr`, which the
interface-address test does exercise.

**Closed on 2026-08-26.** `csp_send_direct` never picks an interface: it walks every match
and **clones the packet for each**, keeping one behind so the last match gets the original.
Measured on the real libcsp by `ctest/suite_route.c`, counting frames and the interfaces
they left by:

| | frames | left by |
|---|---|---|
| one link owning the destination | 1 | `LINK_A` |
| two links owning it | **2** | `LINK_A`, `LINK_B` |
| two default interfaces | **2** | `LINK_A`, `LINK_B` |

The port sent **one frame where the C sends two**, in both the subnet scan and the default
scan, and the one it sent was the *last* match — `chosen = Some(..)` overwrote on each
iteration. That is the entire point of a redundant link quietly not happening: every test
asking "did it forward" passed, because it did forward, once.

`Router` now keeps a small pending-forward queue. `finish_forward` takes the whole
destination list, clones for all but the last, and `work` hands them out one per call — a
step at a time, like everything else it does. A clone the pool cannot supply is counted in
`fanout_missed` rather than dropped silently; the C passes `csp_buffer_clone`'s result
straight to `send_packet` with no NULL check, so there running out of buffers costs the
node rather than a destination.

`just mutants` keeps it honest: collapsing the fan-out back to a single destination is
caught by two records.

**Closed on 2026-08-26: a connection was not an endpoint.** `deliver_local` refused any
packet whose destination port was not bound, before ever consulting the connection table.
`csp_route_deliver` (`csp_route.c:276-285`) looks up *both* — the socket table and
`csp_conn_find_existing` — and drops only when neither matches, because a reply to a
connection this node opened arrives on the ephemeral source port `connect` chose and
nothing ever binds that.

So **every reply to every connection the port opened was dropped** as `PortNotBound`:
`Node::connect` produced a connection that could not receive. The client API, the CMP
client and RDP's `SYN|ACK` were all dead for the same reason. 495 tests, two module audits
and the whole corpus passed, because nothing had ever put a reply into a node that had
called `connect` — every node-level test drove the *server* direction.

Found by coverage rather than by reading: `Action::SendSyn` showed as never executed, which
led to `Event::Connect` being constructed nowhere, which led to `Node::connect` refusing
RDP, and the client path came apart from there.

Corpus case: `conn::a_reply_reaches_the_connection_that_asked_for_it` — the C delivers
`"pong"` to the connection, the port delivered nothing. Mutation
`conn: a connection is an endpoint too` restores the old order and the record fails.

**A correction to how this was nearly reported.** The first version of that C test read the
ephemeral port with `csp_conn_sport`, which returns `idin.sport` — the *remote* port.
`csp_conn_dport` is the one that returns the ephemeral port a client connection listens on.
With the wrong accessor the C also dropped the reply, and the measurement said the two
stacks agreed. The "nothing bound this port" guard passed either way, since the remote port
20 is also unbound. A test that confirms the C agrees with a broken port is worse than no
test, and this one was two characters away from being that.

**Also closed: the RDP client.** `Node::connect(RDP_REQ)` used to return
`Error::Unsupported`. `csp-core`'s `State::SynSent` and `Action::SendSyn` were complete and
unit-tested the whole time, and unreachable, because nothing constructed `Event::Connect` —
the router carried a match arm for an action it could never receive. `connect` now seeds the
sequence number, queues the `SYN`, and `Node::is_rdp_open` reports when the peer's
`SYN|ACK` has opened the connection. `csp_rdp_connect` blocks until that reply arrives;
sans-io has nowhere to block, so the caller drives it.

The C's own SYN is measured by `rdp::an_rdp_connect_puts_a_syn_on_the_wire`: `csp_connect`
emits the frame *before* it blocks on the semaphore its router task would release, so the
frame is comparable even though the call is not. Flags, acknowledgement and option-block
length match. The sequence number is excluded on purpose — it is the ISN, and the port
deliberately does not reproduce `rand_r(csp_get_ms())`.

**Closed on 2026-08-26: the C node could not answer.** Every node-level differential test
drove the *server* direction — a frame in, a delivery or a forward out. `shim_node_recv`
accepts a connection, reads the packet and closes; nothing in the harness could make a real
C node **reply**. That is the structural reason the client direction shipped broken: there
was no way to observe it.

`shim_node_serve` closes it. It accepts on a bound well-known-service port and hands the
packet to `csp_service_handler`, which answers with `csp_sendto_reply` — so the reply is
composed by libcsp, not by the harness. Linking it pulled in `csp_cmp/*.c`,
`arch/posix/csp_system.c` and `arch/posix/csp_clock.c`, which had been compiled and
dead-stripped because nothing referenced the handler.

Two round-trips now run the port as a client against a real C server:

- `a_reply_from_a_real_c_node_reaches_the_connection_that_asked` — the port connects, sends,
  libcsp's `CSP_PING` handler echoes, and the reply is read off the connection that asked.
  Reverting the endpoint fix above makes it fail with nothing delivered.
- `the_cmp_client_understands_what_a_real_c_node_answers` — `client::cmp_request` builds an
  `IDENT`, `csp_cmp_handler` answers, `client::check_cmp_reply` and `cmp::Ident::decode`
  read it. Both halves of the CMP client had only ever been tested against bytes this
  repository composed. The reply is exactly `Ident::LEN` (93), and the assertion is on
  `date`/`time` — the *last* two fields — because one byte of drift in any earlier field
  width makes those unreadable. Narrowing `len::MODEL` by one byte fails the test.

**Corrections along the way.** The ping test first read the request with `with_frame`
without calling `prepend_header`, so it sent an empty frame and blamed the C node for
answering nothing — `send` decides where a packet goes and does not frame it. And
`cmp::Ident::decode` takes the whole message, header included (`Ident::LEN` counts those
two bytes); passing only the body made a correct decoder look truncated. Both were mistakes
in the test, and both initially looked like defects in the port.

The CMP test also carried a `#[cfg(feature = "cmp")]` that `difftest` does not define, so it
compiled to nothing and the run reported 7 passing tests as though all 8 had run. Caught by
counting, not by reading the output.

**Closed on 2026-08-26: the initiator never sent the handshake's third leg.** On
`SYN_SENT` + `SYN|ACK`, `csp_rdp.c:610` sends `ACK(seq = snd_nxt, ack = rcv_cur)`. The port
returned `Action::Opened` and put nothing on the wire, so a peer stayed in `SYN_RCVD`,
retransmitted its `SYN|ACK`, and gave up. The connection died under a client that opened it
and then waited for the server to speak first.

It looked like it worked because the initiator's *first data packet* also carries `ACK` with
the right sequence numbers and drags the peer open. Any test that connected and immediately
sent data — which is every obvious way to write one — passed.

Found by pointing the port's RDP client at the C node that was already in the difftest
build. `CSP_USE_RDP=ON` has been set there all along and the C answers a `SYN` from its
router with no application involved, but a comment in `diff.rs` asserted "the C node under
test here speaks no RDP". Nothing had checked that, and it was wrong; believing it is why
nothing ever sent the C a SYN.

`an_rdp_connection_to_a_real_c_node_handshakes_then_carries_data` drives all three legs and
then a data packet. Restoring `Action::Opened` fails it on the third leg. The unit test
`three_way_handshake_as_the_initiator` had asserted `Action::Opened` — encoding the missing
frame as though it were correct, which is the self-referential shape this whole exercise
exists to remove. It now asserts the `ACK` and cites the C line that sends it.

**Closed on 2026-08-26: a reset connection was reported as back-pressure.** `Node::send`
returned `Error::SendWindowFull` whenever `begin_send` declined, and `begin_send` declines
for two unrelated reasons — the window is full, or the connection is not open.
`csp_rdp_send` (`csp_rdp.c:863`) separates them: `CSP_ERR_RESET` when the state is not
open, and it blocks only for the window. The two need different handling, and the port gave
the caller no way to tell: `SendWindowFull` says "retry", so an application would retry for
ever against a peer that had hung up.

The variant's own documentation carried the contradiction in plain sight — "Either it is
not open, or `snd_nxt` has reached …" one sentence, "*temporary*: the same packet on the
same connection succeeds once an acknowledgement arrives" the next. Both were written here,
and only one can be true. `Error::ConnectionReset` now covers the permanent half.

Found while checking something else: whether a burst larger than one window survives, i.e.
whether the peer's acknowledgements are consumed. **They are** — ten packets over a window
of four, with `snd_una` advancing throughout, so that half was already right. The burst only
exposed the error-reporting defect because the first attempt closed the C's connection
underneath, and the port then reported "window full" for a connection that had been reset.

`an_rdp_connection_sustains_traffic_and_reports_a_reset_as_a_reset` covers both halves.

**A harness constraint this made explicit.** RDP leaves durable state on the C node — an
open or half-closed connection, packets queued on it, buffers held — and libcsp has no
per-test reset. Sharing a process with `node_v2.rs` made tests interfere: a SYN landed on a
connection an earlier test had opened, and the buffer-accounting test counted connections it
had never made. The RDP tests now live in `difftest/tests/node_rdp.rs`, a third binary, for
the same reason `node_v2.rs` is separate from `diff.rs`. Each binds its own destination port
so the two cannot alias each other's connections either.

**2026-08-26: a real C peer originating RDP data.** Every node-level exchange until now had
the port sending and the C receiving. `shim_node_send_on` is the other direction: the C
accepts a connection, keeps it, and calls `csp_send` on it, so for an RDP connection the
bytes are sequenced and held for retransmission by `csp_rdp_send` itself. What reaches the
port is a real peer's data, which it has to deliver and acknowledge.

**No defect. The port was already right**, which is worth stating plainly given the run of
findings before it: ten messages from the C over a window of four all arrive intact and with
the trailer removed. That only works if the port acknowledges as it goes — a port that
stopped would shut the C's window after four and the rest would never be sent. The mutation
`rdp: we acknowledge what we receive` holds it there.

**A harness limitation, measured rather than assumed.** RDP leaves state on the C node that
cannot be cleared in-process. Closing every connection through libcsp's own
`csp_conn_get_array` hook *and* flushing both global `csp_rdp_queue` queues still left **ten
of fifteen buffers held** after a ten-packet burst, so the third test in a binary began with
a third of the pool gone and failed depending on which order the threads ran in. Five of six
runs passed, which is the worst possible failure rate — it trains you to re-run.

A reset that does not reset is the same trap as a test that cannot fail, so it was removed
rather than kept as reassurance. Each RDP scenario now gets its own integration-test file
and therefore its own process: `node_rdp.rs`, `node_rdp_peer.rs`, `node_rdp_reset.rs`. That
is the only reliable reset available, and the precedent already existed — `node_v2.rs` is a
separate binary from `diff.rs` for the same reason. Verified over eight consecutive runs.

**A tooling regression, measured and fixed.** Adding `-p difftest` to the mutation sweep two
cycles ago was correct — it is the only thing covering the port against a *running* C node —
but I never measured what it cost. It links the C library into seven test binaries for each
of 127 mutations, and the sweep went past its fifty-minute timeout and was **killed
mid-mutation**, twice leaving a mutated source file behind. A sweep that slow stops being
run, and one that dies mid-run corrupts the tree.

It now runs the cheap packages first and pays for `difftest` only when nothing cheap
noticed. The guarantee is unchanged — no mutation is reported unnoticed without difftest
having been tried — and the measurement is **259 s against >3000 s**, on the same 127
mutations, same machine, same day.

**2026-08-26: RDP at v1 through a node.** Every node-level RDP test was v2. v1 is not a
cosmetic difference: 5 address bits against 14, a 4-byte header against 6, 6-bit ports. The
RDP trailer sits at the end of the payload either way, but everything around it moves.

**No defect.** The handshake and data carry over v1 exactly as at v2, against a real C peer
that answers the `SYN` from its router. `csp_conf.version` is init-only, so this is its own
binary (`node_rdp_v1.rs`) — one process, one C node, one wire version.

The test asserts the frame's **shape**, not just that it worked: a v1 SYN is
`header_size(V1) + SYN_OPTIONS_LEN + HEADER_LEN` = 33 bytes, where v2 is 35. Without that
it would pass identically at either version and prove nothing about v1 — measured by
setting `VERSION` to `V2` and watching it fail 35 against 33. A second assertion states
that the two header sizes differ, so the first one stops being a distinguisher loudly rather
than silently if that ever changes.

**2026-08-26: retransmission and reordering against a real peer.** Both had only ever been
driven at the libcheck level with hand-built frames, where the give-up case is a recorded
divergence. Two things that only a real peer can answer:

- **A lost packet's retransmission is one the C accepts.** The port sends, the frame is
  never handed to the C, the clock passes `packet_timeout`, and the port resends. The
  retransmitted copy carries the original sequence number and a *refreshed* acknowledgement
  — an earlier bug in that refresh wrote the ack past the trailer and stretched the packet
  to the whole buffer, which nothing on this side would notice. The C's application receives
  the payload exactly once, intact. `node_rdp_retransmit.rs`.
- **A real peer's frames are reordered before the application sees them.** libcsp sequences
  the two messages; the harness hands them to the port second-first, which is what a network
  does. Both arrive, in order. `node_rdp_reorder.rs`.

**No defect in either.** Verified by control rather than by passing: suppressing
retransmission fails the first with nothing resent after four packet timeouts, and dropping
the held frame fails the second with `["first"]` where two were expected.

**A mistake in the reorder test worth keeping.** It first collected deliveries only when
`work` reported `Routed::Delivered`, and reported an empty application queue — the released
frame arrives without a fresh event, so the data was sitting on the connection unread. The
test now reads the connection itself. It looked exactly like the port dropping the
overtaking packet, which is the defect it was written to find.

**2026-08-26: deduplication, node against node.** Covered in `ctest/` against a real C node,
but not in the differential harness where the recent defects surfaced. `csp_dedup_is_duplicate`
keys on a CRC32 over the **framed** bytes — after `csp_id_prepend`, so the header is part of
the key — with a 16-entry ring and a 100 ms window; the port's `Dedup` claims the same. That
was two readings of two implementations. `node_dedup.rs` compares them.

**No defect.** Three cases, all matching: dedup **off** (the default on both sides) delivers
the duplicate twice; **incoming** delivers it once; two frames differing only in source port
are not duplicates for either. The off case matters as much as the on case — a port that
deduplicated by default would look identical to a correct one in any test that only checked
the on case, and would silently swallow a ground station's retransmitted command.

Verified by control: forcing `applies` to true fails the off case, and keying on the last
five bytes instead of the whole frame fails the distinct case.

**Two harness mistakes, both mine.** The cases first shared their frames, so the third
re-injected one the C had seen microseconds earlier — still inside the 100 ms window and
still in the 16-entry ring — and the C suppressed it for reasons unrelated to the case. It
also compared a warm C ring against a cold port one, since `rust_dedup_exchange` builds a
fresh node per call. Every case now uses frames never sent before.

And the first attempt at the second control silently did nothing: a `\&` escape in a
non-raw Python string meant the replacement never matched, so the test "passed" against
unmutated code. A control that does not mutate proves exactly as much as a test that cannot
fail. It now asserts the anchor was found and that the text changed.

**2026-08-26: the promiscuous tap, node against node.** `csp_promisc_add` sits at
`csp_route.c:252` — after the deduplication check and before the `is_to_me` branch. Two
orderings follow, and a port can get either wrong while every individual piece works: a
packet being *forwarded* is tapped, and a packet deduplication already suppressed is *not*.

**No defect.** The C taps `[NODE_ADDR, 21]` — one delivered, one forwarded — and so does the
port; with dedup on, both tap a repeated frame exactly once. Enabling the tap changes
neither what the application receives nor what leaves on the wire, which is what makes it a
diagnostic rather than a second delivery path.

Verified by control on both orderings, since a tap test that only sends one packet to this
node would pass with either placement. Gating the tap on `for_us` gives `[9]` against the
C's `[9, 21]`. Adding a tap above the dedup early-return gives 2 tapped copies against the
C's 1.

Worth stating: this is a *structural* difference that agrees behaviourally. The C's tap
clones into the shared buffer pool; the port's is a fixed array inside `Router` with
`promisc_missed` counting overflow. The two cannot be compared by reading — only by what the
tap reports.

**2026-08-26: connection-table exhaustion and reuse, node against node.** The last of the
`ctest/`-only behaviours to reach the differential harness. Twenty peers offered to an
eight-slot table, three rounds.

**No defect.** Both accept `[8, 8, 8]` and lose no buffers. Eight is `CSP_CONN_MAX`, so the
*table* was the binding constraint rather than the pool — the case actually filled something,
which the test asserts rather than assumes (`accepted < PEERS`, or the table never ran out
and the case proves nothing).

Verified by control: `mem::forget` on the table-full path leaks 7 buffers against the C's 0,
and dropping `Entry::reset` on close gives `[8, 0, 0]` against `[8, 8, 8]` — a node that
stops answering new peers after the first round, which looks exactly like a leak and is not.

**The two nodes had to be sized the same first.** The C builds with `CSP_CONN_MAX = 8` and
`CSP_BUFFER_COUNT = 15`; the port's node in the other difftest files carries 8 connections
but **24** buffers. Each accepted connection holds its packet until the application reads
it, so at 24 buffers the port runs out of *connections* where the C runs out of *buffers*,
and "how many peers were accepted" would have compared two different experiments. This
file's node is `<8, 15, ...>`. A difference there would have been entirely the harness's, and
I would have had a plausible-looking port defect to report.

### The port acknowledged packets it then dropped

2026-08-27. `csp_rdp_check_ack` opens with a gate the acknowledgement conditions never see:
`abs(CSP_CONN_RXQUEUE_LEN - queue_size) < window_size` — while a connection has less than a
window of spare room the C sends **no** acknowledgement, whatever the delay count or the ack
timeout say. The C's own comment gives the reason: *"Only ACK the message if there is room
for a full window in the RX buffer."*

`acks_stop_when_the_application_is_not_reading` recorded that this never fires, which was
true only of its numbers: with `window_size` 4 the gate needs 13 packets queued and 15
buffers cap an unread connection at 12. Proposing a window of 5 moves the threshold to 12,
which the pool can reach. Measured: **13 delivered, 11 acknowledged, the 12th onward silent.**

The port had no such gate, and worse, acknowledged **before** attempting the enqueue.
Measured against a real C peer: it sent 12, the application could read 8, and **4 packets
were acknowledged to a peer that will never see them** — and which had already released its
only copy. That is not weaker flow control, it is a broken promise: RDP's contract is that
an acknowledged packet was received.

Three parts to the fix, and each needs the others:

1. The acknowledgement follows a successful enqueue, so nothing dropped is ever promised.
2. The gate, so the peer stalls before the queue can overflow.
3. `Node::read` acknowledges once space frees, or the stall is permanent and the connection
   is wedged — `csp_io.c:67` does the same inside `csp_read`.

The gate applies only when `RXQ` is deeper than the peer's window. The C never meets that
condition (`CSP_CONN_RXQUEUE_LEN` 16 against a maximum window of 5); `RXQ` here is a const
generic and may be smaller. Gating unconditionally made `spare < window` true from the first
packet, and such a node acknowledged nothing at all — caught by
`a_delay_count_beyond_the_window_is_bound_by_it`, whose node is `RXQ` 4 against a clamped
window of 5. A second existing record caught `Node::read` passing a literal `0` for the
clock, which wrapped `should_ack`'s timeout comparison and fired on every packet. Both were
bugs in the fix, both caught by records already in the corpus.

Covered by `rdp::the_receive_queue_gate_stops_acknowledgements` and two node tests: the
stall-and-resume cycle, and the `RXQ <= window` configuration where the gate stands aside and
the queue genuinely overflows — the only one in which part 1 is reachable at all, since with
the gate on the peer is stalled before the queue can fill.

**Two process failures worth recording.**

The probe that found this drove the C's sender, and once the port stopped acknowledging
`csp_rdp_send` blocked on its semaphore and the harness hung. The block *is* the
back-pressure working, but it means a probe shaped that way cannot survive its own success;
the durable test drives the port directly.

And reverting a control mutation with `git checkout csp/src/router.rs` **discarded the entire
fix**, which was uncommitted in that same file. Rebuilt from the conversation. A whole-file
checkout is not an undo for a one-line experiment when the file holds work in progress —
this is the second time, and the first is already written down elsewhere in this file.

### The acknowledgement the ack timer owes, that nothing sent

2026-08-27. `csp_rdp_check_timeouts` calls `csp_rdp_check_ack` on every open connection with
delayed acks (`csp_rdp.c:451`). Delayed acks are the **default**, so a peer that sends fewer
packets than `ack_delay_count` is acknowledged only when `ack_timeout` elapses — there is no
further packet to drive it.

The port's `should_ack` had the timeout branch and the node never called it outside the
receive path. Measured: **zero acknowledgements across ten seconds of ticks** with one packet
outstanding, where the C sends one after 250 ms. Not a hang — the peer's retransmission
eventually provokes the ack — but every sub-delay-count exchange pays a retransmission
timeout (1000 ms) instead of an ack timeout (250 ms), on the link that can least afford it.

`Router::tick` now sweeps open RDP connections for an acknowledgement that has come due,
subject to the same receive-queue gate: a connection with no room to invite more data should
not be inviting it, whatever the timer says.

**Why the existing record did not catch it.** `rdp::a_proposed_ack_timeout_is_adopted`
measures exactly this behaviour and passes — because its replay drives `poll_ack` in a loop
itself, standing in for the timer. Its own comment says so: *"The C's loop advances 250 ms at
a time and calls `csp_conn_check_timeouts`."* The replay modelled the timer rather than
using the node's, so it proved `should_ack` correct and said nothing about whether anything
called it. That is this port's commonest defect shape — a correct piece of the core the layer
above never drives — and it is the fourth time: `RxQueue`, `TxQueue`, the CMP server, and now
the ack timer.

**A mutation that had stopped applying.** Rebuilding `router.rs` after a `git checkout`
accident (recorded above) rewrote the gate as one expression where the mutation anchored on
two statements, so `rdp: the receive-queue gate` reported *MUTATION DID NOT APPLY* and the
gate was guarded by nothing. `mutants.py` prints that case rather than counting it as
noticed, which is the only reason it was visible. Re-anchored, and the anchor is now checked
against the source before the sweep is trusted.

### The give-up counter that only ever rose

2026-08-27. `MAX_RETRANSMITS` means "no progress after N", and the C makes that true by
zeroing `conn->rdp.retransmits` on **every** acknowledgement — so N counts *consecutive*
failures. Its comment says exactly that: *"Give up on a peer that never acknowledges
anything."*

The port split that into two counters. `Connection::retransmits` is reset on every ack,
faithfully. `TxQueue::retransmits` — the one the give-up decision actually reads — was reset
only by `flush()` on close, and by a `note_progress()` method that **nothing called**.

Measured: six rounds of send / retransmit twice / acknowledge, with the peer answering every
time, and the queue **gave up on round five**. Twelve retransmissions against a limit of ten,
spread over a connection that was working. On a lossy-but-usable link — which is the
interesting case for a spacecraft — a long-lived RDP connection is torn down for lack of a
progress signal that was being delivered the whole time.

Fixed where progress actually happens: the release of an acknowledged entry inside
`TxQueue::poll`. `note_progress` is removed rather than left as a method a caller must
remember, which is what let this happen.

**Its unit test called `note_progress` directly** and asserted the counter reached zero —
proving the helper worked while nothing performed the reset. It now drives the release path,
which makes it a statement about the port rather than about the helper. That is the fifth
instance of this shape, after `RxQueue`, `TxQueue`, the CMP server and the ack timer.

**How it was found, and what the search is worth.** Rather than another one-off, this cycle
enumerated every public function in `csp-core` and `csp` and listed those referenced nowhere
outside their own test module: 51 of 235. Most are legitimately application-facing — the
crate exists to be called from outside — so the list is *leads*, not defects, and reading
each is the work. Two false alarms went first: `decode_clamped` looked undriven because the
search covered only `csp/src`, when the call is at `rdp.rs:919` inside the state machine the
node does drive. The signal is not "unreferenced" but "unreferenced *and* not something an
application would call", and only reading tells the two apart.

### The port could not send a fragment on a connection

2026-08-27, and the sixth instance of the shape above: a correct piece of `csp-core` that the
layer over it never drives.

`Node::send` stamps the connection's own id over whatever the caller put on the packet, and
`conn_flags` never sets `FRAG` — it is a per-packet flag, not a connection option, so there
was nowhere for it to come from. The only send taking explicit flags is `sendto`, which has
no connection and therefore cannot carry RDP either. So an application could fragment a
message with `sfp::Fragmenter`, size it with `Node::conn_sfp_mtu` — a function whose entire
purpose is "how big may a fragment be *on this connection*" — and then had no way to send
one.

Measured against a real C node, not read: every fragment left with `flags=0x00`, and
`csp_sfp_recv_fp` refused the transfer with **-103 `CSP_ERR_SFP`**. Had the receiver used a
plain `csp_read` instead, it would have got each fragment as a datagram with eight bytes of
trailer stuck on the end and no indication the message had been cut up.

**What made it invisible.** Three things looked like coverage, and each was measured on
something else:

| looked like | actually measured |
|---|---|
| `ctest/suite_sfp.c`, 12 corpus records | `csp_sfp_recv_fp` called directly, on packets built by `make_packet` and pushed onto a hand-opened connection — no header on a wire, no routing, no bound port |
| `csp-core::sfp` unit tests | the port's fragmenter and its own reassembler, against each other |
| the multi-fragment stream-over-RDP record | a real C router and a bound port, but reassembling frames the *C test* built |

Every one is a true statement about the SFP codec. None says a C peer accepts what the port
sends. That is the same blind spot as the forwarding bug, which satisfied every assertion
about which interface the router chose while destroying the packet.

`csp::node::the_fragment_flag_is_per_packet_not_sticky_on_the_connection` was worse than
absent. It sent a *plain* packet, set `FRAG` on the packet `send` had already returned, and
then checked the next packet did not have it — true of any two packets, and a statement about
nothing. It read as coverage precisely because the port could not send a fragment, so there
was no other way to write it.

**Fixed** with `Node::send_fragment(conn, packet, offset, total, now)` — `csp_sfp_send`'s
loop body, with the loop left to the caller because sans-io has nowhere to loop. It appends
the trailer where `csp_sfp_header_add` does and sets `FRAG` for that packet only; the RDP
trailer then lands after it, giving the `[body][sfp][rdp]` order `csp_rdp.c` strips in
reverse. It deliberately does not reproduce `csp_sfp.c:131`'s `conn->idout.flags |=
CSP_FFRAG`, which nothing clears (deviation 3).

Both new cells are checked end to end by `difftest/tests/node_sfp.rs` and `node_sfp_rdp.rs`:
the port fragments, a real C node routes the frames to a bound port, and `csp_sfp_recv_fp`
hands the application the original bytes. Three controls confirm the tests bite — no `FRAG`,
a trailer off by one, and no trailer at all each fail them.

**The delivery matrix is now covered in both directions at node level.** `{plain, SFP}` x
`{no RDP, RDP}`, sending and receiving, against a real C node rather than against a reading
of one.

### The CMP reply nothing put on a wire

2026-08-27. CMP had node-level coverage in one direction. `node_v2.rs`'s
`the_cmp_client_understands_what_a_real_c_node_answers` has the port ask and a real C node
answer. The reverse — a peer asking *the port* — looked covered and was not, and the
distinction is worth writing down because it is the forwarding bug's shape exactly:

| | what it drove | where it stopped |
|---|---|---|
| the served-by-a-real-node record | a real `Router`, a bound port 0, the application's `read`, `respond_cmp` | records `replies`, `reply_len`, `reply_type`, `reply_code` — the encoder's output, in memory. **The reply was never sent.** |
| the other CMP records | `respond_cmp` as a function | never near a node |
| golden vectors, `suite_cmp.c` | the C's encoder and dispatcher | say nothing about the port's reply path |

So the reply *bytes* were byte-compared against the C's — `an_ident_reply_carries_the_configured_identity` records the full 93-byte reply as hex — and the request path was driven through a real router. Between them sat the step nobody took: putting the reply on a wire, and having a peer accept it. That is where the port has already shipped one silent drop.

**Measured: the port was right.** `difftest/tests/node_cmp_server.rs` has a real C node
`csp_connect` to the port, send an IDENT request laid out by `struct csp_cmp_ident_msg`,
and read the port's reply off its own connection — which libcsp's struct then parses as a C
application would. Hostname, model and revision come back intact. No fix was needed; what
was missing was the evidence.

The harness gained the direction it never had: `shim_node_client_send`/`_read` make the C
node the one that *connects*. Every node-level exchange before this had the C answering, or
originating on a connection the peer had opened, so the port's reply had never had to find a
connection a real C client was waiting on.

Controls: repointing `reply_to` at the request's own ports fails at the C client's receive;
shortening `Ident::LEN` by one byte fails inside libcsp's struct parse — "did not recognise
the port's IDENT reply (92 bytes)". A no-op mutation passes, so the harness is not failing
on its own.

#### What the same sweep found already covered

Recorded so the next pass does not re-open them:

- **Broadcast transmission and route fan-out.** `ctest/suite_route.c` drives a real C node
  with real interfaces and a recording nexthop, capturing how many frames left, by which
  interface, and the destination each carried — `a_routed_broadcast_leaves_as_the_local_broadcast`,
  `a_broadcast_rewrite_carries_to_the_other_interface`, `an_application_send_to_a_broadcast_is_rewritten_too`,
  `a_table_routed_destination_leaves_unchanged`. This is wire-level, not decision-level.
- **The two shape-mismatch cases** are function-level on *both* sides — `suite_sfp.c` calls
  `csp_sfp_recv_fp` directly, and the port's replay calls `Delivery::classify` directly.
  That is deliberate rather than a gap: classification is a per-packet header-bit decision
  the application makes on a packet it already holds, and the node has no part in it. The
  delivery that precedes it is covered by `a_packet_for_a_bound_port_reaches_the_application_identically`,
  and the one case where the router *does* matter has its own node-level replay
  (`a_fragment_read_as_a_datagram_keeps_the_sfp_header`).

### The built-in services had never been put next to the C

2026-08-27. `csp::service::respond` handles ping, ps, memfree, buf_free, uptime and reboot —
ports 1 to 6, the services a ground station actually uses. Measured, not assumed:

- **no corpus record.** The eleven suites are buffer, cmp, conn, dedup, eth, hmac, promisc,
  queue, rdp, route, security, sfp. There is no `suite_service.c`.
- **no golden vector, no differential test.**
- **its only callers anywhere are three `#[cfg(test)]` bodies in `client.rs`.**

So every statement about the built-in services was a reading of `csp_service_handler.c`.
Ping is how an operator finds out whether the link works at all; reboot is the one service
that cannot be undone from the ground. Neither had ever been compared with libcsp.

**Measured: the port was right.** `difftest/tests/node_service.rs` puts the two side by
side, driving the port's whole path — router, bound port, the application's `read`,
`Request::decode`, `respond`, `reply_to` onto a wire — so what is compared is what a peer
receives.

Not every service is comparable the same way, and saying which is which is half the work:

| service | compared on |
|---|---|
| PING | byte for byte, at 0, 4 and 200 bytes — a pure echo, no node state involved |
| PS | reply-or-silence, both empty and non-empty, so the silent case is not passing because nothing ever answers |
| REBOOT / SHUTDOWN | which payloads open the guard, and that the two magic words are not confused |
| MEMFREE | both stacks *given* the same number: the C's comes from a hook, the port's from the caller |
| BUF_FREE, UPTIME | not comparable by value — the C reports its own pool and clock. The port is fed the number the C reported, so the shared claim is the **encoding**, which is what a ground decoder depends on |

Four controls, each failing exactly one test and no other: a ping short by one byte, an empty
process list answered anyway, little-endian counters, and a reboot guard that accepts any
payload.

One real difference, in the port's favour and already deliberate: `Request::decode` refuses a
REBOOT payload shorter than four bytes. `csp_service_handler.c:50` does
`memcpy(&magic_word, packet->data, sizeof(magic_word))` with no length check, so a
zero-length reboot request reads four bytes past the payload and compares whatever is in the
buffer against the magic word. Reused buffers make that a real, if unlikely, path to an
uncommanded reboot.

#### The harness would have rebooted the machine

Found while setting this up, and worth its own note: `difftest/build.rs` linked
`src/arch/posix/csp_system.c`, whose `csp_reboot_hook` is `sync();
reboot(LINUX_REBOOT_CMD_RESTART)` on Linux. Any test that sent port 4 with the right magic
word would have rebooted the host running it — which is precisely the test anyone would
write when they got to the reboot service. `ctest/hooks.c` had already dealt with this for
the C-oracle build; `difftest` had not, because nothing had yet needed the reboot path.

`build.rs` now omits that file and `shim.c` supplies recording hooks, the same technique
already used for `csp_time.c`. It is also what makes MEMFREE comparable at all: the real hook
reports however much RAM the host happens to have free.

### The bridge named an interface and destroyed the packet

2026-08-27. The forwarding bug, again, in the one forwarding path nothing had ever looked at.

`csp_bridge.c` was in **neither** build — not `difftest/build.rs`'s source list, not
`ctest/CMakeLists.txt`. The C bridge had never been compiled in this project, let alone run.
So `Router::bridge_work` was entirely a reading of it, and its only tests were three
assertions inside `router.rs`:

```rust
assert_eq!(r.bridge_work(&pool, 1, 2, 0), Bridged::Forward { iface: 2 });
```

`Bridged::Forward` carried an interface index and **no pool slot**, unlike
`Routed::Forwarded` which carries `packet: u16` for the caller to take. So `bridge_work`
popped the packet off the queue, reported where it should go, and dropped it on the way out
of the function. Measured before changing anything: buffers free 24 → 23 while queued → **24
after `bridge_work` returned `Forward`**. A node running the port's bridge forwarded nothing
at all.

This is the same defect, in the same shape, as the `Router::forward` failure that started
this whole exercise — and it survived for the same reason. A test that compares the
interface index cannot tell "forwarded" from "reported and destroyed", because both name the
right interface.

**Fixed** by giving `Bridged::Forward` the pool slot, and by rewriting the unit tests to take
the packet and read it back rather than compare a variant.

**`difftest/tests/node_bridge.rs`** now compares against a real `csp_bridge_work`, which
required adding `src/csp_bridge.c` to the build. Five cases, all measured rather than
inferred: each side reaches the other carrying the same bytes; a repeated frame is dropped by
both **with `csp_conf.dedup` off**, and a distinct one still crosses; a frame addressed to
the bridge's own interface address is forwarded rather than delivered, because
`csp_bridge_work` never asks "is this for me"; a broadcast crosses as one frame with the
destination unrewritten; and deviation 12 — a frame from neither side — is asserted as a
*divergence*, the C emitting it on side A and the port refusing.

Three controls. The one that reproduces the bug (`packet: u16::MAX`, so the caller cannot
resolve the slot) **fails four of the five tests**; the three unit tests it replaced passed
it. The other two — both sides out the same interface, and dedup gated on the mode — each
fail exactly one test.

Two smaller things this turned up:

- Adding `csp_bridge.c` puts a **second `__weak csp_input_hook`** in the link, alongside
  `csp_route.c`'s. It linked without a diagnostic, which is the hazard COMPARISON.md and
  `hooks.rs` describe: a C linker silently picks one.
- The harness's first version called `csp_qfifo_wake_up()` before `csp_bridge_work()`, the
  way `shim_node_pump` does. That posts a NULL sentinel, and `csp_bridge_work` reads it *as
  its packet* — so every result was one step behind the frame that caused it. The first case
  still looked correct, which is what made the rest convincing. The fix is not to wake the
  queue: the caller injects exactly one frame per step.

### The CAN interface had never been compiled either

2026-08-27, immediately after the bridge, and found by asking the same question the bridge
answered: *which libcsp source files is neither harness building?* Measured — 68 `.c` files
under `libcsp/src`, 37 in difftest's list. Setting aside the arch shims, drivers, Python
bindings and the documented exclusions (`csp_yaml.c`, `csp_if_tun.c`, `csp_if_zmqhub.c`,
`arch/posix/csp_time.c`, `arch/posix/csp_system.c`), what was left was
**`csp_if_can.c` and `csp_if_can_pbuf.c`** — in neither difftest's build nor `ctest`'s.

CFP looked well covered: four differential tests, `cfp1_identifier_packing_agrees`,
`cfp1_identifier_parsing_agrees_for_arbitrary_identifiers`,
`cfp2_identifiers_from_the_fragmenter_agree_with_the_c` and `cfp2_packing_agrees_bit_for_bit`.
Every one of them compares the **CAN identifier's bit layout**, and every one is measured
against `shim.c` expanding the macros from `csp_if_can.h` *itself*. Not one line of the
interface had run: not `csp_can_rx`, not the pbuf pool it reassembles into, not the
fragmenter that decides how a packet becomes eight-byte frames. CAN is the bus this port is
meant to fly on.

**Measured: the port was right.** `difftest/tests/node_can.rs` drives both directions at
payload lengths that straddle every framing boundary (1, 4, 5, 12, 13, 200 — the first frame
carries a four-byte header extension plus at most four payload bytes, every later frame
eight): the port fragments and a real `csp_can_rx` reassembles into the C application's bound
port; a real `csp_can2_tx` fragments and the port's `V2Reassembler` puts it back together with
the same header and payload.

**A test that was weaker than its name.** The third case interleaves two senders, and its
point is that `csp_if_can_pbuf.c` keys a reassembly buffer by sender. It first gave the two
transfers different sender *counts* as well — and with that, zeroing the fragmenter's whole
sender field still passed. `CFP2_ID_CONN_MASK` is `dst | sender | prio | sc`, so the count
was doing the work and the sender field was never under test. Holding the count equal makes
the control bite. The lesson is the same one as the `api_map` granularity finding: a test
that varies two things at once measures neither.

Two observations about the fork, both from the probe rather than from reading:

- **`csp_can_tx` is declared in `csp_if_can.h` and defined nowhere.**
  `csp_can_add_interface` installs the static `csp_can1_tx` or `csp_can2_tx` according to the
  wire version, so calling the documented entry point does not link. The shim goes through
  `iface->nexthop`, which is what the router uses.
- **`csp_can2_tx` never frames a packet addressed to its own interface**: it calls
  `csp_qfifo_write` and returns. The two nodes in the test therefore address each other.
- The fork's `csp_can_driver_tx_t` takes a fifth argument (the originating packet) that
  upstream's does not. The first capture driver here matched upstream's signature and the
  compiler warned; an incompatible function pointer is undefined behaviour, not a warning to
  wave through.

#### `Bridged::Respond` could never happen

Bycatch from the same sweep. `bridge_work` returns `Idle`, `Dropped` or `Forward` — nothing
else, and it is the only producer of a `Bridged`. `Bridged::Respond` was never constructed
and never matched anywhere in the workspace, and its documentation was `Routed::Respond`'s,
describing RDP handshakes arriving "this way". A transparent bridge terminates nothing and so
originates nothing. Removed, rather than left as a public variant whose doc invites an
application to write a dead arm.

### CFP v1 reassembly: the half of the CAN interface the last cycle left

2026-08-27. `node_can.rs` closed the gap that `csp_if_can.c` had never been compiled — and
covered **v2 only**. `csp_can_rx` dispatches on `csp_conf.version`, which is init-only, so the
v1 half was untouched by construction and stayed exactly as it was.

Measured on this branch before writing anything: **`csp_core::cfp::V1Reassembler` had no
caller anywhere outside its own module** — no golden vector, no differential test, no node
test. `V1Fragmenter` had exactly one, in the golden-vector generator. So v1 reassembly was a
reading of `csp_can1_rx` and nothing else, and "CAN is covered" was a claim about half an
interface.

The two layouts share almost nothing. CFP 1 puts the whole 4-byte CSP header **and** a 2-byte
total length in the first frame's data, leaving *two* payload bytes; CFP 2 puts a 4-byte
header extension there and leaves *four*. CFP 1 counts `remain` down in the identifier and has
no end bit; CFP 2 has begin and end bits and a fragment counter. v2 passing implies nothing
about v1.

**Measured: the port was right.** `difftest/tests/node_can_v1.rs` drives both directions at
lengths straddling CFP 1's own boundaries (1, 2, 3, 10, 11, 100 — 2 and 3 are the first-frame
edge, 10 and 11 the second), plus two senders interleaved.

Five controls, and the split matters: three on the fragmenter (no declared length, `remain`
off by one, source field zeroed) fail the send direction and the interleaving case; two on the
reassembler (declared length read from the wrong offset, continuations overwriting instead of
appending) fail the receive direction. Neither pair touches the other, so each direction is
pinned by a control of its own — the receive direction being the one that had nothing behind
it at all.

The interleaving case holds the transfer identifier **equal** between the two senders from the
start, so only the source field distinguishes them. That is the fix the v2 version of this
test needed after a control caught it varying two fields at once; doing it right the first
time here is the lesson actually being applied rather than just recorded.

### The reassembly pool nothing drove, and a wedge in the C it exposed

2026-08-27. The search that produced the give-up counter and `V1Reassembler` — public
functions referenced nowhere outside their own file — re-run over the current tree: **30 of
235**. Most are legitimately application- or driver-facing (`into_datagram`, `total_len`,
`fanout_missed`, and the six `Interface::note_*` counter setters a driver calls; `note_refusal`
dispatches to two of them inside the same file, which is why they look unreferenced). One was
not.

**`cfp::Pbufs` — the port's counterpart of `csp_if_can_pbuf.c` — had no user anywhere outside
`cfp.rs`.** And the interleaving cases added the day before were half-tests: they fed the
*C's* pool two senders and checked the *C* kept them apart. The port's concurrent reassembly,
the entire reason `Pbufs` exists, had never been driven by anything but its own unit tests.

Driving it turned up a divergence in the C, found by measurement after an assertion of mine
turned out to be wrong.

**What I asserted, and what is true.** The first version of the expiry test asserted that the
C reclaims a stalled buffer after `PBUF_TIMEOUT_MS` and reassembles the sender's retry. It
does not. `csp_can_pbuf_cleanup` runs only from `csp_can_pbuf_new`, and `new` is reached only
when `csp_can_pbuf_find` returns NULL — a stalled buffer with the same identifier bits is
*found*, so the sweep never runs for it however long the sender waits. Measured:

| | retrying the same key after the timeout |
|---|---|
| C | first frame `CSP_ERR_NONE`, every later one `-2 CSP_ERR_INVAL`, nothing delivered |
| port | the repeated `begin` restarts the transfer; the payload arrives intact |

So in the C a single lost frame wedges that sender until some *other* sender allocates a
buffer and incidentally runs the sweep. On a quiet bus with one talker that is indefinite —
and a CAN bus with one talker is exactly a spacecraft between passes. The port treats a
`begin` as what it says it is and starts over, and its sweep is an explicit call rather than a
side effect of allocating, so it can happen with no traffic at all.

Recorded as a deliberate deviation and asserted **as a divergence**: a control that regresses
the port to the C's behaviour (refuse a `begin` while a transfer is in progress) fails
`a_truncated_transfer_wedges_the_c_and_the_port_recovers` and nothing else.

Four controls in total. The pool handing every key the same reassembler fails the interleaving
and sweep cases; a sweep that reclaims everything, and one that reclaims nothing, each fail the
sweep case; the regression above fails only the divergence case.

**And a harness bug worth recording, because it produced a plausible wrong answer.** The first
version of the pool helper allocated the output buffer *inside* the per-frame loop. A
reassembler writes each fragment at its own offset, so every frame landed in a fresh zeroed
array and only the last survived — the failure printed two payloads of zeroes ending in the
right two bytes, which reads like a subtle off-by-one in the port rather than a mistake in the
test. One buffer per sender, not per frame.

### Ethernet reassembly handled one sender at a time

2026-08-27. Following the same thread as the CAN pool: `csp-core::eth` exposes
`reassembly_key` and `is_complete`, both referenced nowhere outside `eth.rs`. `eth` has a
`Reassembler` and no pool, where `cfp` has `Pbufs`.

**All twenty `suite_eth.c` cases are one transfer at a time.** Nothing had ever interleaved
two senders, on either side — so the C's list of reassembly buffers (`csp_if_eth_pbuf.c`) and
the port's single `Reassembler` had never been compared on the case a shared segment produces
constantly.

Measured, with two new C cases and payloads seeded differently so a splice would show:

| | C | port (before) |
|---|---|---|
| delivered | **2**, both bodies intact | **1** |
| refused / frame counter | 0 / 0 | **1 / 1** |

The port refused every segment of the second sender and lost its transfer entirely. Two nodes
transmitting to one is the ordinary case on Ethernet.

**What was actually missing.** The shipped crates could always do this: `Pbufs<R, N>` is
generic and `eth::Reassembler` is `Default + Copy`. What did not exist was any evidence, any
documentation pointing at it, and a safe way to build one — `Pbufs::get_or_create` constructs
through `Default`, which leaves `eth::Reassembler::min_len` at zero and silently drops the
guard that refuses a packet too short to hold a CSP header, a guard two other `eth` records
exist to check. So the fix is `Pbufs::get_or_create_with`, taking the constructor, plus the
replay and docs/API.md using a pool.

**Three things I got wrong on the way, all corrected by measuring rather than re-reading:**

- I predicted the C keys its buffers on the packet id alone, having read
  `csp_eth_pbuf_find`'s `packet->cfpid == id` and stopped there. `csp_if_eth.c:153` builds
  that `id` as *the packet id concatenated with the source address* — the same key the port
  computes. The test named for the collision I predicted never collided, and is now named for
  what it measures.
- The first version of both cases gave the two senders identical payloads, because
  `whole_packet` fills with a fixed `0xD5 ^ i`. Two transfers spliced together would have been
  byte-identical to two intact ones. A seeded fill is what makes the question answerable.
- `drain_qfifo` recorded only the **first** delivered body. With two deliveries expected, that
  is a count with no content behind it — the exact weakness that let a single-`Reassembler`
  port look plausible. It now concatenates every body in order.

That is the third time in this run of cycles that a test turned out to be weaker than its
name — `api_map` at type granularity, the CAN interleaving case varying two fields at once,
and this one comparing indistinguishable payloads. The common shape: **the test could not
have failed for the reason it was written to catch.** Writing the failing case first, or
mutating until it fails, is what separates the two.

### 412 golden vectors that nothing loaded, counted as evidence

2026-08-27, and a target the done-check names directly: a number asserted rather than
measured. `just numbers check` has caught docs/API.md drifting in five consecutive cycles —
and it checks **docs/API.md alone**. Measured across the other three documents with numeric
claims: SCOPE.md 22, AUDIT.md 12, COMPARISON.md 11, none of them guarded by anything.

Three numbers described the same thing and disagreed:

| where | figure | what it counts |
|---|---|---|
| `ctest/tools/numbers.sh`, docs/API.md | **510** | non-comment lines of `vectors/v1.tsv` + `v2.tsv` |
| `difftest/src/lib.rs` docstring | **922** | those, plus `vectors/vectors.tsv` |
| COMPARISON.md | **923** | the same, off by one |

`510 + 412 = 922` located the difference. **`vectors/vectors.tsv` is the original
single-file format** from the first oracle commit (*"506 vectors from the real C API"*),
superseded by the per-version split — its `id_v1` rows still describe inputs as `len=0`
where the current ones use `payload=`. `csp-core/tests/vectors.rs` loads `v1.tsv` and
`v2.tsv` and nothing else, so **412 of the 923 vectors COMPARISON.md offers as evidence that
"the port is checked against observed behaviour" are loaded by no test at all**. That is
worse than a stale count: it inflates the claimed evidence by 80%.

It survived because `oracle/gen_vectors.c` defaulted its output path to
`vectors/vectors.tsv`, so the file appeared once and stayed. The default is now removed —
the path is required, and a run with no path fails rather than writing a file nothing reads.

The same sweep found COMPARISON.md's three-branch table still claiming **451** tests and
**19** differential tests, against 533 and 66 measured.

`numbers.sh` now checks COMPARISON.md's three live figures too. Getting that right took two
attempts, and the first one is the more useful half of this entry: a row of that table has
three cells, and `grep -oE <row> | grep -oE '[0-9]+' | head -1` takes the **first** number on
the line — c2rust's `0`. It matched, so the check looked wired up, and it compared against the
wrong cell. Only running it printed `says comparison: tests = 0, measured 533`. Each of the
three new checks is now confirmed to fail on a deliberately drifted figure.

**The general shape, third instance in this run:** a guard that covers one of four places
guards the one already being watched. `api_map` checked existence but not granularity; the
untraced table checked justifications but not their targets; `numbers.sh` checked the
document whose numbers were already under scrutiny.

### Finishing the sweep the last cycle started

2026-08-27. Last cycle extended `numbers.sh` from docs/API.md to COMPARISON.md and left
SCOPE.md's 22 numeric claims and AUDIT.md's 12 unchecked. Finishing it, because "I will get
to the rest later" is how the first one drifted.

First, the generalisation of the dead vector file: **every checked-in data file, and whether
anything names it.** Measured — `corpus/ctest.jsonl`, `ctest/CMakeLists.txt`,
`ctest/tools/api_map.tsv`, `vectors/v1.tsv`, `vectors/v2.tsv`, all referenced. No second
orphan.

Then SCOPE.md's numbers. Nearly all of them are *historical* — "487 tests against a measured
492", "21 tests, 11 records", "495 tests, two module audits" — records of what was true when
something was found, and they must **not** track the tree; rewriting them would erase the
finding. Three were present tense, and two had drifted:

| claim | said | measured |
|---|---|---|
| "…record something **today**" | 125 of 144 | **148 of 165** |
| `vectors/v1.tsv` is "270 lines of real wire bytes from the C" | 270 | **267** |
| declared `csp_*` functions | 199 | 199 ✓ |

The second is the smaller and the more instructive: 270 is the file's line count, and three
of those lines are the comment header. "Lines of real wire bytes" counted the header as wire
bytes — the number was measured, just not on the thing the sentence named.

`numbers.sh` now checks the "record something today" sentence, both halves separately, since
it moves whenever a C test is added and that is most cycles. Confirmed by drifting each: the
numerator alone reports `= 125, measured 148`, the denominator alone `= 144, measured 165`.
The v1.tsv figure is corrected but deliberately not guarded — that file changes only when the
oracle does, and the oracle's output is verified byte-stable on every run that touches it.

**AUDIT.md is deliberately left unguarded**, and this is a decision rather than an omission:
all twelve of its figures are of the form "34 tests" / "46 tests" / "all 465 tests as they
stood at the time of this audit" — snapshots of a module when it was audited, tied to
conclusions drawn then. A tool that made them track the tree would silently rewrite the
evidence for those conclusions. The distinction worth keeping is **present tense versus past
tense**, not "in a document I have already automated".

### The C's service client, and the reboot word nothing had checked

2026-08-27. A third search, after "which C files are unbuilt" and "which public functions have
no outside caller": **which functions in the *compiled* C does no harness ever invoke?**
Measured across every `.c` in either build — 205 non-static `csp_*` functions, **124 never
named by any harness**.

Most of that 124 is noise, and saying why matters: `csp_crc32_update` is reached through
`csp_crc32_append`, `csp_sha1_process` through `csp_sha1_memory`, the `_fixup_cspv1` helpers
through `csp_id_prepend`. The behaviour is observed even where the symbol is not.

`src/csp_services.c` is the exception. Its twelve functions are the client an application
calls; nothing else in libcsp calls them, and nothing here did either. So `csp::client` had
been compared against the C's *server* and against its own round trip — never against the C's
client.

Ten of the twelve block in `csp_transaction_w_opts` waiting for a reply this harness has no
thread to produce. `csp_reboot` and `csp_shutdown` do not: `csp_transaction_persistent`
returns straight after `csp_send` when `inlen == 0`. They are also the pair where being wrong
is worst and least visible — **a magic word the port got wrong means "reboot the satellite"
silently does nothing, and no round trip inside the port can catch it, because client and
server both read `service::REBOOT_MAGIC`.**

**Measured: the words match.** `csp_reboot` puts `80078007` on port 4, `csp_shutdown`
`d1e5529a`, and `csp::client::{reboot,shutdown}` build the same bytes.

One difference the same measurement turned up, not previously written down: **the C's client
always sends reboot with `CSP_O_CRC32`** — `flags=0x01` and a four-byte trailer,
`80078007413e7883` on the wire. The port's `client::Request` carries `{port, payload}` and
leaves options to the caller, so what the port emits depends on how it is sent. That is not a
break in either direction, but it means the port's node must accept a checksummed reboot from
any real libcsp ground station, and that had never been driven.

It does: the C sends 8 bytes after the header, the application is handed **4**.

**The assertion that matters is the length, not the classification**, and the first version of
this test had only the classification. The magic word is read from the front, so an unstripped
four-byte checksum classifies as `Reboot` regardless — the test would have passed with the
verification removed entirely. Confirmed by control: disabling the CRC branch in
`security::check` fails the length assertion and nothing else. A corrupted checksum is also
refused delivery, which is what separates verifying from truncating.

Same shape as the last three cycles, and now unmistakable: **a test passes for the reason you
wrote it only if you have made it fail for that reason.** The fix each time was one more
assertion on what the application actually received.

### `client::ps` sent an empty request; `csp_ps` sends `0x55`

2026-08-27. The previous entry stopped at `csp_reboot` and `csp_shutdown`, on the grounds that
the other ten members of `csp_services.c` "block in `csp_transaction_w_opts`". **That was a
decision, not a measurement, and it was wrong.** The timeout is a parameter: `csp_read` hands
it to `csp_queue_dequeue`, and `pthread_queue_dequeue` with `0` builds a deadline of *now* and
returns immediately. At `timeout = 0` the request still goes out and the reply-wait costs
nothing — which is all that was ever needed to compare the two clients' requests.

Measured, all five that build a request:

| C client | dport | flags | body on the wire | the port built |
|---|---|---|---|---|
| `csp_ping(size=8)` | 1 | 0x00 | `0001020304050607` | same |
| `csp_memfree` | 3 | 0x01 | 0-byte payload + CRC32 | 0-byte |
| `csp_buf_free` | 5 | 0x01 | 0-byte payload + CRC32 | 0-byte |
| `csp_uptime` | 6 | 0x01 | 0-byte payload + CRC32 | 0-byte |
| **`csp_ps`** | 2 | 0x01 | **`55`** + CRC32 | **nothing** |

`csp_services.c:117` sets `packet->data[0] = 0x55; packet->length = 1`. The port sent an empty
payload.

**Nothing libcsp ships would notice**, and that is worth stating rather than overselling the
find: every `csp_ps_hook` in the tree — posix, freertos, zephyr — is `(void)packet; return 0`,
and `csp_service_handler` only checks the length the hook *returns*. So a stock node answers
both requests identically, which is why the port's own round trip and the server-side
comparison both passed. A sentinel is nevertheless the only reason that byte exists, and a
hook that validates it would ignore ours. Matching the C costs nothing and is the safer
direction for an outgoing request.

The header flags are deliberately **not** compared: `csp_ping` takes `conn_options` from its
caller and the other four hard-code `CSP_O_CRC32`, while the port's `client::Request` is
`{port, payload}` and leaves options to whoever sends it. Comparing them would fail on a shape
difference rather than a payload one, so the test compares the payload against the front of
the C's body and then checks the body is that payload plus exactly the checksum the flags
imply.

Three controls, all failing only the new test. The first — reverting `ps` to an empty request,
which is the bug — trips the **length** assertion, not the byte comparison: with `n = 0` the
prefix comparison passes vacuously. Fourth cycle running in which the assertion that catches
the defect is the one about *how much* arrived rather than *what*.

### `decode_u32` took the first four bytes of anything

2026-08-27. The last of `csp_services.c`'s twelve. `csp_ping_noreply` and `csp_cmp` were
measured first and both **match** — the C sends `55`+CRC32 on port 1 and the port sends `55`;
`csp_cmp(IDENT)` builds 93 payload bytes and so does `client::cmp_request`, byte-identical
prefix. No defect there.

The three `csp_get_*` clients share their request with the plain `csp_*` forms already
covered, so the only thing left in them is **reply decoding** — and that had never been
reachable, because with an empty queue the transaction times out long before the length is
looked at. Opening the connection, injecting a reply addressed to it, and only then running
`csp_transaction_persistent` makes the check observable. Measured at `inlen = 4`:

| reply | C | port, before |
|---|---|---|
| 3 bytes | refused | `Truncated` |
| 4 bytes | the value | the value |
| **5 bytes** | **refused, no value** | **the first four** |
| **8 bytes** | **refused, no value** | **the first four** |

`csp_io.c:352` is `if ((inlen != -1) && ((int)packet->length != inlen))` — refuse, count
`csp_dbg_inval_reply`, return 0. `decode_u32` checked `len < 4` and decoded the front of
whatever arrived, handing an operator a number the peer never sent, indistinguishable from one
it did. Now `!= 4`.

The "never over-reject" rule that governs incoming commands does not apply here and it is
worth being explicit about why: that rule exists because a command wrongly refused in orbit
cannot be retried by anyone who can see the refusal. This is a **reply to a request we made**.
Refusing it costs one retry; accepting it costs a wrong number in a telemetry log.

**How the harness lied first, and what it took to notice.** The first version addressed the
injected reply to `csp_conn_sport(conn)`. That returns `idin.sport` — the *remote* port
dialled — while the connection's incoming destination is the ephemeral `idin.dport` that
`csp_connect` allocated. The reply went to a port nothing was listening on, the transaction
timed out, and the C returned 0 for **every** length including four. Read as a result, that is
"the C refuses everything"; it was the harness. The diagnostic that settled it was printing
the sport alongside the inject and pump return codes — `pumped=1` proved the frame was routed,
so the failure had to be in the addressing, not the delivery.

A 4-byte reply succeeding is what makes the other rows mean anything. Without that row the
test would have passed against a harness that never delivered a thing.
