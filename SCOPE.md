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
| `csp_init.c` | `Csp::new` / `Config` | the global `csp_conf` becomes a field |
| `csp_io.c` | `csp/io.rs` | send / recv / sendto / transaction |
| `csp_conn.c` | `csp/conn.rs` | connection pool; the one real CAS becomes `AtomicU8` |
| `csp_port.c` | `csp/port.rs` | port table; **fixes the `.bss`-reliance re-init leak** |
| `csp_qfifo.c` | `csp/qfifo.rs` | router input queue |
| `csp_route.c` | `csp/route.rs` | `route_work` — must not report idle as an error |
| `csp_buffer.c` | `csp/pool.rs` | **redesigned**: index-based slots, offset instead of `frame_begin`, `AtomicU8` refcount |
| `csp_id.c` | `csp-core/id.rs` | v1 + v2 header codec — **published**; three consumers hand-roll this today |
| `csp_iflist.c` | `csp/iflist.rs` | incl. aliases and subnet lookup |
| `csp_service_handler.c` | `csp/service.rs` | built-in service ports |
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

**Measured, not asserted.** `nm -D` on the built C library plus a header scan gives **186
public functions**. An earlier version of this section claimed full coverage by comparing
*module names* against the goal's list, which is not the same thing and was wrong: the
count was 91 without a counterpart, ~35 of them genuinely missing — including the whole
application-facing socket API.

Those 35 were built, and then every module was audited against its original function by
function (see `AUDIT.md`), which found more: the default-interface routing fan-out, the
three CMP memory hooks, `csp_socket_close`, `csp_ping_noreply`, and four interface
counters that had no way to be incremented.

The current position:

| | Count | |
|---|---|---|
| Covered | 140 | including everything in the goal's scope list |
| Out of scope by design | ~40 | ZMQ (8), USART drivers (5), the 16-function arch shim replaced by the caller's `Platform`, plus `yaml` and `if-tun` |
| Replaced by a different mechanism | 6 | `csp_cmp_set_memcpy`/`memread64`/`memwrite64` (no-ops in the C) → the `Hooks` trait; `csp_panic` → Rust's `#[panic_handler]`; `csp_listen`'s backlog → a const generic |
| Absent by explicit decision | ~5 | the `print` feature (`csp_debug.c`, `csp_hex_dump.c`), `csp_bind_callback`, `csp_conn_print_table` |

### Absent by decision

| What | Why |
|---|---|
| `print` — `csp_print_func`, `csp_hex_dump`, `csp_conn_print_table` | A variadic formatter and ten non-atomic global counters. A `no_std` crate has no business owning either; the caller has `defmt`, `log`, or nothing, and `Stats` is already a struct it can print however it likes |
| `csp_bind_callback` | Binds a bare `fn` to a port, bypassing the connection layer. Every consumer surveyed used `bind(CSP_ANY)` + `accept` + a dispatch table instead, and a callback that cannot own a connection cannot answer a stream |
| `yaml` | libyaml is not installed in this environment, so there is no C oracle to check a Rust parser against. Feature-gated and stubbed rather than written blind |
| `if-tun` | Needs the two `csp_crypto_*` hooks, which exist as `Hooks::encrypt`/`decrypt`; the interface itself is a Linux TUN device and belongs with the platform drivers that are out of scope |

### Implemented

What follows *is* done and tested:

| Area | Where | Status |
|---|---|---|
| Core (io, conn, route, qfifo, port, buffer, id) | `csp/{pool,conn,qfifo,router,iface}.rs`, `csp-core/id.rs` | done |
| RDP | `csp-core/rdp.rs` + `csp/conn.rs` (per-connection state, timers driven by `Router::tick`) | done |
| SFP | `csp-core/sfp.rs` + `csp/delivery.rs` | done |
| CMP | `csp-core/cmp.rs` — client **and** decoder | done |
| Crypto | `csp-core/{crc32,sha1,hmac}.rs` | done |
| Promisc | `csp/router.rs` tap | done |
| Dedup | `csp/dedup.rs` | done |
| Bridge | `csp/router.rs::bridge_work` | done |
| Routing | `csp-core/rtable.rs` + `csp/node.rs::resolve` (fan-out, split horizon, default fallback) | done |
| Socket / client API | `csp/node.rs` — connect, bind, unbind, accept, read, send ×4, recvfrom, transaction, close | done |
| Interface registry | `csp/iflist.rs` — add/remove, lookup by name/addr/subnet/broadcast, `check_default`, aliases | done |
| Client service calls | `csp/client.rs` — ping, ping_noreply, ps, reboot, shutdown, memfree, buf_free, uptime, CMP requests | done |
| Hooks | `csp/hooks.rs` — 14 of the C's 15, incl. the CMP memory hooks, all defaulting safely | done |
| Interface counters | `csp/iface.rs` — all ten, with `note_refusal` routing a security refusal to the right one | done |
| CAN / CFP | `csp-core/cfp.rs` (CFP1 + CFP2) | done |
| KISS | `csp-core/kiss.rs` | done |
| Ethernet / EFP | `csp-core/eth.rs` | done |
| I2C, LOOP, UDP | `csp/iface.rs` | done — each is a datagram interface, so the whole protocol logic is `Interface::send` + `Packet::set_frame`. Proven by a loopback round-trip test, not asserted |
| Built-in services | `csp/service.rs` | done |

Three items listed in the feature table above are **not implemented**, and none is in
scope for the goal:

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
   survive this because libcheck forks per test. `Csp::new` starts clean.
2. **Duplicate weak `csp_input_hook`** — defined `__weak` twice in one library
   (`csp_route.c:106` and `csp_bridge.c:19`); which wins is link-order dependent. Becomes
   one trait method.
3. **Wrong-shape SFP delivery is destructive** — `csp_sfp_header_remove` (`csp_sfp.c:32-35`)
   bails the moment `CSP_FFRAG` is clear and the caller frees the packet, so a plain
   datagram sent to a stream port is lost with a misleading `-103`. The port returns the
   packet to the handler instead.
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
10. **Deduplication stops working at the 49-day clock wrap.** `csp_dedup.c` compares
    `time > csp_dedup_timestamp[i] + CSP_DEDUP_WINDOW_MS` on a free-running 32-bit
    millisecond counter. After the wrap `time` is small, the comparison is false for every
    entry, the scan breaks on the first one, and duplicates stop being suppressed. The
    addition can also overflow near the wrap. The port uses wrapping subtraction, with a
    test that fails on the naive form.
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
   immutable field of the `Csp` value, so this is unrepresentable.
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

---

## Port defects found by the node-level differential harness

Not divergences from the C — **bugs in this port**, found on 2026-08-25 by building the
Rust-node-against-C-node harness that the plan called for and the branches were reported
done without.

1. **A forwarded packet was destroyed and never sent.** `Router::forward` reported
   `Routed::Forwarded { iface, via }` and then `drop(packet)`, with a comment deferring to
   a `Csp::forward` **that was never written**. Nothing anywhere re-sent it. So the node
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

**Still open, and now visible:** `Router::forward` uses the single-destination
`routes.find`, not the `find_all` fan-out and default-interface fallback that
`Node::resolve` implements. So the router path still cannot forward to redundant routes
or fall back to a default interface — the fix for that landed in `resolve` and the router
does not call it. Recorded rather than fixed: it is a design change, not a patch.
