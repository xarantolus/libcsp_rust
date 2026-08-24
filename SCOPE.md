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
| `src/bindings/python/pycsp.c` | Out of scope by definition |
| `examples/`, `samples/` | Rewritten as Rust examples where useful |

## Deviations from the C that are intentional

These are places the port deliberately does **not** reproduce C behaviour. Each one is a
defect in the original, and each is covered by a conformance test asserting the *new*
behaviour:

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
9. **`csp_conf.version` is silently unsafe to change after `csp_init()`.** Found while
   building the oracle. `host_bits` (5 for v1, 14 for v2) is baked into the routing and
   broadcast maths at init, so flipping the version afterwards misroutes every packet
   into the qfifo where nothing drains it. Measured: 18/18 sends clean under v1, then the
   same 18 sends after switching to v2 leak **one buffer per fragment** until the pool is
   empty and every call returns `CSP_ERR_NOMEM` — with no error reported at the point of
   misuse. Nothing in the API says the field is init-only. In the port the version is an
   immutable field of the `Csp` value, so this is unrepresentable.
