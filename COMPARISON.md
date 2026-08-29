# Three ways to turn libcsp into Rust, measured

What actually happened when each approach was run end-to-end against libcsp
(`xarantolus/libcsp` @ `13a8c841`, **68 translation units, 11 692 lines of C**).

Nothing here is estimated, and every size figure below is produced by
`ctest/tools/loc.py`, which states the definition it counts by. `just numbers` checks this
file against it. Full detail: `PHASE1.md` (`port/c2rust`), `PHASE2.md`
(`port/c2rust-safer`), and the `csp-core` source on `port/llm`.

**What each column is measured on.** The two c2rust columns describe *the transpiler's
output* — the `transpiled/` tree on those branches — not the branch as a whole. Those
branches also carry the hand port, so a branch-wide count would report the hand port's
numbers three times. The `hand port` column is `csp-core/src` + `csp/src` on `port/llm`.

## Scoreboard

| | c2rust | c2rust + de-unsafe | hand port |
|---|---|---|---|
| Branch | `port/c2rust` | `port/c2rust-safer` | `port/llm` |
| Produces a crate? | after 3 hand patches | **no — tool panics** | yes |
| `no_std` | no | no | **yes** |
| `unsafe` | **441** | 441 | **0** |
| `static mut` | **90** | 90 | **0** |
| `extern "C"` | 486 | 486 | 0 |
| raw pointers | **2 709** | 2 709 | 0 |
| Rust LOC (implementation) | 16 954 (**1.45× the C**) | 16 954 | **11 734 (1.00×)** |
| Rust LOC (tests) | 0 | 0 | 15 547 |
| Toolchain | nightly-2023-04-15 | same | **stable** |
| Tests passing | 0 | 0 | **608** |
| Differential tests vs the C | 0 | 0 | **132** |
| Two nodes in one process | no | no | **yes** |

The implementation figure has roughly doubled since the first "the port is complete", and
that growth is the most useful number in the table. The early version was **missing
functionality** — the default-interface routing fan-out, the CMP memory hooks,
`csp_socket_close`, `csp_ping_noreply`, several interface counters — and it looked finished
because every module in the goal list had a file with its name on it. Counting public C
functions rather than module names is what exposed it. All **199** `csp_*` functions
declared in `libcsp/include/csp/**.h` are now accounted for — 144 ported, 50 out of scope,
5 deferred by an explicit decision — and `just api` fails if that stops being true, as does
`just numbers` if this sentence stops matching it.

*(This paragraph said 186 for months, after `SCOPE.md` had already recorded that 186 "is
not reproducible by either method". The figure the tool measures is 199.)*

## corrode — ruled out without running

Last commit **2017-04-12**. Its own README: *"it is not yet possible to translate most
real C programs or libraries."* Nine years unmaintained against a 10 kLOC library with
`_Atomic`, weak symbols and packed structs. Not attempted.

## c2rust — works, and tells you honestly that it isn't finished

The transpile is faithful. Three things are worth knowing before relying on it.

**It exits 0 while emitting a crate that cannot compile.** The log says

```
error: Failed to translate arr_conn: Unsupported default initializer: Atomic(...)
```

`arr_conn` is the connection pool. c2rust cannot synthesise a default initializer for a
struct containing an `_Atomic` field, so it emitted all **11 uses** of the symbol and
**none of its definition** — and returned success. Only `rustc` catches it.
`--fail-on-error` exists and is not the default.

**Every C type is re-declared per module.** `csp_packet_s` is defined **40 times**,
`csp_id_t` 40, `csp_iface_s` 23. Same-named types from different modules are distinct, so
cross-module calls need pointer casts, and 16 functions end up *"redeclared with a
different signature"*. The intended fix, `--reorganize-definitions`, needs
`c2rust-refactor`, which is not shipped in the crates.io release.

**`--emit-no-std` does nothing here.** Measured rather than assumed: the emitted `lib.rs`
preamble is byte-identical to the default, with no `#![no_std]` anywhere. `no_std` is not
something the transpiler gives you.

The output also needs four unstable features. `raw_ref_op` has since stabilised, but
**`core_intrinsics` is not on a stabilisation path** — the atomic CAS becomes
`core::intrinsics::atomic_cxchg_seqcst_seqcst` — so this output can never build on stable
as emitted.

One correction to a widely repeated claim: c2rust 0.22 does **not** depend on the `libc`
crate. It uses `core::ffi` throughout. Zero `libc::` references.

## c2rust-analyze — runs, then panics, for structural reasons

Not shipped either; built from source on the pinned nightly. It produced 647 066 lines of
analysis and exited 101 without producing a rewritten crate.

The 296 errors and 190 warnings land on exactly the three things that define libcsp's
memory model:

| Blocker | Count | What it is |
|---|---|---|
| `UnknownDef` callees | 444 | every cross-module call is opaque — a direct consequence of c2rust's own per-module duplication. Worst hit: `csp_buffer_get`, `csp_buffer_free`, `csp_queue_*`, `csp_qfifo_write` |
| unsupported ptr-to-ptr casts | 190 | includes `*mut u8 as *mut rdp_header_t` and `*mut sfp_header_t` — RDP/SFP writing headers **into the payload array at a runtime offset** |
| `void *` interface data | 76 | `interface_data` / `driver_data` downcasts. The C threw the type information away by design |

Plus `[u8; 256] Single -> OffsetPtr`, which is `frame_begin`: a pointer into the packet's
own array.

This is not a knock on the tool — its `TODO:` messages are honest, and on code that passes
pointers to structs it would likely do well. libcsp is built almost entirely out of the
three patterns it cannot see through.

## The convergence prediction held

The plan predicted all three branches would converge, and that c2rust's real value would
be as an **oracle and completeness checklist** rather than as code. That is what happened,
and the reason is specific: three properties of libcsp's memory model cannot be improved
mechanically, because a faithful translation is obliged to preserve them.

1. **`frame_begin` is a self-referential interior pointer** — `packet->data - 4` (v1) or
   `-6` (v2), pointing back into the same struct. `csp_buffer_copy` has to recompute it
   after a `memcpy`.
2. **The free path uses `CONTAINER_OF`** to walk 16 bytes *backwards* from the pointer the
   user holds to a refcount and a canary.
3. **That refcount is a plain `unsigned int`**, incremented and decremented from ISR and
   task context with no synchronisation.

In the hand port these dissolve together: the pool is an array of slots, `Packet` is a
handle carrying an **index**, `frame_begin` becomes a `u8` **offset**, and the refcount
becomes an `AtomicU8`. No interior pointer, no `container_of`, no move hazard — and buffer
leaks become unrepresentable, which matters because the flight test suite contains a test
(`test_csp_robustness.py`) that exists solely to catch handlers that forget
`csp_buffer_free`.

## The single best argument for doing this at all

While building `port/c2rust`, the build failed with:

```
error: symbol `csp_input_hook` is already defined
```

`csp_input_hook` is defined `__weak` **twice in one library** — `csp_route.c:106` and
`csp_bridge.c:19`, byte-identically. C linkers silently pick one, so which implementation
runs is link-order dependent, and no C toolchain says a word. Rust has no weak symbols, so
the build simply stops.

**A latent defect that C hides for free became a hard compile error.** That is the whole
value proposition in one line, and it was not found by reading the code — it was found by
trying to build it.

## Defects found in the C along the way

Every one was found by building or testing, not by review. Each is recorded in `SCOPE.md`
with the behaviour the port adopts instead.

| # | Defect |
|---|---|
| 1 | `csp_input_hook` defined `__weak` twice; which one runs is link-order dependent |
| 2 | `csp_port.c` relies on `.bss` with no `csp_port_init()`, so a second `csp_init()` leaks bindings — the C unittests only survive this because libcheck forks per test |
| 3 | **`csp_conf.version` cannot be changed after `csp_init()`.** Nothing says so. Measured: 18/18 SFP sends clean under v1, then the same sends after switching to v2 leak **one buffer per fragment** until the pool empties and everything returns `CSP_ERR_NOMEM`, with no error at the point of misuse |
| 4 | `csp_hmac_memory()` takes an unsized `uint8_t *` and writes the **full 20-byte** digest while `CSP_HMAC_LENGTH` is 4 — the obvious call overflows the caller's buffer by 16 bytes. Found by making that exact mistake in the oracle |
| 5 | An empty HMAC key returns `CSP_ERR_INVAL` **without touching the out buffer**, so a caller ignoring the return value MACs over uninitialised stack. Also found the hard way |
| 6 | `CSP_21` is defined by **no build system in the tree**, so the CRC never covers the header despite the comment saying 2.1 does. The verifier's try-with-header always falls through to try-without — which is why the ground decoder brute-forces both modes |
| 7 | `csp_id_prepend` masks nothing on encode, so a 14-bit address written as a v1 header silently corrupts the source address and produces a header that decodes as a *different valid packet* |
| 8 | Wrong-shape SFP delivery is destructive: `csp_sfp_header_remove` bails the moment `CSP_FFRAG` is clear and the caller frees the packet, so a plain datagram sent to a stream port is lost with a misleading `-103` |

Items 3, 4 and 5 were each found by the oracle doing the obvious thing and getting burned.

**The audit phase took the count from 8 to 29.** The full list is in `SCOPE.md`; the ones
that would matter most on a flying spacecraft:

| # | Defect |
|---|---|
| 19 | **CMP `PEEK`/`POKE` are arbitrary memory read and write, on by default.** The handler checks only `len <= 200` and then calls `csp_cmp_memcpy` with an address off the wire; the default implementation is a bare `memcpy` with no validation. The 64-bit variants refuse by default, which is what makes the 32-bit pair look like an oversight. `csp_cmp_set_memcpy`, the function an integrator would call to install a validating replacement, has an empty body |
| 20 | `csp_iflist_add` clears `ifc->next` *before* checking for a duplicate, so re-registering an interface silently unlinks every interface added after it, and returns `void` |
| 23 | A UDP interface can never report a transmit error: `csp_if_udp_tx` ignores `sendto`'s return and returns success even with no socket, so `tx` counts packets that never left |
| 27 | A one-character route-table entry ends the parse and `csp_rtable_load` reports success, silently dropping every entry after it |
| 28 | The route table is truncated at 100 characters — rejecting a valid table outright if the cut lands mid-entry, or silently dropping its tail if it lands on a separator |
| 29 | `CSP_ENABLE_KISS_CRC` defaults ON, so a KISS frame without a trailing CRC32 is dropped with `iface->frame++` as the only trace — a node whose frames all vanish this way looks exactly like one with a dead UART |

The distribution is worth noting: **the first eight were found by building, and most of the
next twenty-one were found by auditing module by module against the C.** Getting the port
working found the defects that stop you; reading every function against its original found
the ones that do not.

None of these were reported upstream — the instruction for this project was to record them
here, not to file them.

## What the audit changed about the conclusion

The convergence prediction held, and the branches do converge. But the experiment produced
a second result that the plan did not anticipate, and it is the more useful one.

**A port can pass a conformance suite, match golden vectors captured from the running C,
and still be missing a third of the library.** This one did. 254 tests passed, every golden
vector matched, 12 differential tests were green, and the default-interface routing fan-out
was absent — meaning a node with two redundant routes to a subnet would have used one of them
and reported nothing. The suite did not catch it because the suite tested what the port
implemented.

What caught it was enumerating the C's public functions — 199 of them, by the count
`just api` now makes — and checking each one off, then
auditing each module against its original function by function. That found:

- entire behaviours missing (the fan-out, the CMP memory hooks, `csp_socket_close`);
- **two slot leaks in the port's own code**, both the same shape — a queue entry taken out
  and then discarded when the report buffer was full;
- errors reused for unrelated conditions, surviving because nothing tested the failure path;
- and twenty-one more defects in the C.

So the honest recommendation is not just "hand port with the transpile as an oracle". It is
that **the checklist and the audit are the deliverable, and the tests are how you keep what
they found.** A transpile gives you the checklist for free — every function, in a form you
can diff against — and that is worth more than its code ever was.

## Recommendation

**Hand port, with the transpile kept as an oracle.**

Not because c2rust performed badly — it did what it says it does — but because the
distance between "faithful transliteration" and the stated goal (`no_std`, few `unsafe`,
no global state, no pointers in the API) *is* the library. 90 `static mut` is the exact
opposite of "all state owned by a `Node` value"; 2 709 raw pointers is the exact opposite of
"no raw pointers in the public API".

What the transpile is genuinely worth keeping for:

- **a completeness checklist** — 50 modules, every exported symbol, nothing forgotten;
- **a semantic oracle** — when the hand port and the C disagree, the transliteration says
  which one matches;
- **evidence** — the three defects it surfaced by refusing to build.

And the golden vectors are worth more than either. 510 vectors captured from the running C
mean the port is checked against **observed behaviour**, not against a reading of the
source — which is how the `CSP_21` question got settled: the KISS frames only match
byte-for-byte if the CRC covers payload only.
