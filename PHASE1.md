# Phase 1 — c2rust, measured

What c2rust 0.22.1 actually does to libcsp. Everything here is observed, not predicted.

## Reproduction

```sh
# canonical config, see SCOPE.md
cmake -S libcsp -B build/canonical -G Ninja -DCMAKE_EXPORT_COMPILE_COMMANDS=1 \
  -DCSP_USE_RDP=ON -DCSP_USE_HMAC=ON -DCSP_USE_PROMISC=ON -DCSP_USE_RTABLE=ON \
  -DCSP_HAVE_STDIO=ON -DCSP_ENABLE_CSP_PRINT=ON -DCSP_PRINT_STDIO=ON
ninja -C build/canonical

# library units only, minus zmqhub (out of scope, and it does not transpile -- see below)
python3 -c "import json;d=json.load(open('build/canonical/compile_commands.json'));\
json.dump([e for e in d if not any(x in e['file'] for x in \
('/examples/','/samples/','/unittests/','zmqhub'))],open('build/canonical/cc_port.json','w'))"

c2rust transpile build/canonical/cc_port.json -e -o build/c2rust-port \
  -- -Wno-error -Wno-gnu-zero-variadic-macro-arguments
```

The extra clang args are required, not cosmetic: c2rust invokes clang with `-Werror`, and
`csp_debug.h:81` uses the GNU `##__VA_ARGS__` extension, which clang diagnoses as
`-Wgnu-zero-variadic-macro-arguments`. Without them, 4 core files
(`csp_io.c`, `csp_route.c`, `csp_rdp.c`, `csp_bridge.c`) report `Error while processing`.

## Did it work?

**No — and it exited 0 while not working.** The transpile logs

```
error: Failed to translate arr_conn: Unsupported default initializer: Atomic(...)
```

then **returns exit status 0** and writes a crate that references `arr_conn` eleven times
without ever declaring it. `arr_conn` is the connection pool —
`static csp_conn_t arr_conn[CSP_CONN_MAX] __noinit;` — and c2rust cannot synthesise a
default initializer for a struct containing an `_Atomic` field.

Nothing but the Rust compiler catches this. `--fail-on-error` exists; it is not the
default.

Eight of the nine other `__noinit` statics translated fine, so this is about `_Atomic`,
not the section attribute.

## Three hand patches were needed to reach a compiling crate

| # | Error | Cause |
|---|---|---|
| 1 | `cannot find value arr_conn` ×11 | the untranslated static above. `core::mem::zeroed()` is not `const` on the nightly c2rust pins, so the initializer had to be written out field by field |
| 2 | ``symbol `csp_input_hook` is already defined`` | **the latent C bug became a hard error** — see below |
| 3 | `arguments to this function are incorrect` | per-module type duplication — see below |

Plus one class excluded rather than patched: `csp_if_zmqhub.c` emits **invalid Rust**.
libzmq's `zmq_msg_t` has a field literally named `_`, and c2rust emits `pub _: [u8; 64]`,
which does not parse. ZMQ is out of scope (SCOPE.md), so it is excluded from the unit list.

### Patch 2 is the interesting one

The survey flagged that `csp_input_hook` is defined `__weak` **twice in one library** —
`csp_route.c:106` and `csp_bridge.c:19`, byte-identically — so which implementation runs
is link-order dependent and no C toolchain says a word.

Rust has no weak symbols. c2rust emitted both as `#[no_mangle] pub extern "C" fn` and the
build failed outright. **A defect that C hides for free is a compile error in Rust.** That
is the single best argument in this whole exercise for doing the port at all.

## Per-module type duplication

c2rust emits each translation unit as an independent module that re-declares every C type
it touches. There is no shared type namespace:

| C type | Rust definitions emitted |
|---|---|
| `csp_packet_s` | **40** |
| `csp_id_t` | **40** |
| `csp_iface_s` | **23** |
| `csp_conn_s` | 7 |
| `csp_conf_s` | 7 |

So `csp_bridge::csp_iface_s` and `csp_route::csp_iface_s` are *distinct Rust types* for
the same C struct, and passing one where the other is expected is a type error. Patch 3 is
a raw-pointer cast to get around it.

The consequence at scale: **16 `redeclared with a different signature` warnings**, e.g.
`csp_buffer_get`, `csp_buffer_clone`, `csp_promisc_add`, `csp_qfifo_read`. The layouts are
in fact identical, so it works — but the compiler cannot know that, and neither can a
reader.

`--reorganize-definitions` is the intended fix. It invokes `c2rust-refactor`, which is
pinned to `nightly-2023-04-15`.

## Metrics

Measured on the compiling, patched crate (50 translation units, zmqhub excluded):

| | |
|---|---|
| C source | **8 527 LOC** |
| Rust output | **16 903 LOC** (**1.98×**) |
| `.rs` files | 52 |
| `unsafe` occurrences | **441** |
| `static mut` | **90** |
| `extern "C"` | **486** |
| raw pointer types (`*mut` / `*const`) | **2 709** |
| `libc::` references | **0** |
| build warnings | 66 (49 unused variable, 16 signature mismatch) |

## Toolchain

c2rust emits a `rust-toolchain.toml` pinning **`nightly-2023-04-15`** and a preamble
requiring four unstable features:

```rust
#![feature(c_variadic)]      // csp_print_func
#![feature(core_intrinsics)] // the atomics
#![feature(extern_types)]
#![feature(raw_ref_op)]
```

`raw_ref_op` has since stabilised as `&raw`, but **`core_intrinsics` is not on a
stabilisation path**. The atomic CAS at `csp_conn.c:172` becomes
`::core::intrinsics::atomic_cxchg_seqcst_seqcst`, so this output can never build on
stable Rust as emitted.

Worth correcting a common assumption: the output does **not** depend on the `libc` crate.
c2rust 0.22 uses `::core::ffi` throughout. Zero `libc::` references.

## `--emit-no-std` does nothing here

The flag exists, so it was measured rather than assumed. Transpiling with
`--emit-no-std` produces a `lib.rs` preamble **byte-identical** to the default, with no
`#![no_std]` anywhere in the crate.

That settles the central question for this project: **`no_std` is not something the
transpiler gives you.** It has to be earned afterwards, and earning it means removing
`extern "C"`, the pthread-backed arch layer, and the `core_intrinsics` dependency — i.e.
most of what makes the output what it is.

## Verdict

The output is a faithful transliteration and a genuinely useful **oracle** — it is the C
semantics in a form you can diff against. It is not a crate, and it is not a starting
point for one:

- 90 `static mut` is the *opposite* of the goal (all state owned by a `Csp` value).
- 2 709 raw pointers, 441 `unsafe`, 486 `extern "C"` — the public API is the C API.
- 40 copies of `csp_packet_s` means the module structure has to be rebuilt regardless.
- Permanently nightly, and `no_std` is not offered.

None of that is a criticism of c2rust, which says plainly that its output is *"unsafe and
unidiomatic … merely the first step in a longer migration process."* It is a measurement
of how long that step is for this particular library, whose memory model —
`frame_begin` as a self-referential interior pointer, `CONTAINER_OF` on the free path,
non-atomic refcounts — is exactly what a mechanical translation cannot improve.

**The convergence prediction stands so far:** getting from here to the definition of done
requires replacing the memory model, the module structure, the global state and the
public API — which is the whole library. Phases 3–5 test whether that is really true by
doing it both ways.
