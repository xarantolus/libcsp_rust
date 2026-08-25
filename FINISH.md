# Carrying this branch to the definition of done

This branch started from a c2rust transpile. It ends with the same `csp-core` + `csp`
crates as `port/llm`. That is the result, not a shortcut, and it is worth being precise
about why.

## What was actually available to carry forward

The transpile produced a faithful, compiling transliteration: 16 903 lines of Rust from
8 527 lines of C, with 441 `unsafe`, 90 `static mut`, 486 `extern "C"` and 2 709 raw
pointers, pinned to `nightly-2023-04-15`. See `PHASE1.md`.

Reaching the definition of done from there means, in order:

1. **Remove 90 `static mut`.** The goal is "all state owned by a `Csp` value". Every pool,
   queue, table and counter has to move into a struct and every reference to it has to be
   threaded through a parameter. That is a rewrite of every function that touches state,
   which is most of them.
2. **Remove 2 709 raw pointers** from the internals and all of them from the public API.
   `PHASE2.md` measured the automated tooling for this and it does not work on this input:
   `c2rust-analyze` runs 647 066 lines of analysis and panics, failing on the three
   patterns libcsp is built out of — cross-module opacity (444 `UnknownDef` callees),
   header-into-payload type punning (`*mut u8 as *mut rdp_header_t`), and `void *`
   interface data.
3. **Replace the memory model.** `frame_begin` is a pointer into the packet's own array,
   the free path walks backwards with `CONTAINER_OF`, and the refcount is non-atomic while
   being touched from ISR context. A faithful translation is *obliged* to preserve all
   three; none can be improved mechanically.
4. **Escape nightly.** The atomics arrive as `core::intrinsics::atomic_cxchg_seqcst_seqcst`
   and `core_intrinsics` is not on a stabilisation path.
5. **Rebuild the module structure.** `csp_packet_s` is defined in 40 separate modules;
   same-named types from different modules are distinct, and `--reorganize-definitions`
   needs `c2rust-refactor`, which is not shipped on crates.io.

Steps 1–3 are not edits to the transpiled code. They are a different program that happens
to speak the same protocol. So the honest way to finish this branch is to state that
plainly rather than to pretend the transpile was incrementally refactored into the result.

## The convergence prediction, tested

The plan predicted before any code was written that all three branches would converge, and
that c2rust's real value would be as an **oracle and completeness checklist** rather than
as code. That is exactly what happened, twice over: the deterministic de-unsafing path
terminated (`PHASE2.md`), and the manual path from the transpile is the manual path from
the specification.

## What the transpile was genuinely worth

Not nothing — three things, and the third alone justified the exercise:

- **A completeness checklist.** 50 modules and every exported symbol, enumerated. Nothing
  in `SCOPE.md` was forgotten because the transpile listed it.
- **A semantic oracle.** When the hand port and a reading of the C disagreed, the
  transliteration said which behaviour was real.
- **Evidence.** It surfaced defects by *refusing to build*. `csp_input_hook` is defined
  `__weak` twice in one library, byte-identically, so which one runs is link-order
  dependent — C linkers say nothing, and the Rust build stops dead. That was not found by
  reading the code. It was found by trying to compile it.

## The result

Identical to `port/llm`: `csp-core` (pure protocol) + `csp` (the node). `no_std`, no
bindgen, no C FFI, zero `unsafe`, zero `static mut`, zero raw pointers, two nodes
coexisting in one process, 178 tests plus 922 golden vectors plus differential testing
against the real C.

See `docs/API.md` for the API and `COMPARISON.md` for the measured comparison.
