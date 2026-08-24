# libcsp in pure Rust — port experiment

This branch (`port/base`) is the **shared root** for three independent attempts to turn
[libcsp](https://github.com/libcsp/libcsp) into a pure-Rust crate. It carries only the C
library (as a submodule, used as reference and as a test oracle) and the conformance
suite that judges all three ports identically.

## Why

`main` on this repository is a **bindgen + `cc` wrapper**: it compiles the C libcsp and
hides it behind RAII types. Consumers therefore still ship C, still need libclang at build
time, and still inherit libcsp's ~38 file-scope mutable statics — which is why only one
CSP node can exist per process.

The target is the opposite:

> A pure-Rust, `no_std`, few-`unsafe` crate with no C and no FFI, where all of libcsp's
> global state lives inside a `Csp` value the user owns, and two instances can coexist.

## Definition of done — identical for every port branch

1. Builds for `thumbv7em-none-eabihf` with `--no-default-features`. `#![no_std]`, no
   `libc`, no `build.rs` compiling C, no bindgen, no `extern "C"` in the crate.
2. **No global mutable state.** No `static mut`, no global `Mutex`/`AtomicPtr`. Two `Csp`
   instances coexist in one process, proven by a test.
3. The conformance suite passes.
4. Every remaining `unsafe` block carries a `// SAFETY:` justification, and the count is
   reported.
5. Public API contains no raw pointers and no `unsafe fn`.
6. `docs/API.md` describes the resulting public API.

## Branches

| Branch | Method |
|---|---|
| `port/base` | This one. Submodule + conformance suite only. |
| `port/c2rust` | Raw [c2rust](https://github.com/immunant/c2rust) transpile, carried by hand to the definition of done. |
| `port/c2rust-safer` | Same transpile, plus automated ownership-recovery passes before the manual finish. |
| `port/llm` | Module-by-module rewrite with the C as spec and the c2rust output as semantic oracle. |

`COMPARISON.md` reports what actually happened, measured — `unsafe` counts, LOC, effort,
and conformance pass rate per branch per stage.

### Tools considered and rejected

**corrode** — last commit 2017-04-12. Its own README states it is *"not yet possible to
translate most real C programs or libraries."* Not attempted.

### Prior art

Three pure-Rust CSP attempts exist. All are sketches against libcsp's ~10 000-line core,
and none implements RDP, SFP, CMP, crypto or CAN/CFP:

| Repo | Rust | Last push |
|---|---|---|
| `mariusmm/libcsp` | 23 KB | 2022-08-14 |
| `Quettle/libcsp-async` | 14 KB | 2026-02-05 |
| `xiugaze/libcsp-rs` | 40 KB | 2026-08-08 |

Completeness is therefore treated as a gate, not a goal.

## Layout

```
libcsp/        submodule — the C library. Reference + test oracle. Never shipped.
oracle/        C program that dumps golden test vectors from the submodule
vectors/       the generated vectors, committed so Rust tests need no C
conformance/   the shared test suite every port branch must pass
SCOPE.md       module-by-module in / out / feature-gate decisions
```

The C library is a **dev-dependency oracle only**. It never appears in a shipped crate.
