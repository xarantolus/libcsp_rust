# Phase 2 — deterministic de-unsafing, measured

Can a tool mechanically lift the transpiled output toward safe Rust? This branch is the
attempt. Everything here is observed.

## What is actually available

| Tool | Status |
|---|---|
| `c2rust refactor` | **Not shipped.** `cargo install c2rust` (0.22.1) gives `Error: known subcommand not found (probably not built): refactor` |
| `c2rust analyze` | **Not shipped.** Same error |
| `--reorganize-definitions` | Invokes `c2rust-refactor`, so it fails. It emitted **2 of 50 files** and stopped |
| `c2rust-analyze` (from source) | **Builds and runs.** This is the real attempt |

A caution for anyone repeating this: after `--reorganize-definitions` the output directory
looked *deduplicated* — `csp_packet_s` down from 40 definitions to 2. It was not. Only two
files had been written, and grepping an almost-empty directory finds almost nothing. The
number was real; the conclusion drawn from it was not.

## Building `c2rust-analyze`

Not on crates.io; it has to come from the repo, on the pinned toolchain:

```sh
git clone --depth 1 https://github.com/immunant/c2rust.git
cd c2rust
rustup component add rustc-dev rust-src --toolchain nightly-2023-04-15
cargo build --release -p c2rust-analyze
```

That works. It self-describes as *"C2Rust analysis implementation for lifting unsafe Rust
to safe Rust"* — exactly the deterministic pointer→reference pass this branch is for.

```sh
cd transpiled
PATH="$HOME/.rustup/toolchains/nightly-2023-04-15-x86_64-unknown-linux-gnu/bin:$PATH" \
  c2rust-analyze --rewrite-mode none -- build
```

## Result: it runs, then panics

647 066 lines of analysis output, then exit 101. No rewritten crate is produced.

The failures are not incidental. **296 errors and 190 warnings, and they land on exactly
the three things that make libcsp's memory model what it is.**

### 1. Cross-module opacity — 444 `UnknownDef` callees

Every call that crosses a module boundary is opaque to the analysis, because c2rust
re-declares each callee as `extern "C"` in each module that uses it (PHASE1.md). The
analyser cannot see the body, so every pointer crossing a boundary must be treated as
unknown.

The most-hit callees are the core primitives — i.e. the ones whose pointers most need
analysing:

| Callee | Occurrences |
|---|---|
| `csp_print_func` | 56 |
| `csp_queue_size` | 28 |
| `csp_transaction_w_opts` | 24 |
| `csp_queue_dequeue` | 24 |
| `csp_queue_create_static` | 24 |
| `csp_buffer_get` | 24 |
| `clock_gettime` | 24 |
| `pthread_mutex_lock` | 20 |
| `csp_buffer_free` | 20 |
| `csp_qfifo_write` | 16 |

This is circular: the fix for the duplication is `--reorganize-definitions`, which needs
`c2rust-refactor`, which is not shipped.

### 2. Type punning — the header-into-payload trick

```
TODO: unsupported ptr-to-ptr cast between pointee types
      not yet supported as safely transmutable: `*mut u8 as *mut rdp_header_t`   (x6)
                                                `*mut u8 as *mut sfp_header_t`   (x4)
```

This is `(rdp_header_t *)&packet->data[packet->length]` — RDP and SFP write their headers
*into the payload array at a runtime offset* and read them back by casting. It is the
single most characteristic thing libcsp does, and it is the thing the analyser explicitly
cannot model.

Related, on the packet buffer itself:

```
unsupported cast kind: TypeDesc { own: Mut, qty: Single, pointee_ty: [u8; 256] }
                    -> TypeDesc { own: Mut, qty: OffsetPtr, pointee_ty: [u8; 256] }
```

That is `frame_begin` — a pointer *into* the packet's own array — which is the
self-referential interior pointer flagged in SCOPE.md as problem 1.

### 3. `void *` interface data — 76 of the 190 cast warnings

`*mut u8 <-> *mut c_void` (70 occurrences) plus the downcasts that make the interface
layer work:

```
*mut c_void as *mut csp_kiss_interface_data_t
*mut c_void as *mut csp_can_interface_data_t
*mut c_void as *mut eth_context_t
```

`csp_iface_t` carries `void * interface_data` and `void * driver_data`, and every
interface casts them back to its own type. There is no type information for an analyser to
recover — the C threw it away by design.

## Verdict

**Deterministic de-unsafing does not work on this input, and the reasons are structural.**

The three blockers are the same three things that a port has to redesign anyway:

1. Cross-module opacity is c2rust's own output shape, and the fix is unavailable.
2. Header punning has to become explicit `to_be_bytes`/`from_be_bytes` codecs.
3. `void *` interface data has to become a trait object or a generic.

So the `port/c2rust-safer` branch does not diverge from `port/c2rust` by an automated
rewrite, because no automated rewrite is obtainable. Both converge on the same manual
work — which is the convergence prediction, holding for the second time.

This is not a knock on `c2rust-analyze`. Its `TODO:` messages are honest about being
incomplete, and on code that passes pointers to structs it would likely do well. libcsp
happens to be built almost entirely out of the three patterns it cannot see through.
