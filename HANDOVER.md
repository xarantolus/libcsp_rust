# Handover

Pure-Rust, `no_std`, few-`unsafe` port of [libcsp](https://github.com/libcsp/libcsp), with
all of libcsp's ~38 global statics moved inside a `Node` value so two nodes coexist in one
process. Start here; the detail is in the docs linked below.

## Layout
- `csp-core/` — codecs and state machines (CFP, RDP, SFP, CMP, eth, KISS, HMAC/CRC32).
- `csp/` — the `Node`: router, connection table, pool, ports, delivery.
- `difftest/` — links the real C libcsp and runs both on identical bytes (`c_*` = the C).
- `ctest/` — C oracle suites → `corpus/*.jsonl`, replayed against the port.
- `libcsp/` — the C library, pinned submodule, reference and oracle only.

## Verify
- `just check` — the full pre-commit gate (tests, clippy, fmt, both thumb targets, the
  no-default-features run, doc links, and the doc-figure/citation guards).
- `just gate` — `check` plus `just mutants` (mutation testing; slow, runs last, never
  alongside `check` since it mutates the tree in place).
- `just cov` — region/line coverage.

## How faithfulness is argued
Not by unit tests alone — those encode a *reading* of the C. Every behaviour that matters is
pinned against the **real C** through `difftest/`: whole RDP sessions over CAN and KISS under
every protection, in transit through the node as a router, both wire versions (v1 is the
flown format), and the crypto/sequence primitives swept across their whole input domain. New
node scenarios reuse `difftest/src/harness.rs` (`CanLink`, `inject`, `work_until_idle`).

## Where the divergences are
`SCOPE.md` logs every deliberate difference from the C (with the `csp_*.c:NNN` line and the
test that pins it). `just check` fails if a divergence loses its written basis. The C's own
bugs are recorded there, not reproduced.

## Known floor
Coverage is ~96.6%. The remainder is `const fn` bodies (compile-time), `#[cfg(test)]` panic
arms, and defensive error/counter branches whose only trigger is an injected internal
failure — not gaps in behaviour. Five libcsp functions are deferred by decision
(`ctest/tools/api_map.tsv`): `csp_yaml_init`, `csp_if_tun_init` + its two `csp_crypto_*`
hooks, `csp_bind_callback`.

## More
`README.md` (why + definition of done) · `docs/API.md` (public API) · `docs/ASYNC.md`
(the sans-io threading model) · `COMPARISON.md` (this port vs. the bindgen wrapper).
