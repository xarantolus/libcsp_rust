# `ctest/` — the C oracle

Real libcsp, driven by libcheck, with a clock the test controls. What the C does here is
the answer the Rust port is measured against.

```sh
just ctest            # build and run every suite
just ctest RDP        # one suite
just ctest-asan       # the same, under ASan + UBSan
```

## Why not `libcsp/unittests/`

Three things this build does that the submodule's cannot, without modifying a submodule
that should stay at its pinned commit:

1. **`src/arch/posix/csp_time.c` is left out** and `clock.c` supplies `csp_get_ms` and its
   three siblings. Time becomes an input. See `clock.h` for what that reaches.
2. **`autoconfig.h` is generated here** from `autoconfig.h.in`, so a second build
   directory can set `-DCTEST_USE_HMAC=0` and make the "feature compiled out" branches
   reachable.
3. The application-side hooks live in `hooks.c`, where a test can set what
   `csp_memfree_hook` reports or check that `csp_reboot_hook` was reached — rather than
   linking libcsp's Linux drivers and doing real I/O.

The submodule needs nothing added to it: `csp_conn_get_array` (`src/csp_conn.h:94`) is
already the hook a test needs to look at connection state.

## What the virtual clock bought

Measured on this machine, both Debug builds, `CK_RUN_SUITE=RDP CK_RUN_CASE=retransmit`:

| | Wall clock | Per-test budget |
|---|---|---|
| `libcsp/unittests` (`usleep`) | 1.635 s | `tcase_set_timeout(tc_tx, 60)` |
| `ctest` (`ctest_clock_advance`) | 0.005 s | the default |

The 60-second override existed because the retransmit sequence is driven by real time and
a loaded machine can take arbitrarily long. Advancing the clock removes the dependence
rather than shortening it, so the budget is gone rather than reduced.

The other half is reproducibility. `csp_rdp.c:548` seeds `rand_r` from `csp_get_ms()` on
every SYN, so the RDP initial sequence number is a pure function of the clock —
`test_rdp_isn_is_a_function_of_the_clock` pins it at a fixed value. That is what lets a
recorded exchange be replayed. It is also a finding in its own right: an attacker who can
estimate a flight node's uptime to the millisecond can guess the sequence number its next
connection will open with.

## Fork-per-test

Left on deliberately — it is what lets every test call `csp_init()`, and it isolates the
process-global state libcsp keeps (the RDP option statics and `csp_rdp_incr`, the dedup
array, `csp_conf`, the interface list, the promiscuous queue).

So `CK_FORK=no` works one test at a time, not for a whole run: the second test to call
`csp_promisc_enable()` in one process gets `CSP_ERR_NOMEM` because the first one's queue is
still registered. Pair it with `CK_RUN_CASE`.

## Layout

| File | |
|---|---|
| `CMakeLists.txt` | the libcsp source list, and the one file deliberately absent from it |
| `autoconfig.h.in` | build configuration, with the varying knobs as CMake cache variables |
| `clock.{c,h}` | the virtual clock |
| `hooks.{c,h}` | the application half of libcsp |
| `main.c` | the libcheck runner |
| `suite_*.c` | the suites |
