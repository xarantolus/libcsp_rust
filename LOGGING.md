# CSP Logging and Debug Output

## Overview

libcsp reports diagnostics through two channels:

1. **Counters** — per-error-path `uint8_t` globals that you snapshot on
   demand.
2. **Print toggles** — two `uint8_t` switches that enable per-packet and
   per-RDP-transition messages routed through libcsp's `csp_print_func`.

The Rust `debug` module wraps both in a typed API. There is no Rust-side
message hook; messages flow through the C-level `csp_print_func` which by
default writes to stdout.

## Understanding CSP log messages

When you see output like:

```
Port 15 is already in use
```

it is coming from the **C library itself** via `csp_print_func`, not from
the Rust bindings.

## Log sources

CSP logging originates from several places:

1. **Counters** — incremented on buffer exhaustion, connection overflow,
   routing failures and similar error paths.
2. **Per-packet trace** — when enabled, one line per packet routed.
3. **RDP trace** — when enabled, lines describing RDP state transitions.
4. **Architecture layer** — OS-specific diagnostics emitted by
   mutex/queue/thread primitives you provide via `CspArch`.
5. **Interface drivers** — SocketCAN, USART, ZMQ, etc.

## Enabling CSP debug output

### At compile time

Add the `debug` feature in `Cargo.toml`:

```toml
[dependencies]
libcsp = { version = "2.1", features = ["debug"] }
```

With the feature disabled the counter globals and print toggles still exist
in the C sources but the `libcsp::debug` module is not compiled in. Keep
`debug` off for flight builds to avoid the print overhead and strip the
module from your binary.

## Using the `debug` module

```rust
use libcsp::debug::{self, Counters, RdpTrace};

// Snapshot the current error counters.
let c: Counters = debug::counters();
println!(
    "buffer_out={} conn_out={} conn_ovf={} conn_noroute={} \
     inval_reply={} errno={} can_errno={} eth_errno={}",
    c.buffer_out, c.conn_out, c.conn_ovf, c.conn_noroute,
    c.inval_reply, c.errno, c.can_errno, c.eth_errno,
);

// Zero all counters (useful between test phases).
debug::reset_counters();

// Enable per-packet tracing. Each routed packet produces one print line.
debug::set_packet_trace(true);

// Tune RDP verbosity.
debug::set_rdp_trace(RdpTrace::Errors);   // error paths only
debug::set_rdp_trace(RdpTrace::Protocol); // errors + every state transition
debug::set_rdp_trace(RdpTrace::Off);      // silent
```

### Counter meanings

| Field | Incremented when |
|-------|------------------|
| `buffer_out` | `csp_buffer_get` returned `NULL` (pool exhausted) |
| `conn_out` | No free connection slot for an outbound connect |
| `conn_ovf` | A connection's RX queue overflowed |
| `conn_noroute` | Router could not find a route for the destination |
| `inval_reply` | A received reply did not match any pending request |
| `errno` | Generic libcsp error counter (last-resort) |
| `can_errno` | SocketCAN driver error |
| `eth_errno` | Ethernet driver error |

Each counter saturates at `u8::MAX`; reset periodically if you want
finer-grained long-running stats.

### RDP trace levels

| Variant | Meaning |
|---------|---------|
| `RdpTrace::Off` | No RDP prints |
| `RdpTrace::Errors` | Log only RDP error paths (invalid ACKs, timeouts, …) |
| `RdpTrace::Protocol` | Log errors plus every state-machine transition |

## Where the prints go

Print output is emitted by libcsp's `csp_print_func`. The default
implementation writes to stdout via `printf()`. To redirect log messages to
a file, ring buffer, or over a network, override `csp_print_func` at the C
level — for example, by providing your own implementation and linking it
before libcsp's default:

```c
// Linked into your binary alongside libcsp.
#include <stdarg.h>
#include <stdio.h>

int csp_print_func(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = my_log_vprintf(fmt, ap);  // your transport: RTT, UART, syslog…
    va_end(ap);
    return n;
}
```

This is the only supported way to capture libcsp's own messages — the
bindings expose no Rust-side message hook.

## Capturing output during tests

### Option 1 — test output capture

```bash
# Cargo captures test output by default
cargo test

# Show output for passing tests too
cargo test -- --nocapture

# Single-threaded (required for CSP tests since libcsp uses globals)
cargo test -- --nocapture --test-threads=1
```

### Option 2 — redirect to a file

```bash
cargo test 2>&1 | tee test.log
```

### Option 3 — custom arch diagnostics

When you implement [`CspArch`] for embedded systems, the trait methods are
the natural place to add low-level tracing of mutex/queue/thread
operations:

```rust
unsafe impl CspArch for MyArch {
    fn queue_create(&self, length: usize, item_size: usize) -> *mut core::ffi::c_void {
        defmt::debug!("queue_create len={} item={}", length, item_size);
        // ...
        core::ptr::null_mut()
    }
    // ...
}
```

## Interpreting common messages

### "Port X is already in use"

**What it means:** A socket tried to bind to a port that is already bound.

**When you see it:**
- Running tests in parallel
- Reusing a CSP node without proper cleanup
- Port binding before a previous socket was dropped

**Example from tests:**
```
test service::tests::test_dispatcher_basic ... ok
Port 15 is already in use
```

**Is this a problem?**
- If the test still passes, the library correctly rejected the duplicate
  binding (expected behaviour).
- If the test fails, there is a resource leak or improper cleanup.

**Solution:**
```rust
// Ensure sockets are dropped before reuse
{
    let mut sock = Socket::new(0);
    sock.bind(15)?;
    // sock is dropped here, releasing port 15
}

// Now port 15 can be bound again
let mut sock2 = Socket::new(0);
sock2.bind(15)?;  // Should succeed
```

### RDP trace lines

With `debug::set_rdp_trace(RdpTrace::Protocol)` you will see lines tracing
the state machine, e.g.:

```
RDP: Connection opened
RDP: Sending SYN
RDP: Received ACK
```

### Routing messages

```
Route: Adding route 10/5 via LOOP
Route: Packet forwarded to interface LOOP
```

These are useful for debugging route-table population and dispatch.

## Best practices

### For development
- Enable the `debug` feature.
- Run tests with `--nocapture --test-threads=1` for deterministic output.
- Snapshot counters before and after a scenario to catch regressions.

### For production
- Disable the `debug` feature to drop the print-trace code.
- Still consider reading counters from your telemetry task — the globals
  are available regardless of the feature flag, but the typed wrapper lives
  behind `debug`.
- Use release builds which strip debug symbols.

### For tests
- Use unique ports (0-63 range for CSP).
- Ensure proper cleanup with RAII patterns.
- Run tests sequentially (`--test-threads=1`) — CSP state is global.

## Troubleshooting

| **Issue** | **Cause** | **Solution** |
|-----------|-----------|--------------|
| No log output | `debug` feature not enabled | Add `features = ["debug"]` |
| Counters stuck at zero | Never triggered the error path, or `reset_counters` called unexpectedly | Inspect paths; re-snapshot |
| "Port already in use" errors | Resource leak or parallel tests | Use unique ports, run tests sequentially |
| Garbled output | Multiple threads printing | Use `--test-threads=1` or route prints through your own `csp_print_func` |

## Related Files

- `src/debug.rs` — counter snapshot and trace-toggle API
- `src/arch/test_arch.rs` — Test architecture implementation
- `src/arch.rs` — Architecture trait definition
- `build.rs` — Build configuration for debug features

---

**Note:** CSP logging is designed for debugging, not production monitoring. For production systems, implement application-level telemetry using Rust logging frameworks (e.g. `tracing`, `defmt`) and expose the counter snapshot through it.
