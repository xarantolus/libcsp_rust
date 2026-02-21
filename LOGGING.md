# CSP Logging and Debug Output

## Overview

The libcsp C library has built-in logging facilities that output diagnostic messages. This document explains how to capture and control these logs in Rust applications.

## Understanding CSP Log Messages

When you see messages like:
```
0.000000 Port 15 is already in use
```

These are coming from the **C library itself**, not from the Rust bindings. The format is:
```
<timestamp> <message>
```

## Log Sources

CSP logging comes from several sources:

1. **CSP Debug Output** - Controlled by `debug` and `debug-timestamp` features
2. **Architecture Layer** - OS-specific logging (mutexes, queues, threads)
3. **Interface Drivers** - CAN, USART, ZMQ, etc.
4. **Protocol Handlers** - RDP, routing, services

## Enabling CSP Debug Logs

### At Compile Time

Enable debug features in `Cargo.toml`:

```toml
[dependencies]
libcsp = { version = "1.6", features = ["debug", "debug-timestamp"] }
```

### Feature Flags

- **`debug`** - Enables CSP debug output (via `CSP_DEBUG` macro)
- **`debug-timestamp`** - Adds timestamps to debug messages

## Controlling Log Output with the Debug Module

### Using Custom Debug Hooks (Recommended)

The `debug` module provides a safe Rust API to capture and control CSP log messages:

```rust
use libcsp::debug::{set_debug_level, set_debug_hook, DebugLevel};

// Enable specific debug levels
set_debug_level(DebugLevel::Error, true);
set_debug_level(DebugLevel::Warn, true);
set_debug_level(DebugLevel::Info, true);

// Set custom logging handler
set_debug_hook(|level, message| {
    match level {
        DebugLevel::Error => log::error!("[CSP] {}", message),
        DebugLevel::Warn => log::warn!("[CSP] {}", message),
        DebugLevel::Info => log::info!("[CSP] {}", message),
        _ => log::debug!("[CSP {:?}] {}", level, message),
    }
});
```

### Debug Levels

| Level | Constant | Default | Description |
|-------|----------|---------|-------------|
| Error | `DebugLevel::Error` | Enabled | Critical errors |
| Warn | `DebugLevel::Warn` | Enabled | Warnings |
| Info | `DebugLevel::Info` | Disabled | Informational messages |
| Buffer | `DebugLevel::Buffer` | Disabled | Buffer allocation/deallocation |
| Packet | `DebugLevel::Packet` | Disabled | Packet processing details |
| Protocol | `DebugLevel::Protocol` | Disabled | Protocol state machine |
| Lock | `DebugLevel::Lock` | Disabled | Mutex/lock operations |

### Helper Functions

```rust
use libcsp::debug;

// Enable common development levels (Error, Warn, Info)
debug::enable_dev_debug();

// Enable all debug levels
debug::enable_verbose_debug();

// Disable all debug output
debug::disable_all_debug();

// Remove custom hook (revert to default stdout)
debug::clear_debug_hook();
```

### Default Behavior (Without Debug Hook)

By default (when no custom hook is set), CSP logs go to **stdout** via `printf()` in the C library.

### Alternative: Redirect at Runtime

```rust
// Redirect stdout/stderr in your application
use std::fs::File;

fn redirect_logs() -> std::io::Result<()> {
    let log_file = File::create("csp.log")?;
    // Note: This is platform-specific
    Ok(())
}
```

#### Option 2: Custom Architecture with Logging (Advanced)

If using the `external-arch` feature, you can implement logging in your custom architecture:

```rust
// src/my_arch.rs
use libcsp::arch::CspArch;

pub struct MyCustomArch;

impl CspArch for MyCustomArch {
    // Implement all required methods...

    // You can add logging to queue operations, mutex operations, etc.
    unsafe extern "C" fn queue_create(length: i32, item_size: usize) -> *mut c_void {
        eprintln!("[CSP] Creating queue: length={}, item_size={}", length, item_size);
        // Your implementation...
    }
}
```

## Interpreting Common Log Messages

### "Port X is already in use"

**What it means**: A socket tried to bind to a port that's already bound.

**When you see it**:
- Running tests in parallel
- Reusing a CSP node without proper cleanup
- Port binding before previous socket was closed

**Example from tests**:
```
test service::tests::test_dispatcher_basic ... ok
0.000000 Port 15 is already in use
```

**Is this a problem?**
- ✅ If the test still passes, the library correctly rejected the duplicate binding (expected behavior)
- ❌ If the test fails, there's a resource leak or improper cleanup

**Solution**:
```rust
// Ensure sockets are dropped before reuse
{
    let sock = Socket::new(0)?;
    sock.bind(15)?;
    // sock is dropped here, releasing port 15
}

// Now port 15 can be bound again
let sock2 = Socket::new(0)?;
sock2.bind(15)?;  // Should succeed
```

### RDP Debug Messages

When `rdp` feature is enabled:
```
RDP: Connection opened
RDP: Sending SYN
RDP: Received ACK
```

These trace the Reliable Datagram Protocol state machine.

### Routing Messages

```
Route: Adding route 10/5 via LOOP
Route: Packet forwarded to interface LOOP
```

Useful for debugging packet routing issues.

## Capturing Logs in Tests

### Method 1: Test Output Capture

```bash
# Cargo captures test output by default
cargo test

# Show output for passing tests too
cargo test -- --nocapture

# Show output and run single-threaded
cargo test -- --nocapture --test-threads=1
```

### Method 2: Redirect to File

```bash
cargo test 2>&1 | tee test.log
```

### Method 3: Custom Test Logger

```rust
#[test]
fn my_test() {
    // Set up logging
    env_logger::init();

    // Your test code...
}
```

## Architecture-Specific Logging

### Test Architecture (Default for Tests)

The `test_arch` implementation in `src/arch/test_arch.rs` uses standard Rust primitives:
- Mutex/Condvar logging goes to stderr
- Thread creation can be logged by wrapping `libc::pthread_create`

### Custom Architecture (external-arch feature)

When implementing `CspArch` for embedded systems:

```rust
unsafe extern "C" fn system_assert(cond: bool, msg: *const c_char) {
    if !cond {
        let msg_str = CStr::from_ptr(msg).to_string_lossy();
        // Send to your logging system
        your_log_function(&format!("CSP ASSERT: {}", msg_str));
        // Or panic in Rust
        panic!("CSP assertion failed: {}", msg_str);
    }
}
```

## Best Practices

### For Development
✅ Enable `debug` and `debug-timestamp` features
✅ Run tests with `--nocapture` to see all output
✅ Check for "already in use" messages and fix resource leaks

### For Production
✅ Disable `debug` feature to reduce binary size and overhead
✅ Implement architecture-specific logging for embedded systems
✅ Use release builds which strip debug symbols

### For Tests
✅ Use unique ports (0-63 range for CSP)
✅ Ensure proper cleanup with RAII patterns
✅ Run tests sequentially (`--test-threads=1`) when debugging port conflicts

## Log Levels

CSP uses a simple binary debug system (on/off), not log levels. To control verbosity:

1. **At compile time**: Enable/disable `debug` feature
2. **At module level**: Comment out `CSP_DEBUG` calls in specific C source files
3. **At runtime**: Not directly supported (requires custom architecture)

## Examples

### Example 1: Debugging Port Binding

```rust
use libcsp::{Socket, socket_opts};

let sock1 = Socket::new(socket_opts::NONE)?;
sock1.bind(10)?;  // Success

let sock2 = Socket::new(socket_opts::NONE)?;
let result = sock2.bind(10);
// With debug enabled, you'll see:
// "0.000000 Port 10 is already in use"
assert!(result.is_err());  // Expected!
```

### Example 2: Tracing RDP State

```rust
// With features = ["rdp", "debug"]
let conn = node.connect(Priority::Norm, 2, 10, 1000, conn_opts::RDP)?;
// Logs will show:
// "RDP: Opening connection"
// "RDP: Sending SYN packet"
// "RDP: Received SYN-ACK"
// "RDP: Connection established"
```

## Troubleshooting

| **Issue** | **Cause** | **Solution** |
|-----------|-----------|--------------|
| No log output | Debug feature not enabled | Add `features = ["debug"]` |
| Logs missing timestamps | Missing feature | Add `features = ["debug-timestamp"]` |
| "Port already in use" errors | Resource leak or parallel tests | Use unique ports, run tests sequentially |
| Garbled output | Multiple threads logging | Use `--test-threads=1` or add synchronization |

## Future: Structured Logging

For more advanced logging, consider:
- Implementing a custom `csp_debug_hook` in external architecture
- Using `tracing` or `log` crates at the Rust binding layer
- Contributing structured logging support to libcsp upstream

## Related Files

- `src/arch/test_arch.rs` - Test architecture implementation
- `src/arch.rs` - Architecture trait definition
- `build.rs` - Build configuration for debug features

---

**Note**: CSP logging is designed for debugging, not production monitoring. For production systems, implement application-level telemetry using Rust logging frameworks.
