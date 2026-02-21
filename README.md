# libcsp — Rust bindings for libcsp v1.6

Safe, idiomatic Rust wrappers for the
[Cubesat Space Protocol](https://github.com/libcsp/libcsp) C library.

- **No Python / waf dependency** — the build script compiles libcsp directly
  with the Rust `cc` crate.
- **Zero unsafe in the public API** — raw pointers are hidden behind RAII
  wrappers (`Packet`, `Connection`, `CspNode`).
- **`no_std` compatible** — disable the `std` feature; `alloc` is still
  required for `CspConfig` string fields.

---

## Requirements

| Tool | Version |
|------|---------|
| Rust | ≥ 1.64 (for `alloc::ffi::CString`, `core::ffi::c_*`) |
| clang / libclang | any recent release (for bindgen) |
| C compiler | gcc or clang with C99 support |

On Linux you also need the headers for any optional drivers you enable:

```sh
# SocketCAN (optional)
sudo apt install libsocketcan-dev

# ZMQ hub interface (optional)
sudo apt install libzmq3-dev
```

---

## Quick start

Add to `Cargo.toml`:

```toml
[dependencies]
libcsp = { path = "." }   # or from crates.io once published
```

### Server example

```rust
use libcsp::{CspConfig, Packet, Socket, Priority, ANY_PORT, MAX_TIMEOUT};

fn main() {
    // 1. Initialise the CSP stack
    let node = CspConfig::new()
        .address(1)
        .hostname("my-cubesat")
        .model("CubeSat-1U")
        .revision("v1.0")
        .buffers(20, 256)
        .init()
        .expect("csp_init failed");

    // 2. Start the router task (spawns a POSIX thread on Linux)
    node.route_start_task(4096, 0).expect("router task failed");

    // 3. Add a loopback route for local testing:
    //    (use sys::csp_rtable_set or add ifaces with the raw sys module)

    // 4. Create a server socket on port 10
    let sock = Socket::new(0).expect("csp_socket failed");
    sock.bind(10).unwrap();
    sock.listen(5).unwrap();

    println!("Listening on CSP port 10 …");

    loop {
        // Accept the next connection (100 ms timeout)
        let Some(conn) = sock.accept(100) else { continue };

        println!(
            "Incoming connection from node {} port {}",
            conn.src_addr(),
            conn.src_port()
        );

        // Read packets until the connection is closed
        while let Some(pkt) = conn.read(100) {
            println!("  Received {} bytes: {:?}", pkt.length(), pkt.data());
            // pkt is freed automatically here (Drop calls csp_buffer_free)
        }
        // conn is closed automatically here (Drop calls csp_close)
    }
}
```

### Client example

```rust
use libcsp::{CspConfig, Packet, Priority};

fn main() {
    let node = CspConfig::new()
        .address(2)
        .hostname("ground-station")
        .buffers(10, 256)
        .init()
        .expect("csp_init failed");

    node.route_start_task(4096, 0).unwrap();

    // Connect to node 1, port 10, with normal priority, no connection options
    let conn = node
        .connect(Priority::Norm, 1, 10, 1000, 0)
        .expect("csp_connect failed — no free connections?");

    // Allocate a packet and fill it
    let mut pkt = Packet::get(32).expect("CSP buffer pool exhausted");
    pkt.write(b"hello from Rust!").unwrap();

    // send() returns Ok(()) on success; on failure returns Err((err, pkt))
    match conn.send(pkt, 0) {
        Ok(()) => println!("Sent!"),
        Err((e, _returned_pkt)) => eprintln!("Send failed: {e}"),
    }
    // conn is closed on drop
}
```

### Connectionless (UDP-style) example

```rust
use libcsp::{CspConfig, Socket, socket_opts};

fn main() {
    let node = CspConfig::new().address(3).init().unwrap();
    node.route_start_task(4096, 0).unwrap();

    let sock = Socket::new(socket_opts::CONN_LESS).unwrap();
    sock.bind(20).unwrap();

    while let Some(pkt) = sock.recvfrom(1000) {
        println!("Datagram: {:?}", pkt.data());
    }
}
```

---

## Feature flags

| Flag | Default | Description |
|------|---------|-------------|
| `std` | ✓ | `std::error::Error` impl for `CspError` |
| `rdp` | ✓ | Reliable Datagram Protocol |
| `crc32` | ✓ | CRC32 packet integrity check |
| `hmac` | ✓ | HMAC-SHA1 authentication |
| `xtea` | ✓ | XTEA encryption |
| `qos` | ✓ | Quality-of-Service priority queues |
| `promisc` | ✓ | Promiscuous receive mode |
| `dedup` | ✓ | Packet deduplication |
| `cidr-rtable` | – | CIDR routing table (default: static) |
| `socketcan` | – | Linux SocketCAN driver (`libsocketcan` required) |
| `zmq` | – | ZMQ hub interface (`libzmq` required) |
| `usart-linux` | – | Linux USART / KISS driver |
| `usart-windows` | – | Windows USART driver |
| `debug` | – | CSP debug/log output to stdout |
| `debug-timestamp` | – | Prepend timestamps to debug output |

### Buffer / connection sizing

Override the compile-time sizing constants via environment variables before
running `cargo build`:

```sh
LIBCSP_BUFFER_SIZE=512      # bytes per packet buffer (default 256)
LIBCSP_BUFFER_COUNT=32      # number of packet buffers (default 10)
LIBCSP_CONN_MAX=20          # max simultaneous connections (default 10)
LIBCSP_CONN_RXQUEUE_LEN=16  # per-connection Rx queue (default 10)
LIBCSP_QFIFO_LEN=50         # router FIFO length (default 25)
LIBCSP_PORT_MAX_BIND=58     # highest bindable port (default 24, max 62)
LIBCSP_RTABLE_SIZE=20       # routing table entries (default 10)
LIBCSP_RDP_MAX_WINDOW=10    # RDP window size (default 20)
```

**Important:** `LIBCSP_PORT_MAX_BIND` controls the port range split:
- Ports 0 to `PORT_MAX_BIND`: Bindable by servers
- Ports (`PORT_MAX_BIND`+1) to 63: Ephemeral (auto-assigned for client connections)
- Must be ≤ 62 (leaving at least 1 port for ephemeral use)

See [USAGE.md](USAGE.md#port-architecture) for details on port assignment.

---

## Debug and Logging

Enable the `debug` feature to capture CSP log messages in Rust:

```toml
[dependencies]
libcsp = { version = "1.6", features = ["debug"] }
```

### Custom Log Handlers

```rust
use libcsp::debug::{set_debug_level, set_debug_hook, DebugLevel};

// Enable specific debug levels
set_debug_level(DebugLevel::Info, true);
set_debug_level(DebugLevel::Error, true);

// Capture CSP log messages
set_debug_hook(|level, message| {
    match level {
        DebugLevel::Error => eprintln!("[CSP ERROR] {}", message),
        DebugLevel::Warn => eprintln!("[CSP WARN] {}", message),
        _ => println!("[CSP {:?}] {}", level, message),
    }
});
```

### Debug Levels

| Level | Description |
|-------|-------------|
| `Error` | Critical errors (always enabled by default) |
| `Warn` | Warnings (enabled by default) |
| `Info` | Informational messages |
| `Buffer` | Buffer allocation/deallocation |
| `Packet` | Packet processing details |
| `Protocol` | Protocol state machine |
| `Lock` | Mutex/lock operations |

See [LOGGING.md](LOGGING.md) for complete logging documentation.

---

## `no_std` usage

```toml
[dependencies]
libcsp = { path = ".", default-features = false, features = ["rdp", "crc32"] }
```

The `alloc` crate must be available on your target (it is on FreeRTOS with a
heap configured).  If you need a fully allocation-free init path, construct the
`csp_conf_t` directly via the `sys` module.

---

## Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Quick start guide and feature overview (this file) |
| [USAGE.md](USAGE.md) | Comprehensive usage guide with patterns and examples |
| [LOGGING.md](LOGGING.md) | Debug and logging configuration |
| [USAGE_STRESS.md](USAGE_STRESS.md) | Stress testing patterns and performance tuning |

---

## Architecture

```
libcsp crate
├── sys          — raw bindgen output (unsafe, all C symbols)
├── error        — CspError enum + csp_result() helper
├── packet       — Packet (RAII, auto-frees via csp_buffer_free)
├── connection   — Connection (RAII, auto-closes via csp_close)
├── socket       — Socket (server-side listener)
└── init         — CspConfig builder + CspNode token
```

The C library (`./libcsp`) is compiled as a static library by `build.rs` using
the `cc` crate.  `bindgen` generates `$OUT_DIR/bindings.rs` from
`libcsp/include/csp/csp.h`, which is included verbatim by `src/sys.rs`.

---

## License

This crate is a binding to libcsp which is licensed under the
**GNU Lesser General Public License v2.1** (LGPL-2.1).  The Rust wrapper code
is licensed under the same terms.  See [`libcsp/COPYING`](libcsp/COPYING).
