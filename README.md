# libcsp — Rust bindings for libcsp v2.1

Safe, idiomatic Rust wrappers for the
[Cubesat Space Protocol](https://github.com/libcsp/libcsp) C library.

- **No Python / waf dependency** — the build script compiles libcsp directly
  with the Rust `cc` crate.
- **Zero unsafe in the public API** — raw pointers are hidden behind RAII
  wrappers (`Packet`, `Connection`, `CspNode`).
- **`no_std` compatible** — disable the `std` feature; `alloc` is still
  required for `CspConfig` string fields.
- **Wire-format v1 by default** — 4-byte header, 5-bit addresses (0–31), for
  compatibility with existing flight hardware. Opt into v2 framing with
  `CspConfig::version(2)`.

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
libcsp = { version = "2.1", path = "." }   # or from crates.io once published
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
        .init()
        .expect("csp_init failed");

    // 2. Start the router task (spawns a POSIX thread on Linux/macOS)
    node.route_start_task(0, 0).expect("router task failed");

    // 3. Add a loopback route for local testing
    node.route_load("0/0 LOOP").unwrap();

    // 4. Create a server socket on port 10
    let mut sock = Socket::new(0);
    sock.bind(10).unwrap();

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
        .init()
        .expect("csp_init failed");

    node.route_start_task(0, 0).unwrap();
    node.route_load("0/0 LOOP").unwrap();

    // Connect to node 1, port 10, with normal priority, no connection options
    let conn = node
        .connect(Priority::Norm, 1, 10, 1000, 0)
        .expect("csp_connect failed — no free connections?");

    // Allocate a packet and fill it
    let mut pkt = Packet::get(32).expect("CSP buffer pool exhausted");
    pkt.write(b"hello from Rust!").unwrap();

    // send() always consumes the packet — libcsp frees the buffer whether
    // delivery succeeds or fails.
    conn.send(pkt);
    println!("Sent!");
    // conn is closed on drop
}
```

### Connectionless (UDP-style) example

```rust
use libcsp::{CspConfig, Packet, Priority, Socket, socket_opts};

fn main() {
    let node = CspConfig::new().address(3).init().unwrap();
    node.route_start_task(0, 0).unwrap();

    let mut sock = Socket::new(socket_opts::CONN_LESS);
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
| `std` | ✓ | `std::error::Error` impl for `CspError` and host-side helpers |
| `rdp` | ✓ | Reliable Datagram Protocol |
| `rdp-fast-close` | – | Fast close of RDP connections (implies `rdp`) |
| `hmac` | ✓ | HMAC-SHA1 authentication |
| `promisc` | ✓ | Promiscuous receive mode |
| `dedup` | ✓ | Packet deduplication (runtime toggle via `CspConfig::dedup`) |
| `host-default-arch` | ✓ | Auto-export POSIX arch shims when `external-arch` is on (Linux/macOS) |
| `socketcan` | – | Linux SocketCAN driver (`libsocketcan` required) |
| `zmq` | – | ZMQ hub interface (`libzmq` required) |
| `usart-linux` | – | Linux USART / KISS driver |
| `debug` | – | CSP debug counters and per-event print toggles |
| `external-arch` | – | Provide your own OS primitives via the `CspArch` trait |
| `zmq-v1-fixup` | – | Little-endian CSP v1 headers over ZMQ (legacy bridging) |
| `buffer-zero-clear` | – | Zero freed buffers on release |
| `ropi-rwpi` | – | ROPI/RWPI trampolines for R9-based ARM position independence |

### Buffer / connection sizing

Buffer count, buffer size and connection limits are compile-time constants.
Override them via environment variables before running `cargo build`:

```sh
LIBCSP_BUFFER_SIZE=512         # bytes per packet buffer
LIBCSP_BUFFER_COUNT=32         # number of packet buffers
LIBCSP_CONN_MAX=20             # max simultaneous connections
LIBCSP_CONN_RXQUEUE_LEN=16     # per-connection Rx queue
LIBCSP_QFIFO_LEN=50            # router FIFO length
LIBCSP_PORT_MAX_BIND=58        # highest bindable port (max 62)
LIBCSP_RTABLE_SIZE=20          # routing table entries
LIBCSP_MAX_INTERFACES=6        # max registered interfaces
LIBCSP_RDP_MAX_WINDOW=10       # RDP window size
LIBCSP_PACKET_PADDING_BYTES=8  # pre-data scratch bytes (header/IV space)
```

Read the resolved values back at runtime via `libcsp::consts::*` (e.g.
`libcsp::consts::BUFFER_SIZE`, `libcsp::consts::BUFFER_COUNT`, …).

**Port range split:** `LIBCSP_PORT_MAX_BIND` controls where the bindable
port range ends:
- Ports 0 to `PORT_MAX_BIND`: Bindable by servers
- Ports (`PORT_MAX_BIND`+1) to 63: Ephemeral (auto-assigned for client connections)
- Must be ≤ 62 (leaving at least 1 port for ephemeral use)

See [USAGE.md](USAGE.md#port-architecture) for details on port assignment.

---

## Debug and Logging

Enable the `debug` feature to activate CSP's counter-based diagnostics and
per-event print toggles:

```toml
[dependencies]
libcsp = { version = "2.1", features = ["debug"] }
```

```rust
use libcsp::debug::{self, RdpTrace};

// Snapshot the current error counters.
let c = debug::counters();
println!("buffer_out={} conn_out={} errno={}", c.buffer_out, c.conn_out, c.errno);

// Turn on RDP state-machine tracing and per-packet prints.
debug::set_rdp_trace(RdpTrace::Protocol);
debug::set_packet_trace(true);

// Reset counters between test runs.
debug::reset_counters();
```

Debug output goes through libcsp's `csp_print_func`, which by default writes
to stdout. See [LOGGING.md](LOGGING.md) for the full logging reference.

---

## `no_std` usage

```toml
[dependencies]
libcsp = { path = ".", default-features = false, features = ["rdp"] }
```

The `alloc` crate must be available on your target (it is on FreeRTOS with a
heap configured). The `external-arch` feature lets you supply your own OS
primitives via the [`CspArch`] trait — see [USAGE.md](USAGE.md#custom-arch-and-time-rtosbare-metal).

---

## Documentation

| Document | Description |
|----------|-------------|
| [README.md](README.md) | Quick start guide and feature overview (this file) |
| [USAGE.md](USAGE.md) | Comprehensive usage guide with patterns and examples |
| [LOGGING.md](LOGGING.md) | Debug counters and print-toggle reference |
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
├── interface    — CspInterface trait for custom transports
├── route        — Routing table helpers (load/set_raw/iterate)
├── service      — Dispatcher + CMP (ident/peek/poke) client helpers
├── debug        — Counter snapshots + RDP/packet trace toggles
├── arch         — CspArch trait for no_std OS primitives
└── init         — CspConfig builder + CspNode token
```

The C library (`./libcsp`) is compiled as a static library by `build.rs` using
the `cc` crate. `bindgen` generates `$OUT_DIR/bindings.rs` from
`libcsp/include/csp/csp.h`, which is included verbatim by `src/sys.rs`.

---

## License

This crate is a binding to libcsp which is licensed under the
**GNU Lesser General Public License v2.1** (LGPL-2.1). The Rust wrapper code
is licensed under the same terms. See [`libcsp/COPYING`](libcsp/COPYING).
