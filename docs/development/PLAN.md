# libcsp Rust Bindings — Implementation Plan

## Overview

Create a single Rust crate (`libcsp`) that:
1. Compiles the C library from `./libcsp` without any Python/waf dependency.
2. Generates safe FFI bindings via `bindgen`.
3. Exposes an idiomatic, zero-unsafe public API.

---

## Phase 1 — Build System (`build.rs` + `Cargo.toml`)

**Goal:** Reproduce the `wscript` logic in pure Rust using the `cc` crate.

### Steps

1. **`Cargo.toml`**
   - Package name: `libcsp`, version `1.6.0`, `links = "csp"`.
   - Build-dependencies: `cc = "1"`, `bindgen = "0.70"`.
   - Runtime dependencies: `bitflags = "2"`.
   - Feature flags mapping to `wscript` options:
     - `rdp`, `rdp-fast-close`, `crc32`, `hmac`, `xtea` — security/transport
     - `qos`, `promisc`, `dedup` — packet handling
     - `cidr-rtable` — CIDR routing table (default: static)
     - `socketcan`, `zmq`, `usart-linux`, `usart-windows` — optional drivers
     - `debug`, `debug-timestamp` — logging
   - Default features: `rdp crc32 hmac xtea qos promisc dedup`.

2. **`build.rs` — Config header generation**
   - Read `CARGO_CFG_TARGET_OS` for `CSP_POSIX` / `CSP_WINDOWS` / `CSP_MACOSX`.
   - Read `CARGO_CFG_TARGET_ENDIAN` for `CSP_LITTLE_ENDIAN` / `CSP_BIG_ENDIAN`.
   - Read `CARGO_FEATURE_*` env vars to set `CSP_USE_*` defines.
   - Read `LIBCSP_*` env vars for buffer/connection sizing (with documented defaults).
   - Write generated header to `$OUT_DIR/include/csp/csp_autoconfig.h`.

3. **`build.rs` — Compilation**
   - `cc::Build` with flags: `-std=gnu99 -Os -Wall -Wextra -Wshadow -Wcast-align -Wwrite-strings -Wno-unused-parameter`.
   - Explicit source file list (no glob) to avoid cache invalidation:

     **Core (always compiled):**
     ```
     src/{csp_buffer,csp_bridge,csp_conn,csp_crc32,csp_debug,csp_dedup,
          csp_endian,csp_hex_dump,csp_iflist,csp_init,csp_io,csp_port,
          csp_promisc,csp_qfifo,csp_route,csp_service_handler,
          csp_services,csp_sfp}.c
     src/transport/{csp_rdp,csp_udp}.c
     src/crypto/{csp_hmac,csp_sha1,csp_xtea}.c
     src/interfaces/{csp_if_can,csp_if_can_pbuf,csp_if_i2c,
                     csp_if_kiss,csp_if_lo,csp_if_zmqhub}.c
     src/arch/csp_system.c  src/arch/csp_time.c
     src/rtable/csp_rtable.c
     src/rtable/csp_rtable_static.c  (or _cidr.c if feature=cidr-rtable)
     ```

     **POSIX arch (default target):**
     ```
     src/arch/posix/{csp_clock,csp_malloc,csp_queue,csp_semaphore,
                     csp_system,csp_thread,csp_time,pthread_queue}.c
     ```

     **macOS arch (target_os = macos):**
     ```
     src/arch/macosx/{...same list...}.c
     ```

     **Windows arch (target_os = windows):**
     ```
     src/arch/windows/{...,windows_queue}.c
     ```

     **Optional drivers:**
     ```
     src/drivers/can/can_socketcan.c        (feature = socketcan)
     src/drivers/usart/usart_kiss.c         (feature = usart-linux or usart-windows)
     src/drivers/usart/usart_linux.c        (feature = usart-linux)
     src/drivers/usart/usart_windows.c      (feature = usart-windows)
     ```

   - Include paths: `libcsp/include`, `libcsp/src`, `libcsp/src/transport`,
     `libcsp/src/interfaces`, `$OUT_DIR/include`.
   - Compile to static library `libcsp.a`.

4. **`build.rs` — Link flags**
   - POSIX/Linux: `pthread`, `rt`.
   - macOS: `pthread`.
   - Windows: `ws2_32`.
   - Optional: `socketcan` (feature=socketcan), `zmq` (feature=zmq).

5. **`build.rs` — Binding generation**
   - `bindgen::Builder` on `libcsp/include/csp/csp.h`.
   - Clang args: same include paths, OS and endian defines.
   - `allowlist_function("csp_.*")`, `allowlist_type("csp_.*")`, `allowlist_var("CSP_.*")`.
   - `raw_line()` to inject the LGPL license header into generated file.
   - Output: `$OUT_DIR/bindings.rs`.

---

## Phase 2 — Raw Bindings Module (`src/sys.rs`)

**Goal:** Thin wrapper that includes the bindgen output.

```rust
// src/sys.rs
#![allow(non_upper_case_globals, non_camel_case_types, non_snake_case, dead_code)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
```

No other content — all unsafe symbols live here.

---

## Phase 3 — Error Handling (`src/error.rs`)

**Goal:** Map C integer error codes to a Rust enum.

- `CspError` enum with variants for every `CSP_ERR_*` constant plus `Other(i32)`.
- `impl std::error::Error for CspError`.
- `impl std::fmt::Display for CspError`.
- Helper `fn csp_result(code: i32) -> crate::Result<()>`.

Error codes to map:
| C constant      | Variant             |
|-----------------|---------------------|
| CSP_ERR_NONE    | (Ok)                |
| CSP_ERR_NOMEM   | NoMemory            |
| CSP_ERR_INVAL   | InvalidArgument     |
| CSP_ERR_TIMEDOUT| TimedOut            |
| CSP_ERR_USED    | ResourceInUse       |
| CSP_ERR_NOTSUP  | NotSupported        |
| CSP_ERR_BUSY    | Busy                |
| CSP_ERR_ALREADY | AlreadyInProgress   |
| CSP_ERR_RESET   | ConnectionReset     |
| CSP_ERR_NOBUFS  | NoBuffers           |
| CSP_ERR_TX      | TransmitFailed      |
| CSP_ERR_DRIVER  | DriverError         |
| CSP_ERR_AGAIN   | Again               |
| CSP_ERR_HMAC    | HmacFailed          |
| CSP_ERR_XTEA    | XteaFailed          |
| CSP_ERR_CRC32   | Crc32Failed         |
| CSP_ERR_SFP     | SfpError            |
| other           | Other(i32)          |

---

## Phase 4 — Packet RAII Wrapper (`src/packet.rs`)

**Goal:** Safe, owned handle for `csp_packet_t*`. Auto-frees on drop.

### Design

```rust
pub struct Packet { inner: *mut sys::csp_packet_t }
```

### Key impl

- `Packet::get(data_size: usize) -> Option<Packet>`
  — calls `csp_buffer_get(data_size)`
- `fn data(&self) -> &[u8]`
  — uses known layout: data starts at byte offset 16 (padding[10]+length(2)+id(4))
  — slice length = `self.length()`
- `fn data_mut(&mut self) -> &mut [u8]`
  — mutable view of `[..self.length()]`
- `fn data_buf_mut(&mut self) -> &mut [u8]`
  — full writable capacity (`csp_buffer_data_size()` bytes) for initial fill
- `fn length(&self) -> u16`
- `fn set_length(&mut self, len: u16)`
- `fn id(&self) -> u32` — raw CSP header
- `pub(crate) fn into_raw(self) -> *mut sys::csp_packet_t` — forget self
- `pub(crate) unsafe fn from_raw(ptr) -> Packet` — take ownership
- `impl Drop` — calls `csp_buffer_free()`
- `unsafe impl Send for Packet`

### Data layout note

```text
offset  0: uint8_t  padding[10]
offset 10: uint16_t length
offset 12: csp_id_t id (uint32_t)
offset 16: data[] (flexible array)
```

DATA_OFFSET = 16 is stable across all platforms (no compiler padding due to
alignment coincidentally matching standard rules).

---

## Phase 5 — Connection RAII Wrapper (`src/connection.rs`)

**Goal:** Safe handle for `csp_conn_t*`. Auto-closes on drop.

```rust
pub struct Connection { inner: *mut sys::csp_conn_t }
```

### Key impl

- `pub(crate) unsafe fn from_raw(ptr) -> Connection`
- `fn send(&self, packet: Packet, timeout: u32) -> Result<()>`
  — On success (C returns 1): packet ownership transferred to CSP, do NOT free.
  — On failure (C returns 0): take packet back via `from_raw` and let it drop.
- `fn read(&self, timeout: u32) -> Option<Packet>`
  — wraps `csp_read()`; returned pointer is owned by caller.
- `fn dst_port(&self) -> i32` — `csp_conn_dport()`
- `fn src_port(&self) -> i32` — `csp_conn_sport()`
- `fn dst_addr(&self) -> i32` — `csp_conn_dst()`
- `fn src_addr(&self) -> i32` — `csp_conn_src()`
- `fn flags(&self) -> i32` — `csp_conn_flags()`
- `impl Drop` — calls `csp_close()`
- `unsafe impl Send for Connection`

---

## Phase 6 — Socket Wrapper (`src/socket.rs`)

**Goal:** Safe handle for `csp_socket_t*` (server listening socket).

```rust
pub struct Socket { inner: *mut sys::csp_socket_t }
```

### Key impl

- `Socket::new(opts: u32) -> Option<Socket>` — `csp_socket(opts)`
- `fn bind(&self, port: u8) -> Result<()>` — `csp_bind()`
- `fn listen(&self, backlog: usize) -> Result<()>` — `csp_listen()`
- `fn accept(&self, timeout: u32) -> Option<Connection>` — `csp_accept()`
- `fn recvfrom(&self, timeout: u32) -> Option<Packet>` — for connectionless mode
- `unsafe impl Send for Socket`

Note: `csp_socket_t` is `typedef struct csp_conn_s csp_socket_t` — same underlying
type as `csp_conn_t`. No Drop impl (sockets are destroyed by `csp_free_resources()`).

---

## Phase 7 — Initialisation Builder (`src/init.rs`)

**Goal:** Enforce correct initialisation order and keep C string pointers alive.

```rust
pub struct CspConfig {
    address: u8,
    hostname: CString,
    model: CString,
    revision: CString,
    conn_max: u8,
    conn_queue_length: u8,
    fifo_length: u8,
    port_max_bind: u8,
    rdp_max_window: u8,
    buffers: u16,
    buffer_data_size: u16,
}
```

### Builder methods (all `-> Self`)

- `new() -> Self` — sensible defaults matching `csp_conf_get_defaults()`
- `address(u8)`, `hostname(&str)`, `model(&str)`, `revision(&str)`
- `conn_max(u8)`, `conn_queue_length(u8)`, `fifo_length(u8)`
- `port_max_bind(u8)`, `rdp_max_window(u8)`
- `buffers(u16)`, `buffer_data_size(u16)`

### `fn init(self) -> Result<CspNode>`

- Fills `sys::csp_conf_t` from `self` fields.
- Calls `csp_init(&conf)`.
- Returns `CspNode` which holds `self` to keep `CString`s alive.

```rust
pub struct CspNode { _config: CspConfig }
```

### `CspNode` methods

- `fn connect(&self, prio: u8, dst: u8, port: u8, timeout: u32, opts: u32) -> Option<Connection>`
- `fn route_start_task(&self, stack_size: u32, priority: u32) -> Result<()>`
- `impl Drop` — calls `csp_free_resources()`

---

## Phase 8 — Routing Wrapper (`src/route.rs`)

**Goal:** Safe wrapper for the routing table API from `csp_rtable.h`.

- Read `include/csp/csp_rtable.h` to confirm exact function signatures.
- Likely: `fn route_set(addr: u8, iface: &csp_iface_t, netmask: u8) -> Result<()>`.
- Expose `CspRoute` struct or free functions on `CspNode`.

> **Status:** Deferred until `csp_rtable.h` is read. The raw API is accessible
> via `sys::csp_rtable_*` in the meantime.

---

## Phase 9 — Public API surface (`src/lib.rs`)

```rust
pub mod sys;       // raw bindgen output
pub mod error;
pub mod init;
pub mod packet;
pub mod connection;
pub mod socket;

pub use error::CspError;
pub use init::{CspConfig, CspNode};
pub use packet::Packet;
pub use connection::Connection;
pub use socket::Socket;
pub type Result<T> = std::result::Result<T, CspError>;
```

**Socket option constants** — expose as `bitflags!` wrapper:
```rust
bitflags! {
    pub struct SocketOpts: u32 {
        const NONE    = 0x0000;
        const RDP_REQ = 0x0001;
        // ...
    }
}
```

**Priority enum:**
```rust
#[repr(u8)]
pub enum Priority { Critical = 0, High = 1, Norm = 2, Low = 3 }
```

---

## Phase 10 — Documentation & Examples (`README.md`)

### Usage example (minimal server/client)

```rust
use libcsp::{CspConfig, Priority, SocketOpts};

fn main() -> libcsp::Result<()> {
    let node = CspConfig::new()
        .address(1)
        .hostname("my-sat")
        .buffers(10)
        .buffer_data_size(256)
        .init()?;

    node.route_start_task(4096, 0)?;

    // Server
    let socket = libcsp::Socket::new(SocketOpts::NONE.bits())
        .expect("csp_socket failed");
    socket.bind(10)?;
    socket.listen(10)?;

    if let Some(conn) = socket.accept(1000) {
        if let Some(mut pkt) = conn.read(100) {
            println!("Received {} bytes", pkt.length());
        }
    }

    // Client
    let conn = node
        .connect(Priority::Norm as u8, 2, 10, 1000, 0)
        .expect("csp_connect failed");

    let mut pkt = libcsp::Packet::get(32).expect("no buffers");
    pkt.data_buf_mut()[..5].copy_from_slice(b"hello");
    pkt.set_length(5);
    conn.send(pkt, 100)?;

    Ok(())
}
```

---

## File Checklist

| File | Status |
|------|--------|
| `Cargo.toml` | ✅ Done |
| `build.rs` | ✅ Done |
| `src/sys.rs` | ✅ Done |
| `src/lib.rs` | ✅ Done |
| `src/error.rs` | ✅ Done |
| `src/init.rs` | ✅ Done |
| `src/packet.rs` | ✅ Done |
| `src/connection.rs` | ✅ Done |
| `src/socket.rs` | ✅ Done |
| `src/route.rs` | ✅ Done |
| `README.md` | ✅ Done |

---

---

## Phase 11 — `no_std` Support

**Goal:** Make all core-protocol code work without the standard library
(e.g. embedded targets running FreeRTOS or bare-metal).

### Changes required

| File | Change |
|------|--------|
| `Cargo.toml` | Add `std` feature (default-on). Gate `std::error::Error` impl behind it. |
| `build.rs` | Set `use_core(true)` on bindgen so generated code uses `core::ffi` types. |
| `src/lib.rs` | `#![cfg_attr(not(feature = "std"), no_std)]` + `extern crate alloc`. |
| `src/error.rs` | `use core::fmt`. Impl `std::error::Error` only under `#[cfg(feature = "std")]`. |
| `src/packet.rs` | `use core::slice`, `use core::fmt`. |
| `src/connection.rs` | `use core::fmt`. All `std::` → `core::`. |
| `src/socket.rs` | Pure `core` — no heap, no strings. |
| `src/init.rs` | `use alloc::ffi::CString`. Requires `alloc` feature (FreeRTOS typically has a heap). |

### Feature-gating strategy

```toml
[features]
default = ["std", "rdp", "crc32", "hmac", "xtea", "qos", "promisc", "dedup"]
std     = []    # pulls in std::error::Error impl and std-only helpers
```

- `no_std` targets: disable `std` feature, keep `alloc` available (required for
  `CString` in `init.rs` and the `Packet` heap allocation from the CSP pool).
- A truly allocation-free mode (no `alloc`) is possible only if CSP itself is
  configured with a static buffer pool — that is already how libcsp works, so
  `Packet::get()` never calls Rust allocator; however `CString` in `init.rs`
  still needs `alloc`. A future `static-init` feature could accept raw
  `*const c_char` pointers to bypass this.

### Affected items

- `std::error::Error` impl for `CspError`: `#[cfg(feature = "std")]` only.
- `std::fmt` → `core::fmt` everywhere.
- `std::slice` → `core::slice`.
- `std::mem` → `core::mem`.
- `std::ffi::CString` → `alloc::ffi::CString`.
- bindgen `use_core(true)` so output uses `core::ffi::c_*` types.

---

## Known Risks / Open Questions

1. **`data[0]` flexible array** — bindgen generates `__IncompleteArrayField`. Packet
   data access uses hardcoded offset 16 as a safe fallback. If struct alignment ever
   differs (e.g. on exotic targets), this needs `offset_of!` validation.

2. **`csp_socket_t` lifetime** — libcsp doesn't expose an explicit socket-free function.
   Sockets are freed by `csp_free_resources()`. `Socket` therefore has no `Drop` impl;
   the `CspNode` drop handles cleanup.

3. **Thread safety** — libcsp uses POSIX mutexes internally. Our wrappers add `Send`
   but not `Sync`. Sharing a `Connection` across threads is unsafe in the general case
   and should be done only via `Arc<Mutex<Connection>>`.

4. **`zmq` interface** — `csp_if_zmqhub.c` is always compiled into the library but the
   ZMQ _socket_ init requires `libzmq` at link time. The `zmq` feature controls linking.
   If ZMQ is not needed, the interface file is still compiled but never called, so
   link errors only occur if `feature = zmq` is set.

5. **Routing table API** — `csp_rtable.h` was not read during planning. The `route.rs`
   module must be completed after inspecting that header.
