# libcsp Rust Port — Usage Guide

This guide explains how to use the `libcsp` Rust bindings, focusing on memory safety, ownership, and idiomatic patterns.

---

## 1. Initialisation

CSP is a global singleton. Initialise it once at the start of your application.

```rust
use libcsp::CspConfig;

fn main() -> libcsp::Result<()> {
    let node = CspConfig::new()
        .address(1)            // Set local CSP address (0-31)
        .hostname("my-sat")
        .buffers(20, 256)      // 20 buffers of 256 bytes each
        .init()?;              // Returns a CspNode handle (RAII)

    // The CspNode handle keeps the CSP runtime alive.
    // When dropped, it calls `csp_free_resources()`.

    // Start the background router task (optional but recommended)
    // Note: This spawns a thread/task using the C library's arch layer.
    node.route_start_task(4096, 0)?;

    Ok(())
}
```

### Manual Routing (For RTOS/Embassy)
If you are in an environment where you want to manage tasks yourself (like `embassy` or a custom RTOS), do **not** call `route_start_task`. Instead, call `route_work` in your own task:

```rust
// Dedicated router task
loop {
    // This call is BLOCKING. It will put your task to sleep
    // and wake up instantly when a packet is pumped via handle.rx(pkt).
    node.route_work(libcsp::MAX_TIMEOUT).unwrap();
}
```

**Note on Latency:** Because `handle.rx(pkt)` signals the internal router queue, the handoff from your hardware RX interrupt/task to the CSP router is immediate. You do not need to poll.

**Note on RDP:** The router must run periodically even if no hardware traffic exists to handle RDP retransmissions and connection timeouts.

---

## 2. Packet Management (The `Packet` Struct)

The `Packet` struct is an RAII wrapper around `csp_packet_t`.

### Allocation and Ownership
*   **Get:** `Packet::get(size)` allocates from the CSP pool.
*   **Drop:** When a `Packet` goes out of scope, it is **automatically freed** back to the pool.
*   **Transfer:** When you `send` a packet, ownership is transferred to the CSP stack.

```rust
use libcsp::Packet;

if let Some(mut pkt) = Packet::get(32) {
    pkt.write(b"hello").unwrap();
    // Packet will be freed here if not moved (e.g. into conn.send())
}
```

### Decoding Headers
`Packet` provides safe methods to inspect the CSP header without bit-shifting:
```rust
let src = pkt.src_addr();
let dst = pkt.dst_addr();
let port = pkt.dst_port();
if pkt.is_rdp() { /* ... */ }
```

---

## 3. Send Patterns

This section shows the four common patterns for sending data: fire-and-forget, reliable, encrypted, and request/response.

---

### 3.1 Fire-and-Forget Telemetry

Use `node.sendto()` when you want to blast data out as fast as possible without consuming a connection slot. Think sensor readings, status beacons, or anything where a lost frame is acceptable.

```rust
use libcsp::{Packet, Priority, socket_opts};

const TELEMETRY_PORT: u8 = 10;
const DST_NODE: u8 = 2;

// node.sendto returns the packet on failure so you can log and drop it.
if let Some(mut pkt) = Packet::get(16) {
    let telemetry: [u8; 16] = build_telemetry_frame();
    pkt.write(&telemetry).unwrap();

    if let Err((_e, _pkt)) = node.sendto(
        Priority::Norm as u8,
        DST_NODE,
        TELEMETRY_PORT,
        0,                   // src_port: 0 lets CSP assign one
        socket_opts::NONE,
        pkt,
        0,                   // timeout: unused for connectionless send
    ) {
        // _pkt is dropped here, automatically returned to the pool.
        // Log the failure or just ignore it — this is fire-and-forget.
    }
}
```

**Receiver side:**
```rust
use libcsp::{Socket, socket_opts};

let sock = Socket::new(socket_opts::NONE).unwrap();
sock.bind(TELEMETRY_PORT).unwrap();
sock.listen(10).unwrap();

while let Some(conn) = sock.accept(libcsp::MAX_TIMEOUT) {
    while let Some(pkt) = conn.read(100) {
        let data = pkt.data();
        println!("[RX] {} bytes from node {}", data.len(), conn.src_addr());
        // pkt freed here automatically
    }
}
```

**When to use:** High-rate sensor data, heartbeats, logs. No handshake overhead.

---

### 3.2 Reliable Data Transfer (RDP)

Use a connection opened with `conn_opts::RDP` when delivery must be guaranteed. CSP's Reliable Datagram Protocol adds sequence numbers, acknowledgements, and retransmission.

```rust
use libcsp::{Priority, conn_opts};

const DATA_PORT: u8 = 11;
const DST_NODE: u8 = 2;

// Connect — the RDP three-way handshake happens here.
// Returns None if no connection slots are free or the handshake times out.
if let Some(conn) = node.connect(
    Priority::Norm as u8,
    DST_NODE,
    DATA_PORT,
    1000,           // handshake timeout (ms)
    conn_opts::RDP,
) {
    for chunk in big_payload.chunks(200) {
        if let Some(mut pkt) = Packet::get(chunk.len()) {
            pkt.write(chunk).unwrap();

            // send() returns the packet on failure so you can retry or abort.
            if let Err((_e, _pkt)) = conn.send(pkt, 500) {
                eprintln!("send failed, aborting transfer");
                break;
            }
        }
    }
    // conn dropped here → graceful RDP FIN exchange
}
```

**Receiver side** (same as fire-and-forget, but RDP delivers in order):
```rust
use libcsp::{Socket, socket_opts};

let sock = Socket::new(socket_opts::NONE).unwrap();
sock.bind(DATA_PORT).unwrap();
sock.listen(10).unwrap();

while let Some(conn) = sock.accept(libcsp::MAX_TIMEOUT) {
    if conn.flags() & libcsp::sys::CSP_FRDP as i32 != 0 {
        println!("RDP session from node {}", conn.src_addr());
    }
    while let Some(pkt) = conn.read(500) {
        process(pkt.data()); // guaranteed order, no duplicates
    }
}
```

**When to use:** Firmware uploads, large file transfers, anything where data loss is unacceptable.

**Tip:** Call `csp_rdp_set_opt` before opening connections to tune window size and timeouts for your link budget.

---

### 3.3 Encrypted Transfer (XTEA)

Add `conn_opts::XTEA` to any connection to transparently encrypt the payload. The shared 128-bit key is pre-loaded into the C layer via `csp_xtea_set_key()`. You can combine flags — e.g. `conn_opts::RDP | conn_opts::XTEA` gives you both reliability and encryption.

```rust
use libcsp::{Priority, conn_opts};

const SECRET_PORT: u8 = 20;
const DST_NODE: u8 = 2;

// Establish an XTEA-encrypted channel.
// Both ends must have the same pre-shared key loaded.
if let Some(conn) = node.connect(
    Priority::Norm as u8,
    DST_NODE,
    SECRET_PORT,
    1000,
    conn_opts::XTEA,        // or: conn_opts::RDP | conn_opts::XTEA
) {
    if let Some(mut pkt) = Packet::get(32) {
        pkt.write(b"top secret command").unwrap();
        let _ = conn.send_discard(pkt, 500);
    }
}
```

**Loading the key** (do this once at startup, before any connections):
```rust
// Safety: csp_xtea_set_key writes to a global C array.
// Call before route_start_task and any connections.
let key: [u32; 4] = [0xDEAD_BEEF, 0xCAFE_F00D, 0x1234_5678, 0xABCD_EF01];
unsafe {
    libcsp::sys::csp_xtea_set_key(key.as_ptr(), key.len() as u32);
}
```

**Receiver side** — decryption is automatic as long as the socket does not prohibit XTEA:
```rust
use libcsp::{Socket, socket_opts};

// socket_opts::NONE accepts any security flags the sender used.
let sock = Socket::new(socket_opts::NONE).unwrap();
sock.bind(SECRET_PORT).unwrap();
sock.listen(5).unwrap();

while let Some(conn) = sock.accept(libcsp::MAX_TIMEOUT) {
    while let Some(pkt) = conn.read(500) {
        // CSP has already decrypted the payload by the time we read it.
        println!("Decrypted: {:?}", pkt.data());
    }
}
```

**To require encryption** (reject unencrypted connections):
```rust
// Bind with XTEA_REQ — CSP drops packets that arrive unencrypted.
let sock = Socket::new(socket_opts::XTEA_REQ).unwrap();
```

**When to use:** Command channels, keying material distribution, any data that must not be readable on-wire.

---

### 3.4 Request / Response

#### One-Shot (Single Round-Trip)

`node.transaction()` opens a connection, sends a request, waits for exactly one reply, and closes the connection — all in one call. Ideal for simple queries.

```rust
use libcsp::{Priority, conn_opts};

const QUERY_PORT: u8 = 12;
const DST_NODE: u8 = 2;

let request  = b"GET temperature";
let mut reply = [0u8; 64];

let reply_len = node.transaction(
    Priority::Norm as u8,
    DST_NODE,
    QUERY_PORT,
    1000,           // timeout (ms)
    request,
    &mut reply,
    -1,             // -1 = unknown reply length (reply buf is the limit)
    conn_opts::NONE,
)?;

println!("Reply ({} bytes): {:?}", reply_len, &reply[..reply_len as usize]);
```

#### Server Side

Return `Some(reply_pkt)` from a `Dispatcher` handler to send a response back on the same connection.

```rust
use libcsp::{Dispatcher, Packet, Port};

let mut server = Dispatcher::new().unwrap();

server.register(Port::Custom(QUERY_PORT), |_conn, pkt| {
    let request = pkt.data();
    println!("Query: {:?}", request);

    // Build the reply.
    let response = b"23.4 C";
    if let Some(mut reply) = Packet::get(response.len()) {
        reply.write(response).unwrap();
        Some(reply)   // Returning Some sends the reply automatically.
    } else {
        None          // Returning None consumes pkt with no reply sent.
    }
})?;

// Run blocks the current thread. Spin it in a dedicated thread or task.
server.run(libcsp::MAX_TIMEOUT);
```

#### Multi-Round-Trip (Persistent Connection)

For protocols that need several exchanges on one connection, open the connection manually and send/receive in a loop.

```rust
use libcsp::{Priority, conn_opts, Packet};

if let Some(conn) = node.connect(
    Priority::Norm as u8, DST_NODE, QUERY_PORT, 1000, conn_opts::NONE,
) {
    // Round 1
    if let Some(mut req) = Packet::get(16) {
        req.write(b"HELLO").unwrap();
        let _ = conn.send_discard(req, 200);
    }
    if let Some(reply) = conn.read(500) {
        println!("Round 1 reply: {:?}", reply.data());
    }

    // Round 2
    if let Some(mut req) = Packet::get(16) {
        req.write(b"GET data").unwrap();
        let _ = conn.send_discard(req, 200);
    }
    if let Some(reply) = conn.read(500) {
        println!("Round 2 reply: {:?}", reply.data());
    }

    // conn dropped here → connection closed
}
```

### 3.5 Large Payload Transfer (SFP)

CSP's Simple Fragmentation Protocol (SFP) lets you send payloads larger than a single packet MTU. The sender fragments the data automatically; the receiver reassembles it into a single `Vec<u8>`. Use SFP whenever your payload is bigger than your packet buffer size (typically 128–256 bytes on embedded links).

```rust
use libcsp::{Priority, conn_opts};

const SFP_PORT: u8 = 11;
const DST_NODE: u8 = 2;

// Sender
if let Some(conn) = node.connect(
    Priority::Norm as u8,
    DST_NODE,
    SFP_PORT,
    1000,
    conn_opts::NONE,        // add conn_opts::RDP for reliable fragmented transfer
) {
    let firmware: Vec<u8> = load_firmware(); // e.g. 32 KB
    // mtu = max bytes per CAN frame payload (≤ packet buffer data size)
    conn.sfp_send(&firmware, 180, 2000)?;
}
```

**Receiver side:**
```rust
use libcsp::{Socket, socket_opts};

let sock = Socket::new(socket_opts::NONE).unwrap();
sock.bind(SFP_PORT).unwrap();
sock.listen(5).unwrap();

while let Some(conn) = sock.accept(libcsp::MAX_TIMEOUT) {
    match conn.sfp_recv(5000) {   // timeout covers the whole reassembly
        Ok(data) => {
            println!("SFP: received {} bytes from node {}", data.len(), conn.src_addr());
            flash_write(&data);
        }
        Err(e) => eprintln!("SFP reassembly failed: {:?}", e),
    }
}
```

**When to use:** Firmware uploads, telemetry dumps, large configuration blobs — anything that must be delivered as one logical unit but is too large for a single CSP packet.

**Tip:** Combine with RDP (`conn_opts::RDP | conn_opts::NONE` → just `conn_opts::RDP`) to get reliable, ordered fragment delivery with retransmission.

---

## 4. High-Level Networking

### The `Port` Enum
Avoid magic numbers by using the `Port` enum for standard services and custom ports.
```rust
use libcsp::Port;

let port_ping   = Port::Ping;
let port_custom = Port::Custom(10);
```

### Server-Side: The `Dispatcher`
The `Dispatcher` allows you to register closures for specific ports, avoiding manual `accept`/`read` loops.

```rust
use libcsp::{Dispatcher, Port, MAX_TIMEOUT};

let mut server = Dispatcher::new().unwrap();

// Bind standard service handlers (Ping, Uptime, etc.)
server.bind_service(Port::Ping)?;

// Register custom port logic
server.register(Port::Custom(10), |conn, pkt| {
    println!("Received {} bytes", pkt.length());
    Some(pkt) // Return packet to send as a reply, or None to consume
})?;

// Run the dispatcher (blocks or run in thread)
server.run(MAX_TIMEOUT);
```

### Client-Side: CMP Services
Safe wrappers for the CSP Management Protocol (CMP) return high-level Rust types.

```rust
// Get remote node identification
let info = node.ident(address, 1000)?;
println!("Remote node is {} running {}", info.hostname, info.model);

// Read/Write remote memory (Peek/Poke)
let data = node.peek(address, 0x20000000, 4, 1000)?;
node.poke(address, 0x20000000, &[0xDE, 0xAD, 0xBE, 0xEF], 1000)?;
```

---

## 5. Custom Interfaces (Transports)

Implement the `CspInterface` trait to bridge CSP to custom hardware (e.g., STM32 CAN via `embassy`).

```rust
use libcsp::{CspInterface, Packet, interface};

struct MyCanDriver { /* ... */ }

impl CspInterface for MyCanDriver {
    fn name(&self) -> &str { "MY_CAN" }

    fn nexthop(&mut self, via: u8, pkt: Packet) {
        // 1. Hardware TX
        // self.hw.send(pkt.id_raw(), pkt.data());

        // 2. Packet pkt is dropped and freed here automatically.
    }
}

// Registration returns an InterfaceHandle
let my_iface = MyCanDriver { ... };
let handle = interface::register(my_iface);
```

### The RX Flow (Pumping packets into CSP)

When receiving data from hardware, you must manually feed it into the CSP router.

```rust
// 1. You receive data from your hardware
let raw_data = [0u8; 10];
let can_id = 0x12345678;

// 2. Allocate a packet from the CSP pool
if let Some(mut pkt) = Packet::get(raw_data.len()) {
    // 3. Fill the packet
    pkt.set_id_raw(can_id);
    pkt.write(&raw_data).unwrap();

    // 4. "Pump" it into the router
    // This transfers ownership to the CSP stack.
    handle.rx(pkt);
}
```

Internal mechanism: `handle.rx()` calls `csp_qfifo_write()`, which wakes up the background router task to process the packet.

---

## 6. Sniffing Traffic

Use the RAII `Sniffer` handle to enable promiscuous mode. It disables automatically when dropped.

```rust
use libcsp::promisc;

let sniffer = promisc::Sniffer::open(10).expect("Promisc failed");
while let Some(pkt) = sniffer.read(1000) {
    println!("Sniffed: {} -> {}", pkt.src_addr(), pkt.dst_addr());
}
```

---

## 7. Custom Arch and Time (RTOS/Bare-Metal)

In a `no_std` or custom RTOS environment (like `embassy` on STM32), libcsp needs primitives for time, mutexes, and queues.

### Providing Time
Libcsp does not have a built-in clock for `no_std`. You **must** provide the following C symbols. You can implement them directly in Rust using `#[no_mangle]`:

```rust
#[no_mangle]
pub extern "C" fn csp_get_ms() -> u32 {
    // Return system time in milliseconds
    // E.g. embassy_time::Instant::now().as_millis() as u32
    0
}

#[no_mangle]
pub extern "C" fn csp_get_s() -> u32 {
    // Return system time in seconds
    0
}
```

### Providing OS Primitives (CspArch Trait)
If you enable the `external-arch` feature, you can provide all OS primitives by implementing the `CspArch` trait. This is the recommended way for `no_std` environments like Embassy.

```rust
use libcsp::{CspArch, export_arch};
use core::ffi::c_void;

struct MyArch;

impl CspArch for MyArch {
    fn get_ms(&self) -> u32 { /* ... */ 0 }
    fn get_s(&self) -> u32 { /* ... */ 0 }

    fn bin_sem_create(&self) -> *mut c_void { /* ... */ core::ptr::null_mut() }
    fn bin_sem_wait(&self, sem: *mut c_void, timeout: u32) -> bool { true }
    // ... implement other methods ...
    fn malloc(&self, size: usize) -> *mut c_void { /* ... */ core::ptr::null_mut() }
    fn free(&self, _ptr: *mut c_void) { /* ... */ }
}

// Export symbols to the C linker
export_arch!(MyArch, MyArch);
```

The `export_arch!` macro generates the `#[no_mangle]` C shims that libcsp expects.

### Cross-Compilation Requirement
When building for an embedded target (e.g. `thumbv7em-none-eabihf`), the `cc` crate requires an appropriate cross-compiler (e.g. `arm-none-eabi-gcc`) to be available on your host system to compile the libcsp C core.

---

## 8. Summary of Ownership

| Action | Ownership |
|--------|-----------|
| `Packet::get()` | Caller owns the packet. |
| `node.sendto(pkt)` | If success: CSP takes ownership. If fail: returned in `Err((e, pkt))`. |
| `conn.send(pkt)` | If success: CSP takes ownership. If fail: returned in `Err((e, pkt))`. |
| `conn.send_discard(pkt)` | Always consumed — freed on failure, sent on success. |
| `conn.read()` / `sniffer.read()` | Caller owns the returned packet. |
| `Dispatcher` handler | Closure takes ownership of `Packet`. Return `Some(pkt)` to send as reply. |
| `CspInterface::nexthop` | Trait method takes ownership of `Packet`. |
| `handle.rx(pkt)` | Ownership transferred to CSP router. |

## 9. Pattern Comparison

| Pattern | API | Overhead | Delivery |
|---------|-----|----------|----------|
| Fire-and-forget | `node.sendto()` | None (no connection slot) | Best-effort |
| Reliable | `node.connect(…, RDP)` + `conn.send()` | RDP handshake + ACKs | Guaranteed, ordered |
| Encrypted | `node.connect(…, XTEA)` + `conn.send()` | XTEA cipher per packet | Best-effort, encrypted |
| Reliable + Encrypted | `node.connect(…, RDP \| XTEA)` | Both | Guaranteed, ordered, encrypted |
| Large payload | `node.connect()` + `conn.sfp_send()` | Fragmentation overhead | Best-effort |
| Large payload, reliable | `node.connect(…, RDP)` + `conn.sfp_send()` | RDP + fragmentation | Guaranteed, ordered |
| One-shot request/reply | `node.transaction()` | Connection per call | Best-effort |
| Multi-round request/reply | `node.connect()` + manual send/read | One connection | Best-effort |
