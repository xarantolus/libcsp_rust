# libcsp Rust Port — Usage Guide

This guide explains how to use the `libcsp` Rust bindings, focusing on memory safety, ownership, and idiomatic patterns.

---

## 1. Initialisation

CSP is a global singleton. Initialise it once at the start of your application.

```rust
use libcsp::{CspConfig, DedupMode};

fn main() -> libcsp::Result<()> {
    let node = CspConfig::new()
        .address(1)            // Set local CSP address (0-31 on wire v1)
        .hostname("my-sat")
        .model("CubeSat-1U")
        .revision("v1.0")
        .dedup(DedupMode::All) // Optional: drop duplicate packets
        .init()?;              // Returns a CspNode handle (RAII)

    // The CspNode handle keeps the CSP runtime alive; cloning it is cheap.
    // When the last clone is dropped, the crate marks the runtime free for
    // re-init.

    // Start the background router task (spawns a POSIX thread on Linux/macOS)
    node.route_start_task(0, 0)?;

    Ok(())
}
```

### Wire-format version

Version 1 uses a 4-byte header with 5-bit host addresses (0–31) and is the
default, matching the framing expected by most existing flight hardware.
Version 2 uses a 6-byte header with 14-bit addresses (0–16383). Opt in
explicitly:

```rust
let node = CspConfig::new()
    .version(2)
    .address(1000)
    .init()?;
```

Both ends of a link must agree on the wire version.

### Sizing

Buffer pool size, connection count, FIFO depth and similar limits are
compile-time constants set by the build script. Override them by setting
environment variables before `cargo build`:

| Env var | Affects |
|---------|---------|
| `LIBCSP_BUFFER_SIZE` | Bytes per packet buffer |
| `LIBCSP_BUFFER_COUNT` | Number of packet buffers |
| `LIBCSP_CONN_MAX` | Max simultaneous connections |
| `LIBCSP_CONN_RXQUEUE_LEN` | Per-connection RX queue depth |
| `LIBCSP_QFIFO_LEN` | Router incoming FIFO depth |
| `LIBCSP_PORT_MAX_BIND` | Highest bindable port (≤ 62) |
| `LIBCSP_RTABLE_SIZE` | Routing table entries |
| `LIBCSP_MAX_INTERFACES` | Max registered interfaces |
| `LIBCSP_RDP_MAX_WINDOW` | RDP window size |
| `LIBCSP_PACKET_PADDING_BYTES` | Reserved scratch bytes in front of the payload |

Read the resolved values back from the [`libcsp::consts`] module:

```rust
use libcsp::consts;

println!("Pool: {} buffers × {} bytes", consts::BUFFER_COUNT, consts::BUFFER_SIZE);
println!("Max conns: {}", consts::CONN_MAX);
```

### Manual Routing (For RTOS/Embassy)

In an environment where you want to manage tasks yourself (like `embassy` or
a custom RTOS), do **not** call `route_start_task`. Instead, call
`route_work` in your own task:

```rust
// Dedicated router task
loop {
    // This call is BLOCKING. It will put your task to sleep
    // and wake up instantly when a packet is pumped via handle.rx(pkt).
    node.route_work().unwrap();
}
```

**Note on Latency:** Because `handle.rx(pkt)` signals the internal router queue, the handoff from your hardware RX interrupt/task to the CSP router is immediate. You do not need to poll.

**Note on RDP:** The router must run periodically even if no hardware traffic exists to handle RDP retransmissions and connection timeouts.

---

## 2. Port Architecture

### Understanding CSP Ports

CSP uses 6-bit port numbers (0-63), divided into three categories:

```
┌──────────────────────────────────────────────────┐
│  CSP Port Space (0-63)                           │
├──────────────────────────────────────────────────┤
│  0-6:    Reserved Service Ports                 │
│          - Port 0: CMP (Management Protocol)    │
│          - Port 1: PING                         │
│          - Port 2-6: Other services             │
│                                                  │
│  7 to port_max_bind:  Bindable Ports           │
│          - Application servers bind here        │
│                                                  │
│  (port_max_bind+1) to 63:  Ephemeral Ports    │
│          - Auto-assigned for client connections │
│          - CSP picks these automatically        │
│                                                  │
│  255 (CSP_ANY):  Wildcard                      │
│          - Bind to accept on all ports          │
└──────────────────────────────────────────────────┘
```

### Port Assignment

**Key Difference from TCP/IP:** There is **NO** "port 0 = auto-assign"!

**Servers** bind to specific ports:
```rust
let mut sock = Socket::new(socket_opts::NONE);
sock.bind(10)?;  // Bind to port 10 — also initialises the RX queue
```

`bind()` already calls `csp_listen` internally, so a separate `listen()`
call is usually unnecessary.

**Clients** automatically get ephemeral source ports:
```rust
// CSP automatically assigns an ephemeral port from (port_max_bind+1) to 63
let conn = node.connect(Priority::Norm, dest_addr, dest_port, timeout, opts)?;
// No need to bind - source port is assigned automatically!
```

### Configuring Port Ranges

Adjust the bindable/ephemeral split at build time via `LIBCSP_PORT_MAX_BIND`:

```sh
LIBCSP_PORT_MAX_BIND=40 cargo build
```

**Important:** `PORT_MAX_BIND` must be ≤ 62 to leave at least one ephemeral
port for client connections.

### Port 0 is NOT for Auto-Assignment

Port 0 is **CMP** (CSP Management Protocol) - a critical service port:

```rust
// WRONG - This binds to CMP service, not auto-assign!
sock.bind(0)?;

// CORRECT - Bind to a specific application port
sock.bind(10)?;

// CORRECT - Client gets automatic ephemeral port
let conn = node.connect(Priority::Norm, dest_addr, 10, timeout, opts)?;
```

### Wildcard Binding

To accept connections on all ports:

```rust
use libcsp::ANY_PORT;

sock.bind(ANY_PORT)?;  // Port 255 = accept on any port
```

Specific port bindings take precedence over wildcard bindings.

---

## 3. Packet Management (The `Packet` Struct)

The `Packet` struct is an RAII wrapper around `csp_packet_t`.

### Allocation and Ownership
*   **Get:** `Packet::get(size)` allocates from the CSP pool.
*   **Drop:** When a `Packet` goes out of scope, it is **automatically freed** back to the pool.
*   **Transfer:** When you `send` a packet, ownership is transferred to the CSP stack.

```rust
use libcsp::Packet;

if let Some(mut pkt) = Packet::get(32) {
    pkt.write(b"hello").unwrap();
    // Packet is freed here automatically because it goes out of scope.
    // If you pass it to conn.send() or handle.rx(), ownership transfers
    // and the packet is freed by the CSP stack instead.
}
```

**Why can `pkt.write()` fail?**

All packet buffers are pre-allocated at startup with a fixed data capacity
controlled by `LIBCSP_BUFFER_SIZE` (exposed at runtime as
`libcsp::packet::BUFFER_SIZE`). The argument to `Packet::get(n)` is a
*minimum request hint*; you always get a buffer of the globally-configured
capacity. `pkt.write(bytes)` returns `Err(bytes.len())` if `bytes.len() >
BUFFER_SIZE`. For payloads that exceed one buffer, use SFP (§5.5).

### Decoding Headers

`Packet` provides safe accessors for the CSP header:

```rust
let src  = pkt.src_addr();   // u16
let dst  = pkt.dst_addr();   // u16
let port = pkt.dst_port();   // u8
let prio = pkt.priority();   // Priority enum
if pkt.is_rdp()   { /* ... */ }
if pkt.is_hmac()  { /* ... */ }
if pkt.is_crc32() { /* ... */ }
if pkt.is_frag()  { /* ... */ }
```

For the raw header struct use `pkt.id()` (returns a copy of
`sys::csp_id_t` with fields `pri`, `flags`, `src`, `dst`, `dport`,
`sport`). Write it back with `pkt.set_id(id)`.

---

## 5. Send Patterns

This section shows the common patterns for sending data: fire-and-forget,
reliable, and request/response.

---

### 5.1 Fire-and-Forget Telemetry

Use `node.sendto()` when you want to blast data out as fast as possible without consuming a connection slot. Think sensor readings, status beacons, or anything where a lost frame is acceptable.

```rust
use libcsp::{Packet, Priority, socket_opts};

const TELEMETRY_PORT: u8 = 10;
const DST_NODE: u16 = 2;

if let Some(mut pkt) = Packet::get(16) {
    let telemetry: [u8; 16] = build_telemetry_frame();
    pkt.write(&telemetry).unwrap();

    // sendto always consumes the packet — libcsp frees the buffer whether
    // delivery succeeded or not.
    node.sendto(
        Priority::Norm,
        DST_NODE,
        TELEMETRY_PORT,
        0,                   // src_port: 0 lets CSP assign one
        socket_opts::NONE,
        pkt,
    );
}
```

**Receiver side:**
```rust
use libcsp::{Socket, socket_opts};

let mut sock = Socket::new(socket_opts::NONE);
sock.bind(TELEMETRY_PORT).unwrap();

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

### 5.2 Reliable Data Transfer (RDP)

Use a connection opened with `conn_opts::RDP` when delivery must be guaranteed. CSP's Reliable Datagram Protocol adds sequence numbers, acknowledgements, and retransmission.

```rust
use libcsp::{Priority, conn_opts, Packet};

const DATA_PORT: u8 = 11;
const DST_NODE: u16 = 2;

// Connect — the RDP three-way handshake happens here.
// Returns None if no connection slots are free or the handshake times out.
if let Some(conn) = node.connect(
    Priority::Norm,
    DST_NODE,
    DATA_PORT,
    1000,           // handshake timeout (ms)
    conn_opts::RDP,
) {
    for chunk in big_payload.chunks(200) {
        if let Some(mut pkt) = Packet::get(chunk.len()) {
            pkt.write(chunk).unwrap();

            // send consumes pkt; libcsp always frees the buffer.
            conn.send(pkt);
        }
    }
    // conn dropped here → graceful RDP FIN exchange
}
```

**Receiver side** (same as fire-and-forget, but RDP delivers in order):
```rust
use libcsp::{Socket, socket_opts};

let mut sock = Socket::new(socket_opts::NONE);
sock.bind(DATA_PORT).unwrap();

while let Some(conn) = sock.accept(libcsp::MAX_TIMEOUT) {
    if conn.is_rdp() {
        println!("RDP session from node {}", conn.src_addr());
    }
    // conn.read(500): block up to 500 ms for the next packet.
    // Returns None when the sender closes the connection or the timeout
    // expires with nothing in the queue.
    while let Some(pkt) = conn.read(500) {
        process(pkt.data()); // guaranteed order, no duplicates
        // pkt freed here automatically
    }
    // conn dropped here → csp_close() called
}
```

**When to use:** Firmware uploads, large file transfers, anything where data loss is unacceptable.

**Tip:** Call `node.rdp_set_opt(...)` before opening connections to tune window size and timeouts for your link budget.

---

### 5.3 Per-Send Priority Override

The connection records a default priority at `connect()` time, but you can
override it on individual sends without tearing down the connection:

```rust
use libcsp::{Priority, Packet};

if let Some(mut pkt) = Packet::get(16) {
    pkt.write(b"urgent alert").unwrap();
    // Send this one packet at Critical priority regardless of the
    // connection's default.
    conn.send_prio(Priority::Critical, pkt);
}
```

**When to use:** Mixed traffic on a single connection where a subset of
messages must jump the QoS queue (alarms, keepalives).

---

### 5.4 Request / Response

#### One-Shot (Single Round-Trip)

`node.transaction()` opens a connection, sends a request, waits for exactly one reply, and closes the connection — all in one call. Ideal for simple queries.

```rust
use libcsp::{Priority, conn_opts};

const QUERY_PORT: u8 = 12;
const DST_NODE: u16 = 2;

let request  = b"GET temperature";
let mut reply = [0u8; 64];

let reply_len = node.transaction(
    Priority::Norm,
    DST_NODE,
    QUERY_PORT,
    1000,           // reply wait timeout (ms): how long to block waiting for the server's reply
    request,
    &mut reply,
    -1,             // -1 = unknown reply length (accept any size up to reply.len())
    conn_opts::NONE,
)?;

println!("Reply ({} bytes): {:?}", reply_len, &reply[..reply_len]);
```

#### Server Side

Return `Some(reply_pkt)` from a `Dispatcher` handler to send a response back on the same connection.

```rust
use libcsp::{Dispatcher, Packet, Port};

let mut server = Dispatcher::new();

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

**How timeouts work:**

| Call | Timeout argument | Meaning |
|------|-----------------|---------|
| `node.connect(…, timeout, …)` | ms | **Handshake timeout.** For RDP, this is how long to wait for the SYN-ACK. For plain CSP (no RDP), the connection slot is allocated immediately and this value is ignored. |
| `conn.send(pkt)` | — | `send` is void: it hands the packet to libcsp which always consumes it. There is no per-send timeout. |
| `conn.read(timeout)` | ms | **Receive timeout.** Blocks until a packet arrives in the connection's RX queue or the timeout expires. Returns `None` on timeout or when the peer closes the connection. Use `libcsp::MAX_TIMEOUT` to block indefinitely. |
| `node.transaction(…, timeout, …)` | ms | **Reply wait timeout.** Used by the one-shot helper; applies only to waiting for the server's single reply. |

**Client side:**
```rust
use libcsp::{Priority, conn_opts, Packet};

// connect: 1000 ms RDP handshake timeout (ignored here since no RDP flag)
if let Some(conn) = node.connect(
    Priority::Norm, DST_NODE, QUERY_PORT, 1000, conn_opts::NONE,
) {
    // Round 1: send a request
    if let Some(mut req) = Packet::get(16) {
        req.write(b"HELLO").unwrap();
        conn.send(req); // req ownership consumed by libcsp
    }
    // Block up to 500 ms for the server's reply
    if let Some(reply) = conn.read(500) {
        println!("Round 1 reply: {:?}", reply.data());
        // reply freed here automatically
    }

    // Round 2: send another request on the same connection
    if let Some(mut req) = Packet::get(16) {
        req.write(b"GET data").unwrap();
        conn.send(req);
    }
    if let Some(reply) = conn.read(500) {
        println!("Round 2 reply: {:?}", reply.data());
        // reply freed here automatically
    }

    // conn dropped here → csp_close() called, connection torn down
}
```

**Server side** — handle multiple packets on the same connection using a `Dispatcher`:
```rust
use libcsp::{Dispatcher, Packet, Port};

let mut server = Dispatcher::new();

server.register(Port::Custom(QUERY_PORT), |_conn, pkt| {
    // pkt is owned by this closure — we must either return it as a reply
    // or drop it.  Both paths free the buffer.
    let request = pkt.data();

    if request == b"HELLO" {
        let mut reply = Packet::get(5)?;
        reply.write(b"HI!").ok()?;
        Some(reply) // reply sent; original pkt freed when closure returns
    } else if request == b"GET data" {
        let mut reply = Packet::get(16)?;
        reply.write(b"data payload").ok()?;
        Some(reply)
    } else {
        None // unknown command — pkt freed automatically, no reply sent
    }
})?;

server.run(libcsp::MAX_TIMEOUT); // blocks; run in a dedicated thread
```

### 5.5 Large Payload Transfer (SFP)

CSP's Simple Fragmentation Protocol (SFP) lets you send payloads larger than a single packet MTU. The sender fragments the data automatically; the receiver reassembles it into a single `Vec<u8>`. Use SFP whenever your payload is bigger than your packet buffer size (typically 128–256 bytes on embedded links).

```rust
use libcsp::{Priority, conn_opts};

const SFP_PORT: u8 = 11;
const DST_NODE: u16 = 2;

// Sender
if let Some(conn) = node.connect(
    Priority::Norm,
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

let mut sock = Socket::new(socket_opts::NONE);
sock.bind(SFP_PORT).unwrap();

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

**Tip:** Combine with RDP (`conn_opts::RDP`) to get reliable, ordered fragment delivery with retransmission.

---

## 6. High-Level Networking

### The `Port` Enum
Avoid magic numbers by using the `Port` enum for standard services and custom ports.
```rust
use libcsp::Port;

let port_ping   = Port::Ping;
let port_custom = Port::Custom(10);
```

### Server-Side: The `Dispatcher`

The `Dispatcher` is a single-socket, single-thread server.  Internally it holds **one `Socket`** bound to all registered port numbers and runs a single `accept` loop.  You do **not** need one thread per port — one thread handles all registered ports.

```text
One socket → bound to ports [1, 3, 5, 6, 10, 11]
One accept loop → dispatches by destination port
```

There are two ways to register a port:

| Method | Effect |
|--------|--------|
| `server.register(port, closure)` | Your closure handles every incoming packet on that port. Return `Some(reply_pkt)` to respond, `None` to silently consume. |
| `server.bind_service(port)` | Binds the port for listening but delegates packet handling to libcsp's built-in `csp_service_handler`. Use this for standard protocol ports (Ping, MemFree, Uptime, BufFree, Reboot, Cmp). |

**Standard services and their client-side calls:**

| `bind_service(…)` | Enables remote call |
|-------------------|---------------------|
| `Port::Ping` | `node.ping(target, …)` |
| `Port::MemFree` | `node.memfree(target, …)` |
| `Port::Uptime` | `node.uptime(target, …)` |
| `Port::BufFree` | `node.buf_free(target, …)` |
| `Port::Reboot` | `node.reboot(target)` |
| `Port::Cmp` | `node.ident(…)`, `node.peek(…)`, `node.poke(…)` |

The server must have called `bind_service` for the corresponding port before a remote client can query it.

```rust
use libcsp::{Dispatcher, Port, MAX_TIMEOUT};
use std::thread;

let mut server = Dispatcher::new();

// Standard built-in service handlers
server.bind_service(Port::Ping)?;    // enables node.ping(this_addr, …) from remotes
server.bind_service(Port::MemFree)?; // enables node.memfree(this_addr, …) from remotes
server.bind_service(Port::Uptime)?;  // enables node.uptime(this_addr, …) from remotes
server.bind_service(Port::Cmp)?;     // enables node.ident/peek/poke from remotes

// Custom port logic — one thread handles all of these
server.register(Port::Custom(10), |_conn, pkt| {
    println!("Port 10: {} bytes", pkt.length());
    Some(pkt) // echo back; pkt ownership returned to CSP for sending
})?;

server.register(Port::Custom(11), |_conn, pkt| {
    println!("Port 11 data: {:?}", pkt.data());
    None // no reply; pkt freed automatically when closure returns
})?;

// Run in a dedicated thread — blocks until the socket is closed
thread::spawn(move || server.run(MAX_TIMEOUT));
```

### CMP: Peer Inspection (Ident, Peek, Poke)

Safe wrappers for the CSP Management Protocol (CMP) return high-level Rust
types. PEEK/POKE are handled directly by libcsp's built-in CMP service
handler, which reads and writes the target node's raw memory at the given
address. The **remote node must have `Port::Cmp` registered** via
`server.bind_service(Port::Cmp)` (see above).

```rust
// Get remote node identification (hostname, model, revision, build date/time)
let info = node.ident(remote_addr, 1000)?; // 1000 ms reply timeout
println!("Remote: {} running {}", info.hostname, info.model);

// Read raw memory from the remote node (peek)
// address: target memory address, len: bytes to read (max CSP_CMP_PEEK_MAX_LEN)
let bytes = node.peek(remote_addr, 0x2000_0000, 4, 1000)?;
println!("Memory at 0x2000_0000: {:02x?}", bytes);

// Write raw memory on the remote node (poke)
// Use with extreme care — writing to the wrong address will crash the target.
node.poke(remote_addr, 0x2000_0000, &[0xDE, 0xAD, 0xBE, 0xEF], 1000)?;
```

On embedded targets `peek`/`poke` act on real hardware memory; use them only
for debugging or well-understood register maps.

---

## 7. Custom Interfaces (Transports)

Implement the `CspInterface` trait to bridge CSP to custom hardware (e.g., STM32 CAN via `embassy`).

```rust
use libcsp::{CspInterface, Packet, interface};

struct MyCanDriver { /* ... */ }

impl CspInterface for MyCanDriver {
    fn name(&self) -> &str { "MY_CAN" }

    fn nexthop(&mut self, via: u16, pkt: Packet, from_me: bool) {
        // `via` is the next-hop CSP address (65535 means "send direct").
        // `from_me` is true when this node generated the packet locally.
        //
        // 1. Hardware TX
        // self.hw.send(&pkt.data(), pkt.id());
        //
        // 2. pkt is dropped and freed here automatically.
        let _ = (via, from_me);
    }
}

// Registration returns an InterfaceHandle
let my_iface = MyCanDriver { /* ... */ };
let handle = interface::register(my_iface);
```

### The RX Flow (Pumping packets into CSP)

When receiving data from hardware, you must manually feed it into the CSP router.

```rust
use libcsp::Packet;

// 1. You receive data from your hardware
let raw_data = [0u8; 10];

// 2. Allocate a packet from the CSP pool
if let Some(mut pkt) = Packet::get(raw_data.len()) {
    // 3. Fill the packet header (csp_id_t: pri/flags/src/dst/dport/sport)
    //    and payload.
    let mut id = pkt.id();
    id.src   = 2;
    id.dst   = 1;
    id.sport = 20;
    id.dport = 10;
    pkt.set_id(id);
    pkt.write(&raw_data).unwrap();

    // 4. "Pump" it into the router.
    //    This transfers ownership to the CSP stack.
    handle.rx(pkt);
}
```

Internal mechanism: `handle.rx()` calls `csp_qfifo_write()`, which wakes up the background router task to process the packet.

### Routing through your interface

Once the interface is registered you can direct traffic through it via the
routing table. The compact-string format is the most ergonomic:

```rust
use libcsp::route;

// Send all traffic for addresses 2 and 3 out of MY_CAN
node.route_load("2 MY_CAN, 3 MY_CAN").unwrap();

// Or programmatically, using the raw interface pointer:
unsafe {
    route::set_raw(2, 0, handle.c_iface_ptr(), route::NO_VIA)?;
}

// Inspect the routing table:
route::iterate(|entry| {
    println!(
        "  {}/{} via {}",
        entry.address(),
        entry.netmask(),
        entry.via(),
    );
    true // keep iterating
});
```

---

## 8. Sniffing Traffic

Use the RAII `Sniffer` handle to enable promiscuous mode. It disables automatically when dropped.

```rust
use libcsp::promisc;

let sniffer = promisc::Sniffer::open(10).expect("Promisc failed");
while let Some(pkt) = sniffer.read(1000) {
    println!("Sniffed: {} -> {}", pkt.src_addr(), pkt.dst_addr());
}
```

---

## 9. Custom Arch and Time (RTOS/Bare-Metal)

In a `no_std` or custom RTOS environment (like `embassy` on STM32), libcsp
needs primitives for time, mutexes, queues and a few standard C string
helpers. Enable the `external-arch` feature and implement the [`CspArch`]
trait.

```rust
use libcsp::{export_arch, CspArch};
use core::ffi::c_void;

struct MyArch;

unsafe impl CspArch for MyArch {
    fn get_ms(&self) -> u32 {
        embassy_time::Instant::now().as_millis() as u32
    }
    fn get_s(&self) -> u32 {
        embassy_time::Instant::now().as_secs() as u32
    }

    fn bin_sem_create(&self) -> *mut c_void { /* ... */ core::ptr::null_mut() }
    fn bin_sem_remove(&self, _sem: *mut c_void) { /* ... */ }
    fn bin_sem_wait(&self, _sem: *mut c_void, _timeout: u32) -> bool { true }
    fn bin_sem_post(&self, _sem: *mut c_void) -> bool { true }

    fn mutex_create(&self) -> *mut c_void { /* ... */ core::ptr::null_mut() }
    fn mutex_remove(&self, _mutex: *mut c_void) { /* ... */ }
    fn mutex_lock(&self, _mutex: *mut c_void, _timeout: u32) -> bool { true }
    fn mutex_unlock(&self, _mutex: *mut c_void) -> bool { true }

    fn queue_create(&self, _len: usize, _item: usize) -> *mut c_void {
        core::ptr::null_mut()
    }
    fn queue_remove(&self, _q: *mut c_void) { /* ... */ }
    fn queue_enqueue(&self, _q: *mut c_void, _item: *const c_void, _to: u32) -> bool { true }
    fn queue_dequeue(&self, _q: *mut c_void, _item: *mut c_void, _to: u32) -> bool { true }
    fn queue_size(&self, _q: *mut c_void) -> usize { 0 }
}

// Export the symbols libcsp's C code links against.
export_arch!(MyArch, MyArch);
```

The `export_arch!` macro emits the `#[no_mangle]` C shims that libcsp
expects (`csp_get_ms`, `csp_mutex_*`, `csp_queue_*`, plus a handful of
standard C string functions such as `strncpy` and `strtok_r`).

When you manage the router yourself, call `node.route_work()` in your own
task instead of `route_start_task` — the default `thread_create` is a
no-op on bare-metal targets.

### Cross-Compilation Requirement
When building for an embedded target (e.g. `thumbv7em-none-eabihf`), the `cc` crate requires an appropriate cross-compiler (e.g. `arm-none-eabi-gcc`) to be available on your host system to compile the libcsp C core.

---

## 10. Summary of Ownership

| Action | Ownership |
|--------|-----------|
| `Packet::get()` | Caller owns the packet. |
| `node.sendto(pkt)` | CSP takes ownership; libcsp always frees the buffer. |
| `conn.send(pkt)` / `conn.send_prio(prio, pkt)` | CSP takes ownership; libcsp always frees the buffer. |
| `conn.read()` / `sniffer.read()` / `sock.recvfrom()` | Caller owns the returned packet. |
| `Dispatcher` handler | Closure takes ownership of `Packet`. Return `Some(pkt)` to send as reply. |
| `CspInterface::nexthop` | Trait method takes ownership of `Packet`. |
| `handle.rx(pkt)` | Ownership transferred to CSP router. |

## 11. Pattern Comparison

| Pattern | API | Overhead | Delivery |
|---------|-----|----------|----------|
| Fire-and-forget | `node.sendto()` | None (no connection slot) | Best-effort |
| Reliable | `node.connect(…, RDP)` + `conn.send()` | RDP handshake + ACKs | Guaranteed, ordered |
| Large payload | `node.connect()` + `conn.sfp_send()` | Fragmentation overhead | Best-effort |
| Large payload, reliable | `node.connect(…, RDP)` + `conn.sfp_send()` | RDP + fragmentation | Guaranteed, ordered |
| One-shot request/reply | `node.transaction()` | Connection per call | Best-effort |
| Multi-round request/reply | `node.connect()` + manual send/read | One connection | Best-effort |
| Per-send priority override | `conn.send_prio(prio, pkt)` | None | Best-effort / RDP |
