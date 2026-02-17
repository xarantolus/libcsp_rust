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

## 3. High-Level Networking

### The `Port` Enum
Avoid magic numbers by using the `Port` enum for standard services and custom ports.
```rust
use libcsp::Port;

let port_ping = Port::Ping;
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

## 4. Custom Interfaces (Transports)

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

## 5. Sniffing Traffic

Use the RAII `Sniffer` handle to enable promiscuous mode. It disables automatically when dropped.

```rust
use libcsp::promisc;

let sniffer = promisc::Sniffer::open(10).expect("Promisc failed");
while let Some(pkt) = sniffer.read(1000) {
    println!("Sniffed: {} -> {}", pkt.src_addr(), pkt.dst_addr());
}
```

## 6. Custom Arch and Time (RTOS/Bare-Metal)

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

### Providing OS Primitives
If you enable the `external-arch` feature, the library will not compile its own POSIX/FreeRTOS arch files. You must then provide implementation for:
*   **Queues**: `csp_queue_create`, `csp_queue_enqueue`, `csp_queue_dequeue`, etc.
*   **Semaphores**: `csp_bin_sem_create`, `csp_bin_sem_wait`, `csp_bin_sem_post`.
*   **Malloc**: `csp_malloc`, `csp_free` (can bridge to your Rust global allocator).
*   **System**: `csp_sys_memfree`, `csp_sys_reboot`, `csp_sys_shutdown`.

See `libcsp/include/csp/arch/` for the exact C signatures required.

## 7. Summary of Ownership

| Action | Ownership |
|--------|-----------|
| `Packet::get()` | Caller owns the packet. |
| `conn.send(pkt)` | If Success: CSP takes ownership. If Fail: Returned to caller in `Err`. |
| `conn.read()` / `sniffer.read()` | Caller owns the returned packet. |
| `Dispatcher` handler | Closure takes ownership of `Packet`. Return `Some(pkt)` to pass back to CSP for reply. |
| `CspInterface::nexthop` | Trait method takes ownership of `Packet`. |
| `handle.rx(pkt)` | Ownership transferred to CSP router. |
