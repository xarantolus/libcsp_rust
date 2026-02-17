# libcsp Rust Port — Usage Guide

This guide explains how to use the `libcsp` Rust bindings, focusing on memory safety, ownership, and idiomatic patterns.

---

## 1. Initialisation

CSP is a global singleton. You must initialise it once at the start of your application using the `CspConfig` builder.

```rust
use libcsp::CspConfig;

fn main() -> libcsp::Result<()> {
    let node = CspConfig::new()
        .address(1)            // Set local CSP address (0-31)
        .hostname("my-sat")
        .buffers(20, 256)      // 20 buffers of 256 bytes each
        .init()?;              // Returns a CspNode handle

    // The CspNode handle keeps the CSP runtime alive.
    // When it is dropped, csp_free_resources() is called.
    
    // Start the background router task (optional but recommended)
    node.route_start_task(4096, 0)?;

    Ok(())
}
```

## 2. Packet Management (The `Packet` Struct)

The `Packet` struct is an RAII wrapper around `csp_packet_t`. 

### Allocation and Ownership
*   **Get:** `Packet::get(size)` allocates from the CSP pool.
*   **Drop:** When a `Packet` goes out of scope, it is **automatically freed** back to the CSP pool via `csp_buffer_free`.
*   **Transfer:** When you `send` a packet, ownership is transferred to the CSP stack.

```rust
use libcsp::Packet;

// Allocate
if let Some(mut pkt) = Packet::get(32) {
    // Write data
    pkt.write(b"hello world").unwrap();
    
    // The packet will be freed here if not moved elsewhere.
}
```

### Writing Data
```rust
pkt.write(b"data").unwrap(); // Sets length automatically
// OR manually:
let buf = pkt.data_buf_mut();
buf[..4].copy_from_slice(b"data");
pkt.set_length(4);
```

## 3. Client/Server Communication

### Sending (Client)
When sending, if `send` returns `Ok(())`, the packet is consumed. If it returns `Err`, you get the packet back.

```rust
match conn.send(pkt, 100) {
    Ok(()) => println!("Sent!"),
    Err((err, pkt)) => {
        eprintln!("Failed: {}", err);
        // pkt is still here, you can retry or let it drop (free)
    }
}
```

### Receiving (Server)
`Socket::accept` returns a `Connection`. `Connection::read` returns an `Option<Packet>`.

```rust
let sock = libcsp::Socket::new(libcsp::socket_opts::NONE).unwrap();
sock.bind(10).unwrap();
sock.listen(5).unwrap();

while let Some(conn) = sock.accept(libcsp::MAX_TIMEOUT) {
    while let Some(pkt) = conn.read(100) {
        println!("Received: {:?}", pkt.data());
        // pkt is freed here
    }
    // conn is closed here
}
```

## 4. Custom Interfaces (Transports)

To implement a custom transport (e.g. for an STM32/Embassy CAN driver):

1.  **Implement `nexthop`**: A C-compatible callback that handles outgoing packets.
2.  **Register Interface**: Add your `csp_iface_t` to the `iflist`.
3.  **Feed RX**: Use `sys::csp_qfifo_write` to inject received packets into the router.

### Lifecycle of a Packet in `nexthop`
In libcsp, the `nexthop` function is responsible for freeing the packet. In Rust, you should:
1.  Take ownership via `Packet::from_raw(packet)`.
2.  Do your hardware TX.
3.  Let the `Packet` drop (which frees it).

```rust
unsafe extern "C" fn my_nexthop(route: *const sys::csp_route_t, packet: *mut sys::csp_packet_t) -> i32 {
    let pkt = Packet::from_raw(packet); // Take ownership
    // hardware_tx(pkt.data());
    0 // Packet drops and is freed here
}
```

## 5. `no_std` Usage

For `no_std` targets (like `embassy` on STM32):
*   Disable default features: `default-features = false`.
*   Ensure an allocator is available (required for `CspConfig`'s CStrings).
*   Use `node.route_work(0)` in your main loop if you aren't using threads.

```toml
[dependencies]
libcsp = { version = "1.6", default-features = false, features = ["rdp", "crc32"] }
```

## 6. Summary of Ownership

| Action | Ownership |
|--------|-----------|
| `Packet::get()` | Caller owns the packet. |
| `conn.send(pkt)` | If Success: CSP owns it. If Fail: Caller owns it. |
| `conn.read()` | Caller owns the returned packet. |
| `sock.recvfrom()` | Caller owns the returned packet. |
| `Packet::from_raw(ptr)` | Caller takes ownership of raw pointer. |
| `pkt.into_raw()` | Caller loses ownership; must free manually or pass to C. |
