//! Example: Basic client/server over the loopback interface.
//!
//! Demonstrates CSP initialisation, routing, server bind/listen/accept,
//! and a client connect/send — all within a single process.
//!
//! Run with: cargo run --example loopback

use libcsp::{CspConfig, Packet, Socket, Priority, socket_opts, conn_opts};
use std::thread;
use std::time::Duration;

fn main() {
    // 1. Initialise the CSP stack with address 1.
    let node = CspConfig::new()
        .address(1)
        .hostname("loopback-test")
        .buffers(10, 256)
        .init()
        .expect("csp_init failed");

    // 2. Start the background router task (spawns a POSIX thread).
    node.route_start_task(4096, 0).expect("router task failed");

    // 3. Route all traffic through the loopback interface.
    node.route_load("0/0 LOOP").expect("failed to load loopback route");

    // Verify iteration works
    let mut found_loop = false;
    libcsp::route::iterate(|addr, mask, entry| {
        println!("Route: {}/{} via {}", addr, mask, entry.via());
        if addr == 0 && mask == 0 {
            found_loop = true;
        }
        true
    });
    assert!(found_loop, "Loopback route not found in table");

    println!("CSP stack initialised, address: {}", node.address());

    // 4. Server thread — bind, listen, accept one connection, read one packet.
    let server_handle = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).expect("csp_socket failed");
        sock.bind(10).expect("bind failed");
        sock.listen(5).expect("listen failed");

        println!("Server: Listening on port 10...");
        if let Some(conn) = sock.accept(2000) {
            println!("Server: Accepted connection from node {}!", conn.src_addr());
            if let Some(pkt) = conn.read(1000) {
                let data = pkt.data();
                println!("Server: Received {} bytes: {:?}", pkt.length(), data);
                assert_eq!(data, b"hello from Rust!");
                // pkt is freed automatically here
                return;
            }
        }
        panic!("Server: Failed to receive packet");
    });

    // Give the server a moment to start listening.
    thread::sleep(Duration::from_millis(100));

    // 5. Client — connect, allocate a packet, write payload, send.
    println!("Client: Connecting to local node...");
    let conn = node
        .connect(Priority::Norm, 1, 10, 1000, conn_opts::NONE)
        .expect("csp_connect failed");

    let mut pkt = Packet::get(32).expect("no buffers");
    pkt.write(b"hello from Rust!").expect("write failed");

    println!("Client: Sending packet...");
    // send_discard: on failure the packet is freed and Err is returned.
    conn.send_discard(pkt, 100).expect("send failed");

    server_handle.join().expect("server thread panicked");
    println!("Test passed!");
}
