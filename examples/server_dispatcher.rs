//! Example: Using the high-level Dispatcher for server-side logic.
//!
//! This demonstrates how to register callbacks for specific ports instead
//! of manual accept/read loops.

use libcsp::{CspConfig, Packet, Priority, Dispatcher, Port};
use std::thread;

fn main() -> libcsp::Result<()> {
    // 1. Initialise CSP
    let node = CspConfig::new()
        .address(1)
        .buffers(20, 256)
        .init()
        .expect("CSP init failed");

    node.route_start_task(4096, 0).unwrap();
    node.route_load("0/0 LOOP").unwrap();

    // 2. Create a Dispatcher
    let mut server = Dispatcher::new().expect("Failed to create dispatcher");

    // 3. Register standard services (Ping, etc.)
    server.bind_service(Port::Ping)?;
    server.bind_service(Port::Uptime)?;

    // 4. Register a custom echo service on port 10
    server.register(Port::Custom(10), |_conn, pkt| {
        println!("Echo: Got {} bytes, returning them.", pkt.length());
        // Return the same packet as a reply
        Some(pkt)
    })?;

    // 5. Register a data logger on port 11 (consumes packets, no reply)
    server.register(11, |_conn, pkt| {
        println!("Logger: Received data: {:?}", pkt.data());
        None // No reply
    })?;

    println!("Server started. Listening for Pings and Custom Port 10/11...");

    // Run the server in a background thread or main loop
    thread::spawn(move || {
        server.run(libcsp::MAX_TIMEOUT);
    });

    // --- Client part for demo ---
    thread::sleep(std::time::Duration::from_millis(100));

    // Send to port 10 (Echo)
    if let Some(conn) = node.connect(Priority::Norm as u8, 1, 10, 1000, 0) {
        let mut pkt = Packet::get(16).unwrap();
        pkt.write(b"Hello Dispatch!").unwrap();
        conn.send(pkt, 100).unwrap();
        
        if let Some(reply) = conn.read(500) {
            println!("Client: Got echo reply: {:?}", std::str::from_utf8(reply.data()));
        }
    }

    // Send to port 11 (Logger)
    if let Some(conn) = node.connect(Priority::Norm as u8, 1, 11, 1000, 0) {
        let mut pkt = Packet::get(16).unwrap();
        pkt.write(b"log this").unwrap();
        conn.send(pkt, 100).unwrap();
    }

    // Ping
    let res = node.ping(1, 1000, 100, 0);
    println!("Client: Ping local node: {} ms", res);

    thread::sleep(std::time::Duration::from_millis(500));
    Ok(())
}
