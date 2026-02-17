use libcsp::{CspConfig, Packet, Socket, Priority};
use std::thread;
use std::time::Duration;

fn main() {
    // 1. Initialise the CSP stack
    let node = CspConfig::new()
        .address(1)
        .hostname("loopback-test")
        .buffers(10, 256)
        .init()
        .expect("csp_init failed");

    // 2. Start the router task
    node.route_start_task(4096, 0).expect("router task failed");

    // 3. Add a loopback route
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

    // 4. Server thread
    let server_handle = thread::spawn(move || {
        let sock = Socket::new(0).expect("csp_socket failed");
        sock.bind(10).expect("bind failed");
        sock.listen(5).expect("listen failed");

        println!("Server: Listening on port 10...");
        if let Some(conn) = sock.accept(2000) {
            println!("Server: Accepted connection from {}!", conn.src_addr());
            if let Some(pkt) = conn.read(1000) {
                let data = pkt.data();
                println!("Server: Received {} bytes: {:?}", pkt.length(), data);
                assert_eq!(data, b"hello from Rust!");
                return;
            }
        }
        panic!("Server: Failed to receive packet");
    });

    // Give the server a moment to start
    thread::sleep(Duration::from_millis(100));

    // 5. Client
    println!("Client: Connecting to local node...");
    let conn = node
        .connect(Priority::Norm as u8, 1, 10, 1000, 0)
        .expect("csp_connect failed");

    let mut pkt = Packet::get(32).expect("no buffers");
    pkt.write(b"hello from Rust!").expect("write failed");

    println!("Client: Sending packet...");
    conn.send(pkt, 100).expect("send failed");

    server_handle.join().expect("server thread panicked");
    println!("Test passed!");
}
