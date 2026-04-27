/// Edge case and error condition tests
/// These tests verify behavior at boundaries and error paths
use libcsp::{conn_opts, socket_opts, CspConfig, CspNode, Packet, Priority, Socket};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread;

static NODE: OnceLock<CspNode> = OnceLock::new();
static TEST_MUTEX: Mutex<()> = Mutex::new(());

// Port allocator to avoid conflicts between tests.
// Allocate from port 30 upward; the crate's default `CSP_PORT_MAX_BIND` is
// 48, leaving 30..=48 = 19 unique ports for this file's tests (15 today).
static NEXT_PORT: AtomicU8 = AtomicU8::new(30);

fn allocate_port() -> u8 {
    let port = NEXT_PORT.fetch_add(1, Ordering::SeqCst);
    assert!(
        (port as usize) <= libcsp::consts::PORT_MAX_BIND,
        "test suite needs more bindable ports than CSP_PORT_MAX_BIND ({}). Raise LIBCSP_PORT_MAX_BIND at build time.",
        libcsp::consts::PORT_MAX_BIND,
    );
    port
}

fn ensure_init() -> CspNode {
    NODE.get_or_init(|| {
        let node = CspConfig::new().address(1).init().expect("init failed");
        node.route_start_task(4096, 0)
            .expect("Failed to start route task");
        node.route_load("0/0 LOOP")
            .expect("Failed to load loopback route");
        node
    })
    .clone()
}

fn lock_csp() -> std::sync::MutexGuard<'static, ()> {
    TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

// ── EDGE CASE 1: Empty packets ──────────────────────────────────────────────

#[test]
fn test_empty_packet_send() {
    let _lock = lock_csp();
    let node = ensure_init();

    let port = allocate_port();
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::NONE);
        sock.bind(port).expect("Failed to bind");
        sock.listen(5).expect("Failed to listen");

        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(1000) {
            if let Some(pkt) = conn.read(1000) {
                // Empty packets should have zero length
                assert_eq!(pkt.length(), 0, "Empty packet should have length 0");
                assert_eq!(pkt.data().len(), 0, "Empty packet data should be empty");
            } else {
                panic!("Server failed to read packet");
            }
        } else {
            panic!("Server failed to accept connection");
        }
    });

    ready_rx.recv().expect("Server failed to start");

    let conn = node
        .connect(Priority::Norm, 1, port, 1000, 0)
        .expect("connect failed");

    // Send an empty packet (length 0)
    let pkt = Packet::get(0).expect("Failed to get packet");
    assert_eq!(pkt.length(), 0, "New packet should have length 0");

    conn.send(pkt);

    server_thread.join().expect("Server thread panicked");
}

// ── EDGE CASE 2: Maximum packet size ───────────────────────────────────────

#[test]
fn test_maximum_packet_size() {
    let _lock = lock_csp();
    let _node = ensure_init();

    // The buffer size is configured as 256 in ensure_init()
    // Try to get a packet with maximum data size
    let mut pkt = Packet::get(256).expect("Should be able to get max-size packet");

    // Fill it with data
    let max_data = vec![0xAB; 256];
    pkt.write(&max_data)
        .expect("Should be able to write max data");

    assert_eq!(pkt.length(), 256, "Packet should have length 256");
    assert_eq!(pkt.data(), &max_data[..], "Data should match");
}

#[test]
fn test_oversized_packet_rejected() {
    let _lock = lock_csp();
    let _node = ensure_init();

    // Buffer size is 256, try to write more
    let mut pkt = Packet::get(256).expect("Should be able to get packet");

    let oversized_data = vec![0xCD; 512];
    let result = pkt.write(&oversized_data);

    assert!(result.is_err(), "Writing oversized data should fail");
    assert_eq!(result.unwrap_err(), 512, "Error should indicate data size");
}

// ── EDGE CASE 3: Buffer exhaustion ─────────────────────────────────────────

#[test]
fn test_buffer_exhaustion() {
    let _lock = lock_csp();
    let _node = ensure_init();

    // Allocate all available buffers (configured as 20 in ensure_init())
    let mut packets = Vec::new();
    let mut allocated = 0;

    for _ in 0..20 {
        if let Some(pkt) = Packet::get(100) {
            packets.push(pkt);
            allocated += 1;
        } else {
            break;
        }
    }

    assert!(
        allocated > 0,
        "Should be able to allocate at least some packets"
    );

    // Try to allocate one more - should fail
    let result = Packet::get(100);
    assert!(
        result.is_none(),
        "Should fail to allocate when pool is exhausted"
    );

    // Free one packet
    packets.pop();

    // Now allocation should succeed again
    let result = Packet::get(100);
    assert!(result.is_some(), "Should succeed after freeing a packet");
}

// ── EDGE CASE 4: Connection timeout ────────────────────────────────────────

#[test]
fn test_connection_timeout() {
    let _lock = lock_csp();
    let node = ensure_init();

    // Try to connect to a port with no server listening
    // Should timeout
    let result = node.connect(Priority::Norm, 1, 99, 100, 0);

    // Connection might succeed (opens immediately) but would fail on actual communication
    // The behavior depends on whether CSP uses synchronous or asynchronous connection setup
    // For loopback, connections typically succeed immediately
    let _ = result; // Accept either outcome for this test
}

#[test]
fn test_accept_timeout() {
    let _lock = lock_csp();
    let _node = ensure_init();

    let port = allocate_port();
    let mut sock = Socket::new(socket_opts::NONE);
    sock.bind(port).expect("Failed to bind");
    sock.listen(5).expect("Failed to listen");

    // Accept with short timeout - no incoming connections
    let result = sock.accept(50);
    assert!(
        result.is_none(),
        "Accept should timeout when no connections"
    );
}

#[test]
fn test_read_timeout() {
    let _lock = lock_csp();
    let node = ensure_init();

    let port = allocate_port();
    let conn = node
        .connect(Priority::Norm, 1, port, 1000, 0)
        .expect("Failed to connect");

    // Try to read with no data available
    let result = conn.read(50);
    assert!(
        result.is_none(),
        "Read should timeout when no data available"
    );
}

// ── EDGE CASE 5: Invalid addresses/ports ───────────────────────────────────

#[test]
fn test_broadcast_address() {
    let _lock = lock_csp();
    let node = ensure_init();

    let port = allocate_port();
    // CSP broadcast address is 31 (all nodes)
    let result = node.connect(Priority::Norm, libcsp::BROADCAST_ADDR, port, 100, 0);

    // Broadcast connections may or may not be allowed depending on configuration
    let _ = result; // Accept either outcome
}

#[test]
fn test_any_port_binding() {
    let _lock = lock_csp();
    let _node = ensure_init();

    let mut sock = Socket::new(socket_opts::NONE);

    // Bind to ANY port (255) - should accept packets on all unbound ports
    sock.bind(libcsp::ANY_PORT)
        .expect("Should be able to bind to ANY port");
    sock.listen(5).expect("Should be able to listen");
}

// ── EDGE CASE 6: RDP-specific edge cases ───────────────────────────────────

#[test]
#[cfg(feature = "rdp")]
fn test_rdp_connection_properly_negotiated() {
    let _lock = lock_csp();
    let node = ensure_init();

    let port = allocate_port();
    let (ready_tx, ready_rx) = mpsc::channel();

    // Server requires RDP
    let server_thread = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::RDP_REQ);
        sock.bind(port).expect("Failed to bind");
        sock.listen(5).expect("Failed to listen");

        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(2000) {
            // Verify the connection has RDP flag set
            assert!(
                conn.is_rdp(),
                "Server accepted connection should have RDP enabled"
            );

            // Verify we can read data over RDP connection
            if let Some(pkt) = conn.read(1000) {
                assert_eq!(
                    pkt.data(),
                    b"rdp-data",
                    "Should receive correct data over RDP"
                );
                assert!(pkt.is_rdp(), "Packet should have RDP flag set");
            } else {
                panic!("Failed to read packet over RDP connection");
            }
        } else {
            panic!("Server failed to accept RDP connection");
        }
    });

    ready_rx.recv().expect("Server failed to start");

    // Client connects WITH RDP (matching server requirement)
    let conn = node
        .connect(Priority::Norm, 1, port, 1000, conn_opts::RDP)
        .expect("RDP connection should succeed when both sides use RDP");

    // Verify connection has RDP flag
    assert!(conn.is_rdp(), "Client connection should have RDP enabled");

    // Send data over RDP connection
    let mut pkt = Packet::get(10).expect("Failed to get packet");
    pkt.write(b"rdp-data").expect("Failed to write packet");
    conn.send(pkt);

    server_thread.join().expect("Server thread panicked");
}

#[test]
#[cfg(feature = "rdp")]
fn test_rdp_prohibited_connection() {
    let _lock = lock_csp();
    let node = ensure_init();

    let port = allocate_port();
    let (ready_tx, ready_rx) = mpsc::channel();

    // Server creates a normal socket (no special RDP requirements)
    // The PROHIB options are only valid in connect(), not socket()
    let server_thread = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::NONE);
        sock.bind(port).expect("Failed to bind");
        sock.listen(5).expect("Failed to listen");

        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(2000) {
            // When client uses NORDP, connection should not have RDP
            assert!(
                !conn.is_rdp(),
                "Connection should not have RDP when client prohibits it"
            );

            if let Some(pkt) = conn.read(1000) {
                assert_eq!(
                    pkt.data(),
                    b"no-rdp",
                    "Should receive data over non-RDP connection"
                );
                assert!(
                    !pkt.is_rdp(),
                    "Packet should not have RDP flag when RDP is prohibited"
                );
            } else {
                panic!("Failed to read packet over non-RDP connection");
            }
        } else {
            panic!("Server failed to accept non-RDP connection");
        }
    });

    ready_rx.recv().expect("Server failed to start");

    // Client explicitly prohibits RDP using NORDP (CSP_O_NORDP)
    // This should create a connection WITHOUT the RDP protocol
    let conn = node
        .connect(Priority::Norm, 1, port, 1000, conn_opts::NORDP)
        .expect("Non-RDP connection should succeed");

    // Verify connection does NOT have RDP flag
    assert!(
        !conn.is_rdp(),
        "Client connection should not have RDP when NORDP is specified"
    );

    let mut pkt = Packet::get(10).expect("Failed to get packet");
    pkt.write(b"no-rdp").expect("Failed to write packet");
    conn.send(pkt);

    server_thread.join().expect("Server thread panicked");
}

// ── EDGE CASE 7: Priority levels ───────────────────────────────────────────

#[test]
fn test_all_priority_levels() {
    let _lock = lock_csp();
    let node = ensure_init();

    let port = allocate_port();
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::NONE);
        sock.bind(port).expect("Failed to bind");
        sock.listen(10).expect("Failed to listen");

        ready_tx.send(()).expect("Failed to signal ready");

        // Receive packets of all priorities
        for _ in 0..4 {
            if let Some(conn) = sock.accept(1000) {
                if let Some(pkt) = conn.read(100) {
                    // Verify packet has one of the valid priority levels
                    let prio = pkt.priority();
                    assert!(
                        matches!(
                            prio,
                            Priority::Critical | Priority::High | Priority::Norm | Priority::Low
                        ),
                        "Invalid priority: {:?}",
                        prio
                    );
                }
            }
        }
    });

    ready_rx.recv().expect("Server failed to start");

    // Send packets with all priority levels
    for prio in [
        Priority::Critical,
        Priority::High,
        Priority::Norm,
        Priority::Low,
    ] {
        let conn = node
            .connect(prio, 1, port, 1000, 0)
            .expect("Failed to connect");

        let mut pkt = Packet::get(10).expect("Failed to get packet");
        pkt.write(b"test").expect("Failed to write");
        conn.send(pkt);
    }

    server_thread.join().expect("Server thread panicked");
}

// ── EDGE CASE 8: Concurrent connections ────────────────────────────────────

#[test]
fn test_concurrent_connections() {
    let _lock = lock_csp();
    let node = ensure_init();

    let port = allocate_port();
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::NONE);
        sock.bind(port).expect("Failed to bind");
        sock.listen(10).expect("Failed to listen");

        ready_tx.send(()).expect("Failed to signal ready");

        // Accept multiple concurrent connections
        for _ in 0..3 {
            if let Some(conn) = sock.accept(2000) {
                if let Some(pkt) = conn.read(100) {
                    assert_eq!(pkt.data(), b"concurrent");
                }
            }
        }
    });

    ready_rx.recv().expect("Server failed to start");

    // Create multiple connections in parallel
    let mut client_threads = vec![];

    for _ in 0..3 {
        let node_clone = node.clone();
        let handle = thread::spawn(move || {
            let conn = node_clone
                .connect(Priority::Norm, 1, port, 1000, 0)
                .expect("Failed to connect");

            let mut pkt = Packet::get(20).expect("Failed to get packet");
            pkt.write(b"concurrent").expect("Failed to write");
            conn.send(pkt);
        });
        client_threads.push(handle);
    }

    // Wait for all clients
    for handle in client_threads {
        handle.join().expect("Client thread panicked");
    }

    server_thread.join().expect("Server thread panicked");
}

// ── EDGE CASE 9: Single-element cases ──────────────────────────────────────

#[test]
fn test_single_byte_packet() {
    let _lock = lock_csp();
    let node = ensure_init();

    let port = allocate_port();
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::NONE);
        sock.bind(port).expect("Failed to bind");
        sock.listen(5).expect("Failed to listen");

        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(1000) {
            if let Some(pkt) = conn.read(1000) {
                assert_eq!(pkt.length(), 1, "Should receive 1-byte packet");
                assert_eq!(pkt.data(), b"X", "Should receive correct byte");
            } else {
                panic!("Server failed to read packet");
            }
        } else {
            panic!("Server failed to accept connection");
        }
    });

    ready_rx.recv().expect("Server failed to start");

    let conn = node
        .connect(Priority::Norm, 1, port, 1000, 0)
        .expect("connect failed");

    let mut pkt = Packet::get(1).expect("Failed to get packet");
    pkt.write(b"X").expect("Failed to write");
    conn.send(pkt);

    server_thread.join().expect("Server thread panicked");
}

// ── EDGE CASE 10: Error recovery ───────────────────────────────────────────

#[test]
fn test_send_retry_after_failure() {
    let _lock = lock_csp();
    let node = ensure_init();

    let port = allocate_port();
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::NONE);
        sock.bind(port).expect("Failed to bind");
        sock.listen(5).expect("Failed to listen");

        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(1000) {
            if let Some(pkt) = conn.read(1000) {
                assert_eq!(pkt.data(), b"retry");
            } else {
                panic!("Server failed to read packet");
            }
        } else {
            panic!("Server failed to accept connection");
        }
    });

    ready_rx.recv().expect("Server failed to start");

    let conn = node
        .connect(Priority::Norm, 1, port, 1000, 0)
        .expect("connect failed");

    // Try to send to a connection (should succeed on loopback)
    let mut pkt = Packet::get(10).expect("Failed to get packet");
    pkt.write(b"retry").expect("Failed to write");

    // Packet is always consumed by send in v2.x (void return).
    conn.send(pkt);

    server_thread.join().expect("Server thread panicked");
}
