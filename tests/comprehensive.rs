use libcsp::{conn_opts, ports, socket_opts, CspConfig, CspNode, Packet, Priority, Socket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread;

static NODE: OnceLock<CspNode> = OnceLock::new();
static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn ensure_init() -> CspNode {
    NODE.get_or_init(|| {
        let node = CspConfig::new()
            .address(1)
            .buffers(50, 256)
            .init()
            .expect("init failed");
        node.route_start_task(4096, 0).unwrap();
        node.route_load("0/0 LOOP").unwrap();
        node
    })
    .clone()
}

fn lock_csp() -> std::sync::MutexGuard<'static, ()> {
    // Handle poison error gracefully - if a test panicked, we still want other tests to run
    TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn test_rdp_basic() {
    let _lock = lock_csp();
    let node = ensure_init();

    let server_received = std::sync::Arc::new(AtomicBool::new(false));
    let server_received_clone = server_received.clone();

    // Use channel to signal when server is ready
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let sock = Socket::new(socket_opts::RDP_REQ).expect("failed to create RDP socket");
        sock.bind(15).expect("Failed to bind");
        sock.listen(5).expect("Failed to listen");

        // Signal ready
        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(2000) {
            assert!(conn.is_rdp(), "Connection should have RDP flag set");
            if let Some(pkt) = conn.read(1000) {
                assert_eq!(pkt.data(), b"rdp-test", "Server received unexpected data");
                assert_eq!(pkt.length(), 8, "Packet length should be 8 bytes");
                server_received_clone.store(true, Ordering::SeqCst);
            } else {
                panic!("Server failed to read RDP packet");
            }
        } else {
            panic!("Server failed to accept RDP connection");
        }
    });

    // Wait for server to be ready
    ready_rx.recv().expect("Server failed to start");

    // Safe connect using node
    let conn = node
        .connect(Priority::Norm, 1, 15, 1000, conn_opts::RDP)
        .expect("RDP connect failed");

    let mut pkt = Packet::get(8).expect("Failed to get packet");
    pkt.write(b"rdp-test").expect("Failed to write packet");
    conn.send(pkt, 1000).expect("RDP send failed");

    server_thread.join().expect("Server thread panicked");
    assert!(
        server_received.load(Ordering::SeqCst),
        "Server did not receive RDP packet"
    );
}

#[test]
fn test_sfp_large_transfer() {
    let _lock = lock_csp();
    let node = ensure_init();

    let data_to_send = vec![0xAAu8; 1000]; // 1000 bytes, larger than MTU (256)
    let data_to_send_clone = data_to_send.clone();

    // Use channel to signal when server is ready
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).expect("Failed to create socket");
        sock.bind(16).expect("Failed to bind");
        sock.listen(5).expect("Failed to listen");

        // Signal ready
        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(5000) {
            let received = conn.sfp_recv(5000).expect("SFP receive failed");
            assert_eq!(
                received.len(),
                data_to_send_clone.len(),
                "Received data length mismatch"
            );
            assert_eq!(
                received, data_to_send_clone,
                "Received data content mismatch"
            );
        } else {
            panic!("Server failed to accept SFP connection");
        }
    });

    // Wait for server to be ready
    ready_rx.recv().expect("Server failed to start");

    let conn = node
        .connect(Priority::Norm, 1, 16, 1000, conn_opts::NONE)
        .expect("SFP connect failed");

    conn.sfp_send(&data_to_send, 200, 5000)
        .expect("SFP send failed");

    server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_transaction_oneshot() {
    let _lock = lock_csp();
    let node = ensure_init();

    // Use channel to signal when server is ready
    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).expect("Failed to create socket");
        sock.bind(17).expect("Failed to bind");
        sock.listen(5).expect("Failed to listen");

        // Signal ready
        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(2000) {
            if let Some(mut pkt) = conn.read(1000) {
                assert_eq!(pkt.data(), b"request", "Server received unexpected request");
                assert_eq!(pkt.length(), 7, "Request packet length should be 7 bytes");
                pkt.write(b"reply").expect("Failed to write reply");
                conn.send(pkt, 1000).expect("Failed to send reply");
            } else {
                panic!("Server failed to read transaction request");
            }
        } else {
            panic!("Server failed to accept transaction connection");
        }
    });

    // Wait for server to be ready
    ready_rx.recv().expect("Server failed to start");

    let out_buf = b"request".to_vec();
    let mut in_buf = vec![0u8; 10];

    let ret = node
        .transaction(Priority::Norm, 1, 17, 1000, &out_buf, &mut in_buf, 5, 0)
        .expect("Transaction failed");

    assert_eq!(ret, 5, "Transaction should have returned 5 bytes");
    assert_eq!(
        &in_buf[0..5],
        b"reply",
        "Transaction reply content mismatch"
    );

    server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_cmp_ident() {
    let _lock = lock_csp();
    let node = ensure_init();

    // Use channel to signal when service is ready
    let (ready_tx, ready_rx) = mpsc::channel();

    let service_thread = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).expect("Failed to create socket");
        sock.bind(ports::CMP).expect("Failed to bind CMP port");
        sock.listen(5).expect("Failed to listen");

        // Signal ready
        ready_tx.send(()).expect("Failed to signal ready");

        for _ in 0..3 {
            if let Some(conn) = sock.accept(2000) {
                if let Some(pkt) = conn.read(1000) {
                    // Safe service handler
                    conn.handle_service(pkt);
                }
            }
        }
    });

    // Wait for service to be ready
    ready_rx.recv().expect("Service thread failed to start");

    let out_buf = vec![0u8, 1u8]; // type = 0 (REQUEST), code = 1 (IDENT)
    let mut in_buf = vec![0u8; 256];

    let ret = node
        .transaction(
            Priority::Norm,
            1,
            ports::CMP,
            1000,
            &out_buf,
            &mut in_buf,
            -1,
            0,
        )
        .expect("CMP transaction failed");

    assert!(
        ret > 0,
        "CMP transaction should return positive bytes received, got {}",
        ret
    );
    assert!(
        ret <= 256,
        "CMP transaction should not exceed buffer size, got {}",
        ret
    );

    service_thread.join().expect("Service thread panicked");
}

#[test]
fn test_route_load() {
    let _lock = lock_csp();
    let node = ensure_init();

    // Load a valid route entry for a specific address
    let res = node.route_load("10/5 LOOP");
    assert!(res.is_ok(), "Failed to load valid route: {:?}", res.err());

    // Verify loading same route again doesn't fail (updates/overwrites)
    let res2 = node.route_load("10/5 LOOP");
    assert!(
        res2.is_ok(),
        "Failed to reload same route: {:?}",
        res2.err()
    );

    // Test loading a compatible non-overlapping address
    // Note: libcsp's static routing table has limitations - we can't load arbitrary routes
    // The format is "address/netmask interface" where interface can be LOOP, I2C, CAN, etc.
    let res3 = node.route_load("11/5 LOOP");
    assert!(
        res3.is_ok(),
        "Failed to load second route: {:?}",
        res3.err()
    );

    // Test error case: invalid format should fail
    let res_invalid = node.route_load("invalid");
    assert!(res_invalid.is_err(), "Should reject invalid route format");
}

#[test]
fn test_node_ping() {
    let _lock = lock_csp();
    let node = ensure_init();

    // Use channel to signal when service is ready
    let (ready_tx, ready_rx) = mpsc::channel();

    let service_thread = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).expect("Failed to create socket");
        sock.bind(ports::PING).expect("Failed to bind PING port");
        sock.listen(5).expect("Failed to listen");

        // Signal ready
        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(2000) {
            if let Some(pkt) = conn.read(1000) {
                conn.handle_service(pkt);
            } else {
                panic!("Service failed to read ping packet");
            }
        } else {
            panic!("Service failed to accept ping connection");
        }
    });

    // Wait for service to be ready
    ready_rx.recv().expect("Service thread failed to start");

    // Safe ping call
    let res = node.ping(1, 1000, 10, 0).expect("Ping failed");

    // Validate ping result
    assert!(
        res < 1000,
        "Ping RTT should be less than timeout (1000ms), got {} ms",
        res
    );

    service_thread.join().expect("Service thread panicked");
}
