use libcsp::{CspConfig, Packet, Socket, Priority, socket_opts, CspNode};
use std::thread;
use std::sync::{OnceLock, Mutex, mpsc};
use std::sync::atomic::{AtomicUsize, Ordering};

static NODE: OnceLock<CspNode> = OnceLock::new();
static TEST_MUTEX: Mutex<()> = Mutex::new(());
static SERVER_RECEIVED: AtomicUsize = AtomicUsize::new(0);

fn ensure_init() -> CspNode {
    NODE.get_or_init(|| {
        let node = CspConfig::new()
            .address(1)
            .buffers(20, 256)
            .init()
            .expect("init failed");
        node.route_start_task(4096, 0).unwrap();
        node.route_load("0/0 LOOP").unwrap();
        node
    }).clone()
}

fn lock_csp() -> std::sync::MutexGuard<'static, ()> {
    // Handle poison error gracefully - if a test panicked, we still want other tests to run
    TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn test_csp_server_client_loopback() {
    let _lock = lock_csp();
    let node = ensure_init();
    SERVER_RECEIVED.store(0, Ordering::SeqCst);

    const MY_SERVER_PORT: u8 = 10;
    const SERVER_ADDR: u8 = 1;

    // Use a channel to signal when server is ready
    let (ready_tx, ready_rx) = mpsc::channel();

    // Start Server
    let server_handle = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).expect("csp_socket failed");
        sock.bind(MY_SERVER_PORT).expect("csp_bind failed");
        sock.listen(10).expect("csp_listen failed");

        // Signal that server is ready
        ready_tx.send(()).expect("Failed to signal ready");

        // Process 5 packets then exit
        for _ in 0..5 {
            if let Some(conn) = sock.accept(2000) {
                while let Some(pkt) = conn.read(100) {
                    if conn.dst_port() == MY_SERVER_PORT {
                        let data = pkt.data();
                        if data.starts_with(b"Hello World") {
                            SERVER_RECEIVED.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                }
            }
        }
    });

    // Wait for server to be ready instead of sleeping
    ready_rx.recv().expect("Server failed to start");

    // Start Client logic
    for count in 0..5 {
        let conn = node.connect(Priority::Norm, SERVER_ADDR, MY_SERVER_PORT, 1000, 0)
            .expect("Connection failed");

        let mut pkt = Packet::get(100).expect("Failed to get buffer");
        let msg = format!("Hello World ({})", count);
        pkt.write(msg.as_bytes()).expect("Failed to write packet");

        conn.send(pkt, 1000).expect("Send failed");
    }

    server_handle.join().expect("Server thread panicked");

    assert_eq!(SERVER_RECEIVED.load(Ordering::SeqCst), 5, "Server should have received exactly 5 packets");
}

#[test]
fn test_csp_ping() {
    let _lock = lock_csp();
    let node = ensure_init();

    // Use a channel to signal when service is ready
    let (ready_tx, ready_rx) = mpsc::channel();

    // Start a thread to handle pings (CSP service port is 1)
    let service_handle = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).expect("Failed to create socket");
        sock.bind(libcsp::ports::PING).expect("Failed to bind ping port");
        sock.listen(5).expect("Failed to listen");

        // Signal that service is ready
        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(2000) {
            if let Some(pkt) = conn.read(100) {
                conn.handle_service(pkt);
            }
        }
    });

    // Wait for service to be ready instead of sleeping
    ready_rx.recv().expect("Service thread failed to start");

    // Ping local address
    let node_addr = 1;
    let res = node.ping(node_addr, 1000, 100, 0).expect("Ping failed");

    // Validate that ping returned a reasonable round-trip time
    assert!(res < 1000, "Ping RTT should be less than timeout (1000ms), got {} ms", res);

    service_handle.join().expect("Service thread panicked");
}
