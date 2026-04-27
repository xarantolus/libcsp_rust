use libcsp::{socket_opts, CspConfig, CspNode, Packet, Priority, Socket};
use std::sync::{mpsc, Mutex, OnceLock};
use std::thread;

static NODE: OnceLock<CspNode> = OnceLock::new();
static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn ensure_init() -> CspNode {
    NODE.get_or_init(|| {
        let node = CspConfig::new().address(1).init().expect("init failed");
        node.route_start_task(4096, 0).unwrap();
        node.route_load("0/0 LOOP").unwrap();
        node
    })
    .clone()
}

fn lock_csp() -> std::sync::MutexGuard<'static, ()> {
    TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn test_basic_client_server() {
    let _lock = lock_csp();
    let node = ensure_init();

    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::NONE);
        sock.bind(10).expect("Failed to bind");
        sock.listen(5).expect("Failed to listen");

        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(conn) = sock.accept(1000) {
            if let Some(pkt) = conn.read(1000) {
                assert_eq!(pkt.data(), b"ping", "Server received unexpected data");
                assert_eq!(pkt.length(), 4, "Packet length should be 4 bytes");
            } else {
                panic!("Server failed to read packet");
            }
        } else {
            panic!("Server failed to accept connection");
        }
    });

    ready_rx.recv().expect("Server failed to start");

    let conn = node
        .connect(Priority::Norm, 1, 10, 1000, 0)
        .expect("connect failed");

    let mut pkt = Packet::get(4).expect("Failed to get packet");
    pkt.write(b"ping").expect("Failed to write packet");
    conn.send(pkt);

    server_thread.join().expect("Server thread panicked");
}

#[test]
fn test_connectionless() {
    let _lock = lock_csp();
    let node = ensure_init();

    let (ready_tx, ready_rx) = mpsc::channel();

    let server_thread = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::CONN_LESS);
        sock.bind(20).expect("Failed to bind");

        ready_tx.send(()).expect("Failed to signal ready");

        if let Some(pkt) = sock.recvfrom(1000) {
            assert_eq!(pkt.data(), b"udp-style", "Server received unexpected data");
            assert_eq!(pkt.length(), 9, "Packet length should be 9 bytes");
        } else {
            panic!("Server failed to receive connectionless packet");
        }
    });

    ready_rx.recv().expect("Server failed to start");

    let mut pkt = Packet::get(10).expect("Failed to get packet");
    pkt.write(b"udp-style").expect("Failed to write packet");
    node.sendto(Priority::Norm, 1, 20, 0, 0, pkt);

    server_thread.join().expect("Server thread panicked");
}
