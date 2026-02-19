use libcsp::{CspConfig, Packet, Socket, Priority, socket_opts, CspNode};
use std::thread;
use std::time::Duration;
use std::sync::{OnceLock, Mutex};

static NODE: OnceLock<CspNode> = OnceLock::new();
static TEST_MUTEX: Mutex<()> = Mutex::new(());

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
    TEST_MUTEX.lock().unwrap()
}

#[test]
fn test_basic_client_server() {
    let _lock = lock_csp();
    let node = ensure_init();

    let server_thread = thread::spawn(|| {
        let sock = Socket::new(socket_opts::NONE).unwrap();
        sock.bind(10).unwrap();
        sock.listen(5).unwrap();

        if let Some(conn) = sock.accept(1000) {
            if let Some(pkt) = conn.read(1000) {
                assert_eq!(pkt.data(), b"ping");
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    let conn = node.connect(Priority::Norm, 1, 10, 1000, 0)
        .expect("connect failed");
    
    let mut pkt = Packet::get(4).unwrap();
    pkt.write(b"ping").unwrap();
    conn.send(pkt, 100).expect("send failed");

    server_thread.join().unwrap();
}

#[test]
fn test_connectionless() {
    let _lock = lock_csp();
    let node = ensure_init();

    let server_thread = thread::spawn(|| {
        let sock = Socket::new(socket_opts::CONN_LESS).unwrap();
        sock.bind(20).unwrap();

        if let Some(pkt) = sock.recvfrom(1000) {
            assert_eq!(pkt.data(), b"udp-style");
        }
    });

    thread::sleep(Duration::from_millis(100));

    let conn = node.connect(Priority::Norm, 1, 20, 1000, socket_opts::CONN_LESS)
        .expect("connect failed");

    let mut pkt = Packet::get(10).unwrap();
    pkt.write(b"udp-style").unwrap();
    conn.send(pkt, 100).expect("send failed");

    server_thread.join().unwrap();
}
