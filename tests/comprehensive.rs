use libcsp::{CspConfig, Packet, Socket, Priority, socket_opts, conn_opts, ports, CspNode};
use std::thread;
use std::time::Duration;
use std::sync::{OnceLock, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

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
    }).clone()
}

fn lock_csp() -> std::sync::MutexGuard<'static, ()> {
    TEST_MUTEX.lock().unwrap()
}

#[test]
fn test_rdp_basic() {
    let _lock = lock_csp();
    let node = ensure_init();

    let server_received = std::sync::Arc::new(AtomicBool::new(false));
    let server_received_clone = server_received.clone();

    let server_thread = thread::spawn(move || {
        let sock = Socket::new(socket_opts::RDP_REQ).expect("failed to create RDP socket");
        sock.bind(15).unwrap();
        sock.listen(5).unwrap();

        if let Some(conn) = sock.accept(2000) {
            assert!(conn.is_rdp(), "Connection should have RDP flag set");
            if let Some(pkt) = conn.read(1000) {
                if pkt.data() == b"rdp-test" {
                    server_received_clone.store(true, Ordering::SeqCst);
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    // Safe connect using node
    let conn = node.connect(Priority::Norm, 1, 15, 1000, conn_opts::RDP)
        .expect("RDP connect failed");

    let mut pkt = Packet::get(8).unwrap();
    pkt.write(b"rdp-test").unwrap();
    conn.send(pkt, 1000).expect("RDP send failed");

    server_thread.join().unwrap();
    assert!(server_received.load(Ordering::SeqCst), "Server did not receive RDP packet");
}

#[test]
fn test_sfp_large_transfer() {
    let _lock = lock_csp();
    let node = ensure_init();

    let data_to_send = vec![0xAAu8; 1000]; // 1000 bytes, larger than MTU (256)
    let data_to_send_clone = data_to_send.clone();

    let server_thread = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).unwrap();
        sock.bind(16).unwrap();
        sock.listen(5).unwrap();

        if let Some(conn) = sock.accept(5000) {
            let received = conn.sfp_recv(5000).expect("SFP receive failed");
            assert_eq!(received, data_to_send_clone);
        }
    });

    thread::sleep(Duration::from_millis(100));

    let conn = node.connect(Priority::Norm, 1, 16, 1000, conn_opts::NONE)
        .expect("SFP connect failed");

    conn.sfp_send(&data_to_send, 200, 5000).expect("SFP send failed");

    server_thread.join().unwrap();
}

#[test]
fn test_transaction_oneshot() {
    let _lock = lock_csp();
    let node = ensure_init();

    let server_thread = thread::spawn(|| {
        let sock = Socket::new(socket_opts::NONE).unwrap();
        sock.bind(17).unwrap();
        sock.listen(5).unwrap();

        if let Some(conn) = sock.accept(2000) {
            if let Some(mut pkt) = conn.read(1000) {
                assert_eq!(pkt.data(), b"request");
                pkt.write(b"reply").unwrap();
                conn.send(pkt, 1000).unwrap();
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    let out_buf = b"request".to_vec();
    let mut in_buf = vec![0u8; 10];
    
    let ret = node.transaction(
        Priority::Norm,
        1,
        17,
        1000,
        &out_buf,
        &mut in_buf,
        5,
        0
    ).expect("Transaction failed");

    assert_eq!(ret, 5);
    assert_eq!(&in_buf[0..5], b"reply");

    server_thread.join().unwrap();
}

#[test]
fn test_cmp_ident() {
    let _lock = lock_csp();
    let node = ensure_init();

    let service_thread = thread::spawn(|| {
        let sock = Socket::new(socket_opts::NONE).unwrap();
        sock.bind(ports::CMP).unwrap();
        sock.listen(5).unwrap();

        for _ in 0..3 {
            if let Some(conn) = sock.accept(2000) {
                if let Some(pkt) = conn.read(1000) {
                    // Safe service handler
                    conn.handle_service(pkt);
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    let out_buf = vec![0u8, 1u8]; // type = 0 (REQUEST), code = 1 (IDENT)
    let mut in_buf = vec![0u8; 256];
    
    let ret = node.transaction(
        Priority::Norm,
        1,
        ports::CMP,
        1000,
        &out_buf,
        &mut in_buf,
        -1,
        0
    ).expect("CMP transaction failed");

    assert!(ret > 0, "CMP transaction returned 0");
    
    service_thread.join().unwrap();
}

#[test]
fn test_route_load() {
    let _lock = lock_csp();
    let node = ensure_init();
    let res = node.route_load("10/5 LOOP");
    assert!(res.is_ok());
}

#[test]
fn test_node_ping() {
    let _lock = lock_csp();
    let node = ensure_init();

    let service_thread = thread::spawn(|| {
        let sock = Socket::new(socket_opts::NONE).unwrap();
        sock.bind(ports::PING).unwrap();
        sock.listen(5).unwrap();

        if let Some(conn) = sock.accept(2000) {
            if let Some(pkt) = conn.read(1000) {
                conn.handle_service(pkt);
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    // Safe ping call
    let _res = node.ping(1, 1000, 10, 0).expect("Ping failed");

    service_thread.join().unwrap();
}
