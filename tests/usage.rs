use libcsp::{CspConfig, Packet, Socket, Priority, Connection, socket_opts};
use std::thread;
use std::time::Duration;
use std::sync::Once;

static INIT: Once = Once::new();

fn ensure_init() {
    INIT.call_once(|| {
        let node = CspConfig::new()
            .address(1)
            .buffers(20, 256)
            .init()
            .expect("init failed");
        node.route_start_task(4096, 0).unwrap();
        node.route_load("0/0 LOOP").unwrap();
        // Leak so it stays alive
        core::mem::forget(node);
    });
}

#[test]
fn test_basic_client_server() {
    ensure_init();

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

    let ptr = unsafe { libcsp::sys::csp_connect(Priority::Norm as u8, 1, 10, 1000, 0) };
    assert!(!ptr.is_null());
    let conn = unsafe { Connection::from_raw(ptr) };
    
    let mut pkt = Packet::get(4).unwrap();
    pkt.write(b"ping").unwrap();
    conn.send(pkt, 100).expect("send failed");

    server_thread.join().unwrap();
}

#[test]
fn test_connectionless() {
    ensure_init();

    let server_thread = thread::spawn(|| {
        let sock = Socket::new(socket_opts::CONN_LESS).unwrap();
        sock.bind(20).unwrap();

        if let Some(pkt) = sock.recvfrom(1000) {
            assert_eq!(pkt.data(), b"udp-style");
        }
    });

    thread::sleep(Duration::from_millis(100));

    let ptr = unsafe { libcsp::sys::csp_connect(Priority::Norm as u8, 1, 20, 1000, socket_opts::CONN_LESS) };
    assert!(!ptr.is_null());
    let conn = unsafe { Connection::from_raw(ptr) };

    let mut pkt = Packet::get(10).unwrap();
    pkt.write(b"udp-style").unwrap();
    conn.send(pkt, 100).expect("send failed");

    server_thread.join().unwrap();
}
