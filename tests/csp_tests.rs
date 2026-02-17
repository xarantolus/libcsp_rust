use libcsp::{CspConfig, Packet, Socket, Priority, socket_opts};
use std::thread;
use std::time::Duration;
use std::sync::Once;
use std::sync::atomic::{AtomicUsize, Ordering};

static INIT: Once = Once::new();
static SERVER_RECEIVED: AtomicUsize = AtomicUsize::new(0);

fn ensure_init() {
    INIT.call_once(|| {
        let node = CspConfig::new()
            .address(1)
            .buffers(20, 256)
            .init()
            .expect("init failed");
        node.route_start_task(4096, 0).unwrap();
        node.route_load("0/0 LOOP").unwrap();
        // Leak so it stays alive for all tests in this process
        core::mem::forget(node);
    });
}

#[test]
fn test_csp_server_client_loopback() {
    ensure_init();

    const MY_SERVER_PORT: u8 = 10;
    const SERVER_ADDR: u8 = 1;

    // Start Server
    let server_handle = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).expect("csp_socket failed");
        sock.bind(MY_SERVER_PORT).expect("csp_bind failed");
        sock.listen(10).expect("csp_listen failed");

        // Process 5 packets then exit
        for _ in 0..5 {
            if let Some(conn) = sock.accept(2000) {
                while let Some(pkt) = conn.read(100) {
                    if conn.dst_port() == MY_SERVER_PORT as i32 {
                        let data = pkt.data();
                        if data.starts_with(b"Hello World") {
                            SERVER_RECEIVED.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    // Packet is freed on drop
                }
                // Connection is closed on drop
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    // Start Client logic
    let mut count = 0;
    for _ in 0..5 {
        thread::sleep(Duration::from_millis(50));

        let ptr = unsafe { libcsp::sys::csp_connect(Priority::Norm as u8, SERVER_ADDR, MY_SERVER_PORT, 1000, 0) };
        assert!(!ptr.is_null(), "Connection failed");
        let conn = unsafe { libcsp::Connection::from_raw(ptr) };

        let mut pkt = Packet::get(100).expect("Failed to get buffer");
        let msg = format!("Hello World ({})", count);
        pkt.write(msg.as_bytes()).unwrap();
        count += 1;

        conn.send(pkt, 1000).expect("Send failed");
        // conn closed on drop
    }

    server_handle.join().expect("Server thread panicked");

    assert_eq!(SERVER_RECEIVED.load(Ordering::SeqCst), 5, "Server should have received 5 packets");
}

#[test]
fn test_csp_ping() {
    ensure_init();
    
    // Start a thread to handle pings (CSP service port is 1)
    let service_handle = thread::spawn(|| {
        let sock = Socket::new(socket_opts::NONE).unwrap();
        sock.bind(libcsp::ports::PING).unwrap();
        sock.listen(5).unwrap();
        
        if let Some(conn) = sock.accept(2000) {
            if let Some(pkt) = conn.read(100) {
                unsafe {
                    libcsp::sys::csp_service_handler(
                        conn.as_raw(),
                        pkt.into_raw()
                    );
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(100));

    // Ping local address
    let node_addr = 1;
    let res = unsafe { libcsp::sys::csp_ping(node_addr, 1000, 100, 0) };
    
    assert!(res >= 0, "Ping failed with error {}", res);
    println!("Ping took {} ms", res);
    
    service_handle.join().expect("Service thread panicked");
}
