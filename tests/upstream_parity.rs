//! Integration tests mirroring upstream libcsp's built-in server/client
//! verification (see `libcsp/examples/csp_server_client.c`, used by the
//! upstream CI pipeline as the canonical smoke test). Each test exercises
//! one piece of service-handler functionality over loopback.

use libcsp::{service::Dispatcher, socket_opts, CspConfig, CspNode, Packet, Port, Priority, Socket};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::Duration;

static NODE: OnceLock<CspNode> = OnceLock::new();
static TEST_MUTEX: Mutex<()> = Mutex::new(());

/// Spawn a long-lived service dispatcher on first call. libcsp allows only
/// one `CSP_ANY` bind per process, so a single shared handler serves every
/// test that needs the CMP service handler reachable on loopback.
static SERVICE_THREAD: OnceLock<thread::JoinHandle<()>> = OnceLock::new();

fn ensure_init() -> CspNode {
    NODE.get_or_init(|| {
        let node = CspConfig::new()
            .address(1)
            .hostname("rust-test")
            .model("unit")
            .revision("0.1")
            .init()
            .expect("init failed");
        node.route_start_task(0, 0).expect("router");
        node
    })
    .clone()
}

fn ensure_service_dispatcher() {
    SERVICE_THREAD.get_or_init(|| {
        // Signal from the dispatcher thread once the CSP_ANY bind is live;
        // the first test would otherwise race the bind and time out.
        let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();
        let handle = thread::spawn(move || {
            let mut sock = Socket::new(socket_opts::NONE);
            sock.bind(libcsp::ANY_PORT).expect("bind CSP_ANY");
            ready_tx.send(()).expect("ready signal");
            loop {
                // Keep accept short so we churn the loop often; long accept
                // windows starve the inner `read` path when back-to-back
                // tests submit requests faster than the accept cadence.
                let Some(conn) = sock.accept(100) else {
                    continue;
                };
                while let Some(pkt) = conn.read(100) {
                    conn.handle_service(pkt);
                }
            }
        });
        ready_rx.recv().expect("dispatcher thread died before binding");
        handle
    });
}

fn lock_csp() -> std::sync::MutexGuard<'static, ()> {
    TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

// ── Server/Client: upstream's primary loopback smoke test ────────────────────

/// Mirrors `./csp_server_client -T <seconds>`: client sends a handful of
/// packets to a server, server counts them.
#[test]
fn upstream_server_client_smoke() {
    let _lock = lock_csp();
    let node = ensure_init();

    const MY_SERVER_PORT: u8 = 10;
    const PACKETS: usize = 5;

    let (tx, rx) = std::sync::mpsc::channel();

    let server = thread::spawn(move || {
        let mut sock = Socket::new(socket_opts::NONE);
        sock.bind(MY_SERVER_PORT).expect("bind");
        tx.send(()).unwrap();

        let mut received = 0usize;
        while received < PACKETS {
            let Some(conn) = sock.accept(2000) else {
                break;
            };
            while let Some(pkt) = conn.read(100) {
                if conn.dst_port() == MY_SERVER_PORT && pkt.data().starts_with(b"Hello") {
                    received += 1;
                }
            }
        }
        received
    });

    rx.recv().unwrap();

    for i in 0..PACKETS {
        let conn = node
            .connect(Priority::Norm, 1, MY_SERVER_PORT, 1000, 0)
            .expect("connect");
        let mut pkt = Packet::get(64).unwrap();
        pkt.write(format!("Hello #{i}").as_bytes()).unwrap();
        conn.send(pkt);
    }

    let received = server.join().expect("server panicked");
    assert_eq!(received, PACKETS, "server should have received all packets");
}

// ── CMP IDENT ────────────────────────────────────────────────────────────────

/// Matches `csp_cmp_ident` on the upstream server_client — the remote
/// identification strings should round-trip unchanged.
#[test]
fn upstream_cmp_ident() {
    let _lock = lock_csp();
    let node = ensure_init();
    ensure_service_dispatcher();

    let ident = node.ident(1, 1000).expect("ident request failed");
    assert_eq!(ident.hostname, "rust-test");
    assert_eq!(ident.model, "unit");
    assert_eq!(ident.revision, "0.1");
}

// ── Free-buffer service ──────────────────────────────────────────────────────

/// `csp_get_buf_free` should return a non-zero count on a freshly-initialised
/// node.
#[test]
fn upstream_cmp_buf_free() {
    let _lock = lock_csp();
    let node = ensure_init();
    ensure_service_dispatcher();

    let n = node.buf_free(1, 1000).expect("buf_free failed");
    assert!(n > 0, "expected non-zero free buffer count, got {n}");
}

// ── Uptime service ───────────────────────────────────────────────────────────

/// `csp_get_uptime` should return a monotonically non-decreasing value.
#[test]
fn upstream_cmp_uptime_monotonic() {
    let _lock = lock_csp();
    let node = ensure_init();
    ensure_service_dispatcher();

    let a = node.uptime(1, 1000).expect("uptime #1 failed");
    thread::sleep(Duration::from_millis(1100));
    let b = node.uptime(1, 1000).expect("uptime #2 failed");

    assert!(b >= a, "uptime went backwards ({b} < {a})");
    assert!(b >= a + 1, "uptime should advance by at least 1s: {a} → {b}");
}

// ── Ping round-trip ──────────────────────────────────────────────────────────

/// The upstream client runs `csp_ping` as the first sanity check after
/// connecting. Mirror that over loopback.
#[test]
fn upstream_ping_roundtrip() {
    let _lock = lock_csp();
    let node = ensure_init();
    ensure_service_dispatcher();

    let rtt = node.ping(1, 1000, 16, 0).expect("ping failed");
    assert!(rtt < 1000, "ping RTT should be well under 1s, got {rtt}ms");
}

// ── Dispatcher replaces the raw accept loop ──────────────────────────────────

/// Verifies the [`Dispatcher`] convenience wrapper can substitute for the
/// ad-hoc `bind / listen / accept / read / switch-on-dport` loop that
/// upstream's `csp_server_client.c` hand-rolls.
#[test]
fn upstream_dispatcher_echo() {
    let _lock = lock_csp();
    let node = ensure_init();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<()>();

    let dispatcher_handle = thread::spawn(move || {
        let mut d = Dispatcher::new();
        let done_tx_clone = done_tx.clone();
        d.register(Port::Custom(11), move |_conn, pkt| {
            done_tx_clone.send(pkt.data().to_vec()).ok();
            None
        })
        .expect("register");
        ready_tx.send(()).expect("ready signal");
        d.run(500);
    });

    ready_rx.recv().expect("dispatcher failed to bind");

    let conn = node
        .connect(Priority::Norm, 1, 11, 1000, 0)
        .expect("connect");
    let mut pkt = Packet::get(32).unwrap();
    pkt.write(b"dispatch-me").unwrap();
    conn.send(pkt);

    let got = done_rx
        .recv_timeout(Duration::from_millis(2000))
        .expect("dispatcher didn't deliver the packet");
    assert_eq!(got, b"dispatch-me");

    drop(dispatcher_handle);
}
