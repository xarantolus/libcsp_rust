/// Test to validate that CMP IDENT responses contain actual node information
/// This addresses the user's requirement: "Ensure that the ident response actually contains the name of the node"

use libcsp::{CspConfig, Socket, socket_opts, ports, CspNode};
use std::sync::{OnceLock, Mutex, mpsc};
use std::thread;

static NODE: OnceLock<CspNode> = OnceLock::new();
static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn ensure_init() -> CspNode {
    NODE.get_or_init(|| {
        // Initialize with a specific hostname to validate later
        let node = CspConfig::new()
            .address(1)
            .hostname("test-satellite")  // Specific hostname for validation
            .buffers(20, 256)
            .port_max_bind(58)  // Allow binding to ports 0-58, leaving 59-63 for ephemeral ports
            .init()
            .expect("init failed");
        node.route_start_task(4096, 0).expect("Failed to start route task");
        node.route_load("0/0 LOOP").expect("Failed to load loopback route");
        node
    }).clone()
}

fn lock_csp() -> std::sync::MutexGuard<'static, ()> {
    TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn test_ident_contains_hostname() {
    let _lock = lock_csp();
    let node = ensure_init();

    let (ready_tx, ready_rx) = mpsc::channel();

    // Start service handler thread
    let service_thread = thread::spawn(move || {
        let sock = Socket::new(socket_opts::NONE).expect("Failed to create socket");
        sock.bind(ports::CMP).expect("Failed to bind CMP port");
        sock.listen(5).expect("Failed to listen");

        ready_tx.send(()).expect("Failed to signal ready");

        // Handle the ident request
        if let Some(conn) = sock.accept(2000) {
            if let Some(pkt) = conn.read(1000) {
                // Use built-in service handler which responds to IDENT requests
                conn.handle_service(pkt);
            } else {
                panic!("Service failed to read CMP packet");
            }
        } else {
            panic!("Service failed to accept CMP connection");
        }
    });

    ready_rx.recv().expect("Service thread failed to start");

    // Request ident from ourselves (loopback)
    let ident_result = node.ident(1, 1000);

    assert!(ident_result.is_ok(), "Ident request should succeed: {:?}", ident_result.err());

    let ident = ident_result.expect("Failed to get ident");

    // CRITICAL VALIDATION: Verify hostname matches what we configured
    assert_eq!(ident.hostname, "test-satellite",
        "Ident hostname should match configured hostname, got: '{}'", ident.hostname);

    // Verify other fields are populated (not empty)
    // The C library populates these with compile-time information
    assert!(!ident.model.is_empty(), "Ident model should not be empty");
    assert!(!ident.revision.is_empty(), "Ident revision should not be empty");
    assert!(!ident.date.is_empty(), "Ident date should not be empty");
    assert!(!ident.time.is_empty(), "Ident time should not be empty");

    // Verify all fields are valid UTF-8 (String type guarantees this)
    // and check they contain reasonable ASCII content
    assert!(ident.hostname.is_ascii(), "Hostname should be ASCII");
    assert!(ident.model.chars().all(|c| c.is_ascii()),
        "Model should be ASCII, got: '{}'", ident.model);
    assert!(ident.revision.chars().all(|c| c.is_ascii()),
        "Revision should be ASCII, got: '{}'", ident.revision);
    assert!(ident.date.chars().all(|c| c.is_ascii()),
        "Date should be ASCII, got: '{}'", ident.date);
    assert!(ident.time.chars().all(|c| c.is_ascii()),
        "Time should be ASCII, got: '{}'", ident.time);

    // Log the ident for debugging
    println!("Ident response:");
    println!("  Hostname: {}", ident.hostname);
    println!("  Model:    {}", ident.model);
    println!("  Revision: {}", ident.revision);
    println!("  Date:     {}", ident.date);
    println!("  Time:     {}", ident.time);

    service_thread.join().expect("Service thread panicked");
}

#[test]
fn test_ident_struct_type_safety() {
    // This test documents that the Ident struct provides type-safe UTF-8 strings.
    // The Ident struct uses Rust's String type for all text fields, which guarantees
    // valid UTF-8 encoding at compile time. This is a significant safety improvement
    // over raw C strings.
    //
    // The actual UTF-8 validation happens in test_ident_contains_hostname, which
    // retrieves an ident and verifies all fields are valid ASCII (a subset of UTF-8).
    //
    // This test exists to document this safety property and can be extended in the
    // future to test edge cases like non-ASCII UTF-8 if the C library ever supports it.

    // Type-level proof: these fields MUST be String (UTF-8 guaranteed)
    let _: fn() -> libcsp::service::Ident = || {
        libcsp::service::Ident {
            hostname: String::new(),
            model: String::new(),
            revision: String::new(),
            date: String::new(),
            time: String::new(),
        }
    };

    // If this compiles, the Ident struct uses String, proving UTF-8 safety
}

#[test]
fn test_ident_timeout_without_service() {
    let _lock = lock_csp();
    let node = ensure_init();

    // Try to get ident without a service handler running
    // Should timeout
    let result = node.ident(1, 100);  // Short timeout

    assert!(result.is_err(), "Ident without service handler should fail");

    match result {
        Err(libcsp::CspError::TimedOut) => {
            // Expected - this is the correct behavior
        }
        Err(other) => {
            panic!("Expected TimedOut error, got: {:?}", other);
        }
        Ok(_) => {
            panic!("Ident should not succeed without a service handler");
        }
    }
}
