//! CSP Stress Test Receiver (Linux)
//!
//! Run with: cargo run --example stress_rx -- vcan0

mod stress;
use stress::{Prng, ProtocolMode, PRNG_SEED, DATA_PORT, SFP_PORT};

use libcsp::{CspConfig, Packet, Priority, Socket, socket_opts};
use std::time::{Instant, Duration};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let iface_name = args.next().unwrap_or_else(|| "vcan0".to_string());

    println!("[RX] Starting CSP Stress Test RECEIVER on {}...", iface_name);

    // 1. Initialise CSP (address 2)
    let node = CspConfig::new()
        .address(2)
        .buffers(100, 256)
        .init()
        .expect("CSP init failed");

    // 2. Add SocketCAN interface
    node.add_interface_socketcan(&iface_name, 0, true)?;
    
    // 3. Setup routing
    node.route_load("1 CAN")?;
    node.route_start_task(4096, 0)?;

    // 4. Bind ports
    let sock_data = Socket::new(socket_opts::NONE).unwrap();
    sock_data.bind(DATA_PORT)?;
    sock_data.listen(10)?;

    let sock_sfp = Socket::new(socket_opts::NONE).unwrap();
    sock_sfp.bind(SFP_PORT)?;
    sock_sfp.listen(10)?;

    let mut prng = Prng::new(PRNG_SEED);
    let mut count = 0u64;
    let start_time = Instant::now();
    let mut last_log = Instant::now();
    let mut bytes_recv = 0u64;
    let mut errors = 0u64;

    println!("[RX] Ready to receive on ports {} (DATA) and {} (SFP)...", DATA_PORT, SFP_PORT);

    loop {
        // Poll both sockets
        if let Some(conn) = sock_data.accept(100) {
            while let Some(pkt) = conn.read(100) {
                let data = pkt.data();
                let mut expected = vec![0u8; data.len()];
                prng.fill(&mut expected);

                if data != expected {
                    eprintln!("[RX] DATA ERROR at count {}! Got {} bytes", count, data.len());
                    errors += 1;
                }
                bytes_recv += data.len() as u64;
                count += 1;
            }
        }

        if let Some(conn) = sock_sfp.accept(100) {
            match conn.sfp_recv(1000) {
                Ok(data) => {
                    let mut expected = vec![0u8; data.len()];
                    prng.fill(&mut expected);

                    if data != expected {
                        eprintln!("[RX] SFP ERROR at count {}! Got {} bytes", count, data.len());
                        errors += 1;
                    }
                    bytes_recv += data.len() as u64;
                    count += 100;
                    println!("[RX] SFP received {} bytes", data.len());
                }
                Err(e) => {
                    eprintln!("[RX] SFP Receive Failed: {:?}", e);
                    errors += 1;
                }
            }
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            let elapsed = start_time.elapsed().as_secs_f64();
            println!("[Stats] Recv {} MB total, Errors: {}, Avg Rate: {:.2} KB/s", 
                bytes_recv / 1024 / 1024,
                errors,
                (bytes_recv as f64 / 1024.0) / elapsed
            );
            last_log = Instant::now();
        }
    }
}
