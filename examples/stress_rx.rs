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
            let src_addr = conn.src_addr();
            let src_port = conn.src_port();
            
            while let Some(pkt) = conn.read(100) {
                let data = pkt.data();
                if data.len() < 8 {
                    errors += 1;
                    continue;
                }
                let mut count_buf = [0u8; 8];
                count_buf.copy_from_slice(&data[0..8]);
                let pkt_count = u64::from_le_bytes(count_buf);

                let mut expected = vec![0u8; data.len()];
                expected[0..8].copy_from_slice(&count_buf);
                let mut packet_prng = Prng::new(PRNG_SEED ^ (pkt_count as u32));
                packet_prng.fill(&mut expected[8..]);

                if data != expected {
                    eprintln!("[RX] DATA ERROR from {}:{} at count {}! Got {} bytes", src_addr, src_port, pkt_count, data.len());
                    errors += 1;
                }
                bytes_recv += data.len() as u64;
                count += 1;

                if count % 100 == 0 {
                    println!("[RX] Received 100 packets (latest count={}, from {}:{})", pkt_count, src_addr, src_port);
                }
            }
        }

        if let Some(conn) = sock_sfp.accept(100) {
            let src_addr = conn.src_addr();
            println!("[RX] Incoming SFP transfer from {}...", src_addr);
            match conn.sfp_recv(1000) {
                Ok(data) => {
                    if data.len() < 8 {
                        errors += 1;
                        continue;
                    }
                    let mut count_buf = [0u8; 8];
                    count_buf.copy_from_slice(&data[0..8]);
                    let pkt_count = u64::from_le_bytes(count_buf);

                    let mut expected = vec![0u8; data.len()];
                    expected[0..8].copy_from_slice(&count_buf);
                    let mut blob_prng = Prng::new(PRNG_SEED ^ (pkt_count as u32));
                    blob_prng.fill(&mut expected[8..]);

                    if data != expected {
                        eprintln!("[RX] SFP DATA ERROR from {} at count {}! Got {} bytes", src_addr, pkt_count, data.len());
                        errors += 1;
                    }
                    bytes_recv += data.len() as u64;
                    count += 100;
                    println!("[RX] SFP complete: received {} bytes from {} (count={})", data.len(), src_addr, pkt_count);
                }
                Err(e) => {
                    eprintln!("[RX] SFP Receive Failed from {}: {:?}", src_addr, e);
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
