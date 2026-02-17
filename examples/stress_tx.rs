//! CSP Stress Test Sender (Linux)
//!
//! Run with: cargo run --example stress_tx -- vcan0

mod stress;
use stress::{Prng, ProtocolMode, PRNG_SEED, DATA_PORT, SFP_PORT};

use libcsp::{CspConfig, Packet, Priority, socket_opts, conn_opts};
use std::time::{Instant, Duration};
use std::thread;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let iface_name = args.next().unwrap_or_else(|| "vcan0".to_string());

    println!("[TX] Starting CSP Stress Test SENDER on {}...", iface_name);

    // 1. Initialise CSP
    let node = CspConfig::new()
        .address(1)
        .buffers(100, 256)
        .init()
        .expect("CSP init failed");

    // 2. Add SocketCAN interface
    node.add_interface_socketcan(&iface_name, 0, true)?;
    
    // 3. Setup routing
    node.route_load("2 CAN")?;
    node.route_start_task(4096, 0)?;

    let mut prng = Prng::new(PRNG_SEED);
    let mut count = 0u64;
    let start_time = Instant::now();
    let mut last_log = Instant::now();
    let mut bytes_sent = 0u64;

    loop {
        let mode = ProtocolMode::from_count(count);
        if count % 1000 == 0 {
            println!(">>> Mode: {} (count={})", mode.to_str(), count);
        }

        match mode {
            ProtocolMode::Normal => {
                // Connectionless / UDP-like
                if let Some(mut pkt) = Packet::get(200) {
                    let mut data = [0u8; 200];
                    prng.fill(&mut data);
                    pkt.write(&data).unwrap();
                    
                    // Connect (connectionless)
                    if let Some(conn) = node.connect(Priority::Norm as u8, 2, DATA_PORT, 100, socket_opts::CONN_LESS) {
                        let _ = conn.send_discard(pkt, 100);
                        bytes_sent += 200;
                        count += 1;
                    }
                }
            }
            ProtocolMode::Rdp => {
                // Reliable connection
                if let Some(conn) = node.connect(Priority::Norm as u8, 2, DATA_PORT, 1000, conn_opts::RDP) {
                    for _ in 0..50 {
                        if let Some(mut pkt) = Packet::get(200) {
                            let mut data = [0u8; 200];
                            prng.fill(&mut data);
                            pkt.write(&data).unwrap();
                            
                            if conn.send_discard(pkt, 500).is_ok() {
                                bytes_sent += 200;
                                count += 1;
                            } else {
                                break;
                            }
                        }
                    }
                    // Connection closed on drop (RDP Close)
                } else {
                    eprintln!("[TX] RDP Connect failed, retrying...");
                    thread::sleep(Duration::from_millis(100));
                    count += 1; // Progress to eventually change mode
                }
            }
            ProtocolMode::SFP | ProtocolMode::RdpSfp => {
                let mut opts = conn_opts::NONE;
                if mode == ProtocolMode::RdpSfp {
                    opts |= conn_opts::RDP;
                }

                if let Some(conn) = node.connect(Priority::Norm as u8, 2, SFP_PORT, 1000, opts) {
                    let size = (prng.next() % 4000) + 1000;
                    let mut data = vec![0u8; size as usize];
                    prng.fill(&mut data);

                    if conn.sfp_send(&data, 200, 1000).is_ok() {
                        bytes_sent += size as u64;
                        count += 100;
                        println!("[TX] SFP sent {} bytes", size);
                    }
                } else {
                    count += 1;
                }
            }
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            let elapsed = start_time.elapsed().as_secs_f64();
            println!("[Stats] Sent {} MB total, Avg Rate: {:.2} KB/s", 
                bytes_sent / 1024 / 1024,
                (bytes_sent as f64 / 1024.0) / elapsed
            );
            last_log = Instant::now();
        }

        // Slight throttle to not overwhelm local vcan if needed
        // thread::sleep(Duration::from_millis(1));
    }
}
