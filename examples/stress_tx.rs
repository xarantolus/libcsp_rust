//! CSP Stress Test Sender (Linux)
//!
//! Run with: cargo run --example stress_tx -- vcan0

mod stress;
use stress::{Prng, ProtocolMode, PRNG_SEED, DATA_PORT, SFP_PORT};

use libcsp::{CspConfig, Packet, Priority, socket_opts, conn_opts, Connection};
use std::time::{Instant, Duration};
use std::thread;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let iface_name = args.next().unwrap_or_else(|| "vcan0".to_string());

    println!("[TX] Starting CSP Stress Test SENDER on {}...", iface_name);

    // 1. Initialise CSP
    let node = CspConfig::new()
        .address(1)
        .buffers(500, 256)
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

    let mut current_mode = ProtocolMode::Normal;
    let mut active_conn: Option<Connection> = None;

    println!(">>> Starting in Mode: {}", current_mode.to_str());

    loop {
        let next_mode = ProtocolMode::from_count(count);
        if next_mode != current_mode {
            println!("[TX] Mode Switch: {} -> {} (count={})", current_mode.to_str(), next_mode.to_str(), count);
            // Drop old connection to trigger close/reset
            if let Some(conn) = active_conn.take() {
                if (conn.flags() & libcsp::sys::CSP_FRDP as i32) != 0 {
                    thread::sleep(Duration::from_millis(50)); // Flush RDP
                }
                drop(conn);
            }
            current_mode = next_mode;
        }

        // Ensure we have a connection for the current mode
        if active_conn.is_none() {
            let opts = match current_mode {
                ProtocolMode::Normal => socket_opts::CONN_LESS,
                ProtocolMode::Rdp => conn_opts::RDP,
                ProtocolMode::SFP => conn_opts::NONE,
                ProtocolMode::RdpSfp => conn_opts::RDP,
            };
            let port = if matches!(current_mode, ProtocolMode::SFP | ProtocolMode::RdpSfp) { SFP_PORT } else { DATA_PORT };
            
            active_conn = node.connect(Priority::Norm as u8, 2, port, 1000, opts);
            if active_conn.is_none() {
                eprintln!("[TX] Failed to establish connection for {}, retrying...", current_mode.to_str());
                thread::sleep(Duration::from_millis(100));
                continue;
            }
            println!("[TX] Established connection for {}", current_mode.to_str());
        }

        let conn = active_conn.as_ref().unwrap();

        match current_mode {
            ProtocolMode::Normal | ProtocolMode::Rdp => {
                if let Some(mut pkt) = Packet::get(200) {
                    let mut data = [0u8; 200];
                    data[0..8].copy_from_slice(&count.to_le_bytes());
                    let mut packet_prng = Prng::new(PRNG_SEED ^ (count as u32));
                    packet_prng.fill(&mut data[8..]);
                    pkt.write(&data).unwrap();
                    
                    if conn.send_discard(pkt, 500).is_ok() {
                        bytes_sent += 200;
                        count += 1;
                    } else {
                        // Send failed, maybe connection died?
                        active_conn = None;
                    }
                }
            }
            ProtocolMode::SFP | ProtocolMode::RdpSfp => {
                let size = (prng.next() % 4000) + 1000;
                let mut data = vec![0u8; size as usize];
                data[0..8].copy_from_slice(&count.to_le_bytes());
                let mut blob_prng = Prng::new(PRNG_SEED ^ (count as u32));
                blob_prng.fill(&mut data[8..]);

                if conn.sfp_send(&data, 200, 1000).is_ok() {
                    bytes_sent += size as u64;
                    count += 100; // SFP counts as more "work"
                    println!("[TX] SFP sent {} bytes (count={})", size, count - 100);
                } else {
                    active_conn = None;
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

        thread::sleep(Duration::from_millis(1));
    }
}
