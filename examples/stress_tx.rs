//! CSP Stress Test Sender (Linux)
//!
//! Cycles through Normal, RDP, SFP, and RDP+SFP modes with clean transitions.

mod stress;
use stress::{Prng, ProtocolMode, PRNG_SEED, DATA_PORT, SFP_PORT};

use libcsp::{CspConfig, Packet, Priority, socket_opts, conn_opts, Connection};
use std::time::{Instant, Duration};
use std::thread;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let iface_name = args.next().unwrap_or_else(|| "vcan0".to_string());

    println!("[TX] Starting CSP Stress Test on {}...", iface_name);

    let node = CspConfig::new()
        .address(1)
        .buffers(1000, 256)
        .fifo_length(100)
        .init()
        .expect("CSP init failed");

    node.add_interface_socketcan(&iface_name, 0, true)?;
    node.route_load("2 CAN")?;
    node.route_start_task(4096, 0)?;

    // Fast RDP close for stress tests
    unsafe { libcsp::sys::csp_rdp_set_opt(20, 500, 100, 1, 100, 2); }

    let mut count = 0u64;
    let mut bytes_sent = 0u64;
    let start_time = Instant::now();
    let mut last_log = Instant::now();
    let mut mode_start = Instant::now();
    
    let mut current_mode = ProtocolMode::Normal;
    let mut active_conn: Option<Connection> = None;

    // 200 PPS = 5ms interval
    let interval = Duration::from_millis(5);
    let mut next_tick = Instant::now();

    loop {
        // 1. Pacing
        let now = Instant::now();
        if now < next_tick { thread::sleep(next_tick - now); }
        next_tick += interval;
        if Instant::now() > next_tick + Duration::from_millis(100) {
            next_tick = Instant::now() + interval;
        }

        // 2. Clean Mode Switch (every 10 seconds)
        if mode_start.elapsed() >= Duration::from_secs(10) {
            let next_mode = match current_mode {
                ProtocolMode::Normal => ProtocolMode::Rdp,
                ProtocolMode::Rdp => ProtocolMode::SFP,
                ProtocolMode::SFP => ProtocolMode::RdpSfp,
                ProtocolMode::RdpSfp => ProtocolMode::Normal,
            };
            
            println!("\n[TX] MODE END: {} (count={})", current_mode.to_str(), count);
            println!("[TX] Cleaning up connections and entering 500ms silence...");
            
            active_conn = None; // Drop connection (calls csp_close)
            
            // SILENCE PERIOD: This is critical. It allows RDP FIN handshakes 
            // to finish without competition from the next mode's packets.
            thread::sleep(Duration::from_millis(500));
            
            current_mode = next_mode;
            mode_start = Instant::now();
            println!("[TX] MODE START: {}\n", current_mode.to_str());
        }

        // 3. Mode Logic
        match current_mode {
            ProtocolMode::Normal => {
                // TRUE Connectionless send - bypasses connection table entirely
                if let Some(mut pkt) = Packet::get(200) {
                    let mut data = [0u8; 200];
                    data[0..8].copy_from_slice(&count.to_le_bytes());
                    let mut packet_prng = Prng::new(PRNG_SEED ^ (count as u32));
                    packet_prng.fill(&mut data[8..]);
                    pkt.write(&data).unwrap();
                    
                    if node.sendto(Priority::Norm, 2, DATA_PORT, 10, socket_opts::NONE, pkt, 0).is_ok() {
                        bytes_sent += 200;
                        count += 1;
                    }
                }
            }
            ProtocolMode::Rdp => {
                if active_conn.is_none() {
                    active_conn = node.connect(Priority::Norm, 2, DATA_PORT, 100, conn_opts::RDP);
                    if active_conn.is_none() { continue; }
                }
                let conn = active_conn.as_ref().unwrap();
                if let Some(mut pkt) = Packet::get(200) {
                    let mut data = [0u8; 200];
                    data[0..8].copy_from_slice(&count.to_le_bytes());
                    let mut packet_prng = Prng::new(PRNG_SEED ^ (count as u32));
                    packet_prng.fill(&mut data[8..]);
                    pkt.write(&data).unwrap();
                    if conn.send_discard(pkt, 0).is_ok() {
                        bytes_sent += 200;
                        count += 1;
                    } else { active_conn = None; }
                }
            }
            ProtocolMode::SFP | ProtocolMode::RdpSfp => {
                if active_conn.is_none() {
                    let opts = if current_mode == ProtocolMode::RdpSfp { conn_opts::RDP } else { conn_opts::NONE };
                    active_conn = node.connect(Priority::Norm, 2, SFP_PORT, 100, opts);
                    if active_conn.is_none() { continue; }
                }
                let conn = active_conn.as_ref().unwrap();
                let size = 600;
                let mut data = vec![0u8; size as usize];
                data[0..8].copy_from_slice(&count.to_le_bytes());
                let mut blob_prng = Prng::new(PRNG_SEED ^ (count as u32));
                blob_prng.fill(&mut data[8..]);

                if conn.sfp_send(&data, 180, 100).is_ok() {
                    bytes_sent += size as u64;
                    count += 1;
                    let burst_packets = (size / 180) + 1;
                    for _ in 0..burst_packets { next_tick += interval; }
                } else { active_conn = None; }
            }
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let kbps_app = (bytes_sent as f64 / 1024.0) / elapsed;
            println!("[Stats] App: {:.2} KB/s, Mode: {}", kbps_app, current_mode.to_str());
            last_log = Instant::now();
        }
    }
}
