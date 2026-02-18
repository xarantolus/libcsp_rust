//! CSP Stress Test Sender (Linux) - Ultra-Consistent Version
//!
//! Targets a rock-steady ~50% load (200 PPS) with seamless mode transitions.

mod stress;
use stress::{Prng, ProtocolMode, PRNG_SEED, DATA_PORT, SFP_PORT};

use libcsp::{CspConfig, Packet, Priority, socket_opts, conn_opts, Connection};
use std::time::{Instant, Duration};
use std::thread;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let iface_name = args.next().unwrap_or_else(|| "vcan0".to_string());

    println!("[TX] Starting CONSISTENT LOAD CSP Stress Test on {}...", iface_name);

    let node = CspConfig::new()
        .address(1)
        .buffers(1000, 256)
        .fifo_length(100)
        .init()
        .expect("CSP init failed");

    node.add_interface_socketcan(&iface_name, 0, true)?;
    node.route_load("2 CAN")?;
    node.route_start_task(4096, 0)?;

    let mut prng = Prng::new(PRNG_SEED);
    let mut count = 0u64;
    let mut bytes_sent = 0u64;
    let start_time = Instant::now();
    let mut last_log = Instant::now();
    
    let mut current_mode = ProtocolMode::Normal;
    let mut mode_start = Instant::now();
    let mut active_conn: Option<Connection> = None;

    // 200 PPS = 5ms interval
    let interval = Duration::from_millis(5);
    let mut next_tick = Instant::now();

    loop {
        // 1. Precise Pacing
        let now = Instant::now();
        if now < next_tick {
            thread::sleep(next_tick - now);
        }
        // Advance clock. If we are lagging behind by more than 100ms, 
        // snap to 'now' to avoid massive catch-up bursts.
        next_tick += interval;
        if Instant::now() > next_tick + Duration::from_millis(100) {
            next_tick = Instant::now() + interval;
        }

        // 2. Seamless Mode Switching (every 5 seconds)
        if mode_start.elapsed() >= Duration::from_secs(5) {
            let next_mode = match current_mode {
                ProtocolMode::Normal => ProtocolMode::Rdp,
                ProtocolMode::Rdp => ProtocolMode::SFP,
                ProtocolMode::SFP => ProtocolMode::RdpSfp,
                ProtocolMode::RdpSfp => ProtocolMode::Normal,
            };
            
            println!("[TX] Switch: {} -> {} (count={})", current_mode.to_str(), next_mode.to_str(), count);
            
            // Seamless handoff: only drop if the protocol type actually changes
            let needs_new_conn = match (current_mode, next_mode) {
                (ProtocolMode::Normal, ProtocolMode::Normal) => false,
                (ProtocolMode::Rdp, ProtocolMode::Rdp) => false,
                _ => true,
            };

            if needs_new_conn {
                active_conn = None; 
            }
            
            current_mode = next_mode;
            mode_start = Instant::now();
        }

        // 3. Robust Connection Management
        if active_conn.is_none() {
            let opts = match current_mode {
                ProtocolMode::Normal => socket_opts::CONN_LESS,
                ProtocolMode::Rdp | ProtocolMode::RdpSfp => conn_opts::RDP,
                _ => conn_opts::NONE,
            };
            let port = if matches!(current_mode, ProtocolMode::SFP | ProtocolMode::RdpSfp) { SFP_PORT } else { DATA_PORT };
            
            // Use a very short timeout for the connect call to avoid stalling the heartbeat
            active_conn = node.connect(Priority::Norm as u8, 2, port, 50, opts);
            if active_conn.is_none() {
                // If connect failed, we just try again next tick.
                // This keeps the loop running and prevents the "silence" gaps.
                continue; 
            }
        }

        // 4. Steady Traffic Generation
        let conn = active_conn.as_ref().unwrap();
        match current_mode {
            ProtocolMode::Normal | ProtocolMode::Rdp => {
                if let Some(mut pkt) = Packet::get(200) {
                    let mut data = [0u8; 200];
                    data[0..8].copy_from_slice(&count.to_le_bytes());
                    let mut packet_prng = Prng::new(PRNG_SEED ^ (count as u32));
                    packet_prng.fill(&mut data[8..]);
                    pkt.write(&data).unwrap();
                    
                    // Non-blocking send (timeout 0) to maintain cadence
                    if conn.send_discard(pkt, 0).is_ok() {
                        bytes_sent += 200;
                        count += 1;
                    } else {
                        // If the pipe is full, we might have a dead connection
                        active_conn = None;
                    }
                }
            }
            ProtocolMode::SFP | ProtocolMode::RdpSfp => {
                // For SFP, we send smaller chunks more often to keep the load "semi-consistent"
                // rather than one massive burst followed by silence.
                let size = 600; // ~4 packets per SFP call
                let mut data = vec![0u8; size as usize];
                data[0..8].copy_from_slice(&count.to_le_bytes());
                let mut blob_prng = Prng::new(PRNG_SEED ^ (count as u32));
                blob_prng.fill(&mut data[8..]);

                if conn.sfp_send(&data, 180, 100).is_ok() {
                    bytes_sent += size as u64;
                    count += 1;
                    
                    // SFP is inherently bursty in the C core, but by sending small 
                    // chunks and advancing the tick, we smooth it out.
                    let packets_sent = (size / 180) + 1;
                    for _ in 0..packets_sent {
                        next_tick += interval;
                    }
                } else {
                    active_conn = None;
                }
            }
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            let elapsed = start_time.elapsed().as_secs_f64();
            let kbps_app = (bytes_sent as f64 / 1024.0) / elapsed;
            // Est load: (Packets * ~30 frames/packet * 128 bits/frame) / (Bitrate * elapsed)
            let est_load = ((count as f64 * 29.0 * 128.0) / (1_000_000.0 * elapsed)) * 100.0;
            
            println!("[Stats] App: {:.2} KB/s, Est Bus Load: {:.1}%, Mode: {}", 
                kbps_app,
                est_load,
                current_mode.to_str()
            );
            last_log = Instant::now();
        }
    }
}
