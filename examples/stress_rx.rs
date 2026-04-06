//! CSP Stress Test Receiver (Linux)
//!
//! Run with: cargo run --example stress_rx --features socketcan -- vcan0

mod stress;
use stress::{Prng, DATA_PORT, PRNG_SEED, SFP_PORT};

use libcsp::{socket_opts, CspConfig, Socket};
use std::thread;
use std::time::{Duration, Instant};

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let iface_name = args.next().unwrap_or_else(|| "vcan0".to_string());

    println!(
        "[RX] Starting CSP Stress Test RECEIVER on {}...",
        iface_name
    );

    let node = CspConfig::new()
        .address(2)
        .buffers(1000, 256)
        .fifo_length(100)
        .init()
        .expect("CSP init failed");

    node.add_interface_socketcan(&iface_name, 0, true)?;
    node.route_load("1 CAN")?;
    node.route_start_task(4096, 0)?;

    let sock_data = Socket::new(socket_opts::NONE).unwrap();
    sock_data.bind(DATA_PORT)?;
    sock_data.listen(10)?;

    let sock_sfp = Socket::new(socket_opts::NONE).unwrap();
    sock_sfp.bind(SFP_PORT)?;
    sock_sfp.listen(10)?;

    let mut count = 0u64;
    let start_time = Instant::now();
    let mut last_log = Instant::now();
    let mut bytes_recv = 0u64;
    let mut errors = 0u64;

    println!(
        "[RX] Ready to receive on ports {} (DATA) and {} (SFP)...",
        DATA_PORT, SFP_PORT
    );

    loop {
        // ── Data port (Normal / RDP) ──────────────────────────────────────
        //
        // accept(0) is non-blocking: returns immediately if no connection is
        // queued rather than sleeping for up to 100ms. This lets us service
        // the SFP socket without a fixed per-socket dead time each iteration.
        if let Some(conn) = sock_data.accept(0) {
            let src_addr = conn.src_addr();
            let src_port = conn.src_port();
            let is_rdp = (conn.flags() & libcsp::sys::CSP_FRDP as i32) != 0;
            if is_rdp {
                println!("[RX] RDP session started from {}:{}", src_addr, src_port);
            }

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
                    eprintln!(
                        "[RX] DATA ERROR from {}:{} at count {}! Got {} bytes",
                        src_addr,
                        src_port,
                        pkt_count,
                        data.len()
                    );
                    errors += 1;
                }
                bytes_recv += data.len() as u64;
                count += 1;

                if count.is_multiple_of(100) {
                    println!(
                        "[RX] Received 100 packets (latest count={}, from {}:{})",
                        pkt_count, src_addr, src_port
                    );
                }
            }

            if is_rdp {
                println!("[RX] RDP session closed from {}:{}", src_addr, src_port);
            }
        }

        // ── SFP port ─────────────────────────────────────────────────────
        //
        // The TX keeps one connection open and calls sfp_send() in a loop.
        // We must loop on sfp_recv() here to drain all blobs from that one
        // connection before it drops. If we only called sfp_recv() once and
        // then dropped `conn`, csp_close() would be called while the TX
        // still holds its end open, causing every subsequent sfp_send() to
        // fail and forcing a reconnect per blob.
        if let Some(conn) = sock_sfp.accept(0) {
            let src_addr = conn.src_addr();
            let is_rdp = (conn.flags() & libcsp::sys::CSP_FRDP as i32) != 0;
            if is_rdp {
                println!("[RX] SFP/RDP session started from {}", src_addr);
            } else {
                println!("[RX] SFP session started from {}", src_addr);
            }

            while let Ok(data) = conn.sfp_recv(500) {
                let data: Vec<u8> = data;
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
                    eprintln!(
                        "[RX] SFP DATA ERROR from {} at count {}! Got {} bytes",
                        src_addr,
                        pkt_count,
                        data.len()
                    );
                    errors += 1;
                }
                bytes_recv += data.len() as u64;
                count += 1;
                println!(
                    "[RX] SFP blob {}: {} bytes from {}",
                    pkt_count,
                    data.len(),
                    src_addr
                );
            }

            if is_rdp {
                println!("[RX] SFP/RDP session closed from {}", src_addr);
            }
        }
        // ── Idle sleep ────────────────────────────────────────────────────
        //
        // Both accept(0) calls returned None — nothing arrived on either
        // socket. Sleep briefly to avoid burning a full CPU core on busy-
        // polling. 1ms is short enough to not miss any traffic at 200 PPS.
        //
        // Previously the code used accept(100) which spent up to 100ms per
        // socket per loop iteration even when the other socket was active.
        // That wasted 100ms between every SFP blob (5× the blob interval),
        // cutting SFP throughput to ~20 % of what the sender produced.
        else {
            thread::sleep(Duration::from_millis(1));
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            let elapsed = start_time.elapsed().as_secs_f64();
            println!(
                "[Stats] Recv {} MB total, Errors: {}, Avg Rate: {:.2} KB/s",
                bytes_recv / 1024 / 1024,
                errors,
                (bytes_recv as f64 / 1024.0) / elapsed
            );
            last_log = Instant::now();
        }
    }
}
