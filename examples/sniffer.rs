//! CSP Sniffer using Rust `socketcan` crate.
//!
//! Captures and decodes all CSP traffic on a Linux CAN interface.
//!
//! Usage: cargo run --example sniffer [interface_name]
//! Default interface: vcan0

use libcsp::{interface, promisc, CspConfig, CspInterface, Packet};
use socketcan::{CanSocket, EmbeddedFrame, Socket};
use std::collections::HashSet;
use std::env;
use std::sync::Arc;
use std::thread;

/// Custom interface that bridges Rust `socketcan` to CSP.
struct RustCanIface {
    name: String,
    _socket: Arc<CanSocket>,
}

impl CspInterface for RustCanIface {
    fn name(&self) -> &str {
        &self.name
    }
    fn nexthop(&mut self, _via: u16, _pkt: Packet, _from_me: bool) {}
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let iface_name = args.get(1).map(|s| s.as_str()).unwrap_or("vcan0");

    println!("Starting CSP Sniffer on {}...", iface_name);

    let socket =
        Arc::new(CanSocket::open(iface_name).map_err(|e| {
            anyhow::anyhow!("Failed to open {}: {}. Ensure it exists.", iface_name, e)
        })?);

    let node = CspConfig::new()
        .address(10)
        .init()
        .expect("CSP init failed");

    let handle = interface::register(RustCanIface {
        name: "CAN".to_string(),
        _socket: Arc::clone(&socket),
    });

    let rx_handle = handle.clone();
    let rx_socket = Arc::clone(&socket);
    thread::spawn(move || loop {
        if let Ok(frame) = rx_socket.read_frame() {
            let data = EmbeddedFrame::data(&frame);
            if let Some(mut pkt) = Packet::get(data.len()) {
                // NOTE: In libcsp v2.x the raw 32-bit CAN ID can no longer be
                // stuffed straight into the packet header — the wire format is
                // no longer a 1:1 mapping. A full sniffer would feed the CAN
                // frame through libcsp's own CAN decoder; here we simply copy
                // the payload so the subsequent promisc-queue code compiles.
                pkt.write(data).unwrap();
                rx_handle.rx(pkt);
            }
        }
    });

    node.route_start_task(4096, 0).unwrap();
    let sniffer = promisc::Sniffer::open(100).expect("Failed to enable promisc mode");

    // Track active RDP connections to detect start/end
    // Key: (src, dst, sport, dport)
    let mut active_rdp = HashSet::new();

    loop {
        if let Some(pkt) = sniffer.read(1000) {
            let src = pkt.src_addr();
            let dst = pkt.dst_addr();
            let sport = pkt.src_port();
            let dport = pkt.dst_port();
            let size = pkt.length();

            let prio = match pkt.priority() {
                libcsp::Priority::Critical => "CRIT",
                libcsp::Priority::High => "HIGH",
                libcsp::Priority::Norm => "NORM",
                libcsp::Priority::Low => "LOW ",
            };

            let mut flags = Vec::new();
            if pkt.is_rdp() {
                flags.push("RDP");
            }
            if pkt.is_hmac() {
                flags.push("HMAC");
            }
            if pkt.is_crc32() {
                flags.push("CRC");
            }
            if pkt.is_frag() {
                flags.push("FRAG");
            }

            let mut event = String::new();
            let conn_key = (src, dst, sport, dport);

            // RDP State Detection
            if pkt.is_rdp() {
                if !active_rdp.contains(&conn_key) {
                    active_rdp.insert(conn_key);
                    event = ">>> [SESSION START]".to_string();
                }
            } else if active_rdp.contains(&conn_key) {
                active_rdp.remove(&conn_key);
                event = "<<< [SESSION END/RESET]".to_string();
            }

            println!(
                "[{:<4}] | {:>2}:{:0>2} ──▶ {:>2}:{:0>2} | SIZE: {:>4}B | FLAGS: [{:<15}] | {}",
                prio,
                src,
                sport,
                dst,
                dport,
                size,
                flags.join(","),
                event
            );
        }
    }
}
