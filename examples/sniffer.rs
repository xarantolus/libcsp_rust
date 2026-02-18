//! CSP Sniffer using Rust `socketcan` crate.
//!
//! Captures and decodes all CSP traffic on a Linux CAN interface.
//!
//! Usage: cargo run --example sniffer [interface_name]
//! Default interface: vcan0

use libcsp::{CspConfig, Packet, CspInterface, interface, promisc};
use socketcan::{CanSocket, Socket, CanFrame, EmbeddedFrame, Frame};
use std::sync::Arc;
use std::thread;
use std::env;
use std::collections::HashSet;

/// Custom interface that bridges Rust `socketcan` to CSP.
struct RustCanIface {
    name: String,
    _socket: Arc<CanSocket>,
}

impl CspInterface for RustCanIface {
    fn name(&self) -> &str { &self.name }
    fn nexthop(&mut self, _via: u8, _pkt: Packet) {}
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let iface_name = args.get(1).map(|s| s.as_str()).unwrap_or("vcan0");

    println!("Starting CSP Sniffer on {}...", iface_name);

    let socket = Arc::new(CanSocket::open(iface_name).map_err(|e| {
        anyhow::anyhow!("Failed to open {}: {}. Ensure it exists.", iface_name, e)
    })?);

    let node = CspConfig::new()
        .address(10) 
        .buffers(100, 256)
        .init()
        .expect("CSP init failed");

    let handle = interface::register(RustCanIface {
        name: "CAN".to_string(),
        _socket: Arc::clone(&socket),
    });

    let rx_handle = handle.clone();
    let rx_socket = Arc::clone(&socket);
    thread::spawn(move || {
        loop {
            if let Ok(frame) = rx_socket.read_frame() {
                let data = EmbeddedFrame::data(&frame);
                if let Some(mut pkt) = Packet::get(data.len()) {
                    pkt.set_id_raw(frame.raw_id());
                    pkt.write(data).unwrap();
                    rx_handle.rx(pkt);
                }
            }
        }
    });

    node.route_start_task(4096, 0).unwrap();
    let sniffer = promisc::Sniffer::open(100).expect("Failed to enable promisc mode");

    // Track active RDP connections to detect start/end
    // Key: (src, dst, sport, dport)
    let mut active_rdp = HashSet::new();

    println!("\n{:<5} | {:<12} | {:<12} | {:<5} | {:<5} | {}", "PRIO", "SOURCE", "DEST", "SIZE", "RDP", "FLAGS/EVENT");
    println!("{:-<100}", "");

    loop {
        if let Some(pkt) = sniffer.read(1000) {
            let src = pkt.src_addr();
            let dst = pkt.dst_addr();
            let sport = pkt.src_port();
            let dport = pkt.dst_port();
            let size = pkt.length();
            
            let prio = match pkt.priority() {
                0 => "CRIT", 1 => "HIGH", 2 => "NORM", 3 => "LOW ", _ => "UNKN",
            };

            let mut flags = Vec::new();
            if pkt.is_rdp()   { flags.push("RDP"); }
            if pkt.is_xtea()  { flags.push("XTEA"); }
            if pkt.is_hmac()  { flags.push("HMAC"); }
            if pkt.is_crc32() { flags.push("CRC"); }
            if pkt.is_frag()  { flags.push("FRAG"); }

            let mut event = "";
            let conn_key = (src, dst, sport, dport);

            // RDP State Detection
            // We look for SYN/FIN flags in the CSP header to track sessions
            let raw_flags = pkt.id_raw() & 0xFF;
            const CSP_FRES1: u32 = 0x80;
            const CSP_FRES2: u32 = 0x40;
            const CSP_FRES3: u32 = 0x20;
            
            // In CSP 1.6, RDP control is handled via FRES bits or payload, 
            // but we can infer OPEN/CLOSE from the RDP flag bit presence.
            if pkt.is_rdp() {
                if !active_rdp.contains(&conn_key) {
                    active_rdp.insert(conn_key);
                    event = ">>> [RDP SESSION START]";
                }
            } else if active_rdp.contains(&conn_key) {
                active_rdp.remove(&conn_key);
                event = "<<< [RDP SESSION END/RESET]";
            }

            println!(
                "{:<5} | {:>2}:{:0>2}       | {:>2}:{:0>2}       | {:>4}B | {:<5} | {:02X} {} {}",
                prio,
                src, sport,
                dst, dport,
                size,
                if pkt.is_rdp() { "YES" } else { "NO" },
                raw_flags,
                flags.join(","),
                event
            );
        }
    }
}
