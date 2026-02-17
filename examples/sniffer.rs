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

/// Custom interface that bridges Rust `socketcan` to CSP.
struct RustCanIface {
    name: String,
    _socket: Arc<CanSocket>,
}

impl CspInterface for RustCanIface {
    fn name(&self) -> &str {
        &self.name
    }

    fn nexthop(&mut self, _via: u8, _pkt: Packet) {
        // Sniffer is mostly passive, but we could implement TX here if needed.
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    let iface_name = args.get(1).map(|s| s.as_str()).unwrap_or("vcan0");

    println!("Starting CSP Sniffer on {}...", iface_name);

    // 1. Open the Rust CAN socket
    let socket = Arc::new(CanSocket::open(iface_name).map_err(|e| {
        anyhow::anyhow!("Failed to open {}: {}. Ensure it exists: sudo ip link add dev vcan0 type vcan && sudo ip link set vcan0 up", iface_name, e)
    })?);

    // 2. Initialise CSP
    let node = CspConfig::new()
        .address(10) 
        .buffers(100, 256)
        .init()
        .expect("CSP init failed");

    // 3. Register the interface
    let can_iface = RustCanIface {
        name: "CAN".to_string(),
        _socket: Arc::clone(&socket),
    };
    let handle = interface::register(can_iface);

    // 4. Start RX thread (This feeds the CSP router)
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

    // 5. Start router and enable promiscuous mode
    node.route_start_task(4096, 0).unwrap();
    let sniffer = promisc::Sniffer::open(50).expect("Failed to enable promisc mode");

    println!("\n{:<4} {:<4} -> {:<4} | {:<5} -> {:<5} | {:<5} | Flags", "PRI", "SRC", "DST", "SPORT", "DPORT", "SIZE");
    println!("{:-<70}", "");

    loop {
        if let Some(pkt) = sniffer.read(1000) {
            let prio = match pkt.priority() {
                0 => "CRIT",
                1 => "HIGH",
                2 => "NORM",
                3 => "LOW ",
                _ => "UNKN",
            };

            let mut flags = Vec::new();
            if pkt.is_rdp()   { flags.push("RDP"); }
            if pkt.is_xtea()  { flags.push("XTEA"); }
            if pkt.is_hmac()  { flags.push("HMAC"); }
            if pkt.is_crc32() { flags.push("CRC"); }
            if pkt.is_frag()  { flags.push("FRAG"); }
            
            println!(
                "{:<4} {:>3}  -> {:>3}  | {:>5} -> {:>5} | {:>5} | {}",
                prio,
                pkt.src_addr(),
                pkt.dst_addr(),
                pkt.src_port(),
                pkt.dst_port(),
                pkt.length(),
                flags.join(", ")
            );
        }
    }
}
