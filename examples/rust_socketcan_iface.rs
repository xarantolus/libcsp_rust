//! Example: Implementing a CSP Interface using the Rust `socketcan` crate.
//!
//! This shows how to implement a fully custom transport (TX and RX) using
//! safe Rust libraries instead of the built-in C drivers.

use libcsp::{CspConfig, Packet, Priority, CspInterface, interface};
use socketcan::{CanSocket, Socket, CanFrame, EmbeddedFrame, ExtendedId, Id, Frame};
use std::thread;
use std::sync::Arc;

struct RustCanIface {
    name: String,
    socket: Arc<CanSocket>,
}

impl CspInterface for RustCanIface {
    fn name(&self) -> &str {
        &self.name
    }

    fn nexthop(&mut self, _via: u8, pkt: Packet) {
        // 1. Convert CSP packet to CAN frame(s)
        let can_id = pkt.id_raw();
        
        let id = Id::Extended(ExtendedId::new(can_id).unwrap());
        if let Some(frame) = CanFrame::new(id, pkt.data()) {
            let _ = self.socket.write_frame(&frame);
        }
        
        // Packet pkt is dropped and freed here automatically.
    }
}

fn main() -> anyhow::Result<()> {
    // 1. Setup local vcan0 interface
    let iface_name = "vcan0";
    let socket = Arc::new(CanSocket::open(iface_name).map_err(|e| {
        anyhow::anyhow!("Failed to open {}: {}. Ensure it exists: sudo ip link add dev vcan0 type vcan && sudo ip link set vcan0 up", iface_name, e)
    })?);

    // 2. Initialise CSP
    let node = CspConfig::new()
        .address(1)
        .buffers(20, 256)
        .init()
        .expect("CSP init failed");

    // 3. Register our Rust-based interface
    let can_iface = RustCanIface {
        name: "RUST_CAN".to_string(),
        socket: Arc::clone(&socket),
    };
    let handle = interface::register(can_iface);
    
    // 4. Start RX thread
    let rx_handle = handle.clone();
    let rx_socket = Arc::clone(&socket);
    thread::spawn(move || {
        println!("RX Thread: Listening on vcan0...");
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

    // 5. Setup routing
    node.route_load("2 RUST_CAN").unwrap();
    node.route_start_task(4096, 0).unwrap();

    println!("Interface registered and RX thread started.");
    println!("Sending test packet to node 2...");

    // 6. Test TX
    let conn = node.connect(Priority::Norm as u8, 2, 10, 1000, 0).expect("Connect failed");
    let mut pkt = Packet::get(16).unwrap();
    pkt.write(b"Rust SocketCAN!").unwrap();
    conn.send(pkt, 100).unwrap();

    thread::sleep(std::time::Duration::from_secs(1));
    Ok(())
}
