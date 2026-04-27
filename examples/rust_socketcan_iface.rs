//! Example: Implementing a CSP Interface using the Rust `socketcan` crate.
//!
//! This shows how to plug a Rust SocketCAN driver into the CSP stack via the
//! [`CspInterface`] trait. The CAN-frame encoding here is **illustrative only**
//! — a production CSP-on-CAN deployment must use the CFP fragmentation
//! protocol (multiple CAN frames per CSP packet) which is non-trivial. Use
//! `node.add_interface_socketcan(...)` for real CFP-compliant CAN; this
//! example is meant to demonstrate the safe-trait wiring, not the wire
//! format.
//!
//! Run with: `cargo run --example rust_socketcan_iface --features socketcan`.

use libcsp::{interface, CspConfig, CspInterface, Packet, Priority};
use socketcan::{CanFrame, CanSocket, EmbeddedFrame, ExtendedId, Id, Socket};
use std::sync::Arc;
use std::thread;

struct RustCanIface {
    name: String,
    socket: Arc<CanSocket>,
}

impl CspInterface for RustCanIface {
    fn name(&self) -> &str {
        &self.name
    }

    fn nexthop(&mut self, via: u16, pkt: Packet, _from_me: bool) {
        // Toy encoding: stuff the next-hop address into the CAN ID and the
        // first 8 bytes of the CSP payload into the CAN frame. A real driver
        // must implement CFP fragmentation across multiple frames.
        let Some(can_id) = ExtendedId::new(via as u32) else {
            return;
        };
        let payload = pkt.data();
        let chunk = &payload[..payload.len().min(8)];
        if let Some(frame) = CanFrame::new(Id::Extended(can_id), chunk) {
            let _ = self.socket.write_frame(&frame);
        }
        // pkt is dropped (and freed) when this scope exits.
    }
}

fn main() -> anyhow::Result<()> {
    let iface_name = "vcan0";
    let socket = Arc::new(CanSocket::open(iface_name).map_err(|e| {
        anyhow::anyhow!(
            "Failed to open {}: {}. Ensure it exists: \
             sudo ip link add dev vcan0 type vcan && sudo ip link set vcan0 up",
            iface_name,
            e,
        )
    })?);

    let node = CspConfig::new().address(1).init().expect("CSP init failed");

    let can_iface = RustCanIface {
        name: "RUST_CAN".to_string(),
        socket: Arc::clone(&socket),
    };
    let handle = interface::register(can_iface);

    let rx_handle = handle;
    let rx_socket = Arc::clone(&socket);
    thread::spawn(move || {
        println!("RX Thread: Listening on vcan0...");
        loop {
            if let Ok(frame) = rx_socket.read_frame() {
                let data = EmbeddedFrame::data(&frame);
                if let Some(mut pkt) = Packet::get(data.len()) {
                    if pkt.write(data).is_ok() {
                        rx_handle.rx(pkt);
                    }
                }
            }
        }
    });

    node.route_load("2 RUST_CAN").unwrap();
    node.route_start_task(4096, 0).unwrap();

    println!("Interface registered and RX thread started.");
    println!("Sending test packet to node 2...");

    let conn = node
        .connect(Priority::Norm, 2, 10, 1000, libcsp::conn_opts::NONE)
        .expect("Connect failed");
    let mut pkt = Packet::get(16).unwrap();
    pkt.write(b"Rust SocketCAN!").unwrap();
    conn.send(pkt);

    thread::sleep(std::time::Duration::from_secs(1));
    Ok(())
}
