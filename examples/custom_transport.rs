//! Example: Implementing a custom CSP interface using the safe Trait.
//!
//! This demonstrates how to bridge a custom hardware driver (e.g., an STM32 CAN
//! peripheral) into the CSP stack using the `CspInterface` trait.

use libcsp::{interface, CspConfig, CspInterface, Packet, Priority};

/// Our custom device implementation.
struct MyHardware {
    name: String,
}

impl CspInterface for MyHardware {
    fn nexthop(&mut self, via: u16, pkt: Packet, from_me: bool) {
        println!(
            "[{}] TX: {} bytes to via={} (from_me={})",
            self.name,
            pkt.length(),
            via,
            from_me
        );
        // Packet is dropped and freed here
    }

    fn name(&self) -> &str {
        &self.name
    }
}

fn main() {
    // 1. Initialise CSP
    let node = CspConfig::new()
        .address(1)
        .init()
        .expect("init failed");

    // 2. Register the custom interface
    let my_hw = MyHardware {
        name: "MY_CAN".to_string(),
    };
    let handle = interface::register(my_hw);

    // 3. Set a route through our interface
    node.route_load("2 MY_CAN").expect("route load failed");

    println!("Custom interface registered.");

    // 4. Test TX
    println!("\n--- Testing TX ---");
    if let Some(conn) = node.connect(Priority::Norm, 2, 10, 100, libcsp::conn_opts::NONE) {
        let mut pkt = Packet::get(16_usize).unwrap();
        pkt.write(b"safe trait tx").unwrap();
        conn.send(pkt);
    }

    // 5. Test RX
    println!("\n--- Testing RX ---");
    let mut pkt = Packet::get(10_usize).unwrap();
    pkt.write(b"safe rx").unwrap();
    handle.rx(pkt);

    // Process the received packet
    node.route_work().unwrap();
}
