//! Example: Implementing a custom CSP interface (transport).
//!
//! This demonstrates how to bridge a custom hardware driver (e.g., an STM32 CAN
//! peripheral) into the CSP stack by implementing the `csp_iface_t` callbacks.

use libcsp::{sys, CspConfig, Packet, Priority};
use std::ffi::CString;

/// Our custom device state.
struct MyDevice {
    name: CString,
    iface: sys::csp_iface_t,
}

impl MyDevice {
    fn new(name: &str) -> Box<Self> {
        let name_cstr = CString::new(name).unwrap();
        
        let mut dev = Box::new(MyDevice {
            name: name_cstr,
            iface: unsafe { std::mem::zeroed() },
        });

        // Setup the interface struct
        dev.iface.name = dev.name.as_ptr();
        dev.iface.nexthop = Some(my_nexthop);
        dev.iface.interface_data = &mut *dev as *mut MyDevice as *mut _;
        dev.iface.mtu = 256;

        dev
    }

    fn register(&mut self) {
        unsafe {
            sys::csp_iflist_add(&mut self.iface);
        }
    }
}

/// In libcsp 1.6, nexthop signature is:
/// int (*nexthop)(const csp_route_t *route, csp_packet_t *packet);
unsafe extern "C" fn my_nexthop(
    route: *const sys::csp_route_t,
    packet: *mut sys::csp_packet_t,
) -> i32 {
    // 1. Recover the interface from the route
    let iface = (*route).iface;
    let dev_ptr = (*iface).interface_data as *mut MyDevice;
    let _dev = &mut *dev_ptr;
    
    // 2. Reconstruct the Packet so we have safe access
    let pkt = Packet::from_raw(packet);

    println!(
        "TX on interface '{}': sending {} bytes to via={}",
        std::ffi::CStr::from_ptr((*iface).name).to_string_lossy(),
        pkt.length(),
        (*route).via
    );

    // 3. Return CSP_ERR_NONE (0) on success.
    // Packet is dropped here, which calls csp_buffer_free.
    0
}

/// Simulate receiving a packet from the hardware.
fn simulate_rx(iface: &mut sys::csp_iface_t, data: &[u8]) {
    let mut pkt = Packet::get(data.len()).expect("no buffers");
    pkt.write(data).expect("data too large");
    
    println!("RX: Handing {} bytes to CSP router", data.len());
    unsafe {
        let raw = pkt.into_raw();
        // csp_qfifo_write(packet, iface, pxTaskWoken)
        sys::csp_qfifo_write(raw, iface, std::ptr::null_mut());
        // Note: csp_qfifo_write in 1.6 doesn't return a code, 
        // it internally handles the queueing. If it fails, 
        // the packet is usually lost/freed or ignored.
    }
}

fn main() {
    let node = CspConfig::new()
        .address(1)
        .buffers(10, 256)
        .init()
        .expect("init failed");

    let mut my_dev = MyDevice::new("MY_CAN");
    my_dev.register();

    node.route_load("2 MY_CAN").expect("route load failed");

    #[cfg(feature = "debug")]
    {
        println!("Custom interface registered. Routing table:");
        libcsp::route::print();
    }

    println!("\n--- Testing TX ---");
    if let Some(conn) = node.connect(Priority::Norm as u8, 2, 10, 100, 0) {
        let mut pkt = Packet::get(16).unwrap();
        pkt.write(b"payload to node 2").unwrap();
        let _ = conn.send_discard(pkt, 100);
    }

    println!("\n--- Testing RX ---");
    simulate_rx(&mut my_dev.iface, b"incoming data");

    node.route_work(100).unwrap();
}
