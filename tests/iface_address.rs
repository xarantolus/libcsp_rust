//! A custom interface's address becomes the source of packets sent through
//! it. Runs in its own process, so it owns the global stack.

use std::sync::mpsc;

use libcsp::interface::{self, CspInterface};
use libcsp::{socket_opts, CspConfig, Packet, Priority};

struct Capture(mpsc::Sender<u16>);

impl CspInterface for Capture {
    fn nexthop(&mut self, _via: u16, packet: Packet, _from_me: bool) {
        let _ = self.0.send(packet.src_addr());
    }
    fn name(&self) -> &str {
        "CAP"
    }
}

#[test]
fn packets_sent_through_an_interface_carry_its_address() {
    let node = CspConfig::new().address(2).version(1).init().expect("init");
    let (tx, rx) = mpsc::channel();
    let iface = interface::try_register(Capture(tx)).unwrap();
    assert_eq!(iface.address(), 0, "a new interface has no address");
    iface.set_address(2, 0);
    assert_eq!(iface.address(), 2);
    libcsp::route::load("0/0 CAP").unwrap();
    node.route_start_task(0, 0).unwrap();

    let mut p = Packet::get(0).unwrap();
    p.write(b"\x01").unwrap();
    node.sendto(Priority::Norm, 13, 20, 53, socket_opts::NONE, p);

    let src = rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .expect("packet sent");
    assert_eq!(src, 2);
}
