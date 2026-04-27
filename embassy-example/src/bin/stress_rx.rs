#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec;
use rtt_target::{rtt_init_print, rprintln};
use embassy_executor::Spawner;
use embassy_stm32::can::Can;
use embassy_stm32::peripherals::CAN1;
use embassy_stm32::bind_interrupts;
use embassy_time::{Duration, Instant, Timer};
use libcsp::{CspConfig, Packet, CspInterface, interface, InterfaceHandle, socket_opts};
use panic_probe as _;
use static_cell::StaticCell;
use embassy_example::Prng;

// --- SHARED STRESS LOGIC (Synchronized with Linux) ---
const PRNG_SEED: u32 = 0x12345678;
const DATA_PORT: u8 = 10;
const SFP_PORT: u8 = 11;

bind_interrupts!(struct Irqs {
    CAN1_TX => embassy_stm32::can::TxInterruptHandler<CAN1>;
    CAN1_RX0 => embassy_stm32::can::Rx0InterruptHandler<CAN1>;
    CAN1_RX1 => embassy_stm32::can::Rx1InterruptHandler<CAN1>;
    CAN1_SCE => embassy_stm32::can::SceInterruptHandler<CAN1>;
});

// Use shared arch implementation from lib
use embassy_example::ARCH;

// Use the export_arch! macro to generate all CSP arch C shims automatically
libcsp::export_arch!(embassy_example::EmbassyArch, ARCH);

struct Stm32CanIface { tx: embassy_stm32::can::CanTx<'static, 'static, CAN1> }
impl CspInterface for Stm32CanIface {
    fn name(&self) -> &str { "CAN" }
    fn nexthop(&mut self, via: u16, pkt: Packet, _from_me: bool) {
        // Toy encoding (see stress_tx.rs for the same caveat).
        use embassy_stm32::can::bxcan::{ExtendedId, Frame, Data, Id};
        let Some(id) = ExtendedId::new(via as u32) else { return };
        let payload = pkt.data();
        let chunk = &payload[..payload.len().min(8)];
        if let Some(data) = Data::new(chunk) {
            let _ = self.tx.try_write(&Frame::new_data(Id::Extended(id), data));
        }
    }
}

static CAN_BUS: StaticCell<Can<'static, CAN1>> = StaticCell::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    rtt_init_print!();
    for _ in 0..10_000_000 { cortex_m::asm::nop(); }
    rprintln!("--- STM32 STRESS RECEIVER START ---");

    let p = embassy_stm32::init(Default::default());

    {
        use core::mem::MaybeUninit;
        static mut HEAP_MEM: [MaybeUninit<u8>; 65536] = [MaybeUninit::uninit(); 65536];
        unsafe { embassy_example::HEAP.init(core::ptr::addr_of!(HEAP_MEM) as usize, 65536) }
    }

    let node = CspConfig::new()
        .address(2)
        .init()
        .expect("CSP INIT FAIL");

    let mut can = Can::new(p.CAN1, p.PA11, p.PA12, Irqs);
    let _ = can.as_mut().modify_config().set_loopback(false).set_silent(false);
    can.set_bitrate(1_000_000);
    can.enable().await;
    
    let can_static = CAN_BUS.init(can);
    let (tx, rx) = can_static.split();
    let handle = interface::register(Stm32CanIface { tx });
    
    node.route_load("1 CAN").unwrap();
    spawner.spawn(csp_router_task(node)).unwrap();
    spawner.spawn(can_rx_task(rx, handle)).unwrap();

    let mut count = 0u64;
    let mut bytes_recv = 0u64;
    let mut errors = 0u64;
    let mut last_log = Instant::now();

    let mut server = libcsp::Dispatcher::new();
    
    // 1. DATA PORT (Normal / RDP)
    server.register(DATA_PORT, move |conn, pkt| {
        let src_addr = conn.src_addr();
        let data = pkt.data();
        
        if data.len() >= 8 {
            let mut count_buf = [0u8; 8];
            count_buf.copy_from_slice(&data[0..8]);
            let pkt_count = u64::from_le_bytes(count_buf);
            
            let mut expected = vec![0u8; data.len()];
            expected[0..8].copy_from_slice(&count_buf);
            let mut packet_prng = Prng::new(PRNG_SEED ^ (pkt_count as u32));
            packet_prng.fill(&mut expected[8..]);

            if data != expected {
                rprintln!("[RX] DATA ERR count {} from {}", pkt_count, src_addr);
            }
            count += 1;
            
            if count % 100 == 0 {
                rprintln!("[RX] Recv 100 pkts (last count={}, from node {})", pkt_count, src_addr);
            }
        }
        None
    }).unwrap();

    // 2. SFP PORT
    let mut sfp_sock = libcsp::Socket::new(socket_opts::NONE);
    sfp_sock.bind(SFP_PORT).unwrap();
    sfp_sock.listen(5).unwrap();

    rprintln!("!!! READY !!!");

    loop {
        server.run(10);
        
        if let Some(conn) = sfp_sock.accept(0) {
            let src_addr = conn.src_addr();
            rprintln!("[RX] SFP start from {}...", src_addr);
            match conn.sfp_recv(1000) {
                Ok(data) => {
                    if data.len() >= 8 {
                        let mut count_buf = [0u8; 8];
                        count_buf.copy_from_slice(&data[0..8]);
                        let pkt_count = u64::from_le_bytes(count_buf);

                        let mut expected = vec![0u8; data.len()];
                        expected[0..8].copy_from_slice(&count_buf);
                        let mut blob_prng = Prng::new(PRNG_SEED ^ (pkt_count as u32));
                        blob_prng.fill(&mut expected[8..]);

                        if data != expected {
                            rprintln!("[RX] SFP DATA ERR count {} from {}", pkt_count, src_addr);
                            errors += 1;
                        } else {
                            rprintln!("[RX] SFP ok: received {} bytes from {} (count={})", data.len(), src_addr, pkt_count);
                        }
                        bytes_recv += data.len() as u64;
                    }
                }
                Err(e) => {
                    rprintln!("[RX] SFP FAIL from {}: {:?}", src_addr, e);
                    errors += 1;
                }
            }
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            rprintln!("[Stats] Recv {} KB, Errors {}, Uptime {}s", 
                bytes_recv / 1024, 
                errors,
                Instant::now().as_secs()
            );
            last_log = Instant::now();
        }
        Timer::after(Duration::from_millis(1)).await;
    }
}

#[embassy_executor::task]
async fn can_rx_task(mut rx: embassy_stm32::can::CanRx<'static, 'static, CAN1>, handle: InterfaceHandle) {
    loop {
        let envelope = rx.read().await.unwrap();
        if let Some(data) = envelope.frame.data() {
            if let Some(mut pkt) = Packet::get(data.len() as usize) {
                pkt.write(data.as_ref()).unwrap();
                handle.rx(pkt);
            }
        }
    }
}

#[embassy_executor::task]
async fn csp_router_task(node: libcsp::CspNode) {
    loop {
        let _ = node.route_work();
        Timer::after(Duration::from_millis(1)).await;
    }
}
