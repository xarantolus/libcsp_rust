#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec;
use rtt_target::{rtt_init_print, rprintln};
use embassy_executor::Spawner;
use embassy_stm32::can::Can;
use embassy_stm32::peripherals::CAN1;
use embassy_stm32::bind_interrupts;
use embassy_time::{Duration, Instant, Timer, Ticker};
use libcsp::{CspConfig, Packet, CspInterface, interface, InterfaceHandle, Priority, socket_opts, conn_opts, Connection};
use panic_probe as _;
use static_cell::StaticCell;
use embassy_example::Prng;

// --- SHARED STRESS LOGIC ---
const PRNG_SEED: u32 = 0x12345678;
const DATA_PORT: u8 = 10;
const SFP_PORT: u8 = 11;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolMode { Normal, Rdp, SFP, RdpSfp }
impl ProtocolMode {
    pub fn to_str(&self) -> &'static str {
        match self {
            ProtocolMode::Normal => "NORMAL",
            ProtocolMode::Rdp => "RDP",
            ProtocolMode::SFP => "SFP",
            ProtocolMode::RdpSfp => "RDP+SFP",
        }
    }
}

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
        // Toy encoding: real CSP-on-CAN needs CFP fragmentation and packs the
        // 6-byte v2 (or 4-byte v1) header into the 29-bit extended ID. This
        // stress test just stuffs the via-address into the ID and the first
        // 8 payload bytes into a single CAN frame.
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
    rprintln!("--- STM32 CONSISTENT LOAD SENDER ---");

    let p = embassy_stm32::init(Default::default());

    {
        use core::mem::MaybeUninit;
        static mut HEAP_MEM: [MaybeUninit<u8>; 65536] = [MaybeUninit::uninit(); 65536];
        unsafe { embassy_example::HEAP.init(core::ptr::addr_of!(HEAP_MEM) as usize, 65536) }
    }

    let node = CspConfig::new()
        .address(1)
        .init()
        .expect("CSP INIT FAIL");

    // Make RDP aggressive
    node.rdp_set_opt(20, 500, 100, 1, 100, 2);

    let mut can = Can::new(p.CAN1, p.PA11, p.PA12, Irqs);
    let _ = can.as_mut().modify_config().set_loopback(false).set_silent(false);
    can.set_bitrate(1_000_000);
    can.enable().await;
    
    let can_static = CAN_BUS.init(can);
    let (tx, rx) = can_static.split();
    let handle = interface::register(Stm32CanIface { tx });
    
    node.route_load("2 CAN").unwrap();
    spawner.spawn(csp_router_task(node.clone())).unwrap();
    spawner.spawn(can_rx_task(rx, handle)).unwrap();

    let mut count = 0u64;
    let mut bytes_sent = 0u64;
    let mut last_log = Instant::now();
    let mut mode_start = Instant::now();

    let mut current_mode = ProtocolMode::Normal;
    let mut active_conn: Option<Connection> = None;

    // 200 PPS = 5ms
    let mut ticker = Ticker::every(Duration::from_millis(5));

    rprintln!("!!! SENDER READY !!!");

    loop {
        ticker.next().await;

        // 1. Mode Switch (10s)
        if mode_start.elapsed() >= Duration::from_secs(10) {
            let next_mode = match current_mode {
                ProtocolMode::Normal => ProtocolMode::Rdp,
                ProtocolMode::Rdp => ProtocolMode::SFP,
                ProtocolMode::SFP => ProtocolMode::RdpSfp,
                ProtocolMode::RdpSfp => ProtocolMode::Normal,
            };
            rprintln!("[TX] MODE END: {}", current_mode.to_str());
            rprintln!("[TX] Quiesce 500ms...");
            
            active_conn = None; 
            Timer::after(Duration::from_millis(500)).await;
            
            current_mode = next_mode;
            mode_start = Instant::now();
            rprintln!("[TX] MODE START: {}", current_mode.to_str());
        }

        // 2. Mode Logic
        match current_mode {
            ProtocolMode::Normal => {
                if let Some(mut pkt) = Packet::get(200) {
                    let mut data = [0u8; 200];
                    data[0..8].copy_from_slice(&count.to_le_bytes());
                    let mut packet_prng = Prng::new(PRNG_SEED ^ (count as u32));
                    packet_prng.fill(&mut data[8..]);
                    pkt.write(&data).unwrap();
                    node.sendto(Priority::Norm, 2, DATA_PORT, 10, socket_opts::NONE, pkt);
                    bytes_sent += 200;
                    count += 1;
                }
            }
            ProtocolMode::Rdp => {
                if active_conn.is_none() {
                    active_conn = node.connect(Priority::Norm, 2, DATA_PORT, 100, conn_opts::RDP);
                    if active_conn.is_none() { continue; }
                }
                let conn = active_conn.as_ref().unwrap();
                if let Some(mut pkt) = Packet::get(200) {
                    let mut data = [0u8; 200];
                    data[0..8].copy_from_slice(&count.to_le_bytes());
                    let mut packet_prng = Prng::new(PRNG_SEED ^ (count as u32));
                    packet_prng.fill(&mut data[8..]);
                    pkt.write(&data).unwrap();
                    conn.send(pkt);
                    bytes_sent += 200;
                    count += 1;
                }
            }
            ProtocolMode::SFP | ProtocolMode::RdpSfp => {
                if active_conn.is_none() {
                    let opts = if current_mode == ProtocolMode::RdpSfp { conn_opts::RDP } else { conn_opts::NONE };
                    active_conn = node.connect(Priority::Norm, 2, SFP_PORT, 100, opts);
                    if active_conn.is_none() { continue; }
                }
                let conn = active_conn.as_ref().unwrap();
                let size = 600;
                let mut data = vec![0u8; size as usize];
                data[0..8].copy_from_slice(&count.to_le_bytes());
                let mut blob_prng = Prng::new(PRNG_SEED ^ (count as u32));
                blob_prng.fill(&mut data[8..]);

                if conn.sfp_send(&data, 180, 100).is_ok() {
                    bytes_sent += size as u64;
                    count += 1;
                    let burst_packets = (size / 180) + 1;
                    for _ in 0..burst_packets { ticker.next().await; }
                } else { active_conn = None; }
            }
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            rprintln!("[Stats] Mode {}, count {}, sent {} KB", current_mode.to_str(), count, bytes_sent / 1024);
            last_log = Instant::now();
        }
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
