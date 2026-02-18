#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use rtt_target::{rtt_init_print, rprintln};
use embassy_executor::Spawner;
use embassy_stm32::can::Can;
use embassy_stm32::peripherals::CAN1;
use embassy_stm32::bind_interrupts;
use embassy_time::{Duration, Instant, Timer};
use core::ffi::c_void;
use libcsp::{CspArch, CspConfig, Packet, Port, Dispatcher, CspInterface, interface, InterfaceHandle, Priority, socket_opts, conn_opts, Connection};
use panic_probe as _;
use static_cell::StaticCell;

// --- SHARED STRESS LOGIC ---
const PRNG_SEED: u32 = 0x12345678;
const DATA_PORT: u8 = 10;
const SFP_PORT: u8 = 11;

pub struct Prng { state: u32 }
impl Prng {
    pub fn new(seed: u32) -> Self { Self { state: if seed == 0 { 1 } else { seed } } }
    pub fn next(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        self.state = x; x
    }
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_exact_mut(4) {
            let val = self.next();
            chunk.copy_from_slice(&val.to_le_bytes());
        }
        let remaining = buf.len() % 4;
        if remaining > 0 {
            let val = self.next().to_le_bytes();
            let start = buf.len() - remaining;
            buf[start..].copy_from_slice(&val[..remaining]);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolMode { Normal, Rdp, SFP, RdpSfp }
impl ProtocolMode {
    pub fn from_count(count: u64) -> Self {
        match (count / 5000) % 4 {
            0 => ProtocolMode::Normal,
            1 => ProtocolMode::Rdp,
            2 => ProtocolMode::SFP,
            _ => ProtocolMode::RdpSfp,
        }
    }
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

#[global_allocator]
static HEAP: embedded_alloc::Heap = embedded_alloc::Heap::empty();

struct EmbassyArch;
impl CspArch for EmbassyArch {
    fn get_ms(&self) -> u32 { Instant::now().as_millis() as u32 }
    fn get_s(&self) -> u32 { Instant::now().as_secs() as u32 }
    fn bin_sem_create(&self) -> *mut c_void { Box::into_raw(Box::new(core::sync::atomic::AtomicBool::new(true))) as *mut c_void }
    fn bin_sem_remove(&self, sem: *mut c_void) { unsafe { drop(Box::from_raw(sem as *mut core::sync::atomic::AtomicBool)); } }
    fn bin_sem_wait(&self, sem: *mut c_void, _t: u32) -> bool {
        let sem = unsafe { &*(sem as *const core::sync::atomic::AtomicBool) };
        while sem.swap(false, core::sync::atomic::Ordering::Acquire) == false { cortex_m::asm::nop(); }
        true
    }
    fn bin_sem_post(&self, sem: *mut c_void) -> bool {
        let sem = unsafe { &*(sem as *const core::sync::atomic::AtomicBool) };
        sem.store(true, core::sync::atomic::Ordering::Release);
        true
    }
    fn mutex_create(&self) -> *mut c_void { self.bin_sem_create() }
    fn mutex_remove(&self, mutex: *mut c_void) { self.bin_sem_remove(mutex) }
    fn mutex_lock(&self, mutex: *mut c_void, t: u32) -> bool { self.bin_sem_wait(mutex, t) }
    fn mutex_unlock(&self, mutex: *mut c_void) -> bool { self.bin_sem_post(mutex) }
    fn queue_create(&self, _l: usize, _s: usize) -> *mut c_void { Box::into_raw(Box::new(0usize)) as *mut c_void }
    fn queue_remove(&self, q: *mut c_void) { unsafe { drop(Box::from_raw(q as *mut usize)); } }
    fn queue_enqueue(&self, _q: *mut c_void, _i: *const c_void, _t: u32) -> bool { true }
    fn queue_dequeue(&self, _q: *mut c_void, _i: *mut c_void, _t: u32) -> bool { true }
    fn queue_size(&self, _q: *mut c_void) -> usize { 0 }
    fn malloc(&self, size: usize) -> *mut c_void { unsafe { core::alloc::GlobalAlloc::alloc(&HEAP, core::alloc::Layout::from_size_align(size, 4).unwrap()) as *mut c_void } }
    fn free(&self, _ptr: *mut c_void) { }
}

static ARCH: EmbassyArch = EmbassyArch;

#[no_mangle] pub extern "C" fn csp_get_ms() -> u32 { ARCH.get_ms() }
#[no_mangle] pub extern "C" fn csp_get_s() -> u32 { ARCH.get_s() }
#[no_mangle] pub extern "C" fn csp_get_uptime_s() -> u32 { ARCH.get_s() }
#[no_mangle] pub extern "C" fn csp_get_ms_isr() -> u32 { ARCH.get_ms() }
#[no_mangle] pub extern "C" fn csp_bin_sem_create(sem: *mut *mut c_void) -> i32 { let s = ARCH.bin_sem_create(); if s.is_null() { 0 } else { unsafe { *sem = s }; 1 } }
#[no_mangle] pub extern "C" fn csp_bin_sem_remove(sem: *mut *mut c_void) -> i32 { unsafe { ARCH.bin_sem_remove(*sem) }; 1 }
#[no_mangle] pub extern "C" fn csp_bin_sem_wait(sem: *mut *mut c_void, timeout: u32) -> i32 { if unsafe { ARCH.bin_sem_wait(*sem, timeout) } { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn csp_bin_sem_post(sem: *mut *mut c_void) -> i32 { if unsafe { ARCH.bin_sem_post(*sem) } { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn csp_bin_sem_post_isr(sem: *mut *mut c_void, _px: *mut i32) -> i32 { if unsafe { ARCH.bin_sem_post(*sem) } { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn csp_mutex_create(mutex: *mut *mut c_void) -> i32 { let m = ARCH.mutex_create(); if m.is_null() { 0 } else { unsafe { *mutex = m }; 1 } }
#[no_mangle] pub extern "C" fn csp_mutex_remove(mutex: *mut *mut c_void) -> i32 { unsafe { ARCH.mutex_remove(*mutex) }; 1 }
#[no_mangle] pub extern "C" fn csp_mutex_lock(mutex: *mut *mut c_void, timeout: u32) -> i32 { if unsafe { ARCH.mutex_lock(*mutex, timeout) } { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn csp_mutex_unlock(mutex: *mut *mut c_void) -> i32 { if unsafe { ARCH.mutex_unlock(*mutex) } { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn csp_queue_create(l: i32, s: usize) -> *mut c_void { ARCH.queue_create(l as usize, s) }
#[no_mangle] pub extern "C" fn csp_queue_remove(q: *mut c_void) { ARCH.queue_remove(q) }
#[no_mangle] pub extern "C" fn csp_queue_enqueue(q: *mut c_void, i: *const c_void, timeout: u32) -> i32 { if ARCH.queue_enqueue(q, i, timeout) { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn csp_queue_enqueue_isr(q: *mut c_void, i: *const c_void, _p: *mut i32) -> i32 { if ARCH.queue_enqueue(q, i, 0) { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn csp_queue_dequeue(q: *mut c_void, i: *mut c_void, timeout: u32) -> i32 { if ARCH.queue_dequeue(q, i, timeout) { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn csp_queue_dequeue_isr(q: *mut c_void, i: *mut c_void, _p: *mut i32) -> i32 { if ARCH.queue_dequeue(q, i, 0) { 1 } else { 0 } }
#[no_mangle] pub extern "C" fn csp_queue_size(q: *mut c_void) -> i32 { ARCH.queue_size(q) as i32 }
#[no_mangle] pub extern "C" fn csp_queue_size_isr(q: *mut c_void) -> i32 { ARCH.queue_size(q) as i32 }
#[no_mangle] pub extern "C" fn csp_malloc(s: usize) -> *mut c_void { ARCH.malloc(s) }
#[no_mangle] pub extern "C" fn csp_calloc(n: usize, s: usize) -> *mut c_void {
    let t = n * s; let p = ARCH.malloc(t);
    if !p.is_null() { unsafe { core::ptr::write_bytes(p, 0, t) }; }
    p
}
#[no_mangle] pub extern "C" fn csp_free(p: *mut c_void) { ARCH.free(p) }
#[no_mangle] pub extern "C" fn csp_clock_set_time(_a: *const c_void) {}
#[no_mangle] pub extern "C" fn csp_clock_get_time(_a: *mut c_void) {}
#[no_mangle] pub extern "C" fn csp_sys_tasklist_size() -> i32 { 0 }
#[no_mangle] pub extern "C" fn csp_sys_tasklist(_p: *mut i8) {}
#[no_mangle] pub extern "C" fn csp_sys_memfree() -> u32 { 0 }
#[no_mangle] pub extern "C" fn csp_sys_reboot() {}
#[no_mangle] pub extern "C" fn csp_sys_shutdown() {}
#[no_mangle] pub extern "C" fn rand() -> i32 { 0 }
#[no_mangle] pub extern "C" fn srand(_s: u32) {}
#[no_mangle] pub unsafe extern "C" fn strncpy(d: *mut i8, s: *const i8, n: usize) -> *mut i8 {
    let mut i = 0; while i < n && *s.add(i) != 0 { *d.add(i) = *s.add(i); i += 1; }
    while i < n { *d.add(i) = 0; i += 1; } d
}
#[no_mangle] pub unsafe extern "C" fn strcpy(d: *mut i8, s: *const i8) -> *mut i8 {
    let mut i = 0; while *s.add(i) != 0 { *d.add(i) = *s.add(i); i += 1; }
    *d.add(i) = 0; d
}
#[no_mangle] pub unsafe extern "C" fn strnlen(s: *const i8, m: usize) -> usize {
    let mut l = 0; while l < m && *s.add(l) != 0 { l += 1; } l
}
#[no_mangle] pub unsafe extern "C" fn strncasecmp(s1: *const i8, s2: *const i8, n: usize) -> i32 {
    for i in 0..n {
        let c1 = (*s1.add(i) as u8).to_ascii_lowercase();
        let c2 = (*s2.add(i) as u8).to_ascii_lowercase();
        if c1 != c2 || c1 == 0 { return (c1 as i32) - (c2 as i32); }
    } 0
}
#[no_mangle] pub unsafe extern "C" fn strtok_r(_s: *mut i8, _d: *const i8, _p: *mut *mut i8) -> *mut i8 { core::ptr::null_mut() }
#[no_mangle] pub unsafe extern "C" fn sscanf(_s: *const i8, _f: *const i8) -> i32 { 0 }
#[no_mangle] pub extern "C" fn _embassy_time_schedule_wake(_at: u64) {}

struct Stm32CanIface { tx: embassy_stm32::can::CanTx<'static, 'static, CAN1> }
impl CspInterface for Stm32CanIface {
    fn name(&self) -> &str { "CAN" }
    fn nexthop(&mut self, _v: u8, pkt: Packet) {
        use embassy_stm32::can::bxcan::{ExtendedId, Frame, Data, Id};
        if let Some(id) = ExtendedId::new(pkt.id_raw()) {
            if let Some(data) = Data::new(pkt.data()) {
                let _ = self.tx.try_write(&Frame::new_data(Id::Extended(id), data));
            }
        }
    }
}

static CAN_BUS: StaticCell<Can<'static, CAN1>> = StaticCell::new();

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    rtt_init_print!();
    for _ in 0..10_000_000 { cortex_m::asm::nop(); }
    rprintln!("--- STM32 STRESS SENDER START ---");

    let p = embassy_stm32::init(Default::default());

    {
        use core::mem::MaybeUninit;
        static mut HEAP_MEM: [MaybeUninit<u8>; 65536] = [MaybeUninit::uninit(); 65536];
        unsafe { HEAP.init(HEAP_MEM.as_ptr() as usize, HEAP_MEM.len()) }
    }

    let node = CspConfig::new()
        .address(1)
        .buffers(1000, 256)
        .fifo_length(100)
        .init()
        .expect("CSP INIT FAIL");

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

    let mut prng = Prng::new(PRNG_SEED);
    let mut count = 0u64;
    let mut bytes_sent = 0u64;
    let mut last_log = Instant::now();

    let mut current_mode = ProtocolMode::Normal;
    let mut active_conn: Option<Connection> = None;

    rprintln!("!!! SENDER READY !!!");

    loop {
        let next_mode = ProtocolMode::from_count(count);
        if next_mode != current_mode {
            rprintln!("[TX] Mode Switch: {} -> {} (count={})", current_mode.to_str(), next_mode.to_str(), count);
            if let Some(conn) = active_conn.take() {
                if (conn.flags() & libcsp::sys::CSP_FRDP as i32) != 0 {
                    Timer::after(Duration::from_millis(50)).await;
                }
                drop(conn);
            }
            current_mode = next_mode;
        }

        if active_conn.is_none() {
            let opts = match current_mode {
                ProtocolMode::Normal => socket_opts::CONN_LESS,
                ProtocolMode::Rdp => conn_opts::RDP,
                ProtocolMode::SFP => conn_opts::NONE,
                ProtocolMode::RdpSfp => conn_opts::RDP,
            };
            let port = if matches!(current_mode, ProtocolMode::SFP | ProtocolMode::RdpSfp) { SFP_PORT } else { DATA_PORT };
            
            active_conn = node.connect(Priority::Norm as u8, 2, port, 200, opts);
            if active_conn.is_none() {
                Timer::after(Duration::from_millis(10)).await;
                continue;
            }
            rprintln!("[TX] Connected for {}", current_mode.to_str());
        }

        let conn = active_conn.as_ref().unwrap();

        match current_mode {
            ProtocolMode::Normal | ProtocolMode::Rdp => {
                for _ in 0..5 {
                    if let Some(mut pkt) = Packet::get(200) {
                        let mut data = [0u8; 200];
                        data[0..8].copy_from_slice(&count.to_le_bytes());
                        let mut packet_prng = Prng::new(PRNG_SEED ^ (count as u32));
                        packet_prng.fill(&mut data[8..]);
                        pkt.write(&data).unwrap();
                        
                        if conn.send_discard(pkt, 10).is_ok() {
                            bytes_sent += 200;
                            count += 1;
                        } else {
                            active_conn = None;
                            Timer::after(Duration::from_millis(5)).await;
                            break;
                        }
                    } else {
                        Timer::after(Duration::from_millis(1)).await;
                        break;
                    }
                }
            }
            ProtocolMode::SFP | ProtocolMode::RdpSfp => {
                let size = (prng.next() % 4000) + 1000;
                let mut data = vec![0u8; size as usize];
                data[0..8].copy_from_slice(&count.to_le_bytes());
                let mut blob_prng = Prng::new(PRNG_SEED ^ (count as u32));
                blob_prng.fill(&mut data[8..]);

                if conn.sfp_send(&data, 200, 1000).is_ok() {
                    bytes_sent += size as u64;
                    count += 20;
                    rprintln!("[TX] SFP sent {} bytes (count={})", size, count - 20);
                } else {
                    active_conn = None;
                    Timer::after(Duration::from_millis(10)).await;
                }
            }
        }

        if last_log.elapsed() >= Duration::from_secs(5) {
            rprintln!("[Stats] Sent {} KB total, count {}", bytes_sent / 1024, count);
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
                use embassy_stm32::can::bxcan::Id;
                let id = match envelope.frame.id() { Id::Standard(s) => s.as_raw() as u32, Id::Extended(e) => e.as_raw() };
                pkt.set_id_raw(id);
                pkt.write(data.as_ref()).unwrap();
                handle.rx(pkt);
            }
        }
    }
}

#[embassy_executor::task]
async fn csp_router_task(node: libcsp::CspNode) {
    loop {
        let _ = node.route_work(10); 
        Timer::after(Duration::from_millis(1)).await;
    }
}
