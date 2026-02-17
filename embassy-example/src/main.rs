#![no_std]
#![no_main]

use rtt_target::{rtt_init_print, rprintln};
use cortex_m_rt::entry;
use embassy_stm32::init;
use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    rprintln!("PANIC!");
    loop {}
}

#[entry]
fn main() -> ! {
    // 1. HW init
    let _p = init(Default::default());

    // 2. RTT init
    rtt_init_print!();

    // 3. WAIT FOR PROBE
    for _ in 0..10_000_000 {
        cortex_m::asm::nop();
    }

    // 4. LOUD OUTPUT
    rprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    rprintln!("!!!    RTT OUTPUT IS WORKING NOW      !!!");
    rprintln!("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");

    let mut count: u32 = 0;
    loop {
        rprintln!("ALIVE: count {}", count);
        count += 1;
        
        for _ in 0..2_000_000 {
            cortex_m::asm::nop();
        }
    }
}
