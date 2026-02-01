#![no_std]
#![no_main]
mod programs;

use crate::programs::signal::try_handle_signal;

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn handle_signal_deliver(ctx: TracePointContext) -> u32 {
    match unsafe { try_handle_signal(ctx) } {
        Ok(()) => 0,
        Err(e) => e as u32,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
