#![no_std]
#![no_main]
mod programs;

#[allow(warnings)]
#[rustfmt::skip]
mod vmlinux;

use crate::programs::{
    sched_process_exec::try_handle_sched_process_exec, signal::try_handle_signal,
};

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

#[tracepoint]
pub fn handle_signal_deliver(ctx: TracePointContext) -> u32 {
    match unsafe { try_handle_signal(ctx) } {
        Ok(()) => 0,
        Err(e) => e as u32,
    }
}

#[tracepoint]
pub fn handle_sched_process_exec(ctx: TracePointContext) -> u32 {
    match try_handle_sched_process_exec(ctx) {
        Ok(()) => 0,
        Err(e) => e as u32,
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
