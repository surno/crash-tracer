#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid, generated::bpf_ktime_get_ns},
    macros::{map, tracepoint},
    maps::RingBuf,
    programs::TracePointContext,
};
use aya_log_ebpf::{info, warn};
use crash_tracer_common::CrashEvent;

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint]
pub fn handle_signal_deliver(ctx: TracePointContext) -> u32 {
    match unsafe { try_handle_signal(ctx) } {
        Ok(()) => 0,
        Err(e) => e as u32,
    }
}

unsafe fn try_handle_signal(ctx: TracePointContext) -> Result<(), i64> {
    // For signal:signal_deliver tracepoint, the signal number is at offset 8
    // See: /sys/kernel/debug/tracing/events/signal/signal_deliver/format
    let signal: i32 = unsafe { ctx.read_at(8)? };

    // Only process crash signals - ignore normal signals like SIGCHLD (17), etc.
    if !CrashEvent::is_crash_signal(signal) {
        return Ok(());
    }

    // si_code is at offset 16 (check with: sudo cat /sys/kernel/debug/tracing/events/signal/signal_deliver/format)
    let si_code: i32 = unsafe { ctx.read_at(16)? };

    let mut entry = match EVENTS.reserve::<CrashEvent>(0) {
        Some(e) => e,
        None => {
            warn!(&ctx, "The buffer is currently full. Cannot capture crash.");
            return Ok(());
        }
    };

    let event = entry.as_mut_ptr();

    unsafe {
        let pid_tgid = bpf_get_current_pid_tgid();
        (*event).pid = pid_tgid as u32;
        (*event).tid = (pid_tgid >> 32) as u32;
        (*event).signal = signal;
        (*event).si_code = si_code;
        (*event).timestamp_ns = bpf_ktime_get_ns();

        // Process name - if this fails, just use empty name rather than failing
        (*event).cmd = bpf_get_current_comm().unwrap_or([0u8; 16]);
    }

    info!(
        &ctx,
        "crash detected: pid={} sig={}",
        unsafe { (*event).pid },
        signal
    );

    entry.submit(0);

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
