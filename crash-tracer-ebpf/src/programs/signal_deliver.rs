use aya_ebpf::{
    bindings::{BPF_F_USER_STACK, pt_regs},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid,
        generated::{bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_task_pt_regs},
    },
    macros::map,
    maps::StackTrace,
    programs::TracePointContext,
};
use aya_log_ebpf::{info, warn};
use crash_tracer_common::{CrashTracerEvent, EventType, SignalDeliverEvent};

use crate::{programs::CRASH_TRACER_EVENTS, vmlinux::task_struct};

#[map]
static SIGNAL_DELIVER_STACKS: StackTrace = StackTrace::with_max_entries(1024, 0);

pub unsafe fn try_handle_signal_deliver(ctx: TracePointContext) -> Result<(), i64> {
    // For signal:signal_deliver tracepoint, the signal number is at offset 8
    // See: /sys/kernel/debug/tracing/events/signal/signal_deliver/format
    let signal: i32 = unsafe { ctx.read_at(8)? };

    // Only process crash signals - ignore normal signals like SIGCHLD (17), etc.
    if !SignalDeliverEvent::is_crash_signal(signal) {
        return Ok(());
    }

    // si_code is at offset 16 (check with: sudo cat /sys/kernel/debug/tracing/events/signal/signal_deliver/format)
    let si_code: i32 = unsafe { ctx.read_at(16)? };

    let mut entry = match CRASH_TRACER_EVENTS.reserve::<CrashTracerEvent>(0) {
        Some(e) => e,
        None => {
            warn!(&ctx, "The buffer is currently full. Cannot capture crash.");
            return Ok(());
        }
    };

    let ptr = entry.as_mut_ptr();
    let task: *const task_struct = unsafe { bpf_get_current_task_btf() as *const task_struct };

    unsafe {
        (*ptr).tag = EventType::SignalDeliver;

        let event = &mut (*ptr).payload.signal;
        let pid_tgid = bpf_get_current_pid_tgid();
        event.pid = pid_tgid as u32;
        event.tid = (pid_tgid >> 32) as u32;
        event.signal = signal;
        event.si_code = si_code;
        event.timestamp_ns = bpf_ktime_get_ns();
        event.boottime = (*task).start_boottime;
        event.fault_addr = (*task).thread.cr2;

        // Process name - if this fails, just use empty name rather than failing
        event.cmd = bpf_get_current_comm().unwrap_or([0u8; 16]);

        event.kernel_stack_id = SIGNAL_DELIVER_STACKS
            .get_stackid::<TracePointContext>(&ctx, 0)
            .unwrap_or(-1);
        event.user_stack_id = SIGNAL_DELIVER_STACKS
            .get_stackid::<TracePointContext>(&ctx, BPF_F_USER_STACK.into())
            .unwrap_or(-1);

        let regs = bpf_task_pt_regs(task as *mut _) as *const pt_regs;
        event.rip = (*regs).rip;
        event.rsp = (*regs).rsp;
        event.rbp = (*regs).rbp;
        event.rflags = (*regs).eflags;
        event.rax = (*regs).rax;
        event.rsi = (*regs).rsi;
        event.rdi = (*regs).rdi;
        event.rdx = (*regs).rdx;
        event.r8 = (*regs).r8;
        event.r9 = (*regs).r9;
        event.r10 = (*regs).r10;
        event.r11 = (*regs).r11;
        event.r12 = (*regs).r12;
        event.r13 = (*regs).r13;
        event.r14 = (*regs).r14;
        event.r15 = (*regs).r15;

        info!(&ctx, "crash detected: pid={} sig={}", event.pid, signal);
    }

    entry.submit(0);

    Ok(())
}
