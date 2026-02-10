use aya_ebpf::{
    bindings::{BPF_F_USER_STACK, pt_regs},
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_probe_read_user_buf,
        generated::{bpf_get_current_task_btf, bpf_ktime_get_ns, bpf_task_pt_regs},
    },
    macros::map,
    maps::{HashMap, PerCpuArray, StackTrace},
    programs::TracePointContext,
};
use aya_log_ebpf::info;
use crash_tracer_common::{SignalDeliverEvent, StackDump, StackDumpKey};

use crate::{programs::PENDING_SIGNALS, vmlinux::task_struct};

#[map]
static SIGNAL_DELIVER_STACKS: StackTrace = StackTrace::with_max_entries(1024, 0);

/// Scratch space for reading user stack memory.
/// PerCpuArray gives each CPU its own 16KB buffer — no contention.
#[map]
static STACK_DUMP_SCRATCH: PerCpuArray<StackDump> = PerCpuArray::with_max_entries(1, 0);

/// Stack dumps keyed by (pid, tid). Userspace reads and deletes after processing.
#[map]
static STACK_DUMP_MAP: HashMap<StackDumpKey, StackDump> = HashMap::with_max_entries(64, 0);

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

    let task: *const task_struct = unsafe { bpf_get_current_task_btf() as *const task_struct };

    let mut event = SignalDeliverEvent::zeroed();
    unsafe {
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

        // Capture raw user stack memory.
        // bpf_probe_read_user is all-or-nothing: if the read extends past
        // mapped memory it fails entirely. Cascade through decreasing sizes
        // so we still capture what we can when RSP is near the stack top.
        if event.rsp != 0 {
            if let Some(scratch) = STACK_DUMP_SCRATCH.get_ptr_mut(0) {
                let scratch = &mut *scratch;
                scratch.rsp = event.rsp;
                scratch.len = 0;
                let src = event.rsp as *const u8;
                if bpf_probe_read_user_buf(src, &mut scratch.data[..16384]).is_ok() {
                    scratch.len = 16384;
                } else if bpf_probe_read_user_buf(src, &mut scratch.data[..8192]).is_ok() {
                    scratch.len = 8192;
                } else if bpf_probe_read_user_buf(src, &mut scratch.data[..4096]).is_ok() {
                    scratch.len = 4096;
                } else if bpf_probe_read_user_buf(src, &mut scratch.data[..2048]).is_ok() {
                    scratch.len = 2048;
                }
                let key = StackDumpKey {
                    pid: event.pid,
                    tid: event.tid,
                    boottime: event.boottime,
                };
                let _ = STACK_DUMP_MAP.insert(&key, scratch, 0);
            }
        }

        info!(&ctx, "crash detected: pid={} sig={}", event.pid, signal);
    }

    let key = StackDumpKey {
        pid: event.pid,
        tid: event.tid,
        boottime: event.boottime,
    };

    let _ = PENDING_SIGNALS.insert(&key, event, 0);

    Ok(())
}
