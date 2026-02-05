use aya_ebpf::{helpers::generated::bpf_get_current_task_btf, programs::TracePointContext};

use aya_log_ebpf::warn;
use crash_tracer_common::{CrashTracerEvent, EventType};
use vmlinux::task_struct;

use crate::{programs::CRASH_TRACER_EVENTS, vmlinux};

pub fn try_handle_sched_process_exit(ctx: TracePointContext) -> Result<(), i64> {
    let task: *const task_struct = unsafe { bpf_get_current_task_btf() as *const task_struct };
    let start_boottime = unsafe { (*task).start_boottime };
    let pid = unsafe { (*task).pid } as u32;

    let mut entry = match CRASH_TRACER_EVENTS.reserve::<CrashTracerEvent>(0) {
        Some(e) => e,
        None => {
            warn!(&ctx, "The buffer is currently full. Cannot capture exec.");
            return Ok(());
        }
    };

    let ptr = entry.as_mut_ptr();
    unsafe {
        (*ptr).tag = EventType::SchedExit;
        (*ptr).payload.exec.pid = pid;
        (*ptr).payload.exec.boottime = start_boottime;
    }

    entry.submit(0);

    Ok(())
}
