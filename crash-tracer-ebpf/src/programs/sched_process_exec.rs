use aya_ebpf::{
    helpers::generated::bpf_get_current_task_btf, macros::map, maps::RingBuf,
    programs::TracePointContext,
};

use aya_log_ebpf::warn;
use crash_tracer_common::SchedExecEvent;
use vmlinux::task_struct;

use crate::vmlinux;

#[map]
static SCHED_EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

pub fn try_handle_sched_process_exec(ctx: TracePointContext) -> Result<(), i64> {
    let task: *const task_struct = unsafe { bpf_get_current_task_btf() as *const task_struct };
    let start_boottime = unsafe { (*task).start_boottime };
    let pid = unsafe { (*task).pid } as u32;

    let mut entry = match SCHED_EXEC_EVENTS.reserve::<SchedExecEvent>(0) {
        Some(e) => e,
        None => {
            warn!(&ctx, "The buffer is currently full. Cannot capture crash.");
            return Ok(());
        }
    };

    let entry_ptr = entry.as_mut_ptr();
    unsafe {
        (*entry_ptr).pid = pid;
        (*entry_ptr).boottime = start_boottime;
    }

    entry.submit(0);

    Ok(())
}
