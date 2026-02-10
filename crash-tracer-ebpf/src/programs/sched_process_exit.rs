use aya_ebpf::{helpers::generated::bpf_get_current_task_btf, programs::TracePointContext};

use aya_log_ebpf::warn;
use crash_tracer_common::{CrashTracerEvent, EventType, StackDumpKey};
use vmlinux::task_struct;

use crate::{
    programs::{CRASH_TRACER_EVENTS, PENDING_SIGNALS, STACK_DUMP_MAP},
    vmlinux,
};

pub fn try_handle_sched_process_exit(ctx: TracePointContext) -> Result<(), i64> {
    let task: *const task_struct = unsafe { bpf_get_current_task_btf() as *const task_struct };
    let boottime = unsafe { (*task).start_boottime };
    let pid = unsafe { (*task).tgid } as u32;
    let tid = unsafe { (*task).pid } as u32;
    let exit_code = unsafe { (*task).exit_code } as u32;

    // determine if the exit code is non-zero
    if exit_code & 0x7f != 0 {
        let entry = PENDING_SIGNALS.get_ptr_mut(StackDumpKey { pid, tid, boottime });
        match entry {
            Some(entry) => {
                match CRASH_TRACER_EVENTS.reserve::<CrashTracerEvent>(0) {
                    Some(mut crash_event) => {
                        let crash_event_ptr = crash_event.as_mut_ptr();
                        unsafe {
                            (*crash_event_ptr).tag = EventType::SignalDeliver;
                            (*crash_event_ptr).payload.signal = *entry;
                        }
                        // commit the crash for userspace to retrieve.
                        crash_event.submit(0);
                    }
                    None => {
                        warn!(&ctx, "The buffer is currently full. Cannot capture signal.");
                        let _ = STACK_DUMP_MAP.remove(StackDumpKey { pid, tid, boottime });
                    }
                };
            }
            _ => {
                // no entry was found. Should be fine.
            }
        }
    } else {
        let _ = STACK_DUMP_MAP.remove(StackDumpKey { pid, tid, boottime });
    }

    match CRASH_TRACER_EVENTS.reserve::<CrashTracerEvent>(0) {
        Some(mut event) => {
            let ptr = event.as_mut_ptr();
            unsafe {
                (*ptr).tag = EventType::SchedExit;
                (*ptr).payload.exit.pid = pid;
                (*ptr).payload.exit.exit_code = exit_code;
                (*ptr).payload.exit.boottime = boottime;
            }

            event.submit(0);
        }
        None => {
            warn!(&ctx, "The buffer is currently full. Cannot capture exec.");
        }
    };

    // clean up the maps, regardless of the exit type.
    let _ = PENDING_SIGNALS.remove(StackDumpKey { pid, tid, boottime });

    Ok(())
}
