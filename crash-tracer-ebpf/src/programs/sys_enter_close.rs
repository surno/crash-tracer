use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, generated::bpf_get_current_task_btf},
    programs::TracePointContext,
};
use crash_tracer_common::{CrashTracerEvent, EventType, FdTrackKey};

use crate::{
    programs::{CRASH_TRACER_EVENTS, TRACKED_FDS, TRACKED_PIDS},
    vmlinux::task_struct,
};

pub fn try_handle_sys_enter_close(ctx: TracePointContext) -> Result<(), i64> {
    let pid = bpf_get_current_pid_tgid() >> 32;

    if TRACKED_PIDS.get_ptr(&(pid as u32)).is_none() {
        return Ok(());
    }

    let fd: u32 = unsafe { ctx.read_at(16)? };

    let Some(file) = TRACKED_FDS.get_ptr(FdTrackKey {
        pid: pid as u32,
        fd: fd as u32,
    }) else {
        return Ok(());
    };

    let task: *const task_struct = unsafe { bpf_get_current_task_btf() as *const task_struct };

    let boottime = unsafe { (*task).start_boottime };

    let Some(mut event) = CRASH_TRACER_EVENTS.reserve::<CrashTracerEvent>(0) else {
        TRACKED_FDS.remove(FdTrackKey {
            pid: pid as u32,
            fd: fd as u32,
        })?;
        return Ok(());
    };

    unsafe {
        let event_ptr = event.as_mut_ptr();
        (*event_ptr).payload.artifact.boottime = boottime;
        (*event_ptr).payload.artifact.filename = (*file).filename;
        (*event_ptr).payload.artifact.filename_len = (*file).filename_len;
        (*event_ptr).payload.artifact.pid = pid as u32;
        (*event_ptr).tag = EventType::ArtifactReady;
    }

    event.submit(0);

    TRACKED_FDS.remove(FdTrackKey {
        pid: pid as u32,
        fd: fd as u32,
    })?;

    Ok(())
}
