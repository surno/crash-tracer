use aya_ebpf::{helpers::bpf_get_current_pid_tgid, programs::TracePointContext};
use aya_log_ebpf::error;
use crash_tracer_common::FdTrackKey;

use crate::programs::{OPENAT_SCRATCH, TRACKED_FDS, TRACKED_PIDS};

pub fn try_handle_sys_exit_openat(ctx: TracePointContext) -> Result<(), i64> {
    let pid = bpf_get_current_pid_tgid() >> 32;

    let Some(_) = TRACKED_PIDS.get_ptr(&(pid as u32)) else {
        return Ok(());
    };

    let fd: i64 = unsafe { ctx.read_at(16)? };

    if fd < 0 {
        error!(ctx, "openat failed on sys_exit_openat");
        return Ok(());
    }

    let Some(scratch) = OPENAT_SCRATCH.get_ptr_mut(0) else {
        error!(ctx, "unable to get scratch data for tracked file");
        return Ok(());
    };

    unsafe {
        if (*scratch).filename_len == 0 {
            return Ok(());
        }

        TRACKED_FDS.insert(
            FdTrackKey {
                pid: pid as u32,
                fd: fd as u32,
            },
            *scratch,
            0,
        )?;
        (*scratch).filename_len = 0;
    }

    return Ok(());
}
