use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user_str_bytes},
    programs::TracePointContext,
};
use crash_tracer_common::ARTIFACT_FILENAME_MAX;

use crate::programs::{OPENAT_SCRATCH, TRACKED_PIDS};

pub fn try_handle_sys_enter_openat(ctx: TracePointContext) -> Result<(), i64> {
    let pid = bpf_get_current_pid_tgid() >> 32;

    let Some(_) = TRACKED_PIDS.get_ptr(&(pid as u32)) else {
        return Ok(());
    };

    // offset is at 24
    let filename_ptr: *const u8 = unsafe { ctx.read_at(24)? };

    let mut buf: [u8; ARTIFACT_FILENAME_MAX] = [0; ARTIFACT_FILENAME_MAX];

    // bpf_probe_read_user_str_bytes returns the string length directly,
    // avoiding a 128-iteration null-scanning loop that blows the verifier budget.
    let str_len = unsafe { bpf_probe_read_user_str_bytes(filename_ptr, &mut buf) }
        .map(|s| s.len())
        .map_err(|_| 1i64)?;

    // Find last '/' by scanning backwards from end of string.
    // Artifact basenames are short (< 30 chars), so 32 positions is sufficient.
    let mut basename_start: usize = 0;
    let mut k: usize = 0;
    while k < 32 {
        if k >= str_len {
            break;
        }
        let pos = str_len - 1 - k;
        if unsafe { *buf.get_unchecked(pos) } == b'/' {
            basename_start = pos + 1;
            break;
        }
        k += 1;
    }

    if is_artifact_filename(&buf, basename_start) {
        let Some(entry) = OPENAT_SCRATCH.get_ptr_mut(0) else {
            return Ok(());
        };
        unsafe {
            (*entry).filename = buf;
            (*entry).filename_len = str_len as u32;
        }
    }

    return Ok(());
}

fn is_artifact_filename(filename: &[u8], start: usize) -> bool {
    // SAFETY: bounds are checked before accessing. Using get_unchecked to avoid
    // panic paths that the compiler places in .text.unlikely. — aya-obj can't link
    // functions from that section, causing "processed 0 insns" on load.
    unsafe {
        if start + 10 < filename.len()
            && *filename.get_unchecked(start) == b'h'
            && *filename.get_unchecked(start + 1) == b's'
            && *filename.get_unchecked(start + 2) == b'_'
            && *filename.get_unchecked(start + 3) == b'e'
            && *filename.get_unchecked(start + 4) == b'r'
            && *filename.get_unchecked(start + 5) == b'r'
            && *filename.get_unchecked(start + 6) == b'_'
            && *filename.get_unchecked(start + 7) == b'p'
            && *filename.get_unchecked(start + 8) == b'i'
            && *filename.get_unchecked(start + 9) == b'd'
        {
            return true;
        } else if start + 7 < filename.len()
            && *filename.get_unchecked(start) == b'r'
            && *filename.get_unchecked(start + 1) == b'e'
            && *filename.get_unchecked(start + 2) == b'p'
            && *filename.get_unchecked(start + 3) == b'o'
            && *filename.get_unchecked(start + 4) == b'r'
            && *filename.get_unchecked(start + 5) == b't'
            && *filename.get_unchecked(start + 6) == b'.'
        {
            return true;
        }
    }

    return false;
}
