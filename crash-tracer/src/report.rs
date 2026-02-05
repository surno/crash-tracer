use std::io::Write;
use std::path::{Path, PathBuf};

use aya::maps::stack_trace::StackTrace;
use crash_tracer_common::SignalDeliverEvent;

use crate::state::map::MemoryMap;

/// Core formatting — writes a crash report to any `Write` target.
fn write_report(
    w: &mut impl Write,
    event: &SignalDeliverEvent,
    stack_trace: Option<&StackTrace>,
    map: Option<&Vec<String>>,
) -> anyhow::Result<()> {
    let cmd = std::str::from_utf8(&event.cmd)
        .unwrap_or("<unknown>")
        .trim_end_matches('\0');

    writeln!(w, "Crash Report")?;
    writeln!(w, "============")?;
    writeln!(w, "Generated: {}", chrono::Utc::now().to_rfc3339())?;
    writeln!(w)?;
    writeln!(w, "Process: {} (PID: {}, TID: {})", cmd, event.pid, event.tid)?;
    writeln!(
        w,
        "Signal:  {} ({})",
        signal_name(event.signal),
        event.signal
    )?;
    writeln!(
        w,
        "Code:    {} ({})",
        si_code_name(event.signal, event.si_code),
        event.si_code
    )?;

    if event.fault_addr != 0 {
        writeln!(w, "Fault:   0x{:016x}", event.fault_addr)?;
    }

    writeln!(w)?;
    writeln!(w, "Registers")?;
    writeln!(w, "---------")?;
    writeln!(
        w,
        "  RIP: 0x{:016x}  RFLAGS: 0x{:016x}",
        event.rip, event.rflags
    )?;
    writeln!(w, "  RSP: 0x{:016x}  RBP:    0x{:016x}", event.rsp, event.rbp)?;
    writeln!(w, "  RAX: 0x{:016x}  RBX:    0x{:016x}", event.rax, event.rbx)?;
    writeln!(w, "  RCX: 0x{:016x}  RDX:    0x{:016x}", event.rcx, event.rdx)?;
    writeln!(w, "  RSI: 0x{:016x}  RDI:    0x{:016x}", event.rsi, event.rdi)?;
    writeln!(w, "  R8:  0x{:016x}  R9:     0x{:016x}", event.r8, event.r9)?;
    writeln!(w, "  R10: 0x{:016x}  R11:    0x{:016x}", event.r10, event.r11)?;
    writeln!(w, "  R12: 0x{:016x}  R13:    0x{:016x}", event.r12, event.r13)?;
    writeln!(w, "  R14: 0x{:016x}  R15:    0x{:016x}", event.r14, event.r15)?;

    if let Some(trace) = stack_trace {
        writeln!(w)?;
        writeln!(w, "User Stack:")?;
        writeln!(w, "---------")?;
        for (i, frame) in trace.frames().iter().enumerate() {
            if frame.ip == 0 {
                break;
            }
            writeln!(w, "  #{:2}: 0x{:016x}", i, frame.ip)?;
        }
    }

    if let Some(maps) = map {
        writeln!(w)?;
        writeln!(w, "Memory Maps")?;
        writeln!(w, "-----------")?;
        for line in maps {
            writeln!(w, "{}", line)?;
        }
    }

    Ok(())
}

/// Save a crash report to a timestamped file in the output directory.
/// Returns the path of the created file.
pub fn save_to_file(
    output_dir: &Path,
    event: &SignalDeliverEvent,
    stack_trace: Option<&StackTrace>,
    map: &MemoryMap,
) -> anyhow::Result<PathBuf> {
    let cmd = std::str::from_utf8(&event.cmd)
        .unwrap_or("<unknown>")
        .trim_end_matches('\0');

    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("crash_{}_{}_{}.txt", cmd, event.pid, timestamp);
    let filepath = output_dir.join(&filename);

    let maps = map.get(event.pid, event.boottime);
    if maps.is_none() {
        log::error!("No memory map for: {}", event.pid);
    }

    let mut file = std::fs::File::create(&filepath)?;
    write_report(&mut file, event, stack_trace, maps)?;

    Ok(filepath)
}

/// Print a crash summary to stdout.
pub fn print_to_console(
    event: &SignalDeliverEvent,
    stack_trace: Option<&StackTrace>,
) {
    let mut stdout = std::io::stdout().lock();
    // Console output omits memory maps (they can be very long)
    if let Err(e) = write_report(&mut stdout, event, stack_trace, None) {
        log::error!("Failed to write to stdout: {}", e);
    }
}

pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        11 => "SIGSEGV",
        _ => "UNKNOWN",
    }
}

pub fn si_code_name(sig: i32, code: i32) -> &'static str {
    match (sig, code) {
        (11, 1) => "SEGV_MAPERR",
        (11, 2) => "SEGV_ACCERR",
        (7, 1) => "BUS_ADRALN",
        (7, 2) => "BUS_ADRERR",
        (8, 1) => "FPE_INTDIV",
        (8, 2) => "FPE_INTOVF",
        (8, 3) => "FPE_FLTDIV",
        (4, 1) => "ILL_ILLOPC",
        _ => "UNKNOWN",
    }
}
