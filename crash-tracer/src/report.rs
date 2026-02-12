use std::io::Write;
use std::path::{Path, PathBuf};

use aya::maps::stack_trace::StackTrace;
use crash_tracer_common::{SignalDeliverEvent, StackDump};

use crate::db;
use crate::state::map::ProcessInfo;

/// Core formatting — writes a crash report to any `Write` target.
fn write_report(
    w: &mut impl Write,
    event: &SignalDeliverEvent,
    stack_trace: Option<&StackTrace>,
    stack_dump: Option<&StackDump>,
    map: Option<&ProcessInfo>,
) -> anyhow::Result<()> {
    let cmd = std::str::from_utf8(&event.cmd)
        .unwrap_or("<unknown>")
        .trim_end_matches('\0');

    writeln!(w, "Crash Report")?;
    writeln!(w, "============")?;
    writeln!(w, "Generated: {}", chrono::Utc::now().to_rfc3339())?;
    writeln!(w)?;
    writeln!(
        w,
        "Process: {} (PID: {}, TID: {})",
        cmd, event.pid, event.tid
    )?;
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

    if let Some(process_info) = map {
        writeln!(w)?;
        writeln!(w, "Detected Runtime: {}", process_info.runtime)?;
    }

    writeln!(w)?;
    writeln!(w, "Registers")?;
    writeln!(w, "---------")?;
    writeln!(
        w,
        "  RIP: 0x{:016x}  RFLAGS: 0x{:016x}",
        event.rip, event.rflags
    )?;
    writeln!(
        w,
        "  RSP: 0x{:016x}  RBP:    0x{:016x}",
        event.rsp, event.rbp
    )?;
    writeln!(
        w,
        "  RAX: 0x{:016x}  RBX:    0x{:016x}",
        event.rax, event.rbx
    )?;
    writeln!(
        w,
        "  RCX: 0x{:016x}  RDX:    0x{:016x}",
        event.rcx, event.rdx
    )?;
    writeln!(
        w,
        "  RSI: 0x{:016x}  RDI:    0x{:016x}",
        event.rsi, event.rdi
    )?;
    writeln!(w, "  R8:  0x{:016x}  R9:     0x{:016x}", event.r8, event.r9)?;
    writeln!(
        w,
        "  R10: 0x{:016x}  R11:    0x{:016x}",
        event.r10, event.r11
    )?;
    writeln!(
        w,
        "  R12: 0x{:016x}  R13:    0x{:016x}",
        event.r12, event.r13
    )?;
    writeln!(
        w,
        "  R14: 0x{:016x}  R15:    0x{:016x}",
        event.r14, event.r15
    )?;

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

    if let Some(dump) = stack_dump {
        let len = dump.len as usize;
        writeln!(w)?;
        writeln!(w, "Raw Stack ({} bytes from 0x{:016x})", len, dump.rsp)?;
        writeln!(w, "---------")?;
        for offset in (0..len).step_by(16) {
            let addr = dump.rsp + offset as u64;
            let end = (offset + 16).min(len);
            let chunk = &dump.data[offset..end];

            write!(w, "  0x{:016x}:", addr)?;
            for (i, byte) in chunk.iter().enumerate() {
                if i % 2 == 0 {
                    write!(w, " ")?;
                }
                write!(w, "{:02x}", byte)?;
            }
            // Pad remaining space if chunk < 16 bytes
            let missing = 16 - chunk.len();
            for i in 0..missing {
                if (chunk.len() + i) % 2 == 0 {
                    write!(w, " ")?;
                }
                write!(w, "  ")?;
            }

            write!(w, "  |")?;
            for byte in chunk {
                let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                    *byte as char
                } else {
                    '.'
                };
                write!(w, "{}", ch)?;
            }
            writeln!(w, "|")?;
        }
    }

    if let Some(process_info) = map {
        writeln!(w)?;
        writeln!(w, "Memory Maps")?;
        writeln!(w, "-----------")?;
        for line in &process_info.maps {
            writeln!(w, "{}", line)?;
        }
    }

    Ok(())
}

/// Print a crash summary to stdout.
pub fn print_to_console(
    event: &SignalDeliverEvent,
    stack_trace: Option<&StackTrace>,
    process_info: Option<&ProcessInfo>,
) {
    let mut stdout = std::io::stdout().lock();
    // Console output omits memory maps and raw stack (they can be very long)
    if let Err(e) = write_report(&mut stdout, event, stack_trace, None, process_info) {
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

pub fn save_from_db(output_dir: &Path, data: &db::CrashReportData) -> anyhow::Result<PathBuf> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("crash_{}_{}_{}.txt", data.cmd, data.pid, timestamp);
    let filepath = output_dir.join(&filename);

    let mut file = std::fs::File::create(&filepath)?;
    write_report_from_db(&mut file, data)?;

    Ok(filepath)
}

fn write_report_from_db(w: &mut impl Write, data: &db::CrashReportData) -> anyhow::Result<()> {
    writeln!(w, "Crash Report")?;
    writeln!(w, "============")?;
    writeln!(w, "Generated: {}", chrono::Utc::now().to_rfc3339())?;
    writeln!(w)?;
    writeln!(w, "Process: {} (PID: {}, TID: {})", data.cmd, data.pid, data.tid)?;
    writeln!(w, "Signal:  {} ({})", signal_name(data.signal), data.signal)?;
    writeln!(w, "Code:    {} ({})", si_code_name(data.signal, data.si_code), data.si_code)?;

    if data.fault_addr != 0 {
        writeln!(w, "Fault:   0x{:016x}", data.fault_addr)?;
    }

    if let Some(exit_code) = data.exit_code {
        writeln!(w, "Exit:    {}", exit_code)?;
    }

    writeln!(w)?;
    writeln!(w, "Detected Runtime: {}", data.runtime)?;

    let r = &data.registers;
    writeln!(w)?;
    writeln!(w, "Registers")?;
    writeln!(w, "---------")?;
    writeln!(w, "  RIP: 0x{:016x}  RFLAGS: 0x{:016x}", r.rip, r.rflags)?;
    writeln!(w, "  RSP: 0x{:016x}  RBP:    0x{:016x}", r.rsp, r.rbp)?;
    writeln!(w, "  RAX: 0x{:016x}  RBX:    0x{:016x}", r.rax, r.rbx)?;
    writeln!(w, "  RCX: 0x{:016x}  RDX:    0x{:016x}", r.rcx, r.rdx)?;
    writeln!(w, "  RSI: 0x{:016x}  RDI:    0x{:016x}", r.rsi, r.rdi)?;
    writeln!(w, "  R8:  0x{:016x}  R9:     0x{:016x}", r.r8, r.r9)?;
    writeln!(w, "  R10: 0x{:016x}  R11:    0x{:016x}", r.r10, r.r11)?;
    writeln!(w, "  R12: 0x{:016x}  R13:    0x{:016x}", r.r12, r.r13)?;
    writeln!(w, "  R14: 0x{:016x}  R15:    0x{:016x}", r.r14, r.r15)?;

    if !data.stack_frames.is_empty() {
        writeln!(w)?;
        writeln!(w, "User Stack:")?;
        writeln!(w, "---------")?;
        for (i, ip) in data.stack_frames.iter().enumerate() {
            if *ip == 0 {
                break;
            }
            writeln!(w, "  #{:2}: 0x{:016x}", i, ip)?;
        }
    }

    if let Some((rsp, ref dump)) = data.stack_dump {
        let len = dump.len();
        writeln!(w)?;
        writeln!(w, "Raw Stack ({} bytes from 0x{:016x})", len, rsp)?;
        writeln!(w, "---------")?;
        for offset in (0..len).step_by(16) {
            let addr = rsp + offset as u64;
            let end = (offset + 16).min(len);
            let chunk = &dump[offset..end];

            write!(w, "  0x{:016x}:", addr)?;
            for (i, byte) in chunk.iter().enumerate() {
                if i % 2 == 0 {
                    write!(w, " ")?;
                }
                write!(w, "{:02x}", byte)?;
            }
            let missing = 16 - chunk.len();
            for i in 0..missing {
                if (chunk.len() + i) % 2 == 0 {
                    write!(w, " ")?;
                }
                write!(w, "  ")?;
            }

            write!(w, "  |")?;
            for byte in chunk {
                let ch = if byte.is_ascii_graphic() || *byte == b' ' {
                    *byte as char
                } else {
                    '.'
                };
                write!(w, "{}", ch)?;
            }
            writeln!(w, "|")?;
        }
    }

    if !data.memory_maps.is_empty() {
        writeln!(w)?;
        writeln!(w, "Memory Maps")?;
        writeln!(w, "-----------")?;
        for line in &data.memory_maps {
            writeln!(w, "{}", line)?;
        }
    }

    if !data.artifacts.is_empty() {
        writeln!(w)?;
        writeln!(w, "Runtime Artifacts")?;
        writeln!(w, "-----------------")?;
        for artifact in &data.artifacts {
            writeln!(w, "  File: {} ({})", artifact.filename, artifact.full_path)?;
            match &artifact.content {
                Some(content) => {
                    if let Ok(text) = std::str::from_utf8(content) {
                        writeln!(w)?;
                        let truncated = text.len() > 4096;
                        let preview = if truncated { &text[..4096] } else { text };
                        for line in preview.lines() {
                            writeln!(w, "    {}", line)?;
                        }
                        if truncated {
                            writeln!(w, "    ... ({} bytes total, truncated)", text.len())?;
                        }
                    } else {
                        writeln!(w, "  (binary content, {} bytes)", content.len())?;
                    }
                }
                None => {
                    writeln!(w, "  (content not available)")?;
                }
            }
        }
    }

    Ok(())
}
