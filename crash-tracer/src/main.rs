mod event;
mod state;
use crate::event::unified_source::UnifiedEventSource;
use crate::event::{Event, EventSource};
use crate::state::map::MemoryMap;

use std::path::PathBuf;

use anyhow::Context;
use aya::{
    maps::{RingBuf, StackTraceMap, stack_trace::StackTrace},
    programs::TracePoint,
};
use aya_log::EbpfLogger;
use clap::Parser;
use crash_tracer_common::SignalDeliverEvent;
use log::{info, warn};
use tokio::signal;

#[derive(Debug, Parser)]
#[command(name = "crash-tracer")]
#[command(about = "eBPF-based crash tracer", long_about = None)]
struct Args {
    #[clap(short, long, default_value = "/tmp/crash-tracer/")]
    output_dir: PathBuf,

    #[clap(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(if args.verbose { "debug" } else { "info" }),
    )
    .init();

    // Bump memlock rlimit for eBPF maps
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe {
        if libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) != 0 {
            warn!("Failed to increase RLIMIT_MEMLOCK");
        }
    }

    info!(
        "Starting crash-tracer and reporting in : {:?}",
        args.output_dir.to_str()
    );

    info!("Loading eBPF program...");
    let mut bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/crash-tracer-ebpf"
    )))?;

    info!("eBPF program loaded successfully");
    info!("Initializing eBPF logger...");
    match EbpfLogger::init(&mut bpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    info!("Attempting to load programs...");
    let signal_program: &mut TracePoint = bpf
        .program_mut("handle_signal_deliver")
        .unwrap()
        .try_into()?;
    signal_program.load()?;
    signal_program
        .attach("signal", "signal_deliver")
        .context("failed to attach signal tracepoint.")?;

    let exec_program: &mut TracePoint = bpf
        .program_mut("handle_sched_process_exec")
        .unwrap()
        .try_into()?;
    exec_program.load()?;
    exec_program
        .attach("sched", "sched_process_exec")
        .context("failed to attach sched_process_exec tracepoint.")?;

    info!("Programs attached. Waiting for events...");

    std::fs::create_dir_all(&args.output_dir)?;

    // Get handles to maps - now using unified ring buffer
    let events = RingBuf::try_from(bpf.take_map("CRASH_TRACER_EVENTS").unwrap())?;
    let signal_deliver_stacks =
        StackTraceMap::try_from(bpf.take_map("SIGNAL_DELIVER_STACKS").unwrap())?;

    let output_dir = args.output_dir.clone();
    let mut memory_map = MemoryMap::new();

    // Single event loop processes events in FIFO order
    // This guarantees exec events are processed before signal events for the same process
    let mut event_source = UnifiedEventSource::new(events);

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Exiting...");
        }
        _ = async {
            while let Some(event) = event_source.next_event().await {
                match event {
                    Event::SchedExec(exec) => {
                        info!("exec event: pid={}, boottime={}", exec.pid, exec.boottime);
                        memory_map.insert(exec.pid, exec.boottime);
                    }
                    Event::SignalDeliver(signal) => {
                        info!("signal event: pid={}, boottime={}", signal.pid, signal.boottime);
                        handle_signal_deliver_event(&signal, &signal_deliver_stacks, &memory_map, &output_dir).await;
                    }
                }
            }
        } => {}
    }

    // Keep bpf alive until here
    drop(bpf);

    Ok(())
}

async fn handle_signal_deliver_event(
    event: &SignalDeliverEvent,
    stacks: &StackTraceMap<aya::maps::MapData>,
    map: &MemoryMap,
    output_dir: &PathBuf,
) {
    let comm = std::str::from_utf8(&event.cmd)
        .unwrap_or("<unknown>")
        .trim_end_matches('\0');
    info!("\n{}", "=".repeat(60));
    info!("CRASH DETECTED");
    info!("\n{}", "=".repeat(60));

    println!("Process: {} (PID: {}, TID: {})", comm, event.pid, event.tid);
    println!("Signal:  {} ({})", signal_name(event.signal), event.signal);
    println!(
        "Code:    {} ({})",
        si_code_name(event.signal, event.si_code),
        event.si_code
    );

    if event.fault_addr != 0 {
        println!("Fault:   0x{:016x}", event.fault_addr);
    }
    println!("\nRegisters:");
    println!(
        "  RIP: 0x{:016x}  RFLAGS: 0x{:016x}",
        event.rip, event.rflags
    );
    println!("  RSP: 0x{:016x}  RBP:    0x{:016x}", event.rsp, event.rbp);
    println!("  RAX: 0x{:016x}  RBX:    0x{:016x}", event.rax, event.rbx);
    println!("  RCX: 0x{:016x}  RDX:    0x{:016x}", event.rcx, event.rdx);
    println!("  RSI: 0x{:016x}  RDI:    0x{:016x}", event.rsi, event.rdi);
    println!("  R8:  0x{:016x}  R9:     0x{:016x}", event.r8, event.r9);
    println!("  R10: 0x{:016x}  R11:    0x{:016x}", event.r10, event.r11);
    println!("  R12: 0x{:016x}  R13:    0x{:016x}", event.r12, event.r13);
    println!("  R14: 0x{:016x}  R15:    0x{:016x}", event.r14, event.r15);

    // Resolve user stack if available
    let mut stack_trace: Option<StackTrace> = None;
    if event.user_stack_id >= 0 {
        println!("\nUser Stack:");
        if let Ok(trace) = stacks.get(&(event.user_stack_id as u32), 0) {
            for (i, frame) in trace.frames().iter().enumerate() {
                if frame.ip == 0 {
                    break;
                }
                println!("  #{:2}: 0x{:016x}", i, frame.ip);
            }
            stack_trace = Some(trace);
        }
    }

    // Save report to file
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("crash_{}_{}_{}.txt", comm, event.pid, timestamp);
    let filepath = output_dir.join(&filename);

    if let Err(e) = save_report(event, stack_trace, map, &filepath) {
        log::error!("Failed to save report: {}", e);
    } else {
        println!("\nReport saved: {}", filepath.display());
    }
}

fn save_report(
    event: &SignalDeliverEvent,
    stack_trace: Option<StackTrace>,
    map: &MemoryMap,
    path: &PathBuf,
) -> anyhow::Result<()> {
    use std::io::Write;

    let cmd = std::str::from_utf8(&event.cmd)
        .unwrap_or("<unknown>")
        .trim_end_matches('\0');

    let mut file = std::fs::File::create(path)?;

    writeln!(file, "Crash Report")?;
    writeln!(file, "============")?;
    writeln!(file, "Generated: {}", chrono::Utc::now().to_rfc3339())?;
    writeln!(file)?;
    writeln!(file, "Process: {}", cmd)?;
    writeln!(file, "PID: {}  TID: {}", event.pid, event.tid)?;
    writeln!(
        file,
        "Signal: {} ({})",
        signal_name(event.signal),
        event.signal
    )?;
    writeln!(
        file,
        "Code: {} ({})",
        si_code_name(event.signal, event.si_code),
        event.si_code
    )?;

    if event.fault_addr != 0 {
        writeln!(file, "Fault Address: 0x{:016x}", event.fault_addr)?;
    }

    writeln!(file)?;
    writeln!(file, "Registers")?;
    writeln!(file, "---------")?;
    writeln!(file, "RIP: 0x{:016x}", event.rip)?;
    writeln!(file, "RSP: 0x{:016x}", event.rsp)?;
    writeln!(file, "RBP: 0x{:016x}", event.rbp)?;
    writeln!(file, "RAX: 0x{:016x}", event.rax)?;
    writeln!(file, "RBX: 0x{:016x}", event.rbx)?;
    writeln!(file, "RCX: 0x{:016x}", event.rcx)?;
    writeln!(file, "RDX: 0x{:016x}", event.rdx)?;
    writeln!(file, "RSI: 0x{:016x}", event.rsi)?;
    writeln!(file, "RDI: 0x{:016x}", event.rdi)?;
    writeln!(file, "R8:  0x{:016x}", event.r8)?;
    writeln!(file, "R9:  0x{:016x}", event.r9)?;
    writeln!(file, "R10: 0x{:016x}", event.r10)?;
    writeln!(file, "R11: 0x{:016x}", event.r11)?;
    writeln!(file, "R12: 0x{:016x}", event.r12)?;
    writeln!(file, "R13: 0x{:016x}", event.r13)?;
    writeln!(file, "R14: 0x{:016x}", event.r14)?;
    writeln!(file, "R15: 0x{:016x}", event.r15)?;

    if let Some(trace) = stack_trace {
        writeln!(file)?;
        writeln!(file, "User Stack:")?;
        writeln!(file, "---------")?;
        for (i, frame) in trace.frames().iter().enumerate() {
            if frame.ip == 0 {
                break;
            }
            writeln!(file, "  #{:2}: 0x{:016x}", i, frame.ip)?;
        }
    }

    // Read memory maps if process still exists
    if let Some(maps) = map.get(event.pid, event.boottime) {
        writeln!(file)?;
        writeln!(file, "Memory Maps")?;
        writeln!(file, "-----------")?;
        for line in maps {
            writeln!(file, "{}", line)?;
        }
    } else {
        log::error!("No memory map for: {}", event.pid)
    }

    Ok(())
}

fn signal_name(sig: i32) -> &'static str {
    match sig {
        4 => "SIGILL",
        6 => "SIGABRT",
        7 => "SIGBUS",
        8 => "SIGFPE",
        11 => "SIGSEGV",
        _ => "UNKNOWN",
    }
}

fn si_code_name(sig: i32, code: i32) -> &'static str {
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
