mod event;
mod report;
mod state;
use crate::event::unified_source::UnifiedEventSource;
use crate::event::{Event, EventSource};
use crate::state::map::MemoryMap;

use std::path::PathBuf;

use anyhow::Context;
use aya::{
    maps::{RingBuf, StackTraceMap},
    programs::TracePoint,
};
use aya_log::EbpfLogger;
use clap::Parser;
use crash_tracer_common::SignalDeliverEvent;
use log::{debug, info, warn};
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

    let exit_program: &mut TracePoint = bpf
        .program_mut("handle_sched_process_exit")
        .unwrap()
        .try_into()?;
    exit_program.load()?;
    exit_program
        .attach("sched", "sched_process_exit")
        .context("failed to attach sched_process_exit tracepoint.")?;

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
                        debug!("exec event: pid={}, boottime={}", exec.pid, exec.boottime);
                        memory_map.insert(exec.pid, exec.boottime);
                    }
                    Event::SignalDeliver(signal) => {
                        debug!("signal event: pid={}, boottime={}", signal.pid, signal.boottime);
                        handle_signal_deliver_event(&signal, &signal_deliver_stacks, &memory_map, &output_dir).await;
                    }
                    Event::SchedExit(exit) => {
                        debug!("exit event: pid={}, boottime={}", exit.pid, exit.boottime);
                        memory_map.remove(exit.pid, exit.boottime);
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
    output_dir: &std::path::Path,
) {
    info!("\n{}", "=".repeat(60));
    info!("CRASH DETECTED");
    info!("\n{}", "=".repeat(60));

    let stack_trace = (event.user_stack_id >= 0)
        .then(|| stacks.get(&(event.user_stack_id as u32), 0).ok())
        .flatten();

    report::print_to_console(event, stack_trace.as_ref());

    match report::save_to_file(output_dir, event, stack_trace.as_ref(), map) {
        Ok(path) => println!("\nReport saved: {}", path.display()),
        Err(e) => log::error!("Failed to save report: {}", e),
    }
}
