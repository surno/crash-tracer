use std::path::PathBuf;

use anyhow::Context;
use aya::{maps::RingBuf, programs::TracePoint};
use aya_log::EbpfLogger;
use clap::Parser;
use crash_tracer_common::CrashEvent;
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

#[tokio::main] // (3)
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
    info!("Attempting to load program...");
    let program: &mut TracePoint = bpf
        .program_mut("handle_signal_deliver")
        .unwrap()
        .try_into()?;
    program.load()?;

    program
        .attach("signal", "signal_deliver")
        .context("failed to attach tracepoint.")?;

    info!("Crash tracer attached. Waiting for crashes...");

    std::fs::create_dir_all(&args.output_dir)?;

    // Get handles to maps
    let events = RingBuf::try_from(bpf.map_mut("EVENTS").unwrap())?;

    // Process events in main loop instead of spawning
    // This keeps bpf alive for the entire program lifetime
    let output_dir = args.output_dir.clone();

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("Exiting...");
        }
        _ = async {
            process_events(events, output_dir).await;
        } => {}
    }

    // Keep bpf alive until here
    drop(bpf);

    Ok(())
}

async fn process_events(mut events: RingBuf<&mut aya::maps::MapData>, _output_dir: PathBuf) {
    let mut buf = [0u8; std::mem::size_of::<CrashEvent>()];

    loop {
        while let Some(item) = events.next() {
            let data = item.as_ref();
            if data.len() >= std::mem::size_of::<CrashEvent>() {
                buf[..std::mem::size_of::<CrashEvent>()]
                    .copy_from_slice(&data[..std::mem::size_of::<CrashEvent>()]);

                let event: CrashEvent = unsafe { std::ptr::read(buf.as_ptr() as *const _) };
                let comm = std::str::from_utf8(&event.cmd)
                    .unwrap_or("<unknown>")
                    .trim_end_matches('\0');
                info!("==== CRASH DETECTED =====");
                println!("Process: {} (PID: {}, TID: {})", comm, event.pid, event.tid);
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }
}
