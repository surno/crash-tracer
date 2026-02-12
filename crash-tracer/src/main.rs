#[cfg(not(target_arch = "x86_64"))]
compile_error!("crash-tracer currently only supports x86_64");

mod db;
mod ebpf;
mod event;
mod report;
mod state;
use crate::db::CrashDb;
use crate::event::unified_source::UnifiedEventSource;
use crate::event::{Event, EventSource};
use crate::state::map::MemoryMap;

use std::path::PathBuf;

use anyhow::Context;
use aya::maps::{HashMap, RingBuf, StackTraceMap};
use aya_log::EbpfLogger;
use clap::Parser;
use crash_tracer_common::{SignalDeliverEvent, StackDump, StackDumpKey};
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
                    let mut guard = match logger.readable_mut().await {
                        Ok(guard) => guard,
                        Err(e) => {
                            log::error!("eBPF logger fd error, stopping log drain: {e}");
                            break;
                        }
                    };
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    ebpf::attach_tracepoints(&mut bpf)?;

    info!("Programs attached. Waiting for events...");

    std::fs::create_dir_all(&args.output_dir)?;
    let db_path = args.output_dir.join("crash-tracer.db");
    let db = db::CrashDb::new(&db_path).await?;

    // Get handles to maps - now using unified ring buffer
    let events = RingBuf::try_from(
        bpf.take_map("CRASH_TRACER_EVENTS")
            .ok_or_else(|| anyhow::anyhow!("eBPF map not found: CRASH_TRACER_EVENTS"))?,
    )?;
    let signal_deliver_stacks = StackTraceMap::try_from(
        bpf.take_map("SIGNAL_DELIVER_STACKS")
            .ok_or_else(|| anyhow::anyhow!("eBPF map not found: SIGNAL_DELIVER_STACKS"))?,
    )?;
    let mut stack_dumps: HashMap<_, StackDumpKey, StackDump> = HashMap::try_from(
        bpf.take_map("STACK_DUMP_MAP")
            .ok_or_else(|| anyhow::anyhow!("eBPF map not found: STACK_DUMP_MAP"))?,
    )?;

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
                        if let Some(info) = memory_map.get(exec.pid, exec.boottime) {
                            if let Err(e) = db.insert_process(info).await
                                .with_context(|| format!("inserting process pid={}", exec.pid))
                            {
                                log::error!("{e:#}");
                            }
                        }
                    }
                    Event::SignalDeliver(signal) => {
                        debug!("signal event: pid={}, boottime={}", signal.pid, signal.boottime);
                        handle_signal_deliver_event(&db, &signal, &signal_deliver_stacks, &mut stack_dumps, &memory_map).await;
                    }
                    Event::SchedExit(exit) => {
                        debug!("exit event: pid={}, boottime={} exit_code={}", exit.pid, exit.boottime, exit.exit_code);
         match db.complete_crash(exit.pid, exit.boottime, exit.exit_code).await
             .with_context(|| format!("completing crash pid={}", exit.pid))
         {
            Ok(Some(crash_id)) => {
              match db.get_crash_report_data(crash_id).await
                  .with_context(|| format!("retrieving report data crash_id={}", crash_id))
              {
                  Ok(data) => match report::save_from_db(&output_dir, &data)
                      .context("writing report file")
                  {
                      Ok(path) => info!("Report saved: {}", path.display()),
                      Err(e) => log::error!("{e:#}"),
                  },
                  Err(e) => log::error!("{e:#}"),
              }
            }
            Ok(None) => {
                  if let Err(e) = db.cleanup_process(exit.pid, exit.boottime).await
                      .with_context(|| format!("cleaning up process pid={}", exit.pid))
                  {
                      log::error!("{e:#}");
                  }
            }
            Err(e) => log::error!("{e:#}"),
        }

          memory_map.remove(exit.pid, exit.boottime);                     }
                    Event::ArtifactReady(artifact) => {
                        debug!("artifact event: pid={}, boottime={}, file={}", artifact.pid, artifact.boottime, std::str::from_utf8(&artifact.filename[..artifact.filename_len as usize])
      .unwrap_or("<invalid>"));
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
    db: &CrashDb,
    event: &SignalDeliverEvent,
    stacks: &StackTraceMap<aya::maps::MapData>,
    stack_dumps: &mut HashMap<aya::maps::MapData, StackDumpKey, StackDump>,
    map: &MemoryMap,
) {
    info!("\n{}", "=".repeat(60));
    info!("CRASH DETECTED");
    info!("\n{}", "=".repeat(60));

    let stack_trace = (event.user_stack_id >= 0)
        .then(|| stacks.get(&(event.user_stack_id as u32), 0).ok())
        .flatten();

    // Retrieve raw stack dump from eBPF HashMap
    let dump_key = StackDumpKey {
        pid: event.pid,
        tid: event.tid,
        boottime: event.boottime,
    };
    let stack_dump = stack_dumps.get(&dump_key, 0).ok();
    let _ = stack_dumps.remove(&dump_key);

    let process_info = map.get(event.pid, event.boottime);

    if let Err(e) = db
        .insert_crash(&event, stack_trace.as_ref(), stack_dump.as_ref())
        .await
        .with_context(|| format!("inserting crash pid={} sig={}", event.pid, event.signal))
    {
        log::error!("{e:#}");
    }
    // Console output for real-time feedback; file report is generated on exit from DB
    report::print_to_console(event, stack_trace.as_ref(), process_info);
}
