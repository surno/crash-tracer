use anyhow::Context;
use aya::programs::TracePoint;
use log::info;

/// (ebpf function name, tracepoint category, tracepoint name)
const TRACEPOINTS: &[(&str, &str, &str)] = &[
    ("handle_signal_deliver", "signal", "signal_deliver"),
    ("handle_sched_process_exec", "sched", "sched_process_exec"),
    ("handle_sched_process_exit", "sched", "sched_process_exit"),
    ("handle_sys_enter_openat", "syscalls", "sys_enter_openat"),
    ("handle_sys_exit_openat", "syscalls", "sys_exit_openat"),
    ("handle_sys_enter_close", "syscalls", "sys_enter_close"),
];

pub fn attach_tracepoints(bpf: &mut aya::Ebpf) -> anyhow::Result<()> {
    for (prog, category, name) in TRACEPOINTS {
        let tp: &mut TracePoint = bpf
            .program_mut(prog)
            .with_context(|| format!("program not found: {prog}"))?
            .try_into()?;
        tp.load()?;
        tp.attach(category, name)
            .with_context(|| format!("failed to attach {category}/{name}"))?;
        info!("Attached {category}/{name}");
    }
    Ok(())
}
