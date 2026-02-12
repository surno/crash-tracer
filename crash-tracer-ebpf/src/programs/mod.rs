use aya_ebpf::{
    macros::map,
    maps::{HashMap, PerCpuArray, RingBuf},
};
use crash_tracer_common::{ArtifactInfo, FdTrackKey, SignalDeliverEvent, StackDump, StackDumpKey};

pub mod sched_process_exec;
pub mod sched_process_exit;
pub mod signal_deliver;
pub mod sys_enter_close;
pub mod sys_enter_openat;
pub mod sys_exit_openat;

#[map]
static CRASH_TRACER_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

#[map]
static PENDING_SIGNALS: HashMap<StackDumpKey, SignalDeliverEvent> =
    HashMap::with_max_entries(64, 0);

/// Stack dumps keyed by (pid, tid). Userspace reads and deletes after processing.
#[map]
static STACK_DUMP_MAP: HashMap<StackDumpKey, StackDump> = HashMap::with_max_entries(64, 0);

#[map]
static TRACKED_PIDS: HashMap<u32, u32> = HashMap::with_max_entries(256, 0);

#[map]
static TRACKED_FDS: HashMap<FdTrackKey, ArtifactInfo> = HashMap::with_max_entries(256, 0);

#[map]
static OPENAT_SCRATCH: PerCpuArray<ArtifactInfo> = PerCpuArray::with_max_entries(1, 0);
