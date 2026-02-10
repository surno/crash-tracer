use aya_ebpf::{
    macros::map,
    maps::{HashMap, RingBuf},
};
use crash_tracer_common::{SignalDeliverEvent, StackDump, StackDumpKey};

pub mod sched_process_exec;
pub mod sched_process_exit;
pub mod signal_deliver;

#[map]
static CRASH_TRACER_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);

#[map]
static PENDING_SIGNALS: HashMap<StackDumpKey, SignalDeliverEvent> =
    HashMap::with_max_entries(64, 0);

/// Stack dumps keyed by (pid, tid). Userspace reads and deletes after processing.
#[map]
static STACK_DUMP_MAP: HashMap<StackDumpKey, StackDump> = HashMap::with_max_entries(64, 0);
