use aya_ebpf::{macros::map, maps::RingBuf};

pub mod sched_process_exec;
pub mod sched_process_exit;
pub mod signal_deliver;

#[map]
static CRASH_TRACER_EVENTS: RingBuf = RingBuf::with_byte_size(512 * 1024, 0);
