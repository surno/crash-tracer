use crash_tracer_common::{CrashEvent, SchedExecEvent};

pub mod crash_source;
pub mod sched_exec_source;

pub enum Event {
    Crash(CrashEvent),
    SchedExec(SchedExecEvent),
}

pub trait EventSource {
    async fn next_event(&mut self) -> Option<Event>;
}
