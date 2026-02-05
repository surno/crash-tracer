use crash_tracer_common::{SchedExecEvent, SignalDeliverEvent};

pub mod sched_exec_source;
pub mod signal_deliver_source;

pub enum Event {
    SignalDeliver(SignalDeliverEvent),
    SchedExec(SchedExecEvent),
}

pub trait EventSource {
    async fn next_event(&mut self) -> Option<Event>;
}
