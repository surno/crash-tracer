use crash_tracer_common::{SchedExecEvent, SignalDeliverEvent};

pub mod unified_source;

pub enum Event {
    SignalDeliver(SignalDeliverEvent),
    SchedExec(SchedExecEvent),
}

pub trait EventSource {
    async fn next_event(&mut self) -> Option<Event>;
}
