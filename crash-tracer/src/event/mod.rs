use crash_tracer_common::{ArtifactReadyEvent, SchedExecEvent, SchedExitEvent, SignalDeliverEvent};

pub mod unified_source;

pub enum Event {
    SignalDeliver(SignalDeliverEvent),
    SchedExec(SchedExecEvent),
    SchedExit(SchedExitEvent),
    ArtifactReady(ArtifactReadyEvent),
}

pub trait EventSource {
    async fn next_event(&mut self) -> Option<Event>;
}
