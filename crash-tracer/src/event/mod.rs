use crash_tracer_common::CrashEvent;

pub mod crash_source;

pub enum Event {
    Crash(CrashEvent),
}

pub trait EventSource {
    async fn next_event(&mut self) -> Option<Event>;
}
