use aya::maps::{MapData, RingBuf};
use crash_tracer_common::{CrashTracerEvent, EventType};
use log::warn;

use crate::event::{Event, EventSource};

pub struct UnifiedEventSource {
    ring_buf: RingBuf<MapData>,
}

impl UnifiedEventSource {
    pub fn new(ring_buf: RingBuf<MapData>) -> Self {
        Self { ring_buf }
    }
}

impl EventSource for UnifiedEventSource {
    async fn next_event(&mut self) -> Option<Event> {
        loop {
            while let Some(item) = self.ring_buf.next() {
                let data = item.as_ref();
                if data.len() < std::mem::size_of::<CrashTracerEvent>() {
                    warn!(
                        "Event too small: {} < {}",
                        data.len(),
                        std::mem::size_of::<CrashTracerEvent>()
                    );
                    continue;
                }

                let mut buf = [0u8; std::mem::size_of::<CrashTracerEvent>()];
                buf.copy_from_slice(&data[..std::mem::size_of::<CrashTracerEvent>()]);
                let event: CrashTracerEvent = unsafe { std::ptr::read(buf.as_ptr() as *const _) };

                match event.tag {
                    EventType::SchedExec => {
                        if let Some(exec) = event.as_exec() {
                            return Some(Event::SchedExec(*exec));
                        }
                    }
                    EventType::SignalDeliver => {
                        if let Some(signal) = event.as_signal() {
                            return Some(Event::SignalDeliver(*signal));
                        }
                    }
                }
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
    }
}
