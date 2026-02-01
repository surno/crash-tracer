use aya::maps::{MapData, RingBuf};
use crash_tracer_common::CrashEvent;
use log::{info, warn};

use crate::event::{Event, EventSource};

pub struct CrashEventSource {
    ring_buf: RingBuf<MapData>,
}

impl CrashEventSource {
    pub fn new(ring_buf: RingBuf<MapData>) -> Self {
        Self { ring_buf }
    }
}

impl EventSource for CrashEventSource {
    async fn next_event(&mut self) -> Option<super::Event> {
        let event = async {
            loop {
                let mut buf = [0u8; std::mem::size_of::<CrashEvent>()];
                while let Some(item) = self.ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<CrashEvent>() {
                        buf[..std::mem::size_of::<CrashEvent>()]
                            .copy_from_slice(&data[..std::mem::size_of::<CrashEvent>()]);
                        let event: CrashEvent = unsafe { std::ptr::read(buf.as_ptr() as *const _) };
                        return Some(Event::Crash(event));
                    }
                    warn!("Unable to parse crash event, unknown event.");
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        };
        event.await
    }
}
