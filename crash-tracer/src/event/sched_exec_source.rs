use aya::maps::{MapData, RingBuf};
use crash_tracer_common::SchedExecEvent;
use tokio::time;

use crate::event::{Event, EventSource};

pub struct SchedExecEventSource {
    ring_buf: RingBuf<MapData>,
}

impl SchedExecEventSource {
    pub fn new(ring_buf: RingBuf<MapData>) -> Self {
        Self { ring_buf }
    }
}

impl EventSource for SchedExecEventSource {
    async fn next_event(&mut self) -> Option<super::Event> {
        let event = async {
            loop {
                let mut buf = [0u8; std::mem::size_of::<SchedExecEvent>()];
                while let Some(item) = self.ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<SchedExecEvent>() {
                        buf[..std::mem::size_of::<SchedExecEvent>()]
                            .copy_from_slice(&item[..std::mem::size_of::<SchedExecEvent>()]);
                        let event: SchedExecEvent =
                            unsafe { std::ptr::read(buf.as_ptr() as *const _) };
                        return Some(Event::SchedExec(event));
                    }
                }
                tokio::time::sleep(time::Duration::from_millis(100)).await;
            }
        };
        event.await
    }
}
