use aya::maps::{MapData, RingBuf};
use crash_tracer_common::SignalDeliverEvent;
use log::warn;

use crate::event::{Event, EventSource};

pub struct SignalDeliverEventSource {
    ring_buf: RingBuf<MapData>,
}

impl SignalDeliverEventSource {
    pub fn new(ring_buf: RingBuf<MapData>) -> Self {
        Self { ring_buf }
    }
}

impl EventSource for SignalDeliverEventSource {
    async fn next_event(&mut self) -> Option<super::Event> {
        let event = async {
            loop {
                let mut buf = [0u8; std::mem::size_of::<SignalDeliverEvent>()];
                while let Some(item) = self.ring_buf.next() {
                    let data = item.as_ref();
                    if data.len() >= std::mem::size_of::<SignalDeliverEvent>() {
                        buf[..std::mem::size_of::<SignalDeliverEvent>()]
                            .copy_from_slice(&data[..std::mem::size_of::<SignalDeliverEvent>()]);
                        let event: SignalDeliverEvent =
                            unsafe { std::ptr::read(buf.as_ptr() as *const _) };
                        return Some(Event::SignalDeliver(event));
                    }
                    warn!("Unable to parse signal deliver event, unknown event.");
                }
                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
        };
        event.await
    }
}
