use std::{
    collections::VecDeque,
    future::poll_fn,
    sync::{Arc, Mutex},
    task::Poll,
};

#[derive(Default)]
pub struct ChannelBuffers {
    pub inbox: VecDeque<Vec<u8>>,
    pub outbox: VecDeque<Vec<u8>>,
}

impl ChannelBuffers {
    pub fn create() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }
}

pub struct FrostChannel {
    buffers: Arc<Mutex<ChannelBuffers>>,
}

impl FrostChannel {
    pub fn attach(buffers: Arc<Mutex<ChannelBuffers>>) -> Self {
        Self { buffers }
    }

    pub async fn broadcast(&self, data: Vec<u8>) {
        let mut frame = Vec::with_capacity(2 + data.len());
        frame.extend_from_slice(&0u16.to_le_bytes());
        frame.extend_from_slice(&data);
        self.buffers.lock().unwrap().outbox.push_back(frame);
    }

    pub async fn send_to(&self, recipient: u16, data: Vec<u8>) {
        let mut frame = Vec::with_capacity(2 + data.len());
        frame.extend_from_slice(&recipient.to_le_bytes());
        frame.extend_from_slice(&data);
        self.buffers.lock().unwrap().outbox.push_back(frame);
    }

    pub async fn recv(&self) -> (u16, Vec<u8>) {
        poll_fn(|_| {
            let mut bufs = self.buffers.lock().unwrap();
            match bufs.inbox.pop_front() {
                Some(frame) => {
                    if frame.len() < 2 {
                        return Poll::Ready((0, frame));
                    }
                    let sender = u16::from_le_bytes([frame[0], frame[1]]);
                    let data = frame[2..].to_vec();
                    Poll::Ready((sender, data))
                }
                None => Poll::Pending,
            }
        })
        .await
    }
}
