use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

use crate::relay::ChannelBuffers;

pub trait Ceremony<R> {
    fn feed(&mut self, msg: Vec<u8>) -> bool;
    fn take_msg(&mut self) -> Option<Vec<u8>>;
    fn result(&mut self) -> Option<R>;
}

pub struct Protocol<R, F: Future<Output = R>> {
    task: Option<Pin<Box<F>>>,
    outcome: Option<R>,
    buffers: Arc<Mutex<ChannelBuffers>>,
}

impl<R, F> Protocol<R, F>
where
    F: Future<Output = R>,
{
    pub fn start<Init>(init: Init) -> Self
    where
        Init: FnOnce(crate::relay::FrostChannel) -> F,
    {
        let buffers = ChannelBuffers::create();
        let channel = crate::relay::FrostChannel::attach(buffers.clone());

        let mut proto = Self {
            task: Some(Box::pin(init(channel))),
            outcome: None,
            buffers,
        };

        proto.advance();
        proto
    }

    pub fn feed(&mut self, msg: Vec<u8>) -> bool {
        if self.outcome.is_some() {
            return true;
        }
        self.buffers.lock().unwrap().inbox.push_back(msg);
        self.advance()
    }

    pub fn take_msg(&mut self) -> Option<Vec<u8>> {
        self.buffers.lock().unwrap().outbox.pop_front()
    }

    pub fn result(&mut self) -> Option<R> {
        self.task = None;
        self.outcome.take()
    }

    fn advance(&mut self) -> bool {
        let waker = Waker::noop();
        let mut cx = Context::from_waker(&waker);

        let Some(task) = &mut self.task else {
            return true;
        };

        match task.as_mut().poll(&mut cx) {
            Poll::Pending => false,
            Poll::Ready(val) => {
                self.task = None;
                self.outcome = Some(val);
                true
            }
        }
    }
}

impl<R, F: Future<Output = R>> Ceremony<R> for Protocol<R, F> {
    fn feed(&mut self, msg: Vec<u8>) -> bool {
        Protocol::feed(self, msg)
    }

    fn take_msg(&mut self) -> Option<Vec<u8>> {
        Protocol::take_msg(self)
    }

    fn result(&mut self) -> Option<R> {
        Protocol::result(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_echo_protocol() {
        let mut proto = Protocol::start(|ch| async move {
            let (_sender, data) = ch.recv().await;
            ch.broadcast(data.clone()).await;
            String::from_utf8(data).unwrap()
        });

        assert!(proto.take_msg().is_none());

        let input = crate::message::wrap_sender(1, b"hello");
        let done = proto.feed(input);
        assert!(done);

        let out = proto.take_msg().unwrap();
        let payload = crate::message::payload(&out);
        assert_eq!(payload, b"hello");

        let result = proto.result().unwrap();
        assert_eq!(result, "hello");
    }

    #[test]
    fn multi_round_protocol() {
        let mut proto = Protocol::start(|ch| async move {
            ch.broadcast(b"round1".to_vec()).await;
            let (_s, r1) = ch.recv().await;
            ch.send_to(42, b"round2".to_vec()).await;
            let (_s, r2) = ch.recv().await;
            (r1, r2)
        });

        let out1 = proto.take_msg().unwrap();
        assert_eq!(crate::message::read_recipient(&out1), 0);
        assert_eq!(crate::message::payload(&out1), b"round1");

        let msg_in = crate::message::wrap_sender(2, b"r1-data");
        let done = proto.feed(msg_in);
        assert!(!done);

        let out2 = proto.take_msg().unwrap();
        assert_eq!(crate::message::read_recipient(&out2), 42);
        assert_eq!(crate::message::payload(&out2), b"round2");

        let msg_in2 = crate::message::wrap_sender(42, b"r2-data");
        let done = proto.feed(msg_in2);
        assert!(done);

        let (r1, r2) = proto.result().unwrap();
        assert_eq!(r1, b"r1-data");
        assert_eq!(r2, b"r2-data");
    }
}
