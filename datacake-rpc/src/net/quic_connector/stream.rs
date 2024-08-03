use quinn::{RecvStream, SendStream};

pub struct QuicStream {
    pub(crate) tx: SendStream,
    pub(crate) rx: RecvStream,
}
