#![forbid(unsafe_code)]

use proto::iface::{PacketSink, PacketSource};
use tokio::io;
use tokio::sync::mpsc;

pub struct Pipe {
    tx: mpsc::Sender<Vec<u8>>,
    rx: mpsc::Receiver<Vec<u8>>,
}

pub struct PipeRx {
    rx: mpsc::Receiver<Vec<u8>>,
}

pub struct PipeTx {
    tx: mpsc::Sender<Vec<u8>>,
}

impl Pipe {
    /// Create a connected pair of pipes.
    pub fn pair() -> (Pipe, Pipe) {
        let (a_tx, b_rx) = mpsc::channel(256);
        let (b_tx, a_rx) = mpsc::channel(256);
        (Pipe { tx: a_tx, rx: a_rx }, Pipe { tx: b_tx, rx: b_rx })
    }

    /// Splits a pipe into two halves - one for sending and one for receiving.
    pub fn split(self) -> (PipeRx, PipeTx) {
        (PipeRx { rx: self.rx }, PipeTx { tx: self.tx })
    }
}

impl PacketSink for PipeTx {
    async fn send(&self, buf: &[u8]) -> std::io::Result<()> {
        self.tx
            .send(buf.to_vec())
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))
    }
}

impl PacketSource for PipeRx {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.rx.recv().await {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::from(io::ErrorKind::BrokenPipe)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::iface::{PacketSink, PacketSource};

    #[tokio::test]
    async fn test_trait_send_recv() {
        let (pipe_a, pipe_b) = Pipe::pair();
        let (mut rx, tx) = pipe_b.split();
        let (mut rx2, tx2) = pipe_a.split();

        let msg = b"ping";

        tx.send(msg).await.unwrap();

        let mut buf = [0u8; 16];
        let n = rx2.recv(&mut buf).await.unwrap();

        assert_eq!(&buf[..n], msg);

        tx2.send(b"pong").await.unwrap();

        let n2 = rx.recv(&mut buf).await.unwrap();
        assert_eq!(&buf[..n2], b"pong");
    }

    #[tokio::test]
    async fn test_truncation() {
        let (pipe_a, pipe_b) = Pipe::pair();
        let (_rx, tx) = pipe_a.split();
        let (mut rx2, _tx2) = pipe_b.split();

        let msg = b"1234567890";
        tx.send(msg).await.unwrap();

        let mut buf = [0u8; 4]; // Small buffer
        let n = rx2.recv(&mut buf).await.unwrap();

        assert_eq!(n, 4);
        assert_eq!(&buf, b"1234");
    }

    #[tokio::test]
    async fn test_broken_pipe_on_drop_sender() {
        let (pipe_a, pipe_b) = Pipe::pair();
        let (mut rx, _tx) = pipe_b.split();

        // Drop all senders
        drop(pipe_a);

        let mut buf = [0u8; 8];
        let err = rx.recv(&mut buf).await.unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn test_broken_pipe_on_drop_receiver() {
        let (pipe_a, pipe_b) = Pipe::pair();
        let (_rx, tx) = pipe_b.split();

        // Drop receiver side
        drop(pipe_a);

        let err = tx.send(b"data").await.unwrap_err();

        assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
    }

    #[tokio::test]
    async fn test_bidirectional() {
        let (pipe_a, pipe_b) = Pipe::pair();
        let (mut rx_a, tx_a) = pipe_a.split();
        let (mut rx_b, tx_b) = pipe_b.split();

        tx_a.send(b"hello").await.unwrap();
        tx_b.send(b"world").await.unwrap();

        let mut buf_a = [0u8; 16];
        let mut buf_b = [0u8; 16];

        let n_a = rx_a.recv(&mut buf_a).await.unwrap();
        let n_b = rx_b.recv(&mut buf_b).await.unwrap();

        assert_eq!(&buf_a[..n_a], b"world");
        assert_eq!(&buf_b[..n_b], b"hello");
    }
}
