use datalink::{
    DataLink,
    messages::{DataLinkRequest, InboundIpv4, OutboundFrame},
};
use proto::{
    iface::MacAddr,
    txbuf::{ETH_HEADER_LEN, TxBuf},
};
use sim::Pipe;
use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::sync::mpsc;

struct Host {
    /// Send [`DataLinkRequest`]s down to this host's datalink layer
    nw_down: mpsc::Sender<DataLinkRequest>,
    /// Receive [`InboundIpv4`] from this host's datalink layer
    nw_up: mpsc::Receiver<InboundIpv4>,
}

impl Host {
    /// Spawns a [`DataLink`] instance connected to one end of a [`Pipe`].
    /// Returns a Host handle for driving the stack from the test.
    fn new(mac: MacAddr, ip: Ipv4Addr, pipe: Pipe) -> Self {
        let (pipe_tx, pipe_rx) = pipe.split();

        let (nw_tx1, nw_up) = mpsc::channel(256);
        let (nw_down, nw_rx2) = mpsc::channel(256);

        let dl = DataLink::new(
            mac,
            ip,
            pipe_tx,
            pipe_rx,
            nw_tx1,
            nw_rx2,
            tokio_util::sync::CancellationToken::new(),
        );

        tokio::spawn(dl.run());

        Self { nw_down, nw_up }
    }
}

async fn timeout<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = Option<T>>,
    T: std::fmt::Debug,
{
    tokio::time::timeout(Duration::from_secs(1), fut)
        .await
        .expect("test timed out — possible deadlock")
        .expect("channel closed unexpectedly")
}

#[tokio::test]
async fn arp_resolves_and_ipv4_delivered() {
    let (pipe_a, pipe_b) = Pipe::pair();

    let mac_a = [0xAA; 6].into();
    let mac_b = [0xBB; 6].into();
    let ip_a = Ipv4Addr::new(10, 0, 0, 1);
    let ip_b = Ipv4Addr::new(10, 0, 0, 2);

    let host_a = Host::new(mac_a, ip_a, pipe_a);
    let mut host_b = Host::new(mac_b, ip_b, pipe_b);

    let payload = vec![0xAA; 20];
    host_a
        .nw_down
        .send(DataLinkRequest::Send(OutboundFrame {
            dst_ip: ip_b,
            buf: TxBuf::new(ETH_HEADER_LEN, &payload),
        }))
        .await
        .unwrap();

    let received = timeout(host_b.nw_up.recv()).await;

    assert_eq!(received.src_mac, mac_a);
    assert_eq!(&received.payload[..payload.len()], &payload);
}

#[tokio::test]
async fn bidirectional_communication() {
    let (pipe_a, pipe_b) = Pipe::pair();

    let mac_a = [0xAA; 6].into();
    let mac_b = [0xBB; 6].into();
    let ip_a = Ipv4Addr::new(10, 0, 0, 1);
    let ip_b = Ipv4Addr::new(10, 0, 0, 2);

    let mut host_a = Host::new(mac_a, ip_a, pipe_a);
    let mut host_b = Host::new(mac_b, ip_b, pipe_b);

    host_a
        .nw_down
        .send(DataLinkRequest::Send(OutboundFrame {
            dst_ip: ip_b,
            buf: TxBuf::new(ETH_HEADER_LEN, &[0x01; 20]),
        }))
        .await
        .unwrap();

    let recv_b = timeout(host_b.nw_up.recv()).await;
    assert_eq!(&recv_b.payload[..20], &[0x01; 20]);

    host_b
        .nw_down
        .send(DataLinkRequest::Send(OutboundFrame {
            dst_ip: ip_a,
            buf: TxBuf::new(ETH_HEADER_LEN, &[0x02; 20]),
        }))
        .await
        .unwrap();

    let recv_a = timeout(host_a.nw_up.recv()).await;
    assert_eq!(&recv_a.payload[..20], &[0x02; 20]);
}
