#![forbid(unsafe_code)]

use crate::{
    cache::{ARP_CACHE_LIMIT, ARP_TTL_LIMIT, ArpCache},
    messages::{DataLinkRequest, InboundIpv4, OutboundFrame},
};
use bytes::Bytes;
use proto::{
    arp::{ArpOperation, ArpPacket},
    ethernet::{EtherType, EthernetFrame, EthernetHeader},
    iface::{MacAddr, PacketSink, PacketSource},
    txbuf::TxBuf,
};
use std::{collections::HashMap, net::Ipv4Addr};
use thiserror::Error;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zerocopy::{BigEndian, IntoBytes, U16};

pub mod cache;
pub mod messages;

/// DataLink layer representation, handling all layer 2 logic.
///
/// # Responsibilities
///
/// - Ethernet frame parsing and dispatch
/// - ARP handling with request/reply and caching
/// - Queueing outbound packets while ARP resolution is pending
///
/// Communicates with the wire using the [`PacketSource`]/[`PacketSink`] traits, allowing for
/// pluggable backends for testing and usage.
pub struct DataLink<Tx, Rx>
where
    Tx: PacketSink,
    Rx: PacketSource,
{
    /// Interface MAC address
    our_mac: MacAddr,
    /// Interface IP address
    our_ip: Ipv4Addr,
    /// ARP cache for IP to MAC mappings
    arp_cache: ArpCache,
    /// Packets waiting for ARP resolution
    outbound_queue: HashMap<Ipv4Addr, Vec<OutboundFrame>>,
    /// Transmit handle to the wire
    wire_tx: Tx,
    /// Receive handle from the wire
    wire_rx: Rx,
    /// Upward channel to network layer
    nw_tx: mpsc::Sender<InboundIpv4>,
    /// Downward channel from network layer
    nw_rx: mpsc::Receiver<DataLinkRequest>,
    /// Cancellation token for graceful shutdown
    token: CancellationToken,
}

impl<Tx, Rx> DataLink<Tx, Rx>
where
    Tx: PacketSink,
    Rx: PacketSource,
{
    /// Create a new [`DataLink`] instance
    pub fn new(
        our_mac: MacAddr,
        our_ip: Ipv4Addr,
        wire_tx: Tx,
        wire_rx: Rx,
        nw_tx: mpsc::Sender<InboundIpv4>,
        nw_rx: mpsc::Receiver<DataLinkRequest>,
        token: CancellationToken,
    ) -> Self {
        DataLink {
            our_mac,
            our_ip,
            arp_cache: ArpCache::new(ARP_CACHE_LIMIT, ARP_TTL_LIMIT),
            outbound_queue: HashMap::new(),
            wire_tx,
            wire_rx,
            nw_tx,
            nw_rx,
            token,
        }
    }

    /// Main event loop of the [`DataLink`] layer.
    ///
    /// Concurrently:
    /// - Receives frames from the wire
    /// - Receives outbound requests from network layer
    pub async fn run(mut self) {
        tracing::info!(
            our_mac = ?self.our_mac,
            our_ip  = %self.our_ip,
            "datalink layer started"
        );

        // Reusable buffer for receiving frames
        let mut buf = vec![0u8; 1514];

        loop {
            tokio::select! {
                _ = self.token.cancelled() => {
                    tracing::info!("DataLink shutting down.");
                    break;
                }

                result = self.wire_rx.recv(&mut buf) => {
                    match result {
                        Ok(n) => {
                            let frame = Bytes::copy_from_slice(&buf[..n]);
                            if let Err(e) = self.handle_frame(frame).await {
                                tracing::warn!("handle_frame error: {e}");
                            }
                        }
                        Err(e) => tracing::warn!("wire_rx error: {e}"),
                    }
                }

                Some(req) = self.nw_rx.recv() => {
                    if let Err(e) = self.handle_outbound(req).await {
                        tracing::warn!("handle_outbound error: {e}");
                    }
                }

                else => {
                    // Both channels closed - stack is shutting down
                    tracing::info!("DataLink channels closed, shutting down");
                    break;
                }
            }
        }
    }

    async fn handle_frame(&mut self, frame: Bytes) -> Result<(), DataLinkError> {
        let eth_frame = match EthernetFrame::parse(frame) {
            Ok(frame) => frame,
            Err(e) => {
                tracing::debug!(error = %e, "ethernet frame parse failed - dropping");
                return Ok(());
            }
        };

        if let Err(e) = eth_frame.validate() {
            tracing::debug!(error = %e, "ethernet frame validation failed - dropping");
            return Ok(());
        }

        match eth_frame.header.ethertype {
            EtherType::ARP => self.handle_arp(&eth_frame.payload).await,
            EtherType::IPV4 => self
                .nw_tx
                .send(InboundIpv4 {
                    src_mac: eth_frame.header.src.into(),
                    payload: eth_frame.payload,
                })
                .await
                .map_err(|_| DataLinkError::NetworkChannelClosed),
            other => {
                tracing::debug!(ethertype = other.value(), "unhandled EtherType — dropping");
                Ok(())
            }
        }
    }

    async fn handle_arp(&mut self, payload: &[u8]) -> Result<(), DataLinkError> {
        let arp_packet = match ArpPacket::parse(payload) {
            Ok(pkt) => pkt,
            Err(e) => {
                tracing::debug!(error = %e, "arp packet parse failed - dropping");
                return Ok(());
            }
        };

        if let Err(e) = arp_packet.validate() {
            tracing::debug!(error = %e, "arp packet validation failed - dropping");
            return Ok(());
        }

        let mac = MacAddr::from(arp_packet.sha);
        let spa = Ipv4Addr::from(arp_packet.spa);
        self.arp_cache.insert(spa, mac);

        tracing::debug!(
            ip  = %spa,
            mac = ?mac,
            "ARP cache updated"
        );

        self.drain_outbound_queue(spa, mac).await?;

        if arp_packet.oper == ArpOperation::REQUEST && Ipv4Addr::from(arp_packet.tpa) == self.our_ip
        {
            self.send_arp_reply(mac, spa).await?;
        }

        Ok(())
    }

    async fn send_arp_reply(
        &self,
        dst_mac: MacAddr,
        dst_ip: Ipv4Addr,
    ) -> Result<(), DataLinkError> {
        let arp_reply = ArpPacket {
            htype: U16::<BigEndian>::new(1),
            ptype: U16::<BigEndian>::new(0x0800),
            hlen: 6,
            plen: 4,
            oper: ArpOperation::REPLY,
            sha: self.our_mac.get(),
            spa: self.our_ip.octets(),
            tha: dst_mac.get(),
            tpa: dst_ip.octets(),
        };

        tracing::debug!(
            dst_ip  = %dst_ip,
            dst_mac = ?dst_mac,
            "sending ARP reply"
        );

        let buf = TxBuf::new(proto::txbuf::ETH_HEADER_LEN, arp_reply.as_bytes());
        self.send_ethernet(dst_mac, EtherType::ARP, buf).await?;

        Ok(())
    }

    async fn handle_outbound(&mut self, request: DataLinkRequest) -> Result<(), DataLinkError> {
        match request {
            DataLinkRequest::Send(frame) => {
                match self.arp_cache.lookup(frame.dst_ip) {
                    Some(mac) => self.send_ethernet(mac, EtherType::IPV4, frame.buf).await?,
                    None => self.queue_outbound(frame).await?,
                };
            }

            DataLinkRequest::UpdateArp { ip, mac } => {
                self.arp_cache.insert(ip, mac);
                self.drain_outbound_queue(ip, mac).await?;
            }
        }

        Ok(())
    }

    async fn queue_outbound(&mut self, frame: OutboundFrame) -> Result<(), DataLinkError> {
        if !self.outbound_queue.contains_key(&frame.dst_ip) {
            tracing::debug!(
                dst_ip = %frame.dst_ip,
                "ARP cache miss — queuing packet, sending ARP request"
            );

            self.send_arp_request(frame.dst_ip).await?;
        }

        self.outbound_queue
            .entry(frame.dst_ip)
            .or_default()
            .push(frame);

        Ok(())
    }

    async fn drain_outbound_queue(
        &mut self,
        dst: Ipv4Addr,
        mac: MacAddr,
    ) -> Result<(), DataLinkError> {
        if let Some(frames) = self.outbound_queue.remove(&dst) {
            tracing::debug!(
                dst_ip = %dst,
                count  = frames.len(),
                "draining outbound queue"
            );

            for frame in frames {
                self.send_ethernet(mac, EtherType::IPV4, frame.buf).await?;
            }
        }

        Ok(())
    }

    async fn send_arp_request(&self, tpa: Ipv4Addr) -> Result<(), DataLinkError> {
        let arp_request = ArpPacket {
            htype: U16::<BigEndian>::new(1),
            ptype: U16::<BigEndian>::new(0x0800),
            hlen: 6,
            plen: 4,
            oper: ArpOperation::REQUEST,
            sha: self.our_mac.get(),
            spa: self.our_ip.octets(),
            tha: [0x00; 6],
            tpa: tpa.octets(),
        };

        let buf = TxBuf::new(proto::txbuf::ETH_HEADER_LEN, arp_request.as_bytes());
        self.send_ethernet(MacAddr::from([0xff; 6]), EtherType::ARP, buf)
            .await?;

        Ok(())
    }

    async fn send_ethernet(
        &self,
        dst_mac: MacAddr,
        ethertype: EtherType,
        mut buf: TxBuf,
    ) -> Result<(), DataLinkError> {
        let header = EthernetHeader {
            dst: dst_mac.get(),
            src: self.our_mac.get(),
            ethertype,
        };

        buf.prepend(header.as_bytes());

        self.wire_tx
            .send(&buf.freeze())
            .await
            .map_err(|_| DataLinkError::WireChannelClosed)?;

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum DataLinkError {
    #[error("wire channel closed")]
    WireChannelClosed,

    #[error("network channel closed")]
    NetworkChannelClosed,
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::txbuf::ETH_HEADER_LEN;

    fn our_mac() -> MacAddr {
        MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
    }

    fn our_ip() -> Ipv4Addr {
        Ipv4Addr::new(10, 0, 0, 1)
    }

    struct NullSource;

    impl PacketSource for NullSource {
        async fn recv(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            std::future::pending().await
        }
    }

    struct CaptureSink {
        tx: mpsc::Sender<Bytes>,
    }

    impl PacketSink for CaptureSink {
        async fn send(&self, buf: &[u8]) -> std::io::Result<()> {
            let _ = self.tx.send(Bytes::copy_from_slice(buf)).await;
            Ok(())
        }
    }

    struct TestHarness {
        dl: DataLink<CaptureSink, NullSource>,
        tap_out: mpsc::Receiver<Bytes>,
        nw_up: mpsc::Receiver<InboundIpv4>,
    }

    impl TestHarness {
        fn new() -> Self {
            let (cap_tx, tap_out) = mpsc::channel(16);

            let (nw_tx, nw_up) = mpsc::channel(16);
            let (_nw_down, nw_rx) = mpsc::channel(16);

            let dl = DataLink::new(
                our_mac(),
                our_ip(),
                CaptureSink { tx: cap_tx },
                NullSource,
                nw_tx,
                nw_rx,
                tokio_util::sync::CancellationToken::new(),
            );

            TestHarness { dl, tap_out, nw_up }
        }
    }

    fn make_arp_bytes(
        oper: ArpOperation,
        sha: [u8; 6],
        spa: [u8; 4],
        tha: [u8; 6],
        tpa: [u8; 4],
    ) -> Bytes {
        let arp = ArpPacket {
            htype: U16::<BigEndian>::new(1),
            ptype: U16::<BigEndian>::new(0x0800),
            hlen: 6,
            plen: 4,
            oper,
            sha,
            spa,
            tha,
            tpa,
        };
        Bytes::copy_from_slice(arp.as_bytes())
    }

    fn wrap_in_eth(dst: [u8; 6], src: [u8; 6], ethertype: EtherType, payload: &[u8]) -> Bytes {
        let header = EthernetHeader {
            dst,
            src,
            ethertype,
        };
        let mut buf = Vec::with_capacity(14 + payload.len().max(46));
        buf.extend_from_slice(header.as_bytes());
        buf.extend_from_slice(payload);
        // Pad to 46-byte minimum payload if needed
        while buf.len() < 60 {
            buf.push(0);
        }
        buf.into()
    }

    async fn recv_eth_frame(tap_out: &mut mpsc::Receiver<Bytes>) -> EthernetFrame {
        let bytes = tap_out.recv().await.expect("expected frame on tap_out");
        EthernetFrame::parse(bytes).expect("tap_out frame failed to parse")
    }

    #[tokio::test]
    async fn arp_request_for_our_ip_send_reply() {
        let mut h = TestHarness::new();

        let sender_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sender_ip = [10, 0, 0, 2];

        let arp = make_arp_bytes(
            ArpOperation::REQUEST,
            sender_mac,
            sender_ip,
            [0x00; 6],
            our_ip().octets(),
        );

        h.dl.handle_arp(&arp).await.unwrap();

        let frame = recv_eth_frame(&mut h.tap_out).await;
        assert_eq!(frame.header.dst, sender_mac);
        assert_eq!(frame.header.src, our_mac().get());
        assert_eq!(frame.header.ethertype, EtherType::ARP);

        let reply = ArpPacket::parse(&frame.payload).unwrap();
        assert_eq!(reply.oper, ArpOperation::REPLY);
        assert_eq!(reply.sha, our_mac().get());
        assert_eq!(reply.spa, our_ip().octets());
        assert_eq!(reply.tha, sender_mac);
        assert_eq!(reply.tpa, sender_ip);
    }

    #[tokio::test]
    async fn arp_request_not_for_our_ip_no_reply() {
        let mut h = TestHarness::new();

        let sender_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sender_ip = [10, 0, 0, 2];

        let arp = make_arp_bytes(
            ArpOperation::REQUEST,
            sender_mac,
            sender_ip,
            [0x00; 6],
            [10, 0, 0, 2],
        );

        h.dl.handle_arp(&arp).await.unwrap();

        assert!(h.tap_out.try_recv().is_err());
    }

    #[tokio::test]
    async fn arp_updates_cache() {
        let mut h = TestHarness::new();

        let sender_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sender_ip = Ipv4Addr::new(10, 0, 0, 2);

        let arp = make_arp_bytes(
            ArpOperation::REQUEST,
            sender_mac,
            sender_ip.octets(),
            [0x00; 6],
            our_ip().octets(),
        );

        h.dl.handle_arp(&arp).await.unwrap();

        assert_eq!(
            h.dl.arp_cache.lookup(sender_ip).unwrap(),
            MacAddr::from(sender_mac)
        );
    }

    #[tokio::test]
    async fn arp_reply_drains_outbound_queue() {
        let mut h = TestHarness::new();

        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let dst_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        let outbound_frame = OutboundFrame {
            dst_ip,
            buf: TxBuf::new(ETH_HEADER_LEN, &[0xAA; 20]),
        };

        h.dl.queue_outbound(outbound_frame).await.unwrap();
        let frame = recv_eth_frame(&mut h.tap_out).await;
        assert_eq!(frame.header.dst, [0xff; 6]);
        assert_eq!(frame.header.ethertype, EtherType::ARP);

        let arp = make_arp_bytes(
            ArpOperation::REPLY,
            dst_mac,
            dst_ip.octets(),
            our_mac().get(),
            our_ip().octets(),
        );
        h.dl.handle_arp(&arp).await.unwrap();

        let frame = recv_eth_frame(&mut h.tap_out).await;
        assert_eq!(frame.header.dst, dst_mac);
        assert_eq!(frame.header.ethertype, EtherType::IPV4);
    }

    #[tokio::test]
    async fn outbound_cache_hit_sends_immediately() {
        let mut h = TestHarness::new();

        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let dst_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        h.dl.arp_cache.insert(dst_ip, MacAddr::from(dst_mac));

        let req = DataLinkRequest::Send(OutboundFrame {
            dst_ip,
            buf: TxBuf::new(ETH_HEADER_LEN, &[0xBB; 20]),
        });

        h.dl.handle_outbound(req).await.unwrap();

        let frame = recv_eth_frame(&mut h.tap_out).await;
        assert_eq!(frame.header.dst, dst_mac);
        assert_eq!(frame.header.src, our_mac().get());
        assert_eq!(frame.header.ethertype, EtherType::IPV4);
    }

    #[tokio::test]
    async fn outbound_cache_miss_queues_and_sends_arp_request() {
        let mut h = TestHarness::new();

        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);

        let req = DataLinkRequest::Send(OutboundFrame {
            dst_ip,
            buf: TxBuf::new(ETH_HEADER_LEN, &[0xBB; 20]),
        });

        h.dl.handle_outbound(req).await.unwrap();

        let frame = recv_eth_frame(&mut h.tap_out).await;
        // Should be a broadcast ARP request
        assert_eq!(frame.header.dst, [0xff; 6]);
        assert_eq!(frame.header.ethertype, EtherType::ARP);

        let arp = ArpPacket::parse(&frame.payload).unwrap();
        assert_eq!(arp.oper, ArpOperation::REQUEST);
        assert_eq!(arp.tpa, dst_ip.octets());
        assert_eq!(arp.sha, our_mac().get());
        assert_eq!(arp.tha, [0x00; 6]);

        // Packet should be in the queue, not yet sent
        assert!(h.dl.outbound_queue.contains_key(&dst_ip));
        assert_eq!(h.dl.outbound_queue[&dst_ip].len(), 1);
    }

    #[tokio::test]
    async fn outbound_cache_miss_only_one_arp_request_per_ip() {
        let mut h = TestHarness::new();

        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);

        // Send two packets to the same unknown IP
        for _ in 0..2 {
            let req = DataLinkRequest::Send(OutboundFrame {
                dst_ip,
                buf: TxBuf::new(ETH_HEADER_LEN, &[0xDD; 10]),
            });
            h.dl.handle_outbound(req).await.unwrap();
        }

        // Only one ARP request should have been sent
        let _arp_request = h.tap_out.recv().await.unwrap();
        assert!(h.tap_out.try_recv().is_err());

        // Both packets queued
        assert_eq!(h.dl.outbound_queue[&dst_ip].len(), 2);
    }

    #[tokio::test]
    async fn update_arp_drains_queue() {
        let mut h = TestHarness::new();

        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let dst_mac = MacAddr::from([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);

        let outbound_frame = OutboundFrame {
            dst_ip,
            buf: TxBuf::new(ETH_HEADER_LEN, &[0xCC; 20]),
        };

        h.dl.queue_outbound(outbound_frame).await.unwrap();

        // Consume the ARP request sent
        recv_eth_frame(&mut h.tap_out).await;

        let req = DataLinkRequest::UpdateArp {
            ip: dst_ip,
            mac: dst_mac,
        };

        h.dl.handle_outbound(req).await.unwrap();

        // Queued packet should be sent
        let frame = recv_eth_frame(&mut h.tap_out).await;
        assert_eq!(frame.header.dst, dst_mac.get());
        assert_eq!(frame.header.ethertype, EtherType::IPV4);

        // Queue should be empty
        assert!(!h.dl.outbound_queue.contains_key(&dst_ip));
    }

    #[tokio::test]
    async fn handle_frame_arp_dispatches_to_handle_arp() {
        let mut h = TestHarness::new();

        let sender_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let sender_ip = [10, 0, 0, 2];
        let arp = make_arp_bytes(
            ArpOperation::REQUEST,
            sender_mac,
            sender_ip,
            [0x00; 6],
            our_ip().octets(),
        );

        let frame_bytes = wrap_in_eth(our_mac().get(), sender_mac, EtherType::ARP, &arp);

        h.dl.handle_frame(frame_bytes).await.unwrap();

        // ARP reply should appear on tap
        let frame = recv_eth_frame(&mut h.tap_out).await;
        assert_eq!(frame.header.ethertype, EtherType::ARP);
    }

    #[tokio::test]
    async fn handle_frame_ipv4_sent_up_to_network() {
        let mut h = TestHarness::new();

        let src_mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let payload = [0xAA; 46];

        let frame_bytes = wrap_in_eth(our_mac().get(), src_mac, EtherType::IPV4, &payload);

        h.dl.handle_frame(frame_bytes).await.unwrap();

        // Should arrive on the network channel
        let inbound = h.nw_up.recv().await.expect("expected InboundIpv4");
        assert_eq!(inbound.src_mac.get(), src_mac);
        assert_eq!(&inbound.payload[..payload.len()], &payload);
    }

    #[tokio::test]
    async fn handle_frame_malformed_is_dropped_not_error() {
        let mut h = TestHarness::new();

        // Too short to be a valid Ethernet frame
        let bad = Bytes::from_static(&[0x00, 0x01, 0x02]);
        let result = h.dl.handle_frame(bad).await;

        // Should return Ok — malformed frames are dropped, not errors
        assert!(result.is_ok());

        // Nothing sent to tap or network
        assert!(h.tap_out.try_recv().is_err());
        assert!(h.nw_up.try_recv().is_err());
    }

    #[tokio::test]
    async fn handle_frame_malformed_arp_is_dropped_not_error() {
        let mut h = TestHarness::new();

        let bad_arp = &[0x00, 0x01]; // too short to be valid ARP
        let frame_bytes = wrap_in_eth(our_mac().get(), [0x11; 6], EtherType::ARP, bad_arp);

        let result = h.dl.handle_frame(frame_bytes).await;
        assert!(result.is_ok());
        assert!(h.tap_out.try_recv().is_err());
    }
}
