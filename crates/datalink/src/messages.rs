use bytes::Bytes;
use proto::{iface::MacAddr, txbuf::TxBuf};
use std::net::Ipv4Addr;

/// Upwards data sent to network layer
pub struct InboundIpv4 {
    pub src_mac: MacAddr,
    pub payload: Bytes,
}

/// Downward request received from network layer
pub enum DataLinkRequest {
    Send(OutboundFrame),
    UpdateArp { ip: Ipv4Addr, mac: MacAddr },
}

/// Outbound frame sent by network layer
pub struct OutboundFrame {
    pub dst_ip: Ipv4Addr,
    pub buf: TxBuf,
}
