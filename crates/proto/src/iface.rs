use std::{io, net::Ipv4Addr};

use thiserror::Error;

/// A sink for raw Ethernet frames.
pub trait PacketSink {
    fn send(&self, buf: &[u8]) -> impl std::future::Future<Output = io::Result<()>> + Send;
}

/// A source of raw Ethernet frames.
pub trait PacketSource {
    fn recv(
        &mut self,
        buf: &mut [u8],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send;
}

/// A valid IPv4 prefix length in CIDR notation (0–32).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixLen(u8);

impl TryFrom<u8> for PrefixLen {
    type Error = InterfaceError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 32 {
            Ok(Self(value))
        } else {
            Err(InterfaceError::InvalidPrefixLen(value))
        }
    }
}

impl PrefixLen {
    /// Returns the raw CIDR prefix length value.
    pub fn get(self) -> u8 {
        self.0
    }

    /// Converts the prefix length to a dotted-decimal netmask.
    pub fn to_netmask(self) -> Ipv4Addr {
        if self.0 == 0 {
            return Ipv4Addr::new(0, 0, 0, 0);
        }
        let bits = !0u32 << (32 - self.0 as u32);
        Ipv4Addr::from(bits)
    }
}

/// A valid unicast MAC address.
///
/// Rejects broadcast (`ff:ff:ff:ff:ff:ff`) and multicast
/// (LSB of first octet set) addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr([u8; 6]);

impl TryFrom<[u8; 6]> for MacAddr {
    type Error = InterfaceError;

    fn try_from(mac: [u8; 6]) -> Result<Self, Self::Error> {
        // Reject broadcast address
        if mac == [0xFF; 6] {
            return Err(InterfaceError::InvalidMac(mac));
        }

        // Reject multicast — LSB of first octet indicates multicast
        // IEEE 802 — bit 0 of the first octet is the I/G (individual/group) bit
        if mac[0] & 0x01 != 0 {
            return Err(InterfaceError::InvalidMac(mac));
        }

        Ok(Self(mac))
    }
}

impl MacAddr {
    /// Returns the raw MAC address bytes.
    pub fn get(self) -> [u8; 6] {
        self.0
    }
}

/// Complete configuration for a network interface.
#[derive(Debug, Clone)]
pub struct InterfaceConfig {
    /// Linux interface name. Maximum 15 characters.
    pub name: String,
    /// MAC address assigned to the network interface.
    pub mac: MacAddr,
    /// IPv4 address assigned to the network interface.
    pub ip: Ipv4Addr,
    /// CIDR prefix length (e.g. 24 for /24).
    pub prefix: PrefixLen,
}

#[derive(Error, Debug)]
pub enum InterfaceError {
    #[error("invalid prefix length {0}: must be 0–32")]
    InvalidPrefixLen(u8),

    #[error("invalid MAC address {0:02x?}: must be a unicast address")]
    InvalidMac([u8; 6]),
}
