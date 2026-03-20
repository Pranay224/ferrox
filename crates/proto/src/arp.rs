use thiserror::Error;
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, U16};

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct ArpOperation(U16<BigEndian>);

impl ArpOperation {
    pub const REQUEST: Self = Self(U16::new(1));
    pub const REPLY: Self = Self(U16::new(2));

    pub fn value(&self) -> u16 {
        self.0.get()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct ArpPacket {
    pub htype: U16<BigEndian>,
    pub ptype: U16<BigEndian>,
    pub hlen: u8,
    pub plen: u8,
    pub oper: ArpOperation,
    pub sha: [u8; 6],
    pub spa: [u8; 4],
    pub tha: [u8; 6],
    pub tpa: [u8; 4],
}

impl ArpPacket {
    /// Parses a ARP packet from a raw byte slice.
    ///
    /// Since ARP has no variable-sized fields, this implementation has no allocations.
    ///
    /// Call [`ArpPacket::validate`] to check for semantic errors after successful parsing.
    ///
    /// # Errors
    ///
    /// - [`ArpError::InvalidBufferLength`] is buf is not exactly `size_of::<ArpPacket>()` bytes long.
    pub fn parse(buf: &[u8]) -> Result<Self, ArpError> {
        ArpPacket::read_from_bytes(buf).map_err(|_| ArpError::InvalidBufferLength {
            needed: size_of::<ArpPacket>(),
            got: buf.len(),
        })
    }

    /// Checks semantic validity of parsed ARP packets.
    ///
    /// This is intentionally different from [`ArpPacket::parse`] - parsing checks structure,
    /// while validation checks semantics. Call this after `parse` before handling any
    /// ARP operation.
    ///
    /// # Errors
    ///
    /// - [`ArpError::UnsupportedHardwareType`] - not Ethernet
    /// - [`ArpError::UnsupportedProtocolType`] - not IPv4
    /// - [`ArpError::InvalidOperation`] - not REQUEST or REPLY
    pub fn validate(&self) -> Result<(), ArpError> {
        // RFC 826 — ferrox only handles Ethernet hardware addresses
        if self.htype != 1 || self.hlen != 6 {
            return Err(ArpError::UnsupportedHardwareType {
                htype: self.htype.get(),
                hlen: self.hlen,
            });
        }

        // RFC 826 — ferrox only handles IPv4 protocol addresses
        if self.ptype != 0x0800 || self.plen != 4 {
            return Err(ArpError::UnsupportedProtocolType {
                ptype: self.ptype.get(),
                plen: self.plen,
            });
        }

        // RFC 826 - only REQUEST (1) and REPLY (2) are defined operations
        if self.oper != ArpOperation::REQUEST && self.oper != ArpOperation::REPLY {
            return Err(ArpError::InvalidOperation(self.oper.value()));
        }

        Ok(())
    }

    /// Serializes an ArpPacket into `buf`.
    ///
    /// # Errors
    ///
    /// - [`ArpError::BufferTooSmall`] if `buf` is shorter than `size_of::<ArpPacket>()` bytes.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, ArpError> {
        let needed = size_of::<ArpPacket>();

        if buf.len() < needed {
            return Err(ArpError::BufferTooSmall {
                needed,
                got: buf.len(),
            });
        }

        buf[..needed].copy_from_slice(self.as_bytes());
        Ok(needed)
    }
}

#[derive(Error, Debug)]
pub enum ArpError {
    #[error("buffer too short: need {needed} bytes for ARP packet, got {got}")]
    InvalidBufferLength { needed: usize, got: usize },

    #[error("unsupported hardware type: htype - {htype}, hlen - {hlen} [expected htype 1, hlen 6]")]
    UnsupportedHardwareType { htype: u16, hlen: u8 },

    #[error(
        "unsupported protocol type: ptype - {ptype:#06x}, plen - {plen} [expected ptype 0x0800, plen 4]"
    )]
    UnsupportedProtocolType { ptype: u16, plen: u8 },

    #[error("invalid ARP operation: {0}")]
    InvalidOperation(u16),

    #[error("buffer too small: needed {needed} bytes, got {got}")]
    BufferTooSmall { needed: usize, got: usize },
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Constructs a valid ARP request packet as raw bytes.
    /// sender: aa:bb:cc:dd:ee:ff / 192.168.1.1
    /// target: 00:00:00:00:00:00 / 192.168.1.2
    fn arp_request_bytes() -> Vec<u8> {
        let pkt = ArpPacket {
            htype: U16::new(1),
            ptype: U16::new(0x0800),
            hlen: 6,
            plen: 4,
            oper: ArpOperation::REQUEST,
            sha: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            spa: [192, 168, 1, 1],
            tha: [0x00; 6],
            tpa: [192, 168, 1, 2],
        };

        pkt.as_bytes().to_vec()
    }

    /// Constructs a valid ARP reply packet as raw bytes.
    /// sender: 11:22:33:44:55:66 / 192.168.1.2
    /// target: aa:bb:cc:dd:ee:ff / 192.168.1.1
    fn arp_reply_bytes() -> Vec<u8> {
        let pkt = ArpPacket {
            htype: U16::new(1),
            ptype: U16::new(0x0800),
            hlen: 6,
            plen: 4,
            oper: ArpOperation::REPLY,
            sha: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            spa: [192, 168, 1, 2],
            tha: [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
            tpa: [192, 168, 1, 1],
        };

        pkt.as_bytes().to_vec()
    }

    // parse

    #[test]
    fn parse_valid_request() {
        let buf = arp_request_bytes();
        let pkt = ArpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.htype.get(), 1);
        assert_eq!(pkt.ptype.get(), 0x0800);
        assert_eq!(pkt.hlen, 6);
        assert_eq!(pkt.plen, 4);
        assert_eq!(pkt.oper, ArpOperation::REQUEST);
        assert_eq!(pkt.sha, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(pkt.spa, [192, 168, 1, 1]);
        assert_eq!(pkt.tha, [0x00; 6]);
        assert_eq!(pkt.tpa, [192, 168, 1, 2]);
    }

    #[test]
    fn parse_valid_reply() {
        let buf = arp_reply_bytes();
        let pkt = ArpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.oper, ArpOperation::REPLY);
        assert_eq!(pkt.sha, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        assert_eq!(pkt.spa, [192, 168, 1, 2]);
        assert_eq!(pkt.tha, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(pkt.tpa, [192, 168, 1, 1]);
    }

    #[test]
    fn parse_empty_buffer_fails() {
        assert!(matches!(
            ArpPacket::parse(&[]),
            Err(ArpError::InvalidBufferLength { needed: 28, got: 0 })
        ));
    }

    #[test]
    fn parse_one_byte_too_short_fails() {
        let buf = arp_request_bytes();
        assert!(matches!(
            ArpPacket::parse(&buf[..27]),
            Err(ArpError::InvalidBufferLength {
                needed: 28,
                got: 27
            })
        ));
    }

    #[test]
    fn parse_exact_size_succeeds() {
        let buf = arp_request_bytes();
        assert_eq!(buf.len(), 28);
        assert!(ArpPacket::parse(&buf).is_ok());
    }

    #[test]
    fn parse_oversized_buffer_fails() {
        // read_from_bytes requires exact size — extra bytes are an error.
        // This is correct behaviour: ARP is fixed 28 bytes, extra bytes
        // indicate a framing error upstream in Ethernet parsing.
        let mut buf = arp_request_bytes();
        buf.push(0x00);
        assert!(matches!(
            ArpPacket::parse(&buf),
            Err(ArpError::InvalidBufferLength { .. })
        ));
    }

    // validate

    #[test]
    fn validate_request_passes() {
        let pkt = ArpPacket::parse(&arp_request_bytes()).unwrap();
        assert!(pkt.validate().is_ok());
    }

    #[test]
    fn validate_reply_passes() {
        let pkt = ArpPacket::parse(&arp_reply_bytes()).unwrap();
        assert!(pkt.validate().is_ok());
    }

    #[test]
    fn validate_wrong_htype_rejected() {
        let mut buf = arp_request_bytes();
        buf[0..2].copy_from_slice(&[0x00, 0x06]); // htype=6 (IEEE 802 instead of Ethernet)
        let pkt = ArpPacket::parse(&buf).unwrap();
        assert!(matches!(
            pkt.validate(),
            Err(ArpError::UnsupportedHardwareType { htype: 6, hlen: 6 })
        ));
    }

    #[test]
    fn validate_wrong_hlen_rejected() {
        let mut buf = arp_request_bytes();
        buf[4] = 8; // hlen=8 instead of 6
        let pkt = ArpPacket::parse(&buf).unwrap();
        assert!(matches!(
            pkt.validate(),
            Err(ArpError::UnsupportedHardwareType { htype: 1, hlen: 8 })
        ));
    }

    #[test]
    fn validate_wrong_ptype_rejected() {
        let mut buf = arp_request_bytes();
        buf[2..4].copy_from_slice(&[0x86, 0xDD]); // ptype=0x86DD (IPv6)
        let pkt = ArpPacket::parse(&buf).unwrap();
        assert!(matches!(
            pkt.validate(),
            Err(ArpError::UnsupportedProtocolType {
                ptype: 0x86DD,
                plen: 4
            })
        ));
    }

    #[test]
    fn validate_wrong_plen_rejected() {
        let mut buf = arp_request_bytes();
        buf[5] = 16; // plen=16 instead of 4
        let pkt = ArpPacket::parse(&buf).unwrap();
        assert!(matches!(
            pkt.validate(),
            Err(ArpError::UnsupportedProtocolType {
                ptype: 0x0800,
                plen: 16
            })
        ));
    }

    #[test]
    fn validate_unknown_operation_rejected() {
        let mut buf = arp_request_bytes();
        buf[6..8].copy_from_slice(&[0x00, 0x03]); // oper=3 (undefined)
        let pkt = ArpPacket::parse(&buf).unwrap();
        assert!(matches!(pkt.validate(), Err(ArpError::InvalidOperation(3))));
    }

    // serialize

    #[test]
    fn serialize_produces_correct_bytes() {
        let original = arp_request_bytes();
        let pkt = ArpPacket::parse(&original).unwrap();

        let mut out = vec![0u8; 28];
        let written = pkt.serialize(&mut out).unwrap();

        assert_eq!(written, 28);
        assert_eq!(out, original);
    }

    #[test]
    fn serialize_into_larger_buffer_succeeds() {
        // Buffer larger than needed — serialize should write 28 bytes and
        // leave the rest untouched.
        let pkt = ArpPacket::parse(&arp_request_bytes()).unwrap();
        let mut out = vec![0xFFu8; 64];
        let written = pkt.serialize(&mut out).unwrap();

        assert_eq!(written, 28);
        assert_eq!(&out[28..], &[0xFFu8; 36]); // untouched
    }

    #[test]
    fn serialize_buffer_too_small_fails() {
        let pkt = ArpPacket::parse(&arp_request_bytes()).unwrap();
        let mut out = vec![0u8; 27];
        assert!(matches!(
            pkt.serialize(&mut out),
            Err(ArpError::BufferTooSmall {
                needed: 28,
                got: 27
            })
        ));
    }

    // round trip

    #[test]
    fn round_trip_request() {
        let original = arp_request_bytes();
        let pkt = ArpPacket::parse(&original).unwrap();

        let mut buf = vec![0u8; 28];
        pkt.serialize(&mut buf).unwrap();

        let reparsed = ArpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.oper, reparsed.oper);
        assert_eq!(pkt.sha, reparsed.sha);
        assert_eq!(pkt.spa, reparsed.spa);
        assert_eq!(pkt.tha, reparsed.tha);
        assert_eq!(pkt.tpa, reparsed.tpa);
    }

    #[test]
    fn round_trip_reply() {
        let original = arp_reply_bytes();
        let pkt = ArpPacket::parse(&original).unwrap();

        let mut buf = vec![0u8; 28];
        pkt.serialize(&mut buf).unwrap();

        let reparsed = ArpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.oper, reparsed.oper);
        assert_eq!(pkt.sha, reparsed.sha);
        assert_eq!(pkt.spa, reparsed.spa);
        assert_eq!(pkt.tha, reparsed.tha);
        assert_eq!(pkt.tpa, reparsed.tpa);
    }
}
