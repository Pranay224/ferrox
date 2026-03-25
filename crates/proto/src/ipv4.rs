use thiserror::Error;
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, U16};

use crate::checksum;

#[derive(FromBytes, IntoBytes, Immutable, KnownLayout, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct IpProtocol(u8);

impl IpProtocol {
    pub const ICMP: Self = Self(1);
    pub const TCP: Self = Self(6);
    pub const UDP: Self = Self(17);

    pub fn value(self) -> u8 {
        self.0
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Debug, Clone, Copy)]
#[repr(C)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: U16<BigEndian>,
    pub identification: U16<BigEndian>,
    pub flags_fragment: U16<BigEndian>,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: U16<BigEndian>,
    pub src: [u8; 4],
    pub dst: [u8; 4],
}

impl Ipv4Header {
    /// Returns the IP version. RFC 791 — high nibble of version_ihl.
    pub fn version(&self) -> u8 {
        (self.version_ihl & 0xF0) >> 4
    }

    /// Returns the IHL field value (header length in 32-bit words).
    /// RFC 791 — low nibble of version_ihl. Valid range: 5–15.
    pub fn ihl(&self) -> u8 {
        self.version_ihl & 0x0F
    }

    /// Returns the header length in bytes (ihl * 4).
    pub fn header_len(&self) -> usize {
        (self.ihl() as usize) * 4
    }

    /// RFC 791 — reserved flag (bit 15). Must always be 0.
    pub fn flag_reserved(&self) -> bool {
        self.flags_fragment.get() & 0x8000 != 0
    }

    /// RFC 791 — Don't Fragment flag (bit 14).
    pub fn flag_dont_fragment(&self) -> bool {
        self.flags_fragment.get() & 0x4000 != 0
    }

    /// RFC 791 — More Fragments flag (bit 13).
    pub fn flag_more_fragments(&self) -> bool {
        self.flags_fragment.get() & 0x2000 != 0
    }

    /// Fragment offset in units of 8 bytes. RFC 791 — low 13 bits.
    pub fn fragment_offset(&self) -> u16 {
        self.flags_fragment.get() & 0x1FFF
    }
}

#[derive(Debug)]
pub struct Ipv4Packet<'a> {
    pub header: &'a Ipv4Header,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> Ipv4Packet<'a> {
    /// Parses an IPv4 packet from a raw byte slice.
    ///
    /// Borrows directly from `buf` — no allocation occurs. Performs structural
    /// parsing only. Call [`Ipv4Packet::validate`] for semantic checks.
    ///
    /// # Errors
    ///
    /// - [`Ipv4Error::TooShort`] — buffer smaller than 20-byte fixed header
    /// - [`Ipv4Error::InvalidIhl`] — IHL field is less than 5
    pub fn parse(buf: &'a [u8]) -> Result<Self, Ipv4Error> {
        let (header, rest) =
            Ref::<_, Ipv4Header>::from_prefix(buf).map_err(|_| Ipv4Error::TooShort {
                needed: size_of::<Ipv4Header>(),
                got: buf.len(),
            })?;

        let header = Ref::into_ref(header);
        let header_len = header.header_len();

        // RFC 791 — minimum IHL is 5 (20 bytes)
        if header.ihl() < 5 {
            return Err(Ipv4Error::InvalidIhl(header.ihl()));
        }

        // Length of the options section is the total header length minus the fixed 20-byte header.
        let options_len = header_len - size_of::<Ipv4Header>();

        // If the IHL is valid but the packet is too short to contain all the options, split_at
        // will panic. This check catches that edge case before splitting again.
        if rest.len() < options_len {
            return Err(Ipv4Error::TooShort {
                needed: header_len,
                got: buf.len(),
            });
        }

        let (options, payload) = rest.split_at(options_len);

        Ok(Self {
            header,
            options,
            payload,
        })
    }

    /// Validates semantic correctness of a parsed IPv4 packet.
    ///
    /// # Errors
    ///
    /// - [`Ipv4Error::InvalidVersion`] — version field is not 4
    /// - [`Ipv4Error::BadChecksum`] — header checksum is invalid
    /// - [`Ipv4Error::BroadcastSource`] — source address is 255.255.255.255
    /// - [`Ipv4Error::TtlExpired`] — TTL is 0
    /// - [`Ipv4Error::InvalidFlags`] — reserved flag is set
    /// - [`Ipv4Error::TotalLengthMismatch`] — total_length field doesn't match actual size
    pub fn validate(&self) -> Result<(), Ipv4Error> {
        // RFC 791 — version must be 4
        if self.header.version() != 4 {
            return Err(Ipv4Error::InvalidVersion(self.header.version()));
        }

        // RFC 791 — header checksum. Checksumming the full header
        // including the checksum field must yield 0x0000 for a valid packet.
        if !checksum::verify(self.header.as_bytes()) {
            return Err(Ipv4Error::BadChecksum);
        }

        // A packet cannot originate from a broadcast address
        if self.header.src == [0xff; 4] {
            return Err(Ipv4Error::BroadcastSource);
        }

        // RFC 791 — TTL of 0 means the packet has expired in transit
        if self.header.ttl == 0 {
            return Err(Ipv4Error::TtlExpired);
        }

        // RFC 791 — reserved flag must be 0
        if self.header.flag_reserved() {
            return Err(Ipv4Error::InvalidFlags);
        }

        // RFC 791 — total_length must match the actual datagram size
        let actual = size_of::<Ipv4Header>() + self.options.len() + self.payload.len();
        let claimed = self.header.total_length.get() as usize;

        if claimed != actual {
            return Err(Ipv4Error::TotalLengthMismatch {
                claimed: self.header.total_length.get(),
                actual,
            });
        }

        Ok(())
    }

    /// Serializes the packet into `buf`, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Ipv4Error::BufferTooSmall`] if `buf` is too short.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, Ipv4Error> {
        let total = size_of::<Ipv4Header>() + self.options.len() + self.payload.len();

        if buf.len() < total {
            return Err(Ipv4Error::BufferTooSmall {
                needed: total,
                got: buf.len(),
            });
        }

        let (header_buf, rest) = buf.split_at_mut(size_of::<Ipv4Header>());
        header_buf.copy_from_slice(self.header.as_bytes());

        let (options_buf, payload_buf) = rest.split_at_mut(self.options.len());
        options_buf.copy_from_slice(self.options);
        payload_buf[..self.payload.len()].copy_from_slice(self.payload);

        Ok(total)
    }
}

#[derive(Error, Debug)]
pub enum Ipv4Error {
    #[error("buffer too short: need {needed} bytes, got {got}")]
    TooShort { needed: usize, got: usize },

    #[error("invalid IHL value {0}: must be between 5 and 15 (20–60 bytes)")]
    InvalidIhl(u8),

    #[error("invalid version {0}: expected 4")]
    InvalidVersion(u8),

    #[error("invalid header checksum")]
    BadChecksum,

    #[error("source address cannot be broadcast")]
    BroadcastSource,

    #[error("packet has expired")]
    TtlExpired,

    #[error("reserved flag is set")]
    InvalidFlags,

    #[error("total_length field ({claimed}) does not match actual packet size ({actual})")]
    TotalLengthMismatch { claimed: u16, actual: usize },

    #[error("buffer too small to serialize: need {needed} bytes, got {got}")]
    BufferTooSmall { needed: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;

    // ── helpers ────────────────────────────────────────────────────────────────

    /// Builds a minimal valid IPv4 header with no options.
    /// Checksum is computed and set correctly.
    fn make_header(
        src: [u8; 4],
        dst: [u8; 4],
        protocol: IpProtocol,
        ttl: u8,
        payload_len: usize,
    ) -> Ipv4Header {
        let total_length = (size_of::<Ipv4Header>() + payload_len) as u16;

        let mut header = Ipv4Header {
            version_ihl: 0x45, // version=4, IHL=5 (no options)
            dscp_ecn: 0,
            total_length: U16::new(total_length),
            identification: U16::new(0),
            flags_fragment: U16::new(0),
            ttl,
            protocol,
            checksum: U16::new(0), // zero before computing
            src,
            dst,
        };

        // Compute and set the checksum
        let csum = checksum::compute(header.as_bytes());
        header.checksum = U16::new(csum);
        header
    }

    /// Builds a complete valid IPv4 packet as raw bytes with given payload.
    fn make_packet(payload: &[u8]) -> Vec<u8> {
        let header = make_header(
            [192, 168, 1, 1],
            [192, 168, 1, 2],
            IpProtocol::TCP,
            64,
            payload.len(),
        );

        let mut buf = header.as_bytes().to_vec();
        buf.extend_from_slice(payload);
        buf
    }

    // ── parse ──────────────────────────────────────────────────────────────────

    #[test]
    fn parse_valid_packet() {
        let payload = [0u8; 20];
        let buf = make_packet(&payload);
        let pkt = Ipv4Packet::parse(&buf).unwrap();

        assert_eq!(pkt.header.version(), 4);
        assert_eq!(pkt.header.ihl(), 5);
        assert_eq!(pkt.header.header_len(), 20);
        assert_eq!(pkt.header.ttl, 64);
        assert_eq!(pkt.header.protocol, IpProtocol::TCP);
        assert_eq!(pkt.header.src, [192, 168, 1, 1]);
        assert_eq!(pkt.header.dst, [192, 168, 1, 2]);
        assert_eq!(pkt.options, &[]);
        assert_eq!(pkt.payload, &payload);
    }

    #[test]
    fn parse_empty_buffer_fails() {
        assert!(matches!(
            Ipv4Packet::parse(&[]),
            Err(Ipv4Error::TooShort { needed: 20, got: 0 })
        ));
    }

    #[test]
    fn parse_one_byte_too_short_fails() {
        let buf = make_packet(&[0u8; 20]);
        assert!(matches!(
            Ipv4Packet::parse(&buf[..19]),
            Err(Ipv4Error::TooShort { .. })
        ));
    }

    #[test]
    fn parse_ihl_too_small_fails() {
        let mut buf = make_packet(&[0u8; 20]);
        buf[0] = 0x44; // version=4, IHL=4 (below minimum of 5)
        assert!(matches!(
            Ipv4Packet::parse(&buf),
            Err(Ipv4Error::InvalidIhl(4))
        ));
    }

    #[test]
    fn parse_ihl_zero_fails() {
        let mut buf = make_packet(&[0u8; 20]);
        buf[0] = 0x40; // version=4, IHL=0
        assert!(matches!(
            Ipv4Packet::parse(&buf),
            Err(Ipv4Error::InvalidIhl(0))
        ));
    }

    #[test]
    fn parse_with_options() {
        // IHL=6 means 24-byte header: 20 fixed + 4 bytes of options
        let options = [0x00u8, 0x00, 0x00, 0x00]; // NOP padding
        let payload = [0xAAu8; 16];

        let mut header = make_header(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            IpProtocol::UDP,
            128,
            options.len() + payload.len(),
        );

        // Set IHL=6 (24 bytes) and recompute checksum
        header.version_ihl = 0x46;
        header.checksum = U16::new(0);
        header.checksum = U16::new(checksum::compute(header.as_bytes()));

        let mut buf = header.as_bytes().to_vec();
        buf.extend_from_slice(&options);
        buf.extend_from_slice(&payload);

        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert_eq!(pkt.header.ihl(), 6);
        assert_eq!(pkt.header.header_len(), 24);
        assert_eq!(pkt.options, &options);
        assert_eq!(pkt.payload, &payload);
    }

    #[test]
    fn parse_options_present_but_buffer_too_short_fails() {
        // IHL=6 claims 24-byte header but buffer only has 20 bytes
        let mut buf = make_packet(&[0u8; 20]);
        buf[0] = 0x46; // IHL=6
        assert!(matches!(
            Ipv4Packet::parse(&buf[..20]),
            Err(Ipv4Error::TooShort { .. })
        ));
    }

    // ── validate ───────────────────────────────────────────────────────────────

    #[test]
    fn validate_valid_packet_passes() {
        let buf = make_packet(&[0u8; 20]);
        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert!(pkt.validate().is_ok());
    }

    #[test]
    fn validate_wrong_version_rejected() {
        let mut buf = make_packet(&[0u8; 20]);
        buf[0] = 0x65; // version=6, IHL=5
        // Recompute checksum so it doesn't fail there first
        let csum = checksum::compute(&buf[..20]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());

        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert!(matches!(pkt.validate(), Err(Ipv4Error::InvalidVersion(6))));
    }

    #[test]
    fn validate_bad_checksum_rejected() {
        let mut buf = make_packet(&[0u8; 20]);
        buf[10] ^= 0xFF; // corrupt the checksum field
        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert!(matches!(pkt.validate(), Err(Ipv4Error::BadChecksum)));
    }

    #[test]
    fn validate_corrupted_payload_with_bad_checksum() {
        // Corrupt a payload byte — the header checksum won't catch this
        // (it only covers the header) but it proves checksum scope is correct.
        let mut buf = make_packet(&[0u8; 20]);
        buf[25] ^= 0xFF; // corrupt a payload byte
        let pkt = Ipv4Packet::parse(&buf).unwrap();
        // Header checksum should still pass — it doesn't cover the payload
        assert!(pkt.validate().is_ok());
    }

    #[test]
    fn validate_broadcast_source_rejected() {
        let mut buf = make_packet(&[0u8; 20]);
        buf[12..16].copy_from_slice(&[0xff; 4]); // src = 255.255.255.255
        // Recompute checksum
        buf[10..12].copy_from_slice(&[0, 0]);
        let csum = checksum::compute(&buf[..20]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());

        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert!(matches!(pkt.validate(), Err(Ipv4Error::BroadcastSource)));
    }

    #[test]
    fn validate_ttl_zero_rejected() {
        let header = make_header(
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            IpProtocol::TCP,
            0, // TTL = 0
            20,
        );
        let mut buf = header.as_bytes().to_vec();
        buf.extend_from_slice(&[0u8; 20]);

        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert!(matches!(pkt.validate(), Err(Ipv4Error::TtlExpired)));
    }

    #[test]
    fn validate_reserved_flag_rejected() {
        let mut buf = make_packet(&[0u8; 20]);
        // Set the reserved flag (bit 15 of flags_fragment, byte offset 6)
        buf[6] |= 0x80;
        // Recompute checksum
        buf[10..12].copy_from_slice(&[0u8; 2]);
        let csum = checksum::compute(&buf[..20]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());

        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert!(matches!(pkt.validate(), Err(Ipv4Error::InvalidFlags)));
    }

    #[test]
    fn validate_total_length_mismatch_rejected() {
        let mut buf = make_packet(&[0u8; 20]);
        // Claim total_length = 100 but actual size is 40
        buf[2..4].copy_from_slice(&100u16.to_be_bytes());
        // Recompute checksum with the new total_length
        buf[10..12].copy_from_slice(&[0u8; 2]);
        let csum = checksum::compute(&buf[..20]);
        buf[10..12].copy_from_slice(&csum.to_be_bytes());

        let pkt = Ipv4Packet::parse(&buf).unwrap();
        assert!(matches!(
            pkt.validate(),
            Err(Ipv4Error::TotalLengthMismatch { claimed: 100, .. })
        ));
    }

    // ── serialize ──────────────────────────────────────────────────────────────

    #[test]
    fn serialize_produces_correct_bytes() {
        let payload = [0xBBu8; 20];
        let original = make_packet(&payload);
        let pkt = Ipv4Packet::parse(&original).unwrap();

        let mut out = vec![0u8; original.len()];
        let written = pkt.serialize(&mut out).unwrap();

        assert_eq!(written, original.len());
        assert_eq!(out, original);
    }

    #[test]
    fn serialize_buffer_too_small_fails() {
        let buf = make_packet(&[0u8; 20]);
        let pkt = Ipv4Packet::parse(&buf).unwrap();

        let mut out = vec![0u8; 10];
        assert!(matches!(
            pkt.serialize(&mut out),
            Err(Ipv4Error::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn serialize_into_larger_buffer_leaves_tail_untouched() {
        let buf = make_packet(&[0u8; 20]);
        let pkt = Ipv4Packet::parse(&buf).unwrap();

        let mut out = vec![0xFFu8; 128];
        let written = pkt.serialize(&mut out).unwrap();

        assert_eq!(written, 40);
        assert!(out[written..].iter().all(|&b| b == 0xFF));
    }

    // ── round trip ─────────────────────────────────────────────────────────────

    #[test]
    fn round_trip_no_options() {
        let payload = [0xAAu8; 32];
        let original = make_packet(&payload);
        let pkt = Ipv4Packet::parse(&original).unwrap();

        let mut buf = vec![0u8; original.len()];
        pkt.serialize(&mut buf).unwrap();

        let reparsed = Ipv4Packet::parse(&buf).unwrap();
        assert_eq!(pkt.header.src, reparsed.header.src);
        assert_eq!(pkt.header.dst, reparsed.header.dst);
        assert_eq!(pkt.header.protocol, reparsed.header.protocol);
        assert_eq!(pkt.header.ttl, reparsed.header.ttl);
        assert_eq!(pkt.options, reparsed.options);
        assert_eq!(pkt.payload, reparsed.payload);
        assert!(reparsed.validate().is_ok());
    }

    #[test]
    fn round_trip_validates_after_serialize() {
        // The most important round-trip property: a packet that validates
        // before serialization must also validate after.
        let payload = [0u8; 20];
        let original = make_packet(&payload);
        let pkt = Ipv4Packet::parse(&original).unwrap();
        assert!(pkt.validate().is_ok());

        let mut buf = vec![0u8; original.len()];
        pkt.serialize(&mut buf).unwrap();

        let reparsed = Ipv4Packet::parse(&buf).unwrap();
        assert!(reparsed.validate().is_ok());
    }

    // ── checksum ───────────────────────────────────────────────────────────────

    #[test]
    fn checksum_verify_passes_on_valid_header() {
        let buf = make_packet(&[0u8; 20]);
        // Running compute over the full header including the checksum field
        // must yield 0x0000 for a valid packet — RFC 1071 property.
        assert_eq!(checksum::compute(&buf[..20]), 0);
    }

    #[test]
    fn checksum_detects_single_bit_flip() {
        let mut buf = make_packet(&[0u8; 20]);
        buf[14] ^= 0x01; // flip one bit in TTL field
        assert_ne!(checksum::compute(&buf[..20]), 0);
    }
}
