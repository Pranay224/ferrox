use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, U16};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Debug, Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct EtherType(U16<BigEndian>);

impl EtherType {
    pub const IPV4: Self = Self(U16::new(0x0800));
    pub const IPV6: Self = Self(U16::new(0x86DD));
    pub const ARP: Self = Self(U16::new(0x0806));
    pub const VLAN: Self = Self(U16::new(0x8100));

    pub fn value(&self) -> u16 {
        self.0.get()
    }
}

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EthernetHeader {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ethertype: EtherType,
}

pub struct EthernetFrame<'a> {
    pub header: &'a EthernetHeader,
    pub payload: &'a [u8],
}

impl<'a> EthernetFrame<'a> {
    /// Parses an Ethernet II frame from a raw byte slice.
    ///
    /// The returned frame borrows directly from `buf` — no allocation occurs.
    /// This performs structural parsing only; call [`EthernetFrame::validate`]
    /// afterwards to enforce semantic constraints (minimum payload length, etc.).
    ///
    /// # Errors
    ///
    /// Returns [`EthernetError::TooShort`] if `buf` is smaller than the
    /// 14-byte Ethernet header.
    ///
    /// # Examples
    ///
    /// ```
    /// # use proto::ethernet::{EthernetFrame, EtherType};
    /// let mut buf = vec![0u8; 60];
    /// buf[12] = 0x08; buf[13] = 0x00; // EtherType: IPv4
    /// let frame = EthernetFrame::parse(&buf).unwrap();
    /// assert_eq!(frame.header.ethertype, EtherType::IPV4);
    /// ```
    pub fn parse(buf: &'a [u8]) -> Result<Self, EthernetError> {
        // Ethernet II header is 14 bytes: dst MAC (6) + src MAC (6) + EtherType (2).
        let (header, payload) =
            Ref::<_, EthernetHeader>::from_prefix(buf).map_err(|_| EthernetError::TooShort {
                needed: size_of::<EthernetHeader>(),
                got: buf.len(),
            })?;

        Ok(Self {
            header: Ref::into_ref(header),
            payload,
        })
    }

    /// Checks semantic validity of a parsed frame.
    ///
    /// This is intentionally separate from [`EthernetFrame::parse`] — parsing
    /// checks structure, validation checks meaning. Call this after `parse`
    /// before dispatching the frame to upper layers.
    ///
    /// # Errors
    ///
    /// - [`EthernetError::PayloadTooShort`] — payload under 46 bytes
    /// - [`EthernetError::BroadcastSource`] — src MAC is `ff:ff:ff:ff:ff:ff`
    /// - [`EthernetError::InvalidEtherType`] — EtherType below `0x0600`
    pub fn validate(&self) -> Result<(), EthernetError> {
        // IEEE 802.3 requires a minimum frame size of 64 bytes.
        // TAP strips the 4-byte CRC, so the minimum we see is 60 bytes total,
        // meaning the payload must be at least 60 - 14 = 46 bytes.
        if self.payload.len() < 46 {
            return Err(EthernetError::PayloadTooShort {
                got: self.payload.len(),
            });
        }

        // A frame cannot originate from a broadcast address
        if self.header.src == [0xff; 6] {
            return Err(EthernetError::BroadcastSource);
        }

        // EtherType values below 0x0600 are payload length fields (IEEE 802.3), not valid
        // EtherType values (Ethernet II). ferrox only handles Ethernet II.
        if self.header.ethertype.value() < 0x0600 {
            return Err(EthernetError::InvalidEtherType(
                self.header.ethertype.value(),
            ));
        }

        Ok(())
    }

    /// Serializes the frame into `buf`, returning the number of bytes written.
    ///
    /// The buffer must be at least `14 + payload.len()` bytes long.
    /// Writes the Ethernet header followed immediately by the payload —
    /// no padding is added. If the payload is shorter than 46 bytes,
    /// the caller is responsible for padding before calling this.
    ///
    /// # Errors
    ///
    /// Returns [`EthernetError::BufferTooSmall`] if `buf` is too short.
    pub fn serialize(&self, buf: &mut [u8]) -> Result<usize, EthernetError> {
        let total = size_of::<EthernetHeader>() + self.payload.len();

        if buf.len() < total {
            return Err(EthernetError::BufferTooSmall {
                needed: total,
                got: buf.len(),
            });
        }

        let (header_buf, rest) = buf.split_at_mut(size_of::<EthernetHeader>());
        header_buf.copy_from_slice(self.header.as_bytes());
        rest[..self.payload.len()].copy_from_slice(self.payload);

        Ok(total)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EthernetError {
    #[error("buffer too short: need {needed} bytes for Ethernet header, got {got}")]
    TooShort { needed: usize, got: usize },
    #[error("payload length too short: got {got} bytes, minimum is 46")]
    PayloadTooShort { got: usize },
    #[error("source address cannot be broadcast")]
    BroadcastSource,
    #[error("got invalid ethertype: {0:#06x}")]
    InvalidEtherType(u16),
    #[error("buffer too small: needed {needed} bytes, got {got}")]
    BufferTooSmall { needed: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid Ethernet frame: ARP payload, padded to 46 bytes.
    /// dst: ff:ff:ff:ff:ff:ff  src: aa:bb:cc:dd:ee:ff  ethertype: 0x0806 (ARP)
    fn arp_frame_bytes() -> Vec<u8> {
        let mut buf = vec![
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // dst MAC
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // src MAC
            0x08, 0x06, // EtherType: ARP
        ];
        buf.extend_from_slice(&[0u8; 46]); // minimum payload, zero-filled
        buf
    }

    // parse

    #[test]
    fn parse_valid_arp_frame() {
        let buf = arp_frame_bytes();
        let frame = EthernetFrame::parse(&buf).unwrap();
        assert_eq!(frame.header.dst, [0xff; 6]);
        assert_eq!(frame.header.src, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(frame.header.ethertype, EtherType::ARP);
        assert_eq!(frame.payload.len(), 46);
    }

    #[test]
    fn parse_empty_buffer_fails() {
        assert!(matches!(
            EthernetFrame::parse(&[]),
            Err(EthernetError::TooShort { .. })
        ));
    }

    #[test]
    fn parse_header_only_no_payload() {
        // 14 bytes — valid header, zero-length payload. Parse should succeed,
        // validate will catch the too-short payload separately.
        let buf = arp_frame_bytes()[..14].to_vec();
        let frame = EthernetFrame::parse(&buf).unwrap();
        assert_eq!(frame.payload.len(), 0);
    }

    #[test]
    fn parse_one_byte_too_short_fails() {
        let buf = arp_frame_bytes()[..13].to_vec();
        assert!(matches!(
            EthernetFrame::parse(&buf),
            Err(EthernetError::TooShort { .. })
        ));
    }

    // validate

    #[test]
    fn validate_valid_frame_passes() {
        let buf = arp_frame_bytes();
        let frame = EthernetFrame::parse(&buf).unwrap();
        assert!(frame.validate().is_ok());
    }

    #[test]
    fn validate_payload_too_short() {
        let buf = arp_frame_bytes()[..14 + 45].to_vec(); // one byte short
        let frame = EthernetFrame::parse(&buf).unwrap();
        assert!(matches!(
            frame.validate(),
            Err(EthernetError::PayloadTooShort { got: 45 })
        ));
    }

    #[test]
    fn validate_broadcast_source_rejected() {
        let mut buf = arp_frame_bytes();
        buf[6..12].copy_from_slice(&[0xff; 6]); // set src to broadcast
        let frame = EthernetFrame::parse(&buf).unwrap();
        assert!(matches!(
            frame.validate(),
            Err(EthernetError::BroadcastSource)
        ));
    }

    #[test]
    fn validate_reserved_ethertype_rejected() {
        let mut buf = arp_frame_bytes();
        buf[12..14].copy_from_slice(&[0x05, 0xff]); // EtherType 0x05ff < 0x0600
        let frame = EthernetFrame::parse(&buf).unwrap();
        assert!(matches!(
            frame.validate(),
            Err(EthernetError::InvalidEtherType(0x05ff))
        ));
    }

    // serialize

    #[test]
    fn serialize_produces_correct_bytes() {
        let buf = arp_frame_bytes();
        let frame = EthernetFrame::parse(&buf).unwrap();

        let mut out = vec![0u8; buf.len()];
        let written = frame.serialize(&mut out).unwrap();

        assert_eq!(written, buf.len());
        assert_eq!(&out[..written], &buf[..]);
    }

    #[test]
    fn serialize_buffer_too_small_fails() {
        let buf = arp_frame_bytes();
        let frame = EthernetFrame::parse(&buf).unwrap();

        let mut out = vec![0u8; 10]; // way too small
        assert!(matches!(
            frame.serialize(&mut out),
            Err(EthernetError::BufferTooSmall { .. })
        ));
    }

    // round trip

    #[test]
    fn round_trip_parse_serialize_parse() {
        let original = arp_frame_bytes();

        let frame1 = EthernetFrame::parse(&original).unwrap();
        let mut serialized = vec![0u8; original.len()];
        frame1.serialize(&mut serialized).unwrap();

        let frame2 = EthernetFrame::parse(&serialized).unwrap();
        assert_eq!(frame1.header.dst, frame2.header.dst);
        assert_eq!(frame1.header.src, frame2.header.src);
        assert_eq!(frame1.header.ethertype, frame2.header.ethertype);
        assert_eq!(frame1.payload, frame2.payload);
    }
}
