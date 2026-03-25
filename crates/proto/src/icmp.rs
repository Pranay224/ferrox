use crate::checksum;
use thiserror::Error;
use zerocopy::{BigEndian, FromBytes, Immutable, IntoBytes, KnownLayout, Ref, U16};

#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Debug, Clone, Copy, PartialEq)]
#[repr(transparent)]
pub struct IcmpType(u8);

impl IcmpType {
    pub const ECHO_REPLY: Self = Self(0);
    pub const DEST_UNREACHABLE: Self = Self(3);
    pub const ECHO_REQUEST: Self = Self(8);
    pub const TIME_EXCEEDED: Self = Self(11);

    pub fn value(&self) -> u8 {
        self.0
    }
}

/// Destination unreachable codes. RFC 792.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DestUnreachableCode {
    NetUnreachable,
    HostUnreachable,
    ProtocolUnreachable,
    PortUnreachable,
    /// RFC 1191 — next_hop_mtu is the MTU of the next-hop link.
    /// Present only when this variant is active.
    FragmentationNeeded {
        next_hop_mtu: u16,
    },
    SourceRouteFailed,
    Unknown(u8),
}

impl DestUnreachableCode {
    /// Parse from code byte and rest field together.
    /// Use this instead of From<u8> to preserve MTU information.
    pub fn from_wire(code: u8, rest: [u8; 4]) -> Self {
        match code {
            0 => Self::NetUnreachable,
            1 => Self::HostUnreachable,
            2 => Self::ProtocolUnreachable,
            3 => Self::PortUnreachable,
            4 => Self::FragmentationNeeded {
                next_hop_mtu: u16::from_be_bytes([rest[2], rest[3]]),
            },
            5 => Self::SourceRouteFailed,
            n => Self::Unknown(n),
        }
    }
}

impl From<DestUnreachableCode> for u8 {
    fn from(value: DestUnreachableCode) -> Self {
        match value {
            DestUnreachableCode::NetUnreachable => 0,
            DestUnreachableCode::HostUnreachable => 1,
            DestUnreachableCode::ProtocolUnreachable => 2,
            DestUnreachableCode::PortUnreachable => 3,
            DestUnreachableCode::FragmentationNeeded { .. } => 4,
            DestUnreachableCode::SourceRouteFailed => 5,
            DestUnreachableCode::Unknown(n) => n,
        }
    }
}

/// Time exceeded codes. RFC 792.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeExceededCode {
    /// TTL reached zero during transit.
    TtlExceeded,
    /// Fragment reassembly time exceeded.
    FragmentReassembly,
    Unknown(u8),
}

impl From<u8> for TimeExceededCode {
    fn from(value: u8) -> Self {
        match value {
            0 => Self::TtlExceeded,
            1 => Self::FragmentReassembly,
            other => Self::Unknown(other),
        }
    }
}

impl From<TimeExceededCode> for u8 {
    fn from(value: TimeExceededCode) -> Self {
        match value {
            TimeExceededCode::TtlExceeded => 0,
            TimeExceededCode::FragmentReassembly => 1,
            TimeExceededCode::Unknown(n) => n,
        }
    }
}

/// Fixed 8-byte ICMP header. RFC 792.
///
/// The `rest` field's meaning depends on the message type:
/// - Echo request/reply: identifier (2 bytes) + sequence number (2 bytes)
/// - Dest unreachable / Time exceeded: unused (all zeros)
/// - Redirect: gateway IP address (4 bytes)
///
/// Use [`IcmpPacket::interpret`] to get a typed view instead of reading `rest` directly.
#[derive(FromBytes, IntoBytes, KnownLayout, Immutable, Debug, Clone, Copy)]
#[repr(C)]
pub struct IcmpHeader {
    pub icmp_type: IcmpType,
    pub code: u8,
    pub checksum: U16<BigEndian>,
    pub rest: [u8; 4],
}

/// A parsed ICMP packet borrowing from the input buffer.
///
/// Provides structural parsing via [`IcmpPacket::parse`],
/// semantic validation via [`IcmpPacket::validate`], and typed
/// interpretation via [`IcmpPacket::interpret`].
pub struct IcmpPacket<'a> {
    pub header: &'a IcmpHeader,
    pub payload: &'a [u8],
}

impl<'a> IcmpPacket<'a> {
    /// Parses an ICMP message from a raw byte slice.
    ///
    /// Borrows directly from `buf` — no allocation occurs.
    /// Performs structural parsing only. Call [`IcmpPacket::validate`]
    /// afterwards to verify the checksum.
    ///
    /// # Errors
    ///
    /// Returns [`IcmpError::TooShort`] if `buf` is shorter than the 8-byte ICMP header.
    pub fn parse(buf: &'a [u8]) -> Result<Self, IcmpError> {
        let (header, payload) =
            Ref::<_, IcmpHeader>::from_prefix(buf).map_err(|_| IcmpError::TooShort {
                needed: size_of::<IcmpHeader>(),
                got: buf.len(),
            })?;

        let header = Ref::into_ref(header);

        Ok(Self { header, payload })
    }

    /// Validates the ICMP packet checksum.
    ///
    /// RFC 792 - the checksum covers the entire packet (header + payload).
    ///
    /// # Errors
    ///
    /// Returns [`IcmpError::BadChecksum`] if the checksum is invalid.
    pub fn validate(&self) -> Result<(), IcmpError> {
        if !checksum::verify_multi(&[self.header.as_bytes(), self.payload]) {
            return Err(IcmpError::BadChecksum);
        }

        Ok(())
    }

    /// Interprets an ICMP packet as a typed [`IcmpMessage`].
    ///
    /// Use after [`IcmpPacket::parse`] and [`IcmpPacket::validate`].
    /// Unknown ICMP message types are represented as [`IcmpMessage::Unknown`].
    /// Caller decides whether to log and drop or handle them.
    pub fn interpret(&'_ self) -> IcmpMessage<'_> {
        match self.header.icmp_type {
            IcmpType::ECHO_REPLY => IcmpMessage::EchoReply {
                identifier: u16::from_be_bytes([self.header.rest[0], self.header.rest[1]]),
                sequence: u16::from_be_bytes([self.header.rest[2], self.header.rest[3]]),
                data: self.payload,
            },

            IcmpType::ECHO_REQUEST => IcmpMessage::EchoRequest {
                identifier: u16::from_be_bytes([self.header.rest[0], self.header.rest[1]]),
                sequence: u16::from_be_bytes([self.header.rest[2], self.header.rest[3]]),
                data: self.payload,
            },

            IcmpType::DEST_UNREACHABLE => {
                // RFC 792 - payload is the original IP header (20 bytes minimum) + first 8 bytes
                // of the original datagram = 28 bytes minimum.
                let split = self.payload.len().min(20);
                let (original_header, rest) = self.payload.split_at(split);
                let original_data = &rest[..rest.len().min(8)];

                IcmpMessage::DestinationUnreachable {
                    // RFC 792 - if code is 4 (Fragmentation Required), insert the next hop mtu
                    // (low 2 bytes of rest) into the message. `from_wire` does this automatically.
                    code: DestUnreachableCode::from_wire(self.header.code, self.header.rest),
                    original_header,
                    original_data,
                }
            }

            IcmpType::TIME_EXCEEDED => {
                // RFC 792 - payload is the original IP header (20 bytes minimum) + first 8 bytes
                // of the original datagram = 28 bytes minimum.
                let split = self.payload.len().min(20);
                let (original_header, rest) = self.payload.split_at(split);
                let original_data = &rest[..rest.len().min(8)];

                IcmpMessage::TimeExceeded {
                    code: TimeExceededCode::from(self.header.code),
                    original_header,
                    original_data,
                }
            }

            _ => IcmpMessage::Unknown {
                icmp_type: self.header.icmp_type.value(),
                code: self.header.code,
                rest: self.header.rest,
                payload: self.payload,
            },
        }
    }
}

impl IcmpPacket<'_> {
    /// Builds an ICMP echo reply packet into `buf`.
    ///
    /// Copies identifier and sequence from the request and preserves the data.
    /// Computes and sets the checksum.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`IcmpError::BufferTooShort`] if `buf` is too short.
    pub fn build_echo_reply(
        identifier: u16,
        sequence: u16,
        data: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, IcmpError> {
        let total_size = size_of::<IcmpHeader>() + data.len();

        if total_size > buf.len() {
            return Err(IcmpError::BufferTooSmall {
                needed: total_size,
                got: buf.len(),
            });
        }

        let mut header = IcmpHeader {
            icmp_type: IcmpType::ECHO_REPLY,
            code: 0,
            checksum: U16::new(0),
            rest: [
                (identifier >> 8) as u8,
                identifier as u8,
                (sequence >> 8) as u8,
                sequence as u8,
            ],
        };

        let csum = checksum::compute_multi(&[header.as_bytes(), data]);
        header.checksum = U16::new(csum);

        buf[..size_of::<IcmpHeader>()].copy_from_slice(header.as_bytes());
        buf[size_of::<IcmpHeader>()..total_size].copy_from_slice(data);

        Ok(total_size)
    }

    /// Builds an ICMP destination unreachable message into `buf`.
    ///
    /// `original_datagram` should be the original IP header plus the
    /// first 8 bytes of the datagram that could not be delivered.
    /// RFC 792 requires at least 28 bytes (20 IP header + 8 data).
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`IcmpError::BufferTooSmall`] if `buf` is too small.
    pub fn build_dest_unreachable(
        code: DestUnreachableCode,
        original_datagram: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, IcmpError> {
        let total = size_of::<IcmpHeader>() + original_datagram.len();

        if buf.len() < total {
            return Err(IcmpError::BufferTooSmall {
                needed: total,
                got: buf.len(),
            });
        }

        let rest = match code {
            DestUnreachableCode::FragmentationNeeded { next_hop_mtu } => {
                [0x00, 0x00, (next_hop_mtu >> 8) as u8, next_hop_mtu as u8]
            }
            _ => [0x00; 4],
        };

        let mut header = IcmpHeader {
            icmp_type: IcmpType::DEST_UNREACHABLE,
            code: u8::from(code),
            checksum: U16::new(0),
            rest,
        };

        let csum = checksum::compute_multi(&[header.as_bytes(), original_datagram]);
        header.checksum = U16::new(csum);

        buf[..size_of::<IcmpHeader>()].copy_from_slice(header.as_bytes());
        buf[size_of::<IcmpHeader>()..total].copy_from_slice(original_datagram);

        Ok(total)
    }

    /// Builds an ICMP time exceeded message into `buf`.
    ///
    /// Sent when a packet's TTL reaches zero in transit (code 0)
    /// or fragment reassembly times out (code 1). RFC 792.
    ///
    /// Returns the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`IcmpError::BufferTooSmall`] if `buf` is too small.
    pub fn build_time_exceeded(
        code: TimeExceededCode,
        original_datagram: &[u8],
        buf: &mut [u8],
    ) -> Result<usize, IcmpError> {
        let total = size_of::<IcmpHeader>() + original_datagram.len();

        if buf.len() < total {
            return Err(IcmpError::BufferTooSmall {
                needed: total,
                got: buf.len(),
            });
        }

        let mut header = IcmpHeader {
            icmp_type: IcmpType::TIME_EXCEEDED,
            code: u8::from(code),
            checksum: U16::new(0),
            rest: [0; 4], // RFC 792 — unused, must be zero
        };

        let csum = checksum::compute_multi(&[header.as_bytes(), original_datagram]);
        header.checksum = U16::new(csum);

        buf[..size_of::<IcmpHeader>()].copy_from_slice(header.as_bytes());
        buf[size_of::<IcmpHeader>()..total].copy_from_slice(original_datagram);

        Ok(total)
    }
}

/// Typed interpretation of a ICMP message.
///
/// Returned by [`IcmpPacket::interpret`].
/// Each variant exposes exactly the fields meaningful for that message type.
#[derive(Debug)]
pub enum IcmpMessage<'a> {
    /// Type 8 - echo request. RFC 792.
    EchoRequest {
        identifier: u16,
        sequence: u16,
        data: &'a [u8],
    },

    /// Type 0 - echo reply. RFC 792.
    EchoReply {
        identifier: u16,
        sequence: u16,
        data: &'a [u8],
    },

    /// Type 3 - destination unreachable. RFC 792.
    DestinationUnreachable {
        code: DestUnreachableCode,

        /// The IP header of the datagram that could not be delivered.
        original_header: &'a [u8],

        /// The first 8 bytes of the datagram that could not be delivered.
        original_data: &'a [u8],
    },

    /// Type 11 - time exceeded. RFC 792.
    TimeExceeded {
        code: TimeExceededCode,

        /// The IP header of the datagram that expired.
        original_header: &'a [u8],

        /// The first 8 bytes of the datagram that expired.
        original_data: &'a [u8],
    },

    /// Any ICMP code ferrox doesn't handle. Returns all data to caller.
    Unknown {
        icmp_type: u8,
        code: u8,
        rest: [u8; 4],
        payload: &'a [u8],
    },
}

#[derive(Error, Debug)]
pub enum IcmpError {
    #[error("packet too short to contain icmp header: needed {needed} bytes, got {got}")]
    TooShort { needed: usize, got: usize },

    #[error("invalid packet checksum")]
    BadChecksum,

    #[error("provided buffer is too small to serialize: needed {needed} bytes, got {got}")]
    BufferTooSmall { needed: usize, got: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checksum;

    // ── helpers ───────────────────────────────────────────────────────────────

    /// Builds a valid echo request as raw bytes with checksum set.
    fn echo_request_bytes(identifier: u16, sequence: u16, data: &[u8]) -> Vec<u8> {
        let mut header = IcmpHeader {
            icmp_type: IcmpType::ECHO_REQUEST,
            code: 0,
            checksum: U16::new(0),
            rest: [
                (identifier >> 8) as u8,
                identifier as u8,
                (sequence >> 8) as u8,
                sequence as u8,
            ],
        };
        let csum = checksum::compute_multi(&[header.as_bytes(), data]);
        header.checksum = U16::new(csum);

        let mut buf = header.as_bytes().to_vec();
        buf.extend_from_slice(data);
        buf
    }

    /// Builds a valid dest unreachable as raw bytes with checksum set.
    fn dest_unreachable_bytes(code: u8, original: &[u8], rest: [u8; 4]) -> Vec<u8> {
        let mut header = IcmpHeader {
            icmp_type: IcmpType::DEST_UNREACHABLE,
            code,
            checksum: U16::new(0),
            rest,
        };
        let csum = checksum::compute_multi(&[header.as_bytes(), original]);
        header.checksum = U16::new(csum);

        let mut buf = header.as_bytes().to_vec();
        buf.extend_from_slice(original);
        buf
    }

    // 28 bytes of fake "original datagram" (IP header + 8 bytes data)
    fn original_datagram() -> Vec<u8> {
        vec![0xAA; 28]
    }

    // ── parse ─────────────────────────────────────────────────────────────────

    #[test]
    fn parse_valid_echo_request() {
        let data = [0x01, 0x02, 0x03, 0x04];
        let buf = echo_request_bytes(0x1234, 0x0001, &data);
        let pkt = IcmpPacket::parse(&buf).unwrap();

        assert_eq!(pkt.header.icmp_type, IcmpType::ECHO_REQUEST);
        assert_eq!(pkt.header.code, 0);
        assert_eq!(pkt.payload, &data);
    }

    #[test]
    fn parse_empty_buffer_fails() {
        assert!(matches!(
            IcmpPacket::parse(&[]),
            Err(IcmpError::TooShort { needed: 8, got: 0 })
        ));
    }

    #[test]
    fn parse_one_byte_too_short_fails() {
        let buf = echo_request_bytes(1, 1, &[]);
        assert!(matches!(
            IcmpPacket::parse(&buf[..7]),
            Err(IcmpError::TooShort { needed: 8, got: 7 })
        ));
    }

    #[test]
    fn parse_header_only_no_payload() {
        let buf = echo_request_bytes(0, 0, &[]);
        let pkt = IcmpPacket::parse(&buf).unwrap();
        assert_eq!(pkt.payload.len(), 0);
    }

    // ── validate ──────────────────────────────────────────────────────────────

    #[test]
    fn validate_valid_echo_request_passes() {
        let buf = echo_request_bytes(1, 1, &[0xAA; 16]);
        let pkt = IcmpPacket::parse(&buf).unwrap();
        assert!(pkt.validate().is_ok());
    }

    #[test]
    fn validate_bad_checksum_rejected() {
        let mut buf = echo_request_bytes(1, 1, &[0xAA; 16]);
        buf[2] ^= 0xFF; // corrupt checksum field
        let pkt = IcmpPacket::parse(&buf).unwrap();
        assert!(matches!(pkt.validate(), Err(IcmpError::BadChecksum)));
    }

    #[test]
    fn validate_checksum_covers_payload() {
        let mut buf = echo_request_bytes(1, 1, &[0xAA; 16]);
        // Corrupt a payload byte — checksum must catch it
        *buf.last_mut().unwrap() ^= 0xFF;
        let pkt = IcmpPacket::parse(&buf).unwrap();
        assert!(matches!(pkt.validate(), Err(IcmpError::BadChecksum)));
    }

    // ── interpret ─────────────────────────────────────────────────────────────

    #[test]
    fn interpret_echo_request() {
        let data = [0xBB; 8];
        let buf = echo_request_bytes(0x1234, 0x0005, &data);
        let pkt = IcmpPacket::parse(&buf).unwrap();

        match pkt.interpret() {
            IcmpMessage::EchoRequest {
                identifier,
                sequence,
                data: d,
            } => {
                assert_eq!(identifier, 0x1234);
                assert_eq!(sequence, 0x0005);
                assert_eq!(d, &data);
            }
            other => panic!("expected EchoRequest, got {other:?}"),
        }
    }

    #[test]
    fn interpret_echo_reply() {
        let data = [0xCC; 4];
        let buf = {
            let mut h = IcmpHeader {
                icmp_type: IcmpType::ECHO_REPLY,
                code: 0,
                checksum: U16::new(0),
                rest: [0x00, 0x07, 0x00, 0x03],
            };
            let csum = checksum::compute_multi(&[h.as_bytes(), &data]);
            h.checksum = U16::new(csum);
            let mut v = h.as_bytes().to_vec();
            v.extend_from_slice(&data);
            v
        };
        let pkt = IcmpPacket::parse(&buf).unwrap();

        match pkt.interpret() {
            IcmpMessage::EchoReply {
                identifier,
                sequence,
                ..
            } => {
                assert_eq!(identifier, 7);
                assert_eq!(sequence, 3);
            }
            other => panic!("expected EchoReply, got {other:?}"),
        }
    }

    #[test]
    fn interpret_dest_unreachable_port() {
        let original = original_datagram();
        let buf = dest_unreachable_bytes(3, &original, [0u8; 4]); // code 3 = port unreachable
        let pkt = IcmpPacket::parse(&buf).unwrap();

        match pkt.interpret() {
            IcmpMessage::DestinationUnreachable {
                code,
                original_header,
                original_data,
            } => {
                assert_eq!(code, DestUnreachableCode::PortUnreachable);
                assert_eq!(original_header.len(), 20);
                assert_eq!(original_data.len(), 8);
            }
            other => panic!("expected DestUnreachable, got {other:?}"),
        }
    }

    #[test]
    fn interpret_fragmentation_needed_dest_unreachable() {
        let original = original_datagram();
        let buf = dest_unreachable_bytes(4, &original, [0xAA; 4]); // code 4 = fragmentation needed
        let pkt = IcmpPacket::parse(&buf).unwrap();

        match pkt.interpret() {
            IcmpMessage::DestinationUnreachable {
                code,
                original_header,
                original_data,
            } => {
                assert_eq!(
                    code,
                    DestUnreachableCode::FragmentationNeeded {
                        next_hop_mtu: 0xAAAA
                    }
                );
                assert_eq!(original_header.len(), 20);
                assert_eq!(original_data.len(), 8);
            }
            other => panic!("expected DestUnreachable, got {other:?}"),
        }
    }

    #[test]
    fn interpret_time_exceeded_ttl() {
        let original = original_datagram();
        let mut header = IcmpHeader {
            icmp_type: IcmpType::TIME_EXCEEDED,
            code: 0,
            checksum: U16::new(0),
            rest: [0; 4],
        };
        let csum = checksum::compute_multi(&[header.as_bytes(), &original]);
        header.checksum = U16::new(csum);
        let mut buf = header.as_bytes().to_vec();
        buf.extend_from_slice(&original);

        let pkt = IcmpPacket::parse(&buf).unwrap();
        match pkt.interpret() {
            IcmpMessage::TimeExceeded { code, .. } => {
                assert_eq!(code, TimeExceededCode::TtlExceeded);
            }
            other => panic!("expected TimeExceeded, got {other:?}"),
        }
    }

    #[test]
    fn interpret_unknown_type() {
        let mut header = IcmpHeader {
            icmp_type: IcmpType(42), // not handled
            code: 0,
            checksum: U16::new(0),
            rest: [1, 2, 3, 4],
        };
        let csum = checksum::compute(header.as_bytes());
        header.checksum = U16::new(csum);
        let buf = header.as_bytes().to_vec();

        let pkt = IcmpPacket::parse(&buf).unwrap();
        assert!(matches!(
            pkt.interpret(),
            IcmpMessage::Unknown { icmp_type: 42, .. }
        ));
    }

    // ── builders ──────────────────────────────────────────────────────────────

    #[test]
    fn build_echo_reply_correct_fields() {
        let data = [0xDD; 12];
        let mut buf = vec![0u8; 8 + data.len()];
        let written = IcmpPacket::build_echo_reply(0x0A0B, 0x0001, &data, &mut buf).unwrap();

        assert_eq!(written, 8 + data.len());

        let pkt = IcmpPacket::parse(&buf).unwrap();
        assert!(pkt.validate().is_ok());

        match pkt.interpret() {
            IcmpMessage::EchoReply {
                identifier,
                sequence,
                data: d,
            } => {
                assert_eq!(identifier, 0x0A0B);
                assert_eq!(sequence, 0x0001);
                assert_eq!(d, &data);
            }
            other => panic!("expected EchoReply, got {other:?}"),
        }
    }

    #[test]
    fn build_echo_reply_buffer_too_small_fails() {
        let data = [0u8; 16];
        let mut buf = vec![0u8; 4]; // too small
        assert!(matches!(
            IcmpPacket::build_echo_reply(1, 1, &data, &mut buf),
            Err(IcmpError::BufferTooSmall { .. })
        ));
    }

    #[test]
    fn build_dest_unreachable_valid_checksum() {
        let original = original_datagram();
        let mut buf = vec![0u8; 8 + original.len()];
        let written = IcmpPacket::build_dest_unreachable(
            DestUnreachableCode::PortUnreachable,
            &original,
            &mut buf,
        )
        .unwrap();

        assert_eq!(written, 8 + original.len());

        let pkt = IcmpPacket::parse(&buf).unwrap();
        assert!(pkt.validate().is_ok());

        match pkt.interpret() {
            IcmpMessage::DestinationUnreachable { code, .. } => {
                assert_eq!(code, DestUnreachableCode::PortUnreachable);
            }
            other => panic!("expected DestUnreachable, got {other:?}"),
        }
    }

    #[test]
    fn build_fragmentation_needed_valid_checksum() {
        let original = original_datagram();
        let mut buf = vec![0u8; 8 + original.len()];

        let written = IcmpPacket::build_dest_unreachable(
            DestUnreachableCode::FragmentationNeeded {
                next_hop_mtu: 0xAAAA,
            },
            &original,
            &mut buf,
        )
        .unwrap();

        assert_eq!(written, 8 + original.len());

        let pkt = IcmpPacket::parse(&buf).unwrap();
        assert!(pkt.validate().is_ok());

        match pkt.interpret() {
            IcmpMessage::DestinationUnreachable { code, .. } => {
                assert_eq!(
                    code,
                    DestUnreachableCode::FragmentationNeeded {
                        next_hop_mtu: 0xAAAA
                    }
                );
            }
            other => panic!("expected DestUnreachable, got {other:?}"),
        }
    }

    #[test]
    fn build_time_exceeded_valid_checksum() {
        let original = original_datagram();
        let mut buf = vec![0u8; 8 + original.len()];
        IcmpPacket::build_time_exceeded(TimeExceededCode::TtlExceeded, &original, &mut buf)
            .unwrap();

        let pkt = IcmpPacket::parse(&buf).unwrap();
        assert!(pkt.validate().is_ok());
    }

    // ── round trips ───────────────────────────────────────────────────────────

    #[test]
    fn echo_reply_round_trip() {
        let data = [0xEE; 20];
        let mut buf = vec![0u8; 8 + data.len()];
        IcmpPacket::build_echo_reply(0xFFFF, 0xABCD, &data, &mut buf).unwrap();

        let pkt = IcmpPacket::parse(&buf).unwrap();
        pkt.validate().unwrap();

        match pkt.interpret() {
            IcmpMessage::EchoReply {
                identifier,
                sequence,
                data: d,
            } => {
                assert_eq!(identifier, 0xFFFF);
                assert_eq!(sequence, 0xABCD);
                assert_eq!(d, &data);
            }
            other => panic!("expected EchoReply, got {other:?}"),
        }
    }

    #[test]
    fn dest_unreachable_round_trip() {
        let original = original_datagram();
        let mut buf = vec![0u8; 8 + original.len()];
        IcmpPacket::build_dest_unreachable(
            DestUnreachableCode::HostUnreachable,
            &original,
            &mut buf,
        )
        .unwrap();

        let pkt = IcmpPacket::parse(&buf).unwrap();
        pkt.validate().unwrap();

        match pkt.interpret() {
            IcmpMessage::DestinationUnreachable {
                code,
                original_header,
                original_data,
            } => {
                assert_eq!(code, DestUnreachableCode::HostUnreachable);
                assert_eq!(original_header, &original[..20]);
                assert_eq!(original_data, &original[20..28]);
            }
            other => panic!("expected DestUnreachable, got {other:?}"),
        }
    }

    #[test]
    fn fragmentation_needed_round_trip() {
        let original = original_datagram();
        let mut buf = vec![0u8; 8 + original.len()];
        IcmpPacket::build_dest_unreachable(
            DestUnreachableCode::FragmentationNeeded {
                next_hop_mtu: 0xCAFE,
            },
            &original,
            &mut buf,
        )
        .unwrap();

        let pkt = IcmpPacket::parse(&buf).unwrap();
        pkt.validate().unwrap();

        match pkt.interpret() {
            IcmpMessage::DestinationUnreachable {
                code,
                original_header,
                original_data,
            } => {
                assert_eq!(
                    code,
                    DestUnreachableCode::FragmentationNeeded {
                        next_hop_mtu: 0xCAFE
                    }
                );
                assert_eq!(original_header, &original[..20]);
                assert_eq!(original_data, &original[20..28]);
            }
            other => panic!("expected DestUnreachable, got {other:?}"),
        }
    }
}
