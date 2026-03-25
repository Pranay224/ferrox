/// Computes the Internet checksum (RFC 1071) over a byte slice.
///
/// The data is interpreted as big-endian 16-bit words and summed using
/// one's complement addition. If the slice has an odd length, the final
/// byte is padded with zero in the low-order position.
///
/// Returns the one's complement of the accumulated sum.
pub fn compute(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    let mut chunks = data.chunks_exact(2);

    for word in &mut chunks {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }

    if let Some(&leftover) = chunks.remainder().first() {
        sum += (leftover as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Computes the Internet checksum (RFC 1071) over multiple byte slices
/// without allocating a concatenated buffer.
///
/// Slices are processed as a continuous stream, correctly handling
/// word boundaries across slice edges.
pub fn compute_multi(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    let mut leftover: Option<u8> = None;

    for &stream in parts {
        let data = if let Some(byte) = leftover.take() {
            if let Some((&first, rest)) = stream.split_first() {
                sum += u16::from_be_bytes([byte, first]) as u32;
                rest
            } else {
                leftover = Some(byte);
                continue;
            }
        } else {
            stream
        };

        let mut chunks = data.chunks_exact(2);

        for word in &mut chunks {
            sum += u16::from_be_bytes([word[0], word[1]]) as u32;
        }

        leftover = chunks.remainder().first().copied();
    }

    if let Some(byte) = leftover {
        sum += (byte as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

/// Verifies that the checksum over the data is valid.
///
/// Returns true if the computed checksum equals zero.
pub fn verify(data: &[u8]) -> bool {
    compute(data) == 0
}

/// Verifies the checksum across multiple byte slices.
///
/// Equivalent to concatenating all slices and calling `verify`,
/// but avoids allocation.
pub fn verify_multi(parts: &[&[u8]]) -> bool {
    compute_multi(parts) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1071_example() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];

        // RFC intermediate sum = 0xddf2
        // Final checksum is one's complement
        assert_eq!(compute(&data), !0xddf2);
    }

    #[test]
    fn rfc1071_example_multi() {
        let parts: &[&[u8]] = &[&[0x00], &[0x01, 0xf2], &[0x03, 0xf4, 0xf5], &[0xf6, 0xf7]];

        assert_eq!(compute_multi(parts), !0xddf2);
    }

    #[test]
    fn compute_vs_multi_equivalence() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9a];

        let parts: &[&[u8]] = &[&[0x12], &[0x34, 0x56], &[0x78], &[0x9a]];

        assert_eq!(compute(&data), compute_multi(parts));
    }

    #[test]
    fn odd_length_padding() {
        let data = [0x12, 0x34, 0x56];

        // Equivalent to 0x1234 + 0x5600 = 0x6834
        // Final checksum is one's complement
        assert_eq!(compute(&data), !0x6834);
    }

    #[test]
    fn empty_input() {
        // sum = 0 → !0 = 0xffff
        assert_eq!(compute(&[]), 0xffff);
    }

    #[test]
    fn verify_valid_checksum() {
        let mut data = vec![0x12, 0x34, 0x56, 0x78];

        let checksum = compute(&data);
        data.push((checksum >> 8) as u8);
        data.push((checksum & 0xff) as u8);

        assert!(verify(&data));
    }

    #[test]
    fn verify_invalid_checksum() {
        let data = [0x12, 0x34, 0x56, 0x78];
        assert!(!verify(&data));
    }

    #[test]
    fn verify_multi_valid_checksum() {
        let data = [0xde, 0xad, 0xbe, 0xef];
        let checksum = compute(&data);

        let parts: &[&[u8]] = &[
            &[0xde],
            &[0xad, 0xbe],
            &[0xef, (checksum >> 8) as u8],
            &[(checksum & 0xff) as u8],
        ];

        assert!(verify_multi(parts));
    }

    #[test]
    fn carry_wraparound() {
        // Forces multiple carries
        let data = [0xff, 0xff, 0xff, 0xff];

        // 0xffff + 0xffff = 0x1fffe → wrap → 0xffff → ! = 0x0000
        assert_eq!(compute(&data), 0x0000);
    }
}
