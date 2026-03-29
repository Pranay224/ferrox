use bytes::{BufMut, Bytes, BytesMut};

/// Minimum header sizes — no options, no extensions
pub const ETH_HEADER_LEN: usize = 14;
pub const IPV4_HEADER_MIN_LEN: usize = 20;
pub const TCP_HEADER_MIN_LEN: usize = 20;
pub const UDP_HEADER_LEN: usize = 8;

/// Maximum header sizes — with all possible options
pub const IPV4_HEADER_MAX_LEN: usize = 60; // 20 fixed + 40 options
pub const TCP_HEADER_MAX_LEN: usize = 60; // 20 fixed + 40 options

/// Headroom needed when transport/ builds a TCP segment.
/// Below transport/: IPv4 header (max) + Ethernet header.
pub const TRANSPORT_TX_HEADROOM: usize = ETH_HEADER_LEN + IPV4_HEADER_MAX_LEN; // 14 + 60 = 74

/// Headroom needed when network/ builds an IP packet directly
/// (e.g. ICMP). Below network/: Ethernet header only.
pub const NETWORK_TX_HEADROOM: usize = ETH_HEADER_LEN; // 14

/// A wrapper over [`BytesMut`] that pre-allocates a fixed amount of headroom.
///
/// Allows layers to prepend their header onto the packet without causing new allocations.
pub struct TxBuf {
    inner: BytesMut,
    head_start: usize,
}

impl TxBuf {
    /// Creates a new [`TxBuf`] with a specified amount of headroom.
    ///
    /// Use the constants provided by this module to pick suitable headroom sizes.
    ///
    /// Layout after construction:
    /// [ headroom (zeroed) | payload ]
    pub fn new(headroom: usize, payload: &[u8]) -> Self {
        let mut inner = BytesMut::with_capacity(headroom + payload.len());
        inner.resize(headroom, 0);
        inner.put_slice(payload);

        Self {
            inner,
            head_start: headroom,
        }
    }

    /// How much headroom is still available.
    /// Useful for debug assertions before prepending.
    pub fn headroom(&self) -> usize {
        self.head_start
    }

    /// Prepends a header by growing the frame backwards into the reserved headroom.
    ///
    /// # Panics
    ///
    /// Panics if there is insufficient headroom. This is a programming
    /// error — the caller must reserve enough headroom at construction.
    pub fn prepend(&mut self, header: &[u8]) {
        assert!(
            self.head_start >= header.len(),
            "TxBuf::prepend: need {} bytes headroom, have {} — \
             increase the headroom constant for this layer",
            header.len(),
            self.head_start
        );
        self.head_start -= header.len();
        self.inner[self.head_start..self.head_start + header.len()].copy_from_slice(header);
    }

    /// View of the complete frame from the first prepended header.
    pub fn as_slice(&self) -> &[u8] {
        &self.inner[self.head_start..]
    }

    /// Total length of the frame as it will appear on the wire.
    pub fn len(&self) -> usize {
        self.inner.len() - self.head_start
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Drops unused headroom and converts into immutable [`Bytes`]
    /// suitable for sending (e.g., via TAP).
    pub fn freeze(mut self) -> Bytes {
        let _ = self.inner.split_to(self.head_start);
        self.inner.freeze()
    }
}
