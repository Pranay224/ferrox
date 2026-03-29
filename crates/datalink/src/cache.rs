use lru::LruCache;
use proto::iface::MacAddr;
use std::{
    net::Ipv4Addr,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

pub const ARP_CACHE_LIMIT: usize = 256;
pub const ARP_TTL_LIMIT: Duration = Duration::from_secs(1200);

struct ArpEntry {
    mac: MacAddr,
    expiry: Instant,
}

pub struct ArpCache {
    inner: LruCache<Ipv4Addr, ArpEntry>,
    ttl: Duration,
}

impl ArpCache {
    /// Creates a new [`ArpCache`] with the specified `capacity` and `ttl` for entries.
    ///
    /// Entries that have been inserted for longer than `ttl` will not be returned on a lookup and
    /// will be subsequently evicted.
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        assert!(capacity > 0, "ArpCache capacity must be non-zero");
        Self {
            inner: LruCache::new(NonZeroUsize::new(capacity).unwrap()),
            ttl,
        }
    }

    /// Inserts or refreshes an ARP entry.
    /// Called on any inbound ARP packet or opportunistically on inbound IPv4 packets.
    pub fn insert(&mut self, ip: Ipv4Addr, mac: MacAddr) {
        self.inner.put(
            ip,
            ArpEntry {
                mac,
                expiry: Instant::now() + self.ttl,
            },
        );
    }

    /// Looks up a MAC address for the given IP.
    /// Returns None if not found or if the entry has expired.
    /// Expired entries are evicted on access.
    pub fn lookup(&mut self, ip: Ipv4Addr) -> Option<MacAddr> {
        match self.inner.get(&ip) {
            Some(entry) if entry.expiry > Instant::now() => Some(entry.mac),
            Some(_) => {
                self.inner.pop(&ip);
                None
            }
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_insert() {
        let mut cache = ArpCache::new(1, Duration::from_secs(1200));
        let ip = Ipv4Addr::from_octets([192, 168, 1, 1]);
        let mac = MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        cache.insert(ip, mac);

        assert_eq!(cache.lookup(ip), Some(mac));
    }

    #[test]
    fn test_evict() {
        let mut cache = ArpCache::new(2, Duration::from_secs(1200));

        cache.insert(
            Ipv4Addr::from_octets([192, 168, 1, 1]),
            MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]),
        );

        cache.insert(
            Ipv4Addr::from_octets([192, 168, 1, 2]),
            MacAddr::from([0xca, 0xfe, 0xf0, 0x00, 0x00, 0x0d]),
        );

        cache.insert(
            Ipv4Addr::from_octets([192, 168, 1, 3]),
            MacAddr::from([0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa]),
        );

        assert!(
            cache
                .lookup(Ipv4Addr::from_octets([192, 168, 1, 1]))
                .is_none()
        );
        assert!(
            cache
                .lookup(Ipv4Addr::from_octets([192, 168, 1, 2]))
                .is_some()
        );
        assert!(
            cache
                .lookup(Ipv4Addr::from_octets([192, 168, 1, 3]))
                .is_some()
        );
    }

    #[test]
    fn test_expiry() {
        let mut cache = ArpCache::new(2, Duration::from_millis(50));
        let ip = Ipv4Addr::from_octets([192, 168, 1, 1]);
        let mac = MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        cache.insert(ip, mac);

        std::thread::sleep(Duration::from_millis(100));

        assert_eq!(cache.lookup(ip), None);
    }
}
