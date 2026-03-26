use proto::iface::{InterfaceConfig, MacAddr, PacketSink, PacketSource, PrefixLen};
use std::{io, net::Ipv4Addr, sync::Arc};
use thiserror::Error;
use tun_rs::{AsyncDevice, DeviceBuilder, Layer};

/// Builder for [`TapDevice`].
///
/// All fields are required. Call [`TapDeviceBuilder::build`] to open
/// the OS interface and produce a [`TapDevice`].
pub struct TapDeviceBuilder {
    name: Option<String>,
    ip: Option<Ipv4Addr>,
    prefix: Option<PrefixLen>,
    mac: Option<MacAddr>,
}

impl TapDeviceBuilder {
    pub fn new() -> Self {
        Self {
            name: Some("tap0".to_string()),
            ip: None,
            prefix: None,
            mac: None,
        }
    }

    /// Sets the interface name. Defaults to `"tap0"`.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// Sets the IPv4 address assigned to the interface.
    pub fn ip(mut self, ip: Ipv4Addr) -> Self {
        self.ip = Some(ip);
        self
    }

    /// Sets the CIDR prefix length (e.g. `24` for `/24`).
    pub fn prefix(mut self, prefix: PrefixLen) -> Self {
        self.prefix = Some(prefix);
        self
    }

    /// Sets the MAC address assigned to the interface.
    pub fn mac(mut self, mac: MacAddr) -> Self {
        self.mac = Some(mac);
        self
    }

    /// Convenience method — constructs from a complete [`InterfaceConfig`].
    pub fn from_config(config: &InterfaceConfig) -> Result<TapDevice, PalError> {
        Self::new()
            .name(&config.name)
            .ip(config.ip)
            .prefix(config.prefix)
            .mac(config.mac)
            .build()
    }

    /// Opens and configures the TAP device.
    ///
    /// Assigns the specified IP, prefix, and MAC to the interface
    /// and brings it up. Requires `CAP_NET_ADMIN`.
    ///
    /// # Errors
    ///
    /// - [`PalError::MissingField`] — a required field was not set
    /// - [`PalError::InvalidIfaceName`] — name is empty or over 15 characters
    /// - [`PalError::InitializationError`] — the OS rejected device creation
    pub fn build(self) -> Result<TapDevice, PalError> {
        let ip = self.ip.ok_or(PalError::MissingField("ip"))?;
        let prefix = self.prefix.ok_or(PalError::MissingField("prefix"))?;
        let mac = self.mac.ok_or(PalError::MissingField("mac"))?;
        let name = self.name.unwrap_or_else(|| "tap0".to_string());

        // Linux interface names are at most IFNAMSIZ-1 = 15 characters
        if name.is_empty() || name.len() > 15 {
            return Err(PalError::InvalidIfaceName(name));
        }

        let device = DeviceBuilder::new()
            .layer(Layer::L2)
            .name(&name)
            .ipv4(ip, prefix.to_netmask(), None)
            .mac_addr(mac.get())
            .build_async()
            .map_err(PalError::InitializationError)?;

        Ok(TapDevice {
            inner: Arc::new(device),
        })
    }
}

impl Default for TapDeviceBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// An open, configured TAP (layer 2) network device.
///
/// Constructed via [`TapDeviceBuilder`]. Call [`TapDevice::split`] to
/// produce independent RX and TX halves for separate async tasks.
pub struct TapDevice {
    inner: Arc<AsyncDevice>,
}

impl TapDevice {
    /// Splits the device into independent RX and TX halves.
    ///
    /// Both halves share the underlying device via `Arc`. Safe to
    /// move into separate tokio tasks — no locking required.
    pub fn split(self) -> (TapRx, TapTx) {
        (
            TapRx {
                inner: Arc::clone(&self.inner),
            },
            TapTx {
                inner: Arc::clone(&self.inner),
            },
        )
    }
}

/// Read half of a [`TapDevice`]. Implements [`PacketSource`].
pub struct TapRx {
    inner: Arc<AsyncDevice>,
}

/// Write half of a [`TapDevice`]. Implements [`PacketSink`].
pub struct TapTx {
    inner: Arc<AsyncDevice>,
}

impl PacketSource for TapRx {
    async fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.recv(buf).await
    }
}

impl PacketSink for TapTx {
    async fn send(&self, buf: &[u8]) -> std::io::Result<()> {
        self.inner.send(buf).await?;
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum PalError {
    #[error("invalid interface name '{0}': must be 1–15 characters")]
    InvalidIfaceName(String),

    #[error("missing required field: {0}")]
    MissingField(&'static str),

    #[error("failed to initialize tap device: {0}")]
    InitializationError(#[source] io::Error),
}
