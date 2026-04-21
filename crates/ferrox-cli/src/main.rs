#![forbid(unsafe_code)]

use anyhow::{Ok, Result};
use clap::Parser;
use datalink::{DataLink, messages::InboundIpv4};
use pal::TapDeviceBuilder;
use proto::iface::{InterfaceConfig, MacAddr, PrefixLen};
use std::net::Ipv4Addr;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{Level, subscriber};

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .with_target(false)
        .compact()
        .finish();
    subscriber::set_global_default(subscriber)?;

    let config = Args::parse();

    let mac = parse_mac(&config.mac)?;
    let prefix = PrefixLen::try_from(config.prefix_length)?;

    let config = InterfaceConfig {
        name: config.iface,
        mac,
        ip: config.ip,
        prefix,
    };

    tracing::info!(
        iface = %config.name,
        ip = %config.ip,
        mac = ?config.mac,
        "starting ferrox"
    );

    let cancel_token = CancellationToken::new();

    let tap = TapDeviceBuilder::from_config(&config)?;
    let (tap_tx, tap_rx) = tap.split();

    let (nw_tx, _nw_rx) = mpsc::channel::<InboundIpv4>(256);
    let (_dl_tx, dl_rx) = mpsc::channel(256);

    let dl = DataLink::new(
        config.mac,
        config.ip,
        tap_tx,
        tap_rx,
        nw_tx,
        dl_rx,
        cancel_token.clone(),
    );

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to listen for ctrl-c");
        cancel_token.cancel();
    });

    dl.run().await;

    Ok(())
}

#[derive(clap::Parser)]
struct Args {
    /// tap device name
    #[arg(long, default_value = "tap0")]
    iface: String,

    /// mac address (hex, colon separated)
    #[arg(long, default_value = "aa:bb:cc:dd:ee:ff")]
    mac: String,

    // ip address
    #[arg(long, default_value = "10.0.0.2")]
    ip: Ipv4Addr,

    // prefix length
    #[arg(long, default_value = "24")]
    prefix_length: u8,
}

fn parse_mac(mac: &str) -> Result<MacAddr> {
    let parts = mac.split(':').collect::<Vec<_>>();
    anyhow::ensure!(
        parts.len() == 6,
        "mac address must be 6 colon-separated hex octets"
    );

    let mut mac = [0u8; 6];
    for (i, &octet) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(octet, 16).map_err(|_| anyhow::anyhow!("invalid mac octet"))?;
    }

    Ok(MacAddr::from(mac))
}
