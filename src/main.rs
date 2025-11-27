use anyhow::{Context, Result, bail};
use clap::Parser;
use pcap::{Capture, Device, Linktype};

mod cli;

use cli::Cli;

fn main() -> Result<()> {
    // Parse CLI arguments and options.
    let cli = Cli::parse();

    // Determine network device to use.
    let device: Device = if cli.interface.is_some() {
        find_device_by_name(&cli.interface.unwrap())?
    } else {
        Device::lookup()
            .context("Failed during network interface lookup")?
            .context("No available device found via lookup")?
    };

    // "In immediate mode, packets are always delivered as soon as they arrive,
    // with no buffering."
    //
    // See https://www.man7.org/linux/man-pages/man3/pcap_set_immediate_mode.3pcap.html.
    let capture = Capture::from_device(device)
        .context("Failed to create a pcap capture handle from device")?
        .immediate_mode(true);

    let mut capture = capture
        .open()
        .context("Failed to open the pcap capture handle on selected device")?;

    capture
        // See https://www.tcpdump.org/linktypes.html.
        .set_datalink(pcap::Linktype(Linktype::IEEE802_11_RADIOTAP.0))
        .context("Failed to set the datalink type")?;

    while let Ok(packet) = capture.next_packet() {
        // TODO
        println!("Packet received...");
    }

    Ok(())
}

/// Checks if `name` is an available network device.
fn find_device_by_name(name: &str) -> Result<Device> {
    let devices = Device::list().context("Failed to list all available network devices")?;

    for device in devices {
        if device.name == name {
            return Ok(device);
        }
    }

    bail!("Device '{}' not found", name)
}
