use anyhow::{Context, Result, bail};
use clap::Parser;
use pcap::{Capture, Device, Linktype, Packet};
use radiotap::Radiotap;

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

    capture
        .filter("type mgt subtype probe-req", true)
        .context("Failed to set the packet filter")?;

    println!("[*] Starting sniffing probe requests...");

    while let Ok(packet) = capture.next_packet() {
        handle_packet(packet)?;
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

fn handle_packet(packet: Packet) -> Result<()> {
    let radiotap = match Radiotap::from_bytes(packet.data) {
        Ok(radiotap) => radiotap,
        Err(_error) => {
            // TODO: handle error
            return Ok(());
        }
    };

    let payload = &packet.data[radiotap.header.length..];
    match libwifi::parse_frame(payload, false) {
        Ok(frame) => match frame {
            libwifi::Frame::ProbeRequest(probe) => {
                if let Some(essid) = probe.station_info.essid() {
                    let s_mac = probe.header.address_2.to_long_string();
                    println!("{} -> {}", s_mac, essid);
                }
            }
            _ => {}
        },
        Err(error) => {
            // TODO: handle error
            println!("Error during parsing: {error}");
        }
    }

    Ok(())
}
