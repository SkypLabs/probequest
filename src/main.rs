use anyhow::{Context, Result, bail};
use clap::Parser;
use pcap::Device;

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

    println!("Device: {}", device.name);

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
