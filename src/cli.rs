//! The CLI module.

use clap::Parser;

/// Toolkit for Playing with Wi-Fi Probe Requests
#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
pub(crate) struct Cli {
    /// Activate the debug mode.
    #[arg(short, long)]
    pub(crate) debug: Option<bool>,

    /// Name of the network interface to use.
    #[arg(short, long)]
    pub(crate) interface: Option<String>,
}
