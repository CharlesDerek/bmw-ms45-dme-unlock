mod desktop;
mod server;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "ms45-gui")]
#[command(about = "Desktop and web GUI for MS45 binary preparation")]
struct Args {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Launch the native desktop GUI.
    Desktop,
    /// Start the browser-based web UI.
    Server {
        #[arg(long, default_value_t = IpAddr::V4(Ipv4Addr::LOCALHOST))]
        host: IpAddr,
        #[arg(long, default_value_t = 4580)]
        port: u16,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    match Args::parse().command.unwrap_or(Command::Desktop) {
        Command::Desktop => desktop::run(),
        Command::Server { host, port } => server::run(SocketAddr::new(host, port)).await,
    }
}
