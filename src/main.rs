use clap::{Parser, Subcommand};
use std::io::Write as _;

mod send;
mod target;

const CHANNEL_PORT: u16 = 12_800;
const FILES_PORT: u16 = 12_802;

#[cfg_attr(not(test), expect(dead_code, reason = "wired in Task 7"))]
mod config;
#[cfg_attr(not(test), expect(dead_code, reason = "wired in Task 7"))]
mod localhost;
#[cfg_attr(not(test), expect(dead_code, reason = "wired in Task 7"))]
mod policy;

#[derive(Parser)]
#[command(
    name = "forward",
    about = "Open devbox URLs and files in the laptop browser"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Open a URL or file path in the laptop browser
    Open { target: String },
    /// Print (and OSC 52 copy) the laptop-clickable URL for a file path
    Url { target: String },
    /// Serve devbox files read-only on loopback (devbox side)
    Serve {
        #[arg(long, default_value_t = FILES_PORT)]
        port: u16,
    },
    /// Receive URLs from the devbox and open them (laptop side)
    Daemon {
        #[arg(long, default_value_t = CHANNEL_PORT)]
        port: u16,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Open { target } => {
            let url = target::to_url(&target, FILES_PORT).unwrap_or_else(|e| exit_with_error(e));
            send::send_url(&url, CHANNEL_PORT).unwrap_or_else(|e| exit_with_error(e));
            Ok(())
        }
        Command::Url { target } => {
            let url = target::to_url(&target, FILES_PORT).unwrap_or_else(|e| exit_with_error(e));
            let _ = writeln!(std::io::stdout(), "{url}");
            let _ = send::osc52_copy(url.as_str());
            Ok(())
        }
        Command::Serve { port } => anyhow::bail!("not implemented: serve {port}"),
        Command::Daemon { port, .. } => anyhow::bail!("not implemented: daemon {port}"),
    }
}

fn exit_with_error(error: impl std::fmt::Display) -> ! {
    eprintln!("{error}");
    std::process::exit(1)
}
