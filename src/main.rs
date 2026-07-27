use clap::{Parser, Subcommand};

mod target;

#[cfg_attr(not(test), expect(dead_code, reason = "wired in Task 7"))]
mod config;
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
        #[arg(long, default_value_t = 12802)]
        port: u16,
    },
    /// Receive URLs from the devbox and open them (laptop side)
    Daemon {
        #[arg(long, default_value_t = 12800)]
        port: u16,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Open { target } => anyhow::bail!("not implemented: open {target}"),
        Command::Url { target } => anyhow::bail!("not implemented: url {target}"),
        Command::Serve { port } => anyhow::bail!("not implemented: serve {port}"),
        Command::Daemon { port, .. } => anyhow::bail!("not implemented: daemon {port}"),
    }
}
