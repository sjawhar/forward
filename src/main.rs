use clap::{Parser, Subcommand};
use std::io::Write as _;

mod config;
mod daemon;
mod localhost;
mod policy;
mod process;
mod render;
mod request;
mod send;
mod serve;
mod target;

const CHANNEL_PORT: u16 = 12_800;
pub(crate) const FILES_PORT: u16 = 12_802;

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
        Command::Serve { port } => {
            serve::run(port).unwrap_or_else(|error| exit_with_error(error));
            Ok(())
        }
        Command::Daemon { port, config } => {
            let config_path = config.unwrap_or_else(|| {
                default_config_path().unwrap_or_else(|error| exit_with_error(error))
            });
            let config = config::load(&config_path).unwrap_or_else(|error| exit_with_error(error));
            daemon::run(config, port).unwrap_or_else(|error| exit_with_error(error));
            Ok(())
        }
    }
}

fn default_config_path() -> anyhow::Result<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("XDG_CONFIG_HOME").map(std::path::PathBuf::from)
        && !path.as_os_str().is_empty()
        && path.is_absolute()
    {
        return Ok(path.join("forward/config.toml"));
    }
    if let Some(path) = std::env::var_os("HOME").map(std::path::PathBuf::from)
        && !path.as_os_str().is_empty()
        && path.is_absolute()
    {
        return Ok(path.join(".config/forward/config.toml"));
    }
    anyhow::bail!(
        "forward: cannot resolve config path: XDG_CONFIG_HOME and HOME are unset or not an absolute path"
    )
}

fn exit_with_error(error: impl std::fmt::Display) -> ! {
    eprintln!("{error}");
    std::process::exit(1)
}
