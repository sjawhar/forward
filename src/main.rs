use clap::{Parser, Subcommand};
use std::io::Write as _;

mod config;
mod daemon;
mod forwards;
mod localhost;
mod policy;
mod process;
mod ratelimit;
mod render;
mod request;
mod send;
mod serve;
mod target;

use forwards::CHANNEL_PORT;
pub(crate) use forwards::FILES_PORT;
const OPENER_REENTRY_ERROR: &str = "forward: refusing to open URL because the configured opener is routing back into forward open; set opener to an absolute path such as /usr/bin/xdg-open";

#[derive(Parser)]
#[command(
    name = "forward",
    version,
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
            open_target(
                &target,
                CHANNEL_PORT,
                std::env::var_os("FORWARD_OPENER_REENTRY").is_some(),
            )
            .unwrap_or_else(|error| exit_with_error(error));
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
            let config_path = std::path::absolute(config.unwrap_or_else(|| {
                default_config_path().unwrap_or_else(|error| exit_with_error(error))
            }))?;
            let config = config::load(&config_path).unwrap_or_else(|error| exit_with_error(error));
            daemon::run(config, &config_path, port).unwrap_or_else(|error| exit_with_error(error));
            Ok(())
        }
    }
}

fn open_target(target: &str, channel_port: u16, opener_reentry: bool) -> anyhow::Result<()> {
    if opener_reentry {
        anyhow::bail!(OPENER_REENTRY_ERROR);
    }
    let url = target::to_url(target, FILES_PORT)?;
    send::send_url(&url, channel_port)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::open_target;
    use std::io::Read as _;

    #[test]
    fn open_sends_url_when_opener_reentry_is_unset() {
        // Given: a listener for the opener channel.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let receiver = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut received = String::new();
            stream.read_to_string(&mut received).unwrap();
            received
        });

        // When: open runs without the re-entry marker.
        open_target("https://example.com/redirect", port, false).unwrap();

        // Then: it sends the URL through the opener channel.
        assert_eq!(receiver.join().unwrap(), "https://example.com/redirect\n");
    }
}
