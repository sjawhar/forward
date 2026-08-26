use std::io::Write as _;

use clap::{Parser, Subcommand};
use forward::callback::CHANNEL_PORT;
use forward::config::{self, Config};
use forward::{bridge, doctor, send, serve, target};

mod daemon;
mod grant;
mod opener;
mod process;
mod ratelimit;
mod request;

pub(crate) use forward::callback::FILES_PORT;

#[derive(Parser)]
#[command(
    name = "forward",
    version,
    about = "Open devbox URLs and files in the laptop browser, and let the devbox reach it"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Open a URL or file path in the laptop browser
    Open {
        target: String,
        #[arg(long, default_value_t = CHANNEL_PORT)]
        port: u16,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Print (and OSC 52 copy) the laptop-clickable URL for a file path
    Url {
        target: String,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Serve devbox files read-only on loopback (devbox side)
    Serve {
        #[arg(long, default_value_t = FILES_PORT)]
        port: u16,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Receive URLs from the devbox and open them, and front the browser relay
    /// channel on :12803 so devbox agents can drive this machine's Chrome
    /// (laptop side)
    Daemon {
        #[arg(long, default_value_t = CHANNEL_PORT)]
        port: u16,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
    /// Report the health of every channel forward owns
    Doctor {
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        #[arg(long, default_value_t = CHANNEL_PORT)]
        channel_port: u16,
        #[arg(long, default_value_t = FILES_PORT)]
        files_port: u16,
    },
    /// Manage browser access
    Browser {
        #[command(subcommand)]
        action: BrowserCommand,
    },
}

#[derive(Subcommand)]
enum BrowserCommand {
    /// Request browser access for this session (devbox side)
    Grant {
        /// Grant lifetime, for example 45s, 30m, or 2h
        #[arg(long, default_value = "30m")]
        ttl: String,
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },
}

fn main() -> anyhow::Result<()> {
    // Suppress core dumps before anything can hold a relay token.
    //
    // The workspace builds with panic = "abort", so a panic in any forward
    // process raises SIGABRT, and a core dump of the daemon would contain the
    // live grant tokens and, on the laptop, the whole mirror. The secrets
    // broker has always applied this; forward held bearer material without it.
    // A failure here is fatal by choice: continuing would mean serving grants
    // from a process whose crash writes them to disk.
    if let Err(error) = hygiene::hardening::apply_no_core_dumps() {
        eprintln!("forward: refusing to start without core-dump suppression: {error}");
        std::process::exit(1);
    }
    let cli = Cli::parse();
    match cli.command {
        Command::Open {
            target,
            port,
            config,
        } => {
            let (cfg, _) = load_config(config)?;
            opener::open_target(
                &cfg,
                &target,
                port,
                std::env::var_os("FORWARD_OPENER_REENTRY").is_some(),
            )
            .unwrap_or_else(|error| exit_with_error(error));
            Ok(())
        }
        Command::Url { target, config } => {
            let (cfg, _) = load_config(config)?;
            let url = target::to_url(&target, &cfg.listen, FILES_PORT)
                .unwrap_or_else(|error| exit_with_error(error));
            let _ = writeln!(std::io::stdout(), "{url}");
            let _ = send::osc52_copy(url.as_str());
            Ok(())
        }
        Command::Serve { port, config } => {
            let (cfg, _) = load_config(config)?;
            // PC/SC binds under a temporary process-wide umask, so start it
            // before any service thread can create a file.
            forward::pcsc::devbox::spawn(&cfg).unwrap_or_else(|error| exit_with_error(error));
            let armed = bridge::Armed::new(cfg.clone());
            bridge::serve_arming(armed.clone(), bridge::arm_socket_path());
            let grants = forward::browser::grant::Grants::new();
            forward::browser::subscription::spawn(grants.clone())
                .unwrap_or_else(|error| exit_with_error(error));
            let slot = forward::browser::push::FeedSlot::new();
            forward::browser::push::spawn_listener(&cfg, slot.clone(), grants.clone())
                .unwrap_or_else(|error| exit_with_error(error));
            let grant_cfg = cfg.clone();
            let grant_slot = slot.clone();
            let grant_grants = grants.clone();
            drop(std::thread::spawn(move || {
                forward::browser::request::serve(
                    grant_grants,
                    grant_cfg,
                    forward::browser::request::socket_path(),
                    grant_slot,
                );
            }));
            let bridge_cfg = cfg.clone();
            drop(std::thread::spawn(move || {
                if let Err(error) = bridge::serve(bridge_cfg, armed) {
                    eprintln!("{error}");
                }
            }));
            serve::run(&cfg, port).unwrap_or_else(|error| exit_with_error(error));
            Ok(())
        }
        Command::Daemon { port, config } => {
            let (cfg, config_path) = load_config(config)?;
            daemon::run(cfg, &config_path, port).unwrap_or_else(|error| exit_with_error(error));
            Ok(())
        }
        Command::Browser { action } => match action {
            BrowserCommand::Grant { ttl, config } => grant::run(&ttl, config),
        },
        Command::Doctor {
            config,
            channel_port,
            files_port,
        } => {
            let (cfg, _) = load_config(config)?;
            if doctor::run(&cfg, channel_port, files_port) {
                Ok(())
            } else {
                std::process::exit(1)
            }
        }
    }
}

fn load_config(path: Option<std::path::PathBuf>) -> anyhow::Result<(Config, std::path::PathBuf)> {
    let config_path =
        std::path::absolute(path.unwrap_or_else(|| {
            default_config_path().unwrap_or_else(|error| exit_with_error(error))
        }))?;
    let cfg = config::load(&config_path).unwrap_or_else(|error| exit_with_error(error));
    cfg.validate()
        .unwrap_or_else(|error| exit_with_error(error));
    Ok((cfg, config_path))
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
