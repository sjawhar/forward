use clap::{Parser, Subcommand};
use forward::callback::CHANNEL_PORT;
use forward::config::{self, Config};
use forward::{bridge, doctor, send, serve, target};
use std::io::Write as _;

mod daemon;
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
    /// Manage browser access (laptop: init-token)
    Browser {
        #[command(subcommand)]
        action: BrowserCommand,
    },
}

#[derive(Subcommand)]
enum BrowserCommand {
    /// Generate the relay token, store it, and print it once (laptop side)
    InitToken {
        #[arg(long)]
        config: Option<std::path::PathBuf>,
    },

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
            let armed = bridge::Armed::new();
            bridge::serve_arming(armed.clone(), bridge::arm_socket_path());
            let grants = forward::browser::grant::Grants::new();
            let grant_cfg = cfg.clone();
            drop(std::thread::spawn(move || {
                forward::browser::request::serve(
                    grants,
                    grant_cfg,
                    forward::browser::request::socket_path(),
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
            BrowserCommand::InitToken { config } => {
                let (cfg, _) = load_config(config)?;
                let path = cfg.relay_token_path().ok_or_else(|| {
                    anyhow::anyhow!(
                        "forward: cannot resolve the relay token path: relay_token_file is unset and neither XDG_CONFIG_HOME nor HOME is an absolute path"
                    )
                })?;
                let value = forward::browser::init::write_token(&path)?;
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "{value}")?;
                Ok(())
            }
            BrowserCommand::Grant { ttl, config } => {
                let _ = load_config(config)?;
                let Ok(token) = std::env::var("FORWARD_BROWSER_GRANT") else {
                    eprintln!("forward: FORWARD_BROWSER_GRANT is not set; run");
                    eprintln!("  secrets FORWARD_BROWSER_GRANT -- forward browser grant --ttl 30m");
                    std::process::exit(1);
                };
                let Some(ttl_secs) = forward::browser::request::parse_ttl(&ttl) else {
                    eprintln!("forward: invalid --ttl {ttl:?}; use 45s, 30m, or 2h");
                    std::process::exit(1);
                };
                let socket = forward::browser::request::socket_path();
                let Some(port) =
                    forward::browser::request::request(&socket, ttl_secs, token.as_bytes())
                else {
                    eprintln!(
                        "forward: grant refused, or no forward serve at {}",
                        socket.display()
                    );
                    std::process::exit(1);
                };
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "http://127.0.0.1:{port}")?;
                Ok(())
            }
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
