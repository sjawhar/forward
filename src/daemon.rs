use crate::ratelimit::{OpenDecision, RecentOpens};
use crate::request::read_url;
use forward::callback::{Leases, MAX_DYNAMIC_FORWARDS, is_dynamic_port, request, spawn_reaper};
use forward::config::Config;
use forward::localhost::forward_ports;
use forward::peer::authorized;
use forward::policy::{Decision, decide};
mod notification;
use notification::notify_url;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use thiserror::Error;
use url::Url;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("forward: refusing to start: {source}")]
    Config {
        #[source]
        source: forward::config::ConfigError,
    },
    #[error("forward: failed to bind daemon on port {port}: {source}")]
    Bind {
        port: u16,
        #[source]
        source: std::io::Error,
    },
}

pub fn run(cfg: Config, config_path: &Path, port: u16) -> Result<(), DaemonError> {
    cfg.validate()
        .map_err(|source| DaemonError::Config { source })?;
    let ip = cfg
        .listen_ip()
        .map_err(|source| DaemonError::Config { source })?;
    let address = SocketAddr::new(ip, port);
    let listener =
        TcpListener::bind(address).map_err(|source| DaemonError::Bind { port, source })?;
    eprintln!(
        "forward: daemon config={} listen={address} peer={:?} mode={:?} opener={:?} allow_entries={}",
        config_path.display(),
        cfg.peer,
        cfg.mode,
        cfg.opener,
        cfg.allow.len()
    );
    let recent_opens = Arc::new(Mutex::new(RecentOpens::new()));
    let leases = Leases::new();
    spawn_reaper(leases.clone());
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let Ok(remote) = stream.peer_addr() else {
                    eprintln!("forward: dropping daemon connection with no peer address");
                    continue;
                };
                if !authorized(&cfg, remote.ip()) {
                    eprintln!("forward: refused URL channel peer {}", remote.ip());
                    continue;
                }
                let peer_port = remote.port();
                let connection_config = cfg.clone();
                let connection_opens = Arc::clone(&recent_opens);
                let connection_leases = leases.clone();
                if let Err(error) = thread::Builder::new()
                    .name(format!("fwd-{peer_port}"))
                    .spawn(move || {
                        handle_connection(
                            stream,
                            connection_config,
                            connection_opens,
                            connection_leases,
                        )
                    })
                {
                    eprintln!("forward: failed to start daemon connection handler: {error}");
                }
            }
            Err(error) => eprintln!("forward: failed to accept daemon connection: {error}"),
        }
    }
    Ok(())
}
fn handle_connection(
    stream: TcpStream,
    cfg: Config,
    recent_opens: Arc<Mutex<RecentOpens>>,
    leases: Leases,
) {
    let Some(url) = read_url(stream) else {
        return;
    };
    // Callback ports belong to the URL, not to the open decision. A notified
    // URL is handed to the user precisely so they can open it themselves, and
    // that login's callback must find a listener when the provider redirects
    // to localhost — otherwise the paste path completes the auth page and then
    // dies on a refused connection. Leasing on notify grants nothing new:
    // this machine is the bridge's authorized peer, so any local process
    // could already ask the bridge directly for anything the lease relays.
    forward_url(&cfg, &url, &leases);
    match decide(&cfg, &url) {
        Decision::Open => {
            eprintln!("forward: URL {url} decision=open");
            open_permitted_url(&cfg, &url, &recent_opens);
        }
        Decision::Notify => {
            eprintln!("forward: URL {url} decision=notify");
            if notify_url(&cfg, &url) {
                eprintln!("forward: notification approved; opening {url}");
                open_permitted_url(&cfg, &url, &recent_opens);
            }
        }
    }
}

fn open_permitted_url(cfg: &Config, url: &Url, recent_opens: &Mutex<RecentOpens>) {
    let decision = match recent_opens.lock() {
        Ok(mut opens) => opens.record(url, Instant::now()),
        Err(poisoned) => poisoned.into_inner().record(url, Instant::now()),
    };
    match decision {
        OpenDecision::Permit => open_url(cfg, url),
        OpenDecision::Drop { count } => {
            eprintln!("forward: dropping {url}: opened {count} times in 2s, refusing to loop")
        }
    }
}

fn forward_url(cfg: &Config, url: &Url, leases: &Leases) {
    let mut forwarded = 0;
    let mut dropped = 0;
    for port in forward_ports(url) {
        if !is_dynamic_port(port) {
            continue;
        }
        if forwarded == MAX_DYNAMIC_FORWARDS {
            dropped += 1;
            continue;
        }
        request(cfg, leases, port);
        forwarded += 1;
    }
    if dropped > 0 {
        eprintln!("forward: dynamic forward limit reached; dropped {dropped} port(s)");
    }
}

fn open_url(cfg: &Config, url: &Url) {
    let Some((program, arguments)) = cfg.opener.split_first() else {
        eprintln!("forward: opener command is empty; cannot open {url}");
        return;
    };
    let mut command = Command::new(program);
    command
        .args(arguments)
        .arg(url.as_str())
        .env("FORWARD_OPENER_REENTRY", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match command.spawn() {
        Ok(mut child) => {
            let url_for_reaper = url.to_string();
            drop(thread::spawn(move || {
                if let Ok(status) = child.wait()
                    && !status.success()
                {
                    eprintln!("forward: opener exited {status} for {url_for_reaper}");
                }
            }));
            eprintln!("forward: opener spawned for {url}");
        }
        Err(error) => eprintln!("forward: failed to open {url}: {error}"),
    }
}
