use crate::config::Config;
use crate::forwards::{ForwardTracker, is_dynamic_port, request_forward, spawn_reaper};
use crate::localhost::forward_ports;
use crate::policy::{Decision, decide};
use crate::ratelimit::{OpenDecision, RecentOpens};
use crate::request::read_url;
mod notification;
use notification::notify_url;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use thiserror::Error;
use url::Url;

const MAX_DYNAMIC_FORWARDS: usize = 4;
#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("forward: failed to bind daemon on port {port}: {source}")]
    Bind {
        port: u16,
        #[source]
        source: std::io::Error,
    },
}

pub fn run(cfg: Config, config_path: &Path, port: u16) -> Result<(), DaemonError> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|source| DaemonError::Bind { port, source })?;
    eprintln!(
        "forward: daemon config={} mode={:?} opener={:?} allow_entries={}",
        config_path.display(),
        cfg.mode,
        cfg.opener,
        cfg.allow.len()
    );
    let recent_opens = Arc::new(Mutex::new(RecentOpens::new()));
    let forwards = ForwardTracker::new();
    spawn_reaper(cfg.clone(), forwards.clone());
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let peer_port = stream
                    .peer_addr()
                    .map(|address| address.port())
                    .unwrap_or_default();
                let connection_config = cfg.clone();
                let connection_opens = Arc::clone(&recent_opens);
                let connection_forwards = forwards.clone();
                if let Err(error) = thread::Builder::new()
                    .name(format!("fwd-{peer_port}"))
                    .spawn(move || {
                        handle_connection(
                            stream,
                            connection_config,
                            connection_opens,
                            connection_forwards,
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
    forwards: ForwardTracker,
) {
    let Some(url) = read_url(stream) else {
        return;
    };
    match decide(&cfg, &url) {
        Decision::Open => {
            eprintln!("forward: URL {url} decision=open");
            open_permitted_url(&cfg, &url, &recent_opens, &forwards);
        }
        Decision::Notify => {
            eprintln!("forward: URL {url} decision=notify");
            if notify_url(&cfg, &url) {
                eprintln!("forward: notification approved; opening {url}");
                open_permitted_url(&cfg, &url, &recent_opens, &forwards);
            }
        }
    }
}

fn open_permitted_url(
    cfg: &Config,
    url: &Url,
    recent_opens: &Mutex<RecentOpens>,
    forwards: &ForwardTracker,
) {
    let decision = match recent_opens.lock() {
        Ok(mut opens) => opens.record(url, Instant::now()),
        Err(poisoned) => poisoned.into_inner().record(url, Instant::now()),
    };
    match decision {
        OpenDecision::Permit => {
            forward_url(cfg, url, forwards);
            open_url(cfg, url);
        }
        OpenDecision::Drop { count } => {
            eprintln!("forward: dropping {url}: opened {count} times in 2s, refusing to loop")
        }
    }
}

fn forward_url(cfg: &Config, url: &Url, forwards: &ForwardTracker) {
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
        request_forward(cfg, forwards, port);
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
