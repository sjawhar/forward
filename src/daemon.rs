use crate::FILES_PORT;
use crate::config::Config;
use crate::localhost::forward_ports;
use crate::policy::{Decision, decide};
use crate::process::{WaitResult, run_command, stderr};
use crate::request::read_url;
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;
use thiserror::Error;
use url::Url;

const SSH_TIMEOUT: Duration = Duration::from_secs(5);
const NOTIFIER_TIMEOUT: Duration = Duration::from_secs(70);
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

pub fn run(cfg: Config, port: u16) -> Result<(), DaemonError> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|source| DaemonError::Bind { port, source })?;
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let peer_port = stream
                    .peer_addr()
                    .map(|address| address.port())
                    .unwrap_or_default();
                let connection_config = cfg.clone();
                if let Err(error) = thread::Builder::new()
                    .name(format!("fwd-{peer_port}"))
                    .spawn(move || handle_connection(stream, connection_config))
                {
                    eprintln!("forward: failed to start daemon connection handler: {error}");
                }
            }
            Err(error) => eprintln!("forward: failed to accept daemon connection: {error}"),
        }
    }
    Ok(())
}
fn handle_connection(stream: TcpStream, cfg: Config) {
    let Some(url) = read_url(stream) else {
        return;
    };
    match decide(&cfg, &url) {
        Decision::Open => {
            eprintln!("forward: URL {url} decision=open");
            forward_url(&cfg, &url);
            open_url(&cfg, &url);
        }
        Decision::Notify => {
            eprintln!("forward: URL {url} decision=notify");
            if notify_url(&cfg, &url) {
                forward_url(&cfg, &url);
                eprintln!("forward: notification approved; opening {url}");
                open_url(&cfg, &url);
            }
        }
    }
}

fn forward_url(cfg: &Config, url: &Url) {
    let mut forwarded = 0;
    let mut dropped = 0;
    for port in forward_ports(url) {
        if port == FILES_PORT {
            continue;
        }
        if forwarded == MAX_DYNAMIC_FORWARDS {
            dropped += 1;
            continue;
        }
        forward_port(cfg, port);
        forwarded += 1;
    }
    if dropped > 0 {
        eprintln!("forward: dynamic forward limit reached; dropped {dropped} port(s)");
    }
}

fn forward_port(cfg: &Config, port: u16) {
    let Some((program, arguments)) = cfg.ssh.split_first() else {
        eprintln!("forward: SSH command is empty; cannot forward port {port}");
        return;
    };
    let mut command = Command::new(program);
    command.args(arguments).args([
        "-O",
        "forward",
        "-L",
        &format!("{port}:127.0.0.1:{port}"),
        &cfg.tunnel_host,
    ]);
    match run_command(command, SSH_TIMEOUT) {
        Ok(WaitResult::Exited(output)) if output.status.success() => {}
        Ok(WaitResult::Exited(output)) => eprintln!(
            "forward: SSH forwarding failed for port {port}: {:?}",
            stderr(&output)
        ),
        Ok(WaitResult::TimedOut(output)) => eprintln!(
            "forward: SSH forwarding timed out for port {port}: {:?}",
            stderr(&output)
        ),
        Err(error) => eprintln!("forward: failed while forwarding port {port}: {error}"),
    }
}

fn notify_url(cfg: &Config, url: &Url) -> bool {
    let mut command = if let Some((program, arguments)) = cfg.notifier.split_first() {
        let mut command = Command::new(program);
        command.args(arguments);
        command
    } else {
        let mut command = Command::new("notify-send");
        command.args([
            "--app-name=forward",
            "--expire-time=60000",
            "--wait",
            "--action=default=Open",
            "forward",
        ]);
        command
    };
    command.arg(url.as_str());
    match run_command(command, NOTIFIER_TIMEOUT) {
        Ok(WaitResult::Exited(output)) if !output.status.success() => {
            eprintln!(
                "forward: notification failed for {url}: {:?}",
                stderr(&output)
            );
            false
        }
        Ok(WaitResult::Exited(output))
            if String::from_utf8_lossy(&output.stdout).trim() == "default" =>
        {
            true
        }
        Ok(WaitResult::Exited(_)) => {
            eprintln!("forward: notification not approved: {url}");
            false
        }
        Ok(WaitResult::TimedOut(output)) => {
            // A killed notifier's stdout is untrusted, so a timed-out notification never approves.
            eprintln!(
                "forward: notification timed out for {url}: {:?}",
                stderr(&output)
            );
            false
        }
        Err(error) => {
            eprintln!("forward: failed to notify for {url}: {error}");
            false
        }
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
