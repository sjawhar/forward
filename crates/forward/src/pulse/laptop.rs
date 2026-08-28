//! Laptop side: accept the devbox on the tailnet, pipe to pipewire-pulse.

use std::net::{IpAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;

use super::{ACCEPT_ERROR_BACKOFF, PulseError, tune};
use crate::bridge::limit::ConnectionLimit;
use crate::config::Config;
use crate::peer::authorized_remote;
use crate::pipe::bidirectional;

/// Where pipewire-pulse listens. Mode 0666 on the supported deployment, so
/// connecting needs no helper or group membership; pipewire-pulse remains
/// responsible for handling its client.
pub fn upstream_path() -> Option<PathBuf> {
    super::runtime_dir().map(|dir| dir.join("pulse/native"))
}

/// Start the laptop pulse listener on the configured address.
pub fn spawn(cfg: &Config) -> Result<(), PulseError> {
    let Ok(Some(_)) = cfg.peer_ip() else {
        eprintln!("forward: pulse channel not served: no peer configured");
        return Ok(());
    };

    if cfg.pulse_port == 0 {
        eprintln!("forward: pulse channel disabled (pulse_port = 0)");
        return Ok(());
    }

    let upstream = upstream_path().ok_or(PulseError::RuntimeDir)?;
    let ip = cfg.listen_ip().map_err(|source| PulseError::Bind {
        address: cfg.listen.clone(),
        source: std::io::Error::other(source),
    })?;
    let listener = TcpListener::bind((ip, cfg.pulse_port)).map_err(|source| PulseError::Bind {
        address: format!("{ip}:{}", cfg.pulse_port),
        source,
    })?;
    eprintln!("forward: pulse channel on {ip}:{}", cfg.pulse_port);
    spawn_with_listener(cfg.clone(), listener, upstream)?;
    Ok(())
}

/// Test seam: accept on a listener the caller already bound.
#[doc(hidden)]
pub fn spawn_with_listener(
    cfg: Config,
    listener: TcpListener,
    upstream: PathBuf,
) -> Result<(), PulseError> {
    listener_spawn_result(
        thread::Builder::new()
            .name("pulse-laptop".to_owned())
            .spawn(move || {
                accept_loop(cfg, listener, upstream);
                eprintln!("forward: pulse channel accept loop ended; exiting");
                std::process::exit(1);
            }),
    )
}

fn listener_spawn_result(
    result: std::io::Result<thread::JoinHandle<()>>,
) -> Result<(), PulseError> {
    result
        .map(drop)
        .map_err(|source| PulseError::Spawn { source })
}

fn accept_loop(cfg: Config, listener: TcpListener, upstream: PathBuf) {
    let limit = ConnectionLimit::standard();
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let Some(permit) = limit.acquire() else {
                    eprintln!(
                        "forward: pulse channel refused connection: concurrency limit reached"
                    );
                    // Bare close: raw native-protocol bytes have no refusal frame.
                    continue;
                };
                let cfg = cfg.clone();
                let upstream = upstream.clone();
                if let Err(error) = thread::Builder::new()
                    .name("pulse-session".to_owned())
                    .spawn(move || {
                        let _permit = permit;
                        handle(&cfg, &upstream, stream);
                    })
                {
                    eprintln!("forward: pulse channel failed to start connection handler: {error}");
                }
            }
            Err(error) => {
                eprintln!("forward: pulse channel accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn handle(cfg: &Config, upstream: &Path, stream: TcpStream) {
    let remote = match stream.peer_addr() {
        Ok(remote) => remote,
        Err(error) => {
            eprintln!("forward: pulse channel refused connection without a peer address: {error}");
            return;
        }
    };
    handle_from(cfg, upstream, remote.ip(), stream);
}

/// Test seam: handle a connection whose peer address is supplied by the caller.
#[doc(hidden)]
pub fn handle_from(cfg: &Config, upstream: &Path, remote: IpAddr, stream: TcpStream) {
    if !authorized_remote(cfg, remote) {
        eprintln!("forward: pulse channel refused peer {remote}");
        // Bare close: this stream carries a protocol we must not touch.
        return;
    }

    let pulse = match UnixStream::connect(upstream) {
        Ok(pulse) => pulse,
        Err(error) => {
            eprintln!(
                "forward: pulse channel: pipewire-pulse socket {} unavailable: {error}",
                upstream.display()
            );
            return;
        }
    };
    if let Err(error) = tune(&stream) {
        eprintln!("forward: pulse channel could not tune the connection from {remote}: {error}");
        return;
    }
    if let Err(error) = bidirectional(stream, pulse) {
        eprintln!("forward: pulse session for {remote} ended: {error}");
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::listener_spawn_result;
    use crate::pulse::PulseError;

    #[test]
    fn listener_thread_spawn_failure_is_reported() {
        let error =
            listener_spawn_result(Err(io::Error::other("thread limit"))).expect_err("must fail");

        assert!(
            matches!(error, PulseError::Spawn { source } if source.kind() == io::ErrorKind::Other)
        );
    }
}
