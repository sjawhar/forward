//! Laptop side: accept the devbox on the tailnet, pipe to the local pcscd.

use std::net::{IpAddr, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;

use super::{ACCEPT_ERROR_BACKOFF, PcscError};
use crate::bridge::limit::ConnectionLimit;
use crate::config::Config;
use crate::peer::authorized;
use crate::pipe::{bidirectional, keepalive};

/// Where Debian/Ubuntu pcscd listens. Mode 0666, so connecting needs no
/// privilege; authorization is polkit's, checked against this daemon's
/// process (verified permitted for systemd --user units on this laptop).
pub const LAPTOP_PCSCD_SOCKET: &str = "/run/pcscd/pcscd.comm";

/// Start the laptop PC/SC listener on the configured address.
pub fn spawn(cfg: &Config) -> Result<(), PcscError> {
    if cfg.pcsc_port == 0 {
        eprintln!("forward: pcsc channel disabled (pcsc_port = 0)");
        return Ok(());
    }

    let ip = cfg.listen_ip().map_err(|source| PcscError::Bind {
        address: cfg.listen.clone(),
        source: std::io::Error::other(source),
    })?;
    let listener = TcpListener::bind((ip, cfg.pcsc_port)).map_err(|source| PcscError::Bind {
        address: format!("{ip}:{}", cfg.pcsc_port),
        source,
    })?;
    eprintln!("forward: pcsc channel on {ip}:{}", cfg.pcsc_port);
    spawn_with_listener(cfg.clone(), listener, PathBuf::from(LAPTOP_PCSCD_SOCKET))?;
    Ok(())
}

/// Test seam: accept on a listener the caller already bound.
#[doc(hidden)]
pub fn spawn_with_listener(
    cfg: Config,
    listener: TcpListener,
    upstream: PathBuf,
) -> Result<(), PcscError> {
    listener_spawn_result(
        thread::Builder::new()
            .name("pcsc-laptop".to_owned())
            .spawn(move || {
                accept_loop(cfg, listener, upstream);
                eprintln!("forward: pcsc channel accept loop ended; exiting");
                std::process::exit(1);
            }),
    )
}

fn listener_spawn_result(result: std::io::Result<thread::JoinHandle<()>>) -> Result<(), PcscError> {
    result
        .map(drop)
        .map_err(|source| PcscError::Spawn { source })
}

fn accept_loop(cfg: Config, listener: TcpListener, upstream: PathBuf) {
    let limit = ConnectionLimit::standard();
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let Some(permit) = limit.acquire() else {
                    eprintln!(
                        "forward: pcsc channel refused connection: concurrency limit reached"
                    );
                    // Bare close: raw pcscd bytes have no refusal frame.
                    continue;
                };
                let cfg = cfg.clone();
                let upstream = upstream.clone();
                if let Err(error) = thread::Builder::new()
                    .name("pcsc-session".to_owned())
                    .spawn(move || {
                        let _permit = permit;
                        handle(&cfg, &upstream, stream);
                    })
                {
                    eprintln!("forward: pcsc channel failed to start connection handler: {error}");
                }
            }
            Err(error) => {
                eprintln!("forward: pcsc channel accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn handle(cfg: &Config, upstream: &Path, stream: TcpStream) {
    let remote = match stream.peer_addr() {
        Ok(remote) => remote,
        Err(error) => {
            eprintln!("forward: pcsc channel refused connection without a peer address: {error}");
            return;
        }
    };
    handle_from(cfg, upstream, remote.ip(), stream);
}

/// Test seam: handle a connection whose peer address is supplied by the caller.
#[doc(hidden)]
pub fn handle_from(cfg: &Config, upstream: &Path, remote: IpAddr, stream: TcpStream) {
    if !authorized(cfg, remote) {
        eprintln!("forward: pcsc channel refused peer {remote}");
        // Bare close: this stream carries a protocol we must not touch.
        return;
    }

    let pcscd = match UnixStream::connect(upstream) {
        Ok(pcscd) => pcscd,
        Err(error) => {
            eprintln!(
                "forward: pcsc channel: pcscd socket {} unavailable: {error}",
                upstream.display()
            );
            return;
        }
    };
    if let Err(error) = keepalive(&stream) {
        eprintln!("forward: pcsc channel could not configure keepalive for {remote}: {error}");
        return;
    }
    if let Err(error) = bidirectional(stream, pcscd) {
        eprintln!("forward: pcsc session for {remote} ended: {error}");
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::listener_spawn_result;
    use crate::pcsc::PcscError;

    #[test]
    fn listener_thread_spawn_failure_is_reported() {
        let error =
            listener_spawn_result(Err(io::Error::other("thread limit"))).expect_err("must fail");

        assert!(
            matches!(error, PcscError::Spawn { source } if source.kind() == io::ErrorKind::Other)
        );
    }
}
