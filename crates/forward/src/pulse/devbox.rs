//! Devbox side: serve `$XDG_RUNTIME_DIR/forward/pulse.sock` — the socket
//! consumers opt into with an explicit `PULSE_SERVER` — and dial the laptop's
//! pulse channel per client connection.

use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::{io, thread};

use super::{ACCEPT_ERROR_BACKOFF, CONNECT_TIMEOUT, PulseError, tune};
use crate::bridge::limit::ConnectionLimit;
use crate::config::Config;
use crate::pipe::bidirectional;

/// `$XDG_RUNTIME_DIR/forward/pulse.sock`. Fixed contract with the dotfiles'
/// `PULSE_SERVER` export; never configurable, and deliberately **not**
/// PulseAudio's default socket path: clients must opt in, sizing their
/// buffers for a network round trip when and only when they do.
pub fn socket_path() -> Option<PathBuf> {
    super::runtime_dir().map(|dir| dir.join("forward/pulse.sock"))
}

/// Serve the pulse socket when this machine has a peer to relay to.
pub fn spawn(cfg: &Config) -> Result<(), PulseError> {
    let Ok(Some(peer)) = cfg.peer_ip() else {
        eprintln!("forward: pulse socket not served: no peer configured");
        return Ok(());
    };
    if cfg.pulse_port == 0 {
        eprintln!("forward: pulse socket not served: pulse channel disabled (pulse_port = 0)");
        return Ok(());
    }

    let path = socket_path().ok_or(PulseError::RuntimeDir)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| socket_error(&path, source))?;
        // 0700 even when the directory pre-existed: the socket's own 0600 is
        // the gate for this uid, but no other uid may traverse or replace it.
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
            .map_err(|source| socket_error(&path, source))?;
    }
    let listener = crate::socket::bind(&path).map_err(|source| socket_error(&path, source))?;
    let upstream = SocketAddr::new(peer, cfg.pulse_port);
    eprintln!(
        "forward: pulse socket at {} relaying to {upstream}",
        path.display()
    );
    spawn_with_unix_listener(listener, upstream)
}

fn socket_error(path: &Path, source: io::Error) -> PulseError {
    PulseError::Socket {
        path: path.to_owned(),
        source,
    }
}

/// Test seam: accept on a unix listener the caller already bound.
#[doc(hidden)]
pub fn spawn_with_unix_listener(
    listener: UnixListener,
    upstream: SocketAddr,
) -> Result<(), PulseError> {
    listener_spawn_result(
        thread::Builder::new()
            .name("pulse-devbox".to_owned())
            .spawn(move || {
                accept_loop(listener, upstream);
                eprintln!("forward: pulse socket accept loop ended; exiting");
                std::process::exit(1);
            }),
    )
}

fn listener_spawn_result(result: io::Result<thread::JoinHandle<()>>) -> Result<(), PulseError> {
    result
        .map(drop)
        .map_err(|source| PulseError::Spawn { source })
}

fn accept_loop(listener: UnixListener, upstream: SocketAddr) {
    let limit = ConnectionLimit::standard();
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let Some(permit) = limit.acquire() else {
                    eprintln!(
                        "forward: pulse socket refused connection: concurrency limit reached"
                    );
                    // Bare close: raw native-protocol bytes have no refusal frame.
                    continue;
                };
                if let Err(error) = thread::Builder::new()
                    .name("pulse-session".to_owned())
                    .spawn(move || {
                        let _permit = permit;
                        handle(upstream, stream);
                    })
                {
                    eprintln!("forward: pulse socket failed to start connection handler: {error}");
                }
            }
            Err(error) => {
                eprintln!("forward: pulse socket accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn handle(upstream: SocketAddr, stream: UnixStream) {
    handle_with_dial(upstream, stream, |address, timeout| {
        TcpStream::connect_timeout(&address, timeout)
    });
}

fn handle_with_dial<F>(upstream: SocketAddr, stream: UnixStream, dial: F)
where
    F: FnOnce(SocketAddr, std::time::Duration) -> io::Result<TcpStream>,
{
    // Fail loud and fast: an immediate close is what pulse clients already
    // treat as "no service", exactly like the retired tunnel when it was
    // down, and the more honest error than "no audio system".
    let laptop = match dial(upstream, CONNECT_TIMEOUT) {
        Ok(laptop) => laptop,
        Err(error) => {
            eprintln!("forward: pulse channel: laptop {upstream} unreachable: {error}");
            return;
        }
    };
    if let Err(error) = tune(&laptop) {
        eprintln!("forward: pulse channel could not tune the connection to {upstream}: {error}");
        return;
    }
    if let Err(error) = bidirectional(stream, laptop) {
        eprintln!("forward: pulse session ended: {error}");
    }
}

#[cfg(test)]
mod tests;
