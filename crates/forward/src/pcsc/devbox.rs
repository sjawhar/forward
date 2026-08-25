//! Devbox side: serve `~/.pcscd/pcscd.comm` — the exact path secretsd's
//! `PCSCLITE_CSOCK_NAME` and `age-plugin-yubikey` already use — and dial the
//! laptop's pcsc channel per client connection.

use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::{io, thread};

use nix::sys::stat::{Mode, umask};

use super::{ACCEPT_ERROR_BACKOFF, CONNECT_TIMEOUT, PcscError};
use crate::bridge::limit::ConnectionLimit;
use crate::config::Config;
use crate::pipe::{bidirectional, keepalive};

/// `$HOME/.pcscd/pcscd.comm`. Fixed contract with secretsd's drop-in
/// (`PCSCLITE_CSOCK_NAME=%h/.pcscd/pcscd.comm`); never configurable.
pub fn socket_path() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(".pcscd/pcscd.comm"))
}

/// Serve the pcsc socket when this machine has a peer to relay to.
pub fn spawn(cfg: &Config) -> Result<(), PcscError> {
    let Ok(Some(peer)) = cfg.peer_ip() else {
        eprintln!("forward: pcsc socket not served: no peer configured");
        return Ok(());
    };
    if cfg.pcsc_port == 0 {
        eprintln!("forward: pcsc socket not served: pcsc channel disabled (pcsc_port = 0)");
        return Ok(());
    }

    let path = socket_path().ok_or(PcscError::Home)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| socket_error(&path, source))?;
    }
    let listener = bind_socket(&path)?;
    let upstream = SocketAddr::new(peer, cfg.pcsc_port);
    eprintln!(
        "forward: pcsc socket at {} relaying to {upstream}",
        path.display()
    );
    spawn_with_unix_listener(listener, upstream)
}

fn socket_error(path: &Path, source: io::Error) -> PcscError {
    PcscError::Socket {
        path: path.to_owned(),
        source,
    }
}

/// Bind the compatibility socket without disrupting a working predecessor.
fn bind_socket(path: &Path) -> Result<UnixListener, PcscError> {
    match UnixStream::connect(path) {
        Ok(_) => {
            return Err(socket_error(
                path,
                io::Error::from(io::ErrorKind::AddrInUse),
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            remove_stale_socket(path, error)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match std::fs::symlink_metadata(path) {
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => return Err(socket_error(path, error)),
                Err(source) => return Err(socket_error(path, source)),
            }
        }
        Err(source) => return Err(socket_error(path, source)),
    }

    bind_listener(path).map_err(|source| socket_error(path, source))
}

/// Remove only a socket that remains unserved at the final check.
fn remove_stale_socket(path: &Path, initial_error: io::Error) -> Result<(), PcscError> {
    if !path_is_socket(path, initial_error)? {
        return Ok(());
    }

    match UnixStream::connect(path) {
        Ok(_) => Err(socket_error(
            path,
            io::Error::from(io::ErrorKind::AddrInUse),
        )),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            if !path_is_socket(path, error)? {
                return Ok(());
            }
            // Cutover ordering serializes a competing socat restart. This
            // recheck narrows, but cannot eliminate, the final syscall race.
            match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(socket_error(path, source)),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(socket_error(path, source)),
    }
}

/// Return false only when the path disappeared; all non-socket entries keep
/// their original connection error rather than being treated as stale.
fn path_is_socket(path: &Path, original_error: io::Error) -> Result<bool, PcscError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(true),
        Ok(_) => Err(socket_error(path, original_error)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(socket_error(path, source)),
    }
}

struct UmaskRestore(Mode);

impl Drop for UmaskRestore {
    fn drop(&mut self) {
        umask(self.0);
    }
}

/// `0177` makes UnixListener's `0777` creation mode exactly `0600`.
fn bind_listener(path: &Path) -> io::Result<UnixListener> {
    let restore = UmaskRestore(umask(Mode::from_bits_truncate(0o177)));
    let listener = UnixListener::bind(path);
    drop(restore);
    listener
}

/// Test seam: accept on a unix listener the caller already bound.
#[doc(hidden)]
pub fn spawn_with_unix_listener(
    listener: UnixListener,
    upstream: SocketAddr,
) -> Result<(), PcscError> {
    listener_spawn_result(
        thread::Builder::new()
            .name("pcsc-devbox".to_owned())
            .spawn(move || {
                accept_loop(listener, upstream);
                eprintln!("forward: pcsc socket accept loop ended; exiting");
                std::process::exit(1);
            }),
    )
}

fn listener_spawn_result(result: io::Result<thread::JoinHandle<()>>) -> Result<(), PcscError> {
    result
        .map(drop)
        .map_err(|source| PcscError::Spawn { source })
}

fn accept_loop(listener: UnixListener, upstream: SocketAddr) {
    let limit = ConnectionLimit::standard();
    for connection in listener.incoming() {
        match connection {
            Ok(stream) => {
                let Some(permit) = limit.acquire() else {
                    eprintln!("forward: pcsc socket refused connection: concurrency limit reached");
                    // Bare close: raw pcscd bytes have no refusal frame.
                    continue;
                };
                if let Err(error) = thread::Builder::new()
                    .name("pcsc-session".to_owned())
                    .spawn(move || {
                        let _permit = permit;
                        handle(upstream, stream);
                    })
                {
                    eprintln!("forward: pcsc socket failed to start connection handler: {error}");
                }
            }
            Err(error) => {
                eprintln!("forward: pcsc socket accept failed: {error}");
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
    // Fail loud and fast: an immediate close is what pcsc clients already
    // treat as "no service", exactly like the retired bridge when its tunnel
    // was down. secretsd's probe and stderr classifier turn that into
    // YUBIKEY_UNREACHABLE before any request queues.
    let laptop = match dial(upstream, CONNECT_TIMEOUT) {
        Ok(laptop) => laptop,
        Err(error) => {
            eprintln!("forward: pcsc channel: laptop {upstream} unreachable: {error}");
            return;
        }
    };
    if let Err(error) = keepalive(&laptop) {
        eprintln!("forward: pcsc channel could not configure keepalive for {upstream}: {error}");
        return;
    }
    if let Err(error) = bidirectional(stream, laptop) {
        eprintln!("forward: pcsc session ended: {error}");
    }
}

#[cfg(test)]
mod tests;
