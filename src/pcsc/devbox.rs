//! Devbox side: serve `~/.pcscd/pcscd.comm` — the exact path secretsd's
//! `PCSCLITE_CSOCK_NAME` and `age-plugin-yubikey` already use — and dial the
//! laptop's pcsc channel per client connection.

use super::{ACCEPT_ERROR_BACKOFF, CONNECT_TIMEOUT, PcscError};
use crate::bridge::limit::ConnectionLimit;
use crate::config::Config;
use crate::pipe::{bidirectional, keepalive};
use std::io;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;

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
        std::fs::create_dir_all(parent).map_err(|source| PcscError::Socket {
            path: path.clone(),
            source,
        })?;
    }
    let listener = bind_socket(&path)?;
    let upstream = SocketAddr::new(peer, cfg.pcsc_port);
    eprintln!(
        "forward: pcsc socket at {} relaying to {upstream}",
        path.display()
    );
    spawn_with_unix_listener(listener, upstream)
}

/// Bind the compatibility socket without disrupting a working predecessor.
fn bind_socket(path: &Path) -> Result<UnixListener, PcscError> {
    let socket_error = |source| PcscError::Socket {
        path: path.to_owned(),
        source,
    };

    match UnixStream::connect(path) {
        Ok(_) => return Err(socket_error(io::Error::from(io::ErrorKind::AddrInUse))),
        // A refused unix-stream connection is the kernel's stale-socket signal.
        // Do not remove any other failure: it may be a live, overloaded, or
        // inaccessible service, and migration must never disrupt one.
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path).map_err(socket_error)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(source) => return Err(socket_error(source)),
    }

    let listener = UnixListener::bind(path).map_err(socket_error)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(socket_error)?;
    Ok(listener)
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
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    accept_loop(listener, upstream)
                }));
                match outcome {
                    Err(_) => eprintln!("forward: pcsc socket accept loop panicked; exiting"),
                    Ok(()) => eprintln!("forward: pcsc socket accept loop ended; exiting"),
                }
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
    // Fail loud and fast: an immediate close is what pcsc clients already
    // treat as "no service", exactly like the retired bridge when its tunnel
    // was down. secretsd's probe and stderr classifier turn that into
    // YUBIKEY_UNREACHABLE before any request queues.
    let laptop = match TcpStream::connect_timeout(&upstream, CONNECT_TIMEOUT) {
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
mod tests {
    use super::listener_spawn_result;
    use crate::pcsc::PcscError;
    use std::io;

    #[test]
    fn listener_thread_spawn_failure_is_reported() {
        let error =
            listener_spawn_result(Err(io::Error::other("thread limit"))).expect_err("must fail");

        assert!(
            matches!(error, PcscError::Spawn { source } if source.kind() == io::ErrorKind::Other)
        );
    }
}
