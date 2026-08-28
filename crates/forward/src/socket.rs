//! Bind a fixed-path Unix socket without disrupting a live predecessor.
//!
//! Shared by the pcsc and pulse channels: both serve a fixed devbox socket
//! and must never unlink a socket another process still answers on.

use std::io;
use std::os::unix::fs::FileTypeExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use nix::sys::stat::{Mode, umask};

/// Bind the socket with mode `0600`, refusing to replace a working
/// predecessor: a served socket is `AddrInUse`, a stale one is unlinked only
/// after a recheck, and a non-socket path keeps its original error.
///
/// This temporarily alters the process-wide umask, so call it only before any
/// file-creating threads exist.
pub(crate) fn bind(path: &Path) -> io::Result<UnixListener> {
    match UnixStream::connect(path) {
        Ok(_) => return Err(io::Error::from(io::ErrorKind::AddrInUse)),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            remove_stale_socket(path, error)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match std::fs::symlink_metadata(path) {
                Err(source) if source.kind() == io::ErrorKind::NotFound => {}
                Ok(_) => return Err(error),
                Err(source) => return Err(source),
            }
        }
        Err(source) => return Err(source),
    }

    bind_listener(path)
}

/// Remove only a socket that remains unserved at the final check.
fn remove_stale_socket(path: &Path, initial_error: io::Error) -> io::Result<()> {
    if !path_is_socket(path, initial_error)? {
        return Ok(());
    }

    match UnixStream::connect(path) {
        Ok(_) => Err(io::Error::from(io::ErrorKind::AddrInUse)),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            if !path_is_socket(path, error)? {
                return Ok(());
            }
            // Cutover ordering serializes a competing predecessor restart.
            // This recheck narrows, but cannot eliminate, the final syscall
            // race before remove_file.
            match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(source),
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(source),
    }
}

/// Return false only when the path disappeared; all non-socket entries keep
/// their original connection error rather than being treated as stale.
fn path_is_socket(path: &Path, original_error: io::Error) -> io::Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => Ok(true),
        Ok(_) => Err(original_error),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(source),
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
