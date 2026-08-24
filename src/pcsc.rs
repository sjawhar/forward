//! The PC/SC channel: raw pcscd bytes between the laptop's pcscd and the
//! devbox's `~/.pcscd/pcscd.comm`, replacing the SSH RemoteForward + socat
//! bridge with listeners both ends' `Restart=always` daemons own.
//!
//! There is no protocol here to parse and none to speak: pcscd frames are
//! opaque, so a refusal is a bare close. Writing `REFUSED ...` bytes would be
//! injected into a real client's protocol stream.

pub mod laptop;

use std::time::Duration;

/// Dialing a slept or unreachable machine must fail loud and fast, matching
/// the connection-refused behaviour clients saw when the old tunnel was down.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

#[derive(Debug, thiserror::Error)]
pub enum PcscError {
    #[error("forward: failed to bind pcsc channel on {address}: {source}")]
    Bind {
        address: String,
        #[source]
        source: std::io::Error,
    },
    #[error("forward: failed to start pcsc channel accept loop: {source}")]
    Spawn {
        #[source]
        source: std::io::Error,
    },
    #[error("forward: failed to serve pcsc socket {path}: {source}")]
    Socket {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("forward: cannot resolve the pcsc socket path: HOME is unset or not absolute")]
    Home,
}
