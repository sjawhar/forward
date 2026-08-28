//! The pulse channel: raw PulseAudio native-protocol bytes between the
//! devbox's `$XDG_RUNTIME_DIR/forward/pulse.sock` and the laptop's
//! pipewire-pulse, with listeners both ends' `Restart=always` daemons own.
//!
//! There is no protocol here to parse and none to speak: native-protocol
//! frames are opaque, so a refusal is a bare close. Writing `REFUSED ...`
//! bytes would be injected into a real client's protocol stream.

pub mod devbox;
pub mod laptop;

use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

/// Dialing a slept or unreachable machine must fail loud and fast, matching
/// the connection-refused behaviour clients saw when the old tunnel was down.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub(crate) const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Tune a TCP leg for interactive audio: the shared keepalive (a dead peer is
/// found in about two minutes, with no idle timeout on a legitimately quiet
/// stream) plus `TCP_NODELAY`, because the native protocol is a chatty
/// request/reply exchange during stream setup and a steady sequence of small
/// writes during playback and capture, and Nagle coupling either to the
/// round-trip time adds avoidable latency.
pub(crate) fn tune(stream: &TcpStream) -> std::io::Result<()> {
    crate::pipe::keepalive(stream)?;
    stream.set_nodelay(true)
}

/// `$XDG_RUNTIME_DIR`, required absolute; both fixed socket paths hang off it.
fn runtime_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
}

#[derive(Debug, thiserror::Error)]
pub enum PulseError {
    #[error("forward: failed to bind pulse channel on {address}: {source}")]
    Bind {
        address: String,
        #[source]
        source: std::io::Error,
    },
    #[error("forward: failed to start pulse channel accept loop: {source}")]
    Spawn {
        #[source]
        source: std::io::Error,
    },
    #[error("forward: failed to serve pulse socket {path}: {source}")]
    Socket {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "forward: cannot resolve a pulse socket path: XDG_RUNTIME_DIR is unset or not absolute"
    )]
    RuntimeDir,
}

#[cfg(test)]
mod tests {
    use std::net::{TcpListener, TcpStream};

    use super::tune;

    #[test]
    fn tune_enables_nodelay_and_keepalive() {
        // Given: an accepted TCP stream with platform defaults.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        assert!(!accepted.nodelay().unwrap());

        // When: the channel tunes its leg.
        tune(&accepted).unwrap();

        // Then: Nagle is off and keepalive probing is armed.
        assert!(accepted.nodelay().unwrap());
        let keepalive =
            nix::sys::socket::getsockopt(&accepted, nix::sys::socket::sockopt::KeepAlive).unwrap();
        assert!(keepalive);
        drop(client);
    }
}
