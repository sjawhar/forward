//! Transport client for the broker's versioned Unix-socket protocol.
//!
//! Shared by the `secrets` CLI and by forward. It is deliberately free of CLI
//! concerns -- no argv, no stdout, no process exec -- because forward's daemon
//! calls it from inside an accept loop. Presentation stays with each caller:
//! the CLI maps these errors to its exit codes and messages, forward maps them
//! to its own refusal strings.

use std::io::{IsTerminal, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroize as _;

use crate::response::{BrokerResponse, ClientError};
use crate::{MAX_FRAME_BYTES, PROTOCOL_VERSION};

/// How long to wait on a verb that blocks for a human decision.
///
/// The broker's own approval window is 90s; this covers it plus queueing
/// behind another session's touch. Both callers need it: the CLI's GET and
/// REQUEST, and forward's AUTHORIZE. Keying the timeout off the verb is what
/// stops an AUTHORIZE from inheriting the 5s control timeout and failing
/// mid-ceremony.
const APPROVAL_TIMEOUT: Duration = Duration::from_secs(120);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

/// Verbs that block on a human decision rather than returning immediately.
const APPROVAL_VERBS: [&str; 3] = ["GET\t", "REQUEST\t", "AUTHORIZE\t"];

/// A lazily resolved path to the broker's Unix socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketPath(PathBuf);

impl SocketPath {
    /// Resolve a broker socket override, runtime-directory path, or per-user fallback.
    pub fn resolve(override_path: Option<&str>, runtime_dir: Option<&str>, uid: u32) -> Self {
        match (override_path, runtime_dir) {
            (Some(path), _) => Self(PathBuf::from(path)),
            (None, Some(directory)) if !directory.is_empty() => {
                Self(Path::new(directory).join("secretsd.sock"))
            }
            (None, Some(_) | None) => Self(PathBuf::from(format!("/run/user/{uid}/secretsd.sock"))),
        }
    }

    /// Borrow the resolved socket path.
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// Resolve the runtime directory shared by the broker socket and edit temps.
pub fn runtime_dir() -> PathBuf {
    std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|directory| !directory.is_empty())
        .map_or_else(
            || PathBuf::from(format!("/run/user/{}", nix::unistd::getuid())),
            PathBuf::from,
        )
}

impl AsRef<Path> for SocketPath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

/// Typed client for the broker's versioned Unix-socket protocol.
#[derive(Debug, Clone)]
pub struct BrokerClient {
    socket_path: PathBuf,
    get_timeout: Duration,
    control_timeout: Duration,
}

impl BrokerClient {
    /// Build a client connected to `socket_path` on demand.
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self::with_timeouts(socket_path, APPROVAL_TIMEOUT, CONTROL_TIMEOUT)
    }

    #[doc(hidden)]
    pub fn with_timeouts(
        socket_path: impl AsRef<Path>,
        get_timeout: Duration,
        control_timeout: Duration,
    ) -> Self {
        Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            get_timeout,
            control_timeout,
        }
    }

    #[doc(hidden)]
    pub fn with_test_timeouts(
        socket_path: impl AsRef<Path>,
        get_timeout: Duration,
        control_timeout: Duration,
    ) -> Self {
        Self::with_timeouts(socket_path, get_timeout, control_timeout)
    }

    /// Resolve the broker socket only when a broker operation is requested.
    pub fn from_environment() -> Self {
        let socket_override = std::env::var("SECRETSD_SOCK").ok();
        let runtime_directory = std::env::var("XDG_RUNTIME_DIR").ok();
        let socket_path = SocketPath::resolve(
            socket_override.as_deref(),
            runtime_directory.as_deref(),
            nix::unistd::getuid().as_raw(),
        );
        Self::new(socket_path)
    }

    /// Verify that the connected broker speaks exactly this protocol version.
    pub fn hello(&self) -> Result<(), ClientError> {
        let version = PROTOCOL_VERSION.to_string();
        let request = format!("HELLO\tversion={version}");
        let BrokerResponse::Fields(fields) = self.request(&request)? else {
            return Err(ClientError::VersionHandshake);
        };
        // Fields this client does not consume are tolerated -- the daemon also
        // reports its instance id, which only a registering harness needs -- but
        // a missing or differing version must fail rather than degrade.
        if fields
            .split(' ')
            .any(|field| field.strip_prefix("version=") == Some(version.as_str()))
        {
            Ok(())
        } else {
            Err(ClientError::VersionHandshake)
        }
    }

    /// Complete a version handshake, then send one request and parse its typed response.
    pub fn call(&self, request: &str) -> Result<BrokerResponse, ClientError> {
        self.hello()?;
        self.request(request)
    }

    /// Send one request on a fresh connection, without a version handshake.
    ///
    /// [`BrokerClient::call`] is the usual entry point; this is for a caller
    /// that has already handshaked, or that is sending `HELLO` itself.
    pub fn request(&self, request: &str) -> Result<BrokerResponse, ClientError> {
        let mut stream = UnixStream::connect(&self.socket_path).map_err(ClientError::Io)?;
        let waits_for_approval = APPROVAL_VERBS.iter().any(|verb| request.starts_with(verb));
        let timeout = if waits_for_approval {
            self.get_timeout
        } else {
            self.control_timeout
        };
        stream
            .set_read_timeout(Some(timeout))
            .map_err(ClientError::Io)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(ClientError::Io)?;
        write_request(&mut stream, request)?;
        // The deadline covers the whole reply, not each read of it.
        let deadline = std::time::Instant::now().checked_add(timeout);
        match crate::response::read_response_by(stream, deadline) {
            Err(ClientError::Io(error))
                if waits_for_approval
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
            {
                Err(ClientError::ApprovalTimeout)
            }
            other => other,
        }
    }
}

fn write_request(stream: &mut UnixStream, request: &str) -> Result<(), ClientError> {
    let request_is_valid = !request.is_empty()
        && request.len() <= MAX_FRAME_BYTES
        && request.is_ascii()
        && !request.contains(['\n', '\r', '\0']);
    if !request_is_valid {
        return Err(ClientError::InvalidRequest);
    }
    stream
        .write_all(request.as_bytes())
        .map_err(ClientError::Io)?;
    stream.write_all(b"\n").map_err(ClientError::Io)
}

/// Read a session token from an inherited token file without exposing its bytes in errors.
pub fn read_token_file(path: impl AsRef<Path>) -> Result<String, ClientError> {
    let mut bytes = std::fs::read(path).map_err(|_| ClientError::TokenFile)?;
    let token = std::str::from_utf8(&bytes)
        .ok()
        .filter(|value| !value.is_empty() && value.trim() == *value)
        .map(ToOwned::to_owned)
        .ok_or(ClientError::TokenFile);
    bytes.zeroize();
    token
}

/// Return the caller's terminal path when standard input is an interactive Unix terminal.
pub fn caller_tty() -> Option<String> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    let path = std::fs::read_link("/proc/self/fd/0").ok()?;
    let text = path.into_os_string().into_string().ok()?;
    text.starts_with("/dev/").then_some(text)
}
