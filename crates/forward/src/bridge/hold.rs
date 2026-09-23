use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::holder::{BUSY, DIAL, HELD, UNSAFE, send_dialed, send_unreachable};

/// How long the bridge has to acknowledge a hold.
const HOLD_REPLY_TIMEOUT: Duration = Duration::from_secs(5);
/// Per address family, so both attempts fit inside the bridge's dial deadline.
const LOOPBACK_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, thiserror::Error)]
pub enum HoldError {
    #[error("forward: no local bridge at {}: {source}", path.display())]
    NoBridge {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(
        "forward: the bridge refused port {port}: it is privileged, reserved by forward, or unsafe to expose"
    )]
    Refused { port: u16 },
    #[error(
        "forward: the local bridge at {} did not answer a hold; it predates `forward port`, so \
         upgrade forward on the devbox and restart its `forward serve`",
        path.display()
    )]
    Unanswered { path: PathBuf },
    #[error("forward: port {port} is already held by another process on this devbox")]
    Busy { port: u16 },
    #[error("forward: the bridge ended the hold on port {port}: {source}")]
    Ended {
        port: u16,
        #[source]
        source: std::io::Error,
    },
    #[error("forward: the bridge sent {request:?} on the hold for port {port}, not a dial")]
    Unexpected { port: u16, request: String },
    #[error("forward: hold on port {port} failed: {source}")]
    Io {
        port: u16,
        #[source]
        source: std::io::Error,
    },
}

/// One port held on the local bridge, dialled from this process's own loopback.
#[derive(Debug)]
pub struct Held {
    control: UnixStream,
    port: u16,
}

/// Hold `port` on the bridge whose arming socket is `path`.
///
/// While the returned hold is served, a laptop connection to `localhost:<port>`
/// reaches `127.0.0.1:<port>` (or `[::1]:<port>`) as this process sees it, so a
/// hold made inside an agent box reaches that box's loopback, not the host's.
pub fn hold(path: &Path, port: u16) -> Result<Held, HoldError> {
    let io = |source| HoldError::Io { port, source };
    let mut control = UnixStream::connect(path).map_err(|source| HoldError::NoBridge {
        path: path.to_path_buf(),
        source,
    })?;
    control
        .set_read_timeout(Some(HOLD_REPLY_TIMEOUT))
        .map_err(io)?;
    writeln!(control, "HOLD {port}").map_err(io)?;
    // `ok\n` is the shortest reply; the refusals are told apart by their first
    // bytes, and the connection is dropped either way. Silence means a bridge
    // from before holds, which closes on a request it cannot parse.
    let unanswered = || HoldError::Unanswered {
        path: path.to_path_buf(),
    };
    let mut reply = [0_u8; HELD.len()];
    match control.read_exact(&mut reply) {
        Ok(()) if &reply == HELD => {}
        Ok(()) if BUSY.starts_with(&reply) => return Err(HoldError::Busy { port }),
        Ok(()) if UNSAFE.starts_with(&reply) => return Err(HoldError::Refused { port }),
        Ok(()) => return Err(unanswered()),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(unanswered());
        }
        Err(source) => return Err(io(source)),
    }
    control.set_read_timeout(None).map_err(io)?;
    control
        .set_write_timeout(Some(HOLD_REPLY_TIMEOUT))
        .map_err(io)?;
    Ok(Held { control, port })
}

impl Held {
    /// The port this hold keeps reachable.
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Answer the bridge's dials until it ends the hold. Blocks; the hold ends
    /// for the bridge the moment this process exits.
    pub fn serve(self) -> HoldError {
        let port = self.port;
        let mut request = [0_u8; DIAL.len()];
        loop {
            if let Err(source) = (&self.control).read_exact(&mut request) {
                return HoldError::Ended { port, source };
            }
            if &request != DIAL {
                return HoldError::Unexpected {
                    port,
                    request: String::from_utf8_lossy(&request).into_owned(),
                };
            }
            let answered = match connect_loopback(port) {
                Ok(socket) => send_dialed(&self.control, &socket),
                Err(error) => {
                    eprintln!(
                        "forward: a laptop connection for port {port} found nothing listening on \
                         127.0.0.1:{port} or [::1]:{port} here: {error}"
                    );
                    send_unreachable(&self.control)
                }
            };
            if let Err(source) = answered {
                return HoldError::Io { port, source };
            }
        }
    }
}

/// Dev servers bind either family, so try IPv4 loopback and then IPv6.
fn connect_loopback(port: u16) -> std::io::Result<TcpStream> {
    let v4 = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let v6 = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&v4, LOOPBACK_CONNECT_TIMEOUT).or_else(|v4_error| {
        TcpStream::connect_timeout(&v6, LOOPBACK_CONNECT_TIMEOUT).map_err(|_| v4_error)
    })
}
