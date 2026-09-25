use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

mod answers;
mod ceremony;
mod control;

use answers::{answer_probe, answer_status, peer_pid};
#[doc(hidden)]
pub use control::serve as serve_control;

use super::line;
use crate::browser::LONGEST_TTL;
use crate::browser::grant::Grants;
use crate::browser::peer::{anchor_for, session_label};
use crate::config::Config;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
pub type SessionResolver = Arc<dyn Fn(u32) -> Option<String> + Send + Sync>;
pub type Redeemer = Arc<
    dyn Fn(&[u8]) -> Result<crate::secretsd::RedeemedGrant, crate::secretsd::BrokerError>
        + Send
        + Sync,
>;
pub type IdentityReader = Arc<
    dyn Fn() -> Result<crate::secretsd::BrokerIdentity, crate::secretsd::BrokerError> + Send + Sync,
>;

/// The collaborators the grant request server threads through every request.
///
/// Bundled rather than passed individually: they are one stable dependency
/// set, every one of them is needed on the grant path, and the alternative is
/// an eight-parameter signature that grows again with each new authority check.
pub struct Deps {
    pub grants: Grants,
    pub slot: crate::browser::push::FeedSlot,
    pub resolver: SessionResolver,
    pub redeemer: Redeemer,
    pub identity_reader: IdentityReader,
}
pub fn socket_path() -> PathBuf {
    crate::bridge::arm_socket_path().with_file_name("browser-grant.sock")
}

/// Parse `GRANT <ttl> <receipt> <port>`.
///
/// The port is the caller's own loopback endpoint, which it has already bound.
/// It is reported back by `STATUS` and named in log lines; it authorizes
/// nothing, because a port number means nothing outside the namespace it was
/// bound in.
pub fn parse(line: &[u8]) -> Option<(u64, Vec<u8>, u16)> {
    let text = std::str::from_utf8(line).ok()?.strip_prefix("GRANT ")?;
    let mut fields = text.split(' ');
    let (ttl, receipt, port) = (fields.next()?, fields.next()?, fields.next()?);
    if fields.next().is_some() {
        return None;
    }
    let ttl: u64 = ttl.parse().ok()?;
    let port: u16 = port.parse().ok()?;
    if ttl == 0
        || ttl > LONGEST_TTL.as_secs()
        || port == 0
        || receipt.len() != 64
        || !receipt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some((ttl, receipt.as_bytes().to_vec(), port))
}

pub fn serve(grants: Grants, cfg: Config, path: PathBuf, slot: crate::browser::push::FeedSlot) {
    let socket = crate::secretsd::socket_path();
    let redeem_socket = socket.clone();
    serve_with_deps(
        Deps {
            grants,
            slot,
            resolver: Arc::new(session_label),
            redeemer: Arc::new(move |receipt: &[u8]| {
                crate::secretsd::redeem(&redeem_socket, receipt, crate::secretsd::CAP_BROWSER)
            }),
            identity_reader: Arc::new(move || crate::secretsd::broker_identity(&socket)),
        },
        cfg,
        path,
    );
}

#[doc(hidden)]
pub fn serve_with_deps(deps: Deps, cfg: Config, path: PathBuf) {
    if let Err(error) = crate::socket::prepare_private_parent(&path) {
        eprintln!(
            "forward: could not prepare the directory of grant socket {}: {error}",
            path.display()
        );
        return;
    }
    let _ = std::fs::remove_file(&path);
    let Ok(listener) = UnixListener::bind(&path) else {
        eprintln!("forward: could not bind grant socket {}", path.display());
        return;
    };
    if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!(
            "forward: could not restrict grant socket {}: {error}",
            path.display()
        );
        let _ = std::fs::remove_file(&path);
        return;
    }
    let upstream = cfg
        .peer_ip()
        .ok()
        .flatten()
        .map(|ip| SocketAddr::new(ip, cfg.relay_port));
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => handle(&deps, upstream, stream),
            Err(error) => {
                eprintln!("forward: grant request accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

/// Answer one request. `STATUS` and `PROBE` are answered and closed here; a
/// granted `GRANT` keeps its connection as the grant's control channel and
/// leaves it to a thread of its own, so one live grant cannot stop this loop
/// from serving every other request.
fn handle(deps: &Deps, upstream: Option<SocketAddr>, mut stream: UnixStream) {
    if stream.set_read_timeout(Some(REQUEST_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(REQUEST_TIMEOUT)).is_err()
    {
        return;
    }
    let Some(pid) = peer_pid(&stream) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let anchor = anchor_for(pid);
    let Some(line) = line::read_line(&stream, REQUEST_TIMEOUT) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    if line.as_slice() == b"STATUS" {
        answer_status(&deps.grants, anchor, stream);
        return;
    }
    if line.as_slice() == b"PROBE" {
        answer_probe(pid, anchor, upstream, stream);
        return;
    }
    let Some(request) = parse(line.as_slice()) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    ceremony::answer(deps, upstream, (pid, anchor), request, stream);
}
