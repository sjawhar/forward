mod client;

pub use client::{GrantStatus, parse_status, parse_ttl, request, status};

use crate::browser::grant::{Grant, Grants, ProcessAnchor};
use crate::browser::peer::{grant_anchor_for_pid, session_for_pid};
use crate::browser::proxy;
use crate::config::Config;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

/// `GRANT 43200 ` plus a 43-character token is well under this.
const MAX_REQUEST_LINE: u64 = 128;
const LONGEST_TTL: Duration = Duration::from_secs(12 * 60 * 60);
/// A request is one short line, and the serve loop is serial, so a stalled
/// client must not be able to pin it.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Resolve a pid to its omp session. Injectable so a test can observe the pid
/// `SO_PEERCRED` produced without running inside a real session.
pub type SessionResolver = Arc<dyn Fn(u32) -> Option<String> + Send + Sync>;

/// Where `forward browser grant` reaches the local daemon.
///
/// A unix socket, never a TCP port: `SO_PEERCRED` identifies the caller and
/// its kernel-maintained parent chain binds a grant to the enclosing session.
pub fn socket_path() -> PathBuf {
    crate::bridge::arm_socket_path().with_file_name("forward-browser-grant.sock")
}

/// Parse a `GRANT <ttl_secs> <token>` request body.
pub fn parse(line: &[u8]) -> Option<(u64, Vec<u8>)> {
    let text = std::str::from_utf8(line).ok()?.strip_prefix("GRANT ")?;
    let (ttl, token) = text.split_once(' ')?;
    let ttl: u64 = ttl.parse().ok()?;
    if ttl == 0 || ttl > LONGEST_TTL.as_secs() || token.is_empty() || token.contains(' ') {
        return None;
    }
    Some((ttl, token.as_bytes().to_vec()))
}

/// Serve grant requests for the life of the process.
///
/// Serial on purpose: a grant is a rare, human-gated event, every request is
/// one line under a read deadline, and serialising removes any window where
/// two requests race the registry.
pub fn serve(grants: Grants, cfg: Config, path: PathBuf) {
    serve_with_resolver(grants, cfg, path, Arc::new(session_for_pid));
}

/// Test seam: serve with an injected pid-to-session resolver.
#[doc(hidden)]
pub fn serve_with_resolver(grants: Grants, cfg: Config, path: PathBuf, resolver: SessionResolver) {
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
            Ok(stream) => handle(&grants, upstream, &resolver, stream),
            Err(error) => {
                eprintln!("forward: grant request accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn handle(
    grants: &Grants,
    upstream: Option<SocketAddr>,
    resolver: &SessionResolver,
    mut stream: UnixStream,
) {
    if stream.set_read_timeout(Some(REQUEST_TIMEOUT)).is_err()
        || stream.set_write_timeout(Some(REQUEST_TIMEOUT)).is_err()
    {
        return;
    }
    let Some(pid) = peer_pid(&stream) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let anchor =
        grant_anchor_for_pid(pid).map(|(pid, start_time)| ProcessAnchor { pid, start_time });
    let Some(line) = read_line(&stream) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    if line == b"STATUS" {
        answer_status(grants, anchor, stream);
        return;
    }
    let Some((ttl, token)) = parse(&line) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let session = resolver(pid);
    let Some(session) = session else {
        eprintln!("forward: grant refused: pid {pid} is not inside an omp session");
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let Some(anchor) = anchor else {
        eprintln!("forward: grant refused: could not anchor requesting pid {pid}");
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let Some(upstream) = upstream else {
        eprintln!("forward: grant refused: no peer configured to relay to");
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let Ok(proxy) = proxy::bind(grants.clone(), upstream) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let port = proxy.port();
    let deadline = Instant::now() + Duration::from_secs(ttl);
    grants.insert(
        port,
        Grant {
            session: session.clone(),
            anchor,
            token,
            deadline,
        },
    );
    proxy::reap_at(grants.clone(), port, deadline);
    proxy.serve();
    eprintln!(
        "forward: granted browser access to session {session} on 127.0.0.1:{port} for {ttl}s"
    );
    let _ = writeln!(stream, "{port}");
}

fn read_line(stream: &UnixStream) -> Option<Vec<u8>> {
    let mut line = Vec::new();
    let mut reader = BufReader::new(stream.try_clone().ok()?).take(MAX_REQUEST_LINE);
    reader.read_until(b'\n', &mut line).ok()?;
    while line
        .last()
        .is_some_and(|byte| *byte == b'\n' || *byte == b'\r')
    {
        line.pop();
    }
    Some(line)
}

fn answer_status(grants: &Grants, caller: Option<ProcessAnchor>, mut stream: UnixStream) {
    let reply = caller
        .and_then(|caller| grants.live_for_descendant(caller))
        .map(|(port, grant)| {
            let remaining_secs = grant
                .deadline
                .saturating_duration_since(Instant::now())
                .as_secs();
            format!("LIVE {port} {remaining_secs}\n")
        })
        .unwrap_or_else(|| "NONE\n".to_owned());
    let _ = stream.write_all(reply.as_bytes());
}

/// The caller's pid from `SO_PEERCRED` — exact, with no lookup and no race.
fn peer_pid(stream: &UnixStream) -> Option<u32> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials).ok()?;
    u32::try_from(credentials.pid()).ok()
}
