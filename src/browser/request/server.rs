use std::io::Write as _;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::line;
use crate::browser::grant::{Grant, Grants, ProcessAnchor};
use crate::browser::peer::{grant_anchor_for_pid, session_for_pid};
use crate::browser::proxy;
use crate::config::Config;
const LONGEST_TTL: Duration = Duration::from_secs(12 * 60 * 60);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
pub type SessionResolver = Arc<dyn Fn(u32) -> Option<String> + Send + Sync>;
pub type Redeemer = Arc<dyn Fn(&[u8]) -> Result<(), crate::secretsd::BrokerError> + Send + Sync>;
#[doc(hidden)]
pub type Binder =
    Arc<dyn Fn(Grants, SocketAddr) -> Result<proxy::BoundProxy, proxy::ProxyError> + Send + Sync>;
pub fn socket_path() -> PathBuf {
    crate::bridge::arm_socket_path().with_file_name("forward-browser-grant.sock")
}

pub fn parse(line: &[u8]) -> Option<(u64, Vec<u8>)> {
    let text = std::str::from_utf8(line).ok()?.strip_prefix("GRANT ")?;
    let (ttl, receipt) = text.split_once(' ')?;
    let ttl: u64 = ttl.parse().ok()?;
    if ttl == 0
        || ttl > LONGEST_TTL.as_secs()
        || receipt.len() != 64
        || !receipt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some((ttl, receipt.as_bytes().to_vec()))
}

pub fn serve(grants: Grants, cfg: Config, path: PathBuf, slot: crate::browser::push::FeedSlot) {
    let socket = crate::secretsd::socket_path();
    serve_with(
        grants,
        cfg,
        path,
        slot,
        Arc::new(session_for_pid),
        Arc::new(move |receipt: &[u8]| {
            crate::secretsd::redeem(&socket, receipt, crate::secretsd::CAP_BROWSER)
        }),
    );
}

#[doc(hidden)]
pub fn serve_with(
    grants: Grants,
    cfg: Config,
    path: PathBuf,
    slot: crate::browser::push::FeedSlot,
    resolver: SessionResolver,
    redeemer: Redeemer,
) {
    serve_with_binder(
        grants,
        cfg,
        path,
        slot,
        resolver,
        redeemer,
        Arc::new(proxy::bind),
    );
}

#[doc(hidden)]
pub fn serve_with_binder(
    grants: Grants,
    cfg: Config,
    path: PathBuf,
    slot: crate::browser::push::FeedSlot,
    resolver: SessionResolver,
    redeemer: Redeemer,
    binder: Binder,
) {
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
            Ok(stream) => handle(
                &grants, upstream, &slot, &resolver, &redeemer, &binder, stream,
            ),
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
    slot: &crate::browser::push::FeedSlot,
    resolver: &SessionResolver,
    redeemer: &Redeemer,
    binder: &Binder,
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
    let Some(line) = line::read_line(&stream, REQUEST_TIMEOUT) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    if line.as_slice() == b"STATUS" {
        answer_status(grants, anchor, stream);
        return;
    }
    let Some((ttl, receipt)) = parse(line.as_slice()) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let receipt = Zeroizing::new(receipt);
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
    if let Err(error) = redeemer(receipt.as_slice()) {
        eprintln!("forward: grant refused: receipt not redeemed: {error}");
        let _ = stream.write_all(b"REFUSED RECEIPT\n");
        return;
    }
    let Ok(token) = crate::browser::push::mint_token() else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    let Ok(proxy) = binder(grants.clone(), upstream) else {
        let _ = stream.write_all(b"REFUSED\n");
        return;
    };
    if !slot.push(&token, ttl) {
        eprintln!("forward: grant refused: laptop feed unavailable");
        let _ = stream.write_all(b"REFUSED LAPTOP\n");
        return;
    }
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

fn answer_status(grants: &Grants, caller: Option<ProcessAnchor>, mut stream: UnixStream) {
    let reply = caller
        .and_then(|caller| grants.live_for_descendant(caller))
        .map(|(port, grant)| {
            format!(
                "LIVE {port} {}\n",
                grant
                    .deadline
                    .saturating_duration_since(Instant::now())
                    .as_secs()
            )
        })
        .unwrap_or_else(|| "NONE\n".to_owned());
    let _ = stream.write_all(reply.as_bytes());
}

fn peer_pid(stream: &UnixStream) -> Option<u32> {
    let credentials =
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials).ok()?;
    u32::try_from(credentials.pid()).ok()
}
