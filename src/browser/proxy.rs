use crate::bridge::limit::ConnectionLimit;
use crate::browser::grant::{Grant, Grants, ProcessAnchor};
use crate::config::Config;
use crate::pipe::bidirectional;
use crate::refusal::refuse;
use std::io::Write as _;
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);
const GENERIC_REFUSAL: &[u8] = b"REFUSED\n";
const BUSY_REFUSAL: &[u8] = b"REFUSED BUSY\n";
const UNGRANTED_REFUSAL: &[u8] = b"REFUSED UNGRANTED\n";
const SESSION_REFUSAL: &[u8] = b"REFUSED SESSION\n";

/// Resolve a loopback connection to its owning process. Injectable so tests can
/// exercise the proxy without depending on kernel TCP-table timing.
pub type Resolver = Arc<dyn Fn(SocketAddrV4, SocketAddrV4) -> Option<u32> + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("failed to bind a grant port: {source}")]
    Bind {
        #[source]
        source: std::io::Error,
    },
}

/// A loopback listener that has been bound but is not yet accepting clients.
///
/// Callers must record their grant and arm its reaper before calling [`serve`],
/// preventing an early connection from retiring an ungranted listener.
pub struct BoundProxy {
    grants: Grants,
    listener: TcpListener,
    port: u16,
    upstream: SocketAddr,
}

impl BoundProxy {
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn serve(self) {
        spawn_with_listener(
            self.grants,
            self.listener,
            self.upstream,
            Arc::new(crate::browser::peer::pid_for_connection),
        );
    }
}

/// Bind a fresh loopback endpoint without accepting a connection yet.
///
/// The Task 6 request handler has the configuration at its callsite and derives
/// the laptop relay address before calling this function. The endpoint is always
/// loopback, so no configuration value changes this bind.
pub fn bind(_cfg: &Config, grants: Grants, upstream: SocketAddr) -> Result<BoundProxy, ProxyError> {
    let listener =
        TcpListener::bind("127.0.0.1:0").map_err(|source| ProxyError::Bind { source })?;
    let port = listener
        .local_addr()
        .map_err(|source| ProxyError::Bind { source })?
        .port();
    Ok(BoundProxy {
        grants,
        listener,
        port,
        upstream,
    })
}

/// Expire `port` at `deadline`, then wake its accept loop so the listener
/// closes even when no client ever connects.
pub fn reap_at(grants: Grants, port: u16, deadline: Instant) {
    drop(thread::spawn(move || {
        thread::sleep(deadline.saturating_duration_since(Instant::now()));
        grants.expire(port);
        drop(TcpStream::connect(("127.0.0.1", port)));
    }));
}

/// Test seam: start accepting on a listener the caller already bound.
#[doc(hidden)]
pub fn spawn_with_listener(
    grants: Grants,
    listener: TcpListener,
    upstream: SocketAddr,
    resolver: Resolver,
) {
    drop(thread::spawn(move || {
        accept_loop(grants, listener, upstream, resolver)
    }));
}

fn accept_loop(grants: Grants, listener: TcpListener, upstream: SocketAddr, resolver: Resolver) {
    let limit = ConnectionLimit::standard();
    let Ok(port) = listener.local_addr().map(|address| address.port()) else {
        eprintln!("forward: grant proxy could not determine its listener port");
        return;
    };

    for connection in listener.incoming() {
        match connection {
            Ok(mut stream) => {
                let Some(grant) = grants.live(port) else {
                    refuse(&mut stream, UNGRANTED_REFUSAL);
                    return;
                };
                let Some(permit) = limit.acquire() else {
                    refuse(&mut stream, BUSY_REFUSAL);
                    continue;
                };
                let resolver = Arc::clone(&resolver);
                drop(thread::spawn(move || {
                    let _permit = permit;
                    handle(grant, port, upstream, &resolver, stream);
                }));
            }
            Err(error) => {
                eprintln!("forward: grant proxy accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

fn handle(
    grant: Grant,
    port: u16,
    upstream: SocketAddr,
    resolver: &Resolver,
    mut stream: TcpStream,
) {
    let (Ok(SocketAddr::V4(peer)), Ok(SocketAddr::V4(local))) =
        (stream.peer_addr(), stream.local_addr())
    else {
        refuse(&mut stream, SESSION_REFUSAL);
        return;
    };
    if !owns_grant(resolver, peer, local, grant.anchor) {
        eprintln!("forward: grant proxy refused a connection outside its process anchor");
        refuse(&mut stream, SESSION_REFUSAL);
        return;
    }

    let Ok(mut laptop) = TcpStream::connect(upstream) else {
        refuse(&mut stream, GENERIC_REFUSAL);
        return;
    };
    if laptop
        .write_all(b"RELAY ")
        .and_then(|()| laptop.write_all(&grant.token))
        .and_then(|()| laptop.write_all(b"\n"))
        .is_err()
    {
        refuse(&mut stream, GENERIC_REFUSAL);
        return;
    }
    for socket in [&stream, &laptop] {
        if socket.set_read_timeout(Some(PIPE_IDLE_TIMEOUT)).is_err()
            || socket.set_write_timeout(Some(PIPE_IDLE_TIMEOUT)).is_err()
        {
            return;
        }
    }
    if let Err(error) = bidirectional(stream, laptop) {
        eprintln!("forward: grant proxy session on {port} ended: {error}");
    }
}

fn owns_grant(
    resolver: &Resolver,
    peer: SocketAddrV4,
    local: SocketAddrV4,
    anchor: ProcessAnchor,
) -> bool {
    resolver(peer, local).is_some_and(|pid| {
        crate::browser::peer::ancestry_contains(pid, anchor.pid, anchor.start_time)
    })
}
