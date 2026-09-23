use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::config::Config;

mod lease;
mod listener;
mod relay;

pub use lease::Leases;
use lease::Refresh;
use listener::{bind_polling, spawn_accept_loop};

const REAPER_INTERVAL: Duration = Duration::from_millis(100);
/// Generous liveness bound for idle reads and blocked writes during a callback.
const PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
pub const MAX_DYNAMIC_FORWARDS: usize = 4;
/// URL receiver port, named by the `forward-daemon.service` user unit.
pub const CHANNEL_PORT: u16 = 12_800;
/// File-preview port, named by the `forward.service` user unit.
pub const FILES_PORT: u16 = 12_802;
/// Laptop-loopback port where `omp browser-relay` listens; the browser
/// channel's constant upstream (the relay's own default).
pub const RELAY_TARGET_PORT: u16 = 9_224;

/// Every port the effective config assigns to a forward service, plus the
/// constant service ports. Derived from `Config`, never from the defaults: an
/// overridden port carries its protection with it. A value of 0 marks a
/// disabled service and reserves nothing (port 0 is separately never leased).
pub fn service_ports(cfg: &Config) -> [u16; 7] {
    [
        CHANNEL_PORT,
        FILES_PORT,
        cfg.bridge_port,
        cfg.relay_port,
        cfg.pcsc_port,
        cfg.grant_port,
        cfg.pulse_port,
    ]
}

/// Ports served by forward itself are never leased for callbacks.
pub fn is_dynamic_port(cfg: &Config, port: u16) -> bool {
    port != 0 && !service_ports(cfg).contains(&port)
}

/// One logical lease per callback port, however many listeners serve it.
pub fn request(cfg: &Config, leases: &Leases, port: u16) {
    let _ = request_on(cfg, leases, port);
}

/// Serve `port` on laptop loopback, relaying each connection to the devbox
/// bridge. Port `0` binds an ephemeral port and returns the number chosen.
pub fn request_on(cfg: &Config, leases: &Leases, port: u16) -> Option<u16> {
    serve_on(cfg, leases, port, Duration::from_secs(cfg.forward_ttl_secs))
        .map_err(|error| eprintln!("forward: {error}"))
        .ok()
}

/// Why a callback port is not being served.
///
/// Displayed without the `forward:` prefix its siblings carry: a caller either
/// prefixes it for the log, or puts it on the wire for the devbox to report.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    #[error("no literal peer address; not serving callback port {port}")]
    NoPeer { port: u16 },
    #[error("cannot serve callback port {port}: {source}")]
    Bind {
        port: u16,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot determine callback port: {source}")]
    Unnamed {
        #[source]
        source: std::io::Error,
    },
    #[error("could not start serving callback port {port}")]
    NotStarted { port: u16 },
}

/// Serve `port` for `ttl`, refreshing a lease already live. The error says why
/// the port is not served, for a caller that has to report it.
pub fn serve_on(
    cfg: &Config,
    leases: &Leases,
    port: u16,
    ttl: Duration,
) -> Result<u16, ServeError> {
    if port != 0 {
        match leases.refresh(port, ttl) {
            Refresh::Live => {
                eprintln!("forward: refreshed callback lease for port {port}");
                return Ok(port);
            }
            Refresh::Releasing => leases.wait_until_released(port),
            Refresh::Absent => {}
        }
    }
    // Fail closed before binding: a port we cannot relay is a port squatted on
    // some other tool for a whole TTL.
    let Ok(Some(peer)) = cfg.peer_ip() else {
        return Err(ServeError::NoPeer { port });
    };
    let bridge = SocketAddr::new(peer, cfg.bridge_port);
    let listener = bind_polling(Ipv4Addr::LOCALHOST.into(), port)
        .map_err(|source| ServeError::Bind { port, source })?;
    let bound = listener
        .local_addr()
        .map_err(|source| ServeError::Unnamed { source })?
        .port();
    let stop = Arc::new(AtomicBool::new(false));
    // Tolerated when IPv6 is unavailable: a host with IPv6 disabled must still
    // get callbacks, which is all `ssh -L 127.0.0.1:N` ever delivered. Not when
    // another process owns `[::1]:N`: a browser resolving `localhost` to IPv6
    // would reach that process, not the devbox.
    let ipv6_listener = match bind_polling(Ipv6Addr::LOCALHOST.into(), bound) {
        Ok(listener) => Some(listener),
        Err(source) if source.kind() == std::io::ErrorKind::AddrInUse => {
            return Err(ServeError::Bind {
                port: bound,
                source,
            });
        }
        Err(error) => {
            eprintln!("forward: callback port {bound} has no [::1] listener: {error}");
            None
        }
    };
    leases.insert(
        bound,
        ttl,
        Arc::clone(&stop),
        1 + usize::from(ipv6_listener.is_some()),
    );
    if !spawn_accept_loop(listener, bridge, bound, leases.clone(), Arc::clone(&stop)) {
        if let Some(listener) = ipv6_listener {
            drop(listener);
            if leases.release(bound, &stop) {
                eprintln!("forward: callback port {bound} released");
            }
        }
        return Err(ServeError::NotStarted { port: bound });
    }
    if let Some(listener) = ipv6_listener {
        let _ = spawn_accept_loop(listener, bridge, bound, leases.clone(), stop);
    }
    eprintln!("forward: callback port {bound} served on loopback");
    Ok(bound)
}

pub fn spawn_reaper(leases: Leases) {
    if let Err(error) = thread::Builder::new()
        .name("forward-reaper".to_owned())
        .spawn(move || {
            loop {
                thread::sleep(REAPER_INTERVAL);
                leases.expire();
            }
        })
    {
        eprintln!("forward: failed to start the callback reaper: {error}");
    }
}
