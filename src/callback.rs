use crate::config::Config;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

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
/// Devbox endpoint of the laptop hardware-token tunnel.
pub const PCSC_PORT: u16 = 12_799;
/// URL receiver port, named by the `forward-daemon.service` user unit.
pub const CHANNEL_PORT: u16 = 12_800;
/// File-preview port, named by the `forward.service` user unit.
pub const FILES_PORT: u16 = 12_802;
const STATIC_TUNNEL_PORTS: [u16; 3] = [PCSC_PORT, CHANNEL_PORT, FILES_PORT];

/// Ports carried by the SSH tunnel or served by forward itself, never leased.
pub fn is_dynamic_port(port: u16) -> bool {
    !STATIC_TUNNEL_PORTS.contains(&port)
}

/// One logical lease per callback port, however many listeners serve it.
pub fn request(cfg: &Config, leases: &Leases, port: u16) {
    let _ = request_on(cfg, leases, port);
}

/// Serve `port` on laptop loopback, relaying each connection to the devbox
/// bridge. Port `0` binds an ephemeral port and returns the number chosen.
pub fn request_on(cfg: &Config, leases: &Leases, port: u16) -> Option<u16> {
    let ttl = Duration::from_secs(cfg.forward_ttl_secs);
    if port != 0 {
        match leases.refresh(port, ttl) {
            Refresh::Live => {
                eprintln!("forward: refreshed callback lease for port {port}");
                return Some(port);
            }
            Refresh::Releasing => leases.wait_until_released(port),
            Refresh::Absent => {}
        }
    }
    // Fail closed before binding: a port we cannot relay is a port squatted on
    // some other tool for a whole TTL.
    let Ok(Some(peer)) = cfg.peer_ip() else {
        eprintln!("forward: no literal peer address; not serving callback port {port}");
        return None;
    };
    let bridge = SocketAddr::new(peer, cfg.bridge_port);
    let listener = match bind_polling(Ipv4Addr::LOCALHOST.into(), port) {
        Ok(listener) => listener,
        Err(error) => {
            eprintln!("forward: cannot serve callback port {port}: {error}");
            return None;
        }
    };
    let bound = match listener.local_addr() {
        Ok(address) => address.port(),
        Err(error) => {
            eprintln!("forward: cannot determine callback port: {error}");
            return None;
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    // Tolerated rather than fatal: a host with IPv6 disabled must still get
    // callbacks, which is all `ssh -L 127.0.0.1:N` ever delivered.
    let ipv6_listener = match bind_polling(Ipv6Addr::LOCALHOST.into(), bound) {
        Ok(listener) => Some(listener),
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
        return None;
    }
    if let Some(listener) = ipv6_listener {
        let _ = spawn_accept_loop(listener, bridge, bound, leases.clone(), stop);
    }
    eprintln!("forward: callback port {bound} served on loopback");
    Some(bound)
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
