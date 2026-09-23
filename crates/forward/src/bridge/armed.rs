use std::collections::HashMap;
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

use super::holder::{Dial, Holder};
use super::port_policy::can_arm;
use crate::config::Config;

/// Callback ports the devbox will hop to, and until when.
///
/// The bridge is a service that connects to loopback ports on request, which is
/// the shape of a confinement bypass. This set is what stops a reachable peer
/// from choosing a port: only ports a local `forward open` armed — from a URL
/// that actually named them — are reachable, and only until the lease expires;
/// or ports a local `forward port` holds, and only while it runs.
///
/// Clones share one set, so the arming socket and the bridge listener can hold a
/// handle each.
#[derive(Clone)]
pub struct Armed {
    cfg: Config,
    ports: Arc<Mutex<HashMap<u16, Instant>>>,
    holders: Arc<Mutex<HashMap<u16, Arc<Holder>>>>,
}

/// Why a hold was not taken.
pub(super) enum HoldRefusal {
    /// The port is one the bridge must never dial. The refused connection comes
    /// back so the refusal can be written on it.
    Unsafe(UnixStream),
    /// A live holder already has the port. The refused connection comes back
    /// so the refusal can be written on it.
    Busy(UnixStream),
    /// The holder closed its connection before the hold was acknowledged.
    Vanished,
}

/// Where one bridge connection for a port goes.
pub(super) enum Upstream {
    Connected(TcpStream),
    /// Nothing armed or holds the port.
    Unarmed,
    /// The port is reachable in principle, but this connection could not be made.
    Failed(String),
}

impl Armed {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            ports: Arc::default(),
            holders: Arc::default(),
        }
    }

    /// Arm `port` for `ttl`. A longer lease replaces a shorter one; a shorter one
    /// never shortens a lease already granted. Returns false for an unsafe port or
    /// an unrepresentable deadline.
    ///
    /// A port a live holder has is already reachable, so arming it succeeds and
    /// records nothing: a held port has exactly one route, and a lease left under
    /// it would send the next connection after the holder dies to whatever this
    /// host has on that port instead.
    pub fn arm(&self, port: u16, ttl: Duration) -> bool {
        if !can_arm(&self.cfg, port) {
            return false;
        }
        let Some(deadline) = Instant::now().checked_add(ttl) else {
            return false;
        };
        loop {
            // The liveness peek runs outside the map lock, as in `hold`.
            let existing = self.holders.lock().get(&port).cloned();
            if let Some(holder) = existing {
                if holder.is_alive() {
                    eprintln!("forward: port {port} is held; arming it records nothing");
                    return true;
                }
                self.release(port, &holder);
            }
            // Re-check under the holders lock, then take the ports lock after it
            // (the order `hold` uses), so a hold landing in between wins.
            let holders = self.holders.lock();
            if holders.contains_key(&port) {
                continue;
            }
            let mut ports = self.ports.lock();
            let entry = ports.entry(port).or_insert(deadline);
            if *entry < deadline {
                *entry = deadline;
            }
            return true;
        }
    }

    /// Whether `port` is armed right now. Expired entries are dropped here, so no
    /// reaper thread is needed for this set.
    pub fn is_armed(&self, port: u16) -> bool {
        let mut ports = self.ports.lock();
        let now = Instant::now();
        ports.retain(|_, deadline| *deadline > now);
        ports.contains_key(&port)
    }

    /// Hold `port` for as long as `control` stays open, dialled by the process at
    /// its other end. A live holder is never displaced; a dead one is.
    pub(super) fn hold(&self, port: u16, control: UnixStream) -> Result<(), HoldRefusal> {
        if !can_arm(&self.cfg, port) {
            return Err(HoldRefusal::Unsafe(control));
        }
        loop {
            // The liveness peek runs outside the map lock: a holder mid-dial
            // holds its own lock for up to the dial deadline.
            let existing = {
                let mut holders = self.holders.lock();
                if let Some(holder) = holders.get(&port) {
                    Arc::clone(holder)
                } else {
                    let holder = Arc::new(Holder::new(control));
                    if !holder.acknowledge() {
                        return Err(HoldRefusal::Vanished);
                    }
                    holders.insert(port, holder);
                    // The holder is now the port's only route; see `arm`.
                    self.ports.lock().remove(&port);
                    return Ok(());
                }
            };
            if existing.is_alive() {
                return Err(HoldRefusal::Busy(control));
            }
            self.release(port, &existing);
        }
    }

    /// Connect one bridge connection for `port`: through its holder, which dials
    /// its own loopback, or else to this host's loopback if `forward open` armed it.
    pub(super) fn connect(&self, port: u16) -> Upstream {
        let holder = self.holders.lock().get(&port).cloned();
        if let Some(holder) = holder {
            return match holder.dial(port) {
                Dial::Connected(upstream) => Upstream::Connected(upstream),
                Dial::Unreachable => Upstream::Failed(format!(
                    "found nothing listening on port {port} where its holder runs"
                )),
                Dial::Gone(reason) => {
                    self.release(port, &holder);
                    Upstream::Failed(format!("released port {port}: its holder {reason}"))
                }
            };
        }
        if !self.is_armed(port) {
            return Upstream::Unarmed;
        }
        TcpStream::connect(("127.0.0.1", port)).map_or_else(
            |error| Upstream::Failed(format!("could not reach 127.0.0.1:{port}: {error}")),
            Upstream::Connected,
        )
    }

    /// Free `port` if `holder` is still the one holding it.
    fn release(&self, port: u16, holder: &Arc<Holder>) {
        let mut holders = self.holders.lock();
        if holders
            .get(&port)
            .is_some_and(|current| Arc::ptr_eq(current, holder))
        {
            holders.remove(&port);
        }
    }
}

#[cfg(test)]
mod tests;
