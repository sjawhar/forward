use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// A process instance that owns a grant.
/// Linux may reuse a PID after its process exits. Pairing the PID with the
/// kernel start time prevents a new process from inheriting that authority.
/// Shared with the secrets broker: see `crates/containment`.
pub use containment::anchored::AnchoredPeer as ProcessAnchor;
use parking_lot::Mutex;
use zeroize::Zeroize;

/// One session's authorisation to reach the laptop's browser.
/// `Clone` on purpose: `Grants::live` hands the proxy a copy whose token lives
/// as long as its handler; expiry zeroes only the registry's copy.
#[derive(Clone)]
pub struct Grant {
    /// The omp session id is retained for display and logging only.
    pub session: String,
    /// The unforgeable process instance allowed to use this port.
    pub anchor: ProcessAnchor,
    /// The relay token, held only while the grant is live.
    pub token: Vec<u8>,
    pub deadline: Instant,
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}
/// Live pipe handles per port: duplicated descriptors for both ends of every
/// connection the port's grant is currently serving.
type PipeTable = HashMap<u16, Vec<(u64, (std::net::TcpStream, std::net::TcpStream))>>;
type PipeHandles = Vec<(u64, (std::net::TcpStream, std::net::TcpStream))>;

/// Live grants, keyed by the loopback port each one owns.
///
/// Clones share one map so the request socket and the proxy listeners can hold
/// a handle each, matching `bridge::Armed`. `Armed` is deliberately not reused:
/// it keys on port with a port-safety policy, and a grant keys on session.
#[derive(Clone, Default)]
pub struct Grants {
    ports: Arc<Mutex<HashMap<u16, Grant>>>,
    pipes: Arc<Mutex<PipeTable>>,
    authority_epoch: Arc<Mutex<Option<u64>>>,
    next_pipe_id: Arc<std::sync::atomic::AtomicU64>,
}

impl Grants {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, port: u16, grant: Grant) {
        let mut ports = self.ports.lock();
        drop(scrub(&mut ports, port));
        ports.insert(port, grant);
    }

    /// Insert only when a live subscription has proven `epoch` current.
    ///
    /// Keeping the authority lock through insertion closes the last interval
    /// between the request handler's HELLO recheck and this registry update.
    pub fn insert_if_epoch(&self, port: u16, epoch: u64, grant: Grant) -> bool {
        let authority_epoch = self.authority_epoch.lock();
        if *authority_epoch != Some(epoch) {
            return false;
        }
        self.insert(port, grant);
        true
    }

    /// Record a subscription epoch and revoke every grant if it changed.
    ///
    /// The first epoch merely establishes authority. Every later advance or
    /// regression is unprovable continuity and therefore fails closed.
    pub fn observe_epoch(&self, epoch: u64) -> bool {
        let mut authority_epoch = self.authority_epoch.lock();
        let changed = authority_epoch.is_some_and(|seen| seen != epoch);
        *authority_epoch = Some(epoch);
        if changed {
            shutdown(self.drain_all());
        }
        changed
    }

    /// Revoke every grant for a newly observed broker instance.
    pub fn replace_authority(&self, epoch: u64) {
        let mut authority_epoch = self.authority_epoch.lock();
        *authority_epoch = Some(epoch);
        shutdown(self.drain_all());
    }

    /// Revoke every grant when the subscription remains unprovable.
    pub fn invalidate_authority(&self) {
        let mut authority_epoch = self.authority_epoch.lock();
        *authority_epoch = None;
        shutdown(self.drain_all());
    }

    /// The grant for `port` if it has not expired.
    ///
    /// The returned `Grant` is a clone; see the type docs for what expiry
    /// does and does not zero. Expired entries are scrubbed here as a
    /// backstop — the proxy's reaper normally beats this path.
    pub fn live(&self, port: u16) -> Option<Grant> {
        let mut ports = self.ports.lock();
        let expired = ports
            .get(&port)
            .is_some_and(|grant| grant.deadline <= Instant::now());
        if expired {
            drop(scrub(&mut ports, port));
            return None;
        }
        ports.get(&port).cloned()
    }

    /// Live tokens with their remaining lifetimes for feed re-push after the
    /// laptop reconnects. Expired grants are excluded; the reaper owns removal.
    pub fn snapshot_live(&self) -> Vec<(Vec<u8>, u64)> {
        let now = Instant::now();
        self.ports
            .lock()
            .values()
            .filter(|grant| grant.deadline > now)
            .map(|grant| {
                (
                    grant.token.clone(),
                    grant
                        .deadline
                        .saturating_duration_since(now)
                        .as_secs()
                        .max(1),
                )
            })
            .collect()
    }

    /// The live grant an authenticated process may use, if any.
    ///
    /// The caller anchor comes from `SO_PEERCRED` and `/proc`, not asserted
    /// process arguments. A descendant of the grant's anchor may query its
    /// status, matching the proxy's authorization rule.
    pub fn live_for_descendant(&self, caller: ProcessAnchor) -> Option<(u16, Grant)> {
        if crate::browser::peer::process_start(caller.pid) != Some(caller.start) {
            return None;
        }
        let now = Instant::now();
        self.ports
            .lock()
            .iter()
            .find(|(_, grant)| grant.deadline > now && grant.anchor.contains(caller.pid))
            .map(|(port, grant)| (*port, grant.clone()))
    }

    /// Register a live pipe's socket pair under `port`, so ending the grant
    /// ends the pipe.
    ///
    /// CDP multiplexes a whole session over one long-lived websocket, so a
    /// grant that only refuses *new* connections leaves an established session
    /// driving the browser for as long as it likes. The handles are duplicated
    /// descriptors: shutting them down wakes the blocked copies inside the
    /// pipe threads, and the returned guard removes the entry when the pipe
    /// ends on its own, so a finished pipe does not leak two descriptors.
    pub fn register_pipe(
        &self,
        port: u16,
        client: &std::net::TcpStream,
        laptop: &std::net::TcpStream,
    ) -> std::io::Result<PipeGuard> {
        // Lock pipes before ports, as `expire` does below: this keeps its
        // removal from falling between the live-grant check and registration.
        let mut pipes = self.pipes.lock();
        let ports = self.ports.lock();
        if !ports.contains_key(&port) {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        }
        let handles = (client.try_clone()?, laptop.try_clone()?);
        let id = self
            .next_pipe_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        pipes.entry(port).or_default().push((id, handles));
        drop(ports);
        Ok(PipeGuard {
            pipes: Arc::clone(&self.pipes),
            port,
            id,
        })
    }

    /// Drop `port`'s grant now, zeroing the registry's token copy in place and
    /// severing every live pipe the grant was serving.
    pub fn expire(&self, port: u16) {
        let severed = {
            // Lock pipes before ports, as `register_pipe` does above, so a
            // registration cannot escape the pipe table after this removal.
            let mut pipes = self.pipes.lock();
            let mut ports = self.ports.lock();
            drop(scrub(&mut ports, port));
            pipes.remove(&port).unwrap_or_default()
        };
        shutdown(severed);
    }

    fn drain_all(&self) -> PipeHandles {
        let mut pipes = self.pipes.lock();
        let mut ports = self.ports.lock();
        ports.values_mut().for_each(|grant| grant.token.zeroize());
        ports.clear();
        std::mem::take(&mut *pipes)
            .into_values()
            .flatten()
            .collect()
    }
}

fn shutdown(severed: PipeHandles) {
    for (_, (client, laptop)) in severed {
        // Both directions of both sockets: the pipe threads block on reads of
        // either end, and a one-sided shutdown leaves the other blocked.
        let _ = client.shutdown(std::net::Shutdown::Both);
        let _ = laptop.shutdown(std::net::Shutdown::Both);
    }
}

/// Removes its pipe's handles when the pipe ends of its own accord.
pub struct PipeGuard {
    pipes: Arc<Mutex<PipeTable>>,
    port: u16,
    id: u64,
}

impl Drop for PipeGuard {
    fn drop(&mut self) {
        if let Some(entries) = self.pipes.lock().get_mut(&self.port) {
            entries.retain(|(id, _)| *id != self.id);
        }
    }
}

/// Remove `port`'s grant, overwriting its token before releasing the buffer.
fn scrub(ports: &mut HashMap<u16, Grant>, port: u16) -> Option<Grant> {
    let mut grant = ports.remove(&port)?;
    grant.token.zeroize();
    Some(grant)
}

#[cfg(test)]
mod tests;
