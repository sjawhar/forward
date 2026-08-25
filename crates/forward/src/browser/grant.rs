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
struct GrantEntry {
    id: u64,
    grant: Grant,
}
mod pipes;
pub use pipes::PipeGuard;
use pipes::{PipeHandles, PipeTable};

/// Live grants keyed by their loopback port.
#[derive(Clone, Default)]
pub struct Grants {
    ports: Arc<Mutex<HashMap<u16, GrantEntry>>>,
    pipes: Arc<Mutex<PipeTable>>,
    authority: Arc<Mutex<Option<crate::secretsd::BrokerIdentity>>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

impl Grants {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, port: u16, grant: Grant) {
        let mut ports = self.ports.lock();
        drop(scrub(&mut ports, port));
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        ports.insert(port, GrantEntry { id, grant });
    }

    /// Insert only under the current broker authority, closing the final
    /// redeem-to-registry race.
    pub fn insert_if_authority(
        &self,
        port: u16,
        authority: &crate::secretsd::BrokerIdentity,
        grant: Grant,
    ) -> bool {
        let observed = self.authority.lock();
        if observed.as_ref() != Some(authority) {
            return false;
        }
        self.insert(port, grant);
        true
    }

    /// Observe broker authority; a changed pair revokes every live grant.
    pub fn observe_authority(&self, authority: crate::secretsd::BrokerIdentity) -> bool {
        let mut observed = self.authority.lock();
        let changed = observed.as_ref().is_some_and(|seen| seen != &authority);
        *observed = Some(authority);
        if changed {
            pipes::shutdown(self.drain_all());
        }
        changed
    }

    /// Revoke every grant when the subscription remains unprovable.
    pub fn invalidate_authority(&self) {
        let mut authority = self.authority.lock();
        *authority = None;
        pipes::shutdown(self.drain_all());
    }

    /// Return the unexpired grant for `port`, scrubbing a stale backstop entry.
    pub fn live(&self, port: u16) -> Option<Grant> {
        self.live_with_id(port).map(|(_, grant)| grant)
    }

    pub(crate) fn live_with_id(&self, port: u16) -> Option<(u64, Grant)> {
        let mut ports = self.ports.lock();
        let expired = ports
            .get(&port)
            .is_some_and(|entry| entry.grant.deadline <= Instant::now());
        if expired {
            drop(scrub(&mut ports, port));
            return None;
        }
        ports
            .get(&port)
            .map(|entry| (entry.id, entry.grant.clone()))
    }

    /// Live tokens with their remaining lifetimes for feed re-push after the
    /// laptop reconnects. Expired grants are excluded; the reaper owns removal.
    pub fn snapshot_live(&self) -> Vec<(zeroize::Zeroizing<Vec<u8>>, u64)> {
        let now = Instant::now();
        self.ports
            .lock()
            .values()
            .filter(|entry| entry.grant.deadline > now)
            .map(|entry| {
                (
                    zeroize::Zeroizing::new(entry.grant.token.clone()),
                    entry
                        .grant
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
            .find(|(_, entry)| {
                entry.grant.deadline > now && entry.grant.anchor.contains(caller.pid)
            })
            .map(|(port, entry)| (*port, entry.grant.clone()))
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
        pipes::shutdown(severed);
    }

    fn drain_all(&self) -> PipeHandles {
        let mut pipes = self.pipes.lock();
        let mut ports = self.ports.lock();
        ports
            .values_mut()
            .for_each(|entry| entry.grant.token.zeroize());
        ports.clear();
        std::mem::take(&mut *pipes)
            .into_values()
            .flatten()
            .collect()
    }
}

/// Remove `port`'s grant, overwriting its token before releasing the buffer.
fn scrub(ports: &mut HashMap<u16, GrantEntry>, port: u16) -> Option<GrantEntry> {
    let mut entry = ports.remove(&port)?;
    entry.grant.token.zeroize();
    Some(entry)
}

#[cfg(test)]
mod tests;
