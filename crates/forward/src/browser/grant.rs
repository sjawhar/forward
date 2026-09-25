use std::collections::HashMap;
use std::os::unix::net::UnixStream;
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
/// `Clone` on purpose: `Grants::live` hands each relayed connection a copy
/// whose token lives as long as its handler; expiry zeroes only the registry's
/// copy.
#[derive(Clone)]
pub struct Grant {
    /// The omp session id is retained for display and logging only.
    pub session: String,
    /// The unforgeable process instance allowed to use this grant, as
    /// `forward serve` reads it from the requesting connection's `SO_PEERCRED`
    /// pid. Descriptive here: the endpoint's own admission check runs in the
    /// caller's namespace, against the anchor the caller derived there.
    pub anchor: ProcessAnchor,
    /// The relay token, held only while the grant is live.
    pub token: Vec<u8>,
    pub deadline: Instant,
    /// The loopback port the caller's relay listens on, for `STATUS` and log
    /// lines. It identifies nothing: two callers in different network
    /// namespaces can hold the same number at the same time.
    pub endpoint_port: u16,
}
impl Drop for Grant {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}
/// A live grant and the control channel its relay holds open.
///
/// Shutting the channel down is how every ending reaches both ends at once:
/// it wakes `forward serve`'s own control loop and tells the caller's relay to
/// close its listener and exit.
struct GrantEntry {
    grant: Grant,
    control: UnixStream,
}
mod lifetime;
mod pipes;
pub use pipes::PipeGuard;
use pipes::{PipeHandles, PipeTable};

/// Live grants keyed by an id this registry mints.
///
/// Keyed by id rather than by endpoint port: the port belongs to the caller's
/// network namespace, so two live grants may carry the same one.
#[derive(Clone, Default)]
pub struct Grants {
    grants: Arc<Mutex<HashMap<u64, GrantEntry>>>,
    pipes: Arc<Mutex<PipeTable>>,
    authority: Arc<Mutex<Option<crate::secretsd::BrokerIdentity>>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

impl Grants {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, grant: Grant, control: &UnixStream) -> Option<u64> {
        let control = control.try_clone().ok()?;
        let mut grants = self.grants.lock();
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        grants.insert(id, GrantEntry { grant, control });
        Some(id)
    }

    /// Insert only under the current broker authority, closing the final
    /// redeem-to-registry race. Returns the new grant's id.
    pub fn insert_if_authority(
        &self,
        authority: &crate::secretsd::BrokerIdentity,
        grant: Grant,
        control: &UnixStream,
    ) -> Option<u64> {
        let observed = self.authority.lock();
        if observed.as_ref() != Some(authority) {
            return None;
        }
        self.insert(grant, control)
    }

    /// Observe broker authority; a changed pair revokes every live grant.
    pub fn observe_authority(&self, authority: crate::secretsd::BrokerIdentity) -> bool {
        let mut observed = self.authority.lock();
        let changed = observed.as_ref().is_some_and(|seen| seen != &authority);
        *observed = Some(authority);
        if changed {
            self.revoke_all();
        }
        changed
    }

    /// Revoke every grant when the subscription remains unprovable.
    pub fn invalidate_authority(&self) {
        let mut authority = self.authority.lock();
        *authority = None;
        self.revoke_all();
    }

    /// Return the unexpired grant for `id`, ending a stale backstop entry.
    ///
    /// An entry found past its deadline here is ended through [`Self::expire`]
    /// rather than dropped in place: dropping the row alone would leave the
    /// caller's relay serving an endpoint for a grant nothing holds, and the
    /// reaper's later `expire` would find nothing left to close. The lock is
    /// released first so `expire` can take pipes before grants, as every other
    /// removal path does.
    pub fn live(&self, id: u64) -> Option<Grant> {
        {
            let grants = self.grants.lock();
            let entry = grants.get(&id)?;
            if entry.grant.deadline > Instant::now() {
                return Some(entry.grant.clone());
            }
        }
        self.expire(id);
        None
    }

    /// Live tokens with their remaining lifetimes for feed re-push after the
    /// laptop reconnects. Expired grants are excluded; the reaper owns removal.
    pub fn snapshot_live(&self) -> Vec<(zeroize::Zeroizing<Vec<u8>>, u64)> {
        let now = Instant::now();
        self.grants
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

    /// The live grant an authenticated process may use, with its endpoint port.
    ///
    /// The caller anchor comes from `SO_PEERCRED` and `/proc`, not asserted
    /// process arguments. A descendant of the grant's anchor may query its
    /// status, matching the endpoint's own authorization rule.
    pub fn live_for_descendant(&self, caller: ProcessAnchor) -> Option<(u16, Grant)> {
        if crate::browser::peer::process_start(caller.pid) != Some(caller.start) {
            return None;
        }
        let now = Instant::now();
        self.grants
            .lock()
            .values()
            .find(|entry| entry.grant.deadline > now && entry.grant.anchor.contains(caller.pid))
            .map(|entry| (entry.grant.endpoint_port, entry.grant.clone()))
    }
}

/// Remove `id`'s grant, overwriting its token before releasing the buffer.
fn scrub(grants: &mut HashMap<u64, GrantEntry>, id: u64) -> Option<GrantEntry> {
    let mut entry = grants.remove(&id)?;
    entry.grant.token.zeroize();
    Some(entry)
}

#[cfg(test)]
mod tests;
