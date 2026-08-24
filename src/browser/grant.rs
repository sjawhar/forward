use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use zeroize::Zeroize;

/// A process instance that owns a grant.
///
/// Linux may reuse a PID after its process exits. Pairing the PID with the
/// kernel start time prevents a new process from inheriting that authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProcessAnchor {
    pub pid: u32,
    pub start_time: u64,
}

/// One session's authorisation to reach the laptop's browser.
///
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

/// Live grants, keyed by the loopback port each one owns.
///
/// Clones share one map so the request socket and the proxy listeners can hold
/// a handle each, matching `bridge::Armed`. `Armed` is deliberately not reused:
/// it keys on port with a port-safety policy, and a grant keys on session.
#[derive(Clone, Default)]
pub struct Grants {
    ports: Arc<Mutex<HashMap<u16, Grant>>>,
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
        if crate::browser::peer::process_start(caller.pid) != Some(caller.start_time) {
            return None;
        }
        let now = Instant::now();
        self.ports
            .lock()
            .iter()
            .find(|(_, grant)| {
                grant.deadline > now
                    && crate::browser::peer::ancestry_contains(
                        caller.pid,
                        grant.anchor.pid,
                        grant.anchor.start_time,
                    )
            })
            .map(|(port, grant)| (*port, grant.clone()))
    }

    /// Drop `port`'s grant now, zeroing the registry's token copy in place.
    pub fn expire(&self, port: u16) {
        drop(scrub(&mut self.ports.lock(), port));
    }
}

/// Remove `port`'s grant, overwriting its token before releasing the buffer.
fn scrub(ports: &mut HashMap<u16, Grant>, port: u16) -> Option<Grant> {
    let mut grant = ports.remove(&port)?;
    grant.token.zeroize();
    Some(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn grant(session: &str, ttl: Duration) -> Grant {
        Grant {
            session: session.to_owned(),
            anchor: ProcessAnchor {
                pid: 1,
                start_time: 1,
            },
            token: b"correct-horse".to_vec(),
            deadline: Instant::now() + ttl,
        }
    }

    #[test]
    fn a_live_grant_is_returned_for_its_port() {
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));
        assert_eq!(grants.live(12811).unwrap().session, "session-a");
    }

    #[test]
    fn an_expired_grant_is_not_returned() {
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));
        assert!(grants.live(12811).is_none());
    }

    #[test]
    fn an_unknown_port_has_no_grant() {
        assert!(Grants::new().live(12811).is_none());
    }

    #[test]
    fn expiring_one_grant_leaves_another_usable() {
        // The token is shared by every grant, so dropping one must not disarm
        // the other.
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));
        grants.insert(12812, grant("session-b", Duration::from_secs(60)));
        grants.expire(12811);
        assert!(grants.live(12811).is_none());
        assert_eq!(grants.live(12812).unwrap().session, "session-b");
    }

    #[test]
    fn clones_share_one_registry() {
        let grants = Grants::new();
        let clone = grants.clone();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));
        assert!(clone.live(12811).is_some());
    }

    #[test]
    fn replacing_a_grant_retires_its_predecessor() {
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));
        grants.insert(12811, grant("session-b", Duration::from_secs(60)));
        assert_eq!(grants.live(12811).unwrap().session, "session-b");
    }

    #[test]
    fn expiring_a_grant_removes_its_token_from_the_registry() {
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));
        grants.expire(12811);
        assert!(grants.live(12811).is_none());
    }

    #[test]
    fn expiring_a_grant_overwrites_its_removed_token() {
        let mut ports = HashMap::new();
        let original = grant("session-a", Duration::from_secs(60));
        let token_len = original.token.len();
        ports.insert(12811, original);

        let expired = scrub(&mut ports, 12811).expect("the grant is removed");

        assert!(ports.is_empty());
        // SAFETY: `zeroize` clears the Vec length but keeps its allocation;
        // `token_len` bytes are initialized and within that allocation.
        let wiped = unsafe { std::slice::from_raw_parts(expired.token.as_ptr(), token_len) };
        assert!(
            wiped.iter().all(|byte| *byte == 0),
            "removed token buffer was not overwritten"
        );
        assert!(expired.token.is_empty());
    }

    #[test]
    fn a_live_grant_is_found_for_its_process_anchor() {
        let caller = ProcessAnchor {
            pid: std::process::id(),
            start_time: crate::browser::peer::process_start(std::process::id()).unwrap(),
        };
        let grants = Grants::new();
        let mut owned = grant("session-a", Duration::from_secs(60));
        owned.anchor = caller;
        grants.insert(12811, owned);
        grants.insert(12812, grant("session-b", Duration::from_secs(60)));

        let (port, found) = grants.live_for_descendant(caller).unwrap();
        assert_eq!((port, found.session.as_str()), (12811, "session-a"));
    }
    #[test]
    fn snapshot_live_excludes_expired_grants_and_preserves_a_positive_ttl() {
        let grants = Grants::new();
        grants.insert(12811, grant("live", Duration::from_secs(60)));
        grants.insert(12812, grant("expired", Duration::from_millis(1)));
        std::thread::sleep(Duration::from_millis(5));

        let snapshot = grants.snapshot_live();

        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].0.as_slice() == b"correct-horse");
        assert!(snapshot[0].1 > 0);
    }
}
