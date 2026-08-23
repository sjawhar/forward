use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

/// One session's authorisation to reach the laptop's browser.
///
/// `Clone` on purpose: `Grants::live` hands the proxy a copy whose token lives
/// as long as the connection handler that took it. Expiry zeroes only the
/// registry's copy — established connections are never guillotined.
#[derive(Clone)]
pub struct Grant {
    /// The omp session id every connection on this port must resolve to.
    pub session: String,
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
        drop(self.ports.lock().insert(port, grant));
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

    /// Drop `port`'s grant now, zeroing the registry's token copy in place.
    pub fn expire(&self, port: u16) {
        drop(self.take_scrubbed(port));
    }

    /// Test seam: expire `port` and hand back the scrubbed buffer, so a test
    /// can prove the registry's bytes were zeroed rather than merely dropped.
    #[doc(hidden)]
    pub fn take_scrubbed(&self, port: u16) -> Option<Vec<u8>> {
        scrub(&mut self.ports.lock(), port)
    }

    /// How many grants still hold a token. Test seam for the zeroing contract.
    #[doc(hidden)]
    pub fn tokens_held(&self) -> usize {
        self.ports.lock().len()
    }
}

/// Remove `port`'s grant, overwriting its token before the buffer is released,
/// so an expired grant leaves no copy in the allocator's free memory.
/// Hand-rolled: `zeroize` would be a dependency for six lines. Returns the
/// scrubbed buffer so the test seam can observe it.
fn scrub(ports: &mut HashMap<u16, Grant>, port: u16) -> Option<Vec<u8>> {
    let mut grant = ports.remove(&port)?;
    for byte in &mut grant.token {
        *byte = 0;
    }
    Some(std::mem::take(&mut grant.token))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn grant(session: &str, ttl: Duration) -> Grant {
        Grant {
            session: session.to_owned(),
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
        assert_eq!(grants.tokens_held(), 0);
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
    fn expiring_a_grant_zeroes_its_token_in_place() {
        // Given: a live grant holding a 13-byte token.
        let grants = Grants::new();
        grants.insert(12811, grant("session-a", Duration::from_secs(60)));

        // When: it is expired through the same scrub path `expire` uses,
        // keeping the registry's own buffer observable. `take_scrubbed` moves
        // the Vec out, so this is the very allocation the registry held.
        let scrubbed = grants.take_scrubbed(12811).unwrap();

        // Then: the buffer keeps the token's length and every byte is zero.
        // An implementation that removes without zeroing fails here, which is
        // the bug this test exists to name.
        assert_eq!(scrubbed.len(), b"correct-horse".len());
        assert!(scrubbed.iter().all(|byte| *byte == 0));
        assert_eq!(grants.tokens_held(), 0);
        assert!(grants.live(12811).is_none());
    }
}
