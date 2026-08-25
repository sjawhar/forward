//! Broker-owned grants for non-secret capabilities.
//!
//! These entries are authority records, not secret values. The broker expires
//! them on its monotonic clock and clears them atomically with `LOCK`.

use std::time::Instant;

struct Entry {
    deadline: Instant,
}

/// Capability authority issued by receipt redemption.
///
/// Capability entries deliberately do not share [`crate::grants::GrantTable`]:
/// secret lookup grants have no per-entry deadline, while these entries do.
#[derive(Default)]
pub struct CapabilityGrantTable {
    entries: Vec<Entry>,
}

impl std::fmt::Debug for CapabilityGrantTable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CapabilityGrantTable")
            .field("active", &self.entries.len())
            .finish()
    }
}

impl CapabilityGrantTable {
    /// Record a redeemed capability until the broker's authoritative deadline.
    pub(crate) fn insert(&mut self, deadline: Instant) -> usize {
        self.entries.push(Entry { deadline });
        self.entries.len().saturating_sub(1)
    }

    /// Return the broker-owned remaining lifetime for the just-recorded grant.
    pub(crate) fn remaining_secs(&self, index: usize, now: Instant) -> Option<u64> {
        self.entries
            .get(index)
            .filter(|entry| is_live(entry.deadline, now))
            .map(|entry| entry.deadline.saturating_duration_since(now).as_secs())
    }

    /// Remove grants whose broker-owned deadline has passed.
    pub(crate) fn sweep(&mut self, now: Instant) {
        self.entries.retain(|entry| is_live(entry.deadline, now));
    }

    /// Forget every live capability grant as part of `LOCK`.
    pub(crate) fn clear(&mut self) {
        self.entries.clear();
    }

    #[cfg(test)]
    pub(crate) const fn len(&self) -> usize {
        self.entries.len()
    }
}

fn is_live(deadline: Instant, now: Instant) -> bool {
    deadline > now
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn grants_expire_at_their_authoritative_deadlines() {
        let now = Instant::now();
        let mut grants = CapabilityGrantTable::default();

        grants.insert(now + Duration::from_secs(1));
        let second = grants.insert(now + Duration::from_secs(2));
        assert_eq!(grants.remaining_secs(second, now), Some(2));
        grants.sweep(now + Duration::from_secs(1));

        assert_eq!(grants.len(), 1);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn clear_forgets_live_capability_grants() {
        let now = Instant::now();
        let mut grants = CapabilityGrantTable::default();
        grants.insert(now + Duration::from_secs(1));

        grants.clear();

        assert_eq!(grants.len(), 0);
    }

    #[test]
    fn deadline_is_live_only_strictly_before_expiry() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);

        assert!(is_live(deadline, now));
        assert!(!is_live(deadline, deadline));
    }
}
