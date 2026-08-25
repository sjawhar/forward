//! The laptop side of the browser grant feed.
//!
//! The laptop dials the devbox and holds one persistent connection. Each
//! `TOKEN <token> <ttl>` line registers a relay token until its deadline.
mod client;
mod reaper;

use std::sync::Arc;
use std::time::Duration;

pub use client::spawn_client;
use hygiene::clock::BootTime;
use parking_lot::Mutex;
use zeroize::Zeroize as _;

/// More live grants than this is not a workflow; evict the oldest.
const MAX_LIVE_TOKENS: usize = 64;
/// A laptop mirror is a renewed cache, never an independent 12-hour authority.
const LEASE: Duration = Duration::from_secs(5 * 60);

trait Clock: Send + Sync {
    fn now(&self) -> BootTime;
}

struct BoottimeClock;

impl Clock for BoottimeClock {
    fn now(&self) -> BootTime {
        boottime_now()
    }
}

struct TokenEntry {
    token: Vec<u8>,
    deadline: BootTime,
}

impl Drop for TokenEntry {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Default)]
struct Inner {
    entries: Vec<TokenEntry>,
    connected: bool,
}

/// Live relay tokens shared by the feed client and relay connection handlers.
#[derive(Clone)]
pub struct RelayTokens {
    inner: Arc<Mutex<Inner>>,
    reaper: Arc<reaper::Reaper>,
    clock: Arc<dyn Clock>,
}

impl Default for RelayTokens {
    fn default() -> Self {
        Self::with_clock(Arc::new(BoottimeClock))
    }
}

impl RelayTokens {
    pub fn new() -> Self {
        Self::default()
    }

    fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Arc::default(),
            reaper: Arc::default(),
            clock,
        }
    }

    pub fn insert(&self, mut token: Vec<u8>, ttl: Duration) {
        let now = self.clock.now();
        let Some(deadline) = now.checked_add(clamp_wire_ttl(ttl).min(LEASE)) else {
            token.zeroize();
            return;
        };
        self.insert_until(token, deadline, now);
        self.reaper.schedule(self.clone());
    }

    /// Compare against every live token without early exit. Expiry is checked
    /// before comparison, while a token's byte position remains indistinguishable.
    pub fn accepts(&self, presented: &[u8]) -> bool {
        self.accepts_at(presented, self.clock.now())
    }

    fn insert_until(&self, token: Vec<u8>, deadline: BootTime, now: BootTime) {
        let mut inner = self.inner.lock();
        inner.entries.retain(|entry| entry.deadline > now);
        inner.entries.retain_mut(|entry| {
            let replaced = hygiene::constant_time_eq(&entry.token, &token);
            if replaced {
                entry.token.zeroize();
            }
            !replaced
        });
        if inner.entries.len() == MAX_LIVE_TOKENS {
            drop(inner.entries.remove(0));
        }
        inner.entries.push(TokenEntry { token, deadline });
    }

    fn accepts_at(&self, presented: &[u8], now: BootTime) -> bool {
        let mut inner = self.inner.lock();
        inner.entries.retain(|entry| entry.deadline > now);
        inner.entries.iter().fold(false, |accepted, entry| {
            accepted | hygiene::constant_time_eq(&entry.token, presented)
        })
    }

    fn reap_expired(&self) {
        self.reap_expired_at(self.clock.now());
    }

    fn reap_expired_at(&self, now: BootTime) {
        self.inner
            .lock()
            .entries
            .retain(|entry| entry.deadline > now);
    }

    fn next_deadline(&self) -> Option<BootTime> {
        self.inner
            .lock()
            .entries
            .iter()
            .map(|entry| entry.deadline)
            .min()
    }

    #[cfg(test)]
    fn entry_count(&self) -> usize {
        self.inner.lock().entries.len()
    }

    pub fn set_connected(&self, connected: bool) {
        self.inner.lock().connected = connected;
    }

    pub fn is_connected(&self) -> bool {
        self.inner.lock().connected
    }
}

fn clamp_wire_ttl(ttl: Duration) -> Duration {
    ttl.min(super::LONGEST_TTL)
}

fn boottime_now() -> BootTime {
    BootTime::now().unwrap_or_else(|error| clock_failure(error))
}

fn clock_failure(error: impl std::fmt::Display) -> ! {
    eprintln!("forward: grant feed could not read CLOCK_BOOTTIME: {error}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests;
