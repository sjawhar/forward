//! The laptop side of the browser grant feed.
//!
//! The laptop dials the devbox and holds one persistent connection. Each
//! `TOKEN <token> <ttl>` line registers a relay token until its deadline.
mod client;
mod reaper;

pub use client::spawn_client;

use nix::time::ClockId;
use parking_lot::Mutex;
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroize as _;

/// More live grants than this is not a workflow; evict the oldest.
const MAX_LIVE_TOKENS: usize = 64;

type BootTime = Duration;

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
#[derive(Clone, Default)]
pub struct RelayTokens {
    inner: Arc<Mutex<Inner>>,
    reaper: Arc<reaper::Reaper>,
}

impl RelayTokens {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, mut token: Vec<u8>, ttl: Duration) {
        let now = boottime_now();
        let Some(deadline) = now.checked_add(ttl) else {
            token.zeroize();
            return;
        };
        self.insert_until(token, deadline, now);
        self.reaper.schedule(self.clone());
    }

    /// Compare against every live token without early exit. Expiry is checked
    /// before comparison, while a token's byte position remains indistinguishable.
    pub fn accepts(&self, presented: &[u8]) -> bool {
        self.accepts_at(presented, boottime_now())
    }

    #[cfg(test)]
    fn insert_at(&self, token: Vec<u8>, ttl: Duration, now: BootTime) {
        if let Some(deadline) = now.checked_add(ttl) {
            self.insert_until(token, deadline, now);
        }
    }

    fn insert_until(&self, token: Vec<u8>, deadline: BootTime, now: BootTime) {
        let mut inner = self.inner.lock();
        inner.entries.retain(|entry| entry.deadline > now);
        if inner.entries.len() == MAX_LIVE_TOKENS {
            inner.entries.remove(0);
        }
        inner.entries.push(TokenEntry { token, deadline });
    }

    fn accepts_at(&self, presented: &[u8], now: BootTime) -> bool {
        let mut inner = self.inner.lock();
        inner.entries.retain(|entry| entry.deadline > now);
        inner.entries.iter().fold(false, |accepted, entry| {
            accepted | constant_time_eq(&entry.token, presented)
        })
    }

    fn reap_expired(&self) {
        self.reap_expired_at(boottime_now());
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

/// Compare without an early exit. Length is not secret: a token of the wrong
/// size is already wrong.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

fn boottime_now() -> BootTime {
    let now = ClockId::CLOCK_BOOTTIME
        .now()
        .unwrap_or_else(|error| clock_failure(error));
    let seconds = u64::try_from(now.tv_sec()).unwrap_or_else(|error| clock_failure(error));
    let nanoseconds = u32::try_from(now.tv_nsec()).unwrap_or_else(|error| clock_failure(error));
    Duration::new(seconds, nanoseconds)
}

fn clock_failure(error: impl std::fmt::Display) -> ! {
    eprintln!("forward: grant feed could not read CLOCK_BOOTTIME: {error}");
    std::process::exit(1);
}

#[cfg(test)]
mod tests;
