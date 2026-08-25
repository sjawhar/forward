use std::io;
use std::sync::Arc;
use std::time::Duration;

use nix::time::{ClockId, clock_gettime};
use parking_lot::Mutex;

use super::*;
use crate::browser::BrowserError;

struct ManualClock(Mutex<BootTime>);

impl ManualClock {
    fn set(&self, now: BootTime) {
        *self.0.lock() = now;
    }
}

impl Clock for ManualClock {
    fn now(&self) -> BootTime {
        *self.0.lock()
    }
}

#[test]
fn deadlines_include_simulated_suspend_time() {
    let start = boottime_now();
    let clock = Arc::new(ManualClock(Mutex::new(start)));
    let tokens = RelayTokens::with_clock(clock.clone());
    tokens.insert(b"suspend-safe".to_vec(), Duration::from_secs(30 * 60));

    assert!(tokens.accepts(b"suspend-safe"));
    clock.set(
        start
            .checked_add(Duration::from_secs(8 * 60 * 60))
            .expect("boot time plus eight hours"),
    );
    assert!(!tokens.accepts(b"suspend-safe"));
}

#[test]
fn production_clock_samples_clock_boottime() {
    // The production clock must sample CLOCK_BOOTTIME, not CLOCK_MONOTONIC:
    // the laptop's lease deadlines have to keep advancing across suspend.
    let expected = Duration::from(clock_gettime(ClockId::CLOCK_BOOTTIME).unwrap());
    let actual = BoottimeClock.now().as_duration_since_boot();

    assert!(actual.abs_diff(expected) <= Duration::from_millis(100));
}

#[test]
fn expired_tokens_are_reaped_without_a_relay_attempt() {
    let tokens = RelayTokens::new();
    tokens.insert(b"short-lived".to_vec(), Duration::from_millis(1));

    std::thread::sleep(Duration::from_millis(50));

    assert_eq!(tokens.entry_count(), 0);
}

#[test]
fn mirror_deadline_uses_the_shorter_five_minute_lease() {
    // This fails if a relay mirror retains a longer wire ttl.
    let start = BootTime::from_duration_since_boot(Duration::from_secs(1));
    let clock = Arc::new(ManualClock(Mutex::new(start)));
    let tokens = RelayTokens::with_clock(clock);

    tokens.insert(b"long-wire-ttl".to_vec(), Duration::from_secs(6 * 60));

    assert_eq!(
        tokens.next_deadline(),
        start.checked_add(Duration::from_secs(5 * 60))
    );
}

#[test]
fn renewal_replaces_the_prior_mirror_entry_and_deadline() {
    // This fails if a renewal appends a second entry or leaves the old lease.
    let start = BootTime::from_duration_since_boot(Duration::from_secs(1));
    let clock = Arc::new(ManualClock(Mutex::new(start)));
    let tokens = RelayTokens::with_clock(clock.clone());
    tokens.insert(b"renewed-token".to_vec(), Duration::from_secs(30));

    clock.set(
        start
            .checked_add(Duration::from_secs(10))
            .expect("later boot time"),
    );
    tokens.insert(b"renewed-token".to_vec(), Duration::from_secs(120));

    assert_eq!(tokens.entry_count(), 1);
    assert_eq!(
        tokens.next_deadline(),
        start.checked_add(Duration::from_secs(130))
    );
    clock.set(
        start
            .checked_add(Duration::from_secs(31))
            .expect("past prior deadline"),
    );
    assert!(tokens.accepts(b"renewed-token"));
}

#[test]
fn unrenewed_mirror_entry_expires_at_five_minute_lease() {
    // This fails if a long wire ttl survives without devbox renewal.
    let start = BootTime::from_duration_since_boot(Duration::from_secs(1));
    let clock = Arc::new(ManualClock(Mutex::new(start)));
    let tokens = RelayTokens::with_clock(clock.clone());
    tokens.insert(
        b"unrenewed-token".to_vec(),
        Duration::from_secs(12 * 60 * 60),
    );

    clock.set(
        start
            .checked_add(Duration::from_secs(5 * 60 - 1))
            .expect("just before lease expiry"),
    );
    assert!(tokens.accepts(b"unrenewed-token"));
    clock.set(
        start
            .checked_add(Duration::from_secs(5 * 60))
            .expect("lease expiry"),
    );
    assert!(!tokens.accepts(b"unrenewed-token"));
}

#[test]
fn client_spawn_failure_is_reported() {
    let error = client::client_spawn_result(Err(io::Error::other("thread limit"))).unwrap_err();

    assert!(
        matches!(error, BrowserError::Spawn { source } if source.kind() == io::ErrorKind::Other)
    );
}

#[test]
fn reconnect_budget_escalates_after_the_bounded_outage() {
    let mut budget = client::ReconnectBudget::default();
    let started = std::time::Instant::now();

    assert!(!budget.failed_at(started));
    assert!(!budget.failed_at(started + client::MAX_UNHEALTHY_FEED - Duration::from_millis(1)));
    assert!(budget.failed_at(started + client::MAX_UNHEALTHY_FEED));
    budget.restored();
    assert!(!budget.failed_at(started + client::MAX_UNHEALTHY_FEED));
}
