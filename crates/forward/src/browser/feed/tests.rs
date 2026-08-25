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
