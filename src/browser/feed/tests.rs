use super::*;
use crate::browser::BrowserError;
use std::io;
use std::time::Duration;

#[test]
fn deadlines_include_simulated_suspend_time() {
    let tokens = RelayTokens::new();
    let now = Duration::from_secs(100);
    tokens.insert_at(b"suspend-safe".to_vec(), Duration::from_secs(30), now);

    assert!(tokens.accepts_at(b"suspend-safe", now + Duration::from_secs(29)));
    assert!(!tokens.accepts_at(b"suspend-safe", now + Duration::from_secs(31)));
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
