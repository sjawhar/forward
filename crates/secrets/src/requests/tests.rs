use std::time::{Duration, Instant};

use super::*;
use crate::grants::{Scope, SessionToken};
use crate::proto::ErrCode;
use crate::secret::SecretName;

fn scope(byte: u8) -> Scope {
    Scope::Session(SessionToken::parse_hex(&format!("{byte:02x}").repeat(32)).unwrap())
}

fn name(raw: &str) -> SecretName {
    SecretName::parse(raw).unwrap()
}

fn limits() -> QueueLimits {
    QueueLimits {
        cooldown: Duration::from_secs(16),
        ttl: Duration::from_secs(90),
        max_pending_per_scope: 2,
    }
}

#[test]
fn enqueue_returns_ready_request() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let id = queue.enqueue(scope(0xaa), name("K"), now, None).unwrap();
    assert_eq!(queue.next_ready(now), Some(id));
}

#[test]
fn duplicate_request_for_same_scope_and_key_is_coalesced() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let first = queue.enqueue(scope(0xaa), name("K"), now, None).unwrap();
    let second = queue.enqueue(scope(0xaa), name("K"), now, None).unwrap();
    assert_eq!(first, second);
}

#[test]
fn one_capability_request_per_scope_is_pending_at_a_time() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    queue
        .enqueue(scope(0xaa), name("CAP_BROWSER"), now, None)
        .unwrap();

    assert_eq!(
        queue.enqueue(scope(0xaa), name("CAP_BROWSER"), now, None),
        Err(ErrCode::TooManyPending)
    );
}

#[test]
fn same_key_from_different_scope_is_a_separate_request() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let first = queue.enqueue(scope(0xaa), name("K"), now, None).unwrap();
    let second = queue.enqueue(scope(0xbb), name("K"), now, None).unwrap();
    assert_ne!(first, second, "one approval must never serve two scopes");
}

#[test]
fn only_one_decrypt_is_in_flight() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let first = queue.enqueue(scope(0xaa), name("K"), now, None).unwrap();
    queue.enqueue(scope(0xbb), name("J"), now, None).unwrap();
    queue.mark_decrypting(first, now);
    assert_eq!(
        queue.next_ready(now),
        None,
        "second decrypt started while first in flight"
    );
}

#[test]
fn mark_decrypting_refuses_a_second_inflight_request() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let first = queue.enqueue(scope(0xaa), name("K"), now, None).unwrap();
    let second = queue.enqueue(scope(0xbb), name("J"), now, None).unwrap();
    assert!(queue.mark_decrypting(first, now).is_some());
    assert_eq!(queue.mark_decrypting(second, now), None);
}

#[test]
fn cooldown_blocks_the_next_decrypt_until_the_touch_cache_expires() {
    let mut queue = Queue::new(limits());
    let start = Instant::now();
    let first = queue.enqueue(scope(0xaa), name("K"), start, None).unwrap();
    queue.mark_decrypting(first, start);
    queue.finish(first, start);
    let second = queue.enqueue(scope(0xbb), name("J"), start, None).unwrap();

    assert_eq!(queue.next_ready(start + Duration::from_secs(10)), None);
    assert_eq!(
        queue.next_ready(start + Duration::from_secs(17)),
        Some(second)
    );
}

#[test]
fn denied_request_is_not_ready_and_reports_denied() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let id = queue.enqueue(scope(0xaa), name("K"), now, None).unwrap();
    assert!(queue.deny(id));
    assert_eq!(queue.state_of(id), Some(RequestState::Denied));
    assert_eq!(queue.next_ready(now), None);
}

#[test]
fn late_completion_after_deny_is_rejected() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let id = queue.enqueue(scope(0xaa), name("K"), now, None).unwrap();
    let generation = queue.mark_decrypting(id, now).unwrap();
    queue.deny(id);
    assert!(
        !queue.complete(id, generation, now),
        "a denied request must not install a grant"
    );
}

#[test]
fn pending_limit_per_scope_is_enforced() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    queue.enqueue(scope(0xaa), name("A"), now, None).unwrap();
    queue.enqueue(scope(0xaa), name("B"), now, None).unwrap();
    assert_eq!(
        queue.enqueue(scope(0xaa), name("C"), now, None).err(),
        Some(ErrCode::TooManyPending)
    );
}

#[test]
fn flooding_one_scope_does_not_lock_out_another() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    queue.enqueue(scope(0xaa), name("A"), now, None).unwrap();
    queue.enqueue(scope(0xaa), name("B"), now, None).unwrap();
    assert!(queue.enqueue(scope(0xbb), name("C"), now, None).is_ok());
}

#[test]
fn expired_requests_are_swept() {
    let mut queue = Queue::new(limits());
    let start = Instant::now();
    let id = queue.enqueue(scope(0xaa), name("K"), start, None).unwrap();
    let swept = queue.sweep_timeouts(start + Duration::from_secs(91));
    assert_eq!(swept, vec![id]);
    assert_eq!(queue.state_of(id), Some(RequestState::TimedOut));
}

#[test]
fn timed_out_decrypt_rejects_its_old_generation() {
    let mut queue = Queue::new(limits());
    let start = Instant::now();
    let id = queue.enqueue(scope(0xaa), name("K"), start, None).unwrap();
    let generation = queue.mark_decrypting(id, start).unwrap();

    queue.sweep_timeouts(start + Duration::from_secs(91));

    assert_eq!(queue.state_of(id), Some(RequestState::TimedOut));
    assert!(!queue.complete(id, generation, start + Duration::from_secs(91)));
}

#[test]
fn describe_carries_the_requested_ttl_through_to_the_worker() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let id = queue
        .enqueue(scope(0xaa), name("K"), now, Some(45))
        .unwrap();
    assert_eq!(queue.describe(id), Some((scope(0xaa), name("K"), Some(45))));
}

#[test]
fn describe_reports_no_preference_when_ttl_was_omitted() {
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let id = queue.enqueue(scope(0xaa), name("K"), now, None).unwrap();
    assert_eq!(queue.describe(id), Some((scope(0xaa), name("K"), None)));
}

#[test]
fn coalescing_keeps_the_first_requesters_ttl() {
    // A second caller racing an already-pending request cannot change the
    // grant's eventual lifetime out from under the first caller.
    let mut queue = Queue::new(limits());
    let now = Instant::now();
    let first = queue
        .enqueue(scope(0xaa), name("K"), now, Some(60))
        .unwrap();
    let second = queue
        .enqueue(scope(0xaa), name("K"), now, Some(999_999))
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(
        queue.describe(first),
        Some((scope(0xaa), name("K"), Some(60)))
    );
}
