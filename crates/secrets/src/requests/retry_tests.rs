use std::time::{Duration, Instant};

use super::{Queue, QueueLimits, RequestState};
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
        cooldown: Duration::from_secs(10),
        ttl: Duration::from_secs(90),
        max_pending_per_scope: 2,
    }
}

#[test]
fn retry_moves_a_failed_request_behind_pending_work_without_changing_it() {
    let mut queue = Queue::new(limits());
    let start = Instant::now();
    let a = queue
        .enqueue(scope(0xaa), name("A"), start, Some(45))
        .unwrap();
    let b = queue.enqueue(scope(0xbb), name("B"), start, None).unwrap();
    let c = queue.enqueue(scope(0xcc), name("C"), start, None).unwrap();
    let generation = queue.mark_decrypting(a, start).unwrap();

    assert_eq!(queue.attempt_number(a), Some(1));
    assert!(queue.is_decrypting(a, generation));
    assert!(queue.retry(a, start));
    assert_eq!(queue.next_ready(start + Duration::from_secs(9)), None);
    assert_eq!(queue.next_ready(start + Duration::from_secs(10)), Some(b));

    let request = queue
        .requests
        .iter()
        .find(|request| request.id == a)
        .unwrap();
    assert_eq!(request.created, start);
    assert_eq!(request.requested_ttl, Some(45));
    assert_eq!(request.scope, scope(0xaa));
    assert_eq!(request.state, RequestState::Pending);
    assert_eq!(request.attempts, 1);

    queue.mark_decrypting(b, start + Duration::from_secs(10));
    queue.fail(b, start + Duration::from_secs(10));
    assert_eq!(queue.next_ready(start + Duration::from_secs(20)), Some(c));
    queue.mark_decrypting(c, start + Duration::from_secs(20));
    queue.fail(c, start + Duration::from_secs(20));
    assert_eq!(queue.next_ready(start + Duration::from_secs(30)), Some(a));
}

#[test]
fn retry_preserves_non_capability_coalescing_and_capability_limits() {
    let start = Instant::now();
    let mut queue = Queue::new(limits());
    let request = queue.enqueue(scope(0xaa), name("K"), start, None).unwrap();
    queue.mark_decrypting(request, start);
    assert!(queue.retry(request, start));
    assert_eq!(
        queue.enqueue(scope(0xaa), name("K"), start, Some(45)),
        Ok(request)
    );

    let mut capabilities = Queue::new(limits());
    let request = capabilities
        .enqueue(scope(0xaa), name("CAP_BROWSER"), start, None)
        .unwrap();
    capabilities.mark_decrypting(request, start);
    assert!(capabilities.retry(request, start));
    assert_eq!(
        capabilities.enqueue(scope(0xaa), name("CAP_BROWSER"), start, None),
        Err(ErrCode::TooManyPending)
    );
}

#[test]
fn retry_fail_never_overrides_denial_or_timeout() {
    let start = Instant::now();
    let mut denied = Queue::new(limits());
    let denied_id = denied.enqueue(scope(0xaa), name("K"), start, None).unwrap();
    denied.mark_decrypting(denied_id, start);
    assert!(denied.deny(denied_id));
    denied.fail(denied_id, start);
    assert_eq!(denied.state_of(denied_id), Some(RequestState::Denied));

    let mut timed_out = Queue::new(limits());
    let timed_out_id = timed_out
        .enqueue(scope(0xaa), name("K"), start, None)
        .unwrap();
    timed_out.mark_decrypting(timed_out_id, start);
    assert!(timed_out.timeout(timed_out_id, start));
    timed_out.fail(timed_out_id, start);
    assert_eq!(
        timed_out.state_of(timed_out_id),
        Some(RequestState::TimedOut)
    );
}

#[test]
fn retry_deny_attempted_leaves_never_started_requests_pending() {
    let start = Instant::now();
    let mut queue = Queue::new(limits());
    let in_flight = queue.enqueue(scope(0xaa), name("A"), start, None).unwrap();
    let untouched = queue.enqueue(scope(0xbb), name("B"), start, None).unwrap();
    queue.mark_decrypting(in_flight, start);
    queue.deny_attempted();
    assert_eq!(queue.state_of(in_flight), Some(RequestState::Denied));
    assert_eq!(queue.state_of(untouched), Some(RequestState::Pending));

    let mut retry = Queue::new(limits());
    let retried = retry.enqueue(scope(0xcc), name("C"), start, None).unwrap();
    retry.mark_decrypting(retried, start);
    assert!(retry.retry(retried, start));
    retry.deny_attempted();
    assert_eq!(retry.state_of(retried), Some(RequestState::Denied));
}
