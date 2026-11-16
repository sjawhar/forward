use std::path::Path;
use std::time::{Duration, Instant};

use super::{Job, State, finish_attempt};
use crate::decrypt::AttemptError;
use crate::grants::Scope;
use crate::proto::ErrCode;
use crate::requests::retry::MIN_RETRY_DELAY;
use crate::requests::{RequestId, RequestState};
use crate::secret::SecretName;

fn state(directory: &Path) -> State {
    State::new(crate::Config {
        socket_path: directory.join("secretsd.sock"),
        human_sources: Vec::new(),
        sops_bin: directory.join("sops"),
        pcsc_socket: None,
        yubikey_probe_argv: Vec::new(),
        yubikey_probe_timeout: Duration::from_secs(2),
        touch_policy: crate::TouchPolicy::Always,
        max_grant: Duration::from_secs(60),
        max_requested_grant: Duration::from_secs(60),
        cooldown: Duration::ZERO,
        request_ttl: Duration::from_secs(90),
        max_pending_per_scope: 2,
    })
    .unwrap()
}

fn job(state: &State, id: RequestId, generation: u64, attempt: u32, scope: &Scope) -> Job {
    Job {
        id,
        scope: scope.clone(),
        key: SecretName::parse("DEEL_API_KEY").unwrap(),
        generation,
        attempt,
        lock_epoch: state.lock_epoch,
        store: state.store.clone(),
        decryptor: state.decryptor.clone(),
        requested_ttl: None,
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn retry_a_killed_attempt_keeps_the_last_real_failure() {
    // Given a request whose first attempt found the key unreachable.
    let directory = tempfile::tempdir().unwrap();
    let mut state = state(directory.path());
    let scope = Scope::Tty {
        tty: directory.path().display().to_string(),
        boot_id: "test-boot".to_owned(),
    };
    let start = Instant::now();
    let id = state
        .queue
        .enqueue(
            scope.clone(),
            SecretName::parse("DEEL_API_KEY").unwrap(),
            start,
            None,
        )
        .unwrap();
    let first = state.queue.mark_decrypting(id, start).unwrap();
    let first_job = job(&state, id, first, 1, &scope);
    finish_attempt(
        &mut state,
        first_job,
        Err(AttemptError::unreachable_probe()),
    );
    assert_eq!(state.queue.state_of(id), Some(RequestState::Pending));
    assert_eq!(state.failures, vec![(id, ErrCode::YubikeyUnreachable)]);

    // When a waiter's deadline ends the second attempt and its killed sops fails.
    // The first failure began the MIN_RETRY_DELAY wait, so `later` is past it.
    let later = Instant::now() + MIN_RETRY_DELAY;
    let second = state.queue.mark_decrypting(id, later).unwrap();
    assert!(state.queue.timeout(id, later));
    let second_job = job(&state, id, second, 2, &scope);
    finish_attempt(
        &mut state,
        second_job,
        Err(AttemptError::from(ErrCode::Internal)),
    );

    // Then a coalesced waiter still reads the unreachable key, not the kill.
    assert_eq!(state.queue.state_of(id), Some(RequestState::TimedOut));
    assert_eq!(state.failures, vec![(id, ErrCode::YubikeyUnreachable)]);
}
