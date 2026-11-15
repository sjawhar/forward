use std::sync::Arc;
use std::time::{Duration, Instant};

use super::{HEARTBEAT_INTERVAL, Shared, lock_state, publish_current_authority, wait_state};
use crate::decrypt::Decryptor;
use crate::grants::Scope;
use crate::requests::RequestId;
use crate::secret::SecretName;
use crate::store::HumanStore;

mod attempt;

use attempt::finish_attempt;

#[derive(Debug)]
struct Job {
    id: RequestId,
    scope: Scope,
    key: SecretName,
    generation: u64,
    attempt: u32,
    lock_epoch: u64,
    store: HumanStore,
    decryptor: Decryptor,
    /// Caller-requested grant lifetime, carried from the enqueued request.
    requested_ttl: Option<u64>,
}

/// The lifetime a freshly created grant receives: `requested` clamped to
/// `max_requested_grant`, or `max_grant` -- today's unconditional default --
/// when the caller asked for nothing. Pure and reused nowhere else, so it is
/// unit-tested directly instead of only through a running daemon.
fn effective_grant_ttl(
    requested: Option<u64>,
    max_grant: Duration,
    max_requested_grant: Duration,
) -> Duration {
    requested.map_or(max_grant, |secs| {
        Duration::from_secs(secs).min(max_requested_grant)
    })
}

pub(super) fn worker(shared: &Shared) {
    let mut last_heartbeat = Instant::now();
    loop {
        // Measured as elapsed time rather than a stored future deadline:
        // adding to an `Instant` can overflow, and this loop runs forever.
        if last_heartbeat.elapsed() >= HEARTBEAT_INTERVAL {
            publish_current_authority(shared);
            last_heartbeat = Instant::now();
        }
        let job = {
            let (mutex, condvar) = &**shared;
            let mut state = lock_state(mutex);
            let now = Instant::now();
            let expired = state.queue.sweep_timeouts(now);
            for id in expired {
                state.kill_active(id);
            }
            state.grants.revoke_expired(now);
            state.grants.revoke_vanished_scopes();
            state.queue.prune(now);
            state.receipts.sweep(now);
            state.capability_grants.sweep(now);
            let failures = std::mem::take(&mut state.failures);
            state.failures = failures
                .into_iter()
                .filter(|(id, _)| state.queue.state_of(*id).is_some())
                .collect();
            let Some(id) = state.queue.next_ready(now) else {
                drop(wait_state(condvar, state, Duration::from_millis(100)));
                continue;
            };
            let Some(generation) = state.queue.mark_decrypting(id, now) else {
                continue;
            };
            let Some(attempt) = state.queue.attempt_number(id) else {
                state.queue.fail(id, now);
                condvar.notify_all();
                continue;
            };
            let Some((scope, key, requested_ttl)) = state.queue.describe(id) else {
                state.queue.fail(id, now);
                condvar.notify_all();
                continue;
            };
            Job {
                id,
                scope,
                key,
                generation,
                attempt,
                lock_epoch: state.lock_epoch,
                store: state.store.clone(),
                decryptor: state.decryptor.clone(),
                requested_ttl,
            }
        };
        let shared_for_start = Arc::clone(shared);
        let started = Instant::now();
        let decrypted =
            job.decryptor
                .decrypt_opened_with_start(&job.store, &job.key, move |process_group| {
                    let (mutex, _) = &*shared_for_start;
                    let mut state = lock_state(mutex);
                    if state.queue.state_of(job.id)
                        == Some(crate::requests::RequestState::Decrypting)
                    {
                        state.active_decrypt = Some(super::ActiveDecrypt {
                            id: job.id,
                            process_group,
                        });
                        drop(state);
                    } else {
                        let _ = nix::sys::signal::killpg(
                            nix::unistd::Pid::from_raw(process_group),
                            nix::sys::signal::Signal::SIGKILL,
                        );
                    }
                });
        let duration_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let result = decrypted
            .as_ref()
            .map_or_else(|error| error.label, |_| "ok");
        let request_id = job.id;
        let attempt = job.attempt;
        let (mutex, condvar) = &**shared;
        let mut state = lock_state(mutex);
        state.kill_active(request_id);
        finish_attempt(&mut state, job, decrypted);
        tracing::info!(
            request_id = ?request_id,
            attempt,
            result = %result,
            duration_ms,
            "decrypt attempt"
        );
        drop(state);
        condvar.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::effective_grant_ttl;

    fn max_grant() -> Duration {
        Duration::from_hours(12)
    }

    fn max_requested_grant() -> Duration {
        Duration::from_hours(24)
    }

    #[test]
    fn omitted_ttl_keeps_todays_default_backstop() {
        assert_eq!(
            effective_grant_ttl(None, max_grant(), max_requested_grant()),
            max_grant()
        );
    }

    #[test]
    fn a_requested_ttl_under_the_ceiling_is_honored_exactly() {
        assert_eq!(
            effective_grant_ttl(Some(3_600), max_grant(), max_requested_grant()),
            Duration::from_secs(3_600)
        );
    }

    #[test]
    fn a_requested_ttl_at_the_ceiling_is_honored_exactly() {
        assert_eq!(
            effective_grant_ttl(
                Some(max_requested_grant().as_secs()),
                max_grant(),
                max_requested_grant()
            ),
            max_requested_grant()
        );
    }

    #[test]
    fn a_requested_ttl_over_the_ceiling_is_clamped_to_it() {
        assert_eq!(
            effective_grant_ttl(Some(999_999_999), max_grant(), max_requested_grant()),
            max_requested_grant()
        );
    }

    #[test]
    fn a_requested_ttl_can_undercut_the_default_backstop() {
        // A shorter --ttl is always honored: the ceiling only ever bounds
        // from above, never forces a grant to live as long as the default.
        assert_eq!(
            effective_grant_ttl(Some(45), max_grant(), max_requested_grant()),
            Duration::from_secs(45)
        );
    }
}
