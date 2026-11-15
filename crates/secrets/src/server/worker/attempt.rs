use std::path::Path;
use std::time::Instant;

use containment::omp::OmpProcess;

use super::{Job, effective_grant_ttl};
use crate::audit::sanitize_audit_value;
use crate::decrypt::{AttemptError, DecryptedHumanFile};
use crate::grants::{GrantOrigin, Scope};
use crate::server::State;

pub(super) fn finish_attempt(
    state: &mut State,
    job: Job,
    decrypted: Result<DecryptedHumanFile, AttemptError>,
) {
    match decrypted {
        Ok(decrypted) => finish_success(state, job, decrypted),
        Err(error) => finish_failure(state, &job, error),
    }
}

fn finish_success(state: &mut State, job: Job, decrypted: DecryptedHumanFile) {
    let session_is_active = match &job.scope {
        Scope::Session(token) => state
            .registry
            .registration(token)
            // A session whose root process is gone cannot receive the value,
            // so the approval is dropped rather than waiting for the backstop
            // to expire it.
            .is_some_and(|registration| registration.root.is_alive()),
        Scope::Tty { tty, .. } => Path::new(tty).exists(),
        Scope::Omp { pid, start } => OmpProcess::new(*pid, *start).is_running(),
    };
    if state.lock_epoch != job.lock_epoch || !session_is_active {
        state.queue.deny(job.id);
    }
    let now = Instant::now();
    if state.queue.complete(job.id, job.generation, now) {
        let ttl = effective_grant_ttl(
            job.requested_ttl,
            state.config.max_grant,
            state.config.max_requested_grant,
        );
        tracing::info!(
            source = %sanitize_audit_value(&decrypted.source),
            request_id = ?job.id,
            ttl_secs = ttl.as_secs(),
            "grant inserted"
        );
        state.grants.insert(
            job.scope,
            job.key,
            decrypted.value,
            now,
            GrantOrigin {
                source: decrypted.source,
                identity: decrypted.identity,
            },
            ttl,
        );
    }
}

fn finish_failure(state: &mut State, job: &Job, error: AttemptError) {
    replace_failure(state, job.id, error.code);
    let now = Instant::now();
    let retryable = error.retryable
        && state.lock_epoch == job.lock_epoch
        && state.queue.is_decrypting(job.id, job.generation)
        && state.queue.deadline_not_passed(job.id, now);
    if !retryable || !state.queue.retry(job.id, now) {
        state.queue.fail(job.id, now);
    }
}

fn replace_failure(
    state: &mut State,
    id: crate::requests::RequestId,
    error: crate::proto::ErrCode,
) {
    if let Some((_, recorded)) = state
        .failures
        .iter_mut()
        .find(|(recorded_id, _)| *recorded_id == id)
    {
        *recorded = error;
    } else {
        state.failures.push((id, error));
    }
}
