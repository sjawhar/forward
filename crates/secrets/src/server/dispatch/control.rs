use std::time::Instant;

use super::{Decision, Outcome};
use crate::audit::sanitize_audit_value;
use crate::grants::{Refusal, ScopeKind, SessionToken};
use crate::proto::ErrCode;
use crate::requests::RequestId;
use crate::server::{Shared, lock_state};

/// Report a refused change to a session's registration.
///
/// Both halves are deliberate. The log names the session and the processes
/// involved, because the incident this guards against
/// (<dispatch://INFRA-1644>) left no trace anywhere: the displaced session
/// simply began answering `UNKNOWN_TOKEN`. The response carries
/// `FOREIGN_CALLER` for an ancestry refusal -- the code the protocol already
/// uses for "you are outside this session's process tree", so a client that has
/// not been updated still renders a true explanation and no
/// `PROTOCOL_VERSION` bump is needed -- and `BAD_REQUEST` for a token already
/// bound elsewhere.
///
/// The two refusals get two messages rather than one. A token already bound
/// elsewhere is not a claim on anyone's session, and logging it as one would
/// put a false "held by another process tree" line, with no holder, in front
/// of whoever is reading the log after the next incident.
///
/// The session identifier is debug-quoted, matching the request audit line:
/// the sanitizer escapes control characters but keeps spaces and `=`, and a
/// display-formatted field would let a crafted identifier forge further
/// fields on the line.
fn refused(
    operation: &'static str,
    session: &str,
    caller: Option<i32>,
    refusal: Refusal,
) -> Decision {
    match refusal {
        Refusal::TokenBoundElsewhere => tracing::warn!(
            operation,
            untrusted_registered_session = ?sanitize_audit_value(session),
            caller_pid = ?caller,
            "refused a registration whose token is already bound to another session"
        ),
        Refusal::ForeignClaim { holder_pid } => tracing::warn!(
            operation,
            untrusted_registered_session = ?sanitize_audit_value(session),
            caller_pid = ?caller,
            holder_pid = ?holder_pid,
            "refused a claim on a session the caller was not shown to belong to"
        ),
    }
    Decision::new(Outcome::Failed(refusal.code(), refusal.message()))
}

pub(super) fn register(
    shared: &Shared,
    token_hex: &str,
    session: &str,
    root: crate::peer::PeerIdentity,
) -> Decision {
    match SessionToken::parse_hex(token_hex) {
        Ok(token) => {
            let caller_pid = root.pid();
            let (mutex, condvar) = &**shared;
            let mut state = lock_state(mutex);
            let registered = state.registry.register(crate::grants::Registration {
                token,
                session: session.to_owned(),
                root,
            });
            match registered {
                Ok(displaced) => {
                    state.grants.revoke_tokens(&displaced);
                    drop(state);
                    condvar.notify_all();
                    Decision {
                        outcome: Outcome::Ok,
                        scope_kind: Some(ScopeKind::VerifiedSession),
                        source: None,
                        request_id: None,
                    }
                }
                Err(refusal) => {
                    drop(state);
                    refused("REGISTER", session, caller_pid, refusal)
                }
            }
        }
        Err(error) => Decision::new(Outcome::Failed(error, "invalid session token")),
    }
}

pub(super) fn unregister(
    shared: &Shared,
    session: &str,
    caller: &crate::peer::PeerIdentity,
) -> Decision {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    match state.registry.unregister(session, caller) {
        Ok(tokens) => {
            state.grants.revoke_tokens(&tokens);
            drop(state);
            condvar.notify_all();
            Decision::new(Outcome::Ok)
        }
        Err(refusal) => {
            drop(state);
            refused("UNREGISTER", session, caller.pid(), refusal)
        }
    }
}

pub(super) fn grants(shared: &Shared) -> Decision {
    let (mutex, _) = &**shared;
    let state = lock_state(mutex);
    Decision::new(Outcome::Payload(
        state.grants.render(Instant::now()).into_bytes(),
    ))
}

pub(super) fn deny(shared: &Shared, id: u64) -> Decision {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    let outcome = if state.queue.deny(RequestId(id)) {
        state.kill_active(RequestId(id));
        Outcome::Ok
    } else {
        Outcome::Failed(ErrCode::BadRequest, "request is not pending")
    };
    drop(state);
    condvar.notify_all();
    Decision::new(outcome)
}

pub(super) fn lock(shared: &Shared) -> Decision {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    state.grants.revoke_all();
    state.receipts.clear();
    state.capability_grants.clear();
    state.lock_epoch = state.lock_epoch.saturating_add(1);
    let subscribers = std::sync::Arc::clone(&state.subscribers);
    if let Some(active) = state.active_decrypt.take() {
        state.queue.deny(active.id);
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(active.process_group),
            nix::sys::signal::Signal::SIGKILL,
        );
    }
    drop(state);
    condvar.notify_all();
    // The authority pair changes before any subscriber write. Attachment and
    // publication serialize their event ordering; nonblocking publication
    // drops a blocked subscriber instead of delaying LOCK.
    subscribers.publish_current(shared);
    Decision::new(Outcome::Ok)
}
