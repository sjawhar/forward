use std::time::Instant;

use super::{Decision, Outcome};
use crate::grants::{ScopeKind, SessionToken};
use crate::proto::ErrCode;
use crate::requests::RequestId;
use crate::server::{Shared, lock_state};

pub(super) fn register(
    shared: &Shared,
    token_hex: &str,
    session: &str,
    root: crate::peer::PeerIdentity,
) -> Decision {
    match SessionToken::parse_hex(token_hex) {
        Ok(token) => {
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
                Err(error) => Decision::new(Outcome::Failed(
                    error,
                    "token is already bound to another session",
                )),
            }
        }
        Err(error) => Decision::new(Outcome::Failed(error, "invalid session token")),
    }
}

pub(super) fn unregister(shared: &Shared, session: &str) -> Decision {
    let (mutex, condvar) = &**shared;
    let mut state = lock_state(mutex);
    let tokens = state.registry.unregister(session);
    state.grants.revoke_tokens(&tokens);
    drop(state);
    condvar.notify_all();
    Decision::new(Outcome::Ok)
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
