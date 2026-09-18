use std::time::Instant;

use super::{Queue, RequestId, RequestState};
use crate::grants::Scope;
use crate::secret::SecretName;

impl Queue {
    /// Expire a request and invalidate any decrypt that already started.
    pub fn timeout(&mut self, id: RequestId, now: Instant) -> bool {
        let Some(request) = self.requests.iter_mut().find(|request| request.id == id) else {
            return false;
        };
        match request.state {
            RequestState::Pending | RequestState::Decrypting => {
                request.state = RequestState::TimedOut;
                request.generation = request.generation.saturating_add(1);
                self.finish(id, now);
                true
            }
            RequestState::Granted
            | RequestState::Denied
            | RequestState::TimedOut
            | RequestState::Failed => false,
        }
    }

    /// Reject a pending request.
    pub fn deny(&mut self, id: RequestId) -> bool {
        let Some(request) = self.requests.iter_mut().find(|request| request.id == id) else {
            return false;
        };
        match request.state {
            RequestState::Pending | RequestState::Decrypting => {
                request.state = RequestState::Denied;
                request.generation = request.generation.saturating_add(1);
                self.finish(id, Instant::now());
                true
            }
            RequestState::Granted
            | RequestState::Denied
            | RequestState::TimedOut
            | RequestState::Failed => false,
        }
    }

    /// Expire requests that waited too long.
    pub fn sweep_timeouts(&mut self, now: Instant) -> Vec<RequestId> {
        let ttl = self.limits.ttl;
        let mut expired = Vec::new();
        for request in &mut self.requests {
            if matches!(
                request.state,
                RequestState::Pending | RequestState::Decrypting
            ) && now
                .checked_duration_since(request.created)
                .is_some_and(|elapsed| elapsed > ttl)
            {
                request.state = RequestState::TimedOut;
                request.generation = request.generation.saturating_add(1);
                expired.push(request.id);
            }
        }
        for id in &expired {
            self.finish(*id, now);
        }
        expired
    }

    /// Current state of a request.
    pub fn state_of(&self, id: RequestId) -> Option<RequestState> {
        self.requests
            .iter()
            .find(|request| request.id == id)
            .map(|request| request.state)
    }

    /// Scope, key, and requested ttl of a request.
    pub fn describe(&self, id: RequestId) -> Option<(Scope, SecretName, Option<u64>)> {
        self.requests
            .iter()
            .find(|request| request.id == id)
            .map(|request| {
                (
                    request.scope.clone(),
                    request.key.clone(),
                    request.requested_ttl,
                )
            })
    }

    /// Whether nothing is pending or in flight.
    pub fn is_idle(&self) -> bool {
        !self.requests.iter().any(|request| {
            matches!(
                request.state,
                RequestState::Pending | RequestState::Decrypting
            )
        })
    }

    /// Drop terminal requests older than twice the TTL, bounding memory.
    pub fn prune(&mut self, now: Instant) {
        let horizon = self.limits.ttl.saturating_mul(2);
        self.requests.retain(|request| {
            matches!(
                request.state,
                RequestState::Pending | RequestState::Decrypting
            ) || now
                .checked_duration_since(request.created)
                .is_some_and(|elapsed| elapsed < horizon)
        });
    }
}
