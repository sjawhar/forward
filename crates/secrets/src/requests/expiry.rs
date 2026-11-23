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

    /// Reject requests that have begun an attempt while preserving untouched work.
    pub fn deny_attempted(&mut self) {
        let now = Instant::now();
        let mut inflight = None;
        for request in &mut self.requests {
            let decrypting = request.state == RequestState::Decrypting;
            let waiting_to_retry = request.state == RequestState::Pending && request.attempts >= 1;
            if decrypting || waiting_to_retry {
                request.state = RequestState::Denied;
                request.generation = request.generation.saturating_add(1);
                if decrypting {
                    inflight = Some(request.id);
                }
            }
        }
        if let Some(id) = inflight {
            self.finish(id, now);
        }
    }

    /// Whether the request has not passed its queue deadline.
    pub fn deadline_not_passed(&self, id: RequestId, now: Instant) -> bool {
        self.requests
            .iter()
            .find(|request| request.id == id)
            .and_then(|request| request.created.checked_add(self.limits.ttl))
            .is_some_and(|deadline| now <= deadline)
    }

    /// Requests that wait for a touch or are decrypting and have not passed
    /// their deadline (the rule of `deadline_not_passed`), in id order: each
    /// one's id, key, scope, state and whole seconds to its deadline. A retry
    /// moves a request to the end of the queue, so queue order is not id order.
    pub(crate) fn live(
        &self,
        now: Instant,
    ) -> Vec<(RequestId, &SecretName, &Scope, RequestState, u64)> {
        let mut live: Vec<_> = self
            .requests
            .iter()
            .filter(|request| {
                matches!(
                    request.state,
                    RequestState::Pending | RequestState::Decrypting
                )
            })
            .filter_map(|request| {
                let deadline = request.created.checked_add(self.limits.ttl)?;
                (now <= deadline).then(|| {
                    (
                        request.id,
                        &request.key,
                        &request.scope,
                        request.state,
                        deadline.saturating_duration_since(now).as_secs(),
                    )
                })
            })
            .collect();
        live.sort_unstable_by_key(|&(id, ..)| id);
        live
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
