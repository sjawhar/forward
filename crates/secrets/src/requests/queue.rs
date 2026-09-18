use std::time::Instant;

use super::{QueueLimits, RequestId, RequestState};
use crate::capability::CAPABILITY_KEY_PREFIX;
use crate::grants::Scope;
use crate::proto::ErrCode;
use crate::secret::SecretName;

#[derive(Debug)]
pub(super) struct PendingRequest {
    pub(super) id: RequestId,
    pub(super) scope: Scope,
    pub(super) key: SecretName,
    pub(super) state: RequestState,
    pub(super) generation: u64,
    pub(super) created: Instant,
    /// Caller-requested lifetime for the grant this request may install.
    /// `None` defers to the daemon's own default backstop.
    pub(super) requested_ttl: Option<u64>,
}

/// The approval queue. Exactly one decrypt may be in flight.
#[derive(Debug)]
pub struct Queue {
    pub(super) requests: Vec<PendingRequest>,
    pub(super) limits: QueueLimits,
    next_id: u64,
    generation: u64,
    inflight: Option<RequestId>,
    last_finished: Option<Instant>,
}

impl Queue {
    /// Build an empty queue.
    pub const fn new(limits: QueueLimits) -> Self {
        Self {
            requests: Vec::new(),
            limits,
            next_id: 1,
            generation: 0,
            inflight: None,
            last_finished: None,
        }
    }

    /// Add a request, coalescing an identical pending one.
    pub fn enqueue(
        &mut self,
        scope: Scope,
        key: SecretName,
        now: Instant,
        requested_ttl: Option<u64>,
    ) -> Result<RequestId, ErrCode> {
        let capability = key.as_str().starts_with(CAPABILITY_KEY_PREFIX);
        if !capability
            && let Some(existing) = self.requests.iter().find(|request| {
                request.scope == scope
                    && request.key == key
                    && matches!(
                        request.state,
                        RequestState::Pending | RequestState::Decrypting
                    )
            })
        {
            return Ok(existing.id);
        }
        let active = self
            .requests
            .iter()
            .filter(|request| {
                request.scope == scope
                    && (!capability || request.key.as_str().starts_with(CAPABILITY_KEY_PREFIX))
                    && matches!(
                        request.state,
                        RequestState::Pending | RequestState::Decrypting
                    )
            })
            .count();
        let limit = if capability {
            1
        } else {
            self.limits.max_pending_per_scope
        };
        if active >= limit {
            return Err(ErrCode::TooManyPending);
        }
        let id = RequestId(self.next_id);
        self.next_id = self.next_id.saturating_add(1);
        self.requests.push(PendingRequest {
            id,
            scope,
            key,
            state: RequestState::Pending,
            generation: 0,
            created: now,
            requested_ttl,
        });
        Ok(id)
    }

    /// The next request eligible to touch the hardware, if any.
    pub fn next_ready(&self, now: Instant) -> Option<RequestId> {
        if self.inflight.is_some() {
            return None;
        }
        if let Some(last) = self.last_finished
            && now
                .checked_duration_since(last)
                .is_some_and(|elapsed| elapsed < self.limits.cooldown)
        {
            return None;
        }
        self.requests
            .iter()
            .find(|request| request.state == RequestState::Pending)
            .map(|request| request.id)
    }

    /// Mark a request as decrypting, returning its generation.
    pub fn mark_decrypting(&mut self, id: RequestId, now: Instant) -> Option<u64> {
        if self.inflight.is_some()
            || self.last_finished.is_some_and(|last| {
                now.checked_duration_since(last)
                    .is_some_and(|elapsed| elapsed < self.limits.cooldown)
            })
        {
            return None;
        }
        let request = self.requests.iter_mut().find(|request| request.id == id)?;
        if request.state != RequestState::Pending {
            return None;
        }
        self.generation = self.generation.saturating_add(1);
        let generation = self.generation;
        request.state = RequestState::Decrypting;
        request.generation = generation;
        self.inflight = Some(id);
        Some(generation)
    }

    /// Whether a completing decrypt may still install its grant.
    pub fn complete(&mut self, id: RequestId, generation: u64, now: Instant) -> bool {
        let still_current = self.requests.iter().any(|request| {
            request.id == id
                && request.generation == generation
                && request.state == RequestState::Decrypting
        });
        if still_current
            && let Some(request) = self.requests.iter_mut().find(|request| request.id == id)
        {
            request.state = RequestState::Granted;
        }
        self.finish(id, now);
        still_current
    }

    /// Release the hardware and start the cooldown.
    pub fn finish(&mut self, id: RequestId, now: Instant) {
        if self.inflight == Some(id) {
            self.inflight = None;
        }
        self.last_finished = Some(now);
    }

    /// Mark a decrypt as failed.
    pub fn fail(&mut self, id: RequestId, now: Instant) {
        if let Some(request) = self.requests.iter_mut().find(|request| request.id == id) {
            request.state = RequestState::Failed;
        }
        self.finish(id, now);
    }
}
