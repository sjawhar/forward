use std::time::{Duration, Instant};

use super::queue::PendingRequest;
use super::{Queue, RequestId, RequestState};

/// Least time a request waits after a failed attempt before its next one, even
/// when the cooldown is shorter. A failure that returns at once (an absent PC/SC
/// socket, an instant sops error) would otherwise re-run without pause until
/// the request's time to live ends.
pub(super) const MIN_RETRY_DELAY: Duration = Duration::from_secs(1);

impl PendingRequest {
    /// Whether this request waits for its turn and, after a failed attempt,
    /// has waited out `retry_delay`.
    pub(super) fn is_ready(&self, retry_delay: Duration, now: Instant) -> bool {
        self.state == RequestState::Pending
            && self.retried_at.is_none_or(|retried| {
                now.checked_duration_since(retried)
                    .is_some_and(|elapsed| elapsed >= retry_delay)
            })
    }
}

impl Queue {
    /// The wait between a failed attempt and the same request's next one.
    pub(super) fn retry_delay(&self) -> Duration {
        self.limits.cooldown.max(MIN_RETRY_DELAY)
    }

    /// Move a failed decrypt to the queue tail after starting the cooldown.
    /// The request is not ready again until the cooldown or `MIN_RETRY_DELAY`,
    /// whichever is longer, has passed.
    pub fn retry(&mut self, id: RequestId, now: Instant) -> bool {
        let Some(index) = self.requests.iter().position(|request| request.id == id) else {
            return false;
        };
        if !self
            .requests
            .get(index)
            .is_some_and(|request| request.state == RequestState::Decrypting)
        {
            return false;
        }
        let mut request = self.requests.remove(index);
        request.state = RequestState::Pending;
        request.attempts = request.attempts.saturating_add(1);
        request.retried_at = Some(now);
        self.requests.push(request);
        self.finish(id, now);
        true
    }
}
