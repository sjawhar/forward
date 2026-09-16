use std::time::{Duration, Instant};

/// Source of monotonic time, injectable for tests.
pub trait Clock: Send + Sync {
    /// Current instant.
    fn now(&self) -> Instant;
}

/// Real time.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Instant {
        Instant::now()
    }
}

/// Identifier for a pending hardware-gated request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub struct RequestId(pub u64);

/// Lifecycle of one approval request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RequestState {
    /// Waiting for its turn at the hardware.
    Pending,
    /// A decrypt is running for this request.
    Decrypting,
    /// Completed successfully; a grant was installed.
    Granted,
    /// A human denied it.
    Denied,
    /// It expired before approval.
    TimedOut,
    /// Decryption failed.
    Failed,
}

/// Tunables for the queue.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct QueueLimits {
    /// Minimum gap between decrypts; must exceed the PIV touch cache.
    pub cooldown: Duration,
    /// How long a request may wait for approval.
    pub ttl: Duration,
    /// Concurrent pending requests allowed per scope.
    pub max_pending_per_scope: usize,
}
