//! Pending approval requests and the single-flight hardware queue.

mod expiry;
mod queue;
pub(crate) mod retry;
mod types;

pub use queue::Queue;
pub use types::{Clock, QueueLimits, RequestId, RequestState, SystemClock};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod retry_tests;
