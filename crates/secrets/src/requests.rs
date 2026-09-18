//! Pending approval requests and the single-flight hardware queue.

mod expiry;
mod queue;
mod types;

pub use queue::Queue;
pub use types::{Clock, QueueLimits, RequestId, RequestState, SystemClock};

#[cfg(test)]
mod tests;
