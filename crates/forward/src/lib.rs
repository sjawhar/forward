use std::time::Duration;

pub mod bridge;
pub mod browser;
pub mod callback;
pub mod config;
pub mod doctor;
pub(crate) mod fdpass;
pub mod localhost;
pub mod pcsc;
pub mod peer;
pub mod pipe;
pub mod policy;
pub mod pulse;
pub(crate) mod refusal;
mod render;
pub mod secretsd;
pub mod send;
pub mod serve;
mod socket;
pub mod target;

/// Bounds outbound peer dials so an absent laptop cannot wait for kernel SYN retries.
pub(crate) const PEER_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
