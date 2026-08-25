//! CLI-facing client surface.
//!
//! The transport -- socket resolution, framing, the version handshake, typed
//! responses -- lives in `crates/proto`, shared with forward so the two cannot
//! drift. What stays here is the part only the `secrets` CLI needs: argv
//! handling, presentation, and the GET/REQUEST scoped-frame helpers.

mod agent;
pub mod cli;
mod edit;
mod error;
mod human;
mod sources;
mod status;

pub use agent::AgentStore;
pub use error::CliError;
pub use human::{HumanClient, HumanLocation, HumanNames};
pub use proto::client::{BrokerClient, SocketPath, caller_tty, read_token_file, runtime_dir};
pub use proto::response::{BrokerResponse, ClientError, parse_response};

#[cfg(test)]
mod tests;
