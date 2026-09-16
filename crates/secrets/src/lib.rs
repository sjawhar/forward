//! Session-scoped secrets broker.
//!
//! See `docs/design.md` for the threat model and the reasoning behind the
//! security properties this crate is required to hold.

#[doc(hidden)]
pub mod audit;
/// Capability names and their backing human-store key namespace.
pub mod capability;
/// Broker-owned capability grants, separate from secret release grants.
pub mod capability_grants;
/// Shared Unix-socket protocol client used by the `secrets` CLI.
pub mod client;
/// Shared source-root configuration carrying directory paths, never secret values.
pub mod config;
mod daemon;
/// Sops subprocess handling for one human-tier secret.
pub mod decrypt;
pub mod grants;
/// Process hardening that must complete before plaintext is held.
// Process hardening is shared with forward, which holds relay tokens and
// needs the same core-dump suppression. Re-exported so the many
// `crate::hardening::` call sites keep working.
pub use hygiene::hardening;
pub mod peer;
pub mod proto;
/// Single-use capability authorization receipts.
pub mod receipts;
/// Pending approval requests and the single-flight hardware queue.
pub mod requests;
/// Secret names and zeroizing plaintext bytes.
pub mod secret;
/// Socket server, worker, and request dispatch.
pub mod server;
/// Human-tier ciphertext directory access.
pub mod store;

pub use daemon::{Config, TouchPolicy, run, serve_main};
