//! Process attribution for the browser grant path.
//!
//! The containment logic is shared with the secrets broker, in
//! `crates/containment`: both binaries answer "is this caller inside the
//! subtree this authority was issued to?" and that answer must not drift
//! between them. Independent bugs in two copies of one predicate is the
//! failure this consolidation exists to prevent.
//!
//! What stays here is the part that cannot move: resolving a *loopback TCP*
//! connection to a pid. That reads forward's own socket, and there is no pinned
//! kernel descriptor for the far end of a TCP connection the way there is for a
//! unix peer -- which is exactly why `containment` keeps two identity types and
//! this path uses the pid-plus-start-time one.
//!
//! Note the different `peer` in this crate: `crate::peer` is the tailnet IP
//! ACL, a different notion of peer entirely. That one asks whether an address
//! may connect; this one asks whether a process may use a grant.

mod socket;

pub use containment::anchored::{
    AnchoredPeer, Process, anchor_for, anchor_for_with, process_start, read_process, session_label,
    session_label_with,
};
pub use socket::pid_for_connection;

#[cfg(test)]
mod tests;
