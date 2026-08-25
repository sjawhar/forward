//! Kernel-derived identity for the peer of a socket connection.
//!
//! The implementation is shared with forward, in `crates/containment`: both
//! binaries answer "is this caller inside the subtree this authority was issued
//! to?" and the answer must not drift between them. What is local here is the
//! mapping into this crate's wire error, and the test-only constructor.
//!
//! Note that `containment` deliberately keeps two identity types. This crate
//! uses the pidfd-pinned one, and the loopback-TCP resolver forward needs
//! cannot be substituted for it: a pinned pid cannot be recycled between the
//! kernel's report and the `/proc` walk, and an unpinned one can.

use std::os::unix::net::UnixStream;

pub use containment::pinned::PinnedPeer as PeerIdentity;

use crate::proto::ErrCode;

/// Pin the peer of `stream`, refusing a caller the kernel will not identify.
///
/// # Errors
///
/// Returns [`ErrCode::Internal`] when the kernel does not supply a peer pidfd,
/// so a caller that cannot be identified is refused rather than treated as
/// trusted.
pub fn identify(stream: &UnixStream) -> Result<PeerIdentity, ErrCode> {
    PeerIdentity::from_stream(stream).map_err(|_| ErrCode::Internal)
}
/// Pin the current process, for tests that need a concrete identity.
///
/// Both ends of a socket pair live in this process, so the pinned pid is our
/// own and `descends_from` against it holds.
///
/// Pinned once per test binary: a fresh pidfd per call would shift file
/// descriptor numbers under tests that assert on specific descriptors.
#[cfg(test)]
pub(crate) fn current_for_test() -> PeerIdentity {
    static SHARED: std::sync::LazyLock<PeerIdentity> = std::sync::LazyLock::new(|| {
        let (ours, theirs) = UnixStream::pair().expect("socket pair");
        let identity = PeerIdentity::from_stream(&ours).expect("peer pidfd");
        drop(theirs);
        identity
    });
    SHARED.clone()
}
