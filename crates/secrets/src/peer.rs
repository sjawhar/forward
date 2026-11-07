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

pub use containment::pinned::{Liveness, PinnedPeer as PeerIdentity};

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

/// A real child process pinned the way the daemon pins a connection's peer,
/// for tests that need an identity this process does *not* descend from.
///
/// The registry's displacement rule can only be exercised against two
/// genuinely different process trees, and every other identity a test can
/// reach is this process itself. `cat` with a piped stdin is the child: it
/// stays alive until its stdin is closed, so a test chooses when the holder
/// dies.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ChildPeer {
    identity: PeerIdentity,
    child: std::process::Child,
}

#[cfg(test)]
impl ChildPeer {
    /// Spawn the child and pin it.
    pub(crate) fn spawn() -> Self {
        let child = std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn a child to pin");
        let identity = PeerIdentity::from_owned_fd(pidfd_open(child.id()));
        Self { identity, child }
    }

    /// The pinned identity, as the daemon would hold it for a registration.
    pub(crate) const fn identity(&self) -> &PeerIdentity {
        &self.identity
    }

    /// Let the child exit and reap it, so the pinned descriptor reports no pid.
    pub(crate) fn exit(&mut self) {
        drop(self.child.stdin.take());
        self.child.wait().expect("reap the pinned child");
    }

    /// Let the child exit without reaping it, leaving a zombie.
    ///
    /// A zombie still has a pid, so the kernel has not yet said the process is
    /// gone. Tests use this to pin down which of the two the registry treats
    /// as a released session.
    pub(crate) fn zombify(&mut self) {
        drop(self.child.stdin.take());
        let pid = self.identity.pid().expect("the child is pinned and alive");
        for _ in 0..1000 {
            let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
            let state = stat
                .rsplit(')')
                .next()
                .and_then(|tail| tail.split_whitespace().next());
            if state == Some("Z") {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("the child never became a zombie");
    }
}

#[cfg(test)]
impl Drop for ChildPeer {
    fn drop(&mut self) {
        // `wait` after a successful `exit` is the harmless no-child case.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Open a pidfd for `pid`, the only way to pin a process that did not connect.
///
/// `nix` 0.31 wraps `SO_PEERPIDFD` but no `pidfd_open`, and production code
/// never needs one: it pins the peer of a connection it already accepted.
#[cfg(test)]
fn pidfd_open(pid: u32) -> std::os::fd::OwnedFd {
    use std::os::fd::FromRawFd;

    let pid = libc::pid_t::try_from(pid).expect("pid fits in pid_t");
    // SAFETY: `pidfd_open` reads only its two scalar arguments and returns a
    // new descriptor or -1; it cannot touch this process's memory.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    let raw = std::os::fd::RawFd::try_from(raw).expect("pidfd_open returned a descriptor");
    assert!(raw >= 0, "pidfd_open failed for pid {pid}");
    // SAFETY: `pidfd_open` just returned `raw` to this process and nothing else
    // holds it, so the new `OwnedFd` is its sole owner.
    unsafe { std::os::fd::OwnedFd::from_raw_fd(raw) }
}
