//! Containment for a unix-socket peer, pinned by `SO_PEERPIDFD`.
//!
//! A session token proves *which* session a request belongs to, but on a
//! single-uid machine possession of the token file is not proof that the caller
//! belongs to that session: any process sharing the uid can read it. Pairing the
//! token with the caller's position in the process tree closes that gap.
//!
//! Ancestry is only trustworthy if the pid it starts from cannot be recycled
//! between the moment the kernel reports it and the moment `/proc` is walked.
//! `SO_PEERPIDFD` returns a descriptor pinned to the peer process, which makes
//! that pid stable for as long as the descriptor is held, so this resolver uses
//! it rather than the pid from `SO_PEERCRED`.

use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crate::{Step, stat_fields, status_field, walk};

/// Upper bound on a `/proc` parent walk, so a pathological tree cannot spin the
/// daemon. Deeper than the anchored cap because a broker caller may sit far
/// below its session root.
const MAX_ANCESTRY_DEPTH: usize = 64;

/// The kernel would not identify the peer of a connection.
///
/// A caller that cannot be identified is refused rather than treated as
/// trusted, so this is deliberately opaque: there is nothing a caller can do
/// with a reason.
#[derive(Debug)]
#[non_exhaustive]
pub struct UnidentifiedPeer;

impl std::fmt::Display for UnidentifiedPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("the kernel did not supply a peer pidfd")
    }
}

impl std::error::Error for UnidentifiedPeer {}

/// What the kernel reports about a pinned process.
///
/// Four outcomes, kept apart on purpose. Only [`Liveness::Exited`] is the
/// kernel stating the process is gone, and it is the only one that may
/// release an authority held in that process's name: a read that failed, or
/// a process with no number in this namespace, is an absence of evidence
/// rather than evidence of death. Collapsing these into "alive or not" is
/// what let a daemon out of descriptors treat every live session as finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Liveness {
    /// Running, with this pid in the reader's namespace.
    Running(i32),
    /// Running, with no pid in the reader's namespace (`Pid: 0`).
    Unnumbered,
    /// Reaped (`Pid: -1`).
    Exited,
    /// The `fdinfo` read failed, or carried no `Pid:` field.
    Unknown,
}

/// A pidfd pinned to the process on the other end of a connection.
///
/// Cloning shares the descriptor: every clone observes the same process, and
/// the pid stays reserved until the last clone is dropped.
#[derive(Debug, Clone)]
pub struct PinnedPeer {
    pidfd: Arc<OwnedFd>,
}

impl PinnedPeer {
    /// Pin the peer of `stream`.
    ///
    /// # Errors
    ///
    /// Returns [`UnidentifiedPeer`] when the kernel does not supply a peer
    /// pidfd.
    pub fn from_stream(stream: &UnixStream) -> Result<Self, UnidentifiedPeer> {
        let pidfd = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerPidfd)
            .map_err(|_| UnidentifiedPeer)?;
        Ok(Self {
            pidfd: Arc::new(pidfd),
        })
    }

    /// What the kernel reports about the pinned process.
    ///
    /// One `fdinfo` read, one answer, because the four outcomes it can have
    /// are not interchangeable and collapsing them into booleans is how a
    /// caller comes to release an authority on a read that simply failed.
    #[must_use]
    pub fn liveness(&self) -> Liveness {
        let path = format!("/proc/self/fdinfo/{}", self.pidfd.as_raw_fd());
        let Ok(info) = std::fs::read_to_string(path) else {
            return Liveness::Unknown;
        };
        match status_field(&info, "Pid:") {
            Some(pid) if pid > 0 => Liveness::Running(pid),
            Some(0) => Liveness::Unnumbered,
            Some(_) => Liveness::Exited,
            None => Liveness::Unknown,
        }
    }

    /// The pinned pid, when the kernel reports one in this namespace.
    ///
    /// `None` covers three different answers — reaped, running with no number
    /// here, and not readable — so it is the right input for a `/proc` walk
    /// and the wrong one for deciding that a process is gone. Ask
    /// [`PinnedPeer::liveness`] for that.
    #[must_use]
    pub fn pid(&self) -> Option<i32> {
        match self.liveness() {
            Liveness::Running(pid) => Some(pid),
            Liveness::Unnumbered | Liveness::Exited | Liveness::Unknown => None,
        }
    }

    /// Whether the pinned process is running and numbered in this namespace.
    ///
    /// For culling work whose process is no longer there — a subscriber, an
    /// approval whose session ended. Never for deciding that an authority
    /// may be taken away from that process: `false` here also means "could
    /// not tell", and [`Liveness::Exited`] is the only answer that says gone.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        matches!(self.liveness(), Liveness::Running(_))
    }

    /// Whether this peer is `root` itself or one of its descendants.
    ///
    /// Each end is read from a pinned descriptor, so each answers for the
    /// exact process that connected or registered rather than for whatever
    /// now holds its number. A caller or root the kernel will not number is
    /// refused rather than assumed.
    #[must_use]
    pub fn descends_from(&self, root: &Self) -> bool {
        match (self.pid(), root.pid()) {
            (Some(caller), Some(ancestor)) => descends_from_pid(caller, ancestor),
            _ => false,
        }
    }

    /// Build from a raw descriptor. Tests construct identities directly;
    /// production code goes through [`PinnedPeer::from_stream`].
    #[doc(hidden)]
    #[must_use]
    pub fn from_owned_fd(pidfd: OwnedFd) -> Self {
        Self {
            pidfd: Arc::new(pidfd),
        }
    }
}

pub(crate) fn descends_from_pid(caller: i32, ancestor: i32) -> bool {
    let Ok(start) = u32::try_from(caller) else {
        return false;
    };
    walk(start, MAX_ANCESTRY_DEPTH, |current| {
        let Ok(signed) = i32::try_from(current) else {
            return Step::Stop;
        };
        if signed == ancestor {
            return Step::Match;
        }
        // pid 1 has no parent worth following, and 0 means the walk ran out.
        if signed <= 1 {
            return Step::Stop;
        }
        parent_of(signed)
            .and_then(|parent| u32::try_from(parent).ok())
            .map_or(Step::Stop, Step::Continue)
    })
}

/// The parent pid recorded for `pid`, or `None` if it cannot be read.
///
/// Read positionally out of `stat`, not by key out of `status`: a process
/// controls its own comm, and in `status` that comm precedes `PPid:`.
pub(crate) fn parent_of(pid: i32) -> Option<i32> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    stat_fields(&stat)?.split_whitespace().nth(1)?.parse().ok()
}
