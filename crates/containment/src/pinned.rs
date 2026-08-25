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

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use crate::{Step, stat_fields, status_field, walk};

/// `SO_PEERPIDFD`, added in Linux 6.5 and not surfaced by nix 0.29.
const SO_PEERPIDFD: libc::c_int = 77;

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
        let mut raw: libc::c_int = -1;
        let mut length: libc::socklen_t = size_of::<libc::c_int>()
            .try_into()
            .map_err(|_| UnidentifiedPeer)?;
        // SAFETY: `raw` and `length` are live for the duration of the call and
        // sized as `getsockopt` expects for an integer option, and the socket
        // descriptor is kept open by the borrow of `stream`.
        let outcome = unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&raw mut raw).cast(),
                &raw mut length,
            )
        };
        if outcome != 0 || raw < 0 {
            return Err(UnidentifiedPeer);
        }
        // SAFETY: a successful `SO_PEERPIDFD` installed a fresh descriptor that
        // nothing else owns, so the close obligation is ours alone.
        let pidfd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(Self {
            pidfd: Arc::new(pidfd),
        })
    }

    /// The pinned pid, or `None` once that process has exited.
    ///
    /// A pidfd whose process is gone reports `Pid: -1`, which is how a dead
    /// session root is distinguished from a live one.
    #[must_use]
    pub fn pid(&self) -> Option<i32> {
        let path = format!("/proc/self/fdinfo/{}", self.pidfd.as_raw_fd());
        let info = std::fs::read_to_string(path).ok()?;
        let value = status_field(&info, "Pid:")?;
        (value > 0).then_some(value)
    }

    /// Whether the pinned process is still running.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        self.pid().is_some()
    }

    /// Whether this peer is `root` itself or one of its descendants.
    ///
    /// Both ends are resolved from pinned descriptors, so neither pid can have
    /// been recycled onto an unrelated process.
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
