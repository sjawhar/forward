//! Process containment: is this caller inside the subtree a grant was issued to?
//!
//! Both binaries answer that question, and before this crate each had its own
//! answer. They are unified here, but **deliberately not collapsed into one
//! type**, because the two callers cannot supply the same quality of evidence:
//!
//! - [`pinned::PinnedPeer`] identifies the peer of a unix socket via
//!   `SO_PEERPIDFD`. The kernel hands back a descriptor pinned to that process,
//!   so its pid cannot be recycled onto an unrelated process between the report
//!   and the `/proc` walk.
//! - [`anchored::AnchoredPeer`] identifies the far end of a **loopback TCP**
//!   connection, which cannot be pidfd-pinned at all. It pairs the pid with the
//!   kernel start time so a recycled pid fails the comparison instead of
//!   inheriting authority.
//!
//! A single identity type would make that difference invisible to every
//! downstream caller, so a future change could route a secrets decision through
//! unpinned evidence with the compiler silent and the code reading identically.
//! The types do not convert into each other. What is shared is the [`walk`]:
//! one bounded, cycle-detecting parent traversal, with each type supplying its
//! own stop-and-match policy and its own depth cap.
//!
//! The depth caps differ on purpose and stay per-type: 64 hops for a pinned
//! peer, 12 for an anchored one. Unifying upward would widen the set of
//! processes forward authorizes under a grant; unifying downward would refuse
//! deep broker callers. They are different because the risk is different.

pub mod anchored;
pub mod pinned;

/// What a walk step concluded about one process.
pub(crate) enum Step {
    /// This process is the ancestor being sought.
    Match,
    /// Not the ancestor; continue at this parent pid.
    Continue(u32),
    /// The walk cannot continue or has been refused.
    Stop,
}

/// Walk parents from `start`, up to `max_hops`, asking `visit` about each.
///
/// Cycle detection is unconditional here. The pinned walker previously relied
/// on its depth cap alone to terminate a `PPid` cycle; sharing this loop gives
/// it the visited set for free, which reaches the same answer with less work.
pub(crate) fn walk(start: u32, max_hops: usize, mut visit: impl FnMut(u32) -> Step) -> bool {
    let mut current = start;
    let mut visited = Vec::with_capacity(max_hops);
    for _ in 0..max_hops {
        if visited.contains(&current) {
            return false;
        }
        visited.push(current);
        match visit(current) {
            Step::Match => return true,
            Step::Stop => return false,
            Step::Continue(parent) => current = parent,
        }
    }
    false
}

/// Parse a `key:\tvalue` line out of a kernel-generated `key: value` file.
///
/// Only for files whose every field is written by the kernel, such as a
/// pidfd's `fdinfo`. A prefix match is not safe on `/proc/<pid>/status`,
/// where the process-controlled `Name:` comm line precedes `PPid:`: that
/// would make the result depend on the kernel escaping newlines in comm.
/// Use [`stat_fields`] for anything a process can influence.
pub(crate) fn status_field(contents: &str, key: &str) -> Option<i32> {
    contents
        .lines()
        .find_map(|line| line.strip_prefix(key))?
        .trim()
        .parse()
        .ok()
}

/// The positional fields of a `/proc/<pid>/stat` line, starting at field 3.
///
/// Field 2 is the comm, parenthesised, and a process controls its contents —
/// including `)` and whitespace. The fields therefore begin after the *last*
/// `)`, which is unforgeable no matter what the comm holds. Index into the
/// result: state 0, ppid 1, starttime 19.
pub(crate) fn stat_fields(stat: &str) -> Option<&str> {
    let begin = stat.rfind(')')?.checked_add(2)?;
    stat.get(begin..)
}

#[cfg(test)]
mod tests;
