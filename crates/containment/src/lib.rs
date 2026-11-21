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
//! - [`omp::OmpProcess`] identifies the nearest enclosing process named `omp`,
//!   selected by the name field of its `/proc/<pid>/stat` and paired with the
//!   start time of that same read.
//!
//! A single identity type would make that difference invisible to every
//! downstream caller, so a future change could route a secrets decision through
//! unpinned evidence with the compiler silent and the code reading identically.
//! None of the three converts into another, and the one route from one to the
//! next says in its signature what it gives up: [`pinned::PinnedPeer`] can ask
//! for the omp process above it, and that walk leaves the pinned descriptor
//! behind and follows pids, so what it finds comes back as an
//! [`omp::OmpProcess`] rather than as more pinned evidence. What is shared is
//! the [`walk`]: one bounded, cycle-detecting parent traversal, with each type
//! supplying its own stop-and-match policy.
//!
//! One cap of 12 hops (`MAX_ANCESTRY_HOPS`) bounds every walk that looks for a
//! session: the anchored walk and the omp walk, whether it starts at a grant
//! command or at a pinned broker caller, because the command and the broker
//! have to reach the same omp process. A pinned peer's walk to its session
//! root keeps its own, deeper cap of 64 hops. Unifying upward would widen the
//! set of processes forward authorizes under a grant; unifying downward would
//! refuse deep broker callers. They are different because the risk is
//! different.

pub mod anchored;
pub mod omp;
pub mod pinned;
pub mod uid;

/// Longest ancestry walk an anchor or an omp lookup makes before giving up. A
/// worker nested deeper than this is not a session's child in any arrangement
/// we run.
pub const MAX_ANCESTRY_HOPS: usize = 12;

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
/// Field 2 is the name (the kernel's comm), parenthesised, and a process
/// controls its contents — including `)` and whitespace. The fields therefore
/// begin after the *last* `)`, which is unforgeable no matter what the name
/// holds. Index into the result: state 0, ppid 1, starttime 19.
/// [`parse_stat`] reads all three.
pub(crate) fn stat_fields(stat: &str) -> Option<&str> {
    let begin = stat.rfind(')')?.checked_add(2)?;
    stat.get(begin..)
}

/// The name field of a `/proc/<pid>/stat` line: the text between its first
/// `(` and its last `)`. The pid before it holds no `(`, and the fields after
/// it hold no `)`, so the name keeps every `(` and `)` its process put in it.
/// `None` when no `(` comes before the last `)`.
fn stat_name(stat: &str) -> Option<&str> {
    let begin = stat.find('(')?.checked_add(1)?;
    stat.get(begin..stat.rfind(')')?)
}

/// The fields of `/proc/<pid>/stat` that containment reads, all from one read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Stat {
    /// Process state, such as `S`, or `Z` for a zombie.
    pub(crate) state: char,
    /// Parent pid.
    pub(crate) parent: u32,
    /// Kernel start time, which distinguishes a recycled pid.
    pub(crate) start: u64,
    /// Whether the process's name is omp's, by [`omp::is_omp_name`]. The
    /// verdict rather than the name, so this stays `Copy` and a walk reads it
    /// without an allocation per hop.
    pub(crate) omp: bool,
}

/// Read `/proc/<pid>/stat`; `None` when it cannot be read or parsed. A name
/// that is not UTF-8 makes the read fail, so the walks stop there.
pub(crate) fn read_stat(pid: u32) -> Option<Stat> {
    parse_stat(&std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?)
}

/// Parse a `/proc/<pid>/stat` line: the name as [`stat_name`] finds it, which
/// decides `omp`, and, after the name as [`stat_fields`] finds them, state
/// (field 3), ppid (field 4) and starttime (field 22). `None` for a line with
/// no `(` before its last `)`, or one cut before starttime.
pub(crate) fn parse_stat(line: &str) -> Option<Stat> {
    let omp = omp::is_omp_name(stat_name(line)?);
    let mut fields = stat_fields(line)?.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let parent = fields.next()?.parse().ok()?;
    // Fields 5 through 21, seventeen of them, lie between ppid and starttime.
    let start = fields.nth(17)?.parse().ok()?;
    Some(Stat {
        state,
        parent,
        start,
        omp,
    })
}

#[cfg(test)]
mod tests;
