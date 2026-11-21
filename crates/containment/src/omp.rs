//! Find the nearest enclosing process named `omp`.
//!
//! A process's name is the name field of its `/proc/<pid>/stat`, which the
//! same read gives with its parent and start time, so the walk decides on the
//! name and records the start time of one read. `is_omp_name` states the rule.

use crate::anchored::{AnchoredPeer, Process};
use crate::{MAX_ANCESTRY_HOPS, Step, read_stat, walk};

/// An `omp` process instance, identified by pid and kernel start time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct OmpProcess {
    /// The omp process id.
    pub pid: u32,
    /// The kernel start time that distinguishes a reused pid.
    pub start: u64,
}

impl OmpProcess {
    /// Identify an omp process by its pid and kernel start time.
    #[must_use]
    pub const fn new(pid: u32, start: u64) -> Self {
        Self { pid, start }
    }

    /// Whether this exact omp process is still running.
    #[must_use]
    pub fn is_running(&self) -> bool {
        self.is_running_with(&mut read_process_state)
    }

    /// Test seam: check a caller-supplied process-state table.
    #[doc(hidden)]
    #[must_use]
    pub fn is_running_with(&self, lookup: &mut dyn FnMut(u32) -> Option<(u64, char)>) -> bool {
        matches!(lookup(self.pid), Some((start, state)) if start == self.start && !matches!(state, 'Z' | 'X'))
    }
}

/// Derive an anchor from the nearest enclosing process named `omp`.
#[must_use]
pub fn omp_anchor_for(pid: u32) -> Option<AnchoredPeer> {
    nearest_omp_for(pid).map(|omp| AnchoredPeer::new(omp.pid, omp.start))
}

/// Find the nearest omp ancestor of `pid` on the live `/proc`.
pub(crate) fn nearest_omp_for(pid: u32) -> Option<OmpProcess> {
    nearest_omp_from_with(pid, &mut stat_process)
}

/// The table-driven core of the omp anchor: derive it from caller-supplied
/// process data. [`anchor_for`](crate::anchored::anchor_for) runs it on the
/// live `/proc`; the injectable lookup is what lets miri and tests drive it.
#[doc(hidden)]
#[must_use]
pub fn omp_anchor_for_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<AnchoredPeer> {
    nearest_omp_with(pid, lookup).map(|(pid, start)| AnchoredPeer::new(pid, start))
}

/// Find the nearest omp ancestor of `pid` against caller-supplied process data.
///
/// It walks parent pids from any starting pid and knows nothing of a pinned
/// descriptor, so what it returns is pid and start-time evidence only.
#[doc(hidden)]
#[must_use]
pub fn nearest_omp_from_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<OmpProcess> {
    nearest_omp_with(pid, lookup).map(|(pid, start)| OmpProcess { pid, start })
}

/// Walk up from `pid`'s parent to the nearest process named `omp`, deciding on
/// the `omp` and recording the `start` of one `lookup` per process, so a pid
/// recycled between two reads cannot pair one process's name with another's
/// start time.
fn nearest_omp_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<(u32, u64)> {
    let parent = lookup(pid)?.parent;
    if parent <= 1 || parent == pid {
        return None;
    }

    let mut found = None;
    walk(parent, MAX_ANCESTRY_HOPS, |current| {
        let Some(process) = lookup(current) else {
            return Step::Stop;
        };
        if process.omp {
            found = Some((current, process.start));
            return Step::Match;
        }
        if process.parent <= 1 || process.parent == current {
            return Step::Stop;
        }
        Step::Continue(process.parent)
    });
    found
}

/// Whether a process name, the name field of `/proc/<pid>/stat`, is omp's:
/// exactly `omp`. The kernel sets the name at exec from the last part of the
/// executed file's path, cut to 15 bytes, and a process can change its own
/// name with `prctl(PR_SET_NAME)`; argv never counts. So `omp (deleted)` and
/// `omp daemon brok` are not omp, and an omp whose binary was deleted while it
/// runs, such as a pruned mise version, keeps its name and still counts. The
/// anchor walk, the pinned peer's walk and `session_label` all decide through
/// this one function.
pub(crate) fn is_omp_name(name: &str) -> bool {
    name == "omp"
}

fn read_process_state(pid: u32) -> Option<(u64, char)> {
    read_stat(pid).map(|stat| (stat.start, stat.state))
}

/// Parent, start time and the omp name test for `pid`, from one `stat` read,
/// with an empty argv.
///
/// The omp walk decides on the name in `stat` alone, and the broker runs it for
/// every ancestor of a caller while it holds its state lock, so it reads each
/// ancestor's `stat` only and never its command line.
pub(crate) fn stat_process(pid: u32) -> Option<Process> {
    read_stat(pid).map(|stat| Process {
        argv: Vec::new(),
        parent: stat.parent,
        start: stat.start,
        omp: stat.omp,
    })
}
