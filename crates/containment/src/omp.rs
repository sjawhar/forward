//! Find the nearest enclosing `omp` process by executable name.

use crate::anchored::{AnchoredPeer, Process, read_process};
use crate::{Step, stat_fields, walk};

/// The anchored ancestry bound also limits omp discovery from a pinned peer.
const MAX_ANCESTRY_HOPS: usize = 12;

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

/// Derive an anchor from the nearest enclosing `omp` executable.
#[must_use]
pub fn omp_anchor_for(pid: u32) -> Option<AnchoredPeer> {
    nearest_omp_for(pid).map(|omp| AnchoredPeer::new(omp.pid, omp.start))
}

/// Find the nearest omp ancestor of `pid` on the live `/proc`.
pub(crate) fn nearest_omp_for(pid: u32) -> Option<OmpProcess> {
    nearest_omp_from_with(pid, &mut read_process, &mut is_omp_executable)
}

/// Test seam: derive an omp anchor against caller-supplied process data.
#[doc(hidden)]
#[must_use]
pub fn omp_anchor_for_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
    is_omp: &mut dyn FnMut(u32) -> bool,
) -> Option<AnchoredPeer> {
    nearest_omp_with(pid, lookup, is_omp).map(|(pid, start)| AnchoredPeer::new(pid, start))
}

/// Find the nearest omp ancestor of a pinned process.
#[doc(hidden)]
#[must_use]
pub fn nearest_omp_from_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
    is_omp: &mut dyn FnMut(u32) -> bool,
) -> Option<OmpProcess> {
    nearest_omp_with(pid, lookup, is_omp).map(|(pid, start)| OmpProcess { pid, start })
}

fn nearest_omp_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
    is_omp: &mut dyn FnMut(u32) -> bool,
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
        if is_omp(current) {
            // The candidate's executable is read between these two stat reads.
            // Reject a pid recycled during that interval.
            let Some(after_executable) = lookup(current) else {
                return Step::Stop;
            };
            if process.start != after_executable.start {
                return Step::Stop;
            }
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

/// Whether `pid`'s executable is named `omp`. Reads `/proc/<pid>/exe`, which
/// the process cannot forge, never its argv.
pub(crate) fn is_omp_executable(pid: u32) -> bool {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|executable| executable.file_name().map(|name| name == "omp"))
        .unwrap_or(false)
}

fn read_process_state(pid: u32) -> Option<(u64, char)> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let mut fields = stat_fields(&contents)?.split_whitespace();
    let state = fields.next()?.chars().next()?;
    let start = fields.nth(18)?.parse().ok()?;
    Some((start, state))
}
