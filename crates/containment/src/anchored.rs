//! Containment for a loopback TCP peer, anchored by pid and start time.
//!
//! A browser grant's endpoint is a loopback TCP listener, because a CDP client
//! cannot dial a unix socket. That rules out `SO_PEERPIDFD`: there is no pinned
//! descriptor for the far end of a TCP connection, so the pid is read after the
//! fact and could in principle be recycled. Pairing it with the kernel start
//! time is what closes that: a recycled pid has a later start time and fails the
//! comparison instead of inheriting authority.

use crate::omp::omp_anchor_for_with;
use crate::{MAX_ANCESTRY_HOPS, Step, walk};

/// One process as attribution needs it.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Process {
    /// Argument vector. **Forgeable**: any process can present any argv, so
    /// this is evidence for display, never for authorization on its own.
    pub argv: Vec<String>,
    /// Parent pid.
    pub parent: u32,
    /// Kernel start time, which distinguishes a recycled pid.
    pub start: u64,
    /// Whether the process is named `omp`: the name field of its
    /// `/proc/<pid>/stat` is exactly `omp`, from the same `stat` read as
    /// `parent` and `start`. A process can set its own name, so like argv
    /// this is evidence, not proof.
    pub omp: bool,
}

/// A process instance authorized to use a grant: pid plus kernel start time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct AnchoredPeer {
    /// The anchored pid.
    pub pid: u32,
    /// Its kernel start time.
    pub start: u64,
}

impl AnchoredPeer {
    /// Anchor a caller explicitly.
    #[must_use]
    pub const fn new(pid: u32, start: u64) -> Self {
        Self { pid, start }
    }

    /// Whether `pid` descends from this exact process instance.
    ///
    /// This is the authorization primitive for a grant's endpoint.
    #[must_use]
    pub fn contains(&self, pid: u32) -> bool {
        self.contains_with(pid, &mut read_process)
    }

    /// Test seam: walk a caller-supplied process table.
    ///
    /// Not only for tests: an injectable lookup is what lets the containment
    /// core run under miri, which cannot read `/proc`.
    #[doc(hidden)]
    #[must_use]
    pub fn contains_with(&self, pid: u32, lookup: &mut dyn FnMut(u32) -> Option<Process>) -> bool {
        walk(pid, MAX_ANCESTRY_HOPS, |current| {
            let Some(process) = lookup(current) else {
                return Step::Stop;
            };
            if current == self.pid {
                // The pid matches; authority depends on it being the *same*
                // process instance that was granted, not a recycled pid.
                return if process.start == self.start {
                    Step::Match
                } else {
                    Step::Stop
                };
            }
            if process.parent <= 1 {
                return Step::Stop;
            }
            Step::Continue(process.parent)
        })
    }
}

/// Derive the anchor a grant should record for `pid`.
///
/// A grant belongs to its nearest enclosing process named `omp`, the name in
/// its `/proc/<pid>/stat`, because a nested omp session is the narrowest real
/// subtree that can use it. Selection reads that name, never argv. Without an
/// omp ancestor, the immediate parent remains the fallback anchor.
#[must_use]
pub fn anchor_for(pid: u32) -> Option<AnchoredPeer> {
    anchor_for_with(pid, &mut read_process)
}

/// Test seam: derive against a caller-supplied lookup.
#[doc(hidden)]
#[must_use]
pub fn anchor_for_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<AnchoredPeer> {
    omp_anchor_for_with(pid, lookup).or_else(|| parent_anchor_with(pid, lookup))
}

/// Anchor `pid` to its immediate parent: the anchor a grant falls back to when
/// no process named `omp` encloses the command.
///
/// `None` when that parent is init or `pid` itself, which is a command whose
/// calling process has already gone, or when `/proc` cannot be read for `pid`
/// or its parent.
#[must_use]
pub fn parent_anchor_for(pid: u32) -> Option<AnchoredPeer> {
    parent_anchor_with(pid, &mut read_process)
}

/// Resolve the parent anchor against `lookup`.
fn parent_anchor_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<AnchoredPeer> {
    let parent = lookup(pid)?.parent;
    if parent <= 1 || parent == pid {
        return None;
    }
    lookup(parent).map(|process| AnchoredPeer::new(parent, process.start))
}

/// The omp session id `pid` belongs to, for logs and status output.
///
/// Display only, and it says so at every call site: the value is derived from
/// forgeable argv, and given only when the process that argv belongs to is
/// named `omp`. Authorization uses [`AnchoredPeer::contains`].
#[must_use]
pub fn session_label(pid: u32) -> Option<String> {
    session_label_with(pid, &mut read_process)
}

/// Test seam: resolve a label against a caller-supplied lookup.
#[doc(hidden)]
#[must_use]
pub fn session_label_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<String> {
    let mut current = pid;
    for _ in 0..MAX_ANCESTRY_HOPS {
        let process = lookup(current)?;
        if let Some(session) = session_of(&process) {
            return process.omp.then_some(session);
        }
        if process.parent <= 1 || process.parent == current {
            return None;
        }
        current = process.parent;
    }
    None
}

/// The kernel start time for `pid`, used to distinguish a reused pid.
#[must_use]
pub fn process_start(pid: u32) -> Option<u64> {
    read_process(pid).map(|process| process.start)
}

/// `omp --resume <uuid>` and nothing else. Another program taking `--resume`
/// must not be mistaken for a session.
fn session_of(process: &Process) -> Option<String> {
    let command = process.argv.first()?;
    if command != "omp" && !command.ends_with("/omp") {
        return None;
    }
    let mut arguments = process.argv.iter();
    while let Some(argument) = arguments.next() {
        if argument == "--resume" {
            return arguments
                .next()
                .filter(|value| is_session_id(value))
                .cloned();
        }
    }
    None
}

fn is_session_id(value: &str) -> bool {
    let groups = [8, 4, 4, 4, 12];
    let mut parts = value.split('-');
    groups.iter().all(|width| {
        parts.next().is_some_and(|part| {
            part.len() == *width && part.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    }) && parts.next().is_none()
}

/// Read one process out of `/proc`.
#[must_use]
pub fn read_process(pid: u32) -> Option<Process> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let stat = crate::read_stat(pid)?;
    Some(Process {
        argv,
        parent: stat.parent,
        start: stat.start,
        omp: stat.omp,
    })
}
