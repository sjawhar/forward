//! Containment for a loopback TCP peer, anchored by pid and start time.
//!
//! The browser grant proxy is a loopback TCP listener, because a CDP client
//! cannot dial a unix socket. That rules out `SO_PEERPIDFD`: there is no pinned
//! descriptor for the far end of a TCP connection, so the pid is read after the
//! fact and could in principle be recycled. Pairing it with the kernel start
//! time is what closes that: a recycled pid has a later start time and fails the
//! comparison instead of inheriting authority.

use crate::{Step, walk};

/// Longest ancestry walk before giving up. A worker nested deeper than this is
/// not a session's child in any arrangement we run.
const MAX_ANCESTRY_HOPS: usize = 12;

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
    /// This is the authorization primitive for the grant proxy.
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

/// Derive the anchor a grant should record for `pid`, verifying the executable.
///
/// A grant CLI is short lived, so authority belongs to its nearest enclosing
/// `omp --resume <uuid>` ancestor; without one, the immediate parent is still
/// the narrowest real subtree that can use the grant.
///
/// The session shape is matched on **argv**, which is forgeable, so this
/// verifies `/proc/<pid>/exe` for any candidate it selects on that basis. That
/// check used to live in a separate function which the request path happened to
/// call first; two coupled functions where only the call ordering saves you is
/// exactly the arrangement this crate exists to eliminate. It is fused here, so
/// the anchor cannot be obtained without it.
#[must_use]
pub fn anchor_for(pid: u32) -> Option<AnchoredPeer> {
    anchor_for_with(pid, &mut read_process, &mut is_omp_executable)
}

/// Test seam: derive against caller-supplied lookups.
#[doc(hidden)]
#[must_use]
pub fn anchor_for_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
    is_omp: &mut dyn FnMut(u32) -> bool,
) -> Option<AnchoredPeer> {
    let parent = lookup(pid)?.parent;
    if parent <= 1 || parent == pid {
        return None;
    }
    let mut current = parent;
    let mut fallback = None;
    for _ in 0..MAX_ANCESTRY_HOPS {
        let Some(process) = lookup(current) else {
            break;
        };
        if current == parent {
            fallback = Some(AnchoredPeer::new(current, process.start));
        }
        // An argv-selected candidate is only accepted once its executable is
        // confirmed, so a process presenting a forged `omp --resume` argv
        // cannot widen the anchor to a subtree it controls.
        if session_of(&process).is_some() && is_omp(current) {
            return Some(AnchoredPeer::new(current, process.start));
        }
        if process.parent <= 1 || process.parent == current {
            break;
        }
        current = process.parent;
    }
    fallback
}

/// The omp session id `pid` belongs to, for logs and status output.
///
/// Display only, and it says so at every call site: the value is derived from
/// forgeable argv. Authorization uses [`AnchoredPeer::contains`].
#[must_use]
pub fn session_label(pid: u32) -> Option<String> {
    session_label_with(pid, &mut read_process, &mut is_omp_executable)
}

/// Test seam: resolve a label against caller-supplied lookups.
#[doc(hidden)]
#[must_use]
pub fn session_label_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
    is_omp: &mut dyn FnMut(u32) -> bool,
) -> Option<String> {
    let mut current = pid;
    for _ in 0..MAX_ANCESTRY_HOPS {
        let process = lookup(current)?;
        if let Some(session) = session_of(&process) {
            return is_omp(current).then_some(session);
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

fn is_omp_executable(pid: u32) -> bool {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .and_then(|executable| executable.file_name().map(|name| name == "omp"))
        .unwrap_or(false)
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
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // Fields start at stat field 3: PPID is index 1 and start time is 19.
    let fields_begin = stat.rfind(')')?.checked_add(2)?;
    let tail = stat.get(fields_begin..)?;
    let parent = tail.split_whitespace().nth(1)?.parse().ok()?;
    let started = tail.split_whitespace().nth(19)?.parse().ok()?;
    Some(Process {
        argv,
        parent,
        start: started,
    })
}
