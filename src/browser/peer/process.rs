/// Longest ancestry walk before giving up. A worker nested deeper than this is
/// not a session's child in any arrangement we run, and the cap makes a `PPID`
/// cycle terminate.
pub(super) const MAX_ANCESTRY_HOPS: usize = 12;

/// One process as attribution needs it.
#[derive(Clone, Debug)]
pub struct Process {
    pub argv: Vec<String>,
    pub parent: u32,
    pub start: u64,
}

/// The kernel start time for `pid`, used to distinguish a reused pid.
pub fn process_start(pid: u32) -> Option<u64> {
    process_start_with(pid, &mut read_process)
}

/// Test seam: read a start time from a caller-supplied process table.
#[doc(hidden)]
pub fn process_start_with(pid: u32, lookup: &mut dyn FnMut(u32) -> Option<Process>) -> Option<u64> {
    lookup(pid).map(|process| process.start)
}

/// Whether `pid` descends from the exact process identified by pid and start.
///
/// This is the authorization primitive. The anchor must come from the
/// SO_PEERCRED pid captured while granting access, not from process arguments.
pub fn ancestry_contains(pid: u32, ancestor: u32, ancestor_start: u64) -> bool {
    ancestry_contains_with(pid, ancestor, ancestor_start, &mut read_process)
}

/// Test seam: walk a caller-supplied process table.
#[doc(hidden)]
pub fn ancestry_contains_with(
    pid: u32,
    ancestor: u32,
    ancestor_start: u64,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> bool {
    let mut current = pid;
    let mut visited = Vec::with_capacity(MAX_ANCESTRY_HOPS);
    for _ in 0..MAX_ANCESTRY_HOPS {
        if visited.contains(&current) {
            return false;
        }
        visited.push(current);
        let Some(process) = lookup(current) else {
            return false;
        };
        if current == ancestor {
            return process.start == ancestor_start;
        }
        if process.parent <= 1 {
            return false;
        }
        current = process.parent;
    }
    false
}

pub(super) fn read_process(pid: u32) -> Option<Process> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm can contain spaces and parentheses, so fields follow the final ')'.
    // Those fields start at stat field 3: PPID is index 1 and start time is 19.
    let tail = stat.get(stat.rfind(')')? + 2..)?;
    let parent = tail.split_whitespace().nth(1)?.parse().ok()?;
    let start = tail.split_whitespace().nth(19)?.parse().ok()?;
    Some(Process {
        argv,
        parent,
        start,
    })
}
