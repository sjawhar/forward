use super::process::{MAX_ANCESTRY_HOPS, Process, read_process};

/// The omp session `pid` belongs to, walking ancestry for worker processes.
///
/// This is for display and logging only. Authorization must use
/// `ancestry_contains` with the SO_PEERCRED process anchor; process arguments
/// can be forged even when the executable is genuine.
pub fn session_for_pid(pid: u32) -> Option<String> {
    session_for_pid_with_executable(pid, &mut read_process, &mut is_omp_executable)
}

/// The process anchor a grant should record for a caller.
///
/// A grant CLI is short lived, so authority belongs to its nearest enclosing
/// `omp --resume <uuid>` ancestor. Without one, the immediate parent is still
/// the narrowest real process subtree that can use the grant.
pub fn grant_anchor_for_pid(pid: u32) -> Option<(u32, u64)> {
    grant_anchor_for_pid_with(pid, &mut read_process)
}

fn grant_anchor_for_pid_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<(u32, u64)> {
    let parent = lookup(pid)?.parent;
    if parent <= 1 || parent == pid {
        return None;
    }
    let mut current = parent;
    let mut fallback = None;
    for _ in 0..MAX_ANCESTRY_HOPS {
        let process = match lookup(current) {
            Some(process) => process,
            None => break,
        };
        if current == parent {
            fallback = Some((current, process.start));
        }
        if session_of(&process).is_some() {
            return Some((current, process.start));
        }
        if process.parent <= 1 || process.parent == current {
            break;
        }
        current = process.parent;
    }
    fallback
}

/// Test seam: resolve against a caller-supplied process table.
#[doc(hidden)]
pub fn session_for_pid_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<String> {
    session_for_pid_with_executable(pid, lookup, &mut |_| true)
}

pub(super) fn session_for_pid_with_executable(
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    const SESSION: &str = "01a0223b-94d1-7000-bd0e-5038df7750b0";

    fn process(argv: &[&str], parent: u32, start: u64) -> Process {
        Process {
            argv: argv.iter().map(|value| (*value).to_owned()).collect(),
            parent,
            start,
        }
    }

    fn table(entries: Vec<(u32, Process)>) -> impl FnMut(u32) -> Option<Process> {
        let entries: HashMap<u32, Process> = entries.into_iter().collect();
        move |pid| entries.get(&pid).cloned()
    }

    #[test]
    fn grant_anchor_selects_the_nearest_omp_session_ancestor() {
        let mut lookup = table(vec![
            (13, process(&["forward", "browser", "grant"], 12, 10)),
            (12, process(&["sh", "-c", "forward"], 11, 20)),
            (11, process(&["omp", "--resume", SESSION], 10, 30)),
            (10, process(&["omp", "--resume", SESSION], 1, 40)),
        ]);
        assert_eq!(grant_anchor_for_pid_with(13, &mut lookup), Some((11, 30)));
    }

    #[test]
    fn grant_anchor_falls_back_to_the_callers_immediate_parent() {
        let mut lookup = table(vec![
            (12, process(&["forward", "browser", "grant"], 11, 10)),
            (11, process(&["sh", "-c", "forward"], 1, 20)),
        ]);
        assert_eq!(grant_anchor_for_pid_with(12, &mut lookup), Some((11, 20)));
    }
}
