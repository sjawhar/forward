use super::process::{MAX_ANCESTRY_HOPS, Process, read_process};

/// The omp session `pid` belongs to, walking ancestry for worker processes.
///
/// This is for display and logging only. Authorization must use
/// `ancestry_contains` with the SO_PEERCRED process anchor; process arguments
/// can be forged even when the executable is genuine.
pub fn session_for_pid(pid: u32) -> Option<String> {
    session_for_pid_with_executable(pid, &mut read_process, &mut is_omp_executable)
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
