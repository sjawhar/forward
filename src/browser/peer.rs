mod socket;

pub use socket::pid_for_connection;

/// Longest ancestry walk before giving up. A worker nested deeper than this is
/// not a session's child in any arrangement we run, and the cap makes a `PPID`
/// cycle terminate.
const MAX_ANCESTRY_HOPS: usize = 12;

/// One process as attribution needs it.
#[derive(Clone, Debug)]
pub struct Process {
    pub argv: Vec<String>,
    pub parent: u32,
}

/// The omp session `pid` belongs to, walking ancestry for worker processes.
pub fn session_for_pid(pid: u32) -> Option<String> {
    session_for_pid_with(pid, &mut read_process)
}

/// Test seam: resolve against a caller-supplied process table.
#[doc(hidden)]
pub fn session_for_pid_with(
    pid: u32,
    lookup: &mut dyn FnMut(u32) -> Option<Process>,
) -> Option<String> {
    let mut current = pid;
    for _ in 0..MAX_ANCESTRY_HOPS {
        let process = lookup(current)?;
        if let Some(session) = session_of(&process) {
            return Some(session);
        }
        if process.parent <= 1 || process.parent == current {
            return None;
        }
        current = process.parent;
    }
    None
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

fn read_process(pid: u32) -> Option<Process> {
    let raw = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let argv = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // comm can contain spaces and parentheses, so PPID is located from the last
    // ')' rather than by splitting the whole line.
    let tail = stat.get(stat.rfind(')')? + 2..)?;
    let parent = tail.split_whitespace().nth(1)?.parse().ok()?;
    Some(Process { argv, parent })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{TcpListener, TcpStream};

    fn process(argv: &[&str], parent: u32) -> Process {
        Process {
            argv: argv.iter().map(|value| (*value).to_owned()).collect(),
            parent,
        }
    }

    fn table(entries: &[(u32, Process)]) -> impl FnMut(u32) -> Option<Process> + 'static {
        let map: HashMap<u32, Process> = entries.iter().cloned().collect();
        move |pid| map.get(&pid).cloned()
    }

    #[test]
    fn a_session_process_resolves_to_its_own_session() {
        let mut lookup = table(&[(
            10,
            process(
                &[
                    "/opt/omp",
                    "--resume",
                    "01a0223b-94d1-7000-bd0e-5038df7750b0",
                ],
                1,
            ),
        )]);
        assert_eq!(
            session_for_pid_with(10, &mut lookup).as_deref(),
            Some("01a0223b-94d1-7000-bd0e-5038df7750b0")
        );
    }

    #[test]
    fn a_descendant_resolves_through_its_ancestry() {
        let mut lookup = table(&[
            (12, process(&["python3", "browser-capture"], 11)),
            (11, process(&["bash", "-c", "…"], 10)),
            (
                10,
                process(
                    &[
                        "/opt/omp",
                        "--resume",
                        "01a0223b-94d1-7000-bd0e-5038df7750b0",
                    ],
                    1,
                ),
            ),
        ]);
        assert_eq!(
            session_for_pid_with(12, &mut lookup).as_deref(),
            Some("01a0223b-94d1-7000-bd0e-5038df7750b0")
        );
    }

    #[test]
    fn a_process_outside_any_session_resolves_to_nothing() {
        let mut lookup = table(&[(10, process(&["curl", "http://127.0.0.1:12811"], 1))]);
        assert_eq!(session_for_pid_with(10, &mut lookup), None);
    }

    #[test]
    fn a_non_omp_resume_flag_is_not_a_session() {
        // Another program may take --resume; only omp's counts.
        let mut lookup = table(&[(
            10,
            process(
                &[
                    "/usr/bin/wget",
                    "--resume",
                    "01a0223b-94d1-7000-bd0e-5038df7750b0",
                ],
                1,
            ),
        )]);
        assert_eq!(session_for_pid_with(10, &mut lookup), None);
    }

    #[test]
    fn a_malformed_resume_value_is_not_a_session() {
        let mut lookup = table(&[(10, process(&["omp", "--resume", "not-a-session-id"], 1))]);
        assert_eq!(session_for_pid_with(10, &mut lookup), None);
    }

    #[test]
    fn a_parent_cycle_terminates() {
        let mut lookup = table(&[(10, process(&["a"], 11)), (11, process(&["b"], 10))]);
        assert_eq!(session_for_pid_with(10, &mut lookup), None);
    }

    #[test]
    fn over_deep_ancestry_does_not_reach_a_session() {
        let mut entries = (1..=13)
            .map(|pid| (pid, process(&["worker"], pid - 1)))
            .collect::<Vec<_>>();
        entries[0] = (
            1,
            process(
                &["omp", "--resume", "01a0223b-94d1-7000-bd0e-5038df7750b0"],
                0,
            ),
        );
        let mut lookup = table(&entries);
        assert_eq!(session_for_pid_with(13, &mut lookup), None);
    }

    #[test]
    fn a_live_loopback_connection_resolves_to_this_process() {
        // Given: a loopback connection this test process owns both ends of.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let local = match listener.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            other => panic!("expected IPv4, got {other}"),
        };
        let client = TcpStream::connect(local).unwrap();
        let (_server, _) = listener.accept().unwrap();
        let peer = match client.local_addr().unwrap() {
            std::net::SocketAddr::V4(address) => address,
            other => panic!("expected IPv4, got {other}"),
        };

        // When/Then: the client socket resolves to this process.
        assert_eq!(pid_for_connection(peer, local), Some(std::process::id()));
    }
}
