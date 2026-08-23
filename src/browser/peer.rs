mod process;
mod session;
mod socket;

pub use process::{
    Process, ancestry_contains, ancestry_contains_with, process_start, process_start_with,
};
pub use session::{session_for_pid, session_for_pid_with};
pub use socket::pid_for_connection;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::{TcpListener, TcpStream};
    use std::process::Command;

    fn process(argv: &[&str], parent: u32) -> Process {
        process_with_start(argv, parent, 1)
    }

    fn process_with_start(argv: &[&str], parent: u32, start: u64) -> Process {
        Process {
            argv: argv.iter().map(|value| (*value).to_owned()).collect(),
            parent,
            start,
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
    fn process_start_reads_an_injectable_process_table() {
        let mut lookup = table(&[(10, process_with_start(&["worker"], 1, 42))]);
        assert_eq!(process_start_with(10, &mut lookup), Some(42));
    }

    #[test]
    fn a_live_child_process_resolves_as_a_descendant_of_this_process() {
        let parent = std::process::id();
        let parent_start = process_start(parent).unwrap();
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let contains_parent = ancestry_contains(child.id(), parent, parent_start);
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(contains_parent);
    }

    #[test]
    fn a_non_descendant_is_not_an_authorized_ancestor() {
        let mut lookup = table(&[
            (10, process_with_start(&["worker"], 1, 50)),
            (20, process_with_start(&["other"], 1, 60)),
        ]);
        assert!(!ancestry_contains_with(10, 20, 60, &mut lookup));
    }

    #[test]
    fn a_matching_pid_with_a_mismatched_start_time_is_not_authorized() {
        let mut lookup = table(&[
            (12, process_with_start(&["worker"], 10, 50)),
            (10, process_with_start(&["omp"], 1, 60)),
        ]);
        assert!(!ancestry_contains_with(12, 10, 61, &mut lookup));
    }

    #[test]
    fn an_unreadable_process_mid_walk_is_not_authorized() {
        let mut lookup = table(&[(12, process_with_start(&["worker"], 11, 50))]);
        assert!(!ancestry_contains_with(12, 10, 60, &mut lookup));
    }

    #[test]
    fn an_ancestry_cycle_is_not_authorized() {
        let mut lookup = table(&[
            (10, process_with_start(&["a"], 11, 50)),
            (11, process_with_start(&["b"], 10, 60)),
        ]);
        assert!(!ancestry_contains_with(10, 12, 70, &mut lookup));
    }

    #[test]
    fn over_deep_ancestry_is_not_authorized() {
        let mut entries = (1..=13)
            .map(|pid| (pid, process_with_start(&["worker"], pid - 1, pid as u64)))
            .collect::<Vec<_>>();
        entries[0] = (1, process_with_start(&["ancestor"], 0, 77));
        let mut lookup = table(&entries);
        assert!(!ancestry_contains_with(13, 1, 77, &mut lookup));
    }

    #[test]
    fn display_resolution_checks_the_session_candidate_executable() {
        let mut lookup = table(&[
            (12, process(&["worker"], 10)),
            (
                10,
                process(
                    &["omp", "--resume", "01a0223b-94d1-7000-bd0e-5038df7750b0"],
                    1,
                ),
            ),
        ]);
        let mut is_omp = |pid| pid == 10;
        assert_eq!(
            super::session::session_for_pid_with_executable(12, &mut lookup, &mut is_omp)
                .as_deref(),
            Some("01a0223b-94d1-7000-bd0e-5038df7750b0")
        );
        let mut not_omp = |_| false;
        assert_eq!(
            super::session::session_for_pid_with_executable(12, &mut lookup, &mut not_omp),
            None
        );
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
