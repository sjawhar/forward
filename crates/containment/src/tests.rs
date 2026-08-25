use std::collections::HashMap;

use crate::anchored::{AnchoredPeer, Process, anchor_for_with, process_start, session_label_with};

fn process(argv: &[&str], parent: u32, start: u64) -> Process {
    Process {
        argv: argv.iter().map(|part| (*part).to_owned()).collect(),
        parent,
        start,
    }
}

const SESSION: &str = "01a0223b-94d1-7000-bd0e-5038df7750b0";

/// pid 40 is a worker under `omp --resume` (pid 30) under a shell (pid 20).
fn tree() -> HashMap<u32, Process> {
    HashMap::from([
        (40, process(&["worker"], 30, 4_000)),
        (30, process(&["omp", "--resume", SESSION], 20, 3_000)),
        (20, process(&["bash"], 1, 2_000)),
    ])
}

fn lookup(table: HashMap<u32, Process>) -> impl FnMut(u32) -> Option<Process> {
    move |pid| table.get(&pid).cloned()
}

#[test]
fn ancestry_requires_the_same_process_instance_not_just_the_pid() {
    let anchor = AnchoredPeer::new(30, 3_000);

    assert!(anchor.contains_with(40, &mut lookup(tree())));
    // Same pid, different start time: a recycled pid must not inherit the
    // grant.
    let recycled = AnchoredPeer::new(30, 9_999);
    assert!(!recycled.contains_with(40, &mut lookup(tree())));
}

#[test]
fn ancestry_stops_at_the_hop_cap_and_survives_a_cycle() {
    // 10 -> 11 -> 10 is a cycle; the visited set must end the walk rather than
    // spin to the cap.
    let cyclic = HashMap::from([(10, process(&["a"], 11, 1)), (11, process(&["b"], 10, 2))]);
    let anchor = AnchoredPeer::new(99, 1);

    assert!(!anchor.contains_with(10, &mut lookup(cyclic)));
}

#[test]
fn an_unreadable_process_refuses_rather_than_continuing() {
    let anchor = AnchoredPeer::new(30, 3_000);

    // pid 41 is not in the table at all.
    assert!(!anchor.contains_with(41, &mut lookup(tree())));
}

#[test]
fn the_anchor_is_the_enclosing_session_when_its_executable_is_omp() {
    let anchor =
        anchor_for_with(40, &mut lookup(tree()), &mut |pid| pid == 30).expect("anchor resolves");

    assert_eq!(anchor, AnchoredPeer::new(30, 3_000));
}

#[test]
fn a_forged_session_argv_cannot_widen_the_anchor() {
    // pid 30 presents `omp --resume <uuid>` but its executable is not omp.
    // Before the executable check was fused into anchor derivation, this
    // returned pid 30 and anchored the grant to a subtree the forger controls.
    // The narrower fallback -- the immediate parent -- is the correct answer.
    let anchor = anchor_for_with(40, &mut lookup(tree()), &mut |_| false).expect("fallback");

    assert_eq!(
        anchor,
        AnchoredPeer::new(30, 3_000),
        "the immediate parent of the caller is the fallback anchor"
    );
    // And the label, which is display-only, refuses it outright.
    assert_eq!(
        session_label_with(40, &mut lookup(tree()), &mut |_| false),
        None
    );
}

#[test]
fn the_anchor_falls_back_to_the_immediate_parent_without_a_session() {
    let plain = HashMap::from([
        (40, process(&["worker"], 30, 4_000)),
        (30, process(&["bash"], 20, 3_000)),
        (20, process(&["sshd"], 1, 2_000)),
    ]);

    let anchor = anchor_for_with(40, &mut lookup(plain), &mut |_| true).expect("fallback");

    assert_eq!(anchor, AnchoredPeer::new(30, 3_000));
}

#[test]
fn a_caller_whose_parent_is_init_has_no_anchor() {
    let orphan = HashMap::from([(40, process(&["worker"], 1, 4_000))]);

    assert!(anchor_for_with(40, &mut lookup(orphan), &mut |_| true).is_none());
}

#[test]
fn the_session_label_matches_only_omp_resume_with_a_session_id() {
    let cases: [(&[&str], bool); 5] = [
        (&["omp", "--resume", SESSION], true),
        (&["/usr/bin/omp", "--resume", SESSION], true),
        // Another program taking --resume is not a session.
        (&["other", "--resume", SESSION], false),
        // omp without --resume is not a session.
        (&["omp", "run"], false),
        // --resume without a well-formed session id is not a session.
        (&["omp", "--resume", "not-a-uuid"], false),
    ];

    for (argv, expected) in cases {
        let table = HashMap::from([(40, process(argv, 1, 1))]);
        let resolved = session_label_with(40, &mut lookup(table), &mut |_| true);
        assert_eq!(resolved.is_some(), expected, "argv {argv:?}");
    }
}

/// A chain longer than the 12-hop cap: the walk must give up rather than
/// keep climbing, in both the authorization and the labelling direction.
fn deep_chain(depth: u32) -> HashMap<u32, Process> {
    // pid `depth` is the caller and each pid's parent is the next one down, so
    // pid 2 is the session root and the caller sits `depth - 2` hops below it.
    // The root is pid 2, not 1: a walk stops when it sees `parent <= 1`, so a
    // root at pid 1 is never examined.
    let mut table = HashMap::new();
    for pid in 2..=depth {
        let argv: &[&str] = if pid == 2 {
            &["omp", "--resume", SESSION]
        } else {
            &["worker"]
        };
        table.insert(pid, process(argv, pid.saturating_sub(1), u64::from(pid)));
    }
    table
}

#[test]
fn over_deep_ancestry_is_not_authorized() {
    // The session root is pid 1, thirty hops above the caller.
    let anchor = AnchoredPeer::new(2, 2);

    assert!(!anchor.contains_with(30, &mut lookup(deep_chain(30))));
    // The same anchor within the cap resolves, so this is the cap and not a
    // broken table.
    assert!(anchor.contains_with(8, &mut lookup(deep_chain(30))));
}

#[test]
fn over_deep_ancestry_does_not_reach_a_session() {
    assert_eq!(
        session_label_with(30, &mut lookup(deep_chain(30)), &mut |_| true),
        None
    );
    assert_eq!(
        session_label_with(8, &mut lookup(deep_chain(30)), &mut |_| true).as_deref(),
        Some(SESSION)
    );
}

// A resolver front-end: spawns a process and reads /proc, neither of which
// miri's isolation can execute (spec §9).
#[test]
#[cfg_attr(miri, ignore)]
fn a_real_child_process_resolves_as_a_descendant_of_this_process() {
    // The injected-table tests above pin the policy; this one pins that the
    // production `/proc` reader agrees with it on a real process tree.
    let child = std::process::Command::new("sleep")
        .arg("30")
        .spawn()
        .expect("spawn a child");
    let child_pid = child.id();
    let own_pid = std::process::id();
    let own_start = process_start(own_pid).expect("this process has a start time");

    let anchor = AnchoredPeer::new(own_pid, own_start);
    let authorized = anchor.contains(child_pid);

    let mut child = child;
    let _ = child.kill();
    let _ = child.wait();

    assert!(authorized, "a spawned child must descend from this process");
}

// Also a resolver front-end: reads the live /proc process table.
#[test]
#[cfg_attr(miri, ignore)]
fn process_start_reads_the_live_process_table() {
    let first = process_start(std::process::id()).expect("start time");
    let second = process_start(std::process::id()).expect("start time");

    // Stable across reads: it is what distinguishes this process instance from
    // a future one that reuses the pid.
    assert_eq!(first, second);
    assert!(process_start(u32::MAX).is_none());
}

#[test]
fn the_anchor_selects_the_nearest_session_ancestor_not_the_outermost() {
    // Nested sessions: the grant belongs to the innermost enclosing one, so a
    // nested agent cannot anchor its grant to its parent session's whole tree.
    let nested = HashMap::from([
        (13, process(&["forward", "browser", "grant"], 12, 10)),
        (12, process(&["sh", "-c", "forward"], 11, 20)),
        (11, process(&["omp", "--resume", SESSION], 10, 30)),
        (10, process(&["omp", "--resume", SESSION], 1, 40)),
    ]);

    let anchor = anchor_for_with(13, &mut lookup(nested), &mut |_| true).expect("anchor");

    assert_eq!(anchor, AnchoredPeer::new(11, 30));
}

#[test]
fn the_anchor_falls_back_to_the_callers_immediate_parent() {
    let no_session = HashMap::from([
        (12, process(&["forward", "browser", "grant"], 11, 10)),
        (11, process(&["sh", "-c", "forward"], 1, 20)),
    ]);

    let anchor = anchor_for_with(12, &mut lookup(no_session), &mut |_| true).expect("fallback");

    assert_eq!(anchor, AnchoredPeer::new(11, 20));
}

mod pinned_peer {
    use std::os::unix::net::{UnixListener, UnixStream};

    use crate::pinned::{PinnedPeer, descends_from_pid, parent_of};
    use crate::status_field;

    /// This process's pid as the signed value `/proc` uses.
    fn own_pid() -> i32 {
        i32::try_from(std::process::id()).expect("pid fits in i32")
    }

    /// Connect to a throwaway socket and return the accepted end's identity.
    fn connected_pair() -> (PinnedPeer, tempfile::TempDir) {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("peer.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let client = UnixStream::connect(&socket).unwrap();
        let (accepted, _) = listener.accept().unwrap();
        // Keep the client alive so the pinned process (this test) stays running.
        drop(client);
        (PinnedPeer::from_stream(&accepted).unwrap(), directory)
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn pins_the_connecting_process() {
        let (peer, _directory) = connected_pair();

        // Both ends are this test process, so the pinned pid must be our own.
        assert_eq!(peer.pid(), Some(own_pid()));
        assert!(peer.is_alive());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_peer_descends_from_itself() {
        let (peer, _directory) = connected_pair();

        // A session's own process legitimately requests its own secrets.
        assert!(peer.descends_from(&peer));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn walks_parents_to_find_an_ancestor() {
        // This process descends from pid 1 on any normal system.
        assert!(descends_from_pid(own_pid(), 1));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn a_process_does_not_descend_from_an_unrelated_pid() {
        // pid 0 is never a real ancestor, so the walk must terminate false
        // rather than climbing forever.
        assert!(!descends_from_pid(own_pid(), 0));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn an_unreadable_pid_denies_rather_than_assuming_kinship() {
        // A pid that cannot exist has no /proc entry; failing to read it must
        // not be treated as a match.
        assert!(!descends_from_pid(i32::MAX, 1));
        assert_eq!(parent_of(i32::MAX), None);
    }

    #[test]
    fn parses_kernel_written_fdinfo_fields() {
        let status = "Name:\tbash\nPid:\t4242\nPPid:\t99\n";

        assert_eq!(status_field(status, "Pid:"), Some(4242));
        assert_eq!(status_field(status, "Absent:"), None);
    }

    #[test]
    fn a_forged_comm_cannot_supply_the_parent_pid() {
        // A process controls its own comm. In `status` the comm precedes
        // `PPid:`, so a prefix match would read a forged line — the parse
        // must come from `stat`, positionally, after the last `)`.
        let forged = "Name:\tx\nPPid:\t1\nPid:\t4242\nPPid:\t99\n";
        assert_eq!(status_field(forged, "PPid:"), Some(1));

        // The same forgery inside a real stat line cannot move the field:
        // comm is `x) 1 1 1 1 1 1 1` and the true ppid is 99.
        let stat = "4242 (x) 1 1 1 1 1 1 1) S 99 4242 4242 0";
        let tail = crate::stat_fields(stat).expect("fields after the comm");
        assert_eq!(tail.split_whitespace().nth(1), Some("99"));
    }

    #[test]
    fn stat_fields_needs_a_closing_comm_paren() {
        assert_eq!(crate::stat_fields("4242 (truncated"), None);
    }
}
