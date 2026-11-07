use std::os::unix::net::{UnixListener, UnixStream};

use crate::pinned::{Liveness, PinnedPeer, descends_from_pid, parent_of};
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
    assert_eq!(peer.liveness(), Liveness::Running(own_pid()));
    assert_eq!(peer.pid(), Some(own_pid()));
    assert!(peer.is_alive());
}

#[test]
#[cfg_attr(miri, ignore)]
fn an_identity_that_cannot_be_read_is_unknown_rather_than_exited() {
    // An identity the kernel will not describe is not an identity that
    // has died, and that difference decides whether a live session's
    // registration may be taken away from it.
    let (peer, _directory) = connected_pair();
    assert_eq!(peer.liveness(), Liveness::Running(own_pid()));

    // A descriptor that is not a pidfd carries no `Pid:` field, the same
    // answer an `fdinfo` read that failed outright gives: nothing is
    // known. `pid` goes quiet, which is why `pid().is_none()` must never
    // be read as death.
    let non_pidfd = PinnedPeer::from_owned_fd(
        std::fs::File::open("/dev/null")
            .expect("open /dev/null")
            .into(),
    );

    assert_eq!(non_pidfd.liveness(), Liveness::Unknown);
    assert_eq!(non_pidfd.pid(), None);
    assert!(!non_pidfd.is_alive());
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
