//! Finding the detached relay a grant leaves behind, and what must be
//! true of it.

use forward::browser::grant::ProcessAnchor;

/// The relay this test's grant left behind.
///
/// Found by its anchor rather than by the socket it holds: the relay
/// suppresses its own core dumps, which also makes its `/proc/<pid>/fd`
/// unreadable to a same-uid process. The anchor is the one thing that
/// distinguishes it from any other machine's relay -- a relay of another
/// session is anchored to a tree this test process is not inside.
pub(super) fn relay_child() -> i32 {
    let mut found: Vec<i32> = Vec::new();
    for entry in std::fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse().ok())
        else {
            continue;
        };
        let Ok(cmdline) = std::fs::read(entry.path().join("cmdline")) else {
            continue;
        };
        let argv: Vec<String> = String::from_utf8_lossy(&cmdline)
            .split('\0')
            .map(str::to_owned)
            .collect();
        if !argv.iter().any(|word| word == "relay") || !argv.iter().any(|word| word == "browser") {
            continue;
        }
        if anchor_of(&argv).is_some_and(|anchor| anchor.contains(std::process::id())) {
            found.push(pid);
        }
    }
    match found.as_slice() {
        [pid] => *pid,
        other => panic!("expected exactly one relay for this session, found {other:?}"),
    }
}

fn anchor_of(argv: &[String]) -> Option<ProcessAnchor> {
    let field = |flag: &str| {
        argv.iter()
            .position(|word| word == flag)
            .and_then(|at| argv.get(at + 1))
            .map(String::as_str)
    };
    Some(ProcessAnchor::new(
        field("--anchor-pid")?.parse().ok()?,
        field("--anchor-start")?.parse().ok()?,
    ))
}

/// The relay must outlive the terminal that ran the grant, and `setsid` is the
/// only thing that makes it so. Nothing else this test does would notice its
/// absence: the grant would simply die on the next SIGHUP in real use.
pub(super) fn assert_is_a_session_leader(pid: i32) {
    // SAFETY: `getsid` reads scheduling state for a pid and changes nothing.
    let session = unsafe { nix::libc::getsid(pid) };
    assert_eq!(
        session, pid,
        "the relay child did not start its own session"
    );
    // SAFETY: as above, for this process.
    let ours = unsafe { nix::libc::getsid(0) };
    assert_ne!(session, ours, "the relay child shares this test's session");
}
