//! Finding the detached relay a grant leaves behind, and what must be
//! true of it.

use forward::browser::grant::ProcessAnchor;
use forward::browser::peer::{omp_anchor_for, process_start};

/// The relay this test's grant left behind.
///
/// Relays cannot be distinguished by their socket: core-dump suppression also
/// makes `/proc/<pid>/fd` unreadable to this process. The exact anchor and a
/// start time no earlier than this grant command identify this test's relay,
/// even when several grants share the enclosing omp process.
pub(super) fn relay_child(grant_start: u64) -> i32 {
    let expected_anchor = anchor_for_grant_child();
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
        let Some(anchor) = anchor_of(&argv) else {
            continue;
        };
        let Some(relay_start) = u32::try_from(pid).ok().and_then(process_start) else {
            continue;
        };
        // Kernel start times have tick resolution, so a relay and its parent
        // may share a tick. Equality still proves the relay did not predate it.
        if anchor == expected_anchor && relay_start >= grant_start {
            found.push(pid);
        }
    }
    match found.as_slice() {
        [pid] => *pid,
        other => panic!("expected exactly one relay for this grant, found {other:?}"),
    }
}

/// Derive the anchor a command directly below this test process must receive.
fn anchor_for_grant_child() -> ProcessAnchor {
    let pid = std::process::id();
    omp_anchor_for(pid).unwrap_or_else(|| ProcessAnchor::new(pid, process_start(pid).unwrap()))
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
