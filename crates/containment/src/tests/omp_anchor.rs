use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::Duration;

use super::SESSION;
use super::omp_walk::{is_omp, lookup, table};
use crate::anchored::{AnchoredPeer, anchor_for_with};
use crate::omp::{is_omp_executable, is_omp_name, nearest_omp_from_with, omp_anchor_for_with};

const GRANT: &[&str] = &["forward", "browser", "grant"];
const RPC: &[&str] = &["omp", "--model", "@default", "--mode", "rpc"];

#[test]
fn omp_anchor_cases_use_the_nearest_omp_executable() {
    let cases = [
        (
            "rpc omp directly above the command",
            table(&[(40, "forward", GRANT, 30, 400), (30, "omp", RPC, 1, 300)]),
            Some(AnchoredPeer::new(30, 300)),
            AnchoredPeer::new(30, 300),
        ),
        (
            "rpc omp above script and sh",
            table(&[
                (40, "forward", GRANT, 39, 400),
                (39, "sh", &["sh", "-c", "forward"], 38, 390),
                (38, "script", &["script", "-qec", "forward"], 30, 380),
                (30, "omp", RPC, 1, 300),
            ]),
            Some(AnchoredPeer::new(30, 300)),
            AnchoredPeer::new(30, 300),
        ),
        (
            "resume omp without an inner omp",
            table(&[
                (40, "forward", GRANT, 30, 400),
                (30, "omp", &["omp", "--resume", SESSION], 1, 300),
            ]),
            Some(AnchoredPeer::new(30, 300)),
            AnchoredPeer::new(30, 300),
        ),
        (
            "rpc omp inside a resume omp",
            table(&[
                (40, "forward", GRANT, 12, 400),
                (12, "sh", &["sh", "-c", "forward"], 11, 390),
                (11, "omp", &["omp", "--mode", "rpc"], 10, 380),
                (10, "omp", &["omp", "--resume", SESSION], 1, 300),
            ]),
            Some(AnchoredPeer::new(11, 380)),
            AnchoredPeer::new(11, 380),
        ),
        (
            "argv claims omp but its executable is not omp",
            table(&[
                (40, "forward", GRANT, 30, 400),
                (30, "sh", &["omp", "--resume", SESSION], 20, 300),
                (20, "sh", &["sh"], 1, 200),
            ]),
            None,
            AnchoredPeer::new(30, 300),
        ),
        (
            "no omp ancestor",
            table(&[
                (40, "forward", GRANT, 30, 400),
                (30, "sh", &["sh"], 20, 300),
                (20, "sshd", &["sshd"], 1, 200),
            ]),
            None,
            AnchoredPeer::new(30, 300),
        ),
    ];

    for (name, processes, expected_omp, expected_fallback) in cases {
        let omp = nearest_omp_from_with(
            40,
            &mut lookup(processes.clone()),
            &mut is_omp(processes.clone()),
        );
        let omp_anchor = omp_anchor_for_with(
            40,
            &mut lookup(processes.clone()),
            &mut is_omp(processes.clone()),
        );
        let anchor = anchor_for_with(40, &mut lookup(processes.clone()), &mut is_omp(processes));

        assert_eq!(
            omp_anchor,
            omp.map(|omp| AnchoredPeer::new(omp.pid, omp.start)),
            "{name}"
        );
        assert_eq!(anchor, omp_anchor.or(Some(expected_fallback)), "{name}");
        assert_eq!(omp_anchor, expected_omp, "{name}");
    }
}

#[test]
fn omp_anchor_admits_the_omp_process_and_rejects_a_reused_pid() {
    let processes = table(&[
        (40, "forward", &["forward"], 30, 400),
        (30, "omp", &["omp", "--mode", "rpc"], 1, 300),
    ]);
    let anchor = omp_anchor_for_with(
        40,
        &mut lookup(processes.clone()),
        &mut is_omp(processes.clone()),
    )
    .expect("omp anchor");

    assert!(anchor.contains_with(30, &mut lookup(processes.clone())));
    let mut recycled = processes;
    recycled.get_mut(&30).expect("omp entry").start = 301;
    assert!(!anchor.contains_with(30, &mut lookup(recycled)));
}

#[test]
fn omp_anchor_accepts_only_omp_or_the_kernels_deleted_omp_name() {
    let cases = [
        ("omp", true),
        ("omp (deleted)", true),
        ("omp (deleted)x", false),
        ("xomp (deleted)", false),
        ("omp (deleted) (deleted)", false),
        ("omp-wrapper", false),
        ("momp", false),
        ("omp ", false),
    ];

    for (name, expected) in cases {
        assert_eq!(is_omp_name(OsStr::new(name)), expected, "{name:?}");
    }
}

/// Run a copy of `/bin/sh` named `name` in `dir`, then delete the copy while
/// it runs. A test thread that forks while the copy is still open for writing
/// makes the exec fail with ETXTBSY for a moment, so the spawn retries that.
fn spawn_deleted_shell(dir: &Path, name: &str) -> Child {
    let path = dir.join(name);
    std::fs::copy("/bin/sh", &path).expect("copy /bin/sh");
    let child = (0..100)
        .find_map(
            |_| match Command::new(&path).args(["-c", "sleep 30; :"]).spawn() {
                Ok(child) => Some(child),
                Err(error) if error.raw_os_error() == Some(nix::libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(10));
                    None
                }
                Err(error) => panic!("spawn {}: {error}", path.display()),
            },
        )
        .expect("the copied shell started");
    std::fs::remove_file(&path).expect("delete the running copy");
    child
}

fn exe_link(child: &Child) -> PathBuf {
    std::fs::read_link(format!("/proc/{}/exe", child.id())).expect("read the exe link")
}

// Spawns processes and reads /proc, which miri's isolation cannot execute.
#[test]
#[cfg_attr(miri, ignore)]
fn omp_anchor_accepts_a_deleted_omp_binary() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut omp = spawn_deleted_shell(dir.path(), "omp");
    let mut other = spawn_deleted_shell(dir.path(), "xomp");

    let omp_link = exe_link(&omp);
    let other_link = exe_link(&other);
    let omp_accepted = is_omp_executable(omp.id());
    let other_accepted = is_omp_executable(other.id());
    for child in [&mut omp, &mut other] {
        let _ = child.kill();
        let _ = child.wait();
    }

    assert_eq!(omp_link.file_name(), Some(OsStr::new("omp (deleted)")));
    assert_eq!(other_link.file_name(), Some(OsStr::new("xomp (deleted)")));
    assert!(
        omp_accepted,
        "a running omp whose binary was deleted is omp"
    );
    assert!(!other_accepted, "a deleted xomp binary is not omp");
}
