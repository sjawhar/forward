use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use super::SESSION;
use super::omp_walk::{lookup, table};
use crate::anchored::{AnchoredPeer, anchor_for_with, read_process};
use crate::omp::{nearest_omp_from_with, omp_anchor_for_with, stat_process};

const GRANT: &[&str] = &["forward", "browser", "grant"];
const RPC: &[&str] = &["omp", "--model", "@default", "--mode", "rpc"];

#[test]
fn omp_anchor_cases_use_the_nearest_process_named_omp() {
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
            "named omp whatever its argv says",
            table(&[
                (40, "forward", GRANT, 30, 400),
                (30, "omp", &["bun", "cli.js"], 1, 300),
            ]),
            Some(AnchoredPeer::new(30, 300)),
            AnchoredPeer::new(30, 300),
        ),
        (
            "argv claims omp but its name is not omp",
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
        let omp = nearest_omp_from_with(40, &mut lookup(processes.clone()));
        let omp_anchor = omp_anchor_for_with(40, &mut lookup(processes.clone()));
        let anchor = anchor_for_with(40, &mut lookup(processes));

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
    let anchor = omp_anchor_for_with(40, &mut lookup(processes.clone())).expect("omp anchor");

    assert!(anchor.contains_with(30, &mut lookup(processes.clone())));
    let mut recycled = processes;
    recycled.get_mut(&30).expect("omp entry").start = 301;
    assert!(!anchor.contains_with(30, &mut lookup(recycled)));
}

/// Copy `/bin/sh` to `dir/name`. The copy keeps the mode of `/bin/sh`, so it
/// runs.
fn copy_shell(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::copy("/bin/sh", &path).expect("copy /bin/sh");
    path
}

/// Run `program -c 'read -r line'` with argv[0] `arg0`. The shell waits on its
/// stdin pipe and starts no child, so killing it leaves nothing running. A
/// test thread that forks while a copy is still open for writing makes the
/// exec fail with ETXTBSY for a moment, so the spawn retries that.
fn spawn_shell(program: &Path, arg0: &str) -> Child {
    (0..100)
        .find_map(|_| {
            let spawned = Command::new(program)
                .arg0(arg0)
                .args(["-c", "read -r line"])
                .stdin(Stdio::piped())
                .spawn();
            match spawned {
                Ok(child) => Some(child),
                Err(error) if error.raw_os_error() == Some(nix::libc::ETXTBSY) => {
                    std::thread::sleep(Duration::from_millis(10));
                    None
                }
                Err(error) => panic!("spawn {}: {error}", program.display()),
            }
        })
        .expect("the shell started")
}

/// Whether `child` is omp, as the walk's `stat` read and the full read each
/// see it.
fn omp_reads(child: &Child) -> (Option<bool>, Option<bool>) {
    (
        stat_process(child.id()).map(|process| process.omp),
        read_process(child.id()).map(|process| process.omp),
    )
}

fn stop(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

// Spawns processes and reads /proc, which miri's isolation cannot execute.
#[test]
#[cfg_attr(miri, ignore)]
fn a_copy_of_a_binary_named_omp_is_omp_before_and_after_its_file_is_deleted() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = copy_shell(dir.path(), "omp");
    // argv[0] is `sh`, so only the file name can make this process omp.
    let mut omp = spawn_shell(&path, "sh");
    let before = omp_reads(&omp);
    let deleted = std::fs::remove_file(&path);
    let after = omp_reads(&omp);
    stop(&mut omp);

    deleted.expect("delete the running copy");
    assert_eq!(before, (Some(true), Some(true)), "a process named omp");
    assert_eq!(
        after,
        (Some(true), Some(true)),
        "an omp whose binary was deleted keeps its name"
    );
}

// Spawns processes and reads /proc, which miri's isolation cannot execute.
#[test]
#[cfg_attr(miri, ignore)]
fn argv_zero_omp_and_a_copy_named_xomp_are_not_omp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut renamed = spawn_shell(Path::new("/bin/sh"), "omp");
    let mut other = spawn_shell(&copy_shell(dir.path(), "xomp"), "omp");
    let renamed_reads = omp_reads(&renamed);
    let other_reads = omp_reads(&other);
    stop(&mut renamed);
    stop(&mut other);

    assert_eq!(
        renamed_reads,
        (Some(false), Some(false)),
        "/bin/sh started as argv[0] omp"
    );
    assert_eq!(other_reads, (Some(false), Some(false)), "a copy named xomp");
}
