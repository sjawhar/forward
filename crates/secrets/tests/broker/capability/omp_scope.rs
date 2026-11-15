use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const PYTHON_FRAMES: &str = concat!(
    "import socket,sys\n",
    "for frame in sys.argv[2:]:\n",
    " s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM)\n",
    " s.connect(sys.argv[1])\n",
    " s.sendall(frame.encode()+b'\\n')\n",
    " sys.stdout.write(s.recv(4096).decode())\n",
);
const NO_OMP_WRAPPER: &str = concat!(
    "depth=$1\n",
    "shift\n",
    "if [ \"$depth\" -gt 0 ]; then\n",
    " sh -c \"$0\" \"$0\" \"$((depth - 1))\" \"$@\"; :\n",
    "else\n",
    " python3 -c \"$1\" \"$2\" \"$3\"; :\n",
    "fi\n",
);

fn python_available() -> bool {
    Command::new("python3").arg("--version").output().is_ok()
}

fn fake_omp(directory: &Path) -> PathBuf {
    let omp = directory.join("omp");
    std::fs::copy("/bin/sh", &omp).unwrap();
    let mut permissions = std::fs::metadata(&omp).unwrap().permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(&omp, permissions).unwrap();
    omp
}

fn fake_omp_command(omp: &Path, socket: &Path, frames: &[&str]) -> Command {
    let mut command = Command::new(omp);
    command
        .arg("-c")
        .arg("python3 -c \"$0\" \"$@\"; :")
        .arg(PYTHON_FRAMES)
        .arg(socket)
        .args(frames)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    command
}

fn fake_omp_frames(omp: &Path, socket: &Path, frames: &[&str]) -> (u32, String) {
    let child = fake_omp_command(omp, socket, frames).spawn().unwrap();
    let pid = child.id();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    (pid, String::from_utf8(output.stdout).unwrap())
}

fn no_omp_frame(socket: &Path, frame: &str) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(NO_OMP_WRAPPER)
        .arg(NO_OMP_WRAPPER)
        .arg("12")
        .arg(PYTHON_FRAMES)
        .arg(socket)
        .arg(frame)
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn prepare_log_capture() {
    install_request_log_capture();
    match request_log().lock() {
        Ok(mut log) => log.clear(),
        Err(error) => error.into_inner().clear(),
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_authorize_uses_the_enclosing_omp_and_audits_its_pid() {
    if !python_available() {
        return;
    }
    prepare_log_capture();
    let harness = Harness::start(&["CAP_BROWSER"]);
    let directory = tempfile::tempdir().unwrap();
    let omp = fake_omp(directory.path());

    let (pid, reply) = fake_omp_frames(&omp, harness.socket(), &["AUTHORIZE\tcap=browser"]);

    assert!(reply.starts_with("OK\tstatus=authorized receipt="), "{reply}");
    let log = String::from_utf8(request_log().lock().unwrap().clone()).unwrap();
    assert!(log.contains("scope_kind=Some(OmpProcess)"), "{log}");
    assert!(log.contains(&format!("scope_omp_pid=Some({pid})")), "{log}");
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_no_omp_refuses_before_sops_runs() {
    if !python_available() {
        return;
    }
    let harness = Harness::start(&["CAP_BROWSER"]);

    let reply = no_omp_frame(harness.socket(), "AUTHORIZE\tcap=browser");

    assert!(reply.contains("NO_SCOPE"), "{reply}");
    assert_eq!(harness.sops_invocations(), 0);
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_secret_operations_do_not_use_the_omp_scope() {
    if !python_available() {
        return;
    }
    let harness = Harness::start(&["DEEL_API_KEY"]);
    let directory = tempfile::tempdir().unwrap();
    let omp = fake_omp(directory.path());

    let (_, reply) = fake_omp_frames(
        &omp,
        harness.socket(),
        &["GET\tkey=DEEL_API_KEY", "REQUEST\tkey=DEEL_API_KEY"],
    );

    assert_eq!(reply.lines().count(), 2, "{reply}");
    assert!(reply.lines().all(|line| line.contains("NO_SCOPE")), "{reply}");
    assert_eq!(harness.sops_invocations(), 0);
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_each_authorize_decrypts_and_mints_a_new_receipt() {
    if !python_available() {
        return;
    }
    let harness = Harness::start(&["CAP_BROWSER"]);
    let directory = tempfile::tempdir().unwrap();
    let omp = fake_omp(directory.path());

    let (_, replies) = fake_omp_frames(
        &omp,
        harness.socket(),
        &["AUTHORIZE\tcap=browser", "AUTHORIZE\tcap=browser"],
    );
    let replies = replies.lines().collect::<Vec<_>>();

    assert_eq!(replies.len(), 2);
    assert!(replies.iter().all(|reply| reply.starts_with("OK\tstatus=authorized")));
    let [first, second] = replies.as_slice() else {
        panic!("expected two authorization responses");
    };
    assert_ne!(receipt_from(first), receipt_from(second));
    assert_eq!(harness.sops_invocations(), 2);
}

#[test]
#[cfg_attr(miri, ignore)]
fn omp_scope_ended_omp_denies_after_the_decrypt() {
    if !python_available() {
        return;
    }
    let harness = Harness::start_with_waiting_sops(&["CAP_BROWSER"]);
    let directory = tempfile::tempdir().unwrap();
    let omp = fake_omp(directory.path());
    let mut child = fake_omp_command(&omp, harness.socket(), &["AUTHORIZE\tcap=browser"])
        .spawn()
        .unwrap();
    let mut output = child.stdout.take().unwrap();
    for _ in 0..100 {
        if harness.sops_invocations() == 1 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(harness.sops_invocations(), 1);

    child.kill().unwrap();
    child.wait().unwrap();
    std::fs::write(harness.wait_marker(), b"release").unwrap();
    let mut reply = String::new();
    output.read_to_string(&mut reply).unwrap();

    assert!(reply.contains("DENIED"), "{reply}");
    assert!(!reply.contains("receipt="), "{reply}");
}
