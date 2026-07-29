use super::daemon_support::{send, start, stub};
use std::path::Path;
use std::thread;
use std::time::Duration;

fn config(ssh: &str) -> String {
    format!(
        r#"
mode = "auto"
opener = ["true"]
ssh = ["{ssh}"]
forward_ttl_secs = 1
"#
    )
}

fn wait_for_lines(path: &Path, count: usize) -> Vec<String> {
    for _ in 0..50 {
        if let Ok(contents) = std::fs::read_to_string(path) {
            let lines = contents.lines().map(str::to_owned).collect::<Vec<_>>();
            if lines.len() >= count {
                return lines;
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("expected {count} SSH invocations at {path:?}");
}

#[test]
fn expires_with_the_exact_local_forward_cancel_spec() {
    let dir = tempfile::tempdir().unwrap();
    let calls = dir.path().join("ssh-calls");
    let ssh = stub(
        dir.path(),
        "ssh",
        &format!("echo \"$@\" >> {}", calls.display()),
    );
    let (_daemon, port) = start(dir.path(), &config(&ssh));

    send(port, "http://localhost:19001/callback");

    let calls = wait_for_lines(&calls, 2);
    assert_eq!(
        calls,
        [
            "-O forward -L 127.0.0.1:19001:127.0.0.1:19001 devbox-tunnel",
            "-O cancel -L 127.0.0.1:19001:127.0.0.1:19001 devbox-tunnel",
        ]
    );
}

#[test]
fn static_tunnel_ports_are_never_created_or_cancelled() {
    let dir = tempfile::tempdir().unwrap();
    let calls = dir.path().join("ssh-calls");
    let ssh = stub(
        dir.path(),
        "ssh",
        &format!("echo \"$@\" >> {}", calls.display()),
    );
    let (_daemon, port) = start(dir.path(), &config(&ssh));

    for static_port in [12_799, 12_800, 12_802] {
        send(port, &format!("http://localhost:{static_port}/callback"));
    }
    thread::sleep(Duration::from_millis(1_500));

    assert!(
        !calls.exists(),
        "static tunnel ports must never be passed to SSH: {calls:?}"
    );
}

#[test]
fn re_request_refreshes_a_live_forward_without_a_second_create() {
    let dir = tempfile::tempdir().unwrap();
    let calls = dir.path().join("ssh-calls");
    let ssh = stub(
        dir.path(),
        "ssh",
        &format!("echo \"$@\" >> {}", calls.display()),
    );
    let (_daemon, port) = start(dir.path(), &config(&ssh));

    send(port, "http://localhost:19002/first");
    assert_eq!(wait_for_lines(&calls, 1).len(), 1);
    thread::sleep(Duration::from_millis(600));
    send(port, "http://localhost:19002/second");
    thread::sleep(Duration::from_millis(600));

    assert_eq!(wait_for_lines(&calls, 1).len(), 1);
    assert_eq!(wait_for_lines(&calls, 2).len(), 2);
}

#[test]
fn failed_cancel_is_logged_without_stopping_later_urls() {
    let dir = tempfile::tempdir().unwrap();
    let calls = dir.path().join("ssh-calls");
    let ssh = stub(
        dir.path(),
        "ssh",
        &format!(
            "echo \"$@\" >> {}; if [ \"$2\" = cancel ]; then echo release-failed >&2; exit 1; fi",
            calls.display()
        ),
    );
    let (daemon, port) = start(dir.path(), &config(&ssh));

    send(port, "http://localhost:19003/callback");
    let calls = wait_for_lines(&calls, 2);
    assert_eq!(
        calls[1],
        "-O cancel -L 127.0.0.1:19003:127.0.0.1:19003 devbox-tunnel"
    );
    daemon.wait_for_log("SSH forward release failed for port 19003");

    send(port, "http://localhost:19004/callback");
    let calls = wait_for_lines(&dir.path().join("ssh-calls"), 3);
    assert_eq!(
        calls[2],
        "-O forward -L 127.0.0.1:19004:127.0.0.1:19004 devbox-tunnel"
    );
}
