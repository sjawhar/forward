use super::daemon_support::{send, start, stub, wait_for};

#[test]
fn redirect_uri_port_is_forwarded() {
    let dir = tempfile::tempdir().unwrap();
    let sshed = dir.path().join("sshed");
    let opener = stub(dir.path(), "opener", "true");
    let ssh = stub(
        dir.path(),
        "ssh",
        &format!("echo \"$@\" >> {}", sshed.display()),
    );
    let (_daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
ssh = ["{ssh}"]
"#
        ),
    );
    send(
        port,
        "https://accounts.google.com/auth?redirect_uri=http%3A%2F%2Flocalhost%3A8085%2F",
    );
    assert_eq!(
        wait_for(&sshed).trim(),
        "-O forward -L 127.0.0.1:8085:127.0.0.1:8085 devbox-tunnel"
    );
}

#[test]
fn ssh_failure_still_opens_url() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let ssh = stub(dir.path(), "ssh", "echo boom >&2; exit 1");
    let (_daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
ssh = ["{ssh}"]
"#
        ),
    );
    send(port, "http://localhost:8400/cb");
    assert!(wait_for(&opened).contains("http://localhost:8400/cb"));
}

#[test]
fn file_server_port_not_dynamically_forwarded() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let sshed = dir.path().join("sshed");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let ssh = stub(
        dir.path(),
        "ssh",
        &format!("echo \"$@\" >> {}", sshed.display()),
    );
    let (_daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
ssh = ["{ssh}"]
"#
        ),
    );
    send(port, "http://localhost:12802/home/ubuntu/x.md");
    assert!(wait_for(&opened).contains("http://localhost:12802/home/ubuntu/x.md"));
    assert!(
        !sshed.exists(),
        "must not ssh -O forward the static file-server port"
    );
}

#[test]
fn redirect_uri_forwards_are_capped_at_four() {
    let dir = tempfile::tempdir().unwrap();
    let sshed = dir.path().join("sshed");
    let opener = stub(dir.path(), "opener", "true");
    let ssh = stub(
        dir.path(),
        "ssh",
        &format!("echo \"$@\" >> {}", sshed.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
ssh = ["{ssh}"]
"#
        ),
    );
    send(
        port,
        "https://example.com/auth?redirect_uri=http%3A%2F%2Flocalhost%3A8001%2F&redirect_uri=http%3A%2F%2Flocalhost%3A8002%2F&redirect_uri=http%3A%2F%2Flocalhost%3A8003%2F&redirect_uri=http%3A%2F%2Flocalhost%3A8004%2F&redirect_uri=http%3A%2F%2Flocalhost%3A8005%2F&redirect_uri=http%3A%2F%2Flocalhost%3A8006%2F",
    );

    daemon.wait_for_log("dynamic forward limit reached");
    let record = std::fs::read_to_string(sshed).unwrap();
    assert_eq!(record.lines().count(), 4);
}
