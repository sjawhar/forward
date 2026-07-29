use super::daemon_support::{send, start, stub, wait_for};

#[test]
fn allowlist_hit_opens_and_forwards_localhost() {
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
mode = "allowlist"
opener = ["{opener}"]
ssh = ["{ssh}"]
tunnel_host = "devbox-tunnel"
allow = ["localhost", "github.com/login"]
"#
        ),
    );
    send(port, "http://localhost:8400/cb?code=abc");
    assert!(wait_for(&opened).contains("http://localhost:8400/cb?code=abc"));
    assert_eq!(
        wait_for(&sshed).trim(),
        "-O forward -L 127.0.0.1:8400:127.0.0.1:8400 devbox-tunnel"
    );
}

#[test]
fn auto_mode_opens_everything_no_ssh_for_remote() {
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
    send(port, "https://random.example/x");
    assert!(wait_for(&opened).contains("https://random.example/x"));
    assert!(!sshed.exists());
}

#[test]
fn opener_receives_reentry_marker() {
    // Given: an opener stub that records its inherited marker.
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("marker");
    let opener = stub(
        dir.path(),
        "opener",
        &format!(
            "printf '%s' \"$FORWARD_OPENER_REENTRY\" > {}",
            marker.display()
        ),
    );
    let (_daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );

    // When: the daemon opens a permitted URL.
    send(port, "https://example.com/redirect");

    // Then: the child process receives the re-entry marker.
    assert_eq!(wait_for(&marker), "1");
}

#[test]
fn auto_mode_rejects_non_web_scheme() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );
    send(port, "file:///tmp/forward-test");
    daemon.wait_for_log("unsupported URL scheme");
    assert!(!opened.exists(), "non-web URLs must not reach the opener");
}

#[test]
fn opener_with_lingering_grandchild_does_not_block_its_handler() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("sleep 10 & echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );

    // Verifies that an opener leaving a pipe-holding descendant does not delay its handler past spawn.
    send(port, "https://example.com/first");
    assert!(wait_for(&opened).contains("https://example.com/first"));
    send(port, "https://example.com/second");
    daemon.wait_for_log("opener spawned for https://example.com/second");
}
