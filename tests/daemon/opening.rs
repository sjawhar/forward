use super::daemon_support::{connect, send, spawn_bridge, start, stub, test_port, wait_for};

#[test]
fn allowlist_hit_opens_and_forwards_localhost() {
    // Given: an allowlisted loopback URL and a fake devbox bridge.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let callback_port = test_port();
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (_daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "allowlist"
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
allow = ["localhost", "github.com/login"]
"#
        ),
    );
    // When: the URL arrives and a browser connects to the port it named.
    let url = format!("http://localhost:{callback_port}/cb?code=abc");
    send(port, &url);
    assert!(wait_for(&opened).contains(&url));
    _daemon.wait_for_log(&format!("callback port {callback_port} served on loopback"));
    drop(connect(callback_port));

    // Then: it opens and the callback port is relayed to the bridge.
    assert_eq!(
        wait_for(&bridged).trim(),
        format!("CONNECT {callback_port}")
    );
}

#[test]
fn auto_mode_opens_everything_no_ssh_for_remote() {
    // Given: a daemon that could lease callback ports, so a remote URL having
    // none is the only reason nothing is leased.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
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
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );
    // When: a URL with no loopback port arrives.
    send(port, "https://random.example/x");

    // Then: it opens and no callback port is leased.
    assert!(wait_for(&opened).contains("https://random.example/x"));
    assert!(!daemon.log().contains("served on loopback"));
    assert!(!bridged.exists());
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
