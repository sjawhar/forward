use super::daemon_support::{send, spawn_bridge, start, stub, test_port, wait_for};

#[test]
fn allowlist_miss_notifies_click_opens() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let notified = dir.path().join("notified");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let notifier = stub(
        dir.path(),
        "notifier",
        &format!("echo \"$@\" >> {}; echo default", notified.display()),
    );
    let (_daemon, port) = start(
        dir.path(),
        &format!(
            r#"
opener = ["{opener}"]
notifier = ["{notifier}"]
allow = ["github.com/login"]
"#
        ),
    );
    send(port, "https://example.com/surprise");
    assert!(wait_for(&notified).contains("https://example.com/surprise"));
    assert!(wait_for(&opened).contains("https://example.com/surprise"));
}

#[test]
fn notifier_silence_drops_url() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let notified = dir.path().join("notified");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let notifier = stub(
        dir.path(),
        "notifier",
        &format!("echo \"$@\" >> {}", notified.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
opener = ["{opener}"]
notifier = ["{notifier}"]
"#
        ),
    );
    send(port, "https://example.com/ignored");
    wait_for(&notified);
    daemon.wait_for_log("notification declined: https://example.com/ignored");
    assert!(
        !opened.exists(),
        "opener must not run when notification not clicked"
    );
}

#[test]
fn notifier_wrong_action_does_not_open() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let notified = dir.path().join("notified");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let notifier = stub(
        dir.path(),
        "notifier",
        &format!("echo \"$@\" >> {}; echo dismissed", notified.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
opener = ["{opener}"]
notifier = ["{notifier}"]
"#
        ),
    );
    send(port, "https://example.com/dismissed");
    wait_for(&notified);
    daemon.wait_for_log("notification declined: https://example.com/dismissed: \"dismissed\\n\"");
    assert!(
        !opened.exists(),
        "opener must not run when action is not 'default'"
    );
}

#[test]
fn failing_custom_notifier_does_not_open() {
    // Given: a custom notifier whose UI process exits unsuccessfully.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let notifier = stub(dir.path(), "notifier", "echo rejected >&2; exit 1");
    let (daemon, port) = start(
        dir.path(),
        &format!("opener = [\"{opener}\"]\nnotifier = [\"{notifier}\"]"),
    );

    // When: the custom notifier cannot produce a successful approval result.
    send(port, "https://example.com/notifier-failed");

    // Then: its failed exit is logged and the URL remains unopened.
    daemon
        .wait_for_log("notification failed for https://example.com/notifier-failed: \"rejected\"");
    assert!(
        !opened.exists(),
        "failed custom notifiers must not open URLs"
    );
}

#[test]
fn a_declined_notification_does_not_open_but_keeps_the_callback_lease() {
    // Given: a declining notifier and a reachable callback bridge.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let notified = dir.path().join("notified");
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let callback_port = test_port();
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let notifier = stub(
        dir.path(),
        "notifier",
        &format!("echo \"$@\" >> {}", notified.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
opener = ["{opener}"]
notifier = ["{notifier}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );
    // When: a loopback callback URL is declined.
    let url = format!("http://localhost:{callback_port}/declined");
    send(port, &url);
    assert!(wait_for(&notified).contains(&url));
    daemon.wait_for_log(&format!("notification declined: {url}"));

    // Then: it never opens — but the callback port stays leased, because a
    // notifier returning false also covers the paste path, where the user is
    // handed the URL precisely to open it themselves and the daemon cannot
    // tell the two apart. The lease grants nothing new: this machine is the
    // bridge's authorized peer, so any local process could already ask the
    // bridge directly. It expires with its TTL.
    daemon.wait_for_log(&format!("callback port {callback_port} served on loopback"));
    assert!(!opened.exists(), "declined URLs must not open");
}
