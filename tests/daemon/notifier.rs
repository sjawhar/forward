use super::daemon_support::{send, start, stub, wait_for};

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
    daemon.wait_for_log("notification not approved: https://example.com/ignored");
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
    daemon.wait_for_log("notification not approved: https://example.com/dismissed");
    assert!(
        !opened.exists(),
        "opener must not run when action is not 'default'"
    );
}

#[test]
fn declined_notification_does_not_forward_or_open() {
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let notified = dir.path().join("notified");
    let sshed = dir.path().join("sshed");
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
    let ssh = stub(
        dir.path(),
        "ssh",
        &format!("echo \"$@\" >> {}", sshed.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
opener = ["{opener}"]
notifier = ["{notifier}"]
ssh = ["{ssh}"]
"#
        ),
    );
    send(port, "http://localhost:8400/declined");
    assert!(wait_for(&notified).contains("http://localhost:8400/declined"));
    daemon.wait_for_log("notification not approved: http://localhost:8400/declined");
    assert!(
        !sshed.exists(),
        "declined URLs must not create SSH forwards"
    );
    assert!(!opened.exists(), "declined URLs must not open");
}
