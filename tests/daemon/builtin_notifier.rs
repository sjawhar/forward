use super::daemon_support::{send, start, stub, wait_for};

#[test]
fn builtin_notifier_hands_off_without_waiting_for_approval() {
    // Given: built-in notification and clipboard stubs that record their input.
    let dir = tempfile::tempdir().unwrap();
    let clipboard_input = dir.path().join("clipboard-input");
    let notified = dir.path().join("notified");
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" > {}", opened.display()),
    );
    let _notify_send = stub(
        dir.path(),
        "notify-send",
        &format!("printf '%s\\n' \"$@\" > {}", notified.display()),
    );
    let clipboard_command = stub(
        dir.path(),
        "clipboard-command",
        &format!("cat > {}", clipboard_input.display()),
    );
    let (_daemon, port) = start(
        dir.path(),
        &format!(
            r#"
opener = ["{opener}"]
clipboard = ["{clipboard_command}"]
allow = ["github.com/login"]
"#
        ),
    );

    // When: an allowlist miss reaches the built-in notifier.
    send(port, "https://example.com/surprise");

    // Then: the persistent notification and clipboard handoff happen without opening the URL.
    assert_eq!(
        wait_for(&notified).trim(),
        "--app-name=forward\n--urgency=critical\nforward: not in allowlist — URL copied\nhttps://example.com/surprise"
    );
    assert_eq!(wait_for(&clipboard_input), "https://example.com/surprise");
    assert!(
        !opened.exists(),
        "built-in notification must never open the URL"
    );
}

#[test]
fn builtin_notifier_does_not_run_unconfigured_clipboard() {
    // Given: a clipboard command available on PATH but absent from configuration.
    let dir = tempfile::tempdir().unwrap();
    let clipboard_invoked = dir.path().join("clipboard-invoked");
    let notified = dir.path().join("notified");
    let _clipboard = stub(
        dir.path(),
        "clipboard-command",
        &format!("echo ran > {}", clipboard_invoked.display()),
    );
    let _notify_send = stub(
        dir.path(),
        "notify-send",
        &format!("printf '%s\\n' \"$@\" > {}", notified.display()),
    );
    let (_daemon, port) = start(dir.path(), "allow = [\"github.com/login\"]");

    // When: an allowlist miss uses the default empty clipboard configuration.
    send(port, "https://example.com/no-clipboard");

    // Then: notification proceeds but the available clipboard executable is never invoked.
    wait_for(&notified);
    assert!(
        !clipboard_invoked.exists(),
        "empty clipboard configuration must not run a command"
    );
}

#[test]
fn builtin_notifier_logs_clipboard_failure_but_still_notifies() {
    // Given: a configured clipboard executable that exits unsuccessfully.
    let dir = tempfile::tempdir().unwrap();
    let notified = dir.path().join("notified");
    let _notify_send = stub(
        dir.path(),
        "notify-send",
        &format!("printf '%s\\n' \"$@\" > {}", notified.display()),
    );
    let clipboard = stub(dir.path(), "clipboard", "exit 1");
    let (daemon, port) = start(
        dir.path(),
        &format!("clipboard = [\"{clipboard}\"]\nallow = [\"github.com/login\"]"),
    );

    // When: copying a non-allowlisted URL fails.
    send(port, "https://example.com/clipboard-failed");

    // Then: the failure is logged while the user still receives the notification.
    wait_for(&notified);
    daemon.wait_for_log("clipboard failed for https://example.com/clipboard-failed");
}

#[test]
fn builtin_notifier_survives_a_clipboard_tool_that_forks() {
    // Given: a clipboard stub shaped like wl-copy, which has to leave a process alive to
    // own the selection. The survivor inherits our stderr, so reading that pipe to EOF
    // would never return and the connection thread would block forever.
    let dir = tempfile::tempdir().unwrap();
    let clipboard_input = dir.path().join("clipboard-input");
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" > {}", opened.display()),
    );
    let _notify_send = stub(dir.path(), "notify-send", "exit 0");
    let clipboard = stub(
        dir.path(),
        "clipboard",
        &format!("cat > {}\nsleep 30 &\nexit 0", clipboard_input.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            "opener = [\"{opener}\"]\nclipboard = [\"{clipboard}\"]\nallow = [\"github.com/login\"]"
        ),
    );

    // When: an allowlist miss is handed to that clipboard tool.
    send(port, "https://example.com/forking-clipboard");

    // Then: the handoff finishes and is reported, instead of hanging on the inherited pipe.
    assert_eq!(
        wait_for(&clipboard_input),
        "https://example.com/forking-clipboard"
    );
    daemon.wait_for_log("copied to clipboard: https://example.com/forking-clipboard");
    assert!(
        !opened.exists(),
        "an allowlist miss must never open the URL"
    );
}
