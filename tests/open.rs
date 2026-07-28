use std::process::Command;

#[test]
fn open_refuses_opener_reentry_before_connecting() {
    // Given: an opener child that was launched by the forward daemon.
    let mut command = Command::new(env!("CARGO_BIN_EXE_forward"));
    command
        .args(["open", "https://example.com/redirect"])
        .env("FORWARD_OPENER_REENTRY", "1");

    // When: the child tries to hand a URL back to forward.
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Then: it reports the recursion rather than attempting the tunnel connection.
    assert!(!output.status.success());
    assert!(stderr.contains("configured opener is routing back into forward open"));
    assert!(stderr.contains("/usr/bin/xdg-open"));
    assert!(!stderr.contains("opener tunnel down"));
    assert_eq!(stderr.lines().count(), 1);
}

#[test]
fn version_flag_reports_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("0.1.2"));
}
