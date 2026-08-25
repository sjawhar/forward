use super::daemon_support::{start, stub, wait_for};

#[test]
fn open_of_a_bare_path_delivers_the_generated_preview_url() {
    // Given: a running daemon, and a file on the devbox side.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" > {}", opened.display()),
    );
    let (_daemon, port) = start(
        dir.path(),
        &format!("mode = \"auto\"\nopener = [\"{opener}\"]\n"),
    );
    let file = dir.path().join("notes.md");
    std::fs::write(&file, "# notes\n").unwrap();
    // An explicit empty config keeps the test off the developer's real config,
    // which may name a peer. No arming socket is needed: the preview URL's only
    // loopback port is the static file-server port, which is never armed.
    let open_config = dir.path().join("open.toml");
    std::fs::write(&open_config, "").unwrap();

    // When: `forward open` is given the bare path rather than a URL.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "open",
            file.to_str().unwrap(),
            "--port",
            &port.to_string(),
            "--config",
            open_config.to_str().unwrap(),
        ])
        .output()
        .unwrap();

    // Then: it succeeds, and the opener receives the file-server URL for that
    // path. The host is deliberately not asserted — it is configuration-driven —
    // so this pins the port and path that identify the preview.
    assert!(
        output.status.success(),
        "stderr {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
    let recorded = wait_for(&opened);
    assert!(recorded.contains(":12802/"), "opened {recorded:?}");
    assert!(recorded.trim().ends_with("notes.md"), "opened {recorded:?}");
}
