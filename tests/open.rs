use std::process::Command;

#[test]
fn open_refuses_opener_reentry_before_connecting() {
    // Given: an opener child launched by the daemon, with an empty config root.
    let config_root = tempfile::tempdir().unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_forward"));
    command
        .args(["open", "https://example.com/redirect"])
        .env("XDG_CONFIG_HOME", config_root.path())
        .env("FORWARD_OPENER_REENTRY", "1");

    // When: the child tries to hand a URL back to forward.
    let output = command.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Then: it reports the recursion rather than attempting the tunnel connection.
    assert!(!output.status.success());
    assert!(stderr.contains("configured opener is routing back into forward open"));
    assert!(stderr.contains("/usr/bin/xdg-open"));
    assert!(!stderr.contains("cannot reach the laptop daemon"));
    assert_eq!(stderr.lines().count(), 1);
}

#[test]
fn version_flag_reports_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn config_flag_loads_the_named_file_for_serve_open_and_url() {
    // Given: two rejectable config files — one named explicitly, one at the default path.
    let config_root = tempfile::tempdir().unwrap();
    let named = config_root.path().join("named.toml");
    std::fs::write(&named, "named_file_is_not_a_setting = true\n").unwrap();
    let default_dir = config_root.path().join("forward");
    std::fs::create_dir(&default_dir).unwrap();
    std::fs::write(
        default_dir.join("config.toml"),
        "default_file_is_not_a_setting = true\n",
    )
    .unwrap();

    // When: serve and open are pointed at the named file with --config.
    let serve = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["serve", "--port", "0", "--config"])
        .arg(&named)
        .env("XDG_CONFIG_HOME", config_root.path())
        .output()
        .unwrap();
    let open = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["open", "https://example.com/x", "--config"])
        .arg(&named)
        .env("XDG_CONFIG_HOME", config_root.path())
        .output()
        .unwrap();
    let url = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["url", "https://example.com/x", "--config"])
        .arg(&named)
        .env("XDG_CONFIG_HOME", config_root.path())
        .output()
        .unwrap();

    // Then: both refuse to start and name the file from --config, not the default one.
    for output in [serve, open, url] {
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("failed to parse config"));
        assert!(stderr.contains(named.to_str().unwrap()));
        assert!(!stderr.contains("forward/config.toml"));
    }
}

#[test]
fn open_of_a_bare_path_prints_the_preview_url_when_the_send_fails() {
    // Given: an existing file and no daemon. Port 9 (discard) is outside the
    // ephemeral range, so nothing binds it during tests.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("notes.md");
    std::fs::write(&file, "# notes\n").unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "").unwrap();

    // When: the bare path is opened.
    let output = Command::new(env!("CARGO_BIN_EXE_forward"))
        .args([
            "open",
            file.to_str().unwrap(),
            "--port",
            "9",
            "--config",
            config.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Then: it fails loudly and hands the URL back on stdout, instead of
    // exiting 0 having silently dropped it.
    assert!(!output.status.success());
    assert!(stdout.contains(":12802/"), "stdout {stdout:?}");
    assert!(stdout.trim().ends_with("notes.md"), "stdout {stdout:?}");
    assert!(stderr.contains("cannot reach"), "stderr {stderr:?}");
    // The OSC 52 copy is not observable here: osc52_copy writes to /dev/tty by
    // design, not to stdout, and a piped child has no controlling terminal. The
    // escape sequence itself is covered by the osc52_sequence unit tests.
}
