use super::daemon_support::{start, stub};

#[test]
fn startup_logs_effective_config() {
    // Given: a daemon config with an explicit mode, opener, and allowlist.
    let dir = tempfile::tempdir().unwrap();
    let opener = stub(dir.path(), "opener", "true");
    let config_path = dir.path().join("config.toml");

    // When: the daemon starts from that config.
    let (daemon, _port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
allow = ["localhost", "example.com"]
"#
        ),
    );

    // Then: the journal includes the effective config summary.
    daemon.wait_for_log(&format!(
        "daemon config={} mode=Auto opener=[\"{opener}\"] allow_entries=2",
        config_path.display()
    ));
}
