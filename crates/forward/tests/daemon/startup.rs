use super::daemon_support::{start, start_expecting_failure, stub};

#[test]
fn startup_logs_effective_config() {
    // Given: a daemon config with an explicit mode, opener, and allowlist.
    let dir = tempfile::tempdir().unwrap();
    let opener = stub(dir.path(), "opener", "true");
    let config_path = dir.path().join("config.toml");

    // When: the daemon starts from that config.
    let (daemon, port) = start(
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
        "daemon config={} listen=127.0.0.1:{port} peer=\"\" mode=Auto opener=[\"{opener}\"] allow_entries=2",
        config_path.display()
    ));
}

#[test]
fn startup_logs_the_bound_address_and_the_configured_peer() {
    // Given: a daemon with a tailnet counterpart configured.
    let dir = tempfile::tempdir().unwrap();
    let opener = stub(dir.path(), "opener", "true");

    // When: it starts.
    let (daemon, port) = start(
        dir.path(),
        &format!("opener = [\"{opener}\"]\npeer = \"100.64.0.2\"\n"),
    );

    // Then: the journal names both ends, so a misconfigured listen or peer is
    // visible without reading the config file.
    daemon.wait_for_log(&format!("listen=127.0.0.1:{port} peer=\"100.64.0.2\""));
}

#[test]
fn a_non_loopback_listen_without_a_peer_refuses_to_start() {
    // Given: a daemon told to listen on a routable address with no counterpart,
    // which would open the URL channel to the whole tailnet.
    let dir = tempfile::tempdir().unwrap();

    // When: it starts.
    let output = start_expecting_failure(dir.path(), "listen = \"100.64.0.1\"\n");

    // Then: it fails closed with ConfigError::PeerRequired. Validation happens
    // while loading the shared config, before daemon startup can begin.
    assert!(
        output.contains("non-loopback listen address requires an explicit peer"),
        "got {output:?}"
    );
    assert!(output.contains("peer"), "got {output:?}");
}
