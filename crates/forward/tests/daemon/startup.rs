use std::net::TcpListener;

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

#[test]
fn a_pulse_bind_failure_is_fatal_and_names_the_address() {
    // Given: another process owns the configured pulse listener address.
    let dir = tempfile::tempdir().unwrap();
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let pulse_port = held.local_addr().unwrap().port();

    // When: a counterpart is configured and every other optional listener is
    // disabled, so pulse attempts the held bind.
    let output = start_expecting_failure(
        dir.path(),
        &format!(
            "peer = \"127.0.0.1\"\nrelay_port = 0\npcsc_port = 0\ngrant_port = 0\npulse_port = {pulse_port}\n"
        ),
    );

    // Then: it refuses startup instead of continuing without the pulse channel.
    assert!(
        output.contains(&format!(
            "failed to bind pulse channel on 127.0.0.1:{pulse_port}"
        )),
        "got {output:?}"
    );
}

#[test]
fn startup_announces_the_pulse_channel() {
    // Given: a default-port daemon config with a counterpart.
    let dir = tempfile::tempdir().unwrap();
    let opener = stub(dir.path(), "opener", "true");

    // When: the daemon starts.
    let (daemon, _port) = start(
        dir.path(),
        &format!("opener = [\"{opener}\"]\npeer = \"127.0.0.1\"\n"),
    );

    // Then: the pulse listener announces itself on the default port, proving
    // the daemon spawned the channel before serving URLs.
    daemon.wait_for_log("forward: pulse channel on 127.0.0.1:12806");
}
