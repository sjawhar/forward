use super::daemon_support::{connect, start, start_expecting_failure, test_port};
use std::io::Read as _;
use std::net::TcpListener;

#[test]
fn a_bind_failure_is_fatal_and_names_the_address() {
    // Given: the browser relay's ephemeral test port is already occupied.
    let dir = tempfile::tempdir().unwrap();
    let port = test_port();
    let _squatter = TcpListener::bind(("127.0.0.1", port)).unwrap();

    // When: the daemon starts with that browser relay port.
    let stderr = start_expecting_failure(dir.path(), &format!("relay_port = {port}\n"));

    // Then: startup fails with the listener address named for remediation.
    assert!(
        stderr.contains("failed to bind browser relay channel on 127.0.0.1:"),
        "got {stderr:?}"
    );
    assert!(stderr.contains(&port.to_string()), "got {stderr:?}");
}

#[test]
fn relay_port_zero_skips_the_spawn_and_logs_disabled() {
    // Given: a daemon whose browser relay channel is explicitly disabled.
    let dir = tempfile::tempdir().unwrap();

    // When: it starts.
    let (daemon, port) = start(dir.path(), "relay_port = 0\n");
    daemon.wait_for_log("browser relay channel disabled (relay_port = 0)");

    // Then: the URL channel still accepts and the mutually exclusive bind branch
    // did not log a listener banner.
    drop(connect(port));
    let logs = daemon.log();
    assert!(
        !logs.contains("browser relay channel on "),
        "got daemon logs {logs:?}"
    );
}

#[test]
fn the_daemon_serves_the_channel_it_announces() {
    // Given: an ephemeral browser relay listener. Nothing listens on
    // 127.0.0.1:9224 here: omp-browser-relay never runs on the devbox or CI, so
    // this dials only the daemon's ephemeral listener and never binds 9224.
    let dir = tempfile::tempdir().unwrap();
    let relay_port = test_port();

    // When: the daemon announces the channel and it is dialed locally.
    let (daemon, port) = start(dir.path(), &format!("relay_port = {relay_port}\n"));
    daemon.wait_for_log(&format!("browser relay channel on 127.0.0.1:{relay_port}"));
    let mut relay = connect(relay_port);
    let mut response = Vec::new();
    relay.read_to_end(&mut response).unwrap();

    // Then: the channel returns the generic upstream refusal and the daemon's
    // original URL channel remains responsive.
    assert_eq!(response, b"REFUSED\n");
    drop(connect(port));
}
