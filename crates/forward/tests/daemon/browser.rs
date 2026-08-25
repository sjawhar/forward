use std::io::{Read as _, Write as _};
use std::net::TcpListener;

use super::daemon_support::{connect, start, start_expecting_failure, test_port};

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
fn the_daemon_serves_the_channel_it_announces_when_the_feed_is_down() {
    // Given: an ephemeral browser relay listener. Nothing listens on
    // 127.0.0.1:9224 here: omp-browser-relay never runs on the devbox or CI, so
    // this dials only the daemon's ephemeral listener and never binds 9224.
    let dir = tempfile::tempdir().unwrap();
    let relay_port = test_port();

    // When: the daemon announces the channel and a client dials it locally
    // while no devbox feed has attached.
    let (daemon, port) = start(dir.path(), &format!("relay_port = {relay_port}\n"));
    daemon.wait_for_log(&format!("browser relay channel on 127.0.0.1:{relay_port}"));
    let mut relay = connect(relay_port);
    relay.write_all(b"RELAY daemon-relay-token\n").unwrap();
    let mut response = Vec::new();
    relay.read_to_end(&mut response).unwrap();

    // Then: the channel reports the observed missing feed and the daemon's
    // original URL channel remains responsive.
    assert_eq!(response, b"REFUSED FEED\n");
    drop(connect(port));
}

#[test]
fn the_url_channel_survives_a_feed_outage_past_the_reconnect_budget() {
    // Given: a feed peer that greets and closes, the exact flapper that can
    // never reset the reconnect budget. The old client exited the whole daemon
    // once that budget ran out, taking the URL channel down with it.
    let dir = tempfile::tempdir().unwrap();
    let grant_port = test_port();
    let flapper = TcpListener::bind(("127.0.0.1", grant_port)).unwrap();
    std::thread::spawn(move || {
        for stream in flapper.incoming() {
            drop(stream);
        }
    });
    let config = format!(
        "peer = \"127.0.0.1\"\nrelay_port = {}\npcsc_port = {}\ngrant_port = {grant_port}\n",
        test_port(),
        test_port(),
    );

    // When: the daemon runs past its whole 30-second reconnect budget. This is
    // the one deliberately slow test in the suite: the budget is wall-clock
    // time, and shrinking it would need a knob in production code.
    let (daemon, port) = start(dir.path(), &config);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while !daemon.log().contains("grant feed outage budget exhausted") {
        assert!(
            std::time::Instant::now() < deadline,
            "no outage escalation within 60s; daemon logs: {:?}",
            daemon.log()
        );
        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    // Then: past the point where the old client called exit(1), the daemon
    // still serves its URL channel and reports no worker exit.
    drop(connect(port));
    assert!(
        !daemon.log().contains("exiting"),
        "a worker exited during the outage; daemon logs: {:?}",
        daemon.log()
    );
}
