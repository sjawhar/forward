use super::daemon_support::{send, start, stub, wait_for};

#[test]
fn a_configured_peer_does_not_displace_loopback_acceptance() {
    // Given: a daemon configured with a counterpart that is not this machine.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" > {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!("opener = [\"{opener}\"]\nmode = \"auto\"\npeer = \"100.64.0.99\"\n"),
    );

    // When: a URL arrives from loopback. An integration test cannot originate a
    // connection from a foreign address, so refusal is covered by the
    // peer::authorized unit tests; what is testable here is the inverse.
    send(port, "https://example.com/from-loopback");

    // Then: configuring a peer added an allowed address rather than replacing
    // loopback, so same-machine tooling and doctor keep working.
    daemon.wait_for_log("decision=open");
    assert!(wait_for(&opened).contains("from-loopback"));
}
