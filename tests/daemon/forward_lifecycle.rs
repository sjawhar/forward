use super::daemon_support::{connect, connection_is_refused, send, spawn_bridge, start, test_port};
use std::path::Path;

fn config(bridge_port: u16, ttl_secs: u64) -> String {
    format!(
        r#"
mode = "auto"
opener = ["true"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
forward_ttl_secs = {ttl_secs}
"#
    )
}

fn bridge(dir: &Path) -> u16 {
    spawn_bridge(&dir.join("bridged"))
}

#[test]
fn an_expired_lease_stops_listening() {
    // Given: a callback port leased for one second.
    let dir = tempfile::tempdir().unwrap();
    let callback_port = test_port();
    let (daemon, port) = start(dir.path(), &config(bridge(dir.path()), 1));
    send(port, &format!("http://localhost:{callback_port}/callback"));
    daemon.wait_for_log(&format!("callback port {callback_port} served on loopback"));
    assert!(connect(callback_port).peer_addr().is_ok());

    // When: the lease expires.
    daemon.wait_for_log(&format!("callback port {callback_port} released"));

    // Then: release is the listener closing, not an `ssh -O cancel` that could
    // take unrelated forwards with it.
    assert!(
        connection_is_refused(callback_port),
        "port {callback_port} still listening after its lease expired"
    );
}

#[test]
fn static_tunnel_ports_are_never_leased() {
    // Given: a daemon that can serve callback ports.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let (daemon, port) = start(dir.path(), &config(bridge_port, 1));

    // When: URLs naming each static tunnel port arrive.
    for static_port in [12_799, 12_800, 12_802] {
        send(port, &format!("http://localhost:{static_port}/callback"));
        daemon.wait_for_log(&format!(
            "opener spawned for http://localhost:{static_port}/callback"
        ));
    }

    // Then: none of them is ever leased or relayed. 12799 above all: on the
    // devbox that port is the far end of the PC/SC tunnel.
    assert!(
        !daemon.log().contains("served on loopback"),
        "static tunnel ports must never be leased"
    );
    assert!(
        !bridged.exists(),
        "static tunnel ports must never be dialled"
    );
}

#[test]
fn re_request_refreshes_a_live_lease_without_a_second_listener() {
    // Given: a live lease on a callback port, with a TTL long enough that the
    // second request lands inside it.
    let dir = tempfile::tempdir().unwrap();
    let callback_port = test_port();
    let (daemon, port) = start(dir.path(), &config(bridge(dir.path()), 30));
    send(port, &format!("http://localhost:{callback_port}/first"));
    daemon.wait_for_log(&format!("callback port {callback_port} served on loopback"));

    // When: the same port is requested again.
    send(port, &format!("http://localhost:{callback_port}/second"));

    // Then: the lease is refreshed, and no second bind is attempted.
    daemon.wait_for_log(&format!(
        "refreshed callback lease for port {callback_port}"
    ));
    assert_eq!(daemon.log().matches("served on loopback").count(), 1);
    assert!(connect(callback_port).peer_addr().is_ok());
}

#[test]
fn an_unreachable_bridge_does_not_stop_later_urls() {
    // Given: a daemon whose bridge port has nothing behind it.
    let dir = tempfile::tempdir().unwrap();
    let bridge_port = test_port();
    let first_port = test_port();
    let second_port = test_port();
    let (daemon, port) = start(dir.path(), &config(bridge_port, 30));
    send(port, &format!("http://localhost:{first_port}/callback"));
    daemon.wait_for_log(&format!("callback port {first_port} served on loopback"));

    // When: a browser connects and the relay cannot reach the bridge.
    drop(connect(first_port));
    daemon.wait_for_log("cannot reach callback bridge");

    // Then: the failure is logged and later URLs are still served.
    send(port, &format!("http://localhost:{second_port}/callback"));
    daemon.wait_for_log(&format!("callback port {second_port} served on loopback"));
}
