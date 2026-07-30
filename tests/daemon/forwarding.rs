use super::daemon_support::{connect, send, spawn_bridge, start, stub, test_port, wait_for};
use std::io::Write;

#[test]
fn redirect_uri_port_is_forwarded() {
    // Given: a daemon whose peer is a fake devbox bridge.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let callback_port = test_port();
    let opener = stub(dir.path(), "opener", "true");
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );

    // When: a URL carrying a loopback redirect_uri arrives and a browser then
    // connects to the port it named.
    send(
        port,
        &format!(
            "https://accounts.google.com/auth?redirect_uri=http%3A%2F%2Flocalhost%3A{callback_port}%2F"
        ),
    );
    daemon.wait_for_log(&format!("callback port {callback_port} served on loopback"));
    let mut browser = connect(callback_port);
    browser.write_all(b"GET /cb HTTP/1.1\r\n\r\n").unwrap();

    // Then: the daemon asks the bridge for exactly that port.
    assert_eq!(
        wait_for(&bridged).trim(),
        format!("CONNECT {callback_port}")
    );
}

#[test]
fn callback_setup_failure_still_opens_url() {
    // Given: a daemon with no peer, so no callback port can be served at all.
    let dir = tempfile::tempdir().unwrap();
    let opened = dir.path().join("opened");
    let callback_port = test_port();
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
"#
        ),
    );

    // When: a URL naming a loopback callback port arrives.
    let url = format!("http://localhost:{callback_port}/cb");
    send(port, &url);

    // Then: the URL still opens, as it did when an SSH forward failed.
    assert!(wait_for(&opened).contains(&url));
    daemon.wait_for_log(&format!(
        "no literal peer address; not serving callback port {callback_port}"
    ));
}

#[test]
fn file_server_port_not_dynamically_forwarded() {
    // Given: a daemon that could serve callback ports, so a static port being
    // skipped is the only reason nothing is leased.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let opened = dir.path().join("opened");
    let opener = stub(
        dir.path(),
        "opener",
        &format!("echo \"$@\" >> {}", opened.display()),
    );
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );

    // When: a file-preview URL on the static port arrives.
    send(port, "http://localhost:12802/home/ubuntu/x.md");

    // Then: it opens without the daemon leasing the static file-server port.
    assert!(wait_for(&opened).contains("http://localhost:12802/home/ubuntu/x.md"));
    assert!(
        !daemon.log().contains("callback port 12802"),
        "must not lease the static file-server port"
    );
    assert!(!bridged.exists(), "must not dial the bridge for 12802");
}

#[test]
fn redirect_uri_forwards_are_capped_at_four() {
    // Given: a daemon that can serve callback ports.
    let dir = tempfile::tempdir().unwrap();
    let bridged = dir.path().join("bridged");
    let bridge_port = spawn_bridge(&bridged);
    let opener = stub(dir.path(), "opener", "true");
    let (daemon, port) = start(
        dir.path(),
        &format!(
            r#"
mode = "auto"
opener = ["{opener}"]
peer = "127.0.0.1"
bridge_port = {bridge_port}
"#
        ),
    );
    let mut ports = Vec::with_capacity(6);
    while ports.len() < 6 {
        let callback_port = test_port();
        if !ports.contains(&callback_port) {
            ports.push(callback_port);
        }
    }
    let url = ports
        .iter()
        .map(|port| format!("redirect_uri=http%3A%2F%2Flocalhost%3A{port}%2F"))
        .collect::<Vec<_>>()
        .join("&");

    // When: one URL names six loopback callback ports.
    send(port, &format!("https://example.com/auth?{url}"));

    // Then: only four are leased and the rest are dropped.
    daemon.wait_for_log("dynamic forward limit reached; dropped 2 port(s)");
    assert_eq!(daemon.log().matches("served on loopback").count(), 4);
}
