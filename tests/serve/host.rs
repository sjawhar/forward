use super::{Guard, raw_status, spawn_serve, spawn_serve_with_config};

#[test]
fn accepts_mixed_case_loopback_host() {
    let config_root = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "alive").unwrap();
    let (child, port) = spawn_serve(config_root.path());
    let _guard = Guard(child);
    let request = format!(
        "GET {}/file.txt HTTP/1.1\r\nHost: LocalHost:{port}\r\n\r\n",
        dir.path().display()
    );

    assert_eq!(
        raw_status("127.0.0.1", port, request.as_bytes()),
        *b"HTTP/1.1 200"
    );
}

#[test]
fn rejects_requests_without_host_header() {
    let config_root = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "alive").unwrap();
    let (child, port) = spawn_serve(config_root.path());
    let _guard = Guard(child);
    let request = format!("GET {}/file.txt HTTP/1.0\r\n\r\n", dir.path().display());

    assert_eq!(
        raw_status("127.0.0.1", port, request.as_bytes()),
        *b"HTTP/1.0 403"
    );
}

#[test]
fn untrusted_host_precedes_malformed_target_validation() {
    let config_root = tempfile::tempdir().unwrap();
    let (child, port) = spawn_serve(config_root.path());
    let _guard = Guard(child);

    assert_eq!(
        raw_status(
            "127.0.0.1",
            port,
            b"GET relative HTTP/1.1\r\nHost: evil.example\r\n\r\n"
        ),
        *b"HTTP/1.1 403"
    );
}

#[test]
fn accepts_the_configured_listen_address_and_refuses_a_mismatch() {
    // Given: a file server told to listen on a specific address rather than the
    // default, standing in for the devbox's tailnet address, with a counterpart
    // configured. 127.0.0.2 is a loopback address, so no peer is required to
    // validate and the test can genuinely bind it.
    let config_root = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "alive").unwrap();
    let (child, port) = spawn_serve_with_config(
        config_root.path(),
        "listen = \"127.0.0.2\"\npeer = \"100.64.0.2\"\n",
    );
    let _guard = Guard(child);

    // When: a request arrives from loopback naming the configured address.
    let configured = format!(
        "GET {}/file.txt HTTP/1.1\r\nHost: 127.0.0.2:{port}\r\n\r\n",
        dir.path().display()
    );

    // Then: it is served — Host validation follows the configured address, and
    // naming a counterpart does not replace loopback acceptance.
    assert_eq!(
        raw_status("127.0.0.2", port, configured.as_bytes()),
        *b"HTTP/1.1 200"
    );

    // When: a request names a different address instead.
    let mismatch = format!(
        "GET {}/file.txt HTTP/1.1\r\nHost: 127.0.0.3:{port}\r\n\r\n",
        dir.path().display()
    );

    // Then: it is refused, because 127.0.0.3 is neither the configured address
    // nor a loopback name.
    assert_eq!(
        raw_status("127.0.0.2", port, mismatch.as_bytes()),
        *b"HTTP/1.1 403"
    );
}
