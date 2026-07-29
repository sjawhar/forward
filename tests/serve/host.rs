use super::{Guard, raw_status, spawn_serve};

#[test]
fn accepts_mixed_case_loopback_host() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "alive").unwrap();
    let (child, port) = spawn_serve(dir.path());
    let _guard = Guard(child);
    let request = format!(
        "GET {}/file.txt HTTP/1.1\r\nHost: LocalHost:{port}\r\n\r\n",
        dir.path().display()
    );

    assert_eq!(raw_status(port, request.as_bytes()), *b"HTTP/1.1 200");
}

#[test]
fn rejects_requests_without_host_header() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "alive").unwrap();
    let (child, port) = spawn_serve(dir.path());
    let _guard = Guard(child);
    let request = format!("GET {}/file.txt HTTP/1.0\r\n\r\n", dir.path().display());

    assert_eq!(raw_status(port, request.as_bytes()), *b"HTTP/1.0 403");
}

#[test]
fn untrusted_host_precedes_malformed_target_validation() {
    let dir = tempfile::tempdir().unwrap();
    let (child, port) = spawn_serve(dir.path());
    let _guard = Guard(child);

    assert_eq!(
        raw_status(port, b"GET relative HTTP/1.1\r\nHost: evil.example\r\n\r\n"),
        *b"HTTP/1.1 403"
    );
}
