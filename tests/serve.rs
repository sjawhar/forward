use std::io::{BufRead as _, Write as _};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::Duration;

#[path = "serve/host.rs"]
mod host;
#[path = "serve/limits.rs"]
mod limits;

fn raw_status(port: u16, request: &[u8]) -> [u8; 12] {
    let mut connection = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    connection.write_all(request).unwrap();
    let mut status = [0_u8; 12];
    std::io::Read::read_exact(&mut connection, &mut status).unwrap();
    status
}

fn spawn_serve(root_marker: &std::path::Path) -> (std::process::Child, u16) {
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["serve", "--port", "0"])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = child.stderr.take().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    let reader = std::thread::spawn(move || {
        let mut line = String::new();
        let mut reader = std::io::BufReader::new(stderr);
        let result = reader.read_line(&mut line);
        let _ = sender.send((result, line));
        let _ = std::io::copy(&mut reader, &mut std::io::sink());
    });
    let (result, line) = match receiver.recv_timeout(Duration::from_secs(1)) {
        Ok(value) => value,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            let _ = reader.join();
            panic!("forward serve did not announce its listener: {error}");
        }
    };
    result.unwrap();
    drop(reader);
    let port = line
        .strip_prefix("forward: loopback server listening on 127.0.0.1:")
        .and_then(|value| value.trim().parse().ok())
        .unwrap_or_else(|| panic!("unexpected forward serve startup message: {line:?}"));
    let _ = root_marker;
    (child, port)
}

struct Guard(std::process::Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

#[test]
fn serves_files_dirs_and_markdown() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("img.png"), b"\x89PNG").unwrap();
    std::fs::write(dir.path().join("doc.md"), "# Title\n\nbody").unwrap();
    std::fs::write(dir.path().join("UPPER.MD"), "# Upper").unwrap();
    std::fs::write(dir.path().join("plain.txt"), "text").unwrap();
    std::fs::write(dir.path().join("noext"), "plain text").unwrap();
    let (child, port) = spawn_serve(dir.path());
    let _guard = Guard(child);
    let base = format!("http://127.0.0.1:{port}");
    let path = dir.path().to_str().unwrap();

    let response = ureq::get(&format!("{base}{path}/img.png")).call().unwrap();
    assert_eq!(response.header("content-type").unwrap(), "image/png");

    let response = ureq::get(&format!("{base}{path}/doc.md")).call().unwrap();
    assert!(
        response
            .header("content-type")
            .unwrap()
            .starts_with("text/html")
    );
    assert!(response.into_string().unwrap().contains("<h1>Title</h1>"));

    let response = ureq::get(&format!("{base}{path}/UPPER.MD")).call().unwrap();
    assert!(response.into_string().unwrap().contains("<h1>Upper</h1>"));

    let response = ureq::get(&format!("{base}{path}/plain.txt"))
        .call()
        .unwrap();
    assert_eq!(
        response.header("content-type").unwrap(),
        "text/plain; charset=utf-8"
    );

    let response = ureq::get(&format!("{base}{path}/doc.md?raw=1"))
        .call()
        .unwrap();
    assert!(
        response
            .header("content-type")
            .unwrap()
            .starts_with("text/plain")
    );
    assert!(response.into_string().unwrap().starts_with("# Title"));

    let response = ureq::get(&format!("{base}{path}/noext")).call().unwrap();
    assert!(
        response
            .header("content-type")
            .unwrap()
            .starts_with("text/plain")
    );

    let response = ureq::get(&format!("{base}{path}/")).call().unwrap();
    let listing = response.into_string().unwrap();
    assert!(listing.contains("img.png") && listing.contains("doc.md"));

    let error = ureq::get(&format!("{base}{path}/missing"))
        .call()
        .unwrap_err();
    assert!(matches!(error, ureq::Error::Status(404, _)));

    let error = ureq::post(&format!("{base}{path}/doc.md"))
        .send_string("x")
        .unwrap_err();
    let ureq::Error::Status(405, response) = error else {
        panic!("expected 405 response");
    };
    assert_eq!(response.header("allow"), Some("GET, HEAD"));

    let response = ureq::head(&format!("{base}{path}/img.png")).call().unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.header("content-length"), Some("4"));

    std::fs::write(dir.path().join("a b.txt"), "spaced").unwrap();
    let response = ureq::get(&format!("{base}{path}/a%20b.txt"))
        .call()
        .unwrap();
    assert_eq!(response.into_string().unwrap(), "spaced");

    assert_eq!(
        raw_status(port, b"GET relative HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        *b"HTTP/1.1 400"
    );
}

#[test]
fn continues_after_client_disconnect_and_rejects_untrusted_host() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("file.txt"), "alive").unwrap();
    let (child, port) = spawn_serve(dir.path());
    let _guard = Guard(child);
    let path = dir.path().to_str().unwrap();

    let request = format!("GET {path}/file.txt HTTP/1.1\r\nHost: evil.example\r\n\r\n");
    assert_eq!(raw_status(port, request.as_bytes()), *b"HTTP/1.1 403");

    let request = format!("GET {path}/file.txt HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let mut connection = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
    connection.write_all(request.as_bytes()).unwrap();
    let connection = socket2::Socket::from(connection);
    connection.set_linger(Some(Duration::ZERO)).unwrap();
    drop(connection);

    let response = ureq::get(&format!("http://127.0.0.1:{port}{path}/file.txt"))
        .call()
        .unwrap();
    assert_eq!(response.into_string().unwrap(), "alive");
}

#[test]
fn adds_browser_boundary_headers_to_every_content_class() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("doc.md"), "# Title").unwrap();
    std::fs::write(dir.path().join("plain.txt"), "plain text").unwrap();
    let (child, port) = spawn_serve(dir.path());
    let _guard = Guard(child);
    let base = format!("http://127.0.0.1:{port}");
    let path = dir.path().to_str().unwrap();

    assert_browser_boundary_headers(&ureq::get(&format!("{base}{path}/doc.md")).call().unwrap());
    assert_browser_boundary_headers(
        &ureq::get(&format!("{base}{path}/plain.txt"))
            .call()
            .unwrap(),
    );
    assert_browser_boundary_headers(&ureq::get(&format!("{base}{path}/")).call().unwrap());
}

#[test]
fn rendered_markdown_does_not_embed_executable_scripts() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("doc.md"),
        "# Title\n\n```rust\nlet x = 1;\n```",
    )
    .unwrap();
    let (child, port) = spawn_serve(dir.path());
    let _guard = Guard(child);
    let page = ureq::get(&format!(
        "http://127.0.0.1:{port}{}/doc.md",
        dir.path().to_str().unwrap()
    ))
    .call()
    .unwrap()
    .into_string()
    .unwrap();

    assert!(!page.contains("<script"));
    assert!(!page.contains("hljs.highlightAll"));
}

fn assert_browser_boundary_headers(response: &ureq::Response) {
    assert_eq!(
        response.header("content-security-policy"),
        Some(
            "sandbox; default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; font-src https://cdn.jsdelivr.net"
        )
    );
    assert_eq!(response.header("x-content-type-options"), Some("nosniff"));
    assert_eq!(
        response.header("cross-origin-resource-policy"),
        Some("same-origin")
    );
}
