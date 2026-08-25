use super::{Guard, spawn_serve};

#[test]
fn adds_browser_boundary_headers_to_every_content_class() {
    let config_root = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("doc.md"), "# Title").unwrap();
    std::fs::write(dir.path().join("plain.txt"), "plain text").unwrap();
    let (child, port) = spawn_serve(config_root.path());
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
    assert_eq!(response.header("referrer-policy"), Some("no-referrer"));
}
