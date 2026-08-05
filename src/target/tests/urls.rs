use super::super::*;

#[test]
fn url_passes_through() {
    let u = to_url("https://example.com/x?y=1", "127.0.0.1", 12802).unwrap();
    assert_eq!(u.as_str(), "https://example.com/x?y=1");
}

#[test]
fn opaque_url_scheme_is_not_openable() {
    let error = to_url("mailto:user@example.com", "127.0.0.1", 12802).unwrap_err();

    assert_eq!(
        error.to_string(),
        "forward: URL scheme is not openable: mailto"
    );
}
