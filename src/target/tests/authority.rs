use super::super::*;

#[test]
fn preview_url_names_this_machine_not_the_counterpart() {
    // Given: a devbox serving previews on its own tailnet address.
    let f = tempfile::NamedTempFile::new().unwrap();

    // When: a path is minted for the laptop to open.
    let u = to_url(f.path().to_str().unwrap(), "100.64.0.1", 12802).unwrap();

    // Then: the URL names the machine holding the file. The counterpart is
    // where the browser is, never where the file is.
    assert_eq!(u.host_str(), Some("100.64.0.1"));
    assert_eq!(u.port(), Some(12802));
}

#[test]
fn an_ipv6_listen_address_is_bracketed() {
    // Given: a listen address held as a bare IPv6 literal, which is how
    // Config stores it.
    let f = tempfile::NamedTempFile::new().unwrap();

    // When: a preview URL is minted against it.
    let u = to_url(f.path().to_str().unwrap(), "::1", 12802).unwrap();

    // Then: it parses, because the authority was bracketed first.
    assert_eq!(u.host_str(), Some("[::1]"));
}
