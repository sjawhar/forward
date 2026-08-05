use super::*;
use std::ffi::OsStr;

#[test]
fn url_passes_through() {
    let u = to_url("https://example.com/x?y=1", "127.0.0.1", 12802).unwrap();
    assert_eq!(u.as_str(), "https://example.com/x?y=1");
}

#[test]
fn existing_file_maps_to_files_url() {
    let f = tempfile::NamedTempFile::new().unwrap();
    let u = to_url(f.path().to_str().unwrap(), "127.0.0.1", 12802).unwrap();
    assert_eq!(u.host_str(), Some("127.0.0.1"));
    assert_eq!(u.port(), Some(12802));
    assert_eq!(u.scheme(), "http");
    let expected_directory = format!("/{}/", encode_path(f.path().parent().unwrap()));
    assert!(u.path().starts_with(&expected_directory));
    assert!(
        u.path()
            .ends_with(f.path().file_name().unwrap().to_str().unwrap())
    );
}

#[test]
fn relative_path_is_canonicalized() {
    // No set_current_dir: it races under the parallel test harness.
    let cwd = std::env::current_dir().unwrap();
    let dir = tempfile::tempdir_in(&cwd).unwrap();
    std::fs::write(dir.path().join("a b.md"), "x").unwrap();
    let rel = dir.path().strip_prefix(&cwd).unwrap().join("a b.md");
    let u = to_url(rel.to_str().unwrap(), "127.0.0.1", 12802).unwrap();
    assert!(u.path().ends_with("/a%20b.md"));
}

#[test]
fn missing_path_errors() {
    assert!(matches!(
        to_url("/no/such/file", "127.0.0.1", 12802),
        Err(TargetError::NotFound(_))
    ));
}

#[test]
fn not_found_error_has_forward_prefix() {
    // Given: a missing target error.
    let error = TargetError::NotFound("missing.md".to_string());

    // When: it is rendered for the CLI.
    let rendered = error.to_string();

    // Then: it identifies the forward command.
    assert_eq!(rendered, "forward: path not found: missing.md");
}

#[test]
fn invalid_error_has_forward_prefix() {
    // Given: an invalid target error.
    let error = TargetError::Invalid("invalid input".to_string());

    // When: it is rendered for the CLI.
    let rendered = error.to_string();

    // Then: it identifies the forward command.
    assert_eq!(rendered, "forward: cannot use target: invalid input");
}

#[test]
fn opaque_url_scheme_is_not_openable() {
    let error = to_url("mailto:user@example.com", "127.0.0.1", 12802).unwrap_err();

    assert_eq!(
        error.to_string(),
        "forward: URL scheme is not openable: mailto"
    );
}

#[test]
fn special_bytes_survive_roundtrip() {
    let cwd = std::env::current_dir().unwrap();
    let dir = tempfile::tempdir_in(&cwd).unwrap();
    let name = "p%20c#h?q\\b.md";
    std::fs::write(dir.path().join(name), "x").unwrap();
    let rel = dir.path().strip_prefix(&cwd).unwrap().join(name);
    let u = to_url(rel.to_str().unwrap(), "127.0.0.1", 12802).unwrap();
    assert!(u.path().ends_with("/p%2520c%23h%3Fq%5Cb.md"));
}

#[test]
fn non_utf8_path_components_are_percent_encoded() {
    let cwd = std::env::current_dir().unwrap();
    let dir = tempfile::tempdir_in(&cwd).unwrap();
    let non_utf8_directory = dir.path().join(OsStr::from_bytes(b"caf\xe9"));
    std::fs::create_dir(&non_utf8_directory).unwrap();
    let target = non_utf8_directory.join("document.md");
    std::fs::write(&target, "x").unwrap();
    let link = dir.path().join("document-link.md");
    std::os::unix::fs::symlink(&target, &link).unwrap();

    let u = to_url(link.to_str().unwrap(), "127.0.0.1", 12802).unwrap();

    assert!(u.path().contains("/caf%E9/document.md"));
}

#[test]
fn canonicalize_errors_other_than_not_found_are_invalid() {
    let f = tempfile::NamedTempFile::new().unwrap();
    let child = f.path().join("child.md");

    assert!(matches!(
        to_url(child.to_str().unwrap(), "127.0.0.1", 12802),
        Err(TargetError::Invalid(_))
    ));
}

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

#[test]
fn file_url_maps_to_files_url() {
    // Given: a file URL naming an existing devbox file.
    let f = tempfile::NamedTempFile::new().unwrap();
    let file_url = Url::from_file_path(f.path()).unwrap();

    // When: it is turned into a target.
    let u = to_url(file_url.as_str(), "127.0.0.1", 12802).unwrap();

    // Then: it is the same preview URL the bare path would have minted.
    assert_eq!(u.scheme(), "http");
    assert_eq!(u.host_str(), Some("127.0.0.1"));
    assert_eq!(u.port(), Some(12802));
    let bare = to_url(f.path().to_str().unwrap(), "127.0.0.1", 12802).unwrap();
    assert_eq!(u.path(), bare.path());
}

#[test]
fn percent_encoded_file_url_roundtrips() {
    // Given: a file whose name needs percent-encoding in a URL.
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("a b.md");
    std::fs::write(&file, "x").unwrap();
    let arg = Url::from_file_path(&file).unwrap();
    assert!(arg.as_str().ends_with("/a%20b.md"));

    // When: the encoded file URL is turned into a target.
    let u = to_url(arg.as_str(), "127.0.0.1", 12802).unwrap();

    // Then: it converted, and the space survived one decode and one re-encode.
    assert_eq!(u.scheme(), "http");
    assert_eq!(u.port(), Some(12802));
    assert!(u.path().ends_with("/a%20b.md"));
}

#[test]
fn non_utf8_file_url_components_are_percent_encoded() {
    // Given: a file URL whose path bytes are not valid UTF-8, which
    // to_file_path decodes straight back into raw OsStr bytes.
    let dir = tempfile::tempdir().unwrap();
    let non_utf8_directory = dir.path().join(OsStr::from_bytes(b"caf\xe9"));
    std::fs::create_dir(&non_utf8_directory).unwrap();
    let target = non_utf8_directory.join("document.md");
    std::fs::write(&target, "x").unwrap();
    let arg = Url::from_file_path(&target).unwrap();

    // When: it is turned into a target.
    let u = to_url(arg.as_str(), "127.0.0.1", 12802).unwrap();

    // Then: it converted, and the raw bytes are encoded on the preview URL —
    // which is why the file branch never turns the path into a &str.
    assert_eq!(u.scheme(), "http");
    assert!(u.path().contains("/caf%E9/document.md"));
}

#[test]
fn file_url_with_a_remote_host_is_invalid() {
    // Given: a file URL whose authority names another machine.
    let error = to_url("file://otherhost/etc/hosts", "127.0.0.1", 12802).unwrap_err();

    // Then: it is refused, because this process can only serve local files.
    assert_eq!(
        error.to_string(),
        "forward: cannot use target: file://otherhost/etc/hosts is not a local file URL"
    );
}

#[test]
fn missing_file_url_errors_as_not_found() {
    assert!(matches!(
        to_url("file:///no/such/file", "127.0.0.1", 12802),
        Err(TargetError::NotFound(_))
    ));
}

#[test]
fn file_url_fragment_is_preserved() {
    // Given: a file URL carrying an anchor, as agent-emitted links do.
    let f = tempfile::NamedTempFile::new().unwrap();
    let arg = format!("{}#anchor", Url::from_file_path(f.path()).unwrap());

    // When: it is turned into a target.
    let u = to_url(&arg, "127.0.0.1", 12802).unwrap();

    // Then: the anchor rides along to the preview URL instead of being lost.
    let bare = to_url(f.path().to_str().unwrap(), "127.0.0.1", 12802).unwrap();
    assert_eq!(u.scheme(), "http");
    assert_eq!(u.path(), bare.path());
    assert_eq!(u.fragment(), Some("anchor"));
}
