use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use super::super::*;

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

#[test]
fn file_url_with_localhost_host_is_local() {
    // Given: a real local file named by a localhost file URL.
    let f = tempfile::NamedTempFile::new().unwrap();
    let file_url = Url::from_file_path(f.path()).unwrap();
    let arg = file_url.as_str().replacen("file://", "file://localhost", 1);

    // When: it is turned into a target.
    let u = to_url(&arg, "127.0.0.1", 12802).unwrap();

    // Then: it converted to the same preview path as the bare local path.
    assert_eq!(u.scheme(), "http");
    let bare = to_url(f.path().to_str().unwrap(), "127.0.0.1", 12802).unwrap();
    assert_eq!(u.path(), bare.path());
}

#[test]
fn file_url_query_is_dropped() {
    // Given: a real local file URL carrying a query string.
    let f = tempfile::NamedTempFile::new().unwrap();
    let arg = format!("{}?raw=1", Url::from_file_path(f.path()).unwrap());

    // When: it is turned into a target.
    let u = to_url(&arg, "127.0.0.1", 12802).unwrap();

    // Then: it converted without carrying the file URL query into the preview URL.
    assert_eq!(u.scheme(), "http");
    assert_eq!(u.query(), None);
    let bare = to_url(f.path().to_str().unwrap(), "127.0.0.1", 12802).unwrap();
    assert_eq!(u.path(), bare.path());
}
