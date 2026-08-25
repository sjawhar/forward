use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use super::super::*;

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
