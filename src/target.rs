use percent_encoding::{AsciiSet, CONTROLS, percent_encode};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use url::Url;

const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'\\')
    .add(b'`')
    .add(b'{')
    .add(b'}');

#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("forward: path not found: {0}")]
    NotFound(String),
    #[error("forward: cannot use target: {0}")]
    Invalid(String),
    #[error("forward: URL scheme is not openable: {0}")]
    UnsupportedScheme(String),
}

pub fn to_url(arg: &str, files_port: u16) -> Result<Url, TargetError> {
    if let Ok(url) = Url::parse(arg) {
        if url.cannot_be_a_base() {
            return Err(TargetError::UnsupportedScheme(url.scheme().to_owned()));
        }
        return Ok(url);
    }
    let abs = std::fs::canonicalize(arg).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => TargetError::NotFound(arg.to_string()),
        _ => TargetError::Invalid(format!("{arg}: {e}")),
    })?;
    let encoded = encode_path(&abs);
    Url::parse(&format!("http://localhost:{files_port}/{encoded}"))
        .map_err(|e| TargetError::Invalid(e.to_string()))
}

fn encode_path(path: &Path) -> String {
    path.components()
        .filter_map(|c| match c {
            std::path::Component::RootDir => None,
            c => Some(percent_encode(c.as_os_str().as_bytes(), PATH_SEGMENT).to_string()),
        })
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn url_passes_through() {
        let u = to_url("https://example.com/x?y=1", 12802).unwrap();
        assert_eq!(u.as_str(), "https://example.com/x?y=1");
    }

    #[test]
    fn existing_file_maps_to_files_url() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let u = to_url(f.path().to_str().unwrap(), 12802).unwrap();
        assert_eq!(u.host_str(), Some("localhost"));
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
        let u = to_url(rel.to_str().unwrap(), 12802).unwrap();
        assert!(u.path().ends_with("/a%20b.md"));
    }

    #[test]
    fn missing_path_errors() {
        assert!(matches!(
            to_url("/no/such/file", 12802),
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
        let error = to_url("mailto:user@example.com", 12802).unwrap_err();

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
        let u = to_url(rel.to_str().unwrap(), 12802).unwrap();
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

        let u = to_url(link.to_str().unwrap(), 12802).unwrap();

        assert!(u.path().contains("/caf%E9/document.md"));
    }

    #[test]
    fn canonicalize_errors_other_than_not_found_are_invalid() {
        let f = tempfile::NamedTempFile::new().unwrap();
        let child = f.path().join("child.md");

        assert!(matches!(
            to_url(child.to_str().unwrap(), 12802),
            Err(TargetError::Invalid(_))
        ));
    }
}
