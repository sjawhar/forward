use base64::Engine as _;
use std::fs::OpenOptions;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

/// Token entropy. 32 bytes is the usual symmetric-secret size and encodes to 43
/// base64 characters, comfortably inside the request-line cap.
const TOKEN_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("failed to read /dev/urandom: {source}")]
    Entropy {
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write token {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to restrict token {path} to 0600: {source}")]
    Restrict {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

/// Generate a relay token, store it at `path` with mode `0600`, and return it.
///
/// The value is returned rather than logged: its only legitimate destination is
/// the caller's stdout, on its way into `secrets edit-human`.
pub fn write_token(path: &Path) -> Result<String, InitError> {
    let mut raw = [0_u8; TOKEN_BYTES];
    std::fs::File::open("/dev/urandom")
        .and_then(|mut source| source.read_exact(&mut raw))
        .map_err(|source| InitError::Entropy { source })?;
    let value = base64::engine::general_purpose::STANDARD_NO_PAD.encode(raw);

    let write_error = |source| InitError::Write {
        path: path.display().to_string(),
        source,
    };
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(write_error)?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(write_error)?;
    // `OpenOptions::mode` applies only at creation. Rotating an existing file
    // keeps whatever mode it had, so restrict it explicitly every time, and
    // propagate a failure: a token the group can read is not provisioned.
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|source| InitError::Restrict {
            path: path.display().to_string(),
            source,
        })?;
    writeln!(file, "{value}").map_err(write_error)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_written_token_is_the_returned_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        let value = write_token(&path).unwrap();
        let stored = std::fs::read_to_string(&path).unwrap();
        assert!(stored.trim_end() == value);
    }

    #[test]
    fn the_token_file_is_readable_only_by_its_owner() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        write_token(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn rotating_a_world_readable_file_restores_owner_only_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        std::fs::write(&path, "old\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        write_token(&path).unwrap();

        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_missing_parent_directory_is_created() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("forward/relay.token");
        write_token(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn two_tokens_differ() {
        let directory = tempfile::tempdir().unwrap();
        let first = write_token(&directory.path().join("a")).unwrap();
        let second = write_token(&directory.path().join("b")).unwrap();
        assert!(first != second, "successive tokens should differ");
    }

    #[test]
    fn rotating_replaces_the_previous_value() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        let first = write_token(&path).unwrap();
        let second = write_token(&path).unwrap();
        assert!(first != second, "successive tokens should differ");
        assert!(std::fs::read_to_string(&path).unwrap().trim_end() == second);
    }
}
