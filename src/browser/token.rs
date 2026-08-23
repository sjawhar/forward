use std::path::Path;

/// Compare without an early exit, so a wrong first byte costs what a wrong last
/// byte costs. Length is not secret: a token of the wrong size is already wrong.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        difference |= left_byte ^ right_byte;
    }
    difference == 0
}

/// The expected token, or `None` when it cannot be read.
///
/// A missing, unreadable, or empty file yields `None`, and every caller treats
/// `None` as "refuse everything". A half-provisioned laptop must not be an open
/// laptop.
pub(crate) fn load(path: &Path) -> Option<Vec<u8>> {
    let value = std::fs::read(path).ok()?;
    let trimmed = value.trim_ascii_end();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_values_compare_equal() {
        assert!(constant_time_eq(b"correct-horse", b"correct-horse"));
    }

    #[test]
    fn a_differing_final_byte_compares_unequal() {
        assert!(!constant_time_eq(b"correct-horse", b"correct-horsf"));
    }

    #[test]
    fn differing_lengths_compare_unequal() {
        assert!(!constant_time_eq(b"correct-horse", b"correct"));
    }

    #[test]
    fn an_empty_token_file_yields_no_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        std::fs::write(&path, "\n").unwrap();
        assert_eq!(load(&path), None);
    }

    #[test]
    fn a_trailing_newline_is_not_part_of_the_token() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.token");
        std::fs::write(&path, "correct-horse\n").unwrap();
        assert_eq!(load(&path).as_deref(), Some(b"correct-horse".as_slice()));
    }

    #[test]
    fn a_missing_token_file_yields_no_token() {
        assert_eq!(load(Path::new("/nonexistent/relay.token")), None);
    }
}
