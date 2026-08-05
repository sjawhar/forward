use super::super::*;

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
