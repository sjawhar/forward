use super::Fixture;

#[test]
fn get_rejects_missing_extra_and_unknown_arguments() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    for arguments in [
        ["get"].as_slice(),
        ["get", "AGENT_ONLY", "ANOTHER"].as_slice(),
        ["get", "AGENT_ONLY", "--unknown"].as_slice(),
        ["get", "--value"].as_slice(),
    ] {
        let output = fixture.run_minimal(arguments);

        assert_ne!(output.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("usage: secrets get KEY [--value|--no-request]")
        );
    }
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn duplicate_agent_and_human_name_fails_closed_before_output() {
    let fixture = Fixture::agent("DUP=agent-value\n");
    fixture.write_human_name("DUP");

    for arguments in [
        ["get", "DUP"].as_slice(),
        ["list"].as_slice(),
        ["DUP", "--", "true"].as_slice(),
    ] {
        let output = fixture.run_minimal(arguments);

        assert_ne!(output.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("exists in both agent and human tiers")
        );
    }
}

#[test]
fn get_rejects_path_traversal_before_constructing_a_path() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "../AGENT_ONLY"]);

    assert_ne!(output.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid secret key"));
    assert_eq!(fixture.sops_calls(), 0);
    assert!(!fixture.dotfiles_dir().join("AGENT_ONLY.env").exists());
}

#[test]
fn inject_form_sets_values_only_in_the_child_environment() {
    let fixture = Fixture::agent("A=one\nB=two\n");

    let output = fixture.run_minimal(["A", "B", "--", "sh", "-c", "printf '%s:%s' \"$A\" \"$B\""]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"one:two");
}
