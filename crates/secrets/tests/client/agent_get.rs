use super::Fixture;

#[test]
fn agent_get_works_with_a_minimal_noninteractive_environment() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "--value", "AGENT_ONLY"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"agent-value\n");
    assert!(
        fixture
            .sops_arguments()
            .windows(b"--input-type\0dotenv\0--output-type\0dotenv\0".len())
            .any(|window| window == b"--input-type\0dotenv\0--output-type\0dotenv\0")
    );
    assert!(!fixture.sops_log().contains("secretsd.sock"));
}

#[test]
fn agent_get_uses_the_optional_local_overlay_before_the_shared_file() {
    let fixture = Fixture::agent("KEY=shared-value\n");
    fixture.write_local("KEY=local-value\n");

    let output = fixture.run_minimal(["get", "KEY", "--value"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"local-value\n");
}

#[test]
fn agent_get_succeeds_when_the_optional_local_overlay_is_missing() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "AGENT_ONLY", "--value"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"agent-value\n");
}

#[test]
fn bare_agent_get_reports_status_without_decrypting_or_printing_the_value() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "AGENT_ONLY"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        output.stdout,
        br#"{"key":"AGENT_ONLY","tier":"agent"}
"#
    );
    assert!(
        !output
            .stdout
            .windows(b"agent-value".len())
            .any(|bytes| bytes == b"agent-value")
    );
    assert_eq!(fixture.sops_calls(), 0);
    // Status output is machine-readable and complete on stdout; nothing else is
    // emitted, so callers piping it get JSON and only JSON.
    assert_eq!(output.stderr, b"");
}
