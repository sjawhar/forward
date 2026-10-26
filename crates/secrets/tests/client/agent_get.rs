use super::Fixture;

#[test]
fn agent_get_works_with_a_minimal_noninteractive_environment() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "--value", "AGENT_ONLY"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"agent-value\n");
    // The value is on stdout alone; the store that answered is on stderr, so a
    // reader cannot mistake this file for another secrets CLI's store.
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!(
            "secrets: AGENT_ONLY from agent tier, source dotfiles ({})\n",
            fixture.dotfiles_dir().join("secrets.env").display()
        )
    );
    assert!(!String::from_utf8_lossy(&output.stderr).contains("agent-value"));
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
    // The named file is the one that answered, not the first configured.
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        format!(
            "secrets: KEY from agent tier, source dotfiles.local ({})\n",
            fixture.dotfiles_dir().join("secrets.local.env").display()
        )
    );
}

#[test]
fn agent_get_succeeds_when_the_optional_local_overlay_is_missing() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "AGENT_ONLY", "--value"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"agent-value\n");
}

#[test]
fn bare_agent_get_reports_its_file_without_decrypting_or_printing_the_value() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "AGENT_ONLY"]);

    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            r#"{{"key":"AGENT_ONLY","tier":"agent","store":"sops file","source":"dotfiles","path":"{}"}}{}"#,
            fixture.dotfiles_dir().join("secrets.env").display(),
            "\n"
        )
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

#[test]
fn a_key_in_no_store_names_every_place_the_client_looked() {
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");

    let output = fixture.run_minimal(["get", "ABSENT_KEY"]);

    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("secret 'ABSENT_KEY' not found"), "{stderr}");
    assert!(
        stderr.contains(&format!(
            "dotfiles.local ({})",
            fixture.dotfiles_dir().join("secrets.local.env").display()
        )),
        "{stderr}"
    );
    assert!(
        stderr.contains(&format!(
            "human-tier directories dotfiles ({})",
            fixture.dotfiles_dir().join("secrets.human.d").display()
        )),
        "{stderr}"
    );
}
