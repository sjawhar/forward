//! A key lives in one tier: the per-key read refusal and the write-door checks.

use super::{FakeBroker, Fixture, Reply};

/// The run failed and its stderr names `needle`.
fn refused(output: &std::process::Output, needle: &str) {
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(needle), "{stderr}");
}

#[test]
fn duplicate_agent_and_human_name_refuses_that_key_only() {
    // Given: DUP in both tiers; AGENT_ONLY agent-only; HUMAN_ONLY human-only.
    let fixture = Fixture::agent("DUP=agent-value\nAGENT_ONLY=agent-value\n");
    fixture.write_human_name("DUP");
    fixture.write_human_name("HUMAN_ONLY");

    // Then: reads of DUP fail closed, however they are asked for.
    for arguments in [
        ["get", "DUP"].as_slice(),
        ["get", "DUP", "--no-request"].as_slice(),
        ["get", "DUP", "--value"].as_slice(),
        ["DUP", "--", "true"].as_slice(),
        ["AGENT_ONLY", "DUP", "--", "true"].as_slice(),
    ] {
        let output = fixture.run_minimal(arguments);

        assert_ne!(output.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("exists in both agent and human tiers")
        );
    }

    // And: an unrelated human-tier key still reaches the broker -- the 2026-09-20
    // regression, where one doubled key refused every human-tier request.
    let broker = FakeBroker::script([Reply::Hello, Reply::Bytes(b"human-value".to_vec())]);
    let output = fixture.run_broker(
        ["get", "HUMAN_ONLY", "--value"],
        broker.socket(),
        None,
        None,
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"human-value\n");

    // And: an unrelated agent-tier key is unaffected too.
    let output = fixture.run_minimal(["AGENT_ONLY", "--", "sh", "-c", "printf %s \"$AGENT_ONLY\""]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"agent-value");

    // And: the listing the refusal points at still renders, and names the clash.
    let output = fixture.run_minimal(["list"]);
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AGENT_ONLY\n"));
    assert!(
        stdout.contains("DUP  (human tier: dotfiles; ALSO agent tier -- ambiguous, reads refuse)")
    );
    assert!(stdout.contains("HUMAN_ONLY  (human tier: dotfiles)\n"));
}

#[test]
fn edit_human_refuses_a_name_the_agent_tier_holds() {
    // Given: DUP is an agent-tier key with no human-tier file.
    let fixture = Fixture::agent("DUP=agent-value\n");
    let target = fixture.dotfiles_dir().join("secrets.human.d/DUP.env");

    // When: a human-tier copy is written from a pipe.
    let output = fixture.run_with_stdin(["edit-human", "DUP"], b"new-value");

    // Then: refused before anything is written, naming the fix.
    refused(&output, "'DUP' is an agent-tier key");
    refused(&output, "secrets list");
    assert!(!target.exists());
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn new_agent_file_refuses_a_name_the_human_tier_holds() {
    // Given: AGENT_TEST_KEY is a human-tier key, and a second root with no agent file yet.
    let fixture = Fixture::agent("");
    fixture.write_human_name("AGENT_TEST_KEY");
    fixture.add_root("private");
    let target = fixture.root_dir("private").join("secrets.env");

    // When: the editor writes AGENT_TEST_KEY into the new agent file.
    let output = fixture.run_editor(
        ["edit", "--source", "private"],
        "# shared agent-tier secrets\n",
        "valid-agent",
        None,
    );

    // Then: nothing is encrypted; the clash is named.
    refused(&output, "'AGENT_TEST_KEY' is a human-tier key");
    assert!(!target.exists());
    assert_eq!(fixture.sops_calls(), 0);
}

#[test]
fn new_agent_file_sees_a_human_key_created_while_the_editor_was_open() {
    // Given: AGENT_TEST_KEY becomes a human-tier key only after the editor opens
    // (the fake editor creates it on the way out, standing in for a concurrent
    // edit-human); the second root has no agent file yet.
    let fixture = Fixture::agent("");
    fixture.add_root("private");
    let human_file = fixture
        .dotfiles_dir()
        .join("secrets.human.d/AGENT_TEST_KEY.env");
    std::fs::create_dir_all(human_file.parent().unwrap()).unwrap();
    let target = fixture.root_dir("private").join("secrets.env");
    let mut command = fixture.command(["edit", "--source", "private"]);
    command
        .env("EDITOR", fixture.editor())
        .env("FAKE_EDITOR_EXPECTED", "# shared agent-tier secrets\n")
        .env("FAKE_EDITOR_MODE", "valid-agent")
        .env("FAKE_EDITOR_CREATE_HUMAN", &human_file);

    let output = Fixture::run_in_tty(command);

    // Then: the clash is judged against the human tier at publish time, not launch.
    refused(&output, "'AGENT_TEST_KEY' is a human-tier key");
    assert!(!target.exists());
}
