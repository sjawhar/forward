//! `secrets edit` on an existing agent-tier file: sops works on a staged copy,
//! and the stage is published only if nothing clashes and nothing raced.

use std::process::Stdio;

use nix::fcntl::{Flock, FlockArg};
use nix::pty::openpty;

use super::Fixture;

/// No `.secretsd-edit-*` stage survived in `directory`.
fn assert_no_stage_left(directory: &std::path::Path) {
    assert!(
        std::fs::read_dir(directory).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".secretsd-edit-")),
        "a staged copy survived"
    );
}

/// The run failed and its stderr names `needle`.
fn refused(output: &std::process::Output, needle: &str) {
    assert_ne!(output.status.code(), Some(0));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(needle), "{stderr}");
}

#[test]
fn existing_agent_file_edit_refuses_a_name_the_human_tier_holds_and_keeps_the_original() {
    // Given: an existing agent file and a human-tier key the edit is about to add.
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");
    fixture.write_human_name("CLASH");
    fixture.use_sops_fixture("fake-sops-edit-adds-clash");
    let target = fixture.dotfiles_dir().join("secrets.env");

    // When: sops (the fake appends CLASH=…) edits the staged copy.
    let output = Fixture::run_in_tty(fixture.command(["edit"]));

    // Then: refused; the original is byte-identical; no stage is left behind.
    refused(&output, "'CLASH' is a human-tier key");
    assert_eq!(std::fs::read(&target).unwrap(), b"AGENT_ONLY=agent-value\n");
    assert_no_stage_left(fixture.dotfiles_dir());
    // The fake edited the stage, not the target.
    assert!(
        !fixture.sops_log().contains("dotfiles/secrets.env\n"),
        "{}",
        fixture.sops_log()
    );
}

#[test]
fn existing_agent_file_edit_publishes_a_clean_result_over_the_original() {
    // Given: an existing agent file; the name the edit adds is nobody's human key.
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");
    fixture.write_human_name("UNRELATED");
    fixture.use_sops_fixture("fake-sops-edit-adds-clash");
    let target = fixture.dotfiles_dir().join("secrets.env");

    // When: sops edits the staged copy.
    let output = Fixture::run_in_tty(fixture.command(["edit"]));

    // Then: the edited stage replaced the original and nothing else is left.
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&target).unwrap(),
        b"AGENT_ONLY=agent-value\nCLASH=added-by-edit\n"
    );
    assert_no_stage_left(fixture.dotfiles_dir());
}

#[test]
fn existing_agent_file_edit_refuses_to_publish_over_a_concurrent_change() {
    // Given: the agent file is replaced by another writer while sops edits the stage.
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");
    fixture.use_sops_fixture("fake-sops-edit-adds-clash");
    let target = fixture.dotfiles_dir().join("secrets.env");
    // The fake edits the stage, then rewrites the target (the other writer landing).
    let mut command = fixture.command(["edit"]);
    command.env("FAKE_SOPS_CLOBBER_TARGET", &target);
    let output = Fixture::run_in_tty(command);

    // Then: nothing is published over the other writer's file; the stage is gone.
    refused(&output, "changed while it was being edited");
    assert_eq!(std::fs::read(&target).unwrap(), b"OTHER_WRITER=won\n");
    assert_no_stage_left(fixture.dotfiles_dir());
}

#[test]
fn existing_agent_file_edit_blocks_on_the_directory_lock() {
    // Given: another writer holds the source directory's lock.
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");
    fixture.use_sops_fixture("fake-sops-edit-adds-clash");
    let directory = std::fs::File::open(fixture.dotfiles_dir()).unwrap();
    let lock = Flock::lock(directory, FlockArg::LockExclusive).unwrap();
    let terminal = openpty(None, None).unwrap();
    let mut child = fixture
        .command(["edit"])
        .stdin(Stdio::from(std::fs::File::from(terminal.slave)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Then: the edit waits for the lock instead of staging around it.
    std::thread::sleep(std::time::Duration::from_millis(300));
    assert!(
        child.try_wait().unwrap().is_none(),
        "the edit did not block on the lock"
    );
    assert_eq!(fixture.sops_calls(), 0, "sops ran before the lock was held");
    drop(lock);
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(fixture.dotfiles_dir().join("secrets.env")).unwrap(),
        b"AGENT_ONLY=agent-value\nCLASH=added-by-edit\n"
    );
}

#[test]
fn existing_agent_file_edit_sees_a_human_key_created_while_the_editor_was_open() {
    // Given: CLASH becomes a human-tier key only after the edit starts (the fake
    // sops creates it on the way out, standing in for a concurrent edit-human).
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");
    fixture.use_sops_fixture("fake-sops-edit-adds-clash");
    let human_file = fixture.dotfiles_dir().join("secrets.human.d/CLASH.env");
    std::fs::create_dir_all(human_file.parent().unwrap()).unwrap();

    let mut command = fixture.command(["edit"]);
    command.env("FAKE_SOPS_CREATE_HUMAN", &human_file);
    let output = Fixture::run_in_tty(command);

    // Then: the clash is judged against the human tier at publish time, not launch.
    refused(&output, "'CLASH' is a human-tier key");
    assert_eq!(
        std::fs::read(fixture.dotfiles_dir().join("secrets.env")).unwrap(),
        b"AGENT_ONLY=agent-value\n"
    );
}

#[test]
fn existing_agent_file_edit_follows_a_symlink_to_its_referent() {
    // Given: the source root's secrets.env is a symlink into another directory.
    let fixture = Fixture::agent("");
    let link = fixture.dotfiles_dir().join("secrets.env");
    std::fs::remove_file(&link).unwrap();
    let actual_dir = fixture.dotfiles_dir().join("actual");
    std::fs::create_dir(&actual_dir).unwrap();
    let referent = actual_dir.join("actual.env");
    std::fs::write(&referent, b"AGENT_ONLY=agent-value\n").unwrap();
    std::os::unix::fs::symlink("actual/actual.env", &link).unwrap();
    fixture.use_sops_fixture("fake-sops-edit-adds-clash");

    let output = Fixture::run_in_tty(fixture.command(["edit"]));

    // Then: the referent carries the edit and the link is still a link.
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert_eq!(
        std::fs::read(&referent).unwrap(),
        b"AGENT_ONLY=agent-value\nCLASH=added-by-edit\n"
    );
    assert_no_stage_left(&actual_dir);
}

#[test]
fn write_lock_takes_each_directory_once_when_roots_alias() {
    // Given: a second source root that is a symlink to the first (the config
    // rejects only identical paths; with any human-tier key present the alias is
    // refused earlier as a duplicate human location, so the store has none).
    // Two exclusive flocks on one inode from one process would wait forever.
    let fixture = Fixture::agent("AGENT_ONLY=agent-value\n");
    fixture.use_sops_fixture("fake-sops-edit-adds-clash");
    let alias = fixture.root_dir("alias");
    std::os::unix::fs::symlink(fixture.dotfiles_dir(), &alias).unwrap();
    fixture.add_root_at("alias", &alias);

    let output = Fixture::run_in_tty(fixture.command(["edit", "--source", "dotfiles"]));

    // Then: the edit completes instead of hanging on its own lock.
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(fixture.dotfiles_dir().join("secrets.env")).unwrap(),
        b"AGENT_ONLY=agent-value\nCLASH=added-by-edit\n"
    );
}
