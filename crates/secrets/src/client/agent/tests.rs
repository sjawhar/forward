use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::{AgentFile, AgentStore};
use crate::client::CliError;
use crate::secret::SecretName;

fn name(raw: &str) -> SecretName {
    SecretName::parse(raw).unwrap()
}

fn fake_sops(directory: &tempfile::TempDir) -> PathBuf {
    let path = directory.path().join("fake-sops");
    fs::write(&path, b"#!/bin/bash\ncat \"${!#}\"\n").unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

#[test]
#[cfg_attr(miri, ignore)]
fn earlier_file_wins_when_a_key_reappears_in_a_later_file() {
    let directory = tempfile::tempdir().unwrap();
    let first = directory.path().join("first.env");
    let second = directory.path().join("second.env");
    let third = directory.path().join("third.env");
    fs::write(&first, b"KEY=first\n").unwrap();
    fs::write(&second, b"OTHER=second\n").unwrap();
    fs::write(&third, b"KEY=third\n").unwrap();
    let store = AgentStore::new(
        vec![
            AgentFile::new("first", first.clone()),
            AgentFile::new("second", second),
            AgentFile::new("third", third),
        ],
        fake_sops(&directory),
    );

    let resolved = store.resolve(&name("KEY")).unwrap();

    // The one resolution returns the plaintext and its winning file together.
    // A future split `locate` then `value` implementation would not establish
    // this pairing when the file changes between its two passes.
    assert_eq!(resolved.value.as_slice(), b"first");
    assert_eq!(resolved.file.path, first);
}

#[test]
#[cfg_attr(miri, ignore)]
fn listed_but_absent_file_is_skipped() {
    let directory = tempfile::tempdir().unwrap();
    let absent = directory.path().join("absent.env");
    let present = directory.path().join("present.env");
    fs::write(&present, b"KEY=present\n").unwrap();
    let store = AgentStore::new(
        vec![
            AgentFile::new("absent", absent),
            AgentFile::new("present", present.clone()),
        ],
        fake_sops(&directory),
    );

    let value = store.value(&name("KEY")).unwrap();

    assert_eq!(value.as_slice(), b"present");
    assert_eq!(store.locate(&name("KEY")).unwrap().unwrap().path, present);
}

#[test]
fn empty_file_list_reports_missing_secret_and_where_it_looked() {
    let name = name("KEY");
    let store = AgentStore::new(Vec::new(), "sops");

    let result = store.value(&name);

    let Err(CliError::MissingSecret {
        name: actual,
        searched,
    }) = result
    else {
        panic!("an absent key must report where the store looked");
    };
    assert_eq!(actual, name);
    assert_eq!(searched, "no configured agent-tier files");
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_missing_key_names_every_file_the_store_read() {
    let directory = tempfile::tempdir().unwrap();
    let shared = directory.path().join("secrets.env");
    fs::write(&shared, b"OTHER=value\n").unwrap();
    let store = AgentStore::new(
        vec![AgentFile::new("dotfiles", shared.clone())],
        fake_sops(&directory),
    );

    let result = store.value(&name("KEY"));

    let Err(CliError::MissingSecret { searched, .. }) = result else {
        panic!("an absent key must report where the store looked");
    };
    assert_eq!(
        searched,
        format!("agent-tier files dotfiles ({})", shared.display())
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_sops_spawn_failure_names_the_file_that_was_being_read() {
    let directory = tempfile::tempdir().unwrap();
    let file = directory.path().join("secrets.env");
    fs::write(&file, b"KEY=value\n").unwrap();
    let missing_sops = directory.path().join("no-sops-here");
    let store = AgentStore::new(
        vec![AgentFile::new("dotfiles", file.clone())],
        missing_sops,
    );

    let error = store.resolve(&name("KEY")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains(&format!("could not start sops for {}", file.display())),
        "{error}"
    );
}
