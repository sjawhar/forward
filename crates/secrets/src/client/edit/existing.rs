//! Editing an existing agent-tier file without letting sops touch the original.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use tempfile::Builder;

use super::super::CliError;
use super::super::agent::AgentStore;
use crate::config::SourceRoot;

/// Edit an existing agent-tier file with sops, publishing the result only if
/// it introduces no human-tier name. Runs under the write lock the caller
/// holds (`edit::lock_roots`).
///
/// sops edits in place, so it works on a staged copy beside the target (same
/// directory, so `.sops.yaml` path rules match). The stage's names are read
/// from its ciphertext (sops keeps dotenv names in the clear); a clash leaves
/// the original untouched. The stage replaces the original by rename, and
/// only while the original still holds the bytes that were staged. That
/// re-read is the guard against a writer that does not take the lock (a sync
/// tool): one that lands before it is caught; one that lands between it and
/// the rename is not - there is no compare-and-rename, and every other write
/// in this client (and sops itself, editing in place) has the same window.
/// Writers that do take the lock cannot land at all while this runs.
///
/// A symlinked agent file is edited through its referent: the stage sits
/// beside the real file and replaces it, and the link stays a link.
pub(super) fn edit_agent(path: &Path, roots: &[SourceRoot]) -> Result<(), CliError> {
    let target = std::fs::canonicalize(path).map_err(CliError::AgentKeySet)?;
    let directory = target.parent().ok_or(CliError::InstallEditedSecret)?;
    let before = std::fs::read(&target).map_err(CliError::AgentKeySet)?;
    let stage = Builder::new()
        .prefix(".secretsd-edit-")
        .suffix(".env")
        .tempfile_in(directory)
        .map_err(|_| CliError::EditTemp)?;
    stage
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))
        .map_err(|_| CliError::EditTemp)?;
    std::fs::write(stage.path(), &before).map_err(|_| CliError::EditTemp)?;
    let status = Command::new("sops")
        .arg(stage.path())
        .status()
        .map_err(CliError::SopsStart)?;
    if !status.success() {
        return Err(CliError::SopsEditFailed(status));
    }
    super::ensure_no_human_clash(&AgentStore::names_in(stage.path())?, roots)?;
    if std::fs::read(&target).map_err(CliError::AgentKeySet)? != before {
        return Err(CliError::AgentFileChangedDuringEdit);
    }
    stage
        .persist(&target)
        .map(|_| ())
        .map_err(|_| CliError::InstallEditedSecret)
}
