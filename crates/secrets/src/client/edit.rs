//! Multi-source edit path selection.
//!
//! A key lives in one tier. Every write door checks the other tier and
//! publishes under the same lock - every configured source root's directory,
//! taken in configuration order - so two writers cannot each pass their check
//! and both publish. The agent doors re-read the human tier under the lock
//! right before publishing; the human door reads agent-tier names from the
//! ciphertext, which is current by construction.

use std::ffi::OsString;
use std::fs::File;
use std::io::IsTerminal;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::process::Command;

use nix::fcntl::{Flock, FlockArg};

use super::cli::parse_name;
use super::{AgentStore, CliError, HumanLocation, HumanNames};
use crate::config::{ConfigError, SourceRoot, Sources};
use crate::secret::SecretName;

mod existing;
mod new;
mod plaintext;

/// Edit an agent-tier file in the selected source root.
///
/// A new file is checked as edited plaintext before encryption; an existing
/// file is edited by sops on a staged copy and renamed over the original only
/// after the check. Neither door can publish a clash.
pub(super) fn agent(
    sources: &Sources,
    source: Option<&OsString>,
    local: bool,
) -> Result<(), CliError> {
    let flags = EditArguments { source, local };
    let [local_path, shared_path] = select_root(sources, flags.source)?.agent_files();
    let path = if local { local_path } else { shared_path };
    let _locks = lock_roots(sources)?;
    if path.exists() {
        existing::edit_agent(&path, &sources.roots)
    } else {
        new::agent(&path, local, &sources.roots)
    }
}

/// Edit a human-tier key or write it from a non-terminal standard input stream.
///
/// Refused while the agent tier holds the same name: the agent copy has to go
/// first (`secrets edit`), or reads of the key would be ambiguous.
pub(super) fn human(
    sources: &Sources,
    agent: &AgentStore,
    human: &HumanNames,
    raw_key: &OsString,
    source: Option<&OsString>,
    local: bool,
) -> Result<(), CliError> {
    let name = parse_name(raw_key)?;
    let flags = EditArguments { source, local };
    let piped = !std::io::stdin().is_terminal();
    let _locks = lock_roots(sources)?;
    if agent.contains(&name)? {
        return Err(CliError::AgentKeyExists(name));
    }
    if let Some(location) = human.location(&name) {
        let path = existing_human_path(
            sources,
            &ExistingHumanEdit {
                name: &name,
                location,
                flags,
            },
        )?;
        if piped {
            new::write_piped_human(&path, &name)
        } else {
            edit(&path)
        }
    } else {
        let path = new_human_path(sources, &name, flags)?;
        if piped {
            new::write_piped_human(&path, &name)
        } else {
            new::human(&path, &name)
        }
    }
}

/// The write lock: every configured source root, in configuration order, so
/// concurrent writers - either tier, any root - serialize against each other
/// and never deadlock. Two roots that are the same directory under different
/// names (a symlink alias; the config rejects only identical paths) are locked
/// once: a second exclusive flock on the same inode from the same process
/// would wait on itself forever. Released when the returned guards drop.
fn lock_roots(sources: &Sources) -> Result<Vec<Flock<File>>, CliError> {
    let mut locked: Vec<(u64, u64)> = Vec::with_capacity(sources.roots.len());
    let mut guards = Vec::with_capacity(sources.roots.len());
    for root in &sources.roots {
        let directory = File::open(&root.path).map_err(|_| CliError::InstallEditedSecret)?;
        let metadata = directory
            .metadata()
            .map_err(|_| CliError::InstallEditedSecret)?;
        let identity = (metadata.dev(), metadata.ino());
        if locked.contains(&identity) {
            continue;
        }
        locked.push(identity);
        guards.push(
            Flock::lock(directory, FlockArg::LockExclusive)
                .map_err(|_| CliError::InstallEditedSecret)?,
        );
    }
    Ok(guards)
}

/// Refuse `names` if the human tier, re-read now, holds any of them. Both
/// agent doors call this under the write lock right before they publish, so a
/// key created while the editor was open is seen.
pub(super) fn ensure_no_human_clash(
    names: &[SecretName],
    roots: &[SourceRoot],
) -> Result<(), CliError> {
    let human = HumanNames::load(roots)?;
    names
        .iter()
        .find(|name| human.contains(name))
        .map_or(Ok(()), |name| Err(CliError::HumanKeyExists(name.clone())))
}

#[derive(Clone, Copy)]
struct EditArguments<'a> {
    source: Option<&'a OsString>,
    local: bool,
}

struct ExistingHumanEdit<'a> {
    name: &'a SecretName,
    location: &'a HumanLocation,
    flags: EditArguments<'a>,
}

fn existing_human_path(
    sources: &Sources,
    edit: &ExistingHumanEdit<'_>,
) -> Result<PathBuf, CliError> {
    let actual_source = edit
        .location
        .label
        .strip_suffix(".local")
        .unwrap_or(edit.location.label.as_str());
    if let Some(source) = edit.flags.source {
        let selected = select_named_root(sources, source)?;
        if selected.name != actual_source {
            return Err(CliError::EditConflict {
                name: edit.name.clone(),
                actual: edit.location.label.clone(),
            });
        }
    }
    let actual_local = edit.location.label.as_str() != actual_source;
    if edit.flags.local && !actual_local {
        return Err(CliError::EditConflict {
            name: edit.name.clone(),
            actual: edit.location.label.clone(),
        });
    }
    Ok(edit.location.path.clone())
}

fn new_human_path(
    sources: &Sources,
    name: &SecretName,
    flags: EditArguments<'_>,
) -> Result<PathBuf, CliError> {
    let root = select_root(sources, flags.source)?;
    let directory = root.human_dir();
    std::fs::create_dir_all(&directory).map_err(CliError::HumanDirectory)?;
    let file_name = if flags.local {
        name.local_file_name()
    } else {
        name.file_name()
    };
    Ok(directory.join(file_name))
}

fn select_root<'a>(
    sources: &'a Sources,
    source: Option<&OsString>,
) -> Result<&'a SourceRoot, CliError> {
    source.map_or_else(
        || match sources.roots.as_slice() {
            [root] => Ok(root),
            [] => Err(CliError::Config(ConfigError::NoRoots)),
            _ => Err(CliError::EditSourceRequired(source_names(sources))),
        },
        |source| select_named_root(sources, source),
    )
}

fn select_named_root<'a>(
    sources: &'a Sources,
    raw_source: &OsString,
) -> Result<&'a SourceRoot, CliError> {
    let source = raw_source.to_str().ok_or(CliError::Usage)?;
    sources
        .roots
        .iter()
        .find(|root| root.name == source)
        .ok_or_else(|| CliError::UnknownEditSource {
            source: source.to_owned(),
            available: source_names(sources),
        })
}

fn source_names(sources: &Sources) -> String {
    sources
        .roots
        .iter()
        .map(|root| root.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// sops edits the human-tier file in place. Not exec'd: the write lock lives on
/// this process's descriptors and has to outlast the editor.
fn edit(path: &PathBuf) -> Result<(), CliError> {
    let status = Command::new("sops")
        .arg(path)
        .status()
        .map_err(CliError::SopsStart)?;
    if status.success() {
        Ok(())
    } else {
        Err(CliError::SopsEditFailed(status))
    }
}
