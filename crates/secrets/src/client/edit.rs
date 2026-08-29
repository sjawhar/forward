//! Multi-source edit path selection.

use std::ffi::OsString;
use std::io::IsTerminal;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;

use super::cli::parse_name;
use super::{CliError, HumanLocation, HumanNames};
use crate::config::{ConfigError, SourceRoot, Sources};
use crate::secret::SecretName;

mod new;

/// Edit an agent-tier file in the selected source root.
pub(super) fn agent(
    sources: &Sources,
    source: Option<&OsString>,
    local: bool,
) -> Result<(), CliError> {
    let flags = EditArguments { source, local };
    let [local_path, shared_path] = select_root(sources, flags.source)?.agent_files();
    let path = if local { local_path } else { shared_path };
    if path.exists() {
        edit(path)
    } else {
        new::agent(&path, local)
    }
}

/// Edit a human-tier key or write it from a non-terminal standard input stream.
pub(super) fn human(
    sources: &Sources,
    human: &HumanNames,
    raw_key: &OsString,
    source: Option<&OsString>,
    local: bool,
) -> Result<(), CliError> {
    let name = parse_name(raw_key)?;
    let flags = EditArguments { source, local };
    let piped = !std::io::stdin().is_terminal();
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
            edit(path)
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

fn edit(path: PathBuf) -> Result<(), CliError> {
    Err(CliError::Exec(Command::new("sops").arg(path).exec()))
}
