//! Naming the store behind an answer, and the stores behind a refusal.
//!
//! One place builds these strings, so the status object, the injection notice
//! and every refusal describe the same store the same way.

use std::path::PathBuf;

use super::super::error::CliError;
use super::super::status::Provenance;
use super::super::{AgentFile, AgentStore, HumanNames};
use crate::config::Sources;
use crate::secret::SecretName;

/// The agent-tier store for a key: the file sops decrypts.
pub(super) fn agent_provenance(file: &AgentFile) -> Provenance {
    Provenance::Agent {
        source: file.label.clone(),
        path: file.path.clone(),
    }
}

/// The human-tier store for a key: the daemon, and the file this client's
/// configuration resolves the key to, which is the one the daemon decrypts.
pub(super) fn human_provenance(
    human: &HumanNames,
    name: &SecretName,
    socket: PathBuf,
    grant_active: bool,
    ttl_secs: Option<u64>,
) -> Provenance {
    Provenance::Human {
        source: human
            .location(name)
            .map_or_else(|| "unknown".to_owned(), |location| location.label.clone()),
        socket,
        grant_active,
        ttl_secs,
    }
}

/// Every store this client would have looked in for a key it cannot find.
pub(super) fn missing(agent: &AgentStore, sources: &Sources, name: &SecretName) -> CliError {
    let human: Vec<String> = sources
        .roots
        .iter()
        .map(|root| format!("{} ({})", root.name, root.human_dir().display()))
        .collect();
    CliError::MissingSecret {
        name: name.clone(),
        searched: format!(
            "{} and human-tier directories {}",
            agent.searched(),
            human.join(", ")
        ),
    }
}

/// Both files a doubled key lives in, so the human knows which to remove.
pub(super) fn ambiguous(human: &HumanNames, name: &SecretName, file: &AgentFile) -> CliError {
    CliError::AmbiguousKey {
        name: name.clone(),
        agent: file.describe(),
        human: human.location(name).map_or_else(
            || "human tier".to_owned(),
            |location| format!("{} ({})", location.label, location.path.display()),
        ),
    }
}
