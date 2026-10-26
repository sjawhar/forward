use std::io::Write;

use super::{CliError, ClientError, caller_tty};
use crate::secret::SecretName;

mod provenance;

pub(super) use provenance::Provenance;

#[derive(Clone, Copy)]
pub(super) enum GetOutput {
    /// Ask the broker to grant the key, then report status. Blocks for the
    /// human's approval, so this is how a session pre-authorizes itself.
    Request,
    /// Report what is known without asking for anything, so no touch is needed.
    Status,
    /// Print the secret itself.
    Value,
}

/// Print the one-line JSON status object, naming the store that answers.
pub(super) fn write_status(name: &SecretName, provenance: &Provenance) -> Result<(), CliError> {
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{}", provenance.status_json(name)).map_err(CliError::Stdout)
}

/// Write one line naming each key's store, before any value leaves this process.
///
/// Values never appear here: the line is the provenance of what is about to be
/// handed over, which is what a reader needs to tell two secrets CLIs apart.
pub(super) fn announce(injected: &[(&str, &Provenance)]) -> Result<(), CliError> {
    let named: Vec<String> = injected
        .iter()
        .map(|(name, provenance)| format!("{name} from {}", provenance.describe()))
        .collect();
    let mut stderr = std::io::stderr().lock();
    writeln!(stderr, "secrets: {}", named.join("; ")).map_err(CliError::SourceNotice)
}

pub(super) fn active_grant(name: &SecretName, grants: &[u8]) -> Result<bool, ClientError> {
    let listing = std::str::from_utf8(grants).map_err(|_| ClientError::InvalidResponse)?;
    let caller_scope = if std::env::var_os("SECRETSD_SESSION_TOKEN_FILE").is_some() {
        CallerScope::Session
    } else {
        caller_tty().map_or(CallerScope::None, CallerScope::Tty)
    };
    Ok(listing.lines().any(|line| {
        let mut fields = line.split('\t');
        let (Some(key), Some(grant_scope), Some(_age), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return false;
        };
        if key != name.as_str() {
            return false;
        }
        match &caller_scope {
            CallerScope::Session => grant_scope == "session",
            CallerScope::Tty(tty) => grant_scope.strip_prefix("tty ") == Some(tty),
            CallerScope::None => false,
        }
    }))
}

enum CallerScope {
    Session,
    Tty(String),
    None,
}
