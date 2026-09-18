//! Command-line dispatch for the `secrets` executable.

mod context;
mod parser;

use std::ffi::OsString;

use clap::Parser as _;

use self::context::Context;
use self::parser::{Cli, CliCommand};
use super::error::CliError;
use super::status::GetOutput;
use crate::secret::SecretName;

/// Run a `secrets` command.
pub fn run(arguments: impl IntoIterator<Item = OsString>) -> Result<(), CliError> {
    let cli = Cli::try_parse_from(arguments).unwrap_or_else(|error| error.exit());
    match cli.command {
        None => Context::from_environment()?.inject(&cli.keys, &cli.program),
        Some(CliCommand::Sources) => super::sources::run(),
        Some(CliCommand::Completions { shell }) => parser::completions(shell),
        Some(CliCommand::Get {
            key,
            value,
            no_request,
            ttl,
        }) => {
            let output = if value {
                GetOutput::Value
            } else if no_request {
                GetOutput::Status
            } else {
                GetOutput::Request
            };
            let ttl_secs = ttl
                .map(|raw| crate::proto::parse_ttl(&raw).ok_or(CliError::InvalidTtl(raw)))
                .transpose()?;
            Context::from_environment()?.get(&key, output, ttl_secs)
        }
        Some(CliCommand::List) => Context::from_environment()?.list(),
        Some(CliCommand::Edit { source }) => {
            let context = Context::from_environment()?;
            super::edit::agent(&context.sources, source.as_ref(), false)
        }
        Some(CliCommand::EditLocal { source }) => {
            let context = Context::from_environment()?;
            super::edit::agent(&context.sources, source.as_ref(), true)
        }
        Some(CliCommand::EditHuman { key, source, local }) => {
            let context = Context::from_environment()?;
            super::edit::human(
                &context.sources,
                &context.human,
                &key,
                source.as_ref(),
                local,
            )
        }
        Some(CliCommand::Grants) => Context::grants(),
        Some(CliCommand::Deny { id }) => Context::deny(&id),
        Some(CliCommand::Lock) => Context::lock(),
    }
}

pub(super) fn parse_name(raw: &OsString) -> Result<SecretName, CliError> {
    raw.to_str()
        .ok_or(CliError::InvalidSecretName)
        .and_then(|name| SecretName::parse(name).map_err(|_| CliError::InvalidSecretName))
}
