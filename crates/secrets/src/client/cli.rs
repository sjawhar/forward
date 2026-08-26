//! Command-line dispatch for the `secrets` executable.

mod parser;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::process::Command;

use clap::Parser as _;

use self::parser::{Cli, CliCommand};
use super::error::CliError;
use super::status::{GetOutput, TierStatus, active_grant, write_status};
use super::{AgentStore, BrokerClient, BrokerResponse, ClientError, HumanClient, HumanNames};
use crate::config::{SourceRoot, Sources};
use crate::secret::{SecretBytes, SecretName};

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
        }) => {
            let output = if value {
                GetOutput::Value
            } else if no_request {
                GetOutput::Status
            } else {
                GetOutput::Request
            };
            Context::from_environment()?.get(&key, output)
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

struct Context {
    agent: AgentStore,
    human: HumanNames,
    sources: Sources,
}

impl Context {
    fn from_environment() -> Result<Self, CliError> {
        let sources = Sources::load().map_err(CliError::Config)?;
        let agent_files = sources
            .roots
            .iter()
            .flat_map(SourceRoot::agent_files)
            .collect();
        Ok(Self {
            agent: AgentStore::new(agent_files, OsString::from("sops")),
            human: HumanNames::load(&sources.roots)?,
            sources,
        })
    }

    fn get(&self, raw_name: &OsString, output: GetOutput) -> Result<(), CliError> {
        let name = parse_name(raw_name)?;
        match output {
            GetOutput::Request => self.request_grant(&name),
            GetOutput::Status => self.status(&name),
            GetOutput::Value => {
                let value = self.value(&name)?;
                let mut stdout = std::io::stdout().lock();
                stdout
                    .write_all(value.as_slice())
                    .map_err(CliError::Stdout)?;
                stdout.write_all(b"\n").map_err(CliError::Stdout)
            }
        }
    }

    /// Pre-authorize a key: ask the broker for a grant, then report status.
    ///
    /// This blocks for the human's approval and triggers the hardware touch when
    /// no grant is live, which is what makes a bare `get` useful -- it leaves the
    /// session authorized for later `--value` or injection calls without the
    /// value ever being printed. Agent-tier keys need no approval, so they only
    /// report their tier.
    fn request_grant(&self, name: &SecretName) -> Result<(), CliError> {
        let agent = self.agent.contains(name)?;
        match (agent, self.human.contains(name)) {
            (true, true) => Err(CliError::AmbiguousKey(name.clone())),
            (true, false) => write_status(name, TierStatus::Agent),
            (false, true) => {
                HumanClient::from_environment()
                    .and_then(|client| client.request_grant(name))
                    .map_err(CliError::from_client)?;
                // The broker answered, so the scope holds a grant now.
                write_status(name, TierStatus::Human { grant_active: true })
            }
            (false, false) => Err(CliError::MissingSecret(name.clone())),
        }
    }

    fn status(&self, name: &SecretName) -> Result<(), CliError> {
        let agent = self.agent.contains(name)?;
        match (agent, self.human.contains(name)) {
            (true, true) => Err(CliError::AmbiguousKey(name.clone())),
            (true, false) => write_status(name, TierStatus::Agent),
            (false, true) => {
                let response = Self::broker_call("GRANTS")?;
                let BrokerResponse::Bytes(grants) = response else {
                    return Err(CliError::from_client(ClientError::InvalidResponse));
                };
                let grant_active = active_grant(name, &grants)?;
                write_status(name, TierStatus::Human { grant_active })
            }
            (false, false) => Err(CliError::MissingSecret(name.clone())),
        }
    }

    fn list(&self) -> Result<(), CliError> {
        let agent = self.agent.all()?;
        self.reject_duplicates(&agent)?;
        let mut stdout = std::io::stdout().lock();
        for name in agent.keys() {
            writeln!(stdout, "{}", name.as_str()).map_err(CliError::Stdout)?;
        }
        for (name, location) in self.human.iter() {
            writeln!(
                stdout,
                "{}  (human tier: {})",
                name.as_str(),
                location.label
            )
            .map_err(CliError::Stdout)?;
        }
        Ok(())
    }

    fn inject(&self, keys: &[OsString], program: &[OsString]) -> Result<(), CliError> {
        // The grammar requires both halves, so an empty program is
        // unreachable through the parser; refuse rather than panic.
        let (command_name, command_arguments) = program.split_first().ok_or(CliError::Usage)?;
        let mut environment = Vec::new();
        for raw_name in keys {
            let name = parse_name(raw_name)?;
            let value = self.value(&name)?;
            environment.push((
                OsString::from(name.as_str()),
                OsString::from_vec(value.as_slice().to_vec()),
            ));
        }
        let mut command = Command::new(command_name);
        command.args(command_arguments).envs(environment);
        Err(CliError::Exec(command.exec()))
    }

    fn value(&self, name: &SecretName) -> Result<SecretBytes, CliError> {
        let agent = self.agent.all()?;
        if self.human.contains(name) {
            self.reject_duplicates(&agent)?;
            return HumanClient::from_environment()
                .and_then(|client| client.get(name))
                .map_err(CliError::from_client);
        }
        agent
            .get(name)
            .cloned()
            .ok_or_else(|| CliError::MissingSecret(name.clone()))
    }

    fn reject_duplicates(&self, agent: &BTreeMap<SecretName, SecretBytes>) -> Result<(), CliError> {
        for (name, _) in self.human.iter() {
            if agent.contains_key(name) {
                return Err(CliError::AmbiguousKey(name.clone()));
            }
        }
        Ok(())
    }

    fn grants() -> Result<(), CliError> {
        let response = Self::broker_call("GRANTS")?;
        let BrokerResponse::Bytes(bytes) = response else {
            return Err(CliError::from_client(super::ClientError::InvalidResponse));
        };
        std::io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(CliError::Stdout)
    }

    fn deny(raw_id: &OsString) -> Result<(), CliError> {
        let id = raw_id
            .to_str()
            .ok_or(CliError::Usage)?
            .parse::<u64>()
            .map_err(|_| CliError::Usage)?;
        let request = format!("DENY\tid={id}");
        Self::expect_ok(&request)
    }

    fn lock() -> Result<(), CliError> {
        Self::expect_ok("LOCK")
    }

    fn broker_call(request: &str) -> Result<BrokerResponse, CliError> {
        BrokerClient::from_environment()
            .call(request)
            .map_err(CliError::from_client)
    }

    fn expect_ok(request: &str) -> Result<(), CliError> {
        match Self::broker_call(request)? {
            BrokerResponse::Ok => Ok(()),
            BrokerResponse::Fields(_) | BrokerResponse::Bytes(_) => {
                Err(CliError::from_client(super::ClientError::InvalidResponse))
            }
        }
    }
}

pub(super) fn parse_name(raw: &OsString) -> Result<SecretName, CliError> {
    raw.to_str()
        .ok_or(CliError::InvalidSecretName)
        .and_then(|name| SecretName::parse(name).map_err(|_| CliError::InvalidSecretName))
}
