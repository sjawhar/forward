//! Per-invocation client state and the subcommand bodies that use it.

use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::process::Command;

use super::super::error::CliError;
use super::super::status::{GetOutput, Provenance, active_grant, announce, write_status};
use super::super::{AgentFile, AgentStore, BrokerResponse, ClientError, HumanClient, HumanNames};
use super::{control, naming, parse_name};
use crate::config::Sources;
use crate::secret::{SecretBytes, SecretName};

pub(super) struct Context {
    pub(super) agent: AgentStore,
    pub(super) human: HumanNames,
    pub(super) sources: Sources,
}

impl Context {
    pub(super) fn from_environment() -> Result<Self, CliError> {
        let sources = Sources::load().map_err(CliError::Config)?;
        let agent_files = sources.roots.iter().flat_map(AgentFile::of_root).collect();
        Ok(Self {
            agent: AgentStore::new(agent_files, OsString::from("sops")),
            human: HumanNames::load(&sources.roots)?,
            sources,
        })
    }

    pub(super) fn get(
        &self,
        raw_name: &OsString,
        output: GetOutput,
        ttl_secs: Option<u64>,
    ) -> Result<(), CliError> {
        let name = parse_name(raw_name)?;
        match output {
            GetOutput::Request => self.request_grant(&name, ttl_secs),
            GetOutput::Status => self.status(&name),
            GetOutput::Value => {
                let (value, provenance) = self.value(&name, ttl_secs)?;
                // The store is named on stderr, so stdout stays exactly the
                // value for whoever reads it. The value is never in the notice.
                announce(&[(name.as_str(), &provenance)])?;
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
    /// report their tier. `ttl_secs` bounds only a *freshly created* grant.
    fn request_grant(&self, name: &SecretName, ttl_secs: Option<u64>) -> Result<(), CliError> {
        match (self.agent.locate(name)?, self.human.contains(name)) {
            (Some(file), true) => Err(naming::ambiguous(&self.human, name, file)),
            (Some(file), false) => write_status(name, &naming::agent_provenance(file)),
            (None, true) => {
                let client = Self::human_client()?;
                let granted_ttl = client
                    .request_grant(name, ttl_secs)
                    .map_err(|error| Self::broker_error(error, &client))?;
                // The broker answered, so the scope holds a grant now.
                let socket = client.socket_path().to_owned();
                write_status(
                    name,
                    &naming::human_provenance(&self.human, name, socket, true, granted_ttl),
                )
            }
            (None, false) => Err(self.missing(name)),
        }
    }

    fn status(&self, name: &SecretName) -> Result<(), CliError> {
        match (self.agent.locate(name)?, self.human.contains(name)) {
            (Some(file), true) => Err(naming::ambiguous(&self.human, name, file)),
            (Some(file), false) => write_status(name, &naming::agent_provenance(file)),
            (None, true) => {
                let socket = control::socket_path();
                let BrokerResponse::Bytes(grants) = control::broker_call("GRANTS")? else {
                    return Err(CliError::from_client(ClientError::InvalidResponse, socket));
                };
                let grant_active = active_grant(name, &grants)
                    .map_err(|error| CliError::from_client(error, socket.clone()))?;
                let provenance =
                    naming::human_provenance(&self.human, name, socket, grant_active, None);
                write_status(name, &provenance)
            }
            (None, false) => Err(self.missing(name)),
        }
    }

    /// Every key in both tiers. A key present in both is reported here and
    /// refused on read; the listing itself never fails on one, because this is
    /// the command the refusal tells the human to run.
    pub(super) fn list(&self) -> Result<(), CliError> {
        let agent = self.agent.all()?;
        let locations = self.agent.locations()?;
        let mut stdout = std::io::stdout().lock();
        for name in agent.keys() {
            let source = locations
                .get(name)
                .map_or("unknown", |file| file.label.as_str());
            writeln!(stdout, "{}  (agent tier: {source})", name.as_str())
                .map_err(CliError::Stdout)?;
        }
        for (name, location) in self.human.iter() {
            let clash = if agent.contains_key(name) {
                "; ALSO agent tier -- ambiguous, reads refuse"
            } else {
                ""
            };
            writeln!(
                stdout,
                "{}  (human tier: {}{clash})",
                name.as_str(),
                location.label
            )
            .map_err(CliError::Stdout)?;
        }
        Ok(())
    }

    pub(super) fn inject(&self, keys: &[OsString], program: &[OsString]) -> Result<(), CliError> {
        // The grammar requires both halves, so an empty program is
        // unreachable through the parser; refuse rather than panic.
        let (command_name, command_arguments) = program.split_first().ok_or(CliError::Usage)?;
        let mut environment = Vec::new();
        let mut injected = Vec::new();
        for raw_name in keys {
            let name = parse_name(raw_name)?;
            let (value, provenance) = self.value(&name, None)?;
            environment.push((
                OsString::from(name.as_str()),
                OsString::from_vec(value.as_slice().to_vec()),
            ));
            injected.push((name, provenance));
        }
        let with_sources: Vec<(&str, &Provenance)> = injected
            .iter()
            .map(|(name, provenance)| (name.as_str(), provenance))
            .collect();
        // Said before the exec, because after it this process no longer exists.
        announce(&with_sources)?;
        let mut command = Command::new(command_name);
        command.args(command_arguments).envs(environment);
        Err(CliError::Exec(command.exec()))
    }

    /// The value of one key, with the store that answered for it. Only that
    /// key's own tier membership matters: a different key sitting in both
    /// tiers is that key's problem, not a reason to refuse this one.
    fn value(
        &self,
        name: &SecretName,
        ttl_secs: Option<u64>,
    ) -> Result<(SecretBytes, Provenance), CliError> {
        if self.human.contains(name) {
            if let Some(file) = self.agent.locate(name)? {
                return Err(naming::ambiguous(&self.human, name, file));
            }
            let client = Self::human_client()?;
            let value = client
                .get(name, ttl_secs)
                .map_err(|error| Self::broker_error(error, &client))?;
            let socket = client.socket_path().to_owned();
            let provenance = naming::human_provenance(&self.human, name, socket, true, None);
            return Ok((value, provenance));
        }
        let provenance = self
            .agent
            .locate(name)?
            .map(naming::agent_provenance)
            .ok_or_else(|| self.missing(name))?;
        Ok((self.agent.value(name)?, provenance))
    }

    fn missing(&self, name: &SecretName) -> CliError {
        naming::missing(&self.agent, &self.sources, name)
    }

    fn human_client() -> Result<HumanClient, CliError> {
        HumanClient::from_environment()
            .map_err(|error| CliError::from_client(error, control::socket_path()))
    }

    fn broker_error(error: ClientError, client: &HumanClient) -> CliError {
        CliError::from_client(error, client.socket_path().to_owned())
    }
}
