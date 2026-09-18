//! Per-invocation client state and the subcommand bodies that use it.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::Write;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::process::Command;

use super::super::error::CliError;
use super::super::status::{GetOutput, TierStatus, active_grant, write_status};
use super::super::{
    AgentStore, BrokerClient, BrokerResponse, ClientError, HumanClient, HumanNames,
};
use super::parse_name;
use crate::config::{SourceRoot, Sources};
use crate::secret::{SecretBytes, SecretName};

pub(super) struct Context {
    agent: AgentStore,
    pub(super) human: HumanNames,
    pub(super) sources: Sources,
}

impl Context {
    pub(super) fn from_environment() -> Result<Self, CliError> {
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
                let value = self.value(&name, ttl_secs)?;
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
        let agent = self.agent.contains(name)?;
        match (agent, self.human.contains(name)) {
            (true, true) => Err(CliError::AmbiguousKey(name.clone())),
            (true, false) => write_status(name, TierStatus::Agent),
            (false, true) => {
                let granted_ttl = HumanClient::from_environment()
                    .and_then(|client| client.request_grant(name, ttl_secs))
                    .map_err(CliError::from_client)?;
                // The broker answered, so the scope holds a grant now.
                write_status(
                    name,
                    TierStatus::Human {
                        grant_active: true,
                        ttl_secs: granted_ttl,
                    },
                )
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
                write_status(
                    name,
                    TierStatus::Human {
                        grant_active,
                        ttl_secs: None,
                    },
                )
            }
            (false, false) => Err(CliError::MissingSecret(name.clone())),
        }
    }

    pub(super) fn list(&self) -> Result<(), CliError> {
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

    pub(super) fn inject(&self, keys: &[OsString], program: &[OsString]) -> Result<(), CliError> {
        // The grammar requires both halves, so an empty program is
        // unreachable through the parser; refuse rather than panic.
        let (command_name, command_arguments) = program.split_first().ok_or(CliError::Usage)?;
        let mut environment = Vec::new();
        for raw_name in keys {
            let name = parse_name(raw_name)?;
            let value = self.value(&name, None)?;
            environment.push((
                OsString::from(name.as_str()),
                OsString::from_vec(value.as_slice().to_vec()),
            ));
        }
        let mut command = Command::new(command_name);
        command.args(command_arguments).envs(environment);
        Err(CliError::Exec(command.exec()))
    }

    fn value(&self, name: &SecretName, ttl_secs: Option<u64>) -> Result<SecretBytes, CliError> {
        let agent = self.agent.all()?;
        if self.human.contains(name) {
            self.reject_duplicates(&agent)?;
            return HumanClient::from_environment()
                .and_then(|client| client.get(name, ttl_secs))
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

    pub(super) fn grants() -> Result<(), CliError> {
        let response = Self::broker_call("GRANTS")?;
        let BrokerResponse::Bytes(bytes) = response else {
            return Err(CliError::from_client(ClientError::InvalidResponse));
        };
        std::io::stdout()
            .lock()
            .write_all(&bytes)
            .map_err(CliError::Stdout)
    }

    pub(super) fn deny(raw_id: &OsString) -> Result<(), CliError> {
        let id = raw_id
            .to_str()
            .ok_or(CliError::Usage)?
            .parse::<u64>()
            .map_err(|_| CliError::Usage)?;
        let request = format!("DENY\tid={id}");
        Self::expect_ok(&request)
    }

    pub(super) fn lock() -> Result<(), CliError> {
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
                Err(CliError::from_client(ClientError::InvalidResponse))
            }
        }
    }
}
