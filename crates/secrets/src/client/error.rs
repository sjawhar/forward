use std::path::PathBuf;

use super::ClientError;
use crate::config::ConfigError;
use crate::proto::ErrCode;
use crate::secret::SecretName;

mod display;

/// A CLI failure that never renders plaintext secret or session-token bytes.
#[derive(Debug)]
#[non_exhaustive]
pub enum CliError {
    /// The command line did not match the compatible CLI surface.
    Usage,
    /// Source-root configuration could not be loaded.
    Config(ConfigError),
    /// A key name does not satisfy `[A-Za-z_][A-Za-z0-9_]*`.
    InvalidSecretName,
    /// A `--ttl` value did not match `45s`, `30m`, or `2h`.
    InvalidTtl(String),
    /// A requested key was absent, with the stores that were searched.
    MissingSecret {
        /// The requested key.
        name: SecretName,
        /// Human-readable list of every store this client looked in.
        searched: String,
    },
    /// The requested key exists in both storage tiers and access is denied.
    AmbiguousKey {
        /// The requested key.
        name: SecretName,
        /// The agent-tier file holding it, as `<source> (<path>)`.
        agent: String,
        /// The human-tier file holding it, as `<source> (<path>)`.
        human: String,
    },
    /// A human-tier write named a key the agent tier already holds.
    AgentKeyExists(SecretName),
    /// An agent-tier edit named a key the human tier already holds.
    HumanKeyExists(SecretName),
    /// The agent-tier file was replaced by another writer while sops edited a
    /// staged copy of it.
    AgentFileChangedDuringEdit,
    /// `sops` edited a staged copy of an agent-tier file and exited
    /// unsuccessfully; the original was not touched.
    SopsEditFailed(std::process::ExitStatus),
    /// Starting `sops` failed.
    SopsStart(std::io::Error),
    /// `sops` exited unsuccessfully, for this agent-tier file when known.
    SopsFailed(Option<PathBuf>),
    /// Decrypted dotenv bytes were malformed or unsafe, in this file when known.
    InvalidDotenv(Option<PathBuf>),
    /// Reading encrypted agent-tier key names from this file failed.
    AgentKeySet {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O failure.
        error: std::io::Error,
    },
    /// Reading a human-tier directory failed.
    HumanDirectory {
        /// The directory that could not be listed.
        path: PathBuf,
        /// The underlying I/O failure.
        error: std::io::Error,
    },
    /// A human-tier filename was not a valid key name.
    InvalidHumanFile,
    /// A key occurs in more than one configured human-tier location.
    DuplicateHumanKey {
        /// Duplicated key name.
        name: SecretName,
        /// First source label in configuration order.
        first: String,
        /// Conflicting source label.
        second: String,
    },
    /// An edit requires a source name because more than one root is configured.
    EditSourceRequired(String),
    /// An edit named no configured source root.
    UnknownEditSource {
        /// Operator-provided source-root name.
        source: String,
        /// Configured source-root names.
        available: String,
    },
    /// An edit flag contradicted an existing human-tier key location.
    EditConflict {
        /// Existing key name.
        name: SecretName,
        /// Actual source label, including `.local` when applicable.
        actual: String,
    },
    /// Creating or opening the private edit scratch file failed.
    EditTemp,
    /// Starting the selected editor failed.
    EditorStart(std::io::Error),
    /// The selected editor exited without producing an accepted edit.
    EditorExited,
    /// A newly created human secret did not retain its required one-key shape.
    InvalidEditedHumanSecret(SecretName),
    /// A newly created human secret retained an empty value.
    EmptyEditedHumanSecret(SecretName),
    /// Encrypting a newly created secret failed for its target file.
    EncryptEditedSecret(PathBuf),
    /// The sops child produced more ciphertext than the accepted limit.
    SopsCiphertextTooLarge {
        /// The accepted ciphertext size in bytes.
        limit: u64,
    },
    /// Atomically installing the new ciphertext failed.
    InstallEditedSecret,
    /// Reading the piped secret value failed.
    PipedHumanRead(std::io::Error),
    /// A piped human secret retained an empty value.
    EmptyPipedHumanSecret(SecretName),
    /// A piped human secret was not one assignment for its requested key.
    InvalidPipedHumanSecret(SecretName),
    /// Disabling core dumps before reading a piped secret failed.
    Hardening(crate::hardening::HardeningError),
    /// The broker rejected the request with a stable protocol error code.
    Broker {
        /// The stable protocol error code.
        code: ErrCode,
        /// The broker socket this client asked.
        socket: PathBuf,
    },
    /// Broker transport or framing failed before an error code was available.
    BrokerTransport {
        /// The transport or framing failure.
        error: ClientError,
        /// The broker socket this client asked.
        socket: PathBuf,
    },
    /// Replacing the process for an edit or injection command failed.
    Exec(std::io::Error),
    /// Writing command output to standard output failed.
    Stdout(std::io::Error),
    /// Writing the line that names each key's store failed.
    ///
    /// Fail closed: a value handed over without naming its store is the
    /// confusion this notice exists to prevent.
    SourceNotice(std::io::Error),
}

impl CliError {
    /// Convert a stable broker error code to retry-safe agent guidance.
    ///
    /// The socket is part of the message: a refusal must say which store
    /// refused, since more than one secrets CLI answers the same key names.
    pub const fn from_broker(code: ErrCode, socket: PathBuf) -> Self {
        Self::Broker { code, socket }
    }

    /// Convert a broker client failure without exposing request credentials.
    pub fn from_client(error: ClientError, socket: PathBuf) -> Self {
        match error {
            ClientError::Broker(code) => Self::from_broker(code, socket),
            error => Self::BrokerTransport { error, socket },
        }
    }

    /// Name the file a dotenv failure came from, when the caller knows it.
    ///
    /// The parsers run over bytes alone, including an editor's plaintext
    /// buffer, so they raise a fileless refusal that readers of a configured
    /// file label here.
    pub fn in_file(self, path: &std::path::Path) -> Self {
        match self {
            Self::InvalidDotenv(None) => Self::InvalidDotenv(Some(path.to_path_buf())),
            Self::SopsFailed(None) => Self::SopsFailed(Some(path.to_path_buf())),
            other => other,
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SopsStart(error)
            | Self::Exec(error)
            | Self::Stdout(error)
            | Self::SourceNotice(error)
            | Self::EditorStart(error)
            | Self::PipedHumanRead(error)
            | Self::AgentKeySet { error, .. }
            | Self::HumanDirectory { error, .. } => Some(error),
            Self::Hardening(error) => Some(error),
            Self::Config(error) => Some(error),
            Self::BrokerTransport { error, .. } => Some(error),
            Self::Usage
            | Self::InvalidSecretName
            | Self::InvalidTtl(_)
            | Self::MissingSecret { .. }
            | Self::AmbiguousKey { .. }
            | Self::AgentKeyExists(_)
            | Self::HumanKeyExists(_)
            | Self::AgentFileChangedDuringEdit
            | Self::SopsEditFailed(_)
            | Self::SopsFailed(_)
            | Self::InvalidDotenv(_)
            | Self::InvalidHumanFile
            | Self::DuplicateHumanKey { .. }
            | Self::EditSourceRequired(_)
            | Self::UnknownEditSource { .. }
            | Self::EditConflict { .. }
            | Self::EditTemp
            | Self::EditorExited
            | Self::InvalidEditedHumanSecret(_)
            | Self::EmptyEditedHumanSecret(_)
            | Self::EncryptEditedSecret(_)
            | Self::SopsCiphertextTooLarge { .. }
            | Self::InstallEditedSecret
            | Self::EmptyPipedHumanSecret(_)
            | Self::InvalidPipedHumanSecret(_)
            | Self::Broker { .. } => None,
        }
    }
}
