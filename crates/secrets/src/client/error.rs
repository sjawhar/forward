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
    /// A requested agent-tier key was absent.
    MissingSecret(SecretName),
    /// A key exists in both storage tiers and access is denied.
    AmbiguousKey(SecretName),
    /// Starting `sops` failed.
    SopsStart(std::io::Error),
    /// `sops` exited unsuccessfully.
    SopsFailed,
    /// Decrypted dotenv bytes were malformed or unsafe.
    InvalidDotenv,
    /// Reading encrypted agent-tier key names failed.
    AgentKeySet(std::io::Error),
    /// Reading the human-tier directory failed.
    HumanDirectory(std::io::Error),
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
    Broker(ErrCode),
    /// Broker transport or framing failed before an error code was available.
    BrokerTransport(ClientError),
    /// Replacing the process for an edit or injection command failed.
    Exec(std::io::Error),
    /// Writing command output to standard output failed.
    Stdout(std::io::Error),
}

impl CliError {
    /// Convert a stable broker error code to retry-safe agent guidance.
    pub const fn from_broker(code: ErrCode) -> Self {
        Self::Broker(code)
    }

    /// Convert a broker client failure without exposing request credentials.
    pub fn from_client(error: ClientError) -> Self {
        match error {
            ClientError::Broker(code) => Self::from_broker(code),
            error => Self::BrokerTransport(error),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::SopsStart(error)
            | Self::AgentKeySet(error)
            | Self::HumanDirectory(error)
            | Self::Exec(error)
            | Self::Stdout(error)
            | Self::EditorStart(error)
            | Self::PipedHumanRead(error) => Some(error),
            Self::Hardening(error) => Some(error),
            Self::Config(error) => Some(error),
            Self::BrokerTransport(error) => Some(error),
            Self::Usage
            | Self::InvalidSecretName
            | Self::InvalidTtl(_)
            | Self::MissingSecret(_)
            | Self::AmbiguousKey(_)
            | Self::SopsFailed
            | Self::InvalidDotenv
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
            | Self::Broker(_) => None,
        }
    }
}
