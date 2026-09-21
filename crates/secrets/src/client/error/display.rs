use std::fmt;

use super::CliError;
use crate::proto::ErrCode;

const AGENT_NOTICE: &str = "AGENT NOTICE: ask the human; do not retry-loop.";

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage => formatter.write_str(
                "expected `secrets <KEY>... -- <PROGRAM> [ARGS]...`; run `secrets --help` for the full grammar",
            ),
            Self::Config(error) => error.fmt(formatter),
            Self::InvalidSecretName => formatter.write_str("invalid secret key"),
            Self::InvalidTtl(raw) => {
                write!(formatter, "invalid --ttl \"{raw}\"; use 45s, 30m, or 2h")
            }
            Self::MissingSecret(name) => write!(formatter, "secret '{}' not found", name.as_str()),
            Self::AmbiguousKey(name) => write!(
                formatter,
                "key '{}' exists in both agent and human tiers; refusing ambiguous access -- keep it in one tier: `secrets list` shows both locations",
                name.as_str()
            ),
            Self::AgentKeyExists(name) => write!(
                formatter,
                "key '{}' is an agent-tier key; refusing a human-tier copy -- remove the agent-tier line first (`secrets list` shows where), or choose another name",
                name.as_str()
            ),
            Self::HumanKeyExists(name) => write!(
                formatter,
                "key '{}' is a human-tier key; refusing to save an agent-tier copy -- remove the human-tier file first (`secrets list` shows where), or choose another name",
                name.as_str()
            ),
            Self::AgentFileChangedDuringEdit => formatter.write_str(
                "the agent-tier file changed while it was being edited; nothing saved -- re-run the edit on the current contents",
            ),
            Self::SopsEditFailed(status) => write!(
                formatter,
                "sops edit exited unsuccessfully ({status}); the agent-tier file is unchanged"
            ),
            Self::SopsStart(error) => write!(formatter, "could not start sops: {error}"),
            Self::SopsFailed => formatter.write_str("sops could not decrypt the agent-tier secrets"),
            Self::InvalidDotenv => formatter.write_str("sops returned invalid dotenv data"),
            Self::AgentKeySet(error) => write!(formatter, "could not read agent-tier key set: {error}"),
            Self::HumanDirectory(error) => write!(formatter, "could not list human-tier keys: {error}"),
            Self::InvalidHumanFile => {
                formatter.write_str("human-tier directory contains an invalid key filename")
            }
            Self::DuplicateHumanKey {
                name,
                first,
                second,
            } => write!(
                formatter,
                "key '{}' exists in more than one human-tier location ({first}, {second}); remove or rename one file",
                name.as_str()
            ),
            Self::EditSourceRequired(available) => write!(
                formatter,
                "multiple secrets sources are configured; pass --source NAME (available: {available})"
            ),
            Self::UnknownEditSource { source, available } => write!(
                formatter,
                "secrets source '{source}' is not configured (available: {available})"
            ),
            Self::EditConflict { name, actual } => write!(
                formatter,
                "edit flags conflict with key '{}' stored in source {actual}",
                name.as_str()
            ),
            Self::EditTemp => formatter.write_str("could not prepare a private edit file"),
            Self::EditorStart(error) => write!(formatter, "could not start editor: {error}"),
            Self::EditorExited => formatter.write_str("editor exited without creating a secret"),
            Self::InvalidEditedHumanSecret(name) => write!(
                formatter,
                "edited secret must contain exactly one assignment named '{}'",
                name.as_str()
            ),
            Self::EmptyEditedHumanSecret(name) => {
                write!(formatter, "edited secret '{}' value must not be empty", name.as_str())
            }
            Self::EncryptEditedSecret(target) => write!(
                formatter,
                "could not encrypt edited secret for '{}'; ensure .sops.yaml has a matching creation rule",
                target.display()
            ),
            Self::SopsCiphertextTooLarge { limit } => write!(
                formatter,
                "sops produced more than {limit} bytes of ciphertext; refusing to stage it"
            ),
            Self::InstallEditedSecret => formatter.write_str("could not install encrypted secret"),
            Self::PipedHumanRead(error) => write!(formatter, "could not read piped secret: {error}"),
            Self::EmptyPipedHumanSecret(name) => {
                write!(formatter, "piped secret '{}' value must not be empty", name.as_str())
            }
            Self::InvalidPipedHumanSecret(name) => write!(
                formatter,
                "piped secret '{}' must be one single-line assignment value",
                name.as_str()
            ),
            Self::Hardening(error) => write!(formatter, "could not disable core dumps: {error}"),
            Self::Broker(code) => write!(formatter, "{AGENT_NOTICE} {}", broker_guidance(*code)),
            Self::BrokerTransport(error) => write!(formatter, "{AGENT_NOTICE} {error}"),
            Self::Exec(error) => write!(formatter, "could not execute command: {error}"),
            Self::Stdout(error) => write!(formatter, "could not write secret value: {error}"),
        }
    }
}

const fn broker_guidance(code: ErrCode) -> &'static str {
    match code {
        ErrCode::BadRequest => {
            "secretsd rejected a malformed request; the human should update or restart the client and daemon."
        }
        ErrCode::UnknownOp => {
            "this client requested an unsupported operation; the human should update the client and daemon together."
        }
        ErrCode::VersionMismatch => {
            "the client and daemon speak different protocol versions; ask the human to move both halves to the same release -- the `secrets` binary and the tag OpenCode pins for its plugin -- then restart the daemon with `systemctl --user restart secretsd.service` and restart OpenCode. Restarting OpenCode while its plugin pin still names the old tag re-fetches the same mismatched plugin, so updating only one half leaves this error in place."
        }
        ErrCode::UnknownToken => {
            "the broker restarted, losing this session's registration and every grant. The OpenCode plugin re-registers on the next command, so run this command once more -- once, not in a loop -- and expect the human's key to blink, because the first request after a restart needs a fresh touch."
        }
        ErrCode::NoScope => {
            "there is neither a terminal tty nor a session token. Inside an agent session (omp or OpenCode) this means the secretsd plugin did not inject a token into this shell -- check with `echo $SECRETSD_SESSION_TOKEN_FILE`; if it is empty, the session predates the plugin or its registration failed, so start a fresh session. From non-interactive ssh ('ssh host secrets get KEY') this is expected; run from a human terminal with a tty instead."
        }
        ErrCode::AgentTty => {
            "a tokenless request came from a known agent terminal; use the OpenCode token path instead."
        }
        ErrCode::ForeignCaller => {
            "this session's token was presented from outside that session's process tree, so it was refused; run the request from the session that owns the token."
        }
        ErrCode::NotHumanKey => {
            "the requested human-tier key is missing or was moved; ask the human to check its encrypted file. If config.toml just gained a new source root, restart secretsd (systemctl --user restart secretsd.service)."
        }
        ErrCode::AmbiguousKey => {
            "the requested key exists in more than one human-tier location; ask the human to remove or rename one of the duplicate files -- run `secrets list` to see every source."
        }
        ErrCode::Denied => "the human declined the secret request.",
        ErrCode::Timeout => {
            "the human did not approve the request before it expired; wait for the human instead of retrying."
        }
        ErrCode::YubikeyUnreachable => {
            "the configured YubiKey path is unavailable; ask the human to connect the required hardware path."
        }
        ErrCode::TooManyPending => {
            "this scope already has too many pending requests; stop retrying and wait for the human."
        }
        ErrCode::Internal => {
            "the broker could not complete the request, including a failure to spawn sops; the human should inspect journalctl --user -u secretsd for the daemon's logged sops stderr."
        }
    }
}
