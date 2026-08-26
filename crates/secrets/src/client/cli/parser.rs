//! Command-line grammar for the `secrets` executable.
//!
//! Two top-level shapes share one parser: a subcommand (`secrets get KEY`)
//! or the bare injection form (`secrets KEY... -- program args...`), kept
//! apart by `args_conflicts_with_subcommands` -- key names never collide
//! with the lowercase subcommand names in practice, and a key that does
//! collide can still be injected alongside a second key.

use std::ffi::OsString;
use std::io::Write;

use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;

use super::CliError;

/// Fetch secrets granted by the secretsd broker and inject them into
/// command environments.
#[derive(Parser)]
#[command(
    name = "secrets",
    version,
    arg_required_else_help = true,
    args_conflicts_with_subcommands = true,
    subcommand_value_name = "COMMAND",
    override_usage = "secrets <COMMAND>\n       secrets <KEY>... -- <PROGRAM> [ARGS]...",
    after_help = "Examples:\n  secrets get GITHUB_TOKEN\n  secrets AWS_KEY AWS_SECRET -- aws s3 ls"
)]
pub(super) struct Cli {
    #[command(subcommand)]
    pub(super) command: Option<CliCommand>,

    /// Keys to fetch and expose to PROGRAM as environment variables
    #[arg(value_name = "KEY", requires = "program")]
    pub(super) keys: Vec<OsString>,

    /// Program to run with the keys in its environment
    #[arg(last = true, value_name = "PROGRAM", num_args = 1.., requires = "keys")]
    pub(super) program: Vec<OsString>,
}

#[derive(Subcommand)]
pub(super) enum CliCommand {
    /// Authorize KEY for this session and report its tier and grant status
    ///
    /// Requesting a human-tier key blocks for the human's approval and
    /// triggers the hardware touch when no grant is live, leaving the
    /// session authorized for later injection calls without ever printing
    /// the value.
    Get {
        /// Secret key name
        #[arg(value_name = "KEY")]
        key: OsString,
        /// Print the secret value instead of its status
        #[arg(long, conflicts_with = "no_request")]
        value: bool,
        /// Report status without requesting a grant (never costs a touch)
        #[arg(long)]
        no_request: bool,
    },
    /// List every agent- and human-tier key
    List,
    /// Report configured source roots and their key counts
    Sources,
    /// Edit the shared agent-tier secrets file
    Edit {
        /// Source root to edit (see `secrets sources`)
        #[arg(long, value_name = "NAME")]
        source: Option<OsString>,
    },
    /// Edit the machine-local agent-tier secrets file
    EditLocal {
        /// Source root to edit (see `secrets sources`)
        #[arg(long, value_name = "NAME")]
        source: Option<OsString>,
    },
    /// Edit or create a human-tier key (writes piped stdin non-interactively)
    EditHuman {
        /// Secret key name
        #[arg(value_name = "KEY")]
        key: OsString,
        /// Source root for a new key (see `secrets sources`)
        #[arg(long, value_name = "NAME")]
        source: Option<OsString>,
        /// Create the key in the machine-local (uncommitted) location
        #[arg(long)]
        local: bool,
    },
    /// List the broker's live grants
    Grants,
    /// Revoke a live grant by id (see `secrets grants`)
    Deny {
        /// Grant id
        #[arg(value_name = "ID")]
        id: OsString,
    },
    /// Lock this session: revoke its live grants
    Lock,
    /// Print shell completion definitions to stdout
    Completions {
        /// Shell to generate completions for
        #[arg(value_name = "SHELL")]
        shell: Shell,
    },
}

/// Render completions for `shell` to stdout.
pub(super) fn completions(shell: Shell) -> Result<(), CliError> {
    let mut command = Cli::command();
    let mut stdout = std::io::stdout().lock();
    clap_complete::generate(shell, &mut command, "secrets", &mut stdout);
    stdout.flush().map_err(CliError::Stdout)
}
