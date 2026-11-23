use std::fmt;

use super::SessionToken;

/// What a grant belongs to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Scope {
    /// A harness session proven by its token.
    Session(SessionToken),
    /// A human at an interactive terminal.
    Tty {
        /// Controlling terminal device path.
        tty: String,
        /// Kernel boot identity captured when the daemon started.
        boot_id: String,
    },
    /// An omp process identified by its kernel pid and start time.
    Omp {
        /// The omp process id.
        pid: u32,
        /// The kernel start time that distinguishes a reused pid.
        start: u64,
    },
}

/// Coarse classification for a grant scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeKind {
    /// Token was presented and verified.
    VerifiedSession,
    /// No token; scoped to a terminal.
    TokenlessTty,
    /// No token or terminal; scoped to an enclosing omp process.
    OmpProcess,
}

impl Scope {
    /// Classify this scope.
    pub const fn kind(&self) -> ScopeKind {
        match self {
            Self::Session(_) => ScopeKind::VerifiedSession,
            Self::Tty { .. } => ScopeKind::TokenlessTty,
            Self::Omp { .. } => ScopeKind::OmpProcess,
        }
    }

    /// The scope as `secrets grants` writes it: `session`, `tty <tty>` or
    /// `omp <pid>`. A session's token never appears.
    pub(crate) const fn label(&self) -> impl fmt::Display + '_ {
        Label(self)
    }
}

/// A scope written as `Scope::label` describes.
struct Label<'scope>(&'scope Scope);

impl fmt::Display for Label<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Scope::Session(_) => f.write_str("session"),
            Scope::Tty { tty, .. } => write!(f, "tty {tty}"),
            Scope::Omp { pid, .. } => write!(f, "omp {pid}"),
        }
    }
}
