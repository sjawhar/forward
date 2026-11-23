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
    pub(crate) fn label(&self) -> String {
        match self {
            Self::Session(_) => "session".to_owned(),
            Self::Tty { tty, .. } => format!("tty {tty}"),
            Self::Omp { pid, .. } => format!("omp {pid}"),
        }
    }
}
