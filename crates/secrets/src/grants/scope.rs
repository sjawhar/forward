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
}

/// Coarse classification for a grant scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScopeKind {
    /// Token was presented and verified.
    VerifiedSession,
    /// No token; scoped to a terminal.
    TokenlessTty,
}

impl Scope {
    /// Classify this scope.
    pub const fn kind(&self) -> ScopeKind {
        match self {
            Self::Session(_) => ScopeKind::VerifiedSession,
            Self::Tty { .. } => ScopeKind::TokenlessTty,
        }
    }
}
