//! Why the registry refused to change a session's registration.

use crate::proto::ErrCode;

/// Why the registry refused to change a session's registration.
///
/// Carries the holder's pid so the refusal can name both sides: the incident
/// that motivated the check (2026-11-07, <dispatch://INFRA-1644>) was silent on
/// every surface, and the displaced session could not tell that anything had
/// happened to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Refusal {
    /// The presented token is already bound to a different session.
    TokenBoundElsewhere,
    /// The caller was not shown to be the process that registered this
    /// session or one of its descendants, and the holder was not shown to be
    /// gone, so the caller may neither displace nor remove the registration.
    ///
    /// "Not shown to be" rather than "is not": the check fails closed, so an
    /// identity the daemon could not read lands here too. Everything this
    /// refusal says about itself has to stay true in that case, which is why
    /// it does not assert that some other live process holds the session.
    ForeignClaim {
        /// The holder's pid as the kernel reports it through the pinned
        /// descriptor, or `None` when the kernel will not report one.
        holder_pid: Option<i32>,
    },
}

impl Refusal {
    /// The wire code this refusal is reported as.
    #[must_use]
    pub const fn code(self) -> ErrCode {
        match self {
            Self::TokenBoundElsewhere => ErrCode::BadRequest,
            Self::ForeignClaim { .. } => ErrCode::ForeignCaller,
        }
    }

    /// The message sent to the caller with the refusal.
    ///
    /// Each one names a next step. The incident this check exists for was
    /// silent, and a refusal a caller cannot act on is the next worst thing.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            Self::TokenBoundElsewhere => {
                "token is already bound to another session; give this session a token of its own"
            }
            Self::ForeignClaim { .. } => {
                "the caller was not shown to be this session's registered process or one of its descendants; use a session identifier of your own, or send this from that process or one of its descendants"
            }
        }
    }
}
