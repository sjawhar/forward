use super::{Scope, SessionToken};
use crate::proto::ErrCode;

/// A registered harness session.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Registration {
    /// Token issued for this session.
    pub token: SessionToken,
    /// Harness-supplied identifier. Untrusted; logging and display only.
    pub session: String,
    /// Kernel-pinned identity of the process that registered this session.
    ///
    /// Captured from the connection rather than taken from the wire, so requests
    /// can be checked against the session's real process tree.
    pub root: crate::peer::PeerIdentity,
}

/// Known sessions and learned agent terminals.
#[derive(Debug)]
pub struct Registry {
    pub(super) sessions: Vec<Registration>,
    agent_ttys: Vec<String>,
    boot_id: String,
}

impl Default for Registry {
    fn default() -> Self {
        Self::new("test-boot".to_owned())
    }
}

impl Registry {
    /// Build a registry bound to one kernel boot.
    pub const fn new(boot_id: String) -> Self {
        Self {
            sessions: Vec::new(),
            agent_ttys: Vec::new(),
            boot_id,
        }
    }
    /// Record a session token, returning any *different* token previously bound
    /// to this session, whose grants must be revoked.
    ///
    /// Re-presenting a session's current token is a **no-op**: the existing
    /// registration is kept, including the kernel-pinned root it was created
    /// with. Replacing the root here instead would hand a same-uid caller that
    /// read the token file a way to become the root of a session that already
    /// holds grants, inheriting them with no touch -- defeating the ancestry
    /// check that contains callers outside the session's process tree. It also
    /// keeps `sessions` in insertion order, so a re-registration cannot move an
    /// entry behind a colliding one and change which root `resolve` finds.
    ///
    /// A token already bound to a *different* session is refused: a token
    /// identifies exactly one session, and two bindings would make the lookup
    /// in `resolve` order-dependent.
    pub fn register(&mut self, registration: Registration) -> Result<Vec<SessionToken>, ErrCode> {
        if self
            .sessions
            .iter()
            .any(|existing| existing.token == registration.token)
        {
            return if self.sessions.iter().any(|existing| {
                existing.token == registration.token && existing.session == registration.session
            }) {
                Ok(Vec::new())
            } else {
                Err(ErrCode::BadRequest)
            };
        }
        let displaced = self
            .sessions
            .iter()
            .filter(|existing| existing.session == registration.session)
            .map(|existing| existing.token)
            .collect();
        self.sessions
            .retain(|existing| existing.session != registration.session);
        self.sessions.push(registration);
        Ok(displaced)
    }

    /// Forget a session, returning the tokens whose grants must be revoked.
    pub fn unregister(&mut self, session: &str) -> Vec<SessionToken> {
        let revoked: Vec<SessionToken> = self
            .sessions
            .iter()
            .filter(|entry| entry.session == session)
            .map(|entry| entry.token)
            .collect();
        self.sessions.retain(|entry| entry.session != session);
        revoked
    }

    /// Find the untrusted registration associated with a verified token.
    pub fn registration(&self, token: &SessionToken) -> Option<&Registration> {
        self.sessions.iter().find(|entry| entry.token == *token)
    }

    /// Whether a terminal has been seen carrying agent traffic.
    pub fn is_agent_tty(&self, tty: &str) -> bool {
        self.agent_ttys.iter().any(|known| known == tty)
    }

    /// Determine the scope of a request, or why it has none.
    pub fn resolve(
        &mut self,
        token: Option<&SessionToken>,
        tty: Option<&str>,
        caller: Option<&crate::peer::PeerIdentity>,
    ) -> Result<Scope, ErrCode> {
        match token {
            Some(presented) => {
                let Some(root) = self
                    .sessions
                    .iter()
                    .find(|entry| entry.token == *presented)
                    .map(|entry| entry.root.clone())
                else {
                    return Err(ErrCode::UnknownToken);
                };
                // The token says which session, not that this caller belongs to
                // it: every process sharing the uid can read the token file.
                // Require the caller to sit inside that session's process tree,
                // and refuse outright instead of degrading to a tty scope, which
                // a caller could otherwise obtain just by allocating a pty.
                if !caller.is_some_and(|caller| caller.descends_from(&root)) {
                    return Err(ErrCode::ForeignCaller);
                }
                if let Some(tty) = tty
                    && !self.is_agent_tty(tty)
                {
                    self.agent_ttys.push(tty.to_owned());
                }
                Ok(Scope::Session(*presented))
            }
            None => match tty {
                Some(tty) if self.is_agent_tty(tty) => Err(ErrCode::AgentTty),
                Some(tty) => Ok(Scope::Tty {
                    tty: tty.to_owned(),
                    boot_id: self.boot_id.clone(),
                }),
                None => Err(ErrCode::NoScope),
            },
        }
    }
}
