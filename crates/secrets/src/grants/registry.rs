use super::{Refusal, Scope, SessionToken};
use crate::peer::{Liveness, PeerIdentity};
use crate::proto::ErrCode;

/// Whether `caller` may displace or remove the registration `holder` made.
///
/// The session identifier on the wire is untrusted, so possession of it proves
/// nothing; only the caller's position in the holder's process tree does. A
/// holder the kernel reports as *gone* is the one exception: it has no
/// descendants, so nobody could ever satisfy the check again, and its
/// registration already refuses every request because `resolve` needs a live
/// root to walk to. Letting the next process claim the identifier is therefore
/// the ordinary restart path -- a session killed outright never sends
/// `UNREGISTER` -- and costs nothing that was still reachable.
///
/// That exception asks for [`Liveness::Exited`], the kernel's own statement
/// that the process is gone. `PinnedPeer::pid` answers `None` for three
/// different things -- reaped, unnumbered in this namespace, and not
/// readable -- so releasing on `pid().is_none()` would let a daemon out of
/// descriptors treat every live holder as gone and hand its session to
/// whoever asked next. A read that did not happen is not evidence.
fn claim_allowed(holder: &PeerIdentity, caller: &PeerIdentity) -> bool {
    holder.liveness() == Liveness::Exited || caller.descends_from(holder)
}

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
    /// Presenting a *different* token for a session a live process already
    /// holds is refused unless the caller is that process or one of its
    /// descendants. The identifier on the wire is untrusted, so without this
    /// any process sharing the uid could name a live session, displace its
    /// token, and leave it answering `UNKNOWN_TOKEN` to every later request
    /// with no error of its own -- which is what a session-copying script did
    /// to 59 live sessions on 2026-11-07 (<dispatch://INFRA-1644>). The caller's
    /// identity is the one the kernel pinned for this connection, never the pid
    /// on the wire.
    ///
    /// A token already bound to a *different* session is refused: a token
    /// identifies exactly one session, and two bindings would make the lookup
    /// in `resolve` order-dependent.
    pub fn register(&mut self, registration: Registration) -> Result<Vec<SessionToken>, Refusal> {
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
                Err(Refusal::TokenBoundElsewhere)
            };
        }
        if let Some(holder) = self
            .sessions
            .iter()
            .find(|existing| existing.session == registration.session)
            && !claim_allowed(&holder.root, &registration.root)
        {
            return Err(Refusal::ForeignClaim {
                holder_pid: holder.root.pid(),
            });
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
    ///
    /// Held to the same rule as `register`: a session a live process holds is
    /// removed only by that process or one of its descendants. `UNREGISTER`
    /// names a session and carries no token, so without the check any caller
    /// could end any session's scope by naming it. Removing a session nobody
    /// holds stays a success, so a harness that shuts down after the daemon
    /// restarted is not made to handle an error for work already done.
    pub fn unregister(
        &mut self,
        session: &str,
        caller: &PeerIdentity,
    ) -> Result<Vec<SessionToken>, Refusal> {
        if let Some(holder) = self.sessions.iter().find(|entry| entry.session == session)
            && !claim_allowed(&holder.root, caller)
        {
            return Err(Refusal::ForeignClaim {
                holder_pid: holder.root.pid(),
            });
        }
        let revoked: Vec<SessionToken> = self
            .sessions
            .iter()
            .filter(|entry| entry.session == session)
            .map(|entry| entry.token)
            .collect();
        self.sessions.retain(|entry| entry.session != session);
        Ok(revoked)
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
