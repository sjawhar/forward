use std::fmt;

use zeroize::Zeroizing;

use super::super::{Shared, lock_state};
use crate::grants::{Scope, ScopeUse, SessionToken};
use crate::proto::ErrCode;
use crate::secret::SecretName;

pub(in crate::server) struct Access {
    pub(in crate::server) key: String,
    pub(in crate::server) token_hex: Option<Zeroizing<String>>,
    pub(in crate::server) tty: Option<String>,
    /// Caller-requested lifetime for a freshly created grant. `None` means no
    /// preference: the daemon's own default backstop governs.
    pub(in crate::server) requested_ttl: Option<u64>,
}

impl fmt::Debug for Access {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Access")
            .field("key", &self.key)
            .field("token_present", &self.token_hex.is_some())
            .field("tty", &self.tty)
            .field("requested_ttl", &self.requested_ttl)
            .finish()
    }
}

pub(super) fn resolve_access(
    shared: &Shared,
    access: &Access,
    caller: &crate::peer::PeerIdentity,
    use_: ScopeUse,
) -> Result<(Scope, SecretName), ErrCode> {
    let key = SecretName::parse(&access.key)?;
    let token = access
        .token_hex
        .as_deref()
        .map(|token_hex| SessionToken::parse_hex(token_hex.as_str()))
        .transpose()?;
    let (mutex, _) = &**shared;
    let mut state = lock_state(mutex);
    let scope =
        state
            .registry
            .resolve(token.as_ref(), access.tty.as_deref(), Some(caller), use_)?;
    drop(state);
    Ok((scope, key))
}
