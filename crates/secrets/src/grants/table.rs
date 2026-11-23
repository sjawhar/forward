use std::time::{Duration, Instant};

use containment::omp::OmpProcess;

use super::{GrantOrigin, Scope, SessionToken};
use crate::secret::{SecretBytes, SecretName};
use crate::store::FileIdentity;

#[derive(Debug)]
pub(super) struct Grant {
    scope: Scope,
    key: SecretName,
    value: SecretBytes,
    origin: GrantOrigin,
    created: Instant,
    /// This grant's own backstop lifetime, already capped by the caller
    /// (`worker::effective_grant_ttl`) before it reaches `insert`.
    ttl: Duration,
}

/// Live grants. Dropping a grant zeroizes its value.
#[derive(Debug, Default)]
pub struct GrantTable {
    pub(super) grants: Vec<Grant>,
}

impl GrantTable {
    /// Find a live grant that has not outlived its own recorded `ttl`.
    ///
    /// Expiry is checked here, not only by the worker's periodic
    /// `revoke_expired` sweep: that sweep can lag behind a grant's deadline
    /// while the worker is busy elsewhere (a single-flight decrypt can run for
    /// up to `request_ttl`), so without this check a short caller-requested
    /// TTL would be advisory rather than a hard bound on how long the cached
    /// plaintext stays readable.
    pub fn lookup(
        &self,
        scope: &Scope,
        key: &SecretName,
        now: Instant,
    ) -> Option<(&SecretBytes, &str, &FileIdentity)> {
        self.grants
            .iter()
            .find(|grant| {
                grant.scope == *scope
                    && grant.key == *key
                    && now.duration_since(grant.created) < grant.ttl
            })
            .map(|grant| {
                (
                    &grant.value,
                    grant.origin.source.as_str(),
                    &grant.origin.identity,
                )
            })
    }

    /// A live grant's remaining lifetime in whole seconds, or `None` if it is
    /// missing or has already outlived its own recorded `ttl`.
    pub fn remaining_secs(&self, scope: &Scope, key: &SecretName, now: Instant) -> Option<u64> {
        self.grants
            .iter()
            .find(|grant| grant.scope == *scope && grant.key == *key)
            .and_then(|grant| grant.ttl.checked_sub(now.duration_since(grant.created)))
            .map(|remaining| remaining.as_secs())
    }

    /// Install a grant, replacing any existing one for the same scope and key.
    #[allow(
        clippy::too_many_arguments,
        reason = "each field is a distinct grant fact; bundling them would only rename the same seven values"
    )]
    pub(crate) fn insert(
        &mut self,
        scope: Scope,
        key: SecretName,
        value: SecretBytes,
        created: Instant,
        origin: GrantOrigin,
        ttl: Duration,
    ) {
        self.grants
            .retain(|grant| !(grant.scope == scope && grant.key == key));
        self.grants.push(Grant {
            scope,
            key,
            value,
            origin,
            created,
            ttl,
        });
    }

    /// Revoke one scope/key grant, zeroizing its cached plaintext.
    pub fn revoke(&mut self, scope: &Scope, key: &SecretName) {
        self.grants
            .retain(|grant| !(grant.scope == *scope && grant.key == *key));
    }

    /// Revoke every grant belonging to a scope.
    pub fn revoke_scope(&mut self, scope: &Scope) {
        self.grants.retain(|grant| grant.scope != *scope);
    }

    /// Revoke every grant belonging to any of these session tokens.
    pub fn revoke_tokens(&mut self, tokens: &[SessionToken]) {
        self.grants.retain(|grant| match &grant.scope {
            Scope::Session(token) => !tokens.contains(token),
            Scope::Tty { .. } | Scope::Omp { .. } => true,
        });
    }

    /// Revoke grants that have outlived their own recorded `ttl`, returning
    /// how many were removed.
    pub fn revoke_expired(&mut self, now: Instant) -> usize {
        let before = self.grants.len();
        self.grants
            .retain(|grant| now.duration_since(grant.created) < grant.ttl);
        before.saturating_sub(self.grants.len())
    }

    /// Revoke everything.
    pub fn revoke_all(&mut self) {
        self.grants.clear();
    }

    /// Revoke tokenless grants whose backing scope vanished.
    pub fn revoke_vanished_scopes(&mut self) {
        self.grants.retain(|grant| match &grant.scope {
            Scope::Session(_) => true,
            Scope::Tty { tty, .. } => std::path::Path::new(tty).exists(),
            Scope::Omp { pid, start } => OmpProcess::new(*pid, *start).is_running(),
        });
    }

    /// Whether any grant is live.
    pub const fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Each grant that has not outlived its own `ttl` (the rule of `lookup`),
    /// in table order: its key, its scope and its whole seconds left. Never
    /// its value.
    pub(crate) fn live(&self, now: Instant) -> impl Iterator<Item = (&SecretName, &Scope, u64)> {
        self.grants.iter().filter_map(move |grant| {
            let age = now.duration_since(grant.created);
            (age < grant.ttl).then(|| {
                (
                    &grant.key,
                    &grant.scope,
                    grant.ttl.saturating_sub(age).as_secs(),
                )
            })
        })
    }
}
