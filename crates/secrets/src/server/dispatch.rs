use std::fmt;

use zeroize::Zeroizing;

use super::approval::dispatch_access;
use super::{Shared, lock_state};
use crate::grants::ScopeKind;
use crate::proto::{ErrCode, PROTOCOL_VERSION, Request};
use crate::requests::RequestId;
use crate::secret::SecretBytes;

mod capability;
mod control;

#[cfg(test)]
use capability::{MintPause, finish_authorization, mint_pause, receipt_mint_failure};
use capability::{authorize, redeem};
use control::{deny, grants, lock, register, unregister};

pub(super) enum Outcome {
    Ok,
    Fields(String),
    Payload(Vec<u8>),
    Bytes(SecretBytes),
    Receipt(Zeroizing<String>),
    Failed(ErrCode, &'static str),
}

impl fmt::Debug for Outcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ok => formatter.write_str("Ok"),
            Self::Fields(fields) => formatter.debug_tuple("Fields").field(fields).finish(),
            Self::Payload(payload) => formatter.debug_tuple("Payload").field(payload).finish(),
            Self::Bytes(value) => formatter.debug_tuple("Bytes").field(value).finish(),
            Self::Receipt(_) => formatter.write_str("Receipt(<redacted>)"),
            Self::Failed(code, message) => formatter
                .debug_tuple("Failed")
                .field(code)
                .field(message)
                .finish(),
        }
    }
}

impl Outcome {
    /// How many secret bytes were handed to the client, if any.
    ///
    /// A release served from a live grant asks nothing of the human and produces
    /// no hardware prompt, so this is the only record that the value moved.
    pub(super) fn released_bytes(&self) -> Option<usize> {
        match self {
            Self::Bytes(value) => Some(value.as_slice().len()),
            Self::Ok | Self::Fields(_) | Self::Payload(_) | Self::Receipt(_) | Self::Failed(..) => {
                None
            }
        }
    }

    pub(super) const fn decision(&self) -> &'static str {
        match self {
            Self::Ok | Self::Fields(_) | Self::Payload(_) | Self::Bytes(_) | Self::Receipt(_) => {
                "ok"
            }
            Self::Failed(code, _) => code.wire(),
        }
    }
}

#[derive(Debug)]
pub(super) struct Decision {
    pub(super) outcome: Outcome,
    pub(super) scope_kind: Option<ScopeKind>,
    pub(super) source: Option<String>,
    pub(super) request_id: Option<RequestId>,
}

impl Decision {
    pub(super) const fn new(outcome: Outcome) -> Self {
        Self {
            outcome,
            scope_kind: None,
            source: None,
            request_id: None,
        }
    }
}

pub(super) fn dispatch(
    request: Request,
    shared: &Shared,
    caller: &crate::peer::PeerIdentity,
) -> Decision {
    match request {
        Request::Hello { version } => Decision::new(if version == PROTOCOL_VERSION {
            // Reported so a harness can tell "same daemon" from "restarted
            // daemon" and re-register before its requests start failing.
            let (mutex, _) = &**shared;
            let state = lock_state(mutex);
            let fields = format!(
                "version={PROTOCOL_VERSION} instance={} epoch={}",
                state.instance, state.lock_epoch
            );
            drop(state);
            Outcome::Fields(fields)
        } else {
            Outcome::Failed(ErrCode::VersionMismatch, "unsupported protocol version")
        }),
        Request::Register {
            token_hex,
            session,
            pid: _wire_pid,
        } => register(shared, &token_hex, &session, caller.clone()),
        Request::Unregister { session } => unregister(shared, &session),
        Request::Get { key, .. } | Request::RequestGrant { key, .. }
            if key.starts_with(crate::capability::CAPABILITY_KEY_PREFIX) =>
        {
            Decision::new(Outcome::Failed(
                ErrCode::NotHumanKey,
                "capability keys hold no retrievable value",
            ))
        }
        Request::Get {
            key,
            token_hex,
            tty,
            ttl_secs,
        } => {
            let access = super::approval::Access {
                key,
                token_hex,
                tty,
                requested_ttl: ttl_secs,
            };
            dispatch_access(shared, &access, true, false, caller)
        }
        Request::RequestGrant {
            key,
            token_hex,
            tty,
            ttl_secs,
        } => {
            let access = super::approval::Access {
                key,
                token_hex,
                tty,
                requested_ttl: ttl_secs,
            };
            dispatch_access(shared, &access, false, false, caller)
        }
        Request::Grants => grants(shared),
        Request::Deny { id } => deny(shared, id),
        Request::Lock => lock(shared),
        Request::Subscribe => Decision::new(Outcome::Failed(
            ErrCode::BadRequest,
            "subscription is connection-scoped",
        )),
        Request::Authorize {
            cap,
            token_hex,
            tty,
        } => authorize(shared, &cap, token_hex, tty, caller),
        Request::Redeem { receipt_hex, cap } => redeem(shared, &receipt_hex, &cap),
    }
}

pub(super) fn request_key(request: &Request) -> Option<&str> {
    match request {
        Request::Get { key, .. } | Request::RequestGrant { key, .. } => Some(key),
        Request::Hello { .. }
        | Request::Register { .. }
        | Request::Unregister { .. }
        | Request::Grants
        | Request::Deny { .. }
        | Request::Lock
        | Request::Subscribe
        | Request::Authorize { .. }
        | Request::Redeem { .. } => None,
    }
}

#[cfg(test)]
mod tests;
