//! Server-side request parsing for wire protocol v3.
//!
//! The protocol vocabulary -- version, frame bound, error codes -- and the
//! client transport live in `crates/proto`, shared with forward. What stays
//! here is the half only a server needs: the `Request` grammar and its parser.

use std::fmt;

pub use proto::{
    ErrCode, MAX_FRAME_BYTES, PROTOCOL_VERSION, SUBSCRIBE_VERB, SUBSCRIBER_CAPACITY_RESPONSE,
};
use zeroize::Zeroizing;

mod response;

pub use response::{Response, format_response};

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
/// A parsed client request. Tokens stay as hex here; `grants` owns the crypto type.
pub enum Request {
    /// Version handshake.
    Hello {
        /// Protocol version the client speaks.
        version: u32,
    },
    /// Harness registers a session token.
    Register {
        /// Hex-encoded session token.
        token_hex: Zeroizing<String>,
        /// Harness-supplied session identifier, untrusted and used only for logging.
        session: String,
        /// Harness process id, shown as unverified caller metadata.
        pid: i32,
    },
    /// Harness reports a session ended.
    Unregister {
        /// Session identifier used at registration.
        session: String,
    },
    /// Fetch a secret value, blocking through the grant flow if needed.
    Get {
        /// Requested key name.
        key: String,
        /// Hex-encoded session token, if the caller has one.
        token_hex: Option<Zeroizing<String>>,
        /// Caller's controlling tty, if any.
        tty: Option<String>,
    },
    /// Trigger the grant flow without returning a value.
    RequestGrant {
        /// Requested key name.
        key: String,
        /// Hex-encoded session token, if the caller has one.
        token_hex: Option<Zeroizing<String>>,
        /// Caller's controlling tty, if any.
        tty: Option<String>,
    },
    /// Run the grant ceremony for a named capability; returns no value, only
    /// a single-use receipt attesting the authorization.
    Authorize {
        /// Capability name, `[a-z][a-z0-9_]*`; the daemon derives the backing
        /// `CAP_<NAME>` key.
        cap: String,
        /// Hex-encoded session token, if the caller has one.
        token_hex: Option<Zeroizing<String>>,
        /// Caller's controlling tty, if any.
        tty: Option<String>,
    },
    /// Consume a receipt minted by a successful AUTHORIZE.
    Redeem {
        /// Hex-encoded receipt.
        receipt_hex: Zeroizing<String>,
        /// Capability this receipt must attest.
        cap: String,
    },
    /// List active grants and pending requests.
    Grants,
    /// Reject a pending request.
    Deny {
        /// Pending request identifier.
        id: u64,
    },
    /// Wipe all plaintext and revoke all grants.
    Lock,
    /// Hold this input-free connection open for `EPOCH <epoch>
    /// instance=<broker-instance>` authority events.
    Subscribe,
}

impl fmt::Debug for Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello { version } => formatter
                .debug_struct("Hello")
                .field("version", version)
                .finish(),
            Self::Register { session, pid, .. } => formatter
                .debug_struct("Register")
                .field("token_hex", &"<redacted>")
                .field("session", session)
                .field("pid", pid)
                .finish(),
            Self::Unregister { session } => formatter
                .debug_struct("Unregister")
                .field("session", session)
                .finish(),
            Self::Get { key, tty, .. } => formatter
                .debug_struct("Get")
                .field("key", key)
                .field("token_hex", &"<redacted>")
                .field("tty", tty)
                .finish(),
            Self::RequestGrant { key, tty, .. } => formatter
                .debug_struct("RequestGrant")
                .field("key", key)
                .field("token_hex", &"<redacted>")
                .field("tty", tty)
                .finish(),
            Self::Authorize { cap, tty, .. } => formatter
                .debug_struct("Authorize")
                .field("cap", cap)
                .field("token_hex", &"<redacted>")
                .field("tty", tty)
                .finish(),
            Self::Redeem { cap, .. } => formatter
                .debug_struct("Redeem")
                .field("receipt_hex", &"<redacted>")
                .field("cap", cap)
                .finish(),
            Self::Grants => formatter.write_str("Grants"),
            Self::Deny { id } => formatter.debug_struct("Deny").field("id", id).finish(),
            Self::Lock => formatter.write_str("Lock"),
            Self::Subscribe => formatter.write_str("Subscribe"),
        }
    }
}

fn field<'a>(fields: &'a [(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(key, _)| *key == name)
        .map(|(_, value)| *value)
}

fn required<'a>(fields: &'a [(&'a str, &'a str)], name: &str) -> Result<&'a str, ErrCode> {
    field(fields, name).ok_or(ErrCode::BadRequest)
}

/// Parse one request frame without its trailing newline.
pub fn parse_request(line: &[u8]) -> Result<Request, ErrCode> {
    if line.is_empty() || line.len() > MAX_FRAME_BYTES {
        return Err(ErrCode::BadRequest);
    }

    let text = std::str::from_utf8(line).map_err(|_| ErrCode::BadRequest)?;
    let mut parts = text.split('\t');
    let op = parts.next().ok_or(ErrCode::BadRequest)?;
    let mut fields = Vec::new();

    for part in parts {
        let (key, value) = part.split_once('=').ok_or(ErrCode::BadRequest)?;
        if field(&fields, key).is_some() {
            return Err(ErrCode::BadRequest);
        }
        fields.push((key, value));
    }

    let owned = |name: &str| field(&fields, name).map(ToOwned::to_owned);
    let credential =
        |name: &str| field(&fields, name).map(|value| Zeroizing::new(value.to_owned()));

    match op {
        "HELLO" => Ok(Request::Hello {
            version: required(&fields, "version")?
                .parse()
                .map_err(|_| ErrCode::BadRequest)?,
        }),
        "REGISTER" => Ok(Request::Register {
            token_hex: Zeroizing::new(required(&fields, "token")?.to_owned()),
            session: required(&fields, "session")?.to_owned(),
            pid: required(&fields, "pid")?
                .parse()
                .map_err(|_| ErrCode::BadRequest)?,
        }),
        "UNREGISTER" => Ok(Request::Unregister {
            session: required(&fields, "session")?.to_owned(),
        }),
        "GET" => Ok(Request::Get {
            key: required(&fields, "key")?.to_owned(),
            token_hex: credential("token"),
            tty: owned("tty"),
        }),
        "REQUEST" => Ok(Request::RequestGrant {
            key: required(&fields, "key")?.to_owned(),
            token_hex: credential("token"),
            tty: owned("tty"),
        }),
        "AUTHORIZE" => Ok(Request::Authorize {
            cap: required(&fields, "cap")?.to_owned(),
            token_hex: credential("token"),
            tty: owned("tty"),
        }),
        "REDEEM" => Ok(Request::Redeem {
            receipt_hex: Zeroizing::new(required(&fields, "receipt")?.to_owned()),
            cap: required(&fields, "cap")?.to_owned(),
        }),
        "GRANTS" => Ok(Request::Grants),
        "DENY" => Ok(Request::Deny {
            id: required(&fields, "id")?
                .parse()
                .map_err(|_| ErrCode::BadRequest)?,
        }),
        "LOCK" => Ok(Request::Lock),
        SUBSCRIBE_VERB => fields
            .is_empty()
            .then_some(Request::Subscribe)
            .ok_or(ErrCode::BadRequest),
        _ => Err(ErrCode::UnknownOp),
    }
}

#[cfg(test)]
mod tests;
