//! Client for the broker's capability verbs, protocol v3.
//!
//! forward is not a secrets client: nothing here ever requests, receives, or
//! forwards a secret value. AUTHORIZE asks the broker to run its YubiKey touch
//! ceremony for a named capability and returns a single-use receipt; REDEEM
//! lets the serve daemon verify that receipt with the broker directly.
//!
//! The transport is `crates/proto`, shared with the broker. This module is the
//! part that is genuinely forward's: which verbs it sends, and how a broker
//! error code becomes a message a forward user can act on. That mapping is
//! **verb-sensitive** -- the same `DENIED` means "the human declined" for
//! AUTHORIZE and "this receipt is not valid" for REDEEM -- which is why it
//! belongs here and not in the shared crate. The broker's own CLI never sends
//! either verb.

use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use proto::{BrokerClient, BrokerResponse, ClientError};
use zeroize::Zeroizing;

const SUBSCRIPTION_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Browser capability namespace in the broker.
pub const CAP_BROWSER: &str = "browser";

/// The broker identity and authority epoch from a version-checked handshake.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrokerIdentity {
    pub(crate) instance: String,
    pub(crate) epoch: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("forward: secretsd unreachable at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Static client diagnostics only; broker payloads never enter this error.
    #[error("forward: secretsd protocol error: {0}")]
    Protocol(String),
    #[error(
        "forward: secretsd is too old for capability authorization; upgrade secretsd to >= 2.6.0"
    )]
    UnknownOp,
    #[error("forward: authorization denied")]
    Denied,
    #[error("forward: authorization timed out waiting for the YubiKey touch")]
    Timeout,
    #[error("forward: YubiKey unreachable; check `forward doctor` and the pcsc channel")]
    YubikeyUnreachable,
    #[error(
        "forward: capability {0} is not provisioned; create secrets.human.d/CAP_{1}.env with `secrets edit-human`"
    )]
    NotProvisioned(String, String),
    #[error(
        "forward: no session token and no terminal; run inside an omp session or an interactive shell"
    )]
    NoScope,
    #[error("forward: secretsd rejected the receipt")]
    ReceiptRejected,
    #[error(
        "forward: the broker's approval queue is full; wait for a pending touch to resolve and retry"
    )]
    TooManyPending,
}

/// Which verb a reply belongs to, so an error code maps to the right message.
#[derive(Clone, Copy)]
enum Verb<'a> {
    Authorize { cap: &'a str },
    Redeem,
    Hello,
}

/// `SECRETSD_SOCK`, else `$XDG_RUNTIME_DIR/secretsd.sock`, else
/// `/run/user/<uid>/secretsd.sock` -- resolved by the shared client, so this
/// cannot drift from the derivation the broker's own clients use.
pub fn socket_path() -> PathBuf {
    proto::SocketPath::resolve(
        std::env::var("SECRETSD_SOCK").ok().as_deref(),
        std::env::var("XDG_RUNTIME_DIR").ok().as_deref(),
        nix::unistd::getuid().as_raw(),
    )
    .as_ref()
    .to_path_buf()
}

/// Run the broker's touch ceremony for `cap`; blocks through the touch window.
/// Returns the single-use receipt as lowercase hex bytes, wiped on drop.
pub fn authorize(cap: &str) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let path = socket_path();
    let frame = Zeroizing::new(authorize_request(cap, session_token()?, caller_tty())?);
    let fields = call(&path, &frame, Verb::Authorize { cap })?;
    let receipt = authorized_receipt(&fields)?;
    Ok(Zeroizing::new(receipt.as_bytes().to_vec()))
}

/// Redeem a receipt with the broker and return its authority epoch.
///
/// One receipt redeems exactly once. The epoch is captured at redemption and
/// must be rechecked before forward records a grant.
pub fn redeem(path: &Path, receipt: &[u8], cap: &str) -> Result<u64, BrokerError> {
    if !valid_hex_bytes(receipt, 64) {
        return Err(BrokerError::Protocol(
            "receipt is not lowercase ASCII hex".to_owned(),
        ));
    }
    if !valid_field(cap) {
        return Err(BrokerError::Protocol(
            "redeem request contains an invalid capability".to_owned(),
        ));
    }
    // The receipt is ASCII hex, checked above, so this is lossless.
    let receipt = String::from_utf8_lossy(receipt);
    let frame = Zeroizing::new(format!("REDEEM\treceipt={receipt}\tcap={cap}"));
    let fields = call(path, &frame, Verb::Redeem)?;
    redeemed_cap(&fields, cap)
}

/// Read the broker identity and authority epoch through a fresh, version-checked
/// `HELLO`.
pub(crate) fn broker_identity(path: &Path) -> Result<BrokerIdentity, BrokerError> {
    let fields = BrokerClient::new(path)
        .hello_fields()
        .map_err(|error| map_error(error, path, Verb::Hello))?;
    let instance = fields.required("instance").map_err(|_| {
        BrokerError::Protocol("broker HELLO reply has no usable instance".to_owned())
    })?;
    let epoch = fields
        .required("epoch")
        .map_err(|_| BrokerError::Protocol("broker HELLO reply has no usable epoch".to_owned()))?
        .parse()
        .map_err(|_| BrokerError::Protocol("broker HELLO reply has no usable epoch".to_owned()))?;
    Ok(BrokerIdentity {
        instance: instance.to_owned(),
        epoch,
    })
}

/// Attach to the broker's input-free authority-event subscription.
pub(crate) fn subscribe(path: &Path) -> Result<UnixStream, BrokerError> {
    let mut stream = UnixStream::connect(path).map_err(|source| BrokerError::Connect {
        path: path.to_path_buf(),
        source,
    })?;
    stream
        .set_write_timeout(Some(SUBSCRIPTION_WRITE_TIMEOUT))
        .map_err(|source| BrokerError::Connect {
            path: path.to_path_buf(),
            source,
        })?;
    stream
        .write_all(b"SUBSCRIBE\n")
        .map_err(|source| BrokerError::Connect {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(stream)
}

/// Read the broker authority epoch through a fresh, version-checked `HELLO`.
pub fn lock_epoch(path: &Path) -> Result<u64, BrokerError> {
    broker_identity(path).map(|identity| identity.epoch)
}

/// Send one request over the shared transport and map its reply.
fn call(path: &Path, request: &str, verb: Verb<'_>) -> Result<Zeroizing<String>, BrokerError> {
    // `call` performs the version handshake first, and the shared client keys
    // its read timeout off the verb, so AUTHORIZE gets the approval window
    // rather than the control timeout.
    match BrokerClient::new(path).call(request) {
        Ok(BrokerResponse::Ok) => Ok(Zeroizing::new(String::new())),
        Ok(BrokerResponse::Fields(fields)) => Ok(Zeroizing::new(fields)),
        Ok(BrokerResponse::Bytes(_)) => Err(BrokerError::Protocol(
            "broker returned a payload to a capability verb".to_owned(),
        )),
        Err(error) => Err(map_error(error, path, verb)),
    }
}

/// Map a transport or broker error onto forward's vocabulary.
fn map_error(error: ClientError, path: &Path, verb: Verb<'_>) -> BrokerError {
    match error {
        ClientError::Io(source) => BrokerError::Connect {
            path: path.to_path_buf(),
            source,
        },
        ClientError::ApprovalTimeout => match verb {
            Verb::Authorize { .. } => BrokerError::Timeout,
            Verb::Redeem => BrokerError::Protocol("redeem timed out".to_owned()),
            Verb::Hello => BrokerError::Protocol("HELLO timed out".to_owned()),
        },
        // A version disagreement and an unknown verb are different failures: the
        // first means the broker speaks another protocol, the second that this
        // one lacks the capability verbs. Only the latter names an upgrade.
        ClientError::VersionHandshake => {
            BrokerError::Protocol("broker did not confirm protocol version 3".to_owned())
        }
        ClientError::Broker(code) => map_code(code.wire(), verb),
        ClientError::InvalidRequest | ClientError::InvalidResponse => {
            BrokerError::Protocol("malformed broker exchange".to_owned())
        }
        ClientError::TokenFile => {
            BrokerError::Protocol("session token file is not valid UTF-8".to_owned())
        }
    }
}

/// The verb-sensitive part: one code, different meanings.
fn map_code(code: &str, verb: Verb<'_>) -> BrokerError {
    match (code, verb) {
        ("UNKNOWN_OP", _) => BrokerError::UnknownOp,
        ("DENIED", Verb::Authorize { .. }) => BrokerError::Denied,
        ("DENIED", Verb::Redeem) => BrokerError::ReceiptRejected,
        ("TIMEOUT", Verb::Authorize { .. }) => BrokerError::Timeout,
        ("YUBIKEY_UNREACHABLE", Verb::Authorize { .. }) => BrokerError::YubikeyUnreachable,
        ("TOO_MANY_PENDING", Verb::Authorize { .. }) => BrokerError::TooManyPending,
        ("NOT_HUMAN_KEY" | "AMBIGUOUS_KEY", Verb::Authorize { cap }) => {
            BrokerError::NotProvisioned(cap.to_owned(), cap.to_ascii_uppercase())
        }
        ("NO_SCOPE" | "UNKNOWN_TOKEN" | "FOREIGN_CALLER" | "AGENT_TTY", Verb::Authorize { .. }) => {
            BrokerError::NoScope
        }
        _ => BrokerError::Protocol("unrecognized broker error".to_owned()),
    }
}

/// Build the AUTHORIZE request, preferring a session token over a terminal.
///
/// The frame bound counts the trailing newline the transport appends, so this
/// is one content byte tighter than the broker's own limit. That asymmetry is
/// deliberate: a request forward refuses locally never reaches the socket.
pub fn authorize_request(
    cap: &str,
    token: Option<String>,
    tty: Option<String>,
) -> Result<String, BrokerError> {
    let (scope_name, scope) = match (token, tty) {
        (Some(token), _) => ("token", token),
        (None, Some(tty)) => ("tty", tty),
        (None, None) => return Err(BrokerError::NoScope),
    };
    if !valid_field(cap) || !valid_field(&scope) {
        return Err(BrokerError::Protocol(
            "authorization request contains an invalid field".to_owned(),
        ));
    }
    let request = format!("AUTHORIZE\tcap={cap}\t{scope_name}={scope}");
    if request.len().saturating_add(1) > proto::MAX_FRAME_BYTES {
        return Err(BrokerError::Protocol(
            "authorization request exceeds the broker frame limit".to_owned(),
        ));
    }
    Ok(request)
}

/// Read the session token, rejecting invalid contents before they become a frame.
///
/// The distinction that matters: an absent file means "no token", and the
/// caller falls back to a terminal scope. A file that exists but does not hold
/// a sendable field is an error, never a fallback -- something wrote a token
/// forward must not put on the wire, and quietly using a tty instead would
/// hide it. The shared reader also rejects a token with surrounding
/// whitespace, so a stray trailing newline lands here rather than on the wire.
fn session_token() -> Result<Option<String>, BrokerError> {
    let Some(path) = std::env::var_os("SECRETSD_SESSION_TOKEN_FILE") else {
        return Ok(None);
    };
    // No file at all is "no token": fall back to a terminal scope.
    if std::fs::metadata(&path).is_err() {
        return Ok(None);
    }
    // A file that exists but does not hold a sendable field is a hard error,
    // never a silent fallback. Something wrote a token forward must not put on
    // the wire, and falling back to a tty would mask that.
    let token = proto::read_token_file(&path).map_err(|_| {
        BrokerError::Protocol("session token file is unreadable or malformed".to_owned())
    })?;
    if valid_field(&token) {
        Ok(Some(token))
    } else {
        Err(BrokerError::Protocol(
            "session token contains an invalid field".to_owned(),
        ))
    }
}

fn caller_tty() -> Option<String> {
    proto::caller_tty()
}

fn authorized_receipt(fields: &str) -> Result<Zeroizing<String>, BrokerError> {
    let parsed = expected_fields(fields, &["status", "receipt"])?;
    match (value(&parsed, "status"), value(&parsed, "receipt")) {
        (Some("authorized"), Some(receipt)) if valid_hex_bytes(receipt.as_bytes(), 64) => {
            Ok(Zeroizing::new(receipt.to_owned()))
        }
        _ => Err(BrokerError::Protocol(
            "broker did not return an authorized receipt".to_owned(),
        )),
    }
}

fn redeemed_cap(fields: &str, cap: &str) -> Result<u64, BrokerError> {
    let parsed = expected_fields(fields, &["status", "cap", "epoch"])?;
    match (
        value(&parsed, "status"),
        value(&parsed, "cap"),
        value(&parsed, "epoch"),
    ) {
        (Some("redeemed"), Some(returned), Some(epoch)) if returned == cap => {
            epoch.parse().map_err(|_| {
                BrokerError::Protocol("broker redeem reply has no usable epoch".to_owned())
            })
        }
        // A reply naming this capability under a status REDEEM never produces
        // is malformed, not a refusal: treating an AUTHORIZE-shaped success as
        // "receipt rejected" would hide a broker that answered the wrong verb.
        (Some(status), _, _) if status != "redeemed" => Err(BrokerError::Protocol(
            "broker success reply has an unexpected status".to_owned(),
        )),
        _ => Err(BrokerError::ReceiptRejected),
    }
}

fn expected_fields<'a>(
    fields: &'a str,
    expected: &[&str],
) -> Result<Vec<(&'a str, &'a str)>, BrokerError> {
    let mut parsed = Vec::with_capacity(expected.len());
    for field in fields.split(' ') {
        let Some((name, field_value)) = field.split_once('=') else {
            return Err(BrokerError::Protocol(
                "malformed broker success reply".to_owned(),
            ));
        };
        if name.is_empty()
            || field_value.is_empty()
            || !expected.contains(&name)
            || parsed.iter().any(|(seen, _)| *seen == name)
        {
            return Err(BrokerError::Protocol(
                "unexpected or duplicate broker success field".to_owned(),
            ));
        }
        parsed.push((name, field_value));
    }
    (parsed.len() == expected.len())
        .then_some(parsed)
        .ok_or_else(|| BrokerError::Protocol("broker success reply is missing a field".to_owned()))
}

fn value<'a>(fields: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find_map(|(field, field_value)| (*field == name).then_some(*field_value))
}

fn valid_field(value: &str) -> bool {
    !value.is_empty() && value.is_ascii() && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_hex_bytes(value: &[u8], length: usize) -> bool {
    value.len() == length
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests;
