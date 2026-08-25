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

use std::ffi::OsStr;
use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use zeroize::Zeroizing;

mod reply;
mod transport;
mod validation;

use reply::{authorized_receipt, redeemed_cap, valid_field, valid_hex_bytes};
#[cfg(test)]
use transport::map_code;
use transport::{broker_identity_as, call_as, connect_as, test_peer_executable};
pub use validation::authorize_request;
use validation::{caller_tty, session_token};

const SUBSCRIPTION_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

/// Browser capability namespace in the broker.
pub const CAP_BROWSER: &str = "browser";

/// The broker instance and authority epoch that jointly identify authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrokerIdentity {
    pub instance: String,
    pub epoch: u64,
}
/// A redeemed capability's current authority and broker-controlled lifetime.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedeemedGrant {
    pub authority: BrokerIdentity,
    pub ttl_secs: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BrokerError {
    #[error("forward: secretsd unreachable at {path}: {source}")]
    Connect {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("forward: secretsd peer at {path} did not pass uid and executable verification")]
    UntrustedPeer { path: PathBuf },
    #[error("forward: secretsd authority subscription closed")]
    SubscriptionClosed,
    #[error("forward: secretsd authority subscription refused: subscriber capacity reached")]
    SubscriberCapacity,
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
    authorize_as(cap, OsStr::new("secrets"))
}

#[doc(hidden)]
pub fn authorize_for_test(cap: &str) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let path = socket_path();
    authorize_as(cap, &test_peer_executable(&path)?)
}

fn authorize_as(cap: &str, expected_executable: &OsStr) -> Result<Zeroizing<Vec<u8>>, BrokerError> {
    let path = socket_path();
    let frame = Zeroizing::new(authorize_request(cap, session_token()?, caller_tty())?);
    let fields = call_as(&path, &frame, Verb::Authorize { cap }, expected_executable)?;
    let receipt = authorized_receipt(&fields)?;
    Ok(Zeroizing::new(receipt.as_bytes().to_vec()))
}

/// Redeem a receipt with the broker and return its authority and remaining TTL.
///
/// One receipt redeems exactly once. The pair is captured at redemption and
/// must be rechecked before forward records a grant; the TTL is the broker's
/// capability-grant deadline and bounds forward's derived caches.
pub fn redeem(path: &Path, receipt: &[u8], cap: &str) -> Result<RedeemedGrant, BrokerError> {
    redeem_as(path, receipt, cap, OsStr::new("secrets"))
}

#[doc(hidden)]
pub fn redeem_for_test(
    path: &Path,
    receipt: &[u8],
    cap: &str,
) -> Result<RedeemedGrant, BrokerError> {
    redeem_as(path, receipt, cap, &test_peer_executable(path)?)
}

fn redeem_as(
    path: &Path,
    receipt: &[u8],
    cap: &str,
    expected_executable: &OsStr,
) -> Result<RedeemedGrant, BrokerError> {
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
    let fields = call_as(path, &frame, Verb::Redeem, expected_executable)?;
    redeemed_cap(&fields, cap)
}

/// Read the broker identity and authority epoch through a fresh, version-checked
/// `HELLO`.
pub fn broker_identity(path: &Path) -> Result<BrokerIdentity, BrokerError> {
    broker_identity_as(path, OsStr::new("secrets"))
}

#[doc(hidden)]
pub fn broker_identity_for_test(path: &Path) -> Result<BrokerIdentity, BrokerError> {
    broker_identity_as(path, &test_peer_executable(path)?)
}

/// Attach to the broker's input-free authority-event subscription. Every
/// `EPOCH` event carries the broker instance and its epoch as one authority pair.
pub(crate) fn subscribe(path: &Path, read_timeout: Duration) -> Result<UnixStream, BrokerError> {
    subscribe_as(path, read_timeout, OsStr::new("secrets"))
}

pub(crate) fn subscribe_for_test(
    path: &Path,
    read_timeout: Duration,
) -> Result<UnixStream, BrokerError> {
    subscribe_as(path, read_timeout, &test_peer_executable(path)?)
}

fn subscribe_as(
    path: &Path,
    read_timeout: Duration,
    expected_executable: &OsStr,
) -> Result<UnixStream, BrokerError> {
    let mut stream = connect_as(path, expected_executable)?;
    stream
        .set_read_timeout(Some(read_timeout))
        .and_then(|()| stream.set_write_timeout(Some(SUBSCRIPTION_WRITE_TIMEOUT)))
        .map_err(|source| BrokerError::Connect {
            path: path.to_path_buf(),
            source,
        })?;
    stream
        .write_all(proto::SUBSCRIBE_VERB.as_bytes())
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|source| BrokerError::Connect {
            path: path.to_path_buf(),
            source,
        })?;
    Ok(stream)
}
#[cfg(test)]
mod tests;
