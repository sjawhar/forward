//! Client for secretsd's capability verbs, protocol v3.
//!
//! forward is not a secrets client: nothing here ever requests, receives, or
//! forwards a secret value. AUTHORIZE asks the broker to run its YubiKey touch
//! ceremony for a named capability and returns a single-use receipt; REDEEM
//! lets the serve daemon verify that receipt with the broker directly.

mod wire;

use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroizing;

pub use wire::authorize_frame;

pub const CAP_BROWSER: &str = "browser";
/// Covers the broker's 90s approval window plus queueing behind another touch.
const AUTHORIZE_TIMEOUT: Duration = Duration::from_secs(120);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

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
}

/// `SECRETSD_SOCK`, else `$XDG_RUNTIME_DIR/secretsd.sock`, else
/// `/run/user/<uid>/secretsd.sock` — the same derivation secretsd's own
/// clients use.
pub fn socket_path() -> PathBuf {
    if let Some(path) = std::env::var_os("SECRETSD_SOCK").filter(|value| !value.is_empty()) {
        return PathBuf::from(path);
    }
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR").filter(|value| !value.is_empty()) {
        return PathBuf::from(dir).join("secretsd.sock");
    }
    PathBuf::from(format!("/run/user/{}/secretsd.sock", wire::process_uid()))
}

/// Run the broker's touch ceremony for `cap`; blocks through the touch window.
/// Returns the single-use receipt as lowercase hex bytes.
pub fn authorize(cap: &str) -> Result<Vec<u8>, BrokerError> {
    let path = socket_path();
    let frame = Zeroizing::new(wire::authorize_frame(
        cap,
        wire::session_token()?,
        wire::caller_tty(),
    )?);
    wire::hello(&path, CONTROL_TIMEOUT)?;
    let fields = wire::call(
        &path,
        frame.as_bytes(),
        AUTHORIZE_TIMEOUT,
        wire::Verb::Authorize { cap },
    )?;
    let receipt = wire::authorized_receipt(&fields)?;
    Ok(receipt.as_bytes().to_vec())
}

/// Redeem a receipt with the broker; `Ok(())` only when the broker confirms
/// this exact capability. One receipt redeems exactly once.
pub fn redeem(path: &Path, receipt: &[u8], cap: &str) -> Result<(), BrokerError> {
    if !wire::valid_receipt_bytes(receipt) {
        return Err(BrokerError::Protocol(
            "receipt is not lowercase ASCII hex".to_owned(),
        ));
    }
    let mut frame = Zeroizing::new(Vec::with_capacity(
        b"REDEEM\treceipt=\n".len() + receipt.len(),
    ));
    frame.extend_from_slice(b"REDEEM\treceipt=");
    frame.extend_from_slice(receipt);
    frame.push(b'\n');
    wire::hello(path, CONTROL_TIMEOUT)?;
    let fields = wire::call(path, &frame, CONTROL_TIMEOUT, wire::Verb::Redeem)?;
    wire::redeemed_cap(&fields, cap)
}
