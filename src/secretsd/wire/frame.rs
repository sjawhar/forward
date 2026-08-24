//! Scope discovery and request-frame validation for `AUTHORIZE`.

use super::super::BrokerError;
use std::io::IsTerminal as _;
use std::os::unix::fs::MetadataExt as _;
use zeroize::Zeroize as _;

/// Must match secretsd's `proto::MAX_FRAME_BYTES`.
const MAX_FRAME_BYTES: usize = 4_096;

/// Current effective UID, derived without a libc dependency.
pub(crate) fn process_uid() -> u32 {
    std::fs::metadata("/proc/self")
        .map(|meta| meta.uid())
        .unwrap_or(0)
}

/// Reads a token, rejecting invalid file contents before they can become a frame.
pub(crate) fn session_token() -> Result<Option<String>, BrokerError> {
    let Some(path) = std::env::var_os("SECRETSD_SESSION_TOKEN_FILE") else {
        return Ok(None);
    };
    let Ok(mut bytes) = std::fs::read(path) else {
        return Ok(None);
    };
    let token = std::str::from_utf8(&bytes)
        .ok()
        .filter(|value| valid_field(value))
        .map(ToOwned::to_owned);
    bytes.zeroize();
    token
        .map(Some)
        .ok_or_else(|| BrokerError::Protocol("session token contains an invalid field".to_owned()))
}

pub(crate) fn caller_tty() -> Option<String> {
    std::io::stdin()
        .is_terminal()
        .then(|| std::fs::read_link("/proc/self/fd/0").ok())
        .flatten()
        .map(|path| path.to_string_lossy().into_owned())
}

pub fn authorize_frame(
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
    let frame_len =
        "AUTHORIZE\tcap=".len() + cap.len() + 1 + scope_name.len() + 1 + scope.len() + 1;
    if frame_len > MAX_FRAME_BYTES {
        return Err(BrokerError::Protocol(
            "authorization request exceeds the broker frame limit".to_owned(),
        ));
    }
    Ok(format!("AUTHORIZE\tcap={cap}\t{scope_name}={scope}\n"))
}

pub(crate) fn valid_field(value: &str) -> bool {
    !value.is_empty() && value.is_ascii() && !value.bytes().any(|byte| byte.is_ascii_control())
}
