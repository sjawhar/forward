use super::BrokerError;
use super::reply::valid_field;

/// Build the `AUTHORIZE` request, preferring a session token over a terminal.
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

pub(super) fn session_token() -> Result<Option<String>, BrokerError> {
    let Some(path) = std::env::var_os("SECRETSD_SESSION_TOKEN_FILE") else {
        return Ok(None);
    };
    if std::fs::metadata(&path).is_err() {
        return Ok(None);
    }
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

pub(super) fn caller_tty() -> Option<String> {
    proto::caller_tty()
}
