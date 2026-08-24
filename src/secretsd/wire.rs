//! Frame building, response parsing, and error mapping for the broker socket.

use super::BrokerError;
use std::io::{IsTerminal as _, Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

const MAX_REPLY_LINE: usize = 256;

/// Current effective UID, derived without a libc dependency.
pub(super) fn process_uid() -> u32 {
    std::fs::metadata("/proc/self")
        .map(|meta| meta.uid())
        .unwrap_or(0)
}

/// Reads the broker session token from its environment-selected file.
pub(super) fn session_token() -> Option<String> {
    let path = std::env::var_os("SECRETSD_SESSION_TOKEN_FILE")?;
    let value = std::fs::read_to_string(path).ok()?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

pub(super) fn caller_tty() -> Option<String> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    std::fs::read_link("/proc/self/fd/0")
        .ok()
        .map(|path| path.to_string_lossy().into_owned())
}

pub fn authorize_frame(
    cap: &str,
    token: Option<String>,
    tty: Option<String>,
) -> Result<String, BrokerError> {
    match (token, tty) {
        (Some(token), _) => Ok(format!("AUTHORIZE\tcap={cap}\ttoken={token}\n")),
        (None, Some(tty)) => Ok(format!("AUTHORIZE\tcap={cap}\ttty={tty}\n")),
        (None, None) => Err(BrokerError::NoScope),
    }
}

pub(super) fn hello(path: &Path, timeout: Duration) -> Result<(), BrokerError> {
    let reply = exchange(path, b"HELLO\tversion=3\n", timeout)?;
    let fields = ok_fields(&reply, Verb::Hello)?;
    if field(&fields, "version").is_some_and(|version| version == "3") {
        Ok(())
    } else {
        Err(BrokerError::Protocol(
            "unsupported broker protocol version".to_owned(),
        ))
    }
}

/// The operation a reply answers, used for verb-specific error mapping.
#[derive(Clone, Copy)]
pub(super) enum Verb<'cap> {
    Hello,
    Authorize { cap: &'cap str },
    Redeem,
}

pub(super) fn call(
    path: &Path,
    frame: &[u8],
    timeout: Duration,
    verb: Verb<'_>,
) -> Result<Zeroizing<String>, BrokerError> {
    let reply = exchange(path, frame, timeout)?;
    ok_fields(&reply, verb)
}

fn exchange(
    path: &Path,
    frame: &[u8],
    timeout: Duration,
) -> Result<Zeroizing<String>, BrokerError> {
    let connect_error = |source| BrokerError::Connect {
        path: path.to_path_buf(),
        source,
    };
    let mut stream = UnixStream::connect(path).map_err(connect_error)?;
    stream
        .set_read_timeout(Some(timeout))
        .map_err(connect_error)?;
    stream.write_all(frame).map_err(connect_error)?;
    let reply = match read_reply(&mut stream) {
        Ok(reply) => reply,
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(BrokerError::Protocol(
                "broker closed without a reply".to_owned(),
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::InvalidData => {
            return Err(BrokerError::Protocol(
                "broker reply missing a newline".to_owned(),
            ));
        }
        Err(error) => return Err(connect_error(error)),
    };
    String::from_utf8(reply)
        .map(Zeroizing::new)
        .map_err(|_| BrokerError::Protocol("broker reply is not UTF-8".to_owned()))
}

fn read_reply(stream: &mut UnixStream) -> std::io::Result<Vec<u8>> {
    let mut reply = Vec::with_capacity(MAX_REPLY_LINE);
    let mut byte = [0_u8; 1];
    while reply.len() < MAX_REPLY_LINE {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(1) => {
                let [received] = byte;
                reply.push(received);
                if received == b'\n' {
                    return Ok(reply);
                }
            }
            Ok(_) => return Err(std::io::Error::from(std::io::ErrorKind::InvalidData)),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    if reply.is_empty() {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
}

/// Parse `OK\t<fields>` or map an `ERR\t<CODE>\t<msg>` to a typed error.
fn ok_fields(reply: &str, verb: Verb<'_>) -> Result<Zeroizing<String>, BrokerError> {
    let reply = reply.trim_end_matches(['\r', '\n']);
    if let Some(fields) = reply.strip_prefix("OK\t") {
        return Ok(Zeroizing::new(fields.to_owned()));
    }
    if reply == "OK" {
        return Ok(Zeroizing::new(String::new()));
    }
    let mut parts = reply.splitn(3, '\t');
    let (Some("ERR"), Some(code), Some(_message)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(BrokerError::Protocol("malformed broker reply".to_owned()));
    };
    Err(match (code, verb) {
        ("UNKNOWN_OP", _) => BrokerError::UnknownOp,
        ("DENIED", Verb::Authorize { .. }) => BrokerError::Denied,
        ("DENIED", Verb::Redeem) => BrokerError::ReceiptRejected,
        ("TIMEOUT", _) => BrokerError::Timeout,
        ("YUBIKEY_UNREACHABLE", _) => BrokerError::YubikeyUnreachable,
        ("NOT_HUMAN_KEY" | "AMBIGUOUS_KEY", Verb::Authorize { cap }) => {
            BrokerError::NotProvisioned(cap.to_owned(), cap.to_ascii_uppercase())
        }
        ("NO_SCOPE" | "UNKNOWN_TOKEN" | "FOREIGN_CALLER" | "AGENT_TTY", _) => BrokerError::NoScope,
        _ => BrokerError::Protocol("unrecognized broker error".to_owned()),
    })
}

pub(super) fn field<'fields>(fields: &'fields str, name: &str) -> Option<&'fields str> {
    fields
        .split(' ')
        .find_map(|field| field.strip_prefix(name)?.strip_prefix('='))
}

pub(super) fn valid_receipt(value: &str) -> bool {
    valid_receipt_bytes(value.as_bytes())
}

pub(super) fn valid_receipt_bytes(value: &[u8]) -> bool {
    value.len() == 64
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorize_frame_prefers_a_token_over_a_tty() {
        let frame = authorize_frame(
            "browser",
            Some("token".to_owned()),
            Some("/dev/pts/1".to_owned()),
        )
        .unwrap();
        assert!(
            frame == "AUTHORIZE\tcap=browser\ttoken=token\n",
            "wrong authorize frame"
        );
    }
    #[test]
    fn authorize_frame_uses_a_tty_or_rejects_an_unknown_scope() {
        let frame = authorize_frame("browser", None, Some("/dev/pts/1".to_owned())).unwrap();
        assert!(
            frame == "AUTHORIZE\tcap=browser\ttty=/dev/pts/1\n",
            "wrong authorize frame"
        );
        assert!(matches!(
            authorize_frame("browser", None, None),
            Err(BrokerError::NoScope)
        ));
    }
    #[test]
    fn fields_extract_named_values() {
        assert_eq!(field("status=redeemed cap=browser", "cap"), Some("browser"));
        assert_eq!(field("status=redeemed", "cap"), None);
    }
    #[test]
    fn broker_errors_map_per_verb() {
        let denied = "ERR\tDENIED\tdeclined";
        assert!(matches!(
            ok_fields(denied, Verb::Authorize { cap: "browser" }),
            Err(BrokerError::Denied)
        ));
        assert!(matches!(
            ok_fields(denied, Verb::Redeem),
            Err(BrokerError::ReceiptRejected)
        ));
        assert!(matches!(
            ok_fields(denied, Verb::Hello),
            Err(BrokerError::Protocol(_))
        ));
        assert!(matches!(
            ok_fields("ERR\tUNKNOWN_OP\tunknown", Verb::Redeem),
            Err(BrokerError::UnknownOp)
        ));
        assert!(matches!(
            ok_fields("ERR\tNOT_HUMAN_KEY\tmissing", Verb::Authorize { cap: "browser" }),
            Err(BrokerError::NotProvisioned(cap, key)) if cap == "browser" && key == "BROWSER"
        ));
        assert!(matches!(
            ok_fields("ERR\tNOT_HUMAN_KEY\tmissing", Verb::Redeem),
            Err(BrokerError::Protocol(_))
        ));
        assert!(matches!(
            ok_fields("ERR\tDENIED", Verb::Redeem),
            Err(BrokerError::Protocol(_))
        ));
    }
}
