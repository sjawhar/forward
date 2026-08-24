//! Broker reply deadline, parsing, and verb-aware error mapping.

use super::super::BrokerError;
use std::io::{Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const MAX_REPLY_LINE: usize = 256;

/// Which request a reply answers. Errors have different meanings per verb.
#[derive(Clone, Copy)]
pub(crate) enum Verb<'cap> {
    Hello,
    Authorize { cap: &'cap str },
    Redeem,
}

pub(crate) fn hello(path: &Path, timeout: Duration) -> Result<(), BrokerError> {
    let fields = call(path, b"HELLO\tversion=3\n", timeout, Verb::Hello)?;
    let values = expected_fields(&fields, &["version", "instance"])?;
    if value(&values, "version") == Some("3") {
        Ok(())
    } else {
        Err(BrokerError::Protocol(
            "unsupported broker protocol version".to_owned(),
        ))
    }
}

pub(crate) fn call(
    path: &Path,
    frame: &[u8],
    timeout: Duration,
    verb: Verb<'_>,
) -> Result<Zeroizing<String>, BrokerError> {
    let reply = exchange(path, frame, timeout)?;
    ok_fields(&reply, verb)
}

pub(crate) fn authorized_receipt(fields: &str) -> Result<&str, BrokerError> {
    let values = expected_fields(fields, &["status", "receipt"])?;
    let (Some("authorized"), Some(receipt)) = (
        value(&values, "status"),
        value(&values, "receipt").filter(|receipt| valid_hex(receipt, 64)),
    ) else {
        return Err(BrokerError::Protocol(
            "invalid authorized broker reply".to_owned(),
        ));
    };
    Ok(receipt)
}

pub(crate) fn redeemed_cap(fields: &str, cap: &str) -> Result<(), BrokerError> {
    let values = expected_fields(fields, &["status", "cap"])?;
    if value(&values, "status") == Some("redeemed") && value(&values, "cap") == Some(cap) {
        Ok(())
    } else {
        Err(BrokerError::Protocol(
            "invalid redeemed broker reply".to_owned(),
        ))
    }
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
    stream.write_all(frame).map_err(connect_error)?;
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| BrokerError::Protocol("broker reply deadline overflowed".to_owned()))?;
    let reply = match read_reply(&mut stream, deadline) {
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
    let reply = std::str::from_utf8(&reply)
        .map_err(|_| BrokerError::Protocol("broker reply is not UTF-8".to_owned()))?;
    Ok(Zeroizing::new(reply.to_owned()))
}

fn read_reply(stream: &mut UnixStream, deadline: Instant) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut reply = Zeroizing::new(Vec::with_capacity(MAX_REPLY_LINE));
    let mut byte = [0_u8; 1];
    while reply.len() < MAX_REPLY_LINE {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(std::io::Error::from(std::io::ErrorKind::TimedOut));
        }
        stream.set_read_timeout(Some(remaining))?;
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
        Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
    } else {
        Err(std::io::Error::from(std::io::ErrorKind::InvalidData))
    }
}

/// Parse `OK\t<fields>` or map an `ERR\t<CODE>\t<msg>` to a typed error.
pub(crate) fn ok_fields(reply: &str, verb: Verb<'_>) -> Result<Zeroizing<String>, BrokerError> {
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
    })
}

fn expected_fields<'a>(
    fields: &'a str,
    expected: &[&str],
) -> Result<Vec<(&'a str, &'a str)>, BrokerError> {
    let mut parsed = Vec::with_capacity(expected.len());
    for field in fields.split(' ') {
        let Some((name, value)) = field.split_once('=') else {
            return Err(BrokerError::Protocol(
                "malformed broker success reply".to_owned(),
            ));
        };
        if name.is_empty()
            || value.is_empty()
            || !expected.contains(&name)
            || parsed.iter().any(|(seen, _)| *seen == name)
        {
            return Err(BrokerError::Protocol(
                "unexpected or duplicate broker success field".to_owned(),
            ));
        }
        parsed.push((name, value));
    }
    (parsed.len() == expected.len())
        .then_some(parsed)
        .ok_or_else(|| BrokerError::Protocol("broker success reply is missing a field".to_owned()))
}

fn value<'a>(fields: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    fields
        .iter()
        .find_map(|(field, value)| (*field == name).then_some(*value))
}

pub(crate) fn valid_receipt_bytes(value: &[u8]) -> bool {
    valid_hex_bytes(value, 64)
}

fn valid_hex(value: &str, length: usize) -> bool {
    valid_hex_bytes(value.as_bytes(), length)
}

fn valid_hex_bytes(value: &[u8], length: usize) -> bool {
    value.len() == length
        && value
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}
