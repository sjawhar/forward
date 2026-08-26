use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// The daemon answers quickly — the YubiKey touch already happened during
/// AUTHORIZE, before this connection opened; only receipt redeem and feed push remain.
const REPLY_TIMEOUT: Duration = Duration::from_secs(10);

/// Whether the calling session holds a live grant, as the daemon reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantStatus {
    /// No daemon answered the request socket's protocol.
    Unreachable,
    /// The daemon answered: the calling session holds no live grant.
    None,
    /// The calling session's grant: its loopback port and remaining seconds.
    Live { port: u16, remaining_secs: u64 },
}

/// Why a grant request produced no port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestFailure {
    /// Nothing answered the socket's protocol — no forward serve listening.
    Unreachable,
    /// forward serve answered `REFUSED`; the payload is its reason word.
    Refused(String),
}

/// A deterministic pre-ceremony answer from forward serve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Nothing answered the socket's protocol — no forward serve listening.
    Unreachable,
    /// forward serve would refuse a grant; the payload is its reason word.
    Refused(String),
    /// Every deterministic check passed; the ceremony is worth running.
    Grantable,
}

/// Human phrasing for a refusal reason word the daemon sent.
#[must_use]
pub fn describe_refusal(reason: &str) -> &'static str {
    match reason {
        "ANCHOR" => "forward serve could not anchor the calling process",
        "UPSTREAM" => "forward serve has no peer configured to relay to",
        "RECEIPT" => "the broker receipt was not redeemed (broker restarted mid-grant?)",
        "LAPTOP" => "the laptop feed is unavailable",
        _ => "forward serve refused (see the forward-serve log for the reason)",
    }
}

/// `45s`, `30m`, or `2h` to seconds, for the CLI's `--ttl`.
pub fn parse_ttl(value: &str) -> Option<u64> {
    if !value.is_ascii() || value.len() < 2 {
        return None;
    }
    let (number, unit) = value.split_at(value.len() - 1);
    let multiplier = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3_600,
        _ => return None,
    };
    number
        .parse::<u64>()
        .ok()?
        .checked_mul(multiplier)
        .filter(|ttl| *ttl > 0)
}

/// Ask the daemon whether a grant for this caller could succeed, without
/// spending a receipt. Runs before the broker's YubiKey ceremony so a
/// deterministic refusal never costs the human a touch.
pub fn probe(path: &Path) -> ProbeOutcome {
    let Ok(mut stream) = UnixStream::connect(path) else {
        return ProbeOutcome::Unreachable;
    };
    if stream.set_read_timeout(Some(REPLY_TIMEOUT)).is_err()
        || stream.write_all(b"PROBE\n").is_err()
    {
        return ProbeOutcome::Unreachable;
    }
    let mut reply = String::new();
    if BufReader::new(stream).read_line(&mut reply).is_err() {
        return ProbeOutcome::Unreachable;
    }
    let reply = reply.trim_end();
    if reply == "OK" {
        return ProbeOutcome::Grantable;
    }
    match reply.strip_prefix("REFUSED") {
        Some(reason) => ProbeOutcome::Refused(reason.trim().to_owned()),
        None => ProbeOutcome::Unreachable,
    }
}

/// Ask the local daemon for a grant. Returns the bound loopback port.
pub fn request(path: &Path, ttl_secs: u64, token: &[u8]) -> Result<u16, RequestFailure> {
    let mut stream = UnixStream::connect(path).map_err(|_| RequestFailure::Unreachable)?;
    stream
        .set_read_timeout(Some(REPLY_TIMEOUT))
        .and_then(|()| stream.write_all(b"GRANT "))
        .and_then(|()| stream.write_all(ttl_secs.to_string().as_bytes()))
        .and_then(|()| stream.write_all(b" "))
        .and_then(|()| stream.write_all(token))
        .and_then(|()| stream.write_all(b"\n"))
        .map_err(|_| RequestFailure::Unreachable)?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|_| RequestFailure::Unreachable)?;
    let reply = reply.trim_end();
    if let Ok(port) = reply.parse() {
        return Ok(port);
    }
    match reply.strip_prefix("REFUSED") {
        Some(reason) => Err(RequestFailure::Refused(reason.trim().to_owned())),
        None => Err(RequestFailure::Unreachable),
    }
}

/// Ask the local daemon whether the calling session holds a live grant.
pub fn status(path: &Path) -> GrantStatus {
    let Ok(mut stream) = UnixStream::connect(path) else {
        return GrantStatus::Unreachable;
    };
    if stream.set_read_timeout(Some(REPLY_TIMEOUT)).is_err()
        || stream.write_all(b"STATUS\n").is_err()
    {
        return GrantStatus::Unreachable;
    }
    let mut reply = String::new();
    if BufReader::new(stream).read_line(&mut reply).is_err() {
        return GrantStatus::Unreachable;
    }
    parse_status(reply.trim_end())
}

/// Test seam: a malformed reply reports as unreachable rather than inventing
/// a grant.
#[doc(hidden)]
pub fn parse_status(reply: &str) -> GrantStatus {
    if reply == "NONE" {
        return GrantStatus::None;
    }
    let Some(rest) = reply.strip_prefix("LIVE ") else {
        return GrantStatus::Unreachable;
    };
    let parsed = rest
        .split_once(' ')
        .and_then(|(port, secs)| Some((port.parse().ok()?, secs.parse().ok()?)));
    match parsed {
        Some((port, remaining_secs)) => GrantStatus::Live {
            port,
            remaining_secs,
        },
        None => GrantStatus::Unreachable,
    }
}
