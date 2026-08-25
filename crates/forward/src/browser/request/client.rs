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

/// Ask the local daemon for a grant. Returns the bound loopback port.
pub fn request(path: &Path, ttl_secs: u64, token: &[u8]) -> Option<u16> {
    let mut stream = UnixStream::connect(path).ok()?;
    stream.set_read_timeout(Some(REPLY_TIMEOUT)).ok()?;
    stream.write_all(b"GRANT ").ok()?;
    stream.write_all(ttl_secs.to_string().as_bytes()).ok()?;
    stream.write_all(b" ").ok()?;
    stream.write_all(token).ok()?;
    stream.write_all(b"\n").ok()?;
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).ok()?;
    reply.trim_end().parse().ok()
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
