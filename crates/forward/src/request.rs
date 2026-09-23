use std::io::{BufRead as _, BufReader, Read as _};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use url::Url;

const MAX_URL_BYTES: usize = 8_192;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// One request on the URL channel.
#[derive(Debug)]
pub(crate) enum Request {
    /// Open, or hand over, a URL; serving any loopback port it names.
    Open(Url),
    /// Serve laptop `localhost:<port>` for `secs` without opening anything.
    Hold { port: u16, secs: u64 },
}

pub(crate) fn read_request(stream: &TcpStream) -> Option<Request> {
    let line = String::from_utf8(read_line(stream)?)
        .map_err(|error| {
            eprintln!("forward: invalid daemon URL bytes: {error}");
        })
        .ok()?;
    let line = line.trim();
    if let Some(hold) = line.strip_prefix("HOLD ") {
        let hold = parse_hold(hold);
        if hold.is_none() {
            eprintln!("forward: malformed hold request {line:?}");
        }
        return hold;
    }
    let url = Url::parse(line)
        .map_err(|error| {
            eprintln!("forward: invalid daemon URL {line:?}: {error}");
        })
        .ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        eprintln!("forward: unsupported URL scheme {:?}: {url}", url.scheme());
        return None;
    }
    Some(Request::Open(url))
}

/// `<port> <secs>`, each decimal digits only.
fn parse_hold(fields: &str) -> Option<Request> {
    let digits = |field: &str| !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_digit());
    let (port, secs) = fields.split_once(' ')?;
    if !digits(port) || !digits(secs) {
        return None;
    }
    Some(Request::Hold {
        port: port.parse().ok()?,
        secs: secs.parse().ok()?,
    })
}

fn read_line(stream: &TcpStream) -> Option<Vec<u8>> {
    let mut reader = BufReader::new(stream);
    let mut bytes = Vec::new();
    let started = Instant::now();

    while bytes.len() < MAX_URL_BYTES {
        let elapsed = started.elapsed();
        if elapsed >= READ_TIMEOUT {
            eprintln!("forward: no newline before deadline");
            return None;
        }
        if let Err(error) = reader
            .get_ref()
            .set_read_timeout(Some(READ_TIMEOUT - elapsed))
        {
            eprintln!("forward: failed to set daemon read timeout: {error}");
            return None;
        }

        let available = match reader.fill_buf() {
            Ok([]) => {
                if !bytes.is_empty() {
                    eprintln!("forward: no newline before end of stream");
                }
                return None;
            }
            Ok(buffer) => buffer.len(),
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                eprintln!("forward: no newline before deadline");
                return None;
            }
            Err(error) => {
                eprintln!("forward: failed to read daemon URL: {error}");
                return None;
            }
        };
        let limit = (MAX_URL_BYTES - bytes.len()).min(available);
        let mut bounded = reader.by_ref().take(limit as u64);
        match bounded.read_until(b'\n', &mut bytes) {
            Ok(_) if bytes.ends_with(b"\n") => break,
            Ok(_) => {}
            // TimedOut and WouldBlock are unreachable: the Take limit is clamped to available
            // buffered data, so read_until never issues a syscall and cannot block.
            Err(error) => {
                eprintln!("forward: failed to read daemon URL: {error}");
                return None;
            }
        }
    }

    if bytes.ends_with(b"\n") {
        Some(bytes)
    } else {
        eprintln!("forward: URL line exceeded 8192 bytes");
        None
    }
}
