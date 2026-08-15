use std::io::{BufRead as _, BufReader, Read as _};
use std::net::TcpStream;
use std::time::{Duration, Instant};
use url::Url;

const MAX_URL_BYTES: usize = 8_192;
const READ_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn read_url(stream: &TcpStream) -> Option<Url> {
    let line = String::from_utf8(read_line(stream)?)
        .map_err(|error| {
            eprintln!("forward: invalid daemon URL bytes: {error}");
        })
        .ok()?;
    let url = Url::parse(line.trim())
        .map_err(|error| {
            eprintln!("forward: invalid daemon URL {:?}: {error}", line.trim());
        })
        .ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        eprintln!("forward: unsupported URL scheme {:?}: {url}", url.scheme());
        return None;
    }
    Some(url)
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
