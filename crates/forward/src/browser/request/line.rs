use std::io::Read as _;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

const MAX_REQUEST_LINE: usize = 128;

pub(super) fn read_line(stream: &UnixStream, timeout: Duration) -> Option<Zeroizing<Vec<u8>>> {
    let deadline = Instant::now().checked_add(timeout)?;
    let mut line = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_LINE));
    let mut source = stream.try_clone().ok()?;
    let mut byte = Zeroizing::new([0_u8; 1]);
    while line.len() < MAX_REQUEST_LINE {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || source.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        match source.read(&mut *byte) {
            Ok(0) => break,
            Ok(1) => {
                let [received] = *byte;
                if received == b'\n' {
                    break;
                }
                line.push(received);
            }
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
    while line.last().is_some_and(|byte| *byte == b'\r') {
        line.pop();
    }
    Some(line)
}

#[doc(hidden)]
pub fn read_line_with_timeout(
    stream: &UnixStream,
    timeout: Duration,
) -> Option<Zeroizing<Vec<u8>>> {
    read_line(stream, timeout)
}
