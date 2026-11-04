use std::io::Read as _;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::MAX_REQUEST_LINE;

/// Read the bearer without buffering payload bytes or leaving unzeroized copies.
pub(super) fn read_relay_token(
    stream: &mut TcpStream,
    timeout: Duration,
) -> Option<Zeroizing<Vec<u8>>> {
    const PREFIX: &[u8] = b"RELAY ";
    let deadline = Instant::now().checked_add(timeout)?;
    let mut token = Zeroizing::new(Vec::with_capacity(MAX_REQUEST_LINE - PREFIX.len()));
    let mut byte = Zeroizing::new([0_u8; 1]);
    for position in 0..MAX_REQUEST_LINE {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || stream.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        match stream.read(&mut *byte) {
            Ok(1) => {}
            Ok(_) => return None,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
        let received = *byte.first()?;
        if let Some(expected) = PREFIX.get(position) {
            (received == *expected).then_some(())?;
        } else if received == b'\n' {
            return Some(token);
        } else {
            token.push(received);
        }
    }
    None
}
