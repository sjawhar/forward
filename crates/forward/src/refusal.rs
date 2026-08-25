use std::io::{Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::Duration;

/// How many nonblocking scratch reads a refusal spends draining the client's
/// pending bytes after it has sent the response and FIN. This gives a legitimate
/// request burst time to arrive before close() decides whether to send RST, so
/// the peer can read the refusal. The cap exists because a peer that never stops
/// writing must not pin this handler — and its ConnectionPermit — forever; past
/// the budget the flooder may lose the refusal to an RST, which costs nothing.
const REFUSAL_DRAIN_READS: usize = 32;
/// A peer that will not receive its small refusal must not hold a handler
/// forever waiting for the send buffer to become writable.
const REFUSAL_WRITE_TIMEOUT: Duration = Duration::from_secs(1);

/// Send a refusal and FIN, then drain at most one legitimate request burst.
pub(crate) fn refuse(stream: &mut TcpStream, response: &[u8]) {
    if stream.set_nonblocking(false).is_ok()
        && stream
            .set_write_timeout(Some(REFUSAL_WRITE_TIMEOUT))
            .is_ok()
    {
        let _ = stream.write_all(response);
    }
    let _ = stream.shutdown(Shutdown::Write);
    if stream.set_nonblocking(true).is_ok() {
        let mut pending = [0_u8; 512];
        for _ in 0..REFUSAL_DRAIN_READS {
            if !matches!(stream.read(&mut pending), Ok(count) if count > 0) {
                break;
            }
        }
    }
}
