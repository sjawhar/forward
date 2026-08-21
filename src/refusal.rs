use std::io::{Read, Write};
use std::net::TcpStream;

/// How many nonblocking scratch reads a refusal spends draining the client's
/// pending bytes before writing the refusal and closing regardless. Draining
/// empties the receive queue so close() sends FIN rather than RST and the
/// refusal text survives to the peer — every legitimate client (a doctor
/// probe, a misconfigured Puppeteer) sends one burst far smaller than this
/// budget, so it still gets an empty queue and a readable refusal. The cap
/// exists because a peer that never stops writing must not pin this handler
/// — and its ConnectionPermit — forever; past the budget the flooder may lose
/// the refusal to an RST, which costs nothing.
const REFUSAL_DRAIN_READS: usize = 32;

/// Drain at most one legitimate request burst, then send a refusal response.
pub(crate) fn refuse(stream: &mut TcpStream, response: &[u8]) {
    let _ = stream.set_nonblocking(true);
    let mut pending = [0_u8; 512];
    for _ in 0..REFUSAL_DRAIN_READS {
        if !matches!(stream.read(&mut pending), Ok(count) if count > 0) {
            break;
        }
    }
    let _ = stream.set_nonblocking(false);
    let _ = stream.write_all(response);
}
