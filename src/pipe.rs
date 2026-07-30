use std::io::copy;
use std::net::{Shutdown, TcpStream};
use std::thread;

/// Copy bytes both ways until each direction reaches EOF.
///
/// On normal EOF a direction shuts down only the *destination's* write half.
/// Without that, an HTTP callback client that finished its request and is waiting
/// for a reply never gets one: the upstream is still blocked waiting for an EOF
/// that never arrives. This is the behaviour `ssh -L` provided for free, and it
/// is easy to lose.
///
/// A copy error is different. The sibling direction may be parked on a read that
/// will never complete because the other side is simply idle, so the failing
/// direction shuts down *both* sockets to wake it, and the error is returned
/// rather than swallowed. When both directions fail, the error from the
/// `left` -> `right` copy is the one reported.
pub fn bidirectional(left: TcpStream, right: TcpStream) -> std::io::Result<()> {
    let left_reverse = left.try_clone()?;
    let right_reverse = right.try_clone()?;
    let outbound = thread::spawn(move || half(left, right));
    let inbound = half(right_reverse, left_reverse);
    let outbound = match outbound.join() {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::other("pipe thread panicked")),
    };
    outbound.and(inbound)
}

/// Copy one direction, then leave both sockets in the state the other direction
/// needs: half-closed on EOF, fully shut down on error.
fn half(mut from: TcpStream, mut to: TcpStream) -> std::io::Result<()> {
    match copy(&mut from, &mut to) {
        Ok(_) => {
            let _ = to.shutdown(Shutdown::Write);
            Ok(())
        }
        Err(error) => {
            let _ = from.shutdown(Shutdown::Both);
            let _ = to.shutdown(Shutdown::Both);
            Err(error)
        }
    }
}
