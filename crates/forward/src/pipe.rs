use std::io::{Read, Write, copy};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::thread;

/// A stream `bidirectional` can pipe: cloneable for the reverse direction and
/// half-closable so an EOF can propagate without dropping the other direction.
pub trait Duplex: Read + Write + Send + Sized {
    fn try_clone(&self) -> std::io::Result<Self>;
    fn shutdown(&self, how: Shutdown) -> std::io::Result<()>;
}

impl Duplex for TcpStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        Self::try_clone(self)
    }

    fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        Self::shutdown(self, how)
    }
}

impl Duplex for UnixStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        Self::try_clone(self)
    }

    fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
        Self::shutdown(self, how)
    }
}

/// Enable TCP keepalive tuned for the cross-machine channels: a dead peer
/// (slept laptop, dropped tailnet path) is detected in about two minutes
/// (60s idle + 6 probes x 10s) without imposing any idle timeout on
/// legitimately silent sessions, which a PC/SC client can hold for hours.
pub fn keepalive(stream: &TcpStream) -> std::io::Result<()> {
    use nix::sys::socket::sockopt::{KeepAlive, TcpKeepCount, TcpKeepIdle, TcpKeepInterval};

    nix::sys::socket::setsockopt(stream, KeepAlive, &true)?;
    nix::sys::socket::setsockopt(stream, TcpKeepIdle, &60)?;
    nix::sys::socket::setsockopt(stream, TcpKeepInterval, &10)?;
    nix::sys::socket::setsockopt(stream, TcpKeepCount, &6)?;
    Ok(())
}

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
pub fn bidirectional<L, R>(left: L, right: R) -> std::io::Result<()>
where
    L: Duplex + 'static,
    R: Duplex + 'static,
{
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
fn half<F: Duplex, T: Duplex>(mut from: F, mut to: T) -> std::io::Result<()> {
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
