//! The grant's CDP endpoint, served in the caller's own network namespace.
//!
//! `forward serve` runs in the host's network namespace, so a `127.0.0.1:N` it
//! binds is not the loopback an agent box can reach, and the host cannot read
//! a box process's `/proc/<pid>/fd` or find its connection in the host's
//! `/proc/net/tcp` — so the per-connection ownership check could never
//! attribute a box client even through a relay. Both therefore live here, in a
//! detached child of the `forward browser grant` CLI: it binds loopback where
//! the caller can reach it, and it reads the same `/proc` the client lives in.
//!
//! What stays in `forward serve` is everything the caller must never hold: the
//! receipt, its redemption, the relay token, and the connection to the laptop.
//! Each admitted socket is handed over by descriptor, and the grant ends for
//! both sides the moment the control channel between them closes.

use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::os::fd::{BorrowedFd, FromRawFd as _, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use nix::sys::socket::{
    AddressFamily, SockType, SockaddrLike as _, SockaddrStorage, getsockname, getsockopt, sockopt,
};

use crate::browser::grant::ProcessAnchor;
use crate::fdpass;
use crate::refusal::refuse;

mod spawn;

pub use spawn::{CONTROL_FD, LISTENER_FD, spawn};

/// The relay's only message to `forward serve`: one admitted CDP connection,
/// attached to this byte as a descriptor.
pub(crate) const CONNECTION: u8 = b'+';
/// What the endpoint answers a connection it cannot attribute to the grant.
/// `doctor` reads it as proof that a relay is serving this grant here: nothing
/// else on this loopback speaks it.
pub(crate) const SESSION_REFUSAL: &[u8] = b"REFUSED SESSION\n";
/// Waiting after a failed accept avoids a tight EMFILE error loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Resolve a loopback connection to its owning process. Injectable so tests can
/// exercise admission without depending on kernel TCP-table timing.
pub type Resolver = Arc<dyn Fn(SocketAddrV4, SocketAddrV4) -> Option<u32> + Send + Sync>;

#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error(
        "forward: descriptor {fd} is not the socket `forward browser grant` passes here; \
         `browser relay` is started by the grant, not by hand"
    )]
    Inherited { fd: RawFd },
}

/// Serve the grant whose listener and control channel this process inherited.
pub fn run(anchor: ProcessAnchor) -> Result<(), RelayError> {
    let (listener, control) = inherited()?;
    serve(
        listener,
        control,
        anchor,
        Arc::new(crate::browser::peer::pid_for_connection),
    );
    Ok(())
}

/// Accept CDP clients inside the grant's process anchor and hand each one to
/// `forward serve`, until the control channel says the grant is over.
pub fn serve(
    listener: TcpListener,
    control: UnixStream,
    anchor: ProcessAnchor,
    resolver: Resolver,
) {
    let Ok(port) = listener.local_addr().map(|address| address.port()) else {
        eprintln!("forward: browser relay could not determine its listener port");
        return;
    };
    let ended = Arc::new(AtomicBool::new(false));
    let Ok(watched) = control.try_clone() else {
        eprintln!("forward: browser relay could not watch its control channel");
        return;
    };
    watch(watched, Arc::clone(&ended), port);

    for connection in listener.incoming() {
        // `watch` sets this before it makes its wake connection, so this loop
        // can never read that connection as a client of the grant it retires.
        if ended.load(Ordering::SeqCst) {
            return;
        }
        match connection {
            Ok(mut stream) => {
                if !admits(&resolver, &stream, anchor) {
                    eprintln!(
                        "forward: browser relay refused a connection outside its process anchor"
                    );
                    refuse(&mut stream, SESSION_REFUSAL);
                    continue;
                }
                if let Err(error) = fdpass::send(&control, CONNECTION, &stream) {
                    eprintln!("forward: browser relay lost its control channel: {error}");
                    return;
                }
            }
            Err(error) => {
                eprintln!("forward: browser relay accept failed: {error}");
                thread::sleep(ACCEPT_ERROR_BACKOFF);
            }
        }
    }
}

/// End the relay when the control channel does.
///
/// `forward serve` never sends on it after `OK`, so anything readable is an
/// end of stream, an error, or a protocol breach — each of which ends the
/// grant. The accept loop is woken by a connection to the listener's own port,
/// which this process can always reach: it is the namespace the port is in.
fn watch(control: UnixStream, ended: Arc<AtomicBool>, port: u16) {
    drop(thread::spawn(move || {
        let mut byte = [0_u8; 1];
        loop {
            match std::io::Read::read(&mut &control, &mut byte) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                _ => break,
            }
        }
        ended.store(true, Ordering::SeqCst);
        drop(TcpStream::connect(("127.0.0.1", port)));
    }));
}

/// Test seam: hand one connection to `forward serve` the way the accept loop
/// above does, with no endpoint in front of it.
#[doc(hidden)]
pub fn hand_over(control: &UnixStream, socket: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    fdpass::send(control, CONNECTION, socket)
}

fn admits(resolver: &Resolver, stream: &TcpStream, anchor: ProcessAnchor) -> bool {
    let (Ok(SocketAddr::V4(peer)), Ok(SocketAddr::V4(local))) =
        (stream.peer_addr(), stream.local_addr())
    else {
        return false;
    };
    resolver(peer, local).is_some_and(|pid| anchor.contains(pid))
}

/// Take ownership of the two descriptors `spawn` placed in this process.
///
/// Each is checked for what it must be, not merely that it is a socket: fd 3
/// is a listening INET stream and fd 4 is a connected unix stream. Without
/// that, a hand-run `browser relay` with unrelated descriptors on 3 and 4
/// would get a misleading failure somewhere later instead of the message
/// below, which tells the reader the one thing that is wrong.
fn inherited() -> Result<(TcpListener, UnixStream), RelayError> {
    if !is_endpoint_listener(LISTENER_FD) {
        return Err(RelayError::Inherited { fd: LISTENER_FD });
    }
    if !is_control_channel(CONTROL_FD) {
        return Err(RelayError::Inherited { fd: CONTROL_FD });
    }
    // SAFETY: `spawn` placed the grant's listener and control channel on
    // exactly these descriptors in the child it exec'd, nothing else in this
    // process has taken ownership of either, and both were just verified.
    let listener = unsafe { TcpListener::from_raw_fd(LISTENER_FD) };
    // SAFETY: as above, for the control channel's descriptor.
    let control = unsafe { UnixStream::from_raw_fd(CONTROL_FD) };
    Ok((listener, control))
}

fn is_endpoint_listener(fd: RawFd) -> bool {
    // SAFETY: borrowed for these checks alone, and never closed through the
    // borrow; ownership is taken by the caller only once they have passed.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    matches!(
        getsockopt(&borrowed, sockopt::SockType),
        Ok(SockType::Stream)
    ) && matches!(getsockopt(&borrowed, sockopt::AcceptConn), Ok(true))
        && matches!(family(fd), Some(AddressFamily::Inet | AddressFamily::Inet6))
}

fn is_control_channel(fd: RawFd) -> bool {
    // SAFETY: as in `is_endpoint_listener`.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
    matches!(
        getsockopt(&borrowed, sockopt::SockType),
        Ok(SockType::Stream)
    ) && family(fd) == Some(AddressFamily::Unix)
}

fn family(fd: RawFd) -> Option<AddressFamily> {
    getsockname::<SockaddrStorage>(fd).ok()?.family()
}

#[cfg(test)]
mod tests;
