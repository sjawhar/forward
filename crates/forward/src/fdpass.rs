//! Handing one connected socket from one forward process to another.
//!
//! A file descriptor crosses a network namespace; an address does not. Two
//! paths need that: the bridge's port holders, which dial their own loopback
//! for the laptop, and the browser grant's relay, which accepts CDP clients in
//! the caller's namespace and hands each one to `forward serve`. Both send
//! exactly one message byte carrying at most one descriptor, so the framing
//! and the type check live here once rather than in each.

use std::io::{IoSlice, IoSliceMut};
use std::net::{SocketAddr, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;

use nix::errno::Errno;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockType, getsockopt, recvmsg, sendmsg, sockopt,
};

/// Send one message byte with `socket` attached by `SCM_RIGHTS`.
pub(crate) fn send(
    control: &UnixStream,
    message: u8,
    socket: &impl AsRawFd,
) -> std::io::Result<()> {
    let descriptors = [socket.as_raw_fd()];
    loop {
        match sendmsg::<()>(
            control.as_raw_fd(),
            &[IoSlice::new(&[message])],
            &[ControlMessage::ScmRights(&descriptors)],
            MsgFlags::empty(),
            None,
        ) {
            Ok(1) => return Ok(()),
            Ok(_) => return Err(std::io::ErrorKind::WriteZero.into()),
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(error.into()),
        }
    }
}

/// Read one message byte, and the socket it carried if any.
pub(crate) fn receive(control: &UnixStream) -> std::io::Result<(u8, Option<OwnedFd>)> {
    let mut reply = [0_u8; 1];
    let mut space = nix::cmsg_space!(RawFd);
    let (bytes, truncated, descriptor) = {
        let mut iov = [IoSliceMut::new(&mut reply)];
        let message = loop {
            match recvmsg::<()>(
                control.as_raw_fd(),
                &mut iov,
                Some(&mut space),
                MsgFlags::MSG_CMSG_CLOEXEC,
            ) {
                Ok(message) => break message,
                Err(Errno::EINTR) => continue,
                Err(error) => return Err(error.into()),
            }
        };
        let mut descriptor: Option<OwnedFd> = None;
        for cmsg in message.cmsgs()? {
            if let ControlMessageOwned::ScmRights(received) = cmsg {
                for raw in received {
                    // SAFETY: SCM_RIGHTS installed `raw` in this process for
                    // this message alone, so nothing else owns it; the
                    // `OwnedFd` takes its single close obligation.
                    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
                    // Anything past the first descriptor is closed here, unused.
                    if descriptor.is_none() {
                        descriptor = Some(owned);
                    }
                }
            }
        }
        (
            message.bytes,
            message.flags.contains(MsgFlags::MSG_CTRUNC),
            descriptor,
        )
    };
    if bytes == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    if truncated {
        return Err(std::io::Error::other("the attached socket was truncated"));
    }
    let [reply] = reply;
    Ok((reply, descriptor))
}

/// Accept only a connected TCP stream, whatever the sender claims it sent.
///
/// The receiver relays bytes over whatever it is handed, so a descriptor of
/// another type or family — a unix socket, a datagram socket, a pipe, a plain
/// file — must never be piped as if it were the client it stands in for.
/// `SO_TYPE` rejects every non-stream socket, and `getpeername` is the family
/// check: it fails for every address family that is neither INET nor INET6,
/// and for a stream socket that is not connected at all. The peer address is
/// returned with the stream because it survives the trip across a network
/// namespace and is the only thing the receiver can still check about origin.
pub(crate) fn connected_stream(socket: OwnedFd) -> Result<(TcpStream, SocketAddr), String> {
    match getsockopt(&socket, sockopt::SockType) {
        Ok(SockType::Stream) => {}
        Ok(other) => return Err(format!("sent a {other:?} socket, not a stream")),
        Err(error) => return Err(format!("sent a descriptor that is not a socket: {error}")),
    }
    let stream = TcpStream::from(socket);
    match stream.peer_addr() {
        Ok(peer) => Ok((stream, peer)),
        Err(error) => Err(format!(
            "sent a socket that is not a connected TCP socket: {error}"
        )),
    }
}
