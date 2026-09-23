use std::io::{IoSlice, IoSliceMut, Write as _};
use std::net::TcpStream;
use std::os::fd::{AsRawFd as _, FromRawFd as _, OwnedFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::socket::{
    ControlMessage, ControlMessageOwned, MsgFlags, SockType, getsockopt, recv, recvmsg, sendmsg,
    sockopt,
};
use parking_lot::Mutex;

/// The bridge's request to a holder for one connection.
pub(super) const DIAL: &[u8; 5] = b"DIAL\n";
/// The bridge's acknowledgement that a port is now held.
pub(super) const HELD: &[u8; 3] = b"ok\n";
/// The bridge's refusal: another live process already holds the port.
pub(super) const BUSY: &[u8; 5] = b"busy\n";
/// The bridge's refusal: the port is one it must never dial. An older bridge
/// closes without any answer instead, which is how the two are told apart.
pub(super) const UNSAFE: &[u8; 7] = b"unsafe\n";
/// A holder's answer: connected, with the socket attached.
const DIALED: u8 = b'+';
/// A holder's answer: nothing accepted the connection where it runs.
const UNREACHABLE: u8 = b'-';
/// How long a holder has to take a request and answer it.
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// A local process keeping one bridge port reachable, and dialling it itself.
///
/// `forward serve` runs in the host's network namespace, so its `127.0.0.1:N`
/// is the wrong loopback for a server inside an agent box. A holder connects to
/// the arming socket from wherever it runs and, for each bridge connection,
/// connects to its own loopback and hands the connected socket back over that
/// unix socket. A file descriptor crosses a network namespace; an address does
/// not. The hold lasts exactly as long as the holder's connection.
pub(super) struct Holder {
    control: Mutex<UnixStream>,
}

/// What asking a holder for a connection produced.
pub(super) enum Dial {
    /// A connection to the holder's loopback port.
    Connected(TcpStream),
    /// The holder is alive, but nothing accepted on its loopback port.
    Unreachable,
    /// The holder is gone or broke protocol, so its port must be freed.
    Gone(String),
}

impl Holder {
    pub(super) fn new(control: UnixStream) -> Self {
        Self {
            control: Mutex::new(control),
        }
    }

    /// Tell the holder its port is held. Written under the lock every dial
    /// takes, so the acknowledgement always precedes the first request.
    pub(super) fn acknowledge(&self) -> bool {
        let mut control = self.control.lock();
        control.set_read_timeout(None).is_ok()
            && control.set_write_timeout(Some(DIAL_TIMEOUT)).is_ok()
            && control.write_all(HELD).is_ok()
    }

    /// Whether the holder still has its end of the connection open.
    ///
    /// A holder never sends unprompted, so a readable connection at rest is an
    /// end of stream or a protocol breach, and either ends the hold.
    pub(super) fn is_alive(&self) -> bool {
        let control = self.control.lock();
        loop {
            let peeked = recv(
                control.as_raw_fd(),
                &mut [0_u8; 1],
                MsgFlags::MSG_PEEK | MsgFlags::MSG_DONTWAIT,
            );
            match peeked {
                Err(Errno::EINTR) => continue,
                Err(Errno::EAGAIN) => return true,
                Ok(_) | Err(_) => return false,
            }
        }
    }

    /// Ask the holder for one connection to its loopback `port`.
    pub(super) fn dial(&self, port: u16) -> Dial {
        let mut control = self.control.lock();
        let bounded = control
            .set_read_timeout(Some(DIAL_TIMEOUT))
            .and_then(|()| control.set_write_timeout(Some(DIAL_TIMEOUT)));
        if let Err(error) = bounded {
            return Dial::Gone(format!("could not be given a deadline: {error}"));
        }
        if let Err(error) = control.write_all(DIAL) {
            return Dial::Gone(format!("did not take the request: {error}"));
        }
        match receive(&control) {
            Ok((DIALED, Some(socket))) => {
                stream_from(socket, port).map_or_else(Dial::Gone, Dial::Connected)
            }
            Ok((DIALED, None)) => Dial::Gone("answered + without an attached socket".to_owned()),
            Ok((UNREACHABLE, None)) => Dial::Unreachable,
            Ok((UNREACHABLE, Some(_))) => {
                Dial::Gone("answered - with an unexpected socket".to_owned())
            }
            Ok((reply, _)) => {
                Dial::Gone(format!("answered {reply:#04x}, which is not a dial reply"))
            }
            Err(error) => Dial::Gone(format!("did not answer: {error}")),
        }
    }
}

/// Answer one dial with a connected socket, which the bridge then relays.
pub(super) fn send_dialed(control: &UnixStream, socket: &TcpStream) -> std::io::Result<()> {
    let descriptors = [socket.as_raw_fd()];
    loop {
        match sendmsg::<()>(
            control.as_raw_fd(),
            &[IoSlice::new(&[DIALED])],
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

/// Answer one dial with "nothing is listening here".
pub(super) fn send_unreachable(mut control: &UnixStream) -> std::io::Result<()> {
    control.write_all(&[UNREACHABLE])
}

/// Read one holder reply: its byte, and the socket it carried if any.
fn receive(control: &UnixStream) -> std::io::Result<(u8, Option<OwnedFd>)> {
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

/// Accept only a TCP stream whose peer is loopback on the held `port`.
///
/// The bridge relays the remote peer over whatever it accepts here, so a
/// socket connected anywhere else (another port, the denylist's Docker API, a
/// unix socket) would let a holder of one allowed port expose an unrelated
/// endpoint. The peer address survives the trip across a network namespace.
fn stream_from(socket: OwnedFd, port: u16) -> Result<TcpStream, String> {
    match getsockopt(&socket, sockopt::SockType) {
        Ok(SockType::Stream) => {}
        Ok(other) => return Err(format!("sent a {other:?} socket, not a stream")),
        Err(error) => return Err(format!("sent a descriptor that is not a socket: {error}")),
    }
    let upstream = TcpStream::from(socket);
    match upstream.peer_addr() {
        Ok(peer) if peer.ip().is_loopback() && peer.port() == port => Ok(upstream),
        Ok(peer) => Err(format!(
            "sent a socket connected to {peer}, not loopback port {port}"
        )),
        Err(error) => Err(format!(
            "sent a socket that is not a connected TCP socket: {error}"
        )),
    }
}
