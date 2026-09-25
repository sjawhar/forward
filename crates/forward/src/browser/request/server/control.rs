//! One grant's control channel: the connections its relay hands back.
//!
//! The channel is authenticated by being the connection on which the receipt
//! was redeemed, so no socket arriving on it has to be identified again. What
//! is still checked is what the descriptor *is*: the relay is trusted to have
//! admitted the right client, not to have sent a socket of the right kind.

use std::io::Write as _;
use std::net::{SocketAddr, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

use crate::bridge::limit::ConnectionLimit;
use crate::browser::grant::Grants;
use crate::browser::relay;
use crate::fdpass;
use crate::pipe::bidirectional;
use crate::refusal::refuse;

/// The maximum idle read or blocked-write interval for a proxied CDP session.
const PIPE_IDLE_TIMEOUT: Duration = Duration::from_secs(15 * 60);
const GENERIC_REFUSAL: &[u8] = b"REFUSED\n";
const BUSY_REFUSAL: &[u8] = b"REFUSED BUSY\n";
const UNGRANTED_REFUSAL: &[u8] = b"REFUSED UNGRANTED\n";

/// Serve grant `id` until its control channel ends, then expire it.
#[doc(hidden)]
pub fn serve(grants: Grants, id: u64, upstream: SocketAddr, control: UnixStream) {
    // The request deadlines belonged to the request; a control channel is idle
    // for as long as the session is, and a deadline here would read as an end.
    if control.set_read_timeout(None).is_err() || control.set_write_timeout(None).is_err() {
        eprintln!("forward: grant {id} control channel could not be made unbounded");
        grants.expire(id);
        return;
    }
    let limit = ConnectionLimit::standard();
    loop {
        match fdpass::receive(&control) {
            Ok((relay::CONNECTION, Some(socket))) => {
                let Some(permit) = limit.acquire() else {
                    busy(id, socket);
                    continue;
                };
                let grants = grants.clone();
                drop(thread::spawn(move || {
                    let _permit = permit;
                    relay_one(&grants, id, upstream, socket);
                }));
            }
            Ok((relay::CONNECTION, None)) => {
                eprintln!("forward: grant {id} relay sent a connection with no socket");
                break;
            }
            Ok((message, _)) => {
                eprintln!("forward: grant {id} relay sent {message:#04x}, which is not a message");
                break;
            }
            Err(error) => {
                eprintln!("forward: grant {id} control channel ended: {error}");
                break;
            }
        }
    }
    grants.expire(id);
}

/// Relay one admitted CDP connection to the laptop under the grant's token.
fn relay_one(grants: &Grants, id: u64, upstream: SocketAddr, socket: OwnedFd) {
    let (mut stream, peer) = match fdpass::connected_stream(socket) {
        Ok(accepted) => accepted,
        Err(reason) => {
            eprintln!("forward: grant {id} relay {reason}");
            return;
        }
    };
    if !peer.ip().is_loopback() {
        eprintln!("forward: grant {id} relay sent a socket connected to {peer}, not loopback");
        return;
    }
    let Some(grant) = grants.live(id) else {
        refuse(&mut stream, UNGRANTED_REFUSAL);
        return;
    };
    let Ok(mut laptop) = TcpStream::connect(upstream) else {
        refuse(&mut stream, GENERIC_REFUSAL);
        return;
    };
    if laptop
        .write_all(b"RELAY ")
        .and_then(|()| laptop.write_all(&grant.token))
        .and_then(|()| laptop.write_all(b"\n"))
        .is_err()
    {
        refuse(&mut stream, GENERIC_REFUSAL);
        return;
    }
    for socket in [&stream, &laptop] {
        if socket.set_read_timeout(Some(PIPE_IDLE_TIMEOUT)).is_err()
            || socket.set_write_timeout(Some(PIPE_IDLE_TIMEOUT)).is_err()
        {
            return;
        }
    }
    // Register before piping: from here, ending the grant ends this session,
    // whether the ending is `secrets lock`, TTL expiry, or anything later.
    // A registration failure refuses rather than serving an unseverable pipe.
    let Ok(_pipe) = grants.register_pipe(id, &stream, &laptop) else {
        refuse(&mut stream, UNGRANTED_REFUSAL);
        return;
    };
    if let Err(error) = bidirectional(stream, laptop) {
        eprintln!("forward: grant {id} session ended: {error}");
    }
}

/// Refuse a connection the concurrency cap has no room for, in the words the
/// client has always seen. Done on this thread on purpose: the refusal is
/// bounded by its own write deadline and drain budget, and spawning a thread
/// to say "too many threads" is how a cap stops being one.
fn busy(id: u64, socket: OwnedFd) {
    eprintln!("forward: grant {id} refused a connection: too many are already open");
    match fdpass::connected_stream(socket) {
        Ok((mut stream, _)) => refuse(&mut stream, BUSY_REFUSAL),
        Err(reason) => eprintln!("forward: grant {id} relay {reason}"),
    }
}
