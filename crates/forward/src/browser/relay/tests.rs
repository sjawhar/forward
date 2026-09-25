//! The endpoint's admission rule, and the cue that retires it.
//!
//! The end-to-end path — admitted socket, `RELAY <token>`, severance — is in
//! `tests/browser_grant.rs`, which drives a real `forward serve` control loop.

use std::io::{Read as _, Write as _};
use std::net::{SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::{Duration, Instant};

use super::{CONNECTION, ProcessAnchor, Resolver, serve};
use crate::fdpass;

fn endpoint() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

fn current_anchor() -> ProcessAnchor {
    let pid = std::process::id();
    ProcessAnchor::new(pid, crate::browser::peer::process_start(pid).unwrap())
}

fn resolver(pid: Option<u32>) -> Resolver {
    std::sync::Arc::new(move |_peer: SocketAddrV4, _local: SocketAddrV4| pid)
}

fn read_refusal(client: &mut TcpStream) -> Vec<u8> {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    reply
}

#[test]
fn a_peer_inside_the_anchor_is_handed_to_forward_serve() {
    // This fails if the relay answers CDP itself, or hands over anything but
    // the accepted socket: the payload below is read through the descriptor
    // that arrives on the control channel, not through any copy of it.
    let (listener, port) = endpoint();
    let (server, caller) = UnixStream::pair().unwrap();
    let anchored = std::process::id();
    thread::spawn(move || serve(listener, caller, current_anchor(), resolver(Some(anchored))));
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();
    let (message, socket) = fdpass::receive(&server).expect("the relay handed the socket over");

    assert_eq!(message, CONNECTION);
    let (mut handed, peer) = fdpass::connected_stream(socket.expect("a socket was attached"))
        .expect("the relay passed a connected TCP stream");
    assert!(peer.ip().is_loopback());
    let mut payload = [0_u8; 4];
    handed.read_exact(&mut payload).unwrap();
    assert_eq!(&payload, b"ping");
}

#[test]
fn a_peer_outside_the_anchor_is_refused_and_never_handed_over() {
    // The intentionally mismatched start time puts this client outside the
    // grant's process anchor. This fails if the owner check is dropped.
    let (listener, port) = endpoint();
    let (server, caller) = UnixStream::pair().unwrap();
    let anchor = current_anchor();
    let foreign = ProcessAnchor::new(anchor.pid, anchor.start + 1);
    thread::spawn(move || serve(listener, caller, foreign, resolver(Some(anchor.pid))));

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_eq!(read_refusal(&mut client), b"REFUSED SESSION\n");
    server
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    assert!(fdpass::receive(&server).is_err());
}

#[test]
fn an_unresolvable_peer_is_refused() {
    // This fails if a connection whose owner cannot be read is treated as
    // authorized -- the case a host-side check hits for every box client.
    let (listener, port) = endpoint();
    let (_server, caller) = UnixStream::pair().unwrap();
    thread::spawn(move || serve(listener, caller, current_anchor(), resolver(None)));

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_eq!(read_refusal(&mut client), b"REFUSED SESSION\n");
}

#[test]
fn closing_the_control_channel_closes_the_endpoint() {
    // The grant's every ending reaches the endpoint this way and no other.
    let (listener, port) = endpoint();
    let (server, caller) = UnixStream::pair().unwrap();
    let anchored = std::process::id();
    thread::spawn(move || serve(listener, caller, current_anchor(), resolver(Some(anchored))));
    // Prove the endpoint was serving before the channel closed, so a bind
    // that never worked cannot pass this test.
    drop(TcpStream::connect(("127.0.0.1", port)).unwrap());

    drop(server);

    let deadline = Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(Instant::now() < deadline, "the endpoint outlived its grant");
        thread::sleep(Duration::from_millis(10));
    }
}
