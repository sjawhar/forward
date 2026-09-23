use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use forward::bridge::{Armed, HoldError, hold, serve_arming};

use super::{assert_refused, read_reply, spawn_bridge, spawn_echo_upstream};

/// A bridge and its arming socket sharing one armed set, as `forward serve` runs them.
fn spawn_bridge_with_arming(dir: &tempfile::TempDir) -> (u16, PathBuf) {
    let armed = Armed::new(forward::config::Config::default_values_for_test());
    let path = dir.path().join("forward-arm.sock");
    serve_arming(armed.clone(), path.clone());
    for _ in 0..100 {
        if path.exists() {
            return (spawn_bridge(armed), path);
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("arming socket never appeared at {}", path.display());
}

fn connect_through(bridge_port: u16, port: u16) -> TcpStream {
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .unwrap();
    client
}

#[test]
fn a_held_port_never_falls_back_to_this_hosts_loopback() {
    // Given: a server on this host's own loopback at P — the service a box's
    // holder must never be swapped for — armed by a `forward open`, then held,
    // then armed again while the hold is live.
    let dir = tempfile::tempdir().unwrap();
    let (bridge_port, path) = spawn_bridge_with_arming(&dir);
    let port = spawn_echo_upstream();
    assert!(forward::bridge::arm(&path, &[port], 300));
    let held = hold(&path, port).unwrap();
    assert!(forward::bridge::arm(&path, &[port], 300));

    // When: the holder dies.
    drop(held);

    // Then: the port is unreachable, rather than routed to the host's server,
    // both for the connection that discovers the death and for every one after.
    let mut discovering = connect_through(bridge_port, port);
    discovering.write_all(b"ping").unwrap();
    assert_refused(&mut discovering, "REFUSED\n");
    let mut later = connect_through(bridge_port, port);
    later.write_all(b"ping").unwrap();
    assert_refused(&mut later, "REFUSED UNARMED\n");
}

#[test]
fn a_held_port_is_dialled_by_its_holder_with_nothing_armed() {
    // Given: a loopback-only upstream that nothing armed, held by a holder.
    let dir = tempfile::tempdir().unwrap();
    let (bridge_port, path) = spawn_bridge_with_arming(&dir);
    let upstream_port = spawn_echo_upstream();
    let held = hold(&path, upstream_port).unwrap();
    std::thread::spawn(move || held.serve());

    // When: a laptop connection asks the bridge for that port.
    let mut client = connect_through(bridge_port, upstream_port);
    client.write_all(b"ping").unwrap();

    // Then: the only route there is the holder's own dial, and bytes arrive.
    assert_eq!(read_reply(&mut client), "pong");
}

#[test]
fn a_live_hold_is_never_taken_over_and_a_dead_one_is_replaced() {
    // Given: one process holding a port.
    let dir = tempfile::tempdir().unwrap();
    let (_, path) = spawn_bridge_with_arming(&dir);
    let port = spawn_echo_upstream();
    let first = hold(&path, port).unwrap();

    // When/Then: a second process is refused while the first is alive...
    assert!(matches!(hold(&path, port), Err(HoldError::Busy { port: busy }) if busy == port));

    // ...and takes the port once the first has gone, with no wait for a lease.
    drop(first);
    assert!(hold(&path, port).is_ok());
}

#[test]
fn a_bridge_that_predates_holds_is_reported_as_needing_an_upgrade() {
    // Given: an arming socket like a serve from before holds, which reads the
    // request line, cannot parse `HOLD`, and closes without answering.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("forward-arm.sock");
    let old_bridge = std::os::unix::net::UnixListener::bind(&path).unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = old_bridge.accept().unwrap();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).unwrap_or(0) == 1 && byte != *b"\n" {}
    });

    // When/Then: the hold fails with the upgrade instruction, not as an unsafe
    // port, which would send the user looking for a problem with the port.
    assert!(matches!(
        hold(&path, 5_173),
        Err(HoldError::Unanswered { .. })
    ));
}

#[test]
fn a_holder_that_breaks_protocol_is_released_after_refusing_that_connection() {
    // Given: a holder accepted by the arming socket but not speaking the dial reply protocol.
    let dir = tempfile::tempdir().unwrap();
    let (bridge_port, path) = spawn_bridge_with_arming(&dir);
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = reservation.local_addr().unwrap().port();
    let mut holder = UnixStream::connect(&path).unwrap();
    holder
        .write_all(format!("HOLD {port}\n").as_bytes())
        .unwrap();
    let mut acknowledgement = [0_u8; 3];
    holder.read_exact(&mut acknowledgement).unwrap();
    assert_eq!(&acknowledgement, b"ok\n");

    // When: the bridge asks it to connect and it answers with garbage.
    let mut client = connect_through(bridge_port, port);
    let mut request = [0_u8; 5];
    holder.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"DIAL\n");
    holder.write_all(b"?").unwrap();

    // Then: that browser connection is refused, and the broken holder no longer owns the port.
    assert_refused(&mut client, "REFUSED\n");
    assert!(hold(&path, port).is_ok());
}

#[test]
fn a_socket_connected_anywhere_but_the_held_port_is_refused() {
    // Given: a holder of port P, and another loopback server on Q that would
    // answer — a stand-in for any endpoint a holder is not holding.
    let dir = tempfile::tempdir().unwrap();
    let (bridge_port, path) = spawn_bridge_with_arming(&dir);
    let reservation = TcpListener::bind("127.0.0.1:0").unwrap();
    let held_port = reservation.local_addr().unwrap().port();
    let elsewhere = spawn_echo_upstream();
    let mut holder = UnixStream::connect(&path).unwrap();
    holder
        .write_all(format!("HOLD {held_port}\n").as_bytes())
        .unwrap();
    let mut acknowledgement = [0_u8; 3];
    holder.read_exact(&mut acknowledgement).unwrap();
    assert_eq!(&acknowledgement, b"ok\n");

    // When: asked to dial P, the holder hands over a socket connected to Q.
    let mut client = connect_through(bridge_port, held_port);
    let mut request = [0_u8; 5];
    holder.read_exact(&mut request).unwrap();
    assert_eq!(&request, b"DIAL\n");
    let wrong = TcpStream::connect(("127.0.0.1", elsewhere)).unwrap();
    let descriptors = [std::os::fd::AsRawFd::as_raw_fd(&wrong)];
    nix::sys::socket::sendmsg::<()>(
        std::os::fd::AsRawFd::as_raw_fd(&holder),
        &[std::io::IoSlice::new(b"+")],
        &[nix::sys::socket::ControlMessage::ScmRights(&descriptors)],
        nix::sys::socket::MsgFlags::empty(),
        None,
    )
    .unwrap();

    // Then: the laptop's connection is refused rather than relayed to Q.
    client.write_all(b"ping").unwrap();
    assert_refused(&mut client, "REFUSED\n");
}

#[test]
fn a_hold_on_a_port_the_bridge_must_never_dial_is_refused() {
    // Given: a bridge; privileged ports and Docker's API are never dialled.
    let dir = tempfile::tempdir().unwrap();
    let (_, path) = spawn_bridge_with_arming(&dir);

    // When/Then: holding one is refused outright, not accepted and ignored.
    for port in [22, 2_375] {
        assert!(matches!(hold(&path, port), Err(HoldError::Refused { .. })));
    }
}

#[test]
fn nothing_listening_refuses_the_connection_and_keeps_the_hold() {
    // Given: a held port with no server behind it yet.
    let dir = tempfile::tempdir().unwrap();
    let (bridge_port, path) = spawn_bridge_with_arming(&dir);
    let port = {
        let probe = TcpListener::bind("127.0.0.1:0").unwrap();
        probe.local_addr().unwrap().port()
    };
    let held = hold(&path, port).unwrap();
    std::thread::spawn(move || held.serve());

    // When: a laptop connection arrives before the server is up.
    let mut early = connect_through(bridge_port, port);

    // Then: it is refused promptly rather than hung...
    assert_refused(&mut early, "REFUSED\n");

    // ...and the hold survives, so the server starting later is reachable.
    let server = TcpListener::bind(("127.0.0.1", port)).unwrap();
    std::thread::spawn(move || {
        let (mut stream, _) = server.accept().unwrap();
        stream.write_all(b"up").unwrap();
    });
    let mut later = connect_through(bridge_port, port);
    assert_eq!(read_reply(&mut later), "up");
}
