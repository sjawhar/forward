use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use forward::browser::grant::{Grant, Grants, ProcessAnchor};
use forward::browser::peer::process_start;
use forward::browser::proxy::{self, Resolver};

const TOKEN: &[u8] = b"correct-horse";

fn current_anchor() -> ProcessAnchor {
    let pid = std::process::id();
    ProcessAnchor::new(pid, process_start(pid).unwrap())
}

fn grant(anchor: ProcessAnchor, deadline: Instant) -> Grant {
    Grant {
        session: "session-a".to_owned(),
        anchor,
        token: TOKEN.to_vec(),
        deadline,
    }
}

fn resolver(pid: Option<u32>) -> Resolver {
    Arc::new(move |_peer: SocketAddrV4, _local: SocketAddrV4| pid)
}

fn listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// An upstream that asserts the header and payload before returning a response.
fn spawn_relay_upstream(expected: &'static [u8]) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            line.push(byte[0]);
        }
        let header = b"RELAY correct-horse";
        assert_eq!(line.len(), header.len(), "unexpected relay header length");
        assert!(
            line.iter()
                .zip(header)
                .all(|(actual, expected)| actual == expected),
            "unexpected relay header"
        );
        let mut payload = vec![0; expected.len()];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(payload, expected);
        stream.write_all(b"pong").unwrap();
    });
    (address, task)
}

fn assert_refused(client: &mut TcpStream, expected: &[u8]) {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, expected);
}
fn unconnected_upstream() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn assert_not_dialed(upstream: &TcpListener) {
    assert!(matches!(
        upstream.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
}

#[test]
fn granted_owner_is_proxied_with_one_relay_token_prefix() {
    // This fails if the proxy omits or duplicates the header, or does not pipe
    // the client payload and relay response.
    let grants = Grants::new();
    let (upstream, task) = spawn_relay_upstream(b"ping");
    let proxy = proxy::bind(grants.clone(), upstream).unwrap();
    let port = proxy.port();
    grants.insert(
        port,
        grant(current_anchor(), Instant::now() + Duration::from_secs(60)),
    );
    proxy.serve();

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).unwrap();

    assert_eq!(&reply, b"pong");
    task.join().unwrap();
}

#[test]
fn connection_outside_the_granted_process_ancestry_is_refused_without_dialing() {
    // This fails if the owner check is removed: the intentionally mismatched
    // start time makes this client outside the grant's process anchor.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let (listener, port) = listener();
    let wrong_anchor = current_anchor();
    let wrong_anchor = ProcessAnchor::new(wrong_anchor.pid, wrong_anchor.start + 1);
    grants.insert(
        port,
        grant(wrong_anchor, Instant::now() + Duration::from_secs(60)),
    );
    proxy::spawn_with_listener(
        grants,
        listener,
        upstream.local_addr().unwrap(),
        resolver(Some(std::process::id())),
    );

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_refused(&mut client, b"REFUSED SESSION\n");
    assert_not_dialed(&upstream);
}

#[test]
fn unresolvable_connection_is_refused_without_dialing() {
    // This fails if a missing socket owner is treated as authorized.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let (listener, port) = listener();
    grants.insert(
        port,
        grant(current_anchor(), Instant::now() + Duration::from_secs(60)),
    );
    proxy::spawn_with_listener(
        grants,
        listener,
        upstream.local_addr().unwrap(),
        resolver(None),
    );

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_refused(&mut client, b"REFUSED SESSION\n");
    assert_not_dialed(&upstream);
}

#[test]
fn port_with_no_live_grant_is_refused() {
    // This fails if an ungranted endpoint is allowed to reach the relay.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let (listener, port) = listener();
    proxy::spawn_with_listener(
        grants,
        listener,
        upstream.local_addr().unwrap(),
        resolver(Some(std::process::id())),
    );

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_refused(&mut client, b"REFUSED UNGRANTED\n");
    assert_not_dialed(&upstream);
}

#[test]
fn expired_grant_is_refused_as_ungranted() {
    // This fails if a past deadline is treated as a live authorization.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let (listener, port) = listener();
    grants.insert(
        port,
        grant(current_anchor(), Instant::now() - Duration::from_secs(1)),
    );
    proxy::spawn_with_listener(
        grants,
        listener,
        upstream.local_addr().unwrap(),
        resolver(Some(std::process::id())),
    );

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_refused(&mut client, b"REFUSED UNGRANTED\n");
    assert_not_dialed(&upstream);
}

#[test]
fn reaper_closes_the_listener_without_a_client_connection() {
    // This fails if expiry only removes the grant and does not wake accept.
    let grants = Grants::new();
    let upstream = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let proxy = proxy::bind(grants.clone(), upstream).unwrap();
    let port = proxy.port();
    let deadline = Instant::now() + Duration::from_millis(50);
    grants.insert(port, grant(current_anchor(), deadline));
    proxy::reap_at(grants.clone(), port, deadline);
    proxy.serve();

    thread::sleep(Duration::from_secs(1));

    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    assert!(grants.live(port).is_none());
}
