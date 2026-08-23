use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn cfg_with_peer(peer: &str) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = peer.to_owned();
    cfg
}

fn cfg_with_token(peer: &str, token: &str) -> (forward::config::Config, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay.token");
    std::fs::write(&path, format!("{token}\n")).unwrap();
    let mut cfg = cfg_with_peer(peer);
    cfg.relay_token_file = Some(path);
    (cfg, directory)
}

fn assert_refused(client: &mut TcpStream, expected: &str) {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = String::new();
    client
        .read_to_string(&mut reply)
        .expect("the relay must write its refusal before closing");
    assert_eq!(reply, expected);
}

fn assert_never_dialed(upstream: &TcpListener) {
    upstream.set_nonblocking(true).unwrap();
    assert!(matches!(
        upstream.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
}

fn spawn_pong(listener: TcpListener) -> SocketAddr {
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").unwrap();
    });
    address
}

fn spawn_pong_upstream() -> SocketAddr {
    spawn_pong(TcpListener::bind("127.0.0.1:0").unwrap())
}

fn spawn_relay(cfg: forward::config::Config, upstream: SocketAddr) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    forward::browser::spawn_with_listener(cfg, listener, upstream).unwrap();
    port
}

fn read_pong(client: &mut TcpStream) {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"pong");
}

#[test]
fn a_connection_without_a_relay_token_is_refused_and_never_reaches_the_upstream() {
    // Given: a relay whose upstream must never be dialed.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (cfg, _directory) = cfg_with_token("127.0.0.1", "correct-horse");
    let port = spawn_relay(cfg, upstream_address);

    // When: a client sends CDP bytes with no request line.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client
        .write_all(b"GET /json/list HTTP/1.1\r\n\r\n")
        .unwrap();

    // Then: it is refused, and the upstream saw no connection.
    assert_refused(&mut client, "REFUSED TOKEN\n");
    assert_never_dialed(&upstream);
}

#[test]
fn a_connection_with_the_wrong_relay_token_is_refused_and_never_reaches_the_upstream() {
    // Given: a relay expecting one token, and an upstream that must stay silent.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let (cfg, _directory) = cfg_with_token("127.0.0.1", "correct-horse");
    let port = spawn_relay(cfg, upstream.local_addr().unwrap());

    // When: a client presents a different token.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"RELAY battery-staple\nping").unwrap();

    // Then: it is refused before the upstream is ever dialed.
    assert_refused(&mut client, "REFUSED TOKEN\n");
    assert_never_dialed(&upstream);
}

#[test]
fn a_connection_with_the_expected_relay_token_is_proxied() {
    // Given: a relay and an upstream that answers ping with pong.
    let (cfg, _directory) = cfg_with_token("127.0.0.1", "correct-horse");
    let port = spawn_relay(cfg, spawn_pong_upstream());

    // When: a client presents the expected token and speaks.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"RELAY correct-horse\nping").unwrap();

    // Then: the payload after the request line reaches the upstream.
    read_pong(&mut client);
}

#[test]
fn a_relay_whose_token_file_is_missing_refuses_without_dialing_the_upstream() {
    // Given: a token path with no file behind it, as on a half-provisioned
    // laptop. The override keeps the test hermetic: the fallback path under
    // $HOME may hold a real token on a deployed machine.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut cfg = cfg_with_peer("127.0.0.1");
    cfg.relay_token_file = Some(directory.path().join("absent.token"));
    let port = spawn_relay(cfg, upstream.local_addr().unwrap());

    // When: a client presents any token.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"RELAY correct-horse\nping").unwrap();

    // Then: it fails closed rather than open, and the upstream stays silent.
    assert_refused(&mut client, "REFUSED TOKEN\n");
    assert_never_dialed(&upstream);
}
