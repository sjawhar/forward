use forward::browser::feed::RelayTokens;
use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn cfg_with_peer(peer: &str) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = peer.to_owned();
    cfg
}

fn cfg_with_token(peer: &str, token: &str) -> (forward::config::Config, RelayTokens) {
    let tokens = RelayTokens::new();
    tokens.insert(token.as_bytes().to_vec(), Duration::from_secs(60));
    tokens.set_connected(true);
    (cfg_with_peer(peer), tokens)
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

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn spawn_relay(cfg: forward::config::Config, tokens: RelayTokens, upstream: SocketAddr) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    forward::browser::spawn_with_listener(cfg, tokens, listener, upstream).unwrap();
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
fn an_unauthorized_peer_is_refused_and_its_payload_never_reaches_the_upstream() {
    // Given: a foreign peer, a payload, and an upstream that must not be dialed.
    let (mut client, server) = socket_pair();
    let tokens = RelayTokens::new();
    client.write_all(b"payload").unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();

    // When: the browser relay handles the unauthorized connection.
    forward::browser::handle_from(
        &cfg_with_peer("100.64.0.9"),
        &tokens,
        upstream.local_addr().unwrap(),
        "100.64.0.7".parse().unwrap(),
        server,
    );

    // Then: it refuses before dialing or inspecting the upstream.
    assert_refused(&mut client, "REFUSED PEER\n");
    assert!(matches!(
        upstream.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
}

#[test]
fn an_unknown_token_with_no_feed_attached_is_refused_as_feed_down() {
    // Given: an authorized peer and no grant feed connection.
    let (mut client, server) = socket_pair();
    let tokens = RelayTokens::new();
    client.write_all(b"RELAY never-issued\n").unwrap();

    // When: it presents a token the laptop has not received.
    forward::browser::handle_from(
        &cfg_with_peer("100.64.0.9"),
        &tokens,
        SocketAddr::from(([127, 0, 0, 1], 1)),
        "100.64.0.9".parse().unwrap(),
        server,
    );

    // Then: the refusal identifies the missing feed, not a normal locked state.
    assert_refused(&mut client, "REFUSED FEED\n");
}

#[test]
fn the_configured_peer_is_proxied_bidirectionally() {
    // Given: the configured, non-loopback peer and a pong upstream.
    let (mut client, server) = socket_pair();
    let (cfg, tokens) = cfg_with_token("100.64.0.9", "correct-horse");
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            &tokens,
            spawn_pong_upstream(),
            "100.64.0.9".parse().unwrap(),
            server,
        );
    });

    // When: that peer presents the token and sends four bytes.
    client.write_all(b"RELAY correct-horse\nping").unwrap();

    // Then: the upstream receives them and returns its reply through the channel.
    read_pong(&mut client);
    drop(client);
    handler.join().unwrap();
}

#[test]
fn a_mapped_ipv6_peer_matches_the_configured_ipv4_peer() {
    // Given: an IPv4 configured peer represented as a mapped IPv6 remote.
    let (mut client, server) = socket_pair();
    let (cfg, tokens) = cfg_with_token("100.64.0.9", "correct-horse");
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            &tokens,
            spawn_pong_upstream(),
            "::ffff:100.64.0.9".parse::<IpAddr>().unwrap(),
            server,
        );
    });

    // When/Then: canonical authorization allows the complete tokened exchange.
    client.write_all(b"RELAY correct-horse\nping").unwrap();
    read_pong(&mut client);
    drop(client);
    handler.join().unwrap();
}

#[test]
fn a_loopback_client_stays_authorized_for_local_tooling() {
    // Given: a real listener and a configuration naming only a remote peer.
    let (cfg, tokens) = cfg_with_token("100.64.0.9", "correct-horse");
    let relay = spawn_relay(cfg, tokens, spawn_pong_upstream());
    let mut client = TcpStream::connect(("127.0.0.1", relay)).unwrap();

    // When/Then: the local doctor-style client is still proxied end to end.
    client.write_all(b"RELAY correct-horse\nping").unwrap();
    read_pong(&mut client);
}

#[test]
fn half_close_propagates_in_each_direction() {
    // Given: a listener whose upstream sends a reply only after receiving EOF.
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = String::new();
        stream.read_to_string(&mut request).unwrap();
        sender.send(request).unwrap();
        stream.write_all(b"gone").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
    });
    let (cfg, tokens) = cfg_with_token("100.64.0.9", "correct-horse");
    let relay = spawn_relay(cfg, tokens, upstream_address);
    let mut client = TcpStream::connect(("127.0.0.1", relay)).unwrap();

    // When: the client half-closes after its tokened request.
    client.write_all(b"RELAY correct-horse\ndata").unwrap();
    client.shutdown(Shutdown::Write).unwrap();

    // Then: the upstream sees EOF and can still return a final reply and EOF.
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(5)).unwrap(),
        "data"
    );
    assert_eq!(reply, "gone");
}

#[test]
fn an_absent_upstream_closes_the_connection_without_killing_the_accept_loop() {
    // Given: a relay pointing to an ephemeral port with no current upstream.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = probe.local_addr().unwrap();
    drop(probe);
    let (cfg, tokens) = cfg_with_token("100.64.0.9", "correct-horse");
    let relay = spawn_relay(cfg, tokens, upstream);

    // When: the first tokened client reaches the absent upstream. The token
    // gate now precedes the dial, so an untokened client would see
    // REFUSED TOKEN instead of exercising this path.
    let mut first = TcpStream::connect(("127.0.0.1", relay)).unwrap();
    first.write_all(b"RELAY correct-horse\n").unwrap();
    assert_refused(&mut first, "REFUSED\n");

    // Then: a later upstream and client prove the accept loop survived.
    spawn_pong(TcpListener::bind(upstream).unwrap());
    let mut second = TcpStream::connect(("127.0.0.1", relay)).unwrap();
    second.write_all(b"RELAY correct-horse\nping").unwrap();
    read_pong(&mut second);
}
