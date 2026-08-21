use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, atomic::{AtomicBool, Ordering}, mpsc};
use std::thread;
use std::time::{Duration, Instant};

fn cfg_with_peer(peer: &str) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = peer.to_owned();
    cfg
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

fn wait_for_exit(handle: &thread::JoinHandle<()>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    handle.is_finished()
}

#[test]
fn an_unauthorized_peer_is_refused_and_its_payload_never_reaches_the_upstream() {
    // Given: a foreign peer, a payload, and an upstream that must not be dialed.
    let (mut client, server) = socket_pair();
    client.write_all(b"payload").unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();

    // When: the browser relay handles the unauthorized connection.
    forward::browser::handle_from(
        &cfg_with_peer("100.64.0.9"),
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
fn a_flooding_unauthorized_peer_still_gets_the_refusal_and_frees_its_slot() {
    // Given: a foreign peer that never stops flooding its socket.
    let (client, server) = socket_pair();
    let mut reader = client.try_clone().unwrap();
    reader.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer_stop = Arc::clone(&stop);
    let writer = thread::spawn(move || {
        while !writer_stop.load(Ordering::Relaxed) {
            let _ = (&client).write_all(&[0_u8; 4096]);
        }
    });
    let cfg = cfg_with_peer("100.64.0.9");
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            upstream.local_addr().unwrap(),
            "100.64.0.7".parse().unwrap(),
            server,
        );
    });

    // When: the bounded drain refuses the connection despite the continuous writes.
    let mut reply = Vec::new();
    while !reply.ends_with(b"REFUSED PEER\n") {
        let mut chunk = [0_u8; 32];
        let count = reader.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "relay closed before sending its refusal");
        reply.extend_from_slice(&chunk[..count]);
    }

    // Then: the refusal survived and the handler returned without waiting for the peer.
    assert_eq!(reply, b"REFUSED PEER\n");
    assert!(wait_for_exit(&handler), "flooding peer pinned the handler");
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    handler.join().unwrap();
}

#[test]
fn the_configured_peer_is_proxied_bidirectionally() {
    // Given: the configured, non-loopback peer and a pong upstream.
    let (mut client, server) = socket_pair();
    let cfg = cfg_with_peer("100.64.0.9");
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            spawn_pong_upstream(),
            "100.64.0.9".parse().unwrap(),
            server,
        );
    });

    // When: that peer sends four bytes.
    client.write_all(b"ping").unwrap();

    // Then: the upstream receives them and returns its reply through the channel.
    read_pong(&mut client);
    drop(client);
    handler.join().unwrap();
}

#[test]
fn a_mapped_ipv6_peer_matches_the_configured_ipv4_peer() {
    // Given: an IPv4 configured peer represented as a mapped IPv6 remote.
    let (mut client, server) = socket_pair();
    let cfg = cfg_with_peer("100.64.0.9");
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            spawn_pong_upstream(),
            "::ffff:100.64.0.9".parse::<IpAddr>().unwrap(),
            server,
        );
    });

    // When/Then: canonical authorization allows the complete bidirectional exchange.
    client.write_all(b"ping").unwrap();
    read_pong(&mut client);
    drop(client);
    handler.join().unwrap();
}

#[test]
fn a_loopback_client_stays_authorized_for_local_tooling() {
    // Given: a real listener and a configuration naming only a remote peer.
    let relay = spawn_relay(cfg_with_peer("100.64.0.9"), spawn_pong_upstream());
    let mut client = TcpStream::connect(("127.0.0.1", relay)).unwrap();

    // When/Then: the local doctor-style client is still proxied end to end.
    client.write_all(b"ping").unwrap();
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
    let relay = spawn_relay(cfg_with_peer("100.64.0.9"), upstream_address);
    let mut client = TcpStream::connect(("127.0.0.1", relay)).unwrap();

    // When: the client half-closes after its request.
    client.write_all(b"data").unwrap();
    client.shutdown(Shutdown::Write).unwrap();

    // Then: the upstream sees EOF and can still return a final reply and EOF.
    client.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert_eq!(receiver.recv_timeout(Duration::from_secs(5)).unwrap(), "data");
    assert_eq!(reply, "gone");
}

#[test]
fn an_absent_upstream_closes_the_connection_without_killing_the_accept_loop() {
    // Given: a relay pointing to an ephemeral port with no current upstream.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = probe.local_addr().unwrap();
    drop(probe);
    let relay = spawn_relay(cfg_with_peer("100.64.0.9"), upstream);

    // When: the first client reaches the absent upstream.
    let mut first = TcpStream::connect(("127.0.0.1", relay)).unwrap();
    assert_refused(&mut first, "REFUSED\n");

    // Then: a later upstream and client prove the accept loop survived.
    spawn_pong(TcpListener::bind(upstream).unwrap());
    let mut second = TcpStream::connect(("127.0.0.1", relay)).unwrap();
    second.write_all(b"ping").unwrap();
    read_pong(&mut second);
}
