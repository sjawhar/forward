use std::os::unix::net::UnixListener;

use forward::bridge::Armed;
use forward::browser::feed::RelayTokens;

use super::*;

#[test]
fn raw_laptop_channels_serve_two_peers_and_close_unlisted_sources_before_payload() {
    // Removing the list gate or sharing a stream would leak a raw session.
    let dir = tempfile::tempdir().unwrap();
    for pulse in [false, true] {
        let path = dir.path().join(if pulse { "pulse" } else { "pcsc" });
        let unix = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            for stream in unix.incoming().flatten() {
                std::thread::spawn(move || echo(stream));
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        if pulse {
            forward::pulse::laptop::spawn_with_listener(config(), listener, path).unwrap();
        } else {
            forward::pcsc::laptop::spawn_with_listener(config(), listener, path).unwrap();
        }
        let mut a = connect_from("127.0.0.2", address);
        let mut b = connect_from("127.0.0.3", address);
        roundtrip(&mut a, b"session-a\x00\xff");
        roundtrip(&mut b, b"session-b\x01\xfe");
        roundtrip(&mut a, b"still-a");
        assert_closed_without_payload(connect_from("127.0.0.4", address));
        assert_closed_without_payload(connect_from("127.0.0.1", address));
    }
}

#[test]
fn browser_peer_refusal_does_not_drain_even_already_queued_bytes() {
    // The old refusal helper drained pending bytes after FIN. Identity refusal
    // must not do that, even if a whole request was queued before accept.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut client = connect_from("127.0.0.4", listener.local_addr().unwrap());
    client.write_all(b"must remain unread").unwrap();
    let (server, _) = listener.accept().unwrap();
    let mut observer = server.try_clone().unwrap();
    observer.set_read_timeout(Some(WAIT)).unwrap();
    let local = server.local_addr().unwrap().ip();
    forward::browser::handle_from(
        &config(),
        &RelayTokens::new(),
        "127.0.0.1:9".parse().unwrap(),
        "127.0.0.4".parse().unwrap(),
        local,
        server,
    );
    let mut pending = [0; 18];
    observer.read_exact(&mut pending).unwrap();
    assert_eq!(&pending, b"must remain unread");
}

#[test]
fn bridge_checks_each_source_before_reading_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = upstream.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in upstream.incoming().flatten() {
            std::thread::spawn(move || echo(stream));
        }
    });
    let armed = Armed::new(config());
    assert!(armed.arm(port, WAIT));
    forward::bridge::spawn_with_listener(config(), armed, listener);
    let mut a = connect_from("127.0.0.2", address);
    let mut b = connect_from("127.0.0.3", address);
    for stream in [&mut a, &mut b] {
        writeln!(stream, "CONNECT {port}").unwrap();
    }
    roundtrip(&mut a, b"bridge-a");
    roundtrip(&mut b, b"bridge-b");
    roundtrip(&mut a, b"still-bridge-a");
    let mut stranger = connect_from("127.0.0.4", address);
    let mut reply = String::new();
    stranger.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "REFUSED PEER\n");
}
