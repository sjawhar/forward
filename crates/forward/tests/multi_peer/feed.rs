use std::io::{BufRead as _, BufReader};
use std::time::Instant;

use forward::browser::feed::{RelayTokens, spawn_client};

use super::*;

#[test]
fn simultaneous_feeds_authorize_only_their_own_peer_and_report_independent_liveness() {
    // A single token cache or connected flag admits a grant from the wrong VM.
    let feed_a = TcpListener::bind("127.0.0.2:0").unwrap();
    let port = feed_a.local_addr().unwrap().port();
    let feed_b = TcpListener::bind(("127.0.0.3", port)).unwrap();
    let mut cfg = config();
    cfg.grant_port = port;
    let tokens = RelayTokens::new();
    spawn_client(&cfg, tokens.clone()).unwrap();
    let mut feeds = Vec::new();
    for (listener, token) in [(feed_a, "token-a"), (feed_b, "token-b")] {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + WAIT;
        let (mut stream, _) = loop {
            match listener.accept() {
                Ok(accepted) => break accepted,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "missing per-peer feed client");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("feed accept: {error}"),
            }
        };
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "FEED\n");
        writeln!(stream, "TOKEN {token} 60").unwrap();
        line.clear();
        reader.read_line(&mut line).unwrap();
        assert_eq!(line, "OK\n");
        feeds.push(stream);
    }
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let target = upstream.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in upstream.incoming().flatten() {
            std::thread::spawn(move || echo(stream));
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    forward::browser::spawn_with_listener(cfg, tokens.clone(), listener, target).unwrap();
    let mut a = connect_from("127.0.0.2", address);
    let mut b = connect_from("127.0.0.3", address);
    a.write_all(b"RELAY token-a\n").unwrap();
    b.write_all(b"RELAY token-b\n").unwrap();
    roundtrip(&mut a, b"a's browser session");
    roundtrip(&mut b, b"b's browser session");
    for (source, stolen) in [("127.0.0.2", "token-b"), ("127.0.0.3", "token-a")] {
        let mut thief = connect_from(source, address);
        writeln!(thief, "RELAY {stolen}").unwrap();
        let mut reply = [0; 8];
        thief.read_exact(&mut reply).unwrap();
        assert_eq!(&reply, b"REFUSED ");
    }
    let mut stranger = connect_from("127.0.0.4", address);
    let mut refused = String::new();
    stranger.read_to_string(&mut refused).unwrap();
    assert_eq!(refused, "REFUSED PEER\n");
    feeds.remove(0).shutdown(Shutdown::Both).unwrap();
    let peer_a = tokens.for_peer("127.0.0.2".parse().unwrap());
    let peer_b = tokens.for_peer("127.0.0.3".parse().unwrap());
    let deadline = Instant::now() + WAIT;
    while peer_a.is_connected() {
        assert!(Instant::now() < deadline, "disconnected feed remained live");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        peer_b.is_connected(),
        "one outage disconnected the other peer"
    );
    roundtrip(&mut b, b"b stays live");
}
