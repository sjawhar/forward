use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use forward::browser::feed::RelayTokens;
use forward::browser::grant::{Grant, Grants, ProcessAnchor};
use forward::browser::push::{FeedSlot, spawn_listener};

#[test]
fn tokens_are_accepted_until_their_deadline_and_never_after() {
    // This fails if expiry does not revoke, or if an unknown value passes.
    let tokens = RelayTokens::new();
    tokens.insert(b"live-token".to_vec(), Duration::from_secs(60));
    tokens.insert(b"dead-token".to_vec(), Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(20));

    assert!(tokens.accepts(b"live-token"));
    assert!(!tokens.accepts(b"dead-token"));
    assert!(!tokens.accepts(b"never-issued"));
    assert!(!tokens.accepts(b"live-tokex"));
    assert!(!tokens.accepts(b""));
}

#[test]
fn the_feed_client_registers_pushed_tokens_and_acknowledges() {
    // This fails if the client mis-parses TOKEN lines, skips the OK ack, or
    // fails to mark the feed connected.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = "127.0.0.1".to_owned();
    cfg.grant_port = port;
    let tokens = RelayTokens::new();
    forward::browser::feed::spawn_client(&cfg, tokens.clone()).unwrap();

    let (feed, _) = listener.accept().unwrap();
    let mut reader = BufReader::new(feed.try_clone().unwrap());
    let mut hello = String::new();
    reader.read_line(&mut hello).unwrap();
    assert_eq!(hello, "FEED\n");

    let mut feed_write = feed;
    feed_write
        .write_all(b"TOKEN fresh-relay-token 60\n")
        .unwrap();
    let mut ack = String::new();
    reader.read_line(&mut ack).unwrap();

    assert_eq!(ack, "OK\n");
    assert!(tokens.accepts(b"fresh-relay-token"));
    assert!(tokens.is_connected());
}

#[test]
fn the_devbox_feed_slot_pushes_a_token_to_the_laptop_feed_client() {
    // This fails if the daemon feed listener does not attach the laptop client
    // or if FeedSlot does not wait for the laptop acknowledgement.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.listen = "127.0.0.1".to_owned();
    cfg.peer = "127.0.0.1".to_owned();
    cfg.grant_port = port;
    let slot = FeedSlot::new();
    let laptop_tokens = RelayTokens::new();

    spawn_listener(&cfg, slot.clone(), Grants::new()).unwrap();
    forward::browser::feed::spawn_client(&cfg, laptop_tokens.clone()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !laptop_tokens.is_connected() {
        assert!(Instant::now() < deadline, "laptop feed did not attach");
        std::thread::sleep(Duration::from_millis(10));
    }

    assert!(slot.push(b"fresh-relay-token", 60));
    assert!(laptop_tokens.accepts(b"fresh-relay-token"));
}

#[test]
fn live_grants_are_re_pushed_on_the_renewal_tick() {
    // This fails if an attached feed does not periodically renew live grants.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.listen = "127.0.0.1".to_owned();
    cfg.peer = "127.0.0.1".to_owned();
    cfg.grant_port = port;
    let grants = Grants::new();
    grants.insert(
        12811,
        Grant {
            session: "live".to_owned(),
            anchor: ProcessAnchor::new(1, 1),
            token: b"renewed-token".to_vec(),
            deadline: Instant::now() + Duration::from_secs(5 * 60),
        },
    );
    grants.insert(
        12812,
        Grant {
            session: "expired".to_owned(),
            anchor: ProcessAnchor::new(1, 1),
            token: b"expired-token".to_vec(),
            deadline: Instant::now() - Duration::from_secs(1),
        },
    );

    spawn_listener(&cfg, FeedSlot::new(), grants).unwrap();
    let mut feed = TcpStream::connect(("127.0.0.1", port)).unwrap();
    feed.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    feed.write_all(b"FEED\n").unwrap();
    let mut reader = BufReader::new(feed.try_clone().unwrap());
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    assert_eq!(first.split_whitespace().nth(1), Some("renewed-token"));
    feed.write_all(b"OK\n").unwrap();

    feed.set_read_timeout(Some(Duration::from_secs(65)))
        .unwrap();
    let mut renewal = String::new();
    reader.read_line(&mut renewal).unwrap();
    assert_eq!(renewal.split_whitespace().nth(1), Some("renewed-token"));
    feed.write_all(b"OK\n").unwrap();
}
