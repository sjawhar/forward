use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use forward::browser::feed::RelayTokens;
use forward::browser::grant::Grants;
use forward::browser::push::{FeedSlot, spawn_listener};

#[test]
fn an_overlong_unterminated_greeting_cannot_block_a_laptop_feed_attachment() {
    // Given: a feed listener and an attacker that sends more than one accepted
    // greeting line without ever ending it.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.listen = "127.0.0.1".to_owned();
    cfg.peer = "127.0.0.1".to_owned();
    cfg.grant_port = port;
    let slot = FeedSlot::new();
    spawn_listener(&cfg, slot.clone(), Grants::new()).unwrap();
    let mut attacker = TcpStream::connect(("127.0.0.1", port)).unwrap();
    attacker.write_all(&[b'x'; 512]).unwrap();

    // When: the actual laptop attaches after the unterminated greeting.
    let laptop_tokens = RelayTokens::new();
    forward::browser::feed::spawn_client(&cfg, laptop_tokens.clone()).unwrap();

    // Then: the bounded, independent handler leaves the accept loop available
    // for the laptop rather than waiting five seconds for attacker input.
    let deadline = Instant::now() + Duration::from_secs(1);
    while !slot.push(b"bounded-greeting-token", 60) {
        assert!(
            Instant::now() < deadline,
            "unterminated greeting blocked the real laptop feed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(laptop_tokens.accepts(b"bounded-greeting-token"));
}

#[test]
fn an_idle_greeting_cannot_block_a_laptop_feed_attachment() {
    // This fails if greeting parsing runs in the accept loop: the first socket
    // consumes its five-second read timeout before the laptop can attach.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.listen = "127.0.0.1".to_owned();
    cfg.peer = "127.0.0.1".to_owned();
    cfg.grant_port = port;
    let slot = FeedSlot::new();
    spawn_listener(&cfg, slot.clone(), Grants::new()).unwrap();
    let _attacker = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let laptop_tokens = RelayTokens::new();
    forward::browser::feed::spawn_client(&cfg, laptop_tokens.clone()).unwrap();

    let deadline = Instant::now() + Duration::from_secs(1);
    while !slot.push(b"idle-greeting-token", 60) {
        assert!(
            Instant::now() < deadline,
            "idle greeting blocked the real laptop feed"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(laptop_tokens.accepts(b"idle-greeting-token"));
}

#[test]
fn a_loopback_source_cannot_attach_the_feed_for_a_remote_laptop() {
    // This fails if the feed retains the general loopback exception: a local
    // process can then attach and receive every live relay token.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.listen = "127.0.0.1".to_owned();
    cfg.peer = "100.64.0.9".to_owned();
    cfg.grant_port = port;
    spawn_listener(&cfg, FeedSlot::new(), Grants::new()).unwrap();
    let mut attacker = TcpStream::connect(("127.0.0.1", port)).unwrap();
    attacker.write_all(b"FEED\n").unwrap();
    attacker
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();

    let mut byte = [0_u8; 1];
    match attacker.read(&mut byte) {
        Ok(0) => {}
        Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
        result => panic!("feed source was not refused: {result:?}"),
    }
}

#[test]
fn an_overlong_greeting_is_closed_before_the_read_timeout() {
    // This fails if the handler accepts an unbounded greeting and waits for the
    // five-second timeout instead of rejecting it at MAX_FEED_GREETING.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.listen = "127.0.0.1".to_owned();
    cfg.peer = "127.0.0.1".to_owned();
    cfg.grant_port = port;
    spawn_listener(&cfg, FeedSlot::new(), Grants::new()).unwrap();
    let mut attacker = TcpStream::connect(("127.0.0.1", port)).unwrap();
    attacker.write_all(&[b'x'; 512]).unwrap();
    attacker
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();

    let mut byte = [0_u8; 1];
    assert_eq!(attacker.read(&mut byte).unwrap(), 0);
}
