use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

use socket2::{Domain, Protocol, Socket, Type};

use super::*;

/// Accepts one connection, reads the URL line, and answers with `reply`
/// verbatim. An empty `reply` stands in for a counterpart that says nothing.
fn counterpart(reply: &'static str) -> (u16, std::thread::JoinHandle<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut received = String::new();
        BufReader::new(&stream).read_line(&mut received).unwrap();
        if !reply.is_empty() {
            stream.write_all(reply.as_bytes()).unwrap();
            stream.flush().unwrap();
        }
        received
    });
    (port, handle)
}

/// Fill a loopback listener's accept queue without accepting any streams.
///
/// The final short dial proves the queue is saturated before the request under
/// test runs, avoiding an external or routable black-hole address.
fn saturated_listener() -> (Socket, SocketAddr, Vec<TcpStream>) {
    let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    listener
        .bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())
        .unwrap();
    listener.listen(1).unwrap();
    let target = listener.local_addr().unwrap().as_socket().unwrap();
    let mut queued = Vec::new();
    loop {
        match TcpStream::connect_timeout(&target, Duration::from_millis(50)) {
            Ok(stream) => {
                queued.push(stream);
                assert!(queued.len() < 16, "listener accept queue did not saturate");
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                return (listener, target, queued);
            }
            Err(error) => panic!("could not fill listener accept queue: {error}"),
        }
    }
}

#[test]
fn sends_newline_terminated_url_and_returns_the_reported_outcome() {
    // Given: a counterpart that opens what it is sent, and a config with no
    // peer, which means loopback.
    let cfg = Config::default_values_for_test();
    let (port, handle) = counterpart("opened\n");

    // When: a URL is sent to it.
    let outcome = send_url(
        &cfg,
        &url::Url::parse("https://example.com/a").unwrap(),
        port,
    )
    .unwrap();

    // Then: it received one newline-terminated URL, and the reported outcome
    // reaches the caller.
    assert_eq!(handle.join().unwrap(), "https://example.com/a\n");
    assert_eq!(outcome, Outcome::Opened);
}

#[test]
fn a_notified_url_is_reported_as_notified() {
    // Given: a counterpart that handed the URL over instead of opening it.
    let cfg = Config::default_values_for_test();
    let (port, handle) = counterpart("notified\n");

    // When: a URL is sent.
    let outcome = send_url(&cfg, &url::Url::parse("https://example.com").unwrap(), port).unwrap();

    // Then: the caller learns nothing opened, which is what lets it fall back
    // to handling the URL itself.
    assert_eq!(outcome, Outcome::Notified);
    handle.join().unwrap();
}

#[test]
fn a_silent_counterpart_is_an_error_rather_than_an_assumed_open() {
    // Given: a counterpart that accepts the URL and closes without answering,
    // as an older daemon does.
    let cfg = Config::default_values_for_test();
    let (port, handle) = counterpart("");

    // When: a URL is sent.
    let result = send_url(&cfg, &url::Url::parse("https://example.com").unwrap(), port);

    // Then: the outcome is reported as unknown rather than guessed as opened,
    // because guessing is what leaves a caller waiting on no browser.
    assert!(
        matches!(result, Err(SendError::Unreported { .. })),
        "got {result:?}"
    );
    handle.join().unwrap();
}

#[test]
fn an_unrecognized_answer_is_not_taken_for_success() {
    // Given: a counterpart answering something this version does not know.
    let cfg = Config::default_values_for_test();
    let (port, handle) = counterpart("sideways\n");

    // When: a URL is sent.
    let result = send_url(&cfg, &url::Url::parse("https://example.com").unwrap(), port);

    // Then: an unknown answer is not read as an open.
    assert!(
        matches!(result, Err(SendError::Unreported { .. })),
        "got {result:?}"
    );
    handle.join().unwrap();
}

#[test]
fn osc52_sequence_is_bare_outside_tmux() {
    // Given: text copied outside tmux.
    let text = "hello";

    // When: OSC 52 is encoded.
    let sequence = osc52_sequence(text, false);

    // Then: it is a bare OSC 52 sequence.
    assert_eq!(sequence, "\x1b]52;c;aGVsbG8=\x07");
}

#[test]
fn osc52_sequence_is_wrapped_inside_tmux() {
    // Given: text copied inside tmux.
    let text = "hello";

    // When: OSC 52 is encoded.
    let sequence = osc52_sequence(text, true);

    // Then: tmux passthrough wraps the OSC 52 sequence.
    assert_eq!(sequence, "\x1bPtmux;\x1b\x1b]52;c;aGVsbG8=\x07\x1b\\");
}

#[test]
fn unreachable_peer_is_reported_with_its_target() {
    // Given: a peer with nothing listening. Port 9 (discard) is outside the
    // ephemeral range, so nothing binds it in tests.
    let mut cfg = Config::default_values_for_test();
    cfg.peer = "127.0.0.1".to_owned();

    // When: a URL is sent.
    let result = send_url(&cfg, &url::Url::parse("https://example.com").unwrap(), 9);

    // Then: the error names what could not be reached, so the caller can
    // print and OSC 52 copy the URL instead of losing it.
    match result {
        Err(SendError::Unreachable { target, .. }) => assert_eq!(target, "127.0.0.1:9"),
        other => panic!("expected Unreachable, got {other:?}"),
    }
}

#[test]
fn send_url_bounds_the_production_dial_when_a_local_listener_queue_is_full() {
    // Given: a local listener whose accept queue rejects another handshake.
    let (listener, target, queued) = saturated_listener();
    let mut cfg = Config::default_values_for_test();
    cfg.peer = target.ip().to_string();
    let url = url::Url::parse("https://example.com").unwrap();
    let (done, result) = mpsc::channel();

    // When: the public URL sender dials the saturated endpoint.
    let handle = std::thread::spawn(move || {
        done.send(send_url(&cfg, &url, target.port())).unwrap();
    });
    let outcome = result.recv_timeout(crate::PEER_CONNECT_TIMEOUT + Duration::from_secs(2));
    drop(queued);
    drop(listener);
    handle.join().unwrap();

    // Then: the production dial reports the usual unreachable error within its bound.
    let error = outcome.expect("production dial did not respect its timeout");
    assert!(matches!(error, Err(SendError::Unreachable { .. })));
}

#[test]
fn malformed_peer_is_reported_rather_than_falling_back_to_loopback() {
    // Given: a peer that is not an address, which Config::validate rejects.
    let mut cfg = Config::default_values_for_test();
    cfg.peer = "not-an-address".to_owned();

    // When: a URL is sent.
    let result = send_url(&cfg, &url::Url::parse("https://example.com").unwrap(), 9);

    // Then: it fails loudly rather than silently sending to this machine.
    assert!(matches!(result, Err(SendError::Config { .. })));
}
