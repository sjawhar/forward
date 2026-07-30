use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc;
use std::time::Duration;

/// An echo-then-close upstream: reads until EOF, writes the reply, closes.
fn spawn_upstream() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(b"HTTP/1.1 200 OK\r\n\r\nok").unwrap();
    });
    port
}

/// A greet-then-half-close upstream: writes, shuts down its own write half, then
/// reads the client's answer to EOF and reports what it received.
fn spawn_greeting_upstream() -> (u16, mpsc::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (answers, answered) = mpsc::channel();
    std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.write_all(b"HELLO\n").unwrap();
        stream.shutdown(Shutdown::Write).unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).unwrap();
        let _ = answers.send(answer);
    });
    (port, answered)
}

/// An upstream that accepts and then resets, the way a callback tool that
/// crashed mid-request does. The reset waits for `dialed`: on a slow machine an
/// immediate RST can land while the dialing side's `connect()` is still
/// returning, failing the dial itself instead of the copy the test is about.
fn spawn_resetting_upstream(dialed: mpsc::Receiver<()>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        // A timeout still resets, so a wedged dialer fails the test loudly
        // instead of hanging it.
        let _ = dialed.recv_timeout(Duration::from_secs(5));
        let stream = socket2::Socket::from(stream);
        stream.set_linger(Some(Duration::ZERO)).unwrap();
        drop(stream);
    });
    port
}

/// The front door: accepts one connection, dials `upstream_port`, pipes the two
/// together, and reports what `bidirectional` returned.
fn spawn_pipe(upstream_port: u16) -> (u16, mpsc::Receiver<std::io::Result<()>>) {
    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let front_port = front.local_addr().unwrap().port();
    let (outcomes, outcome) = mpsc::channel();
    std::thread::spawn(move || {
        let (client, _) = front.accept().unwrap();
        let up = TcpStream::connect(("127.0.0.1", upstream_port)).unwrap();
        let _ = outcomes.send(forward::pipe::bidirectional(client, up));
    });
    (front_port, outcome)
}

#[test]
fn half_close_lets_the_reply_through() {
    // Given: an upstream that only replies after it sees EOF on the request.
    let (front_port, _outcome) = spawn_pipe(spawn_upstream());

    // When: a client sends a request and shuts down its write half.
    let mut client = TcpStream::connect(("127.0.0.1", front_port)).unwrap();
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // Then: EOF is propagated upstream, so the reply comes back instead of
    // both sides waiting forever.
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert!(reply.ends_with("ok"), "got {reply:?}");
}

#[test]
fn half_close_from_the_upstream_reaches_the_client() {
    // Given: an upstream that greets, half-closes, then waits to be answered.
    let (upstream_port, answered) = spawn_greeting_upstream();
    let (front_port, _outcome) = spawn_pipe(upstream_port);

    // When: the client reads to EOF and only then sends its answer.
    let mut client = TcpStream::connect(("127.0.0.1", front_port)).unwrap();
    let mut reader = client.try_clone().unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut greeting = Vec::new();
    reader.read_to_end(&mut greeting).unwrap();
    client.write_all(b"ANSWER\n").unwrap();
    client.shutdown(Shutdown::Write).unwrap();

    // Then: the upstream's EOF reached the client, and shutting down only that
    // one write half left the client-to-upstream direction alive to carry the
    // answer sent after it.
    assert_eq!(greeting, b"HELLO\n");
    assert_eq!(
        answered.recv_timeout(Duration::from_secs(5)).unwrap(),
        b"ANSWER\n"
    );
}

#[test]
fn a_mid_copy_reset_surfaces_as_an_error() {
    // Given: an upstream that resets only once the pipe holds both sockets,
    // and a client that stays idle, so the client-to-upstream copy is parked
    // on a read that will never complete on its own.
    let (dialed, dial_observed) = mpsc::channel();
    let upstream_port = spawn_resetting_upstream(dial_observed);
    let front = TcpListener::bind("127.0.0.1:0").unwrap();
    let front_port = front.local_addr().unwrap().port();
    let (outcomes, outcome) = mpsc::channel();
    std::thread::spawn(move || {
        let (client, _) = front.accept().unwrap();
        let up = TcpStream::connect(("127.0.0.1", upstream_port)).unwrap();
        let _ = dialed.send(());
        let _ = outcomes.send(forward::pipe::bidirectional(client, up));
    });
    let _client = TcpStream::connect(("127.0.0.1", front_port)).unwrap();

    // When: the reset lands mid-copy.
    let outcome = outcome.recv_timeout(Duration::from_secs(5));

    // Then: the failing direction wakes its idle sibling and the error is
    // returned; a timeout here means the pipe hung instead.
    let outcome = outcome.expect("bidirectional never returned");
    assert!(outcome.is_err(), "expected an error, got {outcome:?}");
}
