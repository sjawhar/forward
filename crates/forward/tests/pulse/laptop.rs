use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::pulse_support::{cfg, is_bare_close, tempdir, unix_echo, with_runtime_dir};

const READ_TIMEOUT: Duration = Duration::from_secs(2);

#[test]
fn laptop_channel_pipes_raw_bytes_to_the_pulse_socket() {
    // This fails if the channel parses, frames, or injects anything: native
    // protocol bytes must arrive verbatim and flow back.
    let dir = tempdir();
    let upstream = unix_echo(dir.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    forward::pulse::laptop::spawn_with_listener(cfg(), listener, upstream).unwrap();

    let mut client = TcpStream::connect(address).unwrap();
    client.write_all(&[0x00, 0x00, 0x00, 0x18, 0xff]).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    client.read_to_end(&mut reply).unwrap();

    assert_eq!(reply, [0x00, 0x00, 0x00, 0x18, 0xff]);
}

#[test]
fn laptop_channel_refuses_an_unauthorized_peer_or_loopback_proxy_with_a_bare_close() {
    // This fails if a non-peer address or a local TCP proxy is served, or if
    // the refusal writes bytes into a protocol that has no place for them.
    let dir = tempdir();
    let upstream = unix_echo(dir.path());
    let mut config = cfg();
    config.peer = "100.64.0.9".to_owned();

    for remote in ["100.64.0.7", "127.0.0.1"] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = thread::spawn(move || listener.accept().unwrap().0);
        let mut client = TcpStream::connect(address).unwrap();
        let server_side = accepted.join().unwrap();
        let config = config.clone();
        let upstream = upstream.clone();
        let remote = remote.parse::<IpAddr>().unwrap();
        let handler = thread::spawn(move || {
            forward::pulse::laptop::handle_from(&config, &upstream, remote, server_side);
        });

        client.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        let mut reply = Vec::new();
        match client
            .write_all(b"must not reach pipewire-pulse")
            .and_then(|()| client.shutdown(Shutdown::Write))
            .and_then(|()| client.read_to_end(&mut reply).map(drop))
        {
            Ok(()) => assert!(
                reply.is_empty(),
                "refusal must not write protocol-corrupting bytes"
            ),
            Err(error) if is_bare_close(&error) => {}
            Err(error) => panic!("refused client operation failed: {error}"),
        }
        handler.join().unwrap();
    }
}

#[test]
fn laptop_channel_closes_immediately_when_pipewire_pulse_is_absent() {
    // This fails if a missing pipewire-pulse socket hangs the client instead
    // of the bare close the spec's failure table requires.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = thread::spawn(move || listener.accept().unwrap().0);
    let mut client = TcpStream::connect(address).unwrap();
    let server_side = accepted.join().unwrap();
    let mut config = cfg();
    config.peer = "127.0.0.1".to_owned();

    // Call the production handler synchronously: EOF can then only follow its
    // normal missing-upstream return, not an unobserved session-thread panic.
    forward::pulse::laptop::handle_from(
        &config,
        std::path::Path::new("/nonexistent/pulse/native"),
        "127.0.0.1".parse::<IpAddr>().unwrap(),
        server_side,
    );

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert!(reply.is_empty());
}

#[test]
fn disabled_laptop_channel_does_not_resolve_or_bind_its_listener() {
    // The disabled setting is a complete opt-out: no listener, no upstream
    // path resolution, even with a deliberately invalid listen address.
    with_runtime_dir(None, || {
        let mut config = cfg();
        config.pulse_port = 0;
        config.listen = "not-an-address".to_owned();

        assert!(forward::pulse::laptop::spawn(&config).is_ok());
    });
}

#[test]
fn laptop_channel_with_no_peer_does_not_require_a_runtime_dir_or_bind() {
    // A held port turns any accidental listener bind into AddrInUse. No peer
    // must opt out before either that bind or runtime-dir resolution.
    let held = TcpListener::bind("127.0.0.1:0").unwrap();
    let pulse_port = held.local_addr().unwrap().port();

    with_runtime_dir(None, || {
        let mut config = cfg();
        config.peer.clear();
        config.pulse_port = pulse_port;

        forward::pulse::laptop::spawn(&config).expect("no peer must opt out");
    });
}

#[test]
fn laptop_connection_limit_bare_closes_overflow_and_recovers_after_a_session_ends() {
    const STANDARD_CONNECTION_LIMIT: usize = 32;

    let dir = tempdir();
    let upstream = dir.path().join("native");
    let upstream_listener = UnixListener::bind(&upstream).unwrap();
    let (ready_sender, ready) = mpsc::channel();
    let (release_sender, release) = mpsc::channel::<u8>();
    let upstream_server = thread::spawn(move || {
        let mut held = Vec::with_capacity(STANDARD_CONNECTION_LIMIT);
        for _ in 0..STANDARD_CONNECTION_LIMIT {
            let (mut stream, _) = upstream_listener.accept().unwrap();
            let mut id = [0_u8; 1];
            stream.read_exact(&mut id).unwrap();
            held.push((id[0], stream));
        }
        ready_sender.send(()).unwrap();
        let released_id = release.recv().unwrap();
        let position = held
            .iter()
            .position(|(id, _)| *id == released_id)
            .expect("released session must have an upstream connection");
        drop(held.swap_remove(position).1);

        let (mut stream, _) = upstream_listener.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(&request).unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    forward::pulse::laptop::spawn_with_listener(cfg(), listener, upstream).unwrap();

    let mut sessions = Vec::with_capacity(STANDARD_CONNECTION_LIMIT);
    for session_id in 0..STANDARD_CONNECTION_LIMIT {
        let mut session = TcpStream::connect(address).unwrap();
        session.write_all(&[session_id as u8]).unwrap();
        sessions.push(session);
    }
    ready
        .recv_timeout(READ_TIMEOUT)
        .expect("all standard connection slots must be occupied");

    let mut overflow = TcpStream::connect(address).unwrap();
    overflow.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let mut refused = Vec::new();
    overflow.read_to_end(&mut refused).unwrap();
    assert!(refused.is_empty(), "overflow must receive a bare close");
    drop(overflow);

    let mut released = sessions.pop().unwrap();
    released.shutdown(Shutdown::Write).unwrap();
    release_sender
        .send((STANDARD_CONNECTION_LIMIT - 1) as u8)
        .unwrap();
    released.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    let mut closed = Vec::new();
    released.read_to_end(&mut closed).unwrap();
    assert!(closed.is_empty(), "released session must close cleanly");
    drop(released);
    let deadline = std::time::Instant::now() + READ_TIMEOUT;
    let reply = loop {
        let mut normal = TcpStream::connect(address).unwrap();
        normal.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
        let write = normal
            .write_all(b"normal client")
            .and_then(|()| normal.shutdown(Shutdown::Write));
        let mut reply = Vec::new();
        match write.and_then(|()| normal.read_to_end(&mut reply)) {
            Ok(_) if reply == b"normal client" => break reply,
            Ok(_) if reply.is_empty() => {}
            Err(error) if is_bare_close(&error) => {}
            Ok(_) => panic!("normal client received unexpected bytes: {reply:?}"),
            Err(error) => panic!("normal client operation failed: {error}"),
        }
        assert!(
            std::time::Instant::now() < deadline,
            "normal client was not served after a connection slot was released"
        );
        thread::sleep(Duration::from_millis(10));
    };
    assert_eq!(reply, b"normal client");
    upstream_server.join().unwrap();
}
