use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use crate::pulse_support::{is_bare_close, tempdir};

const READ_TIMEOUT: Duration = Duration::from_secs(2);

#[test]
fn devbox_connection_limit_bare_closes_overflow_and_recovers_after_a_session_ends() {
    const STANDARD_CONNECTION_LIMIT: usize = 32;

    let dir = tempdir();
    let socket = dir.path().join("pulse.sock");
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (ready_sender, ready) = mpsc::channel();
    let (release_sender, release) = mpsc::channel::<u8>();
    let upstream_server = thread::spawn(move || {
        let mut held = Vec::with_capacity(STANDARD_CONNECTION_LIMIT);
        for _ in 0..STANDARD_CONNECTION_LIMIT {
            let (mut stream, _) = upstream.accept().unwrap();
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

        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(&request).unwrap();
    });
    let listener = UnixListener::bind(&socket).unwrap();
    forward::pulse::devbox::spawn_with_unix_listener(listener, upstream_address).unwrap();

    let mut sessions = Vec::with_capacity(STANDARD_CONNECTION_LIMIT);
    for session_id in 0..STANDARD_CONNECTION_LIMIT {
        let mut session = UnixStream::connect(&socket).unwrap();
        session.write_all(&[session_id as u8]).unwrap();
        sessions.push(session);
    }
    ready
        .recv_timeout(READ_TIMEOUT)
        .expect("all standard connection slots must be occupied");

    let mut overflow = UnixStream::connect(&socket).unwrap();
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
        let mut normal = UnixStream::connect(&socket).unwrap();
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
