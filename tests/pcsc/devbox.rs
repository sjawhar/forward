use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

use crate::pcsc_support::{cfg, tempdir, with_home};
#[test]
fn devbox_socket_pipes_raw_bytes_to_the_laptop_leg() {
    // This fails if the devbox leg frames, drops, or reorders pcscd bytes.
    let dir = tempdir();
    let socket = dir.path().join("pcscd.comm");
    let laptop = TcpListener::bind("127.0.0.1:0").unwrap();
    let laptop_address = laptop.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = laptop.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(&request).unwrap();
    });
    let listener = UnixListener::bind(&socket).unwrap();
    forward::pcsc::devbox::spawn_with_unix_listener(listener, laptop_address).unwrap();

    let mut client = UnixStream::connect(&socket).unwrap();
    client.write_all(b"\x01raw pcscd frame").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();

    assert_eq!(reply, b"\x01raw pcscd frame");
}

#[test]
fn devbox_socket_closes_fast_when_the_laptop_is_unreachable() {
    // This fails if an unreachable laptop hangs pcsc clients instead of the
    // immediate loud failure secretsd's classifier expects.
    let dir = tempdir();
    let socket = dir.path().join("pcscd.comm");
    // A bound-then-dropped port refuses connections immediately.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_address = dead.local_addr().unwrap();
    drop(dead);
    let listener = UnixListener::bind(&socket).unwrap();
    forward::pcsc::devbox::spawn_with_unix_listener(listener, dead_address).unwrap();

    let mut client = UnixStream::connect(&socket).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let started = std::time::Instant::now();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();

    assert!(reply.is_empty());
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "close took {:?}; must be far under the connect timeout ceiling",
        started.elapsed()
    );
}

#[test]
fn devbox_spawn_replaces_a_stale_socket_with_mode_0600() {
    let dir = tempdir();
    let socket = dir.path().join(".pcscd/pcscd.comm");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    drop(UnixListener::bind(&socket).unwrap());

    with_home(dir.path(), || {
        let mut config = cfg();
        config.peer = "127.0.0.1".to_owned();
        config.pcsc_port = 1;
        forward::pcsc::devbox::spawn(&config).unwrap();

        let mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    });
}

#[test]
fn devbox_spawn_does_not_replace_a_live_socket() {
    let dir = tempdir();
    let socket = dir.path().join(".pcscd/pcscd.comm");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let _live = UnixListener::bind(&socket).unwrap();

    with_home(dir.path(), || {
        let mut config = cfg();
        config.peer = "127.0.0.1".to_owned();
        config.pcsc_port = 1;
        let error = forward::pcsc::devbox::spawn(&config).expect_err("live socket must win");

        assert!(
            matches!(
                error,
                forward::pcsc::PcscError::Socket { source, .. }
                    if source.kind() == std::io::ErrorKind::AddrInUse
            ),
            "live socket must report an address-in-use error"
        );
        UnixStream::connect(&socket).expect("live socket must remain connectable");
    });
}
