use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener};
use std::os::unix::fs::PermissionsExt as _;
use std::os::unix::net::{UnixListener, UnixStream};
use std::thread;
use std::time::Duration;

use crate::pulse_support::{cfg, tempdir, with_runtime_dir};

const READ_TIMEOUT: Duration = Duration::from_secs(2);

#[test]
fn devbox_socket_pipes_raw_bytes_to_the_laptop_leg() {
    // This fails if the devbox leg frames, drops, or reorders pulse bytes.
    let dir = tempdir();
    let socket = dir.path().join("pulse.sock");
    let laptop = TcpListener::bind("127.0.0.1:0").unwrap();
    let laptop_address = laptop.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = laptop.accept().unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).unwrap();
        stream.write_all(&request).unwrap();
    });
    let listener = UnixListener::bind(&socket).unwrap();
    forward::pulse::devbox::spawn_with_unix_listener(listener, laptop_address).unwrap();

    let mut client = UnixStream::connect(&socket).unwrap();
    client.write_all(b"\x00raw pulse frame").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.set_read_timeout(Some(READ_TIMEOUT)).unwrap();
    client.read_to_end(&mut reply).unwrap();

    assert_eq!(reply, b"\x00raw pulse frame");
}

#[test]
fn devbox_socket_closes_fast_when_the_laptop_is_unreachable() {
    // This fails if an unreachable laptop hangs pulse clients instead of the
    // loud connection-refused failure the retired tunnel gave them.
    let dir = tempdir();
    let socket = dir.path().join("pulse.sock");
    // A bound-then-dropped port refuses connections immediately.
    let dead = TcpListener::bind("127.0.0.1:0").unwrap();
    let dead_address = dead.local_addr().unwrap();
    drop(dead);
    let listener = UnixListener::bind(&socket).unwrap();
    forward::pulse::devbox::spawn_with_unix_listener(listener, dead_address).unwrap();

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
fn devbox_spawn_replaces_a_stale_socket_with_a_0600_socket_in_a_0700_dir() {
    // This fails if the spec's modes regress: directory 0700, socket 0600.
    let dir = tempdir();
    let socket = dir.path().join("forward/pulse.sock");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    drop(UnixListener::bind(&socket).unwrap());

    with_runtime_dir(Some(dir.path()), || {
        let mut config = cfg();
        config.peer = "127.0.0.1".to_owned();
        config.pulse_port = 1;
        forward::pulse::devbox::spawn(&config).unwrap();

        let socket_mode = std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777;
        assert_eq!(socket_mode, 0o600);
        let dir_mode = std::fs::metadata(socket.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    });
}

#[test]
fn devbox_spawn_does_not_replace_a_live_socket() {
    let dir = tempdir();
    let socket = dir.path().join("forward/pulse.sock");
    std::fs::create_dir_all(socket.parent().unwrap()).unwrap();
    let _live = UnixListener::bind(&socket).unwrap();

    with_runtime_dir(Some(dir.path()), || {
        let mut config = cfg();
        config.peer = "127.0.0.1".to_owned();
        config.pulse_port = 1;
        let error = forward::pulse::devbox::spawn(&config).expect_err("live socket must win");

        assert!(
            matches!(
                error,
                forward::pulse::PulseError::Socket { source, .. }
                    if source.kind() == std::io::ErrorKind::AddrInUse
            ),
            "live socket must report an address-in-use error"
        );
        UnixStream::connect(&socket).expect("live socket must remain connectable");
    });
}

#[test]
fn devbox_spawn_checks_peer_before_the_runtime_dir() {
    // No peer is a complete opt-out even when a real runtime directory exists.
    let dir = tempdir();
    let socket = dir.path().join("forward/pulse.sock");
    with_runtime_dir(Some(dir.path()), || {
        let mut config = cfg();
        config.peer.clear();
        config.pulse_port = 1;
        forward::pulse::devbox::spawn(&config).expect("no peer must opt out");
        assert!(!socket.exists(), "no-peer opt-out must not create a socket");
    });

    // A configured peer, by contrast, requires an absolute runtime dir.
    with_runtime_dir(None, || {
        let mut config = cfg();
        config.peer = "127.0.0.1".to_owned();
        config.pulse_port = 1;
        let error = forward::pulse::devbox::spawn(&config).expect_err("must refuse");

        assert!(matches!(error, forward::pulse::PulseError::RuntimeDir));
    });
}

#[test]
fn disabled_devbox_channel_does_not_require_a_runtime_dir_or_create_a_socket() {
    let current_dir = std::env::current_dir().unwrap();
    let dir = tempfile::tempdir_in(&current_dir).unwrap();
    let relative_runtime = dir.path().strip_prefix(&current_dir).unwrap();
    let socket = dir.path().join("forward/pulse.sock");

    for runtime_dir in [None, Some(relative_runtime)] {
        with_runtime_dir(runtime_dir, || {
            let mut config = cfg();
            config.peer = "127.0.0.1".to_owned();
            config.pulse_port = 0;

            forward::pulse::devbox::spawn(&config).expect("disabled channel must opt out");
        });
    }

    assert!(
        !socket.exists(),
        "disabled channel must not create a devbox socket"
    );
}
