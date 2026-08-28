use std::io::{self, Read as _};
use std::net::SocketAddr;
use std::os::unix::net::{UnixListener, UnixStream};

use super::{handle_with_dial, listener_spawn_result};
use crate::pulse::{CONNECT_TIMEOUT, PulseError};

#[test]
fn listener_thread_spawn_failure_is_reported() {
    let error =
        listener_spawn_result(Err(io::Error::other("thread limit"))).expect_err("must fail");

    assert!(matches!(
        error,
        PulseError::Spawn { source } if source.kind() == io::ErrorKind::Other
    ));
}

#[test]
fn handler_uses_the_configured_connect_timeout() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pulse.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let mut client = UnixStream::connect(&path).unwrap();
    let (stream, _) = listener.accept().unwrap();
    let mut timeout = None;

    handle_with_dial(
        "127.0.0.1:12806".parse::<SocketAddr>().unwrap(),
        stream,
        |_, requested| {
            timeout = Some(requested);
            Err(io::Error::new(io::ErrorKind::ConnectionRefused, "offline"))
        },
    );

    assert_eq!(timeout, Some(CONNECT_TIMEOUT));
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert!(reply.is_empty());
}
