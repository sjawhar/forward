use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::thread;

use forward::secretsd::{self, BrokerError, BrokerIdentity};

use super::{FakeBroker, HELLO_OK, hello};

#[test]
fn broker_identity_reads_the_fresh_hello_extension() {
    let broker = FakeBroker::start(vec![hello()]);

    let identity = secretsd::broker_identity_for_test(&broker.path);
    broker.finish();

    assert_eq!(
        identity.ok(),
        Some(BrokerIdentity {
            instance: "abc123".to_owned(),
            epoch: 0,
        })
    );
}

#[test]
fn a_same_uid_impostor_socket_is_rejected_before_its_valid_hello_is_trusted() {
    // This fails if forward trusts the rebindable socket path: the test binary
    // is the socket peer, not the installed `secrets` broker executable.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("secretsd.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let impostor = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let _ = stream.write_all(HELLO_OK.as_bytes());
    });

    let result = secretsd::broker_identity(&path);

    impostor.join().unwrap();
    assert!(matches!(result, Err(BrokerError::UntrustedPeer { .. })));
}
