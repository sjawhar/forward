//! The pre-ceremony probe and the grant path's containment boundary.
//!
//! The anchor is the authorization boundary; the session label is descriptive.
//! A deterministic refusal must be answerable without spending a receipt, so
//! the CLI can refuse before the broker's YubiKey ceremony.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use forward::browser::request::{ProbeOutcome, RequestFailure, probe, request};

use super::{
    RECEIPT, accepting_redeemer, await_socket, feed_acceptor, grant_config, rejecting_redeemer,
    spawn_server,
};

fn probe_reply(path: &std::path::Path) -> String {
    let mut stream = UnixStream::connect(path).unwrap();
    stream.write_all(b"PROBE\n").unwrap();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    reply
}

#[test]
fn a_caller_outside_any_omp_session_is_still_granted() {
    // The session label enforces nothing: the anchor is the containment
    // boundary, checked per CDP connection by the proxy. This fails if a
    // label gate returns to the grant path and refuses plain shells again.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, receiver) = feed_acceptor();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| None),
        accepting_redeemer(),
    );
    await_socket(&path);

    let port = request(&path, 60, RECEIPT).expect("a grant must not require an omp session");
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(grants.live(port).is_some());
}

#[test]
fn probe_answers_grantable_without_spending_a_receipt() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, _receiver) = feed_acceptor();
    spawn_server(
        grants,
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| None),
        Arc::new(|_| panic!("a probe must never reach the redeemer")),
    );
    await_socket(&path);

    assert_eq!(probe_reply(&path), "OK\n");
    assert_eq!(probe(&path), ProbeOutcome::Grantable);
}

#[test]
fn probe_refuses_deterministically_without_an_upstream() {
    // No peer configured: both the probe and a real grant attempt must refuse
    // with the same reason, and neither may touch the redeemer -- a refusal
    // the server can predict must never cost a receipt.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, _receiver) = feed_acceptor();
    spawn_server(
        grants,
        forward::config::Config::default_values_for_test(),
        path.clone(),
        slot,
        Arc::new(|_pid| None),
        Arc::new(|_| panic!("an upstream refusal must never reach the redeemer")),
    );
    await_socket(&path);

    assert_eq!(probe_reply(&path), "REFUSED UPSTREAM\n");
    assert_eq!(probe(&path), ProbeOutcome::Refused("UPSTREAM".to_owned()));
    assert_eq!(
        request(&path, 60, RECEIPT),
        Err(RequestFailure::Refused("UPSTREAM".to_owned()))
    );
}

#[test]
fn client_failures_distinguish_refusal_from_a_missing_daemon() {
    // A healthy socket that refuses and a path with no socket at all must be
    // reported differently; conflating them sends diagnosis the wrong way.
    let directory = tempfile::tempdir().unwrap();
    let missing = directory.path().join("nobody-home.sock");
    assert_eq!(probe(&missing), ProbeOutcome::Unreachable);
    assert_eq!(
        request(&missing, 60, RECEIPT),
        Err(RequestFailure::Unreachable)
    );

    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, _receiver) = feed_acceptor();
    spawn_server(
        grants,
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| None),
        rejecting_redeemer(),
    );
    await_socket(&path);

    assert_eq!(
        request(&path, 60, RECEIPT),
        Err(RequestFailure::Refused("RECEIPT".to_owned()))
    );
}

#[test]
fn a_probed_socket_still_serves_a_following_grant() {
    // The probe and the grant arrive on separate connections; a probe must
    // leave the accept loop ready for the real request.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, receiver) = feed_acceptor();
    spawn_server(
        grants,
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| Some("session-a".to_owned())),
        accepting_redeemer(),
    );
    await_socket(&path);

    assert_eq!(probe(&path), ProbeOutcome::Grantable);
    request(&path, 60, RECEIPT).expect("the grant after a probe must succeed");
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
}

#[test]
fn an_unknown_probe_reply_reads_as_unreachable() {
    // A daemon speaking a different protocol must not read as "grantable".
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("weird.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut sink = [0_u8; 16];
        let _ = stream.read(&mut sink);
        stream.write_all(b"HELLO v9\n").unwrap();
    });

    assert_eq!(probe(&path), ProbeOutcome::Unreachable);
    server.join().unwrap();
}
