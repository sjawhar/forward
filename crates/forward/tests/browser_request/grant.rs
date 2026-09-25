use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use forward::browser::grant::ProcessAnchor;
use forward::browser::peer::process_start;
use forward::browser::push::FeedSlot;
use forward::browser::request::request;

use super::{
    RECEIPT, accepting_redeemer, await_socket, endpoint, feed_acceptor, grant_config,
    redeemer_with_ttl, rejecting_redeemer, reply_for_port, request_reply, spawn_server,
};

fn caller_anchor() -> ProcessAnchor {
    let pid = std::process::id();
    ProcessAnchor::new(pid, process_start(pid).unwrap())
}

#[test]
fn a_redeemed_receipt_records_the_callers_endpoint_and_pushes_a_fresh_token() {
    // This fails if the receipt is not verified, the token is not minted
    // server-side, the laptop is not told before the grant is recorded, or the
    // endpoint the caller bound is not the one `STATUS` will report.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, receiver) = feed_acceptor();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| Some("session-a".to_owned())),
        accepting_redeemer(),
    );
    await_socket(&path);
    let (_listener, port) = endpoint();

    let control = request(&path, 60, RECEIPT, port).expect("the grant request must succeed");
    let (token, _) = receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    assert_eq!(token.len(), 43);
    let (recorded_port, grant) = grants
        .live_for_descendant(caller_anchor())
        .expect("the grant was recorded for this caller");
    assert_eq!(recorded_port, port);
    assert_eq!(grant.token.as_slice(), token.as_slice());
    drop(control);
}

#[test]
fn the_grant_ends_when_its_control_channel_closes() {
    // The control channel is the grant's lifeline: a caller that dies without
    // saying so must not leave a live grant and a usable laptop token behind.
    // This fails if forward serve keeps a grant whose caller is gone.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, receiver) = feed_acceptor();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| Some("session-a".to_owned())),
        accepting_redeemer(),
    );
    await_socket(&path);
    let (_listener, port) = endpoint();
    let control = request(&path, 60, RECEIPT, port).expect("the grant request must succeed");
    receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(grants.live_for_descendant(caller_anchor()).is_some());

    drop(control);

    let deadline = Instant::now() + Duration::from_secs(5);
    while grants.live_for_descendant(caller_anchor()).is_some() {
        assert!(
            Instant::now() < deadline,
            "the grant outlived the caller that held it"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(grants.snapshot_live().is_empty());
}

#[test]
fn a_broker_deadline_clamps_the_grant_and_feed_ttl() {
    // This fails if forward trusts the requested hour rather than the broker's
    // two-second capability deadline for either cached representation.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, receiver) = feed_acceptor();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| Some("session-a".to_owned())),
        redeemer_with_ttl(2),
    );
    await_socket(&path);
    let (_listener, port) = endpoint();

    let control = request(&path, 3_600, RECEIPT, port).expect("broker-bounded grant succeeds");
    let (_, feed_ttl) = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    let remaining = grants
        .live_for_descendant(caller_anchor())
        .expect("grant was inserted")
        .1
        .deadline
        .saturating_duration_since(Instant::now());

    assert_eq!(feed_ttl, 2);
    assert!(remaining <= Duration::from_secs(2));
    drop(control);
}

#[test]
fn a_request_without_a_usable_endpoint_port_is_refused_before_the_broker() {
    // The port is not optional any more: a grant with no endpoint behind it is
    // exactly the bug this shape exists to prevent. Both shapes a caller can
    // get wrong -- the old three-field line, and a port it never bound -- must
    // be refused, and neither may cost a receipt.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, _receiver) = feed_acceptor();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| Some("session-a".to_owned())),
        Arc::new(|_| panic!("a malformed request must not reach the redeemer")),
    );
    await_socket(&path);

    assert_eq!(without_a_port(&path), "REFUSED\n");
    assert_eq!(reply_for_port(&path, 60, RECEIPT, 0), "REFUSED\n");
    assert!(grants.snapshot_live().is_empty());
}

/// The request line a `forward browser grant` from before this shape sends.
fn without_a_port(path: &std::path::Path) -> String {
    use std::io::{BufRead as _, Write as _};

    let mut stream = std::os::unix::net::UnixStream::connect(path).unwrap();
    stream.write_all(b"GRANT 60 ").unwrap();
    stream.write_all(RECEIPT).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply = String::new();
    std::io::BufReader::new(stream)
        .read_line(&mut reply)
        .unwrap();
    reply
}

#[test]
fn a_rejected_receipt_is_refused_without_granting() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, receiver) = feed_acceptor();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| Some("session-a".to_owned())),
        rejecting_redeemer(),
    );
    await_socket(&path);

    assert_eq!(request_reply(&path, 60, RECEIPT), "REFUSED RECEIPT\n");
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(grants.snapshot_live().is_empty());
}

#[test]
fn an_unreachable_laptop_feed_refuses_the_grant() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        FeedSlot::new(),
        Arc::new(|_pid| Some("session-a".to_owned())),
        accepting_redeemer(),
    );
    await_socket(&path);

    assert_eq!(request_reply(&path, 60, RECEIPT), "REFUSED LAPTOP\n");
    assert!(grants.snapshot_live().is_empty());
}
