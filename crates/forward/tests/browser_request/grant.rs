use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use forward::browser::push::FeedSlot;
use forward::browser::request::request;

use super::{
    RECEIPT, accepting_redeemer, await_socket, feed_acceptor, grant_config, redeemer_with_ttl,
    rejecting_redeemer, request_reply, spawn_server,
};

#[test]
fn a_redeemed_receipt_grants_a_port_and_pushes_a_fresh_token() {
    // This fails if the receipt is not verified, the token is not minted
    // server-side, or the laptop is not told before the port is returned.
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

    let port = request(&path, 60, RECEIPT).expect("the grant request must succeed");
    let (token, _) = receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    assert_eq!(token.len(), 43);
    assert!(
        grants
            .live(port)
            .is_some_and(|grant| grant.token.as_slice() == token.as_slice())
    );
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

    let port = request(&path, 3_600, RECEIPT).expect("broker-bounded grant succeeds");
    let (_, feed_ttl) = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    let remaining = grants
        .live(port)
        .expect("grant was inserted")
        .deadline
        .saturating_duration_since(Instant::now());

    assert_eq!(feed_ttl, 2);
    assert!(remaining <= Duration::from_secs(2));
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
