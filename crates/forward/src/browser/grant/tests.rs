use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

use super::*;

fn grant(session: &str, ttl: Duration) -> Grant {
    Grant {
        session: session.to_owned(),
        anchor: ProcessAnchor::new(1, 1),
        token: b"correct-horse".to_vec(),
        deadline: Instant::now() + ttl,
    }
}

#[test]
fn a_live_grant_is_returned_for_its_port() {
    let grants = Grants::new();
    grants.insert(12811, grant("session-a", Duration::from_secs(60)));
    assert_eq!(grants.live(12811).unwrap().session, "session-a");
}

#[test]
fn an_expired_grant_is_not_returned() {
    let grants = Grants::new();
    grants.insert(12811, grant("session-a", Duration::from_millis(1)));
    std::thread::sleep(Duration::from_millis(5));
    assert!(grants.live(12811).is_none());
}

#[test]
fn an_unknown_port_has_no_grant() {
    assert!(Grants::new().live(12811).is_none());
}

#[test]
fn expiring_one_grant_leaves_another_usable() {
    // The token is shared by every grant, so dropping one must not disarm
    // the other.
    let grants = Grants::new();
    grants.insert(12811, grant("session-a", Duration::from_secs(60)));
    grants.insert(12812, grant("session-b", Duration::from_secs(60)));
    grants.expire(12811);
    assert!(grants.live(12811).is_none());
    assert_eq!(grants.live(12812).unwrap().session, "session-b");
}

#[test]
fn clones_share_one_registry() {
    let grants = Grants::new();
    let clone = grants.clone();
    grants.insert(12811, grant("session-a", Duration::from_secs(60)));
    assert!(clone.live(12811).is_some());
}

#[test]
fn replacing_a_grant_retires_its_predecessor() {
    let grants = Grants::new();
    grants.insert(12811, grant("session-a", Duration::from_secs(60)));
    grants.insert(12811, grant("session-b", Duration::from_secs(60)));
    assert_eq!(grants.live(12811).unwrap().session, "session-b");
}

#[test]
fn expiring_a_grant_removes_its_token_from_the_registry() {
    let grants = Grants::new();
    grants.insert(12811, grant("session-a", Duration::from_secs(60)));
    grants.expire(12811);
    assert!(grants.live(12811).is_none());
}

#[test]
fn an_accepted_grant_expiring_before_registration_leaves_no_pipe() {
    // This fails if `register_pipe` only records handles: an accepted handler
    // can otherwise outlive the expired authorization in the pipe table.
    let grants = Grants::new();
    let port = 12811;
    grants.insert(port, grant("session-a", Duration::from_secs(60)));
    let (grant_id, _accepted_grant) = grants.live_with_id(port).expect("grant is live at accept");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (laptop, _) = listener.accept().unwrap();

    grants.expire(port);

    assert!(
        grants
            .register_pipe(port, grant_id, &client, &laptop)
            .is_err()
    );
    assert!(grants.pipes.lock().is_empty());
}
#[test]
fn a_reused_port_rejects_a_handler_accepted_under_the_prior_grant() {
    // This fails if registration looks only at port liveness: a handler that
    // captured grant A could otherwise register beneath replacement grant B.
    let grants = Grants::new();
    let port = 12811;
    grants.insert(port, grant("session-a", Duration::from_secs(60)));
    let (grant_id, _accepted_grant) = grants.live_with_id(port).expect("grant A is live");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (laptop, _) = listener.accept().unwrap();

    grants.expire(port);
    grants.insert(port, grant("session-b", Duration::from_secs(60)));

    assert!(
        grants
            .register_pipe(port, grant_id, &client, &laptop)
            .is_err()
    );
    assert_eq!(grants.live(port).unwrap().session, "session-b");
    assert!(grants.pipes.lock().is_empty());
}

#[test]
fn expiring_a_grant_overwrites_its_removed_token() {
    let mut ports = HashMap::new();
    let original = grant("session-a", Duration::from_secs(60));
    let token_len = original.token.len();
    ports.insert(
        12811,
        GrantEntry {
            id: 0,
            grant: original,
        },
    );

    let expired = scrub(&mut ports, 12811).expect("the grant is removed");

    assert!(ports.is_empty());
    // SAFETY: `zeroize` clears the Vec length but keeps its allocation;
    // `token_len` bytes are initialized and within that allocation.
    let wiped = unsafe { std::slice::from_raw_parts(expired.grant.token.as_ptr(), token_len) };
    assert!(
        wiped.iter().all(|byte| *byte == 0),
        "removed token buffer was not overwritten"
    );
    assert!(expired.grant.token.is_empty());
}

#[test]
fn a_live_grant_is_found_for_its_process_anchor() {
    let caller = ProcessAnchor::new(
        std::process::id(),
        crate::browser::peer::process_start(std::process::id()).unwrap(),
    );
    let grants = Grants::new();
    let mut owned = grant("session-a", Duration::from_secs(60));
    owned.anchor = caller;
    grants.insert(12811, owned);
    grants.insert(12812, grant("session-b", Duration::from_secs(60)));

    let (port, found) = grants.live_for_descendant(caller).unwrap();
    assert_eq!((port, found.session.as_str()), (12811, "session-a"));
}
#[test]
fn snapshot_live_excludes_expired_grants_and_preserves_a_positive_ttl() {
    let grants = Grants::new();
    grants.insert(12811, grant("live", Duration::from_secs(60)));
    grants.insert(12812, grant("expired", Duration::from_millis(1)));
    std::thread::sleep(Duration::from_millis(5));

    let snapshot = grants.snapshot_live();

    assert_eq!(snapshot.len(), 1);
    assert!(snapshot[0].0.as_slice() == b"correct-horse");
    assert!(snapshot[0].1 > 0);
}

#[test]
fn a_grant_redeemed_by_prior_instance_cannot_insert_at_matching_epoch() {
    // This fails if the registry compares only epoch: broker-b at epoch 0
    // would accept a receipt redeemed from broker-a at that same epoch.
    let grants = Grants::new();
    let redeemed = crate::secretsd::BrokerIdentity {
        instance: "broker-a".to_owned(),
        epoch: 0,
    };
    grants.observe_authority(redeemed.clone());
    grants.observe_authority(crate::secretsd::BrokerIdentity {
        instance: "broker-b".to_owned(),
        epoch: 0,
    });

    assert!(!grants.insert_if_authority(
        12811,
        &redeemed,
        grant("session-a", Duration::from_secs(60))
    ));
    assert!(grants.live(12811).is_none());
}
