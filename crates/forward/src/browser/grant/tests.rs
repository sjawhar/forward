use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use super::*;

mod lifetime;

const ENDPOINT_PORT: u16 = 12811;

fn grant(session: &str, ttl: Duration) -> Grant {
    at_port(session, ttl, ENDPOINT_PORT)
}

fn at_port(session: &str, ttl: Duration, endpoint_port: u16) -> Grant {
    Grant {
        session: session.to_owned(),
        anchor: ProcessAnchor::new(1, 1),
        token: b"correct-horse".to_vec(),
        deadline: Instant::now() + ttl,
        endpoint_port,
    }
}

/// A stand-in for the control channel a real grant keeps open. The returned
/// end is the caller's: hold it, or the grant reads as already ended.
fn control() -> (UnixStream, UnixStream) {
    UnixStream::pair().unwrap()
}

fn insert(grants: &Grants, grant: Grant) -> (u64, UnixStream) {
    let (server, caller) = control();
    let id = grants
        .insert(grant, &server)
        .expect("the grant is inserted");
    (id, caller)
}

#[test]
fn a_live_grant_is_returned_for_its_id() {
    let grants = Grants::new();
    let (id, _caller) = insert(&grants, grant("session-a", Duration::from_secs(60)));
    assert_eq!(grants.live(id).unwrap().session, "session-a");
}

#[test]
fn an_expired_grant_is_not_returned() {
    let grants = Grants::new();
    let (id, _caller) = insert(&grants, grant("session-a", Duration::from_millis(1)));
    std::thread::sleep(Duration::from_millis(5));
    assert!(grants.live(id).is_none());
}

#[test]
fn an_unknown_id_has_no_grant() {
    assert!(Grants::new().live(0).is_none());
}

#[test]
fn two_grants_on_one_endpoint_port_are_separate_grants() {
    // Ports are no longer unique: a grant's endpoint lives in its caller's
    // network namespace, so two agent boxes can hold 12811 at the same time.
    // This fails if the registry is keyed by port again -- the second insert
    // would replace the first, and expiring either would end both.
    let grants = Grants::new();
    let (first, _first_caller) = insert(
        &grants,
        at_port("session-a", Duration::from_secs(60), ENDPOINT_PORT),
    );
    let (second, _second_caller) = insert(
        &grants,
        at_port("session-b", Duration::from_secs(60), ENDPOINT_PORT),
    );

    grants.expire(first);

    assert!(grants.live(first).is_none());
    assert_eq!(grants.live(second).unwrap().session, "session-b");
    assert_eq!(grants.live(second).unwrap().endpoint_port, ENDPOINT_PORT);
}

#[test]
fn clones_share_one_registry() {
    let grants = Grants::new();
    let clone = grants.clone();
    let (id, _caller) = insert(&grants, grant("session-a", Duration::from_secs(60)));
    assert!(clone.live(id).is_some());
}

#[test]
fn expiring_a_grant_overwrites_its_removed_token() {
    let mut registry = HashMap::new();
    let original = grant("session-a", Duration::from_secs(60));
    let token_len = original.token.len();
    let (server, _caller) = control();
    registry.insert(
        7,
        GrantEntry {
            grant: original,
            control: server,
        },
    );

    let expired = scrub(&mut registry, 7).expect("the grant is removed");

    assert!(registry.is_empty());
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
    let mut owned = at_port("session-a", Duration::from_secs(60), 38_987);
    owned.anchor = caller;
    let (_, _owned_caller) = insert(&grants, owned);
    let (_, _other_caller) = insert(&grants, grant("session-b", Duration::from_secs(60)));

    let (port, found) = grants.live_for_descendant(caller).unwrap();

    assert_eq!((port, found.session.as_str()), (38_987, "session-a"));
}

#[test]
fn snapshot_live_excludes_expired_grants_and_preserves_a_positive_ttl() {
    let grants = Grants::new();
    let (_, _live_caller) = insert(&grants, grant("live", Duration::from_secs(60)));
    let (_, _expired_caller) = insert(&grants, grant("expired", Duration::from_millis(1)));
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
        socket: crate::secretsd::SocketIdentity {
            device: 50,
            inode: 283,
        },
    };
    grants.observe_authority(redeemed.clone());
    grants.observe_authority(crate::secretsd::BrokerIdentity {
        instance: "broker-b".to_owned(),
        epoch: 0,
        socket: crate::secretsd::SocketIdentity {
            device: 50,
            inode: 283,
        },
    });
    let (server, _caller) = control();

    assert!(
        grants
            .insert_if_authority(
                &redeemed,
                grant("session-a", Duration::from_secs(60)),
                &server
            )
            .is_none()
    );
    assert!(grants.snapshot_live().is_empty());
}
