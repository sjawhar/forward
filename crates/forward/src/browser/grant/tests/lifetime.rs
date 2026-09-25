//! What every ending of a grant must do to the state it was holding.

use std::io::Read as _;
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use super::{Grants, control, grant, insert};

/// Whether the caller's end of a control channel has been closed on it.
fn ended(caller: &UnixStream) -> bool {
    caller
        .set_read_timeout(Some(Duration::from_secs(5)))
        .is_ok()
        && matches!((&mut &*caller).read(&mut [0_u8; 1]), Ok(0))
}

fn pipe_pair() -> (TcpStream, TcpStream, TcpListener) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (laptop, _) = listener.accept().unwrap();
    (client, laptop, listener)
}

#[test]
fn expiring_a_grant_closes_the_control_channel_its_relay_is_watching() {
    // The relay has no other cue: its listener is in another namespace and
    // nothing dials it to wake it. This fails if expiry only drops the
    // registry row, leaving an endpoint accepting for a grant that is gone.
    let grants = Grants::new();
    let (id, caller) = insert(&grants, grant("session-a", Duration::from_secs(600)));

    grants.expire(id);

    assert!(ended(&caller), "the control channel outlived its grant");
}

#[test]
fn a_changed_broker_authority_closes_every_control_channel() {
    // `secrets lock` and a broker restart both arrive this way, and both must
    // retire the endpoints, not merely the registry rows.
    let grants = Grants::new();
    let first = crate::secretsd::BrokerIdentity {
        instance: "broker-a".to_owned(),
        epoch: 0,
        socket: crate::secretsd::SocketIdentity {
            device: 50,
            inode: 283,
        },
    };
    grants.observe_authority(first.clone());
    let (server, caller) = control();
    let id = grants
        .insert_if_authority(
            &first,
            grant("session-a", Duration::from_secs(600)),
            &server,
        )
        .expect("the grant is inserted under the observed authority");

    assert!(grants.observe_authority(crate::secretsd::BrokerIdentity { epoch: 1, ..first }));

    assert!(grants.live(id).is_none());
    assert!(ended(&caller), "the control channel survived revocation");
}

#[test]
fn an_accepted_grant_expiring_before_registration_leaves_no_pipe() {
    // This fails if `register_pipe` only records handles: an accepted handler
    // can otherwise outlive the expired authorization in the pipe table.
    let grants = Grants::new();
    let (id, _caller) = insert(&grants, grant("session-a", Duration::from_secs(60)));
    let (client, laptop, _listener) = pipe_pair();

    grants.expire(id);

    assert!(grants.register_pipe(id, &client, &laptop).is_err());
    assert!(grants.pipes.lock().is_empty());
}

#[test]
fn a_replacement_grant_rejects_a_handler_accepted_under_its_predecessor() {
    // This fails if registration looks only at the pipe table: a handler that
    // captured grant A could otherwise register beneath replacement grant B.
    let grants = Grants::new();
    let (first, _first_caller) = insert(&grants, grant("session-a", Duration::from_secs(60)));
    let (client, laptop, _listener) = pipe_pair();

    grants.expire(first);
    let (second, _second_caller) = insert(&grants, grant("session-b", Duration::from_secs(60)));

    assert!(grants.register_pipe(first, &client, &laptop).is_err());
    assert_eq!(grants.live(second).unwrap().session, "session-b");
    assert!(grants.pipes.lock().is_empty());
}

#[test]
fn the_reaper_ends_a_grant_no_client_ever_connected_to() {
    // The old reaper woke its own accept loop by dialing the port it had
    // bound. There is no such port here, so the deadline has to reach the
    // caller through the control channel or not at all.
    let grants = Grants::new();
    let (id, caller) = insert(&grants, grant("session-a", Duration::from_millis(50)));

    grants.reap_at(id, std::time::Instant::now() + Duration::from_millis(50));

    assert!(ended(&caller), "the deadline never reached the endpoint");
    assert!(grants.live(id).is_none());
}
