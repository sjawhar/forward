use std::io::{Read as _, Write as _};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use forward::browser::grant::Grants;

use super::endpoint::{self, accepted_pair, control_only};
use super::{
    assert_not_dialed, assert_refused, resolver, spawn_relay_upstream, unconnected_upstream,
};

#[test]
fn an_admitted_client_reaches_the_laptop_under_one_relay_token_prefix() {
    // The whole path: the caller's own relay admits the client, hands the
    // socket to forward serve by descriptor, and forward serve presents the
    // token the caller never sees. This fails if the header is omitted or
    // duplicated, or if the payload and response are not piped.
    let grants = Grants::new();
    let (upstream, task) = spawn_relay_upstream(b"ping");
    let endpoint = endpoint::start(
        &grants,
        upstream,
        Instant::now() + Duration::from_secs(60),
        resolver(Some(std::process::id())),
    );

    let mut client = endpoint.connect();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).unwrap();

    assert_eq!(&reply, b"pong");
    task.join().unwrap();
}

#[test]
fn a_connection_for_a_grant_that_is_no_longer_live_is_refused_without_dialing() {
    // The grant can end between the relay's hand-over and the registry
    // lookup. This fails if forward serve pipes whatever arrives on a control
    // channel instead of rechecking the grant it belongs to.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let channel = control_only(&grants, 7, upstream.local_addr().unwrap());
    let (mut client, accepted, _listener) = accepted_pair();

    channel.hand_over(&accepted);

    assert_refused(&mut client, b"REFUSED UNGRANTED\n");
    assert_not_dialed(&upstream);
}

#[test]
fn a_connection_for_an_expired_grant_is_refused_without_dialing() {
    // This fails if a past deadline is treated as a live authorization: the
    // registry still holds the row until something looks at it.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let (server, _caller) = UnixStream::pair().unwrap();
    let id = super::insert_grant(
        &grants,
        super::grant(
            super::current_anchor(),
            Instant::now() - Duration::from_secs(1),
            12_811,
        ),
        &server,
    );
    let channel = control_only(&grants, id, upstream.local_addr().unwrap());
    let (mut client, accepted, _listener) = accepted_pair();

    channel.hand_over(&accepted);

    assert_refused(&mut client, b"REFUSED UNGRANTED\n");
    assert_not_dialed(&upstream);
}

#[test]
fn a_descriptor_that_is_not_an_inet_stream_is_dropped_and_the_grant_keeps_serving() {
    // A unix socket passes the SO_TYPE check, so only the family check stops
    // it. This fails if forward serve relays whatever descriptor it is handed:
    // the laptop would be given the grant's token on a pipe to something no
    // relay ever accepted. The valid connection afterwards proves that one
    // bad descriptor does not cost the caller its grant.
    let grants = Grants::new();
    let (upstream, task) = spawn_relay_upstream(b"ping");
    let (server, _caller) = UnixStream::pair().unwrap();
    let id = super::insert_grant(
        &grants,
        super::grant(
            super::current_anchor(),
            Instant::now() + Duration::from_secs(60),
            12_811,
        ),
        &server,
    );
    let channel = control_only(&grants, id, upstream);
    let (_local, remote) = UnixStream::pair().unwrap();
    let (mut client, accepted, _listener) = accepted_pair();

    channel.hand_over(&remote);
    channel.hand_over(&accepted);
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).unwrap();

    assert_eq!(&reply, b"pong");
    task.join().unwrap();
    assert!(grants.live(id).is_some());
}

#[test]
fn the_reaper_retires_an_endpoint_no_client_ever_connected_to() {
    // This fails if expiry only removes the registry row: the caller's relay
    // would keep accepting for a grant forward serve no longer holds. Nothing
    // connects until the deadline has passed, so the retirement is the
    // deadline's doing and not a client's.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let deadline = Instant::now() + Duration::from_millis(50);
    let endpoint = endpoint::start(
        &grants,
        upstream.local_addr().unwrap(),
        deadline,
        resolver(Some(std::process::id())),
    );
    grants.reap_at(endpoint.id, deadline);

    std::thread::sleep(Duration::from_millis(300));
    endpoint.assert_retired(Duration::from_secs(5));

    assert!(grants.live(endpoint.id).is_none());
    assert_not_dialed(&upstream);
}
