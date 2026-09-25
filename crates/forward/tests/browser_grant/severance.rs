use std::io::{Read as _, Write as _};
use std::sync::Arc;
use std::time::{Duration, Instant};

use forward::browser::grant::Grants;
use forward::browser::relay::Resolver;

use super::{assert_not_dialed, endpoint, resolver, spawn_held_upstream, unconnected_upstream};

#[test]
fn a_grant_that_ends_before_admission_is_never_piped() {
    // The endpoint and the registry are in different processes, so a grant can
    // end while a client is mid-handshake with its relay. This fails if the
    // ending does not reach the control channel: the connection would be
    // handed over and piped under a grant that no longer exists.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let ending = Arc::new(parking_lot::Mutex::new(None::<(Grants, u64)>));
    let ending_for_resolver = Arc::clone(&ending);
    let resolver: Resolver = Arc::new(move |_, _| {
        if let Some((grants, id)) = ending_for_resolver.lock().take() {
            grants.expire(id);
        }
        Some(std::process::id())
    });
    let endpoint = endpoint::start(
        &grants,
        upstream.local_addr().unwrap(),
        Instant::now() + Duration::from_secs(60),
        resolver,
    );
    *ending.lock() = Some((grants.clone(), endpoint.id));

    let mut client = endpoint.connect();
    let _ = client.write_all(b"ping");

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut sink = [0_u8; 16];
    assert!(
        matches!(client.read(&mut sink), Ok(0) | Err(_)),
        "a connection was served under a grant that had ended"
    );
    assert_not_dialed(&upstream);
    assert!(grants.live(endpoint.id).is_none());
    endpoint.assert_retired(Duration::from_secs(5));
}

#[test]
fn expiring_a_grant_severs_an_established_pipe_and_retires_its_endpoint() {
    // The revocation acceptance test. CDP multiplexes a whole session over one
    // long-lived websocket, so a grant ending that only refuses *new*
    // connections leaves the established session driving the browser until its
    // TTL. This fails if `expire` merely removes the registry row, which is
    // exactly what it did before pipes were registered with their grant.
    let grants = Grants::new();
    let (upstream, established, task) = spawn_held_upstream();
    let endpoint = endpoint::start(
        &grants,
        upstream,
        Instant::now() + Duration::from_secs(600),
        resolver(Some(std::process::id())),
    );

    let mut client = endpoint.connect();
    client.write_all(b"hold").unwrap();
    // The upstream has read the payload, so the pipe is registered and moving.
    established
        .recv_timeout(Duration::from_secs(5))
        .expect("pipe established");

    grants.expire(endpoint.id);

    // The established connection must end promptly -- the grant's TTL had ten
    // minutes left and the idle timeout is fifteen, so only severance explains
    // an EOF inside this window.
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut buffer = [0_u8; 16];
    // EOF specifically: a read timeout also lands in Err, and accepting any
    // error let the gutted implementation pass this test.
    let outcome = client.read(&mut buffer);
    assert!(
        matches!(outcome, Ok(0)),
        "an established pipe survived its grant's expiry: {outcome:?}"
    );
    task.join().unwrap();

    // And the endpoint itself is gone, not merely refusing.
    endpoint.assert_retired(Duration::from_secs(5));
}
