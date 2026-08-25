use std::io::Write as _;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use forward::browser::grant::{Grants, ProcessAnchor};
use forward::browser::proxy;

use super::{
    assert_not_dialed, assert_refused, current_anchor, grant, insert_grant, listener, resolver,
    unconnected_upstream,
};

#[test]
fn connection_outside_the_granted_process_ancestry_is_refused_without_dialing() {
    // This fails if the owner check is removed: the intentionally mismatched
    // start time makes this client outside the grant's process anchor.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let (listener, port) = listener();
    let wrong_anchor = current_anchor();
    let wrong_anchor = ProcessAnchor::new(wrong_anchor.pid, wrong_anchor.start + 1);
    insert_grant(
        &grants,
        port,
        grant(wrong_anchor, Instant::now() + Duration::from_secs(60)),
    );
    proxy::spawn_with_listener(
        grants,
        listener,
        upstream.local_addr().unwrap(),
        resolver(Some(std::process::id())),
    );

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_refused(&mut client, b"REFUSED SESSION\n");
    assert_not_dialed(&upstream);
}

#[test]
fn unresolvable_connection_is_refused_without_dialing() {
    // This fails if a missing socket owner is treated as authorized.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let (listener, port) = listener();
    insert_grant(
        &grants,
        port,
        grant(current_anchor(), Instant::now() + Duration::from_secs(60)),
    );
    proxy::spawn_with_listener(
        grants,
        listener,
        upstream.local_addr().unwrap(),
        resolver(None),
    );

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_refused(&mut client, b"REFUSED SESSION\n");
    assert_not_dialed(&upstream);
}
