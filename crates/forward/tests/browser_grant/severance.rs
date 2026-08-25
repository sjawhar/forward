use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use forward::browser::grant::Grants;
use forward::browser::proxy::{self, Resolver};

use super::{assert_refused, current_anchor, grant, insert_grant, listener, spawn_held_upstream};

#[test]
fn expiry_after_accept_refuses_without_piping_the_stale_grant() {
    // This fails if registration trusts the accept-time grant clone: expiry
    // then runs before `handle` registers, leaving an unseverable pipe behind.
    let grants = Grants::new();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let (forwarded, observed) = std::sync::mpsc::channel();
    let upstream_task = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut header = Vec::new();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            header.push(byte[0]);
        }
        assert_eq!(header, b"RELAY correct-horse");
        let mut payload = [0_u8; 4];
        let received = stream.read(&mut payload).unwrap();
        if received > 0 {
            stream.write_all(b"FORWARDED").unwrap();
        }
        forwarded.send(received).unwrap();
    });
    let (listener, port) = listener();
    insert_grant(
        &grants,
        port,
        grant(current_anchor(), Instant::now() + Duration::from_secs(60)),
    );
    let expiring_grants = grants.clone();
    let resolver: Resolver = Arc::new(move |_, _| {
        expiring_grants.expire(port);
        Some(std::process::id())
    });
    proxy::spawn_with_listener(grants.clone(), listener, upstream_address, resolver);

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_refused(&mut client, b"REFUSED UNGRANTED\n");
    assert_eq!(observed.recv_timeout(Duration::from_secs(5)).unwrap(), 0);
    upstream_task.join().unwrap();
    assert!(grants.live(port).is_none());
}

#[test]
fn expiring_a_grant_severs_an_established_pipe() {
    // The revocation acceptance test. CDP multiplexes a whole session over one
    // long-lived websocket, so a grant ending that only refuses *new*
    // connections leaves the established session driving the browser until its
    // TTL. This fails if `expire` merely removes the registry row, which is
    // exactly what it did before pipes were registered with their grant.
    let grants = Grants::new();
    let (upstream, established, task) = spawn_held_upstream();
    let proxy = proxy::bind(grants.clone(), upstream).unwrap();
    let port = proxy.port();
    insert_grant(
        &grants,
        port,
        grant(current_anchor(), Instant::now() + Duration::from_secs(600)),
    );
    proxy.serve();

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"hold").unwrap();
    // The upstream has read the payload, so the pipe is registered and moving.
    established
        .recv_timeout(Duration::from_secs(5))
        .expect("pipe established");

    grants.expire(port);

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

    // And a fresh connection is refused, not proxied.
    let mut late = TcpStream::connect(("127.0.0.1", port)).unwrap();
    assert_refused(&mut late, b"REFUSED UNGRANTED\n");
}
