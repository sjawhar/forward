use std::io::{Read as _, Write as _};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use forward::browser::grant::Grants;
use forward::browser::proxy;

use super::{
    assert_not_dialed, assert_refused, current_anchor, grant, insert_grant, listener, resolver,
    spawn_relay_upstream, unconnected_upstream,
};

#[test]
fn granted_owner_is_proxied_with_one_relay_token_prefix() {
    // This fails if the proxy omits or duplicates the header, or does not pipe
    // the client payload and relay response.
    let grants = Grants::new();
    let (upstream, task) = spawn_relay_upstream(b"ping");
    let proxy = proxy::bind(grants.clone(), upstream).unwrap();
    let port = proxy.port();
    insert_grant(
        &grants,
        port,
        grant(current_anchor(), Instant::now() + Duration::from_secs(60)),
    );
    proxy.serve();

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).unwrap();

    assert_eq!(&reply, b"pong");
    task.join().unwrap();
}

#[test]
fn port_with_no_live_grant_is_refused() {
    // This fails if an ungranted endpoint is allowed to reach the relay.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let (listener, port) = listener();
    proxy::spawn_with_listener(
        grants,
        listener,
        upstream.local_addr().unwrap(),
        resolver(Some(std::process::id())),
    );

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_refused(&mut client, b"REFUSED UNGRANTED\n");
    assert_not_dialed(&upstream);
}

#[test]
fn expired_grant_is_refused_as_ungranted() {
    // This fails if a past deadline is treated as a live authorization.
    let grants = Grants::new();
    let upstream = unconnected_upstream();
    let (listener, port) = listener();
    insert_grant(
        &grants,
        port,
        grant(current_anchor(), Instant::now() - Duration::from_secs(1)),
    );
    proxy::spawn_with_listener(
        grants,
        listener,
        upstream.local_addr().unwrap(),
        resolver(Some(std::process::id())),
    );

    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client.write_all(b"ping").unwrap();

    assert_refused(&mut client, b"REFUSED UNGRANTED\n");
    assert_not_dialed(&upstream);
}

#[test]
fn reaper_closes_the_listener_without_a_client_connection() {
    // This fails if expiry only removes the grant and does not wake accept.
    let grants = Grants::new();
    let upstream = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let proxy = proxy::bind(grants.clone(), upstream).unwrap();
    let port = proxy.port();
    let deadline = Instant::now() + Duration::from_millis(50);
    insert_grant(&grants, port, grant(current_anchor(), deadline));
    proxy::reap_at(grants.clone(), port, deadline);
    proxy.serve();

    thread::sleep(Duration::from_secs(1));

    assert!(TcpStream::connect(("127.0.0.1", port)).is_err());
    assert!(grants.live(port).is_none());
}
