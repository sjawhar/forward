use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::Duration;

const CALLBACK_REQUEST: &str = "GET /cb?code=1 HTTP/1.1\r\n\r\n";
const SOCKET_WAIT: Duration = Duration::from_secs(5);

/// Stands in for the devbox bridge: reports the `CONNECT <port>` line it was
/// asked for, then echoes everything after it.
fn spawn_fake_bridge() -> (u16, Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let tx = tx.clone();
            std::thread::spawn(move || echo(stream, &tx));
        }
    });
    (port, rx)
}

/// Reads the request line a byte at a time: a `BufReader` would swallow the
/// payload that follows it.
fn echo(mut stream: TcpStream, tx: &Sender<String>) {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while stream.read(&mut byte).unwrap_or(0) == 1 && byte[0] != b'\n' {
        line.push(byte[0]);
    }
    tx.send(String::from_utf8_lossy(&line).trim().to_owned())
        .unwrap();
    let mut chunk = [0u8; 512];
    while let Ok(read) = stream.read(&mut chunk) {
        if read == 0 || stream.write_all(&chunk[..read]).is_err() {
            return;
        }
    }
}

fn cfg(bridge_port: u16) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.bridge_port = bridge_port;
    cfg.peer = "127.0.0.1".to_owned();
    cfg.forward_ttl_secs = 30;
    cfg
}

fn socket_addr(address: &str, port: u16) -> SocketAddr {
    SocketAddr::new(address.parse::<IpAddr>().unwrap(), port)
}

fn connect(address: &str, port: u16) -> TcpStream {
    let stream = TcpStream::connect_timeout(&socket_addr(address, port), SOCKET_WAIT).unwrap();
    stream.set_read_timeout(Some(SOCKET_WAIT)).unwrap();
    stream.set_write_timeout(Some(SOCKET_WAIT)).unwrap();
    stream
}

fn connection_is_refused(port: u16) -> bool {
    TcpStream::connect_timeout(&socket_addr("127.0.0.1", port), Duration::from_millis(100)).is_err()
}

fn read_back(stream: &mut TcpStream, expected: &str) -> String {
    let mut buffer = vec![0u8; expected.len()];
    stream.read_exact(&mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

fn asked_for(requests: &Receiver<String>) -> String {
    requests.recv_timeout(SOCKET_WAIT).unwrap()
}

#[test]
fn a_callback_port_is_served_on_loopback_and_relayed_to_the_bridge() {
    // Given: a fake devbox bridge.
    let (bridge_port, requests) = spawn_fake_bridge();
    let leases = forward::callback::Leases::new();

    // When: the daemon is asked for a callback port and a browser connects to it.
    let port = forward::callback::request_on(&cfg(bridge_port), &leases, 0).unwrap();
    let mut browser = connect("127.0.0.1", port);
    browser.write_all(CALLBACK_REQUEST.as_bytes()).unwrap();

    // Then: the bridge is asked for exactly that port, and bytes flow back.
    assert_eq!(asked_for(&requests), format!("CONNECT {port}"));
    assert_eq!(read_back(&mut browser, CALLBACK_REQUEST), CALLBACK_REQUEST);
}

#[test]
fn both_loopback_families_are_served() {
    // Given: a leased callback port. `forward_ports` recognises `[::1]`, and a
    // browser may resolve `localhost` to either family.
    if TcpListener::bind("[::1]:0").is_err() {
        eprintln!("skipping: no IPv6 loopback on this host, where the bind is tolerated");
        return;
    }
    let (bridge_port, requests) = spawn_fake_bridge();
    let leases = forward::callback::Leases::new();
    let port = forward::callback::request_on(&cfg(bridge_port), &leases, 0).unwrap();

    for address in ["127.0.0.1", "::1"] {
        // When: a browser connects over that family.
        let mut browser = connect(address, port);
        browser.write_all(CALLBACK_REQUEST.as_bytes()).unwrap();

        // Then: it reaches the bridge asking for the same single logical port.
        assert_eq!(
            asked_for(&requests),
            format!("CONNECT {port}"),
            "no bridge request for a browser on {address}"
        );
        assert_eq!(read_back(&mut browser, CALLBACK_REQUEST), CALLBACK_REQUEST);
    }
}

#[test]
fn the_lease_is_released_when_it_expires() {
    // Given: a callback port leased for a very short window.
    let (bridge_port, _requests) = spawn_fake_bridge();
    let mut cfg = cfg(bridge_port);
    cfg.forward_ttl_secs = 1;
    let leases = forward::callback::Leases::new();
    let port = forward::callback::request_on(&cfg, &leases, 0).unwrap();
    forward::callback::spawn_reaper(leases);

    // When: the deadline passes.
    for _ in 0..60 {
        if connection_is_refused(port) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Then: the listener is gone, so the port is free for other tools — released
    // by dropping it, with no wake-up connection needed.
    assert!(
        connection_is_refused(port),
        "port {port} still listening after its lease expired"
    );
}

#[test]
fn an_expiring_lease_lets_an_open_transfer_finish() {
    // Given: an open callback connection on a one-second lease.
    let (bridge_port, requests) = spawn_fake_bridge();
    let mut cfg = cfg(bridge_port);
    cfg.forward_ttl_secs = 1;
    let leases = forward::callback::Leases::new();
    let port = forward::callback::request_on(&cfg, &leases, 0).unwrap();
    forward::callback::spawn_reaper(leases);
    let mut browser = connect("127.0.0.1", port);
    browser.write_all(b"first\n").unwrap();
    assert_eq!(asked_for(&requests), format!("CONNECT {port}"));
    assert_eq!(read_back(&mut browser, "first\n"), "first\n");

    // When: the lease expires while that connection is still open.
    std::thread::sleep(Duration::from_millis(2_500));

    // Then: a new connection is refused, the listener having closed...
    assert!(
        connection_is_refused(port),
        "port {port} still accepting after its lease expired"
    );
    // ...while the connection already accepted keeps carrying bytes.
    browser.write_all(b"second\n").unwrap();
    assert_eq!(read_back(&mut browser, "second\n"), "second\n");
}

#[test]
fn requesting_the_same_port_twice_does_not_bind_twice() {
    // Given: a port already leased.
    let (bridge_port, _requests) = spawn_fake_bridge();
    let cfg = cfg(bridge_port);
    let leases = forward::callback::Leases::new();
    let port = forward::callback::request_on(&cfg, &leases, 0).unwrap();

    // When: it is requested again, as a repeated login does.
    forward::callback::request(&cfg, &leases, port);

    // Then: the lease was refreshed and the listener still works, rather than a
    // second bind failing on an address already in use.
    assert!(connect("127.0.0.1", port).peer_addr().is_ok());
}

#[test]
fn a_port_already_held_by_another_tool_is_reported_not_fatal() {
    // Given: an unrelated tool holding the callback port — the case that locked
    // a separate tool out of its own callback port.
    let squatter = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = squatter.local_addr().unwrap().port();
    let (bridge_port, _requests) = spawn_fake_bridge();
    let leases = forward::callback::Leases::new();

    // When: the daemon tries to serve that port.
    let served = forward::callback::request_on(&cfg(bridge_port), &leases, port);

    // Then: the request is refused instead of aborting the daemon, and the
    // squatter still owns the port.
    assert_eq!(served, None);
    assert!(connect("127.0.0.1", port).peer_addr().is_ok());
}
