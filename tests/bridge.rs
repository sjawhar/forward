use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

#[path = "bridge/arming.rs"]
mod arming;
#[path = "bridge/security.rs"]
mod security;

fn cfg(bridge_port: u16) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.bridge_port = bridge_port;
    cfg
}

/// Start a bridge on an ephemeral port and return the port.
fn spawn_bridge(armed: forward::bridge::Armed) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = listener.local_addr().unwrap().port();
    forward::bridge::spawn_with_listener(cfg(bridge_port), armed, listener);
    bridge_port
}

/// An upstream bound ONLY to loopback — the case a tailnet dial cannot reach
/// directly, and the reason this bridge exists. It replies `pong` once it has
/// received four bytes, so a reply proves the payload arrived intact.
fn spawn_echo_upstream() -> u16 {
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = upstream.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = [0_u8; 4];
        stream.read_exact(&mut request).unwrap();
        assert_eq!(&request, b"ping");
        stream.write_all(b"pong").unwrap();
    });
    port
}

/// Read to EOF under a deadline, so a bug that loses bytes fails the test
/// instead of hanging it.
fn read_reply(client: &mut TcpStream) -> String {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = String::new();
    client
        .read_to_string(&mut reply)
        .expect("the bridge must relay a reply, not hang or reset");
    reply
}

fn assert_refused(client: &mut TcpStream, expected: &str) {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = String::new();
    client
        .read_to_string(&mut reply)
        .expect("the bridge must write its refusal before closing");
    assert_eq!(reply, expected);
}

#[test]
fn hops_to_an_armed_loopback_port() {
    // Given: a loopback-only upstream, armed on the bridge.
    let upstream_port = spawn_echo_upstream();
    let armed = forward::bridge::Armed::new(forward::config::Config::default_values_for_test());
    armed.arm(upstream_port, Duration::from_secs(30));
    let bridge_port = spawn_bridge(armed);

    // When: a client asks the bridge for that port, then sends payload in a
    // second write, so the request line arrives on its own.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client
        .write_all(format!("CONNECT {upstream_port}\n").as_bytes())
        .unwrap();
    client.write_all(b"ping").unwrap();

    // Then: bytes reach the loopback-only upstream and come back.
    assert_eq!(read_reply(&mut client), "pong");
}

#[test]
fn payload_in_the_same_packet_as_the_request_line_still_reaches_the_upstream() {
    // Given: the same armed loopback-only upstream.
    let upstream_port = spawn_echo_upstream();
    let armed = forward::bridge::Armed::new(forward::config::Config::default_values_for_test());
    armed.arm(upstream_port, Duration::from_secs(30));
    let bridge_port = spawn_bridge(armed);

    // When: the request line and the first payload bytes arrive in ONE write,
    // so they land in one segment — what a real OAuth callback client does, its
    // GET following the line immediately.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.set_nodelay(true).unwrap();
    client
        .write_all(format!("CONNECT {upstream_port}\nping").as_bytes())
        .unwrap();

    // Then: the payload still reaches the upstream. Parsing the request line
    // with a buffered reader would have pulled "ping" into a buffer that is
    // dropped with the reader, hanging this connection forever.
    assert_eq!(read_reply(&mut client), "pong");
}

#[test]
fn refuses_an_unarmed_port() {
    // Given: a bridge with nothing armed.
    let bridge_port = spawn_bridge(forward::bridge::Armed::new(
        forward::config::Config::default_values_for_test(),
    ));

    // When: a client asks for a port anyway.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.write_all(b"CONNECT 8400\n").unwrap();

    // Then: a reachable peer cannot pick a port, only use one a login flow
    // legitimately requested.
    assert_refused(&mut client, "REFUSED UNARMED\n");
}

#[test]
fn refuses_denylisted_ports_even_when_armed() {
    // Given: a bridge whose config moves the relay port, and an armed set
    // built under a stale default config that would let that port through.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = listener.local_addr().unwrap().port();
    let mut bridge_cfg = cfg(bridge_port);
    bridge_cfg.relay_port = 12_911;
    let armed = forward::bridge::Armed::new(cfg(bridge_port));
    assert!(
        armed.arm(12_911, Duration::from_secs(30)),
        "the stale policy must accept it, or this test proves nothing"
    );
    forward::bridge::spawn_with_listener(bridge_cfg, armed, listener);

    // When: a client asks for the effective relay port.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.write_all(b"CONNECT 12911\n").unwrap();

    // Then: the connect-time denylist refuses it regardless of the armed set,
    // so neither an arming mistake nor a stale arming policy can expose a
    // forward service listener.
    assert_refused(&mut client, "REFUSED DENIED\n");
}

#[test]
fn default_relay_port_is_refused_at_connect_time_when_stale_policy_armed_it() {
    // Given: the default relay port armed under a config that moved that
    // service elsewhere. This makes the arm gate accept it before the bridge
    // starts with the effective default config.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let bridge_port = listener.local_addr().unwrap().port();
    let bridge_cfg = cfg(bridge_port);
    let mut stale_cfg = cfg(bridge_port);
    stale_cfg.relay_port = 12_911;
    let armed = forward::bridge::Armed::new(stale_cfg);
    assert!(armed.arm(12_803, Duration::from_secs(30)));
    forward::bridge::spawn_with_listener(bridge_cfg, armed, listener);

    // When/Then: the bridge refuses the default relay listener before dialing
    // it, even though its stale armed set contains the port.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.write_all(b"CONNECT 12803\n").unwrap();
    assert_refused(&mut client, "REFUSED DENIED\n");
}

#[test]
fn denylist_covers_forwards_own_ports() {
    // Given: a bridge on its default port with an otherwise default config.
    let config = cfg(12_801);

    // When/Then: the URL channel, the bridge itself, the file preview, the
    // browser relay, the pcsc channel, and the grant feed are all refused; an
    // ordinary callback port is not. The listener port stays an explicit
    // argument so a stale Config value cannot bypass it.
    for port in [12_800, 12_801, 12_802, 12_803, 12_804, 12_805] {
        assert!(
            forward::bridge::denied_port(&config, 12_801, port),
            "port {port} was not denied"
        );
    }
    assert!(!forward::bridge::denied_port(&config, 12_801, 8_400));
}

#[test]
fn refuses_a_malformed_request_line() {
    // Given: an armed port and a client that speaks HTTP at the bridge.
    let armed = forward::bridge::Armed::new(forward::config::Config::default_values_for_test());
    armed.arm(8_400, Duration::from_secs(30));
    let bridge_port = spawn_bridge(armed);

    // When: the first line is not `CONNECT <port>`.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.write_all(b"GET / HTTP/1.1\r\n\r\n").unwrap();

    // Then: it is refused.
    assert_refused(&mut client, "REFUSED\n");
}

#[test]
fn refuses_a_request_line_with_no_newline() {
    // Given: an armed port, so only the missing newline can refuse the request.
    let armed = forward::bridge::Armed::new(forward::config::Config::default_values_for_test());
    armed.arm(8_400, Duration::from_secs(30));
    let bridge_port = spawn_bridge(armed);

    // When: the line is otherwise valid but ends at EOF instead of a newline.
    let mut client = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    client.write_all(b"CONNECT 8400").unwrap();
    client.shutdown(std::net::Shutdown::Write).unwrap();

    // Then: it is refused — the protocol says newline-terminated.
    assert_refused(&mut client, "REFUSED\n");

    // When: a peer sends a long line and never terminates it.
    let mut flooder = TcpStream::connect(("127.0.0.1", bridge_port)).unwrap();
    flooder.write_all(&[b'A'; 100]).unwrap();

    // Then: the read is bounded and the connection is refused, not buffered.
    assert_refused(&mut flooder, "REFUSED\n");
}
