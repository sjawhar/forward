use forward::config::Config;
use std::io::{Read as _, Write as _};
use std::net::{IpAddr, Shutdown, TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::thread;
use std::time::Duration;

fn cfg() -> Config {
    Config::default_values_for_test()
}

fn unix_echo(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("pcscd.comm");
    let listener = UnixListener::bind(&path).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            thread::spawn(move || {
                let mut request = Vec::new();
                stream.read_to_end(&mut request).unwrap();
                stream.write_all(&request).unwrap();
            });
        }
    });
    path
}

#[test]
fn laptop_channel_pipes_raw_bytes_to_the_pcscd_socket() {
    // This fails if the channel parses, frames, or injects anything: pcscd
    // bytes must arrive verbatim and flow back.
    let dir = tempfile::tempdir().unwrap();
    let upstream = unix_echo(dir.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    forward::pcsc::laptop::spawn_with_listener(cfg(), listener, upstream).unwrap();

    let mut client = TcpStream::connect(address).unwrap();
    client.write_all(&[0x12, 0x00, 0x00, 0x00, 0x11]).unwrap();
    client.shutdown(Shutdown::Write).unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();

    assert_eq!(reply, [0x12, 0x00, 0x00, 0x00, 0x11]);
}

#[test]
fn laptop_channel_refuses_an_unauthorized_peer_with_a_bare_close() {
    // This fails if a non-peer address is served, or if the refusal writes
    // bytes into a protocol that has no place for them.
    let dir = tempfile::tempdir().unwrap();
    let upstream = unix_echo(dir.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = thread::spawn(move || listener.accept().unwrap().0);
    let mut client = TcpStream::connect(address).unwrap();
    let server_side = accepted.join().unwrap();

    let mut config = cfg();
    config.peer = "100.64.0.9".to_owned();
    forward::pcsc::laptop::handle_from(
        &config,
        &upstream,
        "100.64.0.7".parse::<IpAddr>().unwrap(),
        server_side,
    );

    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert!(
        reply.is_empty(),
        "refusal must not write protocol-corrupting bytes"
    );
}

#[test]
fn laptop_channel_closes_immediately_when_pcscd_is_absent() {
    // This fails if a missing pcscd socket hangs the client instead of the
    // loud connection-refused semantics the socat bridge had.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    forward::pcsc::laptop::spawn_with_listener(
        cfg(),
        listener,
        std::path::PathBuf::from("/nonexistent/pcscd.comm"),
    )
    .unwrap();

    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert!(reply.is_empty());
}

#[test]
fn disabled_laptop_channel_does_not_resolve_or_bind_its_listener() {
    // The disabled setting is a complete opt-out: no listener or upstream
    // socket is touched, even with a deliberately invalid listen address.
    let mut config = cfg();
    config.pcsc_port = 0;
    config.listen = "not-an-address".to_owned();

    assert!(forward::pcsc::laptop::spawn(&config).is_ok());
}
