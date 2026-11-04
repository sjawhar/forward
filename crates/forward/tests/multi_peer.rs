use std::io::{Read as _, Write as _};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use forward::config::Config;
use socket2::{Domain, Protocol, Socket, Type};

#[path = "multi_peer/channels.rs"]
mod channels;
#[path = "multi_peer/doctor.rs"]
mod doctor;
#[path = "multi_peer/feed.rs"]
mod feed;
#[path = "multi_peer/role.rs"]
mod role;

const WAIT: Duration = Duration::from_secs(5);

fn config() -> Config {
    toml::from_str("listen = '127.0.0.1'\npeers = ['127.0.0.2', '127.0.0.3']\n").unwrap()
}

fn connect_from(source: &str, address: SocketAddr) -> TcpStream {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    socket
        .bind(&format!("{source}:0").parse::<SocketAddr>().unwrap().into())
        .unwrap();
    socket.connect_timeout(&address.into(), WAIT).unwrap();
    let stream: TcpStream = socket.into();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    stream.set_write_timeout(Some(WAIT)).unwrap();
    stream
}

fn echo(mut stream: impl std::io::Read + std::io::Write) {
    let mut bytes = [0_u8; 128];
    while let Ok(count) = stream.read(&mut bytes) {
        if count == 0 || stream.write_all(&bytes[..count]).is_err() {
            break;
        }
    }
}

fn roundtrip(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).unwrap();
    let mut reply = vec![0; payload.len()];
    stream.read_exact(&mut reply).unwrap();
    assert_eq!(reply, payload);
}

fn assert_closed_without_payload(mut stream: TcpStream) {
    let mut byte = [0];
    match stream.read(&mut byte) {
        Ok(0) => {}
        Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionReset) => {}
        result => panic!("unlisted source was not closed before payload: {result:?}"),
    }
}

#[test]
fn literal_peer_lists_reject_ambiguous_or_non_unicast_identity() {
    // Ignoring any entry or accepting a hostname would change the ACL silently.
    for body in [
        "peer = '127.0.0.2'\npeers = ['127.0.0.3']",
        "peers = ['127.0.0.2', 'box.example']",
        "peers = ['0.0.0.0']",
        "peers = ['::ffff:0.0.0.0']",
        "peers = ['ff02::1']",
        "peers = ['255.255.255.255']",
        "listen = '100.64.0.1'\npeers = []",
        "listen = '::ffff:0.0.0.0'\npeers = ['127.0.0.2']",
    ] {
        let cfg: Config = toml::from_str(body).unwrap();
        assert!(cfg.validate().is_err(), "accepted {body}");
    }
    assert!(config().validate().is_ok());
    assert!(
        config().peer_ip().is_err(),
        "outbound calls must not choose a peer arbitrarily"
    );
}
