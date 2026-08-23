use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn cfg_with_token(token: &str) -> (forward::config::Config, tempfile::TempDir) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay.token");
    std::fs::write(&path, format!("{token}\n")).unwrap();
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = "100.64.0.9".to_owned();
    cfg.relay_token_file = Some(path);
    (cfg, directory)
}

fn assert_refusal(client: &mut TcpStream, expected: &str) {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = String::new();
    client.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, expected);
}

#[test]
fn an_authorized_peer_is_told_when_the_laptop_token_file_is_missing() {
    let directory = tempfile::tempdir().unwrap();
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = "100.64.0.9".to_owned();
    cfg.relay_token_file = Some(directory.path().join("missing.token"));
    let (mut client, server) = socket_pair();
    client
        .write_all(b"GET /json/version HTTP/1.0\r\n\r\n")
        .unwrap();

    forward::browser::handle_from(
        &cfg,
        SocketAddr::from(([127, 0, 0, 9], 1)),
        "100.64.0.9".parse().unwrap(),
        server,
    );

    assert_refusal(&mut client, "REFUSED TOKEN FILE\n");
}

#[test]
fn an_untokened_authorized_peer_receives_the_upstream_extension_state() {
    let (cfg, _directory) = cfg_with_token("correct-horse");
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream_address = upstream.local_addr().unwrap();
    let upstream_thread = thread::spawn(move || {
        let (mut stream, _) = upstream.accept().unwrap();
        let mut request = [0_u8; 256];
        let _ = stream.read(&mut request).unwrap();
        stream
            .write_all(b"HTTP/1.0 503 Service Unavailable\r\n\r\n")
            .unwrap();
    });
    let (mut client, server) = socket_pair();
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            upstream_address,
            "100.64.0.9".parse().unwrap(),
            server,
        );
    });
    client
        .write_all(b"GET /json/version HTTP/1.0\r\n\r\n")
        .unwrap();

    assert_refusal(&mut client, "REFUSED TOKEN UPSTREAM 503\n");
    handler.join().unwrap();
    upstream_thread.join().unwrap();
}
