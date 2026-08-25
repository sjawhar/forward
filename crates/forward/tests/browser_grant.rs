use std::io::{ErrorKind, Read as _, Write as _};
use std::net::{SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use forward::browser::grant::{Grant, Grants, ProcessAnchor};
use forward::browser::peer::process_start;
use forward::browser::proxy::{self, Resolver};

#[path = "browser_grant/ownership.rs"]
mod ownership;
#[path = "browser_grant/registry.rs"]
mod registry;
#[path = "browser_grant/severance.rs"]
mod severance;
#[path = "browser_grant/subscription.rs"]
mod subscription;

const TOKEN: &[u8] = b"correct-horse";

fn current_anchor() -> ProcessAnchor {
    let pid = std::process::id();
    ProcessAnchor::new(pid, process_start(pid).unwrap())
}

fn grant(anchor: ProcessAnchor, deadline: Instant) -> Grant {
    Grant {
        session: "session-a".to_owned(),
        anchor,
        token: TOKEN.to_vec(),
        deadline,
    }
}
fn insert_grant(grants: &Grants, port: u16, grant: Grant) {
    let authority = forward::secretsd::BrokerIdentity {
        instance: "broker-a".to_owned(),
        epoch: 0,
        socket: forward::secretsd::SocketIdentity {
            device: 50,
            inode: 283,
        },
    };
    grants.observe_authority(authority.clone());
    assert!(grants.insert_if_authority(port, &authority, grant));
}

fn resolver(pid: Option<u32>) -> Resolver {
    Arc::new(move |_peer: SocketAddrV4, _local: SocketAddrV4| pid)
}

fn listener() -> (TcpListener, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    (listener, port)
}

/// An upstream that asserts the header and payload before returning a response.
fn spawn_relay_upstream(expected: &'static [u8]) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = Vec::new();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
            line.push(byte[0]);
        }
        let header = b"RELAY correct-horse";
        assert_eq!(line.len(), header.len(), "unexpected relay header length");
        assert!(
            line.iter()
                .zip(header)
                .all(|(actual, expected)| actual == expected),
            "unexpected relay header"
        );
        let mut payload = vec![0; expected.len()];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(payload, expected);
        stream.write_all(b"pong").unwrap();
    });
    (address, task)
}

fn assert_refused(client: &mut TcpStream, expected: &[u8]) {
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reply = Vec::new();
    client.read_to_end(&mut reply).unwrap();
    assert_eq!(reply, expected);
}
fn unconnected_upstream() -> TcpListener {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    listener
}

fn assert_not_dialed(upstream: &TcpListener) {
    assert!(matches!(
        upstream.accept(),
        Err(error) if error.kind() == ErrorKind::WouldBlock
    ));
}

/// An upstream that acknowledges the established pipe, then holds it open.
fn spawn_held_upstream() -> (
    SocketAddr,
    std::sync::mpsc::Receiver<()>,
    thread::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let (established, ready) = std::sync::mpsc::channel();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut byte = [0_u8; 1];
        while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {}
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).unwrap();
        established.send(()).unwrap();
        // Hold the pipe open until the far side ends it.
        let mut sink = [0_u8; 16];
        while matches!(stream.read(&mut sink), Ok(n) if n > 0) {}
    });
    (address, ready, task)
}
