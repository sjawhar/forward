//! `forward browser grant` end to end against stand-ins for the two things it
//! cannot have in a test: the broker's YubiKey ceremony, and Sami's Chrome.
//!
//! Everything between them is the real thing — the real CLI binary, the real
//! request server, the real detached relay child it leaves behind — because
//! the descriptor hand-off, the `setsid`, and the hidden subcommand only exist
//! across a real `exec`.

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use forward::browser::grant::{Grants, ProcessAnchor};
use forward::browser::push::FeedSlot;
use forward::browser::request::{Deps, serve_with_deps};
use forward::secretsd::{BrokerIdentity, RedeemedGrant, SocketIdentity};

#[path = "endpoint/relay_process.rs"]
mod relay_process;

use relay_process::{assert_is_a_session_leader, relay_child};

const RECEIPT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const VERSION: &str = "OK\tversion=4 instance=broker-a epoch=0\n";

fn authority() -> BrokerIdentity {
    BrokerIdentity {
        instance: "broker-a".to_owned(),
        epoch: 0,
        socket: SocketIdentity {
            device: 50,
            inode: 283,
        },
    }
}

/// A broker that answers `HELLO` and hands out one receipt per `AUTHORIZE`,
/// standing in for the touch ceremony this test must never run for real.
fn spawn_broker(path: &std::path::Path) {
    let listener = std::os::unix::net::UnixListener::bind(path).unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut frame = String::new();
            if BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut frame)
                .unwrap_or(0)
                == 0
            {
                continue;
            }
            let reply = if frame.starts_with("HELLO") {
                VERSION.to_owned()
            } else if frame.starts_with("AUTHORIZE") {
                format!("OK\tstatus=authorized receipt={RECEIPT}\n")
            } else {
                "ERR\treason=unexpected\n".to_owned()
            };
            let _ = stream.write_all(reply.as_bytes());
        }
    });
}

/// The laptop's side of the relay: it checks the token it was pushed, then
/// answers the CDP discovery request the endpoint is asked for.
fn spawn_laptop(expected_token: std::sync::mpsc::Receiver<Vec<u8>>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        let token = expected_token
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut line = Vec::new();
            let mut byte = [0_u8; 1];
            while stream.read(&mut byte).unwrap() == 1 && byte[0] != b'\n' {
                line.push(byte[0]);
            }
            assert_eq!(
                line.strip_prefix(b"RELAY "),
                Some(token.as_slice()),
                "the endpoint presented the wrong relay token"
            );
            let mut request = [0_u8; 256];
            let _ = stream.read(&mut request);
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
        }
    });
    port
}

/// The devbox feed listener's role, reduced to what a grant needs: take the
/// pushed token, acknowledge it, and report it to the laptop stand-in.
fn feed() -> (FeedSlot, std::sync::mpsc::Receiver<Vec<u8>>) {
    let slot = FeedSlot::new();
    let (sender, receiver) = std::sync::mpsc::channel();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut stream = stream;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            let token = line
                .trim_end()
                .strip_prefix("TOKEN ")
                .and_then(|rest| rest.split_once(' '))
                .map(|(token, _)| token.as_bytes().to_vec())
                .unwrap();
            sender.send(token).unwrap();
            stream.write_all(b"OK\n").unwrap();
        }
    });
    slot.attach(TcpStream::connect(address).unwrap());
    (slot, receiver)
}

fn spawn_serve(grants: Grants, slot: FeedSlot, runtime: &std::path::Path, relay_port: u16) {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = "127.0.0.1".to_owned();
    cfg.relay_port = relay_port;
    let path = runtime.join("forward/browser-grant.sock");
    grants.observe_authority(authority());
    thread::spawn(move || {
        serve_with_deps(
            Deps {
                grants,
                slot,
                resolver: Arc::new(|_pid| Some("session-a".to_owned())),
                redeemer: Arc::new(|receipt: &[u8]| {
                    assert_eq!(receipt, RECEIPT.as_bytes());
                    Ok(RedeemedGrant {
                        authority: authority(),
                        ttl_secs: 60,
                    })
                }),
                identity_reader: Arc::new(|| Ok(authority())),
            },
            cfg,
            path,
        )
    });
}

#[test]
fn a_granted_endpoint_answers_json_version_in_the_callers_namespace() {
    // The bug this whole shape exists to fix: the printed endpoint had no
    // listener where the caller could reach it. This fails if the CLI prints a
    // port it did not bind, if the relay child does not inherit the listener
    // and the control channel, or if forward serve does not relay what the
    // child hands it.
    let directory = tempfile::tempdir().unwrap();
    let runtime = directory.path();
    std::fs::create_dir(runtime.join("forward")).unwrap();
    spawn_broker(&runtime.join("secretsd.sock"));
    let (slot, pushed) = feed();
    let (token_sender, token_receiver) = std::sync::mpsc::channel();
    let relay_port = spawn_laptop(token_receiver);
    let grants = Grants::new();
    spawn_serve(grants.clone(), slot, runtime, relay_port);
    let config = runtime.join("config.toml");
    std::fs::write(
        &config,
        format!("peer = \"127.0.0.1\"\nrelay_port = {relay_port}\n"),
    )
    .unwrap();
    super::await_socket(&runtime.join("forward/browser-grant.sock"));

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_forward"))
        .args(["browser", "grant", "--ttl", "45s", "--config"])
        .arg(&config)
        .env("XDG_RUNTIME_DIR", runtime)
        .env("SECRETSD_SOCK", runtime.join("secretsd.sock"))
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "stderr: {stderr}");
    let printed = String::from_utf8_lossy(&output.stdout)
        .trim_end()
        .to_owned();
    let port: u16 = printed
        .strip_prefix("http://127.0.0.1:")
        .unwrap_or_else(|| panic!("unexpected endpoint {printed:?}; stderr: {stderr}"))
        .parse()
        .unwrap();
    token_sender
        .send(pushed.recv_timeout(Duration::from_secs(10)).unwrap())
        .unwrap();

    // The endpoint must answer here, in this process's namespace, after the
    // command that created it has already exited.
    let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    client
        .write_all(b"GET /json/version HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
        .unwrap();
    let mut answer = String::new();
    client.read_to_string(&mut answer).unwrap();

    assert!(answer.starts_with("HTTP/1.1 200 OK"), "got {answer:?}");
    let caller = ProcessAnchor::new(
        std::process::id(),
        forward::browser::peer::process_start(std::process::id()).unwrap(),
    );
    let (recorded_port, _) = grants
        .live_for_descendant(caller)
        .expect("the grant is recorded for this test's process tree");
    assert_eq!(recorded_port, port);
    assert_is_a_session_leader(relay_child());

    // Retire the detached child rather than leaving it running for the TTL.
    grants.invalidate_authority();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(
            std::time::Instant::now() < deadline,
            "the relay child outlived its grant"
        );
        thread::sleep(Duration::from_millis(20));
    }
}
