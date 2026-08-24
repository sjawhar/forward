use forward::browser::push::FeedSlot;
use forward::browser::request::{
    GrantStatus, Redeemer, SessionResolver, parse, parse_status, parse_ttl, request, serve_with,
};
use forward::secretsd::BrokerError;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

#[path = "browser_request/failures.rs"]
mod failures;
#[path = "browser_request/session.rs"]
mod session;

const RECEIPT: &[u8] = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn await_socket(path: &std::path::Path) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while UnixStream::connect(path).is_err() {
        assert!(Instant::now() < deadline, "request socket never came up");
        thread::sleep(Duration::from_millis(10));
    }
}

fn accepting_redeemer() -> Redeemer {
    Arc::new(|_receipt: &[u8]| Ok(()))
}

fn rejecting_redeemer() -> Redeemer {
    Arc::new(|_receipt: &[u8]| Err(BrokerError::ReceiptRejected))
}

/// A laptop-side feed acceptor: accepts one feed attachment and ACKs every
/// TOKEN line, recording tokens so tests can assert what was pushed.
fn feed_acceptor() -> (FeedSlot, mpsc::Receiver<Vec<u8>>) {
    let slot = FeedSlot::new();
    let (sender, receiver) = mpsc::channel();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let acceptor_slot = slot.clone();
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
    acceptor_slot.attach(TcpStream::connect(address).unwrap());
    (slot, receiver)
}

fn grant_config() -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = "127.0.0.1".to_owned();
    cfg
}

fn spawn_server(
    grants: forward::browser::grant::Grants,
    cfg: forward::config::Config,
    path: std::path::PathBuf,
    slot: FeedSlot,
    resolver: SessionResolver,
    redeemer: Redeemer,
) {
    thread::spawn(move || serve_with(grants, cfg, path, slot, resolver, redeemer));
}

fn request_reply(path: &std::path::Path, ttl_secs: u64, receipt: &[u8]) -> String {
    let mut stream = UnixStream::connect(path).unwrap();
    stream.write_all(b"GRANT ").unwrap();
    stream.write_all(ttl_secs.to_string().as_bytes()).unwrap();
    stream.write_all(b" ").unwrap();
    stream.write_all(receipt).unwrap();
    stream.write_all(b"\n").unwrap();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    reply
}

#[test]
fn a_well_formed_request_parses() {
    assert!(matches!(
        parse(b"GRANT 1800 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        Some((1800, receipt)) if receipt.len() == RECEIPT.len()
    ));
}

#[test]
fn a_request_without_the_verb_is_rejected() {
    assert!(
        parse(b"1800 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").is_none()
    );
    assert!(parse(b"STATUS").is_none());
}

#[test]
fn a_non_numeric_ttl_is_rejected() {
    assert!(
        parse(b"GRANT soon aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_none()
    );
}

#[test]
fn a_missing_receipt_is_rejected() {
    assert!(parse(b"GRANT 1800").is_none());
    assert!(parse(b"GRANT 1800 ").is_none());
}

#[test]
fn a_malformed_receipt_is_rejected() {
    assert!(parse(b"GRANT 1800 correct-horse").is_none());
    assert!(
        parse(b"GRANT 1800 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
            .is_none()
    );
    assert!(
        parse(b"GRANT 1800 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ")
            .is_none()
    );
}

#[test]
fn a_zero_or_overlong_ttl_is_rejected() {
    assert!(
        parse(b"GRANT 0 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_none()
    );
    assert!(
        parse(b"GRANT 43201 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            .is_none()
    );
}

#[test]
fn ttl_shorthand_parses() {
    assert_eq!(parse_ttl("45s"), Some(45));
    assert_eq!(parse_ttl("30m"), Some(1_800));
    assert_eq!(parse_ttl("2h"), Some(7_200));
    assert_eq!(parse_ttl("0m"), None);
    assert_eq!(parse_ttl("5x"), None);
    assert_eq!(parse_ttl("m"), None);
    assert_eq!(parse_ttl(""), None);
}

#[test]
fn a_status_reply_parses() {
    assert_eq!(parse_status("NONE"), GrantStatus::None);
    assert_eq!(
        parse_status("LIVE 12811 1799"),
        GrantStatus::Live {
            port: 12_811,
            remaining_secs: 1_799,
        }
    );
    assert_eq!(parse_status("LIVE nonsense"), GrantStatus::Unreachable);
}

#[test]
fn a_redeemed_receipt_grants_a_port_and_pushes_a_fresh_token() {
    // This fails if the receipt is not verified, the token is not minted
    // server-side, or the laptop is not told before the port is returned.
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, receiver) = feed_acceptor();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| Some("session-a".to_owned())),
        accepting_redeemer(),
    );
    await_socket(&path);

    let port = request(&path, 60, RECEIPT).expect("the grant request must succeed");
    let token = receiver.recv_timeout(Duration::from_secs(5)).unwrap();

    assert_eq!(token.len(), 43);
    assert!(
        grants
            .live(port)
            .is_some_and(|grant| grant.token.as_slice() == token.as_slice())
    );
}

#[test]
fn a_rejected_receipt_is_refused_without_granting() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    let (slot, receiver) = feed_acceptor();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        slot,
        Arc::new(|_pid| Some("session-a".to_owned())),
        rejecting_redeemer(),
    );
    await_socket(&path);

    assert_eq!(request_reply(&path, 60, RECEIPT), "REFUSED RECEIPT\n");
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    assert!(grants.snapshot_live().is_empty());
}

#[test]
fn an_unreachable_laptop_feed_refuses_the_grant() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = forward::browser::grant::Grants::new();
    spawn_server(
        grants.clone(),
        grant_config(),
        path.clone(),
        FeedSlot::new(),
        Arc::new(|_pid| Some("session-a".to_owned())),
        accepting_redeemer(),
    );
    await_socket(&path);

    assert_eq!(request_reply(&path, 60, RECEIPT), "REFUSED LAPTOP\n");
    assert!(grants.snapshot_live().is_empty());
}
