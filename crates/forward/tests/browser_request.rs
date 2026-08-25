use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use forward::browser::push::FeedSlot;
use forward::browser::request::{
    Deps, IdentityReader, Redeemer, SessionResolver, serve_with_binder,
};
use forward::secretsd::{BrokerError, BrokerIdentity, RedeemedGrant};

#[path = "browser_request/failures.rs"]
mod failures;
#[path = "browser_request/grant.rs"]
mod grant;
#[path = "browser_request/parsing.rs"]
mod parsing;
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

fn authority() -> BrokerIdentity {
    BrokerIdentity {
        instance: "broker-a".to_owned(),
        epoch: 0,
    }
}

fn accepting_redeemer() -> Redeemer {
    redeemer_with_ttl(60)
}

fn redeemer_with_ttl(ttl_secs: u64) -> Redeemer {
    Arc::new(move |_receipt: &[u8]| {
        Ok(RedeemedGrant {
            authority: authority(),
            ttl_secs,
        })
    })
}

fn accepting_identity_reader() -> IdentityReader {
    Arc::new(|| Ok(authority()))
}

fn rejecting_redeemer() -> Redeemer {
    Arc::new(|_receipt: &[u8]| Err(BrokerError::ReceiptRejected))
}

/// A laptop-side feed acceptor: accepts one feed attachment and ACKs every
/// TOKEN line, recording tokens so tests can assert what was pushed.
/// A laptop-side feed acceptor that acknowledges tokens and records their
/// value and requested lifetime.
fn feed_acceptor() -> (FeedSlot, mpsc::Receiver<(Vec<u8>, u64)>) {
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
            let (token, ttl) = line
                .trim_end()
                .strip_prefix("TOKEN ")
                .and_then(|rest| rest.split_once(' '))
                .map(|(token, ttl)| (token.as_bytes().to_vec(), ttl.parse().unwrap()))
                .unwrap();
            sender.send((token, ttl)).unwrap();
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
    grants.observe_authority(authority());
    thread::spawn(move || {
        serve_with_binder(
            Deps {
                grants,
                slot,
                resolver,
                redeemer,
                identity_reader: accepting_identity_reader(),
                binder: Arc::new(forward::browser::proxy::bind),
            },
            cfg,
            path,
        )
    });
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
