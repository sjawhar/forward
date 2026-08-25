use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixListener;
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{io, thread};

use forward::browser::grant::Grants;
use forward::browser::proxy::ProxyError;
use forward::browser::push::FeedSlot;
use forward::browser::request::{
    Binder, Deps, IdentityReader, Redeemer, SessionResolver, serve_with_binder,
};

use super::super::{
    RECEIPT, accepting_redeemer, authority, await_socket, feed_acceptor, grant_config,
    redeemer_with_ttl, request_reply,
};
use super::spawn_with_binder;

#[test]
fn a_bind_failure_after_redeem_does_not_publish_a_token() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = Grants::new();
    let (slot, receiver) = feed_acceptor();
    let binder: Binder = Arc::new(|_, _| {
        Err(ProxyError::Bind {
            source: io::Error::other("test bind failure"),
        })
    });
    spawn_with_binder(
        grants.clone(),
        path.clone(),
        slot,
        accepting_redeemer(),
        binder,
    );
    await_socket(&path);

    assert_eq!(request_reply(&path, 60, RECEIPT), "REFUSED\n");
    assert!(receiver.try_recv().is_err());
    assert!(grants.snapshot_live().is_empty());
}

#[test]
fn an_instance_change_at_matching_epoch_refuses_before_a_token_or_proxy_survives() {
    let broker_directory = tempfile::tempdir().unwrap();
    let broker_path = broker_directory.path().join("secretsd.sock");
    let broker_listener = UnixListener::bind(&broker_path).unwrap();
    let broker = thread::spawn(move || {
        let steps = [
            (
                "HELLO\tversion=3\n".to_owned(),
                "OK\tversion=3 instance=broker-a epoch=0\n".to_owned(),
            ),
            (
                format!(
                    "REDEEM\treceipt={}\tcap=browser\n",
                    std::str::from_utf8(RECEIPT).unwrap()
                ),
                "OK\tstatus=redeemed cap=browser instance=broker-a epoch=0 ttl=60\n".to_owned(),
            ),
            (
                "HELLO\tversion=3\n".to_owned(),
                "OK\tversion=3 instance=broker-b epoch=0\n".to_owned(),
            ),
        ];
        for (expected, reply) in steps {
            let (mut stream, _) = broker_listener.accept().unwrap();
            let mut frame = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut frame)
                .unwrap();
            assert_eq!(frame, expected);
            stream.write_all(reply.as_bytes()).unwrap();
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = Grants::new();
    let (slot, receiver) = feed_acceptor();
    let bound_port = Arc::new(parking_lot::Mutex::new(None));
    let port_for_binder = Arc::clone(&bound_port);
    let binder: Binder = Arc::new(move |grants, upstream| {
        let proxy = forward::browser::proxy::bind(grants, upstream)?;
        *port_for_binder.lock() = Some(proxy.port());
        Ok(proxy)
    });
    let redeem_path = broker_path.clone();
    let redeemer: Redeemer = Arc::new(move |receipt| {
        forward::secretsd::redeem_for_test(&redeem_path, receipt, forward::secretsd::CAP_BROWSER)
    });
    let recheck_path = broker_path;
    let identity_reader: IdentityReader =
        Arc::new(move || forward::secretsd::broker_identity_for_test(&recheck_path));
    let server_grants = grants.clone();
    thread::spawn(move || {
        serve_with_binder(
            Deps {
                grants: server_grants,
                slot,
                resolver: Arc::new(|_pid| Some("session-a".to_owned())) as SessionResolver,
                redeemer,
                identity_reader,
                binder,
            },
            grant_config(),
            path,
        )
    });
    let request_path = directory.path().join("grant.sock");
    await_socket(&request_path);

    assert_eq!(request_reply(&request_path, 60, RECEIPT), "REFUSED\n");
    broker.join().unwrap();
    assert!(receiver.try_recv().is_err());
    assert!(grants.snapshot_live().is_empty());
    let port = bound_port.lock().unwrap();
    let deadline = Instant::now() + Duration::from_secs(1);
    while TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(
            Instant::now() < deadline,
            "bound proxy listener survived the refusal"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
#[test]
fn authority_advance_during_feed_ack_refuses_without_a_renewable_grant() {
    // This fails if the post-ACK authority check is removed: a token pushed
    // before the lock becomes a live, renewable grant after the ACK arrives.
    let feed_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let feed_address = feed_listener.local_addr().unwrap();
    let (pushed, pushed_receiver) = std::sync::mpsc::channel();
    let (release_ack, release_receiver) = std::sync::mpsc::channel();
    let feed = thread::spawn(move || {
        let (mut stream, _) = feed_listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(stream.try_clone().unwrap())
            .read_line(&mut line)
            .unwrap();
        let ttl = line
            .trim_end()
            .strip_prefix("TOKEN ")
            .and_then(|token| token.rsplit_once(' '))
            .map(|(_, ttl)| ttl.parse::<u64>().unwrap())
            .expect("feed did not receive a TOKEN line");
        pushed.send(ttl).unwrap();
        release_receiver.recv().unwrap();
        stream.write_all(b"OK\n").unwrap();
    });
    let slot = FeedSlot::new();
    slot.attach(TcpStream::connect(feed_address).unwrap());

    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = Grants::new();
    let initial = authority();
    grants.observe_authority(initial.clone());
    let current = Arc::new(parking_lot::Mutex::new(initial));
    let identity_for_server = Arc::clone(&current);
    let bound_port = Arc::new(parking_lot::Mutex::new(None));
    let port_for_binder = Arc::clone(&bound_port);
    let binder: Binder = Arc::new(move |grants, upstream| {
        let proxy = forward::browser::proxy::bind(grants, upstream)?;
        *port_for_binder.lock() = Some(proxy.port());
        Ok(proxy)
    });
    let server_grants = grants.clone();
    thread::spawn(move || {
        serve_with_binder(
            Deps {
                grants: server_grants,
                slot,
                resolver: Arc::new(|_pid| Some("session-a".to_owned())) as SessionResolver,
                redeemer: redeemer_with_ttl(300),
                identity_reader: Arc::new(move || Ok(identity_for_server.lock().clone())),
                binder,
            },
            grant_config(),
            path,
        )
    });
    let request_path = directory.path().join("grant.sock");
    await_socket(&request_path);
    let request = thread::spawn(move || request_reply(&request_path, 3_600, RECEIPT));

    assert_eq!(
        pushed_receiver
            .recv_timeout(Duration::from_secs(5))
            .unwrap(),
        300
    );
    let advanced = forward::secretsd::BrokerIdentity {
        instance: "broker-a".to_owned(),
        epoch: 1,
    };
    // The broker's fresh HELLO has advanced; leave the subscription's observed
    // pair unchanged so this specifically proves the post-ACK recheck.
    *current.lock() = advanced;
    release_ack.send(()).unwrap();

    assert_eq!(request.join().unwrap(), "REFUSED\n");
    feed.join().unwrap();
    assert!(grants.snapshot_live().is_empty());
    let port = (*bound_port.lock()).expect("a proxy was bound before the first check");
    let deadline = Instant::now() + Duration::from_secs(1);
    while TcpStream::connect(("127.0.0.1", port)).is_ok() {
        assert!(
            Instant::now() < deadline,
            "bound proxy listener survived the refused race"
        );
        thread::sleep(Duration::from_millis(10));
    }
}
