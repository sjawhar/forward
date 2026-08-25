use std::io::{self, BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use forward::browser::grant::Grants;
use forward::browser::proxy::ProxyError;
use forward::browser::push::FeedSlot;
use forward::browser::request::{
    Binder, Deps, IdentityReader, Redeemer, SessionResolver, read_line_with_timeout,
    serve_with_binder,
};

use super::{
    RECEIPT, accepting_identity_reader, accepting_redeemer, await_socket, feed_acceptor,
    grant_config, request_reply,
};

fn spawn_with_binder(
    grants: Grants,
    path: std::path::PathBuf,
    slot: FeedSlot,
    redeemer: Redeemer,
    binder: Binder,
) {
    thread::spawn(move || {
        serve_with_binder(
            Deps {
                grants,
                slot,
                resolver: Arc::new(|_pid| Some("session-a".to_owned())) as SessionResolver,
                redeemer,
                identity_reader: accepting_identity_reader(),
                binder,
            },
            grant_config(),
            path,
        )
    });
}

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
                "OK\tstatus=redeemed cap=browser instance=broker-a epoch=0\n".to_owned(),
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
        forward::secretsd::redeem(&redeem_path, receipt, forward::secretsd::CAP_BROWSER)
    });
    let recheck_path = broker_path;
    let identity_reader: IdentityReader =
        Arc::new(move || forward::secretsd::broker_identity(&recheck_path));
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
fn a_non_draining_feed_refuses_then_releases_the_grant_loop() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_secs(7));
    });
    let slot = FeedSlot::new();
    slot.attach(TcpStream::connect(address).unwrap());
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let grants = Grants::new();
    let binder: Binder = Arc::new(forward::browser::proxy::bind);
    spawn_with_binder(grants, path.clone(), slot, accepting_redeemer(), binder);
    await_socket(&path);

    let started = Instant::now();
    assert_eq!(request_reply(&path, 60, RECEIPT), "REFUSED LAPTOP\n");
    assert!(started.elapsed() < Duration::from_secs(7));
    let second_started = Instant::now();
    assert_eq!(request_reply(&path, 60, RECEIPT), "REFUSED LAPTOP\n");
    assert!(second_started.elapsed() < Duration::from_secs(1));
}

#[test]
fn a_stalled_grant_line_is_refused_without_pinning_the_server() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("grant.sock");
    let binder: Binder = Arc::new(forward::browser::proxy::bind);
    spawn_with_binder(
        Grants::new(),
        path.clone(),
        FeedSlot::new(),
        accepting_redeemer(),
        binder,
    );
    await_socket(&path);
    let mut stalled = UnixStream::connect(&path).unwrap();
    stalled
        .set_read_timeout(Some(Duration::from_secs(7)))
        .unwrap();
    stalled.write_all(b"GRANT 60 ").unwrap();
    stalled.write_all(RECEIPT).unwrap();
    let mut reply = String::new();

    BufReader::new(stalled).read_line(&mut reply).unwrap();

    assert_eq!(reply, "REFUSED\n");
    assert_eq!(request_reply(&path, 60, b"not-hex"), "REFUSED\n");
}

#[test]
fn trickling_request_bytes_share_one_total_deadline() {
    let (reader, mut writer) = UnixStream::pair().unwrap();
    let reader_guard = reader.try_clone().unwrap();
    let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(0);
    let reader_task = thread::spawn(move || {
        ready_sender.send(()).unwrap();
        read_line_with_timeout(&reader, Duration::from_millis(200))
    });
    ready_receiver.recv().unwrap();
    writer.write_all(b"G").unwrap();
    thread::sleep(Duration::from_millis(180));
    writer.write_all(b"R").unwrap();
    thread::sleep(Duration::from_millis(180));
    writer.write_all(b"\n").unwrap();

    assert!(reader_task.join().unwrap().is_none());
    drop(reader_guard);
}
