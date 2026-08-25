use std::io::{self, BufRead as _, BufReader, Write as _};
use std::net::{TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use forward::browser::grant::Grants;
use forward::browser::proxy::ProxyError;
use forward::browser::push::FeedSlot;
use forward::browser::request::{
    Binder, Redeemer, SessionResolver, read_line_with_timeout, serve_with_binder,
};

use super::{
    RECEIPT, accepting_redeemer, await_socket, feed_acceptor, grant_config, request_reply,
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
            grants,
            grant_config(),
            path,
            slot,
            Arc::new(|_pid| Some("session-a".to_owned())) as SessionResolver,
            redeemer,
            binder,
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
