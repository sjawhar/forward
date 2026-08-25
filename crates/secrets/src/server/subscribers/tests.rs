use std::io::{BufRead as _, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use nix::errno::Errno;
use nix::sys::socket::{MsgFlags, send};

use super::super::{Outcome, State, dispatch, listener, lock_state, serve_listener, worker};
use super::{SUBSCRIBER_CAPACITY, Subscriber};
use crate::proto::SUBSCRIBE_VERB;

#[test]
fn subscription_reports_the_current_epoch_and_does_not_hold_the_lock_lane() {
    // This fails if SUBSCRIBE is handled as an ordinary one-shot request,
    // if it does not publish the attach epoch, or if its held connection
    // can monopolize LOCK's dedicated worker.
    let directory = tempfile::tempdir().unwrap();
    let config = super::super::tests::test_config(directory.path());
    let socket_path = config.socket_path.clone();
    let server_listener = listener(&config).unwrap();
    let _server = thread::spawn(move || serve_listener(&server_listener, config).unwrap());

    let mut subscriber = UnixStream::connect(&socket_path).unwrap();
    subscriber
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    subscriber
        .write_all(format!("{SUBSCRIBE_VERB}\n").as_bytes())
        .unwrap();
    let mut reader = BufReader::new(subscriber.try_clone().unwrap());
    let mut attached = String::new();
    reader.read_line(&mut attached).unwrap();
    let (instance, epoch) =
        ::proto::parse_authority_event(&attached).expect("attach must identify the broker");
    assert_eq!(epoch, 0);
    let instance = instance.to_owned();

    let mut control = UnixStream::connect(socket_path).unwrap();
    control
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    control.write_all(b"LOCK\n").unwrap();
    let mut response = String::new();
    BufReader::new(control).read_line(&mut response).unwrap();
    assert_eq!(response, "OK\n");

    let mut after_lock = String::new();
    reader.read_line(&mut after_lock).unwrap();
    assert_eq!(after_lock, ::proto::authority_event(&instance, 1));
}

#[test]
fn lock_drops_blocked_subscribers_without_waiting_for_write_timeouts() {
    // This fails if subscription streams remain blocking: eight full send
    // buffers serialize their 250ms write timeouts on LOCK's response path.
    let directory = tempfile::tempdir().unwrap();
    let shared = Arc::new((
        Mutex::new(State::new(super::super::tests::test_config(directory.path())).unwrap()),
        Condvar::new(),
    ));
    let subscribers = Arc::clone(&lock_state(&shared.0).subscribers);
    let mut clients = Vec::with_capacity(SUBSCRIBER_CAPACITY);
    for _ in 0..SUBSCRIBER_CAPACITY {
        let (server, client) = UnixStream::pair().unwrap();
        subscribers
            .attach(&shared, server, crate::peer::current_for_test())
            .unwrap();
        clients.push(client);
    }
    let buffered = [0_u8; 4_096];
    let entries = subscribers
        .subscribers
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for subscriber in entries.iter() {
        loop {
            match send(
                subscriber.stream.as_raw_fd(),
                &buffered,
                MsgFlags::MSG_DONTWAIT | MsgFlags::MSG_NOSIGNAL,
            ) {
                Ok(_) => {}
                Err(Errno::EAGAIN) => break,
                Err(error) => panic!("could not fill subscriber buffer: {error}"),
            }
        }
    }
    drop(entries);

    let started = Instant::now();
    assert!(matches!(
        dispatch(
            crate::proto::Request::Lock,
            &shared,
            &crate::peer::current_for_test()
        )
        .outcome,
        Outcome::Ok
    ));
    assert!(started.elapsed() < Duration::from_millis(500));
    assert!(
        subscribers
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    );
    drop(clients);
}

#[test]
fn a_dead_subscriber_does_not_consume_the_attachment_cap() {
    // This fails if the cap is checked before PinnedPeer::is_alive: the
    // fresh subscriber receives the capacity refusal instead of EPOCH 0.
    let directory = tempfile::tempdir().unwrap();
    let shared = Arc::new((
        Mutex::new(State::new(super::super::tests::test_config(directory.path())).unwrap()),
        Condvar::new(),
    ));
    let subscribers = Arc::clone(&lock_state(&shared.0).subscribers);
    {
        let mut entries = subscribers
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for _ in 0..SUBSCRIBER_CAPACITY {
            let (stream, _) = UnixStream::pair().unwrap();
            let fd = std::fs::File::open("/dev/null").unwrap().into();
            entries.push(Subscriber {
                peer: crate::peer::PeerIdentity::from_owned_fd(fd),
                stream,
            });
        }
    }
    let (server, client) = UnixStream::pair().unwrap();

    subscribers
        .attach(&shared, server, crate::peer::current_for_test())
        .unwrap();

    let mut epoch = String::new();
    BufReader::new(client).read_line(&mut epoch).unwrap();
    assert_eq!(
        ::proto::parse_authority_event(&epoch).map(|(_, epoch)| epoch),
        Some(0)
    );
    assert_eq!(
        subscribers
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1
    );
}

#[test]
fn one_pinned_peer_can_hold_only_one_subscription_slot() {
    // Reattaching from one live process must replace its old stream. Without
    // that keying, one reconnecting forward process can fill every slot.
    let directory = tempfile::tempdir().unwrap();
    let shared = Arc::new((
        Mutex::new(State::new(super::super::tests::test_config(directory.path())).unwrap()),
        Condvar::new(),
    ));
    let subscribers = Arc::clone(&lock_state(&shared.0).subscribers);
    let mut last_client = None;
    for _ in 0..SUBSCRIBER_CAPACITY {
        let (server, client) = UnixStream::pair().unwrap();
        subscribers
            .attach(&shared, server, crate::peer::current_for_test())
            .unwrap();
        last_client = Some(client);
    }

    assert_eq!(
        subscribers
            .subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len(),
        1
    );
    let mut event = String::new();
    BufReader::new(last_client.unwrap())
        .read_line(&mut event)
        .unwrap();
    assert_eq!(
        ::proto::parse_authority_event(&event).map(|(_, epoch)| epoch),
        Some(0)
    );
}

#[test]
fn worker_heartbeats_the_current_authority() {
    // A quiet broker must still prove that its authority feed is healthy.
    let directory = tempfile::tempdir().unwrap();
    let shared = Arc::new((
        Mutex::new(State::new(super::super::tests::test_config(directory.path())).unwrap()),
        Condvar::new(),
    ));
    let subscribers = Arc::clone(&lock_state(&shared.0).subscribers);
    let (server, client) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(12)))
        .unwrap();
    subscribers
        .attach(&shared, server, crate::peer::current_for_test())
        .unwrap();
    let mut reader = BufReader::new(client);
    let mut attached = String::new();
    reader.read_line(&mut attached).unwrap();
    let worker_shared = Arc::clone(&shared);
    let _worker = thread::spawn(move || worker(&worker_shared));

    let mut heartbeat = String::new();
    reader.read_line(&mut heartbeat).unwrap();

    assert_eq!(heartbeat, attached);
}
