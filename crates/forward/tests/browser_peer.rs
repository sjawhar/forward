use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use forward::browser::feed::RelayTokens;

fn cfg_with_peer(peer: &str) -> forward::config::Config {
    let mut cfg = forward::config::Config::default_values_for_test();
    cfg.peer = peer.to_owned();
    cfg
}

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

fn wait_for_exit(handle: &thread::JoinHandle<()>) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !handle.is_finished() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    handle.is_finished()
}

#[test]
fn a_flooding_unauthorized_peer_still_gets_the_refusal_and_frees_its_slot() {
    // Given: a foreign peer that never stops flooding its socket.
    let (client, server) = socket_pair();
    let mut reader = client.try_clone().unwrap();
    reader
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer_stop = Arc::clone(&stop);
    let writer = thread::spawn(move || {
        while !writer_stop.load(Ordering::Relaxed) {
            let _ = (&client).write_all(&[0_u8; 4096]);
        }
    });
    let cfg = cfg_with_peer("100.64.0.9");
    let tokens = RelayTokens::new();
    let handler = thread::spawn(move || {
        forward::browser::handle_from(
            &cfg,
            &tokens,
            upstream.local_addr().unwrap(),
            "100.64.0.7".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            server,
        );
    });

    // When: the bounded drain refuses the connection despite the continuous writes.
    let mut reply = Vec::new();
    while !reply.ends_with(b"REFUSED PEER\n") {
        let mut chunk = [0_u8; 32];
        let count = reader.read(&mut chunk).unwrap();
        assert_ne!(count, 0, "relay closed before sending its refusal");
        reply.extend_from_slice(&chunk[..count]);
    }

    // Then: the refusal survived and the handler returned without waiting for the peer.
    assert_eq!(reply, b"REFUSED PEER\n");
    assert!(wait_for_exit(&handler), "flooding peer pinned the handler");
    stop.store(true, Ordering::Relaxed);
    writer.join().unwrap();
    handler.join().unwrap();
}
