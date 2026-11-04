use std::io::Write as _;
use std::net::{Shutdown, TcpListener, TcpStream};
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
fn a_flooding_unauthorized_peer_cannot_pin_its_handler() {
    // Given: a foreign peer that never stops flooding its socket.
    let (client, server) = socket_pair();
    let reader = client.try_clone().unwrap();
    let upstream = TcpListener::bind("127.0.0.1:0").unwrap();
    upstream.set_nonblocking(true).unwrap();
    let address = upstream.local_addr().unwrap();
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
            address,
            "100.64.0.7".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            server,
        );
    });

    // An identity failure must not drain the flood to preserve its refusal.
    // A peer writing after FIN may see RST; handler liveness is unconditional.
    let finished = wait_for_exit(&handler);
    stop.store(true, Ordering::Relaxed);
    let _ = reader.shutdown(Shutdown::Both);
    writer.join().unwrap();
    assert!(finished, "flooding peer pinned the handler");
    handler.join().unwrap();
    assert!(matches!(upstream.accept(), Err(error)
        if error.kind() == std::io::ErrorKind::WouldBlock));
}
